import tempfile
import subprocess
import threading
import socket
import logging
import time
import os
from collections.abc import Callable

from common import Architecture, Endianess

logger = logging.getLogger("FEMU")

class Qemu:
    def __init__(self, imagePath: str, arch: Architecture, endiannes: Endianess, kernel: str, workDir: str = ""):
        self.imagePath = imagePath
        self.architecture = arch
        self.endiannes = endiannes
        self.kernelPath = kernel

        if workDir:
            self.workDir = workDir
        else:
            self.workDir = tempfile.mkdtemp(prefix="femu-work-", dir="/tmp")

        self.tempdir = tempfile.mkdtemp(prefix="femu-qemu-", dir="/tmp")

    # TODO: Fix This
    def _buildCommand(self, initArg: str, logPath: str) -> list[str]:
        cmd = []

        # Emulator
        if self.architecture == Architecture.ARM:
            cmd.append("qemu-system-arm")
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.BIG:
            cmd.append("qemu-system-mips")
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.LITTLE:
            cmd.append("qemu-system-mipsel")

        cmd.extend(["-m", "256"])  # Memory size, can be made configurable

        # Machine
        if self.architecture == Architecture.ARM:
            cmd.extend(["-M", "virt"])  # Machine type for ARM
        elif self.architecture == Architecture.MIPS:
            cmd.extend(["-M", "malta"])

        # Kernel
        cmd.extend(["-kernel", self.kernelPath])

        # Root filesystem
        if self.architecture == Architecture.ARM:
            cmd.extend(["-drive", f"if=none,file={self.imagePath},format=raw,id=rootfs"])
            cmd.extend(["-device", "virtio-blk-device,drive=rootfs"])
        elif self.architecture == Architecture.MIPS:
            cmd.extend(["-drive", f"if=ide,file={self.imagePath},format=raw"])

        # Append additional arguments
        rootDev = "/dev/sda1" if self.architecture == Architecture.MIPS else "/dev/vda1"

        cmd.append("-append")
        cmd.append(f"firmadyne.syscall=27 root={rootDev} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 {initArg} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL=true FIRMAE_ETC=true user_debug=31")

        # Serial output
        cmd.extend(["-serial", f"file:{logPath}"])
        cmd.extend(["-serial", f"unix:{os.path.join(self.tempdir, 'qemu.S1')},server,nowait"])

        # Monitor
        cmd.extend(["-monitor", f"unix:{os.path.join(self.tempdir, 'qemu.monitor')},server,nowait"])

        # Display
        cmd.extend(["-display", "none"])

        # Network
        if self.architecture == Architecture.ARM:
            cmd.extend(["-device", "virtio-net-device,netdev=net0"])
            cmd.extend(["-netdev", "user,id=net0"])
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.BIG:
            for i in range(1, 5):
                cmd.extend(["-device", f"e1000,netdev=net{i}"])
                cmd.extend(["-netdev", f"user,id=net{i}"])
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.LITTLE:
            for i in range(0, 4):
                cmd.extend(["-device", f"e1000,netdev=net{i}"])
                cmd.extend(["-netdev", f"user,id=net{i}"])

        return cmd

    def _sendMonitorCommand(self, command: str) -> None:
        """Send a command to the QEMU HMP monitor socket."""
        monitorPath = os.path.join(self.tempdir, 'qemu.monitor')
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect(monitorPath)
                try:
                    s.recv(4096)  # drain the HMP banner before sending
                except TimeoutError:
                    pass
                s.sendall(f"{command}\n".encode())
        except Exception as e:
            logger.warning(f"Failed to send monitor command '{command}': {e}")

    def _tailLog(self, logPath: str, stop_event: threading.Event,
                 on_line: Callable[[str | None], bool] | None) -> None:
        """
        Streams logPath to the logger in real time.

        on_line is called with each new line, or None as a periodic tick when
        there is no new output. If it returns True the stop_event is set,
        which causes run() to send 'quit' to QEMU.
        """
        # Wait for QEMU to create the log file
        while not stop_event.is_set():
            if os.path.exists(logPath):
                break
            time.sleep(0.2)

        if stop_event.is_set():
            return

        with open(logPath, 'r', errors='replace') as f:
            while not stop_event.is_set():
                line = f.readline()
                if line:
                    if on_line and on_line(line):
                        stop_event.set()
                else:
                    if on_line and on_line(None):
                        stop_event.set()
                    time.sleep(0.1)

    def run(self, initArg: str, logPath: str = "", timeout: int = 300,
            on_line: Callable[[str | None], bool] | None = None) -> None:
        """
        Run the QEMU emulator.

        on_line: optional callback invoked with each serial log line, or None as
                 a periodic tick when there is no new output. Return True from the
                 callback to stop QEMU early via the monitor socket.
        """
        if not logPath:
            logPath = os.path.join(self.workDir, "qemu.serial.log")
            
        cmd = self._buildCommand(initArg, logPath)

        stop_event = threading.Event()
        early_stopped = False

        process = subprocess.Popen(cmd)
        log_thread = threading.Thread(
            target=self._tailLog,
            args=(logPath, stop_event, on_line),
            daemon=True,
        )
        log_thread.start()
        
        logger.info(f"QEMU started. Output will be logged to {logPath}")

        try:
            deadline = time.monotonic() + timeout
            while True:
                if stop_event.is_set():
                    early_stopped = True
                    logger.info("Early termination triggered, sending quit to QEMU.")
                    self._sendMonitorCommand("quit")
                    break
                if process.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    logger.warning(f"QEMU timed out after {timeout}s, sending quit.")
                    self._sendMonitorCommand("quit")
                    raise subprocess.TimeoutExpired(cmd, timeout)
                time.sleep(0.5)
        finally:
            stop_event.set()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.error("QEMU did not exit after quit command, killing.")
                process.kill()
                process.wait()
            log_thread.join(timeout=5)

        if not early_stopped and process.returncode not in (0, None):
            raise subprocess.CalledProcessError(process.returncode, cmd)
