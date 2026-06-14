import re
import tempfile
import subprocess
import threading
import socket
import logging
import time
import os
from collections.abc import Callable

from .common import Architecture, Endianess, NetworkResult
from .freezeDiagnostics import (
    capture_freeze_state, FREEZE_MIN_BOOT, FREEZE_STALL, FREEZE_MIN_BYTES,
)

logger = logging.getLogger(__name__)

_active_qemu_processes: set[subprocess.Popen] = set()


def kill_all_qemu() -> None:
    """Terminate every tracked QEMU process. Safe to call from a signal handler."""
    for proc in list(_active_qemu_processes):
        if proc.poll() is None:
            logger.warning(f"Killing rogue QEMU process (pid {proc.pid})")
            proc.kill()
            proc.wait()
    _active_qemu_processes.clear()


def _isKernelPanic(line: str | None) -> bool:
    if line and ("Kernel panic" in line or "kernel panic" in line):
        logger.warning(f"Kernel panic detected: {line.strip()}")
        return True
    return False


class Qemu:
    def __init__(self, imagePath: str, arch: Architecture, endiannes: Endianess,
                 kernel: str, workDir: str = "", debug: bool = False):
        self.imagePath    = imagePath
        self.architecture = arch
        self.endiannes    = endiannes
        self.kernelPath   = kernel
        self.debug        = debug
        self.workDir      = workDir or tempfile.mkdtemp(prefix="femu-work-", dir="/tmp")
        self.tempdir      = tempfile.mkdtemp(prefix="femu-qemu-", dir="/tmp")
        self._tapDevices: list[tuple[str, str, int | None]] = []  # (tapName, hostNetdev, vlanId)

    # ------------------------------------------------------------------
    # TAP lifecycle
    # ------------------------------------------------------------------

    def _setupTap(self, networkResult: NetworkResult) -> bool:
        """
        Create one TAP device per candidate interface and configure the host-side IP.
        Uses 'ip tuntap' (modern replacement for tunctl).
        Returns True on success; tears down partial state and returns False on error.
        """
        self._tapDevices = []
        pid = os.getpid()

        for i, (_ip, _iface, _bridge, vlans, _macs) in enumerate(networkResult.candidates[:4]):
            tapName    = f"femu{pid}_{i}"
            vlanId     = vlans[0] if vlans else None
            hostNetdev = f"{tapName}.{vlanId}" if vlanId else tapName

            try:
                subprocess.run(
                    ["sudo", "ip", "tuntap", "add", "mode", "tap", "name", tapName],
                    check=True, capture_output=True,
                )
                subprocess.run(
                    ["sudo", "ip", "link", "set", tapName, "up"],
                    check=True, capture_output=True,
                )

                if vlanId is not None:
                    subprocess.run(
                        ["sudo", "ip", "link", "add", "link", tapName,
                         "name", hostNetdev, "type", "vlan", "id", str(vlanId)],
                        check=True, capture_output=True,
                    )
                    subprocess.run(
                        ["sudo", "ip", "link", "set", hostNetdev, "up"],
                        check=True, capture_output=True,
                    )

                if i < len(networkResult.hostIps) and networkResult.hostIps[i]:
                    subprocess.run(
                        ["sudo", "ip", "addr", "add",
                         f"{networkResult.hostIps[i]}/24", "dev", hostNetdev],
                        check=True, capture_output=True,
                    )

                self._tapDevices.append((tapName, hostNetdev, vlanId))
                logger.info(f"TAP {tapName} up, host netdev {hostNetdev}")

            except subprocess.CalledProcessError as e:
                logger.error(f"TAP setup failed for {tapName}: {e.stderr.decode().strip()}")
                self._teardownTap()
                return False

        return True

    def _teardownTap(self) -> None:
        """Remove TAP devices created by _setupTap(), in reverse order."""
        for tapName, hostNetdev, vlanId in reversed(self._tapDevices):
            try:
                if vlanId is not None:
                    subprocess.run(
                        ["sudo", "ip", "link", "delete", hostNetdev],
                        check=False, capture_output=True,
                    )
                subprocess.run(
                    ["sudo", "ip", "link", "set", tapName, "down"],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["sudo", "ip", "tuntap", "del", "mode", "tap", "name", tapName],
                    check=False, capture_output=True,
                )
                logger.debug(f"TAP {tapName} removed")
            except Exception as e:
                logger.warning(f"TAP teardown error for {tapName}: {e}")
        self._tapDevices = []

    # ------------------------------------------------------------------
    # Command builder
    # ------------------------------------------------------------------

    def _ifaceNo(self, name: str) -> int:
        """Extract the trailing integer from an interface name (eth0 → 0)."""
        m = re.search(r"(\d+)$", name)
        return int(m.group(1)) if m else 0

    def _buildNetworkArgs(self, networkResult: NetworkResult | None) -> list[str]:
        """
        Return the QEMU -device/-netdev arguments for all interface slots.

        Probe mode (networkResult=None) or user networking:
          - SLIRP with port forwarding for detected ports only.
        TAP mode (not isUserNetwork):
          - TAP device per candidate, mapped by interface number.
          - MAC address applied to -device when available.
          - Unmatched slots fall back to user networking (not dead socket listeners).
        """
        numIfaces = 1 if self.architecture == Architecture.ARM else 4
        device    = "virtio-net-device" if self.architecture == Architecture.ARM else "e1000"
        args: list[str] = []

        # --- probe / user networking ---
        if networkResult is None or networkResult.isUserNetwork:
            portfwd = ""
            seen: set[int] = set()
            if networkResult:
                for port, proto in networkResult.ports:
                    if port == 0:
                        continue # Port 0 is not a real port
                    
                    if port not in seen:
                        portfwd += f",hostfwd={proto}::{port}-:{port}"
                        seen.add(port)
            if self.debug:
                for dbgPort in (31337, 31338):
                    if dbgPort not in seen:
                        portfwd += f",hostfwd=tcp::{dbgPort}-:{dbgPort}"
                        seen.add(dbgPort)
            for i in range(numIfaces):
                args += ["-device", f"{device},netdev=net{i}"]
                args += ["-netdev",  f"user,id=net{i}{portfwd if i == 0 else ''}"]
            return args

        # --- TAP networking ---
        # Build a map: interface_number → (tap_index, macs)
        ifaceMap: dict[int, tuple[int, list]] = {}
        for idx, (_, iface, _, _, macs) in enumerate(networkResult.candidates[:numIfaces]):
            ifaceMap[self._ifaceNo(iface)] = (idx, macs)

        for i in range(numIfaces):
            if i in ifaceMap and ifaceMap[i][0] < len(self._tapDevices):
                tapIdx, macs = ifaceMap[i]
                tapName, _, _ = self._tapDevices[tapIdx]
                macStr = f",mac={macs[-1]}" if macs else ""
                args += ["-device", f"{device},netdev=net{i}{macStr}"]
                args += ["-netdev",  f"tap,id=net{i},ifname={tapName},script=no,downscript=no"]
            else:
                # Unmatched slot: user networking is more useful than a dead socket listener
                args += ["-device", f"{device},netdev=net{i}"]
                args += ["-netdev",  f"user,id=net{i}"]

        return args

    def _buildCommand(self, initArg: str, logPath: str,
                      networkResult: NetworkResult | None = None) -> list[str]:
        cmd: list[str] = []

        # emulator binary
        if self.architecture == Architecture.ARM:
            cmd.append("qemu-system-arm")
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.BIG:
            cmd.append("qemu-system-mips")
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.LITTLE:
            cmd.append("qemu-system-mipsel")

        cmd.extend(["-m", "256"])

        # machine
        if self.architecture == Architecture.ARM:
            cmd.extend(["-M", "virt"])
        elif self.architecture == Architecture.MIPS:
            cmd.extend(["-M", "malta"])

        cmd.extend(["-kernel", self.kernelPath])

        # disk
        if self.architecture == Architecture.ARM:
            cmd.extend(["-drive", f"if=none,file={self.imagePath},format=raw,id=rootfs"])
            cmd.extend(["-device", "virtio-blk-device,drive=rootfs"])
        elif self.architecture == Architecture.MIPS:
            cmd.extend(["-drive", f"if=ide,file={self.imagePath},format=raw"])

        rootDev = "/dev/sda1" if self.architecture == Architecture.MIPS else "/dev/vda1"
        debugFlag = "FIRMAE_DEBUG=true" if self.debug else "FIRMAE_DEBUG=false"
        cmd.extend(["-append",
                    f"firmadyne.syscall=27 root={rootDev} console=ttyS0 "
                    f"nandsim.parts=64,64,64,64,64,64,64,64,64,64 {initArg} rw debug "
                    f"ignore_loglevel print-fatal-signals=1 "
                    f"FIRMAE_NET=true FIRMAE_NVRAM=true FIRMAE_KERNEL=true FIRMAE_ETC=true "
                    f"{debugFlag} user_debug=31"])

        cmd.extend(["-serial",  f"file:{logPath}"])
        cmd.extend(["-serial",  f"unix:{os.path.join(self.tempdir, 'qemu.S1')},server,nowait"])
        cmd.extend(["-monitor", f"unix:{os.path.join(self.tempdir, 'qemu.monitor')},server,nowait"])
        cmd.extend(["-display", "none"])

        cmd.extend(self._buildNetworkArgs(networkResult))

        return cmd

    # ------------------------------------------------------------------
    # Monitor helper
    # ------------------------------------------------------------------

    def _sendMonitorCommand(self, command: str) -> None:
        monitorPath = os.path.join(self.tempdir, "qemu.monitor")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect(monitorPath)
                try:
                    s.recv(4096)
                except TimeoutError:
                    pass
                s.sendall(f"{command}\n".encode())
        except Exception as e:
            logger.warning(f"Failed to send monitor command '{command}': {e}")

    # ------------------------------------------------------------------
    # Log tail
    # ------------------------------------------------------------------

    def _tailLog(self, logPath: str, stop_event: threading.Event,
                 on_line: Callable[[str | None], bool] | None) -> None:
        while not stop_event.is_set():
            if os.path.exists(logPath):
                break
            time.sleep(0.2)

        if stop_event.is_set():
            return

        with open(logPath, "r", errors="replace") as f:
            while not stop_event.is_set():
                line = f.readline()
                if line:
                    if on_line and on_line(line):
                        stop_event.set()
                else:
                    if on_line and on_line(None):
                        stop_event.set()
                    time.sleep(0.1)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, initArg: str, logPath: str = "", timeout: int = 300,
            on_line: Callable[[str | None], bool] | None = None,
            networkResult: NetworkResult | None = None,
            capture_freeze: bool = True,
            stop_on_freeze: bool = False) -> bool:
        """
        Run the QEMU emulator.

        networkResult=None  →  probe mode (user networking, no TAP).
        networkResult set   →  final emulation mode:
                                 isUserNetwork=True  → SLIRP + port forwarding
                                 isUserNetwork=False → TAP networking

        capture_freeze      →  if the guest's serial output stalls while QEMU is
                               still alive, snapshot the guest CPU and write a
                               '<log>.freeze.txt' diagnostic (idle/blocked vs spin).
        stop_on_freeze      →  when a BUSY/spin freeze is captured (e.g. the
                               kretprobe loop), quit QEMU early instead of waiting
                               out the timeout, so the caller can retry quickly.

        Returns True if the run was stopped early due to a BUSY/spin freeze,
        False otherwise (normal exit, panic, or idle stall).
        """
        if not logPath:
            logPath = os.path.join(self.workDir, "qemu.serial.log")

        # TAP setup (only for final runs with static networking)
        tap_active = False
        if networkResult and not networkResult.isUserNetwork:
            if self._setupTap(networkResult):
                tap_active = True
            else:
                logger.warning("TAP setup failed — falling back to user networking")
                networkResult = NetworkResult(
                    networkResult.networkType, networkResult.netBridge,
                    networkResult.netInterface, networkResult.candidates,
                    networkResult.ports, True, [],
                )

        for name in ("qemu.monitor", "qemu.S1"):
            p = os.path.join(self.tempdir, name)
            if os.path.exists(p):
                os.unlink(p)

        cmd = self._buildCommand(initArg, logPath, networkResult)

        def _composed(line: str | None) -> bool:
            return _isKernelPanic(line) or bool(on_line and on_line(line))

        stop_event    = threading.Event()
        early_stopped = False
        quit_sent     = False
        start_time    = time.monotonic()

        process    = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        _active_qemu_processes.add(process)
        log_thread = threading.Thread(
            target=self._tailLog,
            args=(logPath, stop_event, _composed),
            daemon=True,
        )
        log_thread.start()
        logger.info(f"QEMU started. Log → {logPath}")

        try:
            deadline = time.monotonic() + timeout
            froze           = False
            freeze_captured = False
            last_log_size   = 0
            last_log_growth = time.monotonic()
            while True:
                if stop_event.is_set():
                    early_stopped = True
                    logger.info("Early termination triggered — sending quit to QEMU.")
                    self._sendMonitorCommand("quit")
                    quit_sent = True
                    break
                if process.poll() is not None:
                    logger.warning(f"QEMU exited on its own (returncode={process.returncode}) after {time.monotonic() - start_time:.1f}s")
                    break
                if time.monotonic() >= deadline:
                    self._sendMonitorCommand("quit")
                    quit_sent = True
                    raise subprocess.TimeoutExpired(cmd, timeout)

                # Freeze watchdog: serial output went silent while QEMU is alive.
                if capture_freeze and not freeze_captured and os.path.exists(logPath):
                    size = os.path.getsize(logPath)
                    now  = time.monotonic()
                    if size != last_log_size:
                        last_log_size, last_log_growth = size, now
                    elif (size > FREEZE_MIN_BYTES
                          and now - start_time > FREEZE_MIN_BOOT
                          and now - last_log_growth > FREEZE_STALL):
                        blocked = capture_freeze_state(
                            os.path.join(self.tempdir, "qemu.monitor"),
                            self.kernelPath, self.architecture, self.endiannes,
                            logPath, now - start_time)
                        freeze_captured = True
                        if stop_on_freeze and not blocked:
                            logger.warning("BUSY/spin freeze detected — stopping QEMU "
                                           "early so the caller can retry.")
                            froze = True
                            early_stopped = True
                            self._sendMonitorCommand("quit")
                            quit_sent = True
                            break

                time.sleep(0.5)
        finally:
            stop_event.set()
            if not quit_sent:
                self._sendMonitorCommand("quit")
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("QEMU did not exit after quit — killing.")
                process.kill()
                process.wait()
            log_thread.join(timeout=5)
            _active_qemu_processes.discard(process)
            if tap_active:
                self._teardownTap()

        elapsed = time.monotonic() - start_time
        logger.info(f"QEMU finished after {elapsed:.2f}s")

        if not early_stopped and process.returncode not in (0, None):
            stderr_out = (process.stderr.read().decode(errors="replace").strip()
                          if process.stderr else "")
            if stderr_out:
                logger.error(f"QEMU stderr:\n{stderr_out}")
            raise subprocess.CalledProcessError(process.returncode, cmd)

        return froze
