import tempfile
import subprocess
import os

from common import Architecture, Endianess

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
    def _buildCommand(self, initArg: str, logFileName: str = "qemu.serial.log") -> list[str]:
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
        cmd.extend(["-serial", f"file:{os.path.join(self.workDir, logFileName)}"])
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
    
    def run(self, initArg: str, logFileName: str = "qemu.serial.log", timeout: int = 300):
        """
        Run the QEMU emulator with the specified init argument.
        """
        cmd = self._buildCommand(initArg, logFileName)
        
        # Execute the command
        try:
            subprocess.run(cmd, check=True, timeout=timeout)
        except subprocess.CalledProcessError as e:
            print(f"QEMU failed with error: {e}")
            print(f"Command: {' '.join(cmd)}")
            print(f"Return code: {e.returncode}")
            print(f"Output: {e.stderr}")
            raise