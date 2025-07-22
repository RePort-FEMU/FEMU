import subprocess
import tempfile
import logging
import shutil
import os
import re

from enum import Enum

from util import mountImage, unmountImage
from guestUtils import hostToGuestPath, guestToHostPath
from common import Endianess, Architecture
from qemuInterface import Qemu

TIMEOUT = 300 # 5 minutes #TODO make this configurable


logger = logging.getLogger("emulator")

class networkType(Enum):
    NONE= 0

class PreEmulator:
    def __init__(self, imagePath: str, possibleInits: list[str], servicesFound: bool, arch: Architecture, endiannes: Endianess, mountPoint: str = "", workDir: str = ""):
        
        self.imagePath = imagePath
        self.possibleInits = possibleInits
        self.architecture = arch
        self.endiannes = endiannes
        self.servicesFound = servicesFound
        
        if len(self.possibleInits) == 0:
            raise ValueError("No possible inits provided")
        
        if mountPoint:
            self.mountPoint = mountPoint
        else:
            self.mountPoint = tempfile.mkdtemp(prefix="femu-mount-", dir="/tmp")
            
        if workDir:
            self.workDir = workDir
        else:
            self.workDir = tempfile.mkdtemp(prefix="femu-work-", dir="/tmp")
            
            
        self.networkType = networkType.NONE
        
    # def __del__(self):
        
    #     # TODO: Unmount the image if it was mounted
    #     try:
    #         shutil.rmtree(self.mountPoint)
    #     except Exception as e:
    #         print(f"Error removing mount point {self.mountPoint}: {e}")
        
    #     try:
    #         shutil.rmtree(self.workDir)
    #     except Exception as e:
    #         print(f"Error removing work directory {self.workDir}: {e}")
            
    def getInitType(self, init: str) -> str:
        """
        Run the file command to determine the init type.
        """
        
        res = subprocess.run(["file", "-b", init], check=True, capture_output=True, text=True)
        
        if res.returncode != 0:
            raise RuntimeError(f"Failed to run file command on {init}: {res.stderr.strip()}")
        
        if "No such file or directory" in res.stdout.strip():
            raise FileNotFoundError(f"File {init}() not found")
                
        output = res.stdout.strip()
        
        return output
    
    def injectInit(self, init: str, initType: str) -> str:
        """
        Inject firmadyne scripts to the init.
        
        Returns the kernel init command line argument to pass to the emulator
        """
        
        def injectFile(filePath:str, extraContent: str = ""):
            with open(filePath, "a") as f:
                f.write("\n# Injected by PreEmulator\n")
                
                if extraContent:
                    f.write(extraContent)
                
                f.write("/firmadyne/network.sh &\n")
                
                if self.servicesFound:
                    f.write('/firmadyne/run_service.sh &\n')
                    
                f.write('/firmadyne/debug.sh &\n')
                
                # Long sleep for devices that need it (TEW-828DRU_1.0.7.2, etc...)
                f.write('/firmadyne/busybox sleep 36000\n')
                
        logger.info(f"Injecting init {init} of type {initType} into image {self.imagePath}")
        # TODO: Refactor this to cover more cases
        if os.path.basename(init) == "preInit.sh":
            injectFile(guestToHostPath(self.mountPoint, init))
        else:
            if initType.find("ELF") == -1 and initType.find("symbolic link") == -1: # possibly a script
                self.backupFile = guestToHostPath(self.mountPoint, init)
                self.backupData = readWithException(self.backupFile)
                injectFile(self.backupFile)
                return 'rdinit=/firmadyne/preInit.sh'
            elif initType.find("ELF") != -1 or initType.find("symbolic link") != -1: # netgear R6200 TODO: improve this check
                self.backupFile = guestToHostPath(self.mountPoint, "/firmadyne/preInit.sh")
                self.backupData = readWithException(self.backupFile)
                injectFile(self.backupFile, f"exec {init} &\n")
                return 'init=/firmadyne/preInit.sh'
                
        return 'rdinit=/firmadyne/preInit.sh'  # Default case, just use the preInit script
            
    def start(self):
        
        logger.info(f"Starting pre-emulator with image {self.imagePath} and inits {self.possibleInits}")
        
        for init in self.possibleInits:            
            logger.info(f"Processing init: {init}")
            
            mountImage(self.imagePath, self.mountPoint)
            
            try:
                initArg = self.injectInit(init, self.getInitType(guestToHostPath(self.mountPoint, init)))
            except Exception as e:
                logger.error(f"Failed to inject init {init}: {e}")
                unmountImage(self.mountPoint)
                continue
                                    
            unmountImage(self.mountPoint)
            
            logger.info(f"Running QEMU with init argument: {initArg}")
            try:
                Qemu(self.imagePath, self.architecture, self.endiannes, self.workDir, "/home/georgerg/FEMU/binaries").run(initArg, timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.error(f"QEMU timed out after {TIMEOUT} seconds while running with init {init}")
            except Exception as e:
                logger.error(f"QEMU failed with error: {e}")
                raise    
            
            # TODO: Add NVRAM dafault file checking
            
            kernelLog = open(os.path.join(self.workDir, "qemu.initial.serial.log"), "r").readlines()
            
            ports = findPorts(kernelLog)
            
            
                    
# TODO: Improve this function 
def readWithException(filePath):
    fileData = ''
    with open(filePath, 'rb') as f:
        while True:
            try:
                line = f.readline().decode()
                if not line:
                    break
                fileData += line
            except:
                fileData += ''

    return fileData
    
def findPorts(kernelLog:list[str]) -> list[str]:
    """
    Find ports in the kernel log.
    """
    ports = []
    portFound = {}
    pattern = r'init_bind\[[^\]]: proto:SOCK(DGRAM|STREAM), port:([0-9]+)\]'
    pattern = re.compile(pattern)
    for line in kernelLog:
        match = pattern.search(line)
        if match:
            port = match.group(2)
            proto = "tcp" if match.group(1) == "STREAM" else "udp"
            if port not in portFound:
                ports.append((port, proto))
                portFound[port] = True
                
    return ports

def findOutwardInterfaces(kernelLog: list[str], endiannes: Endianess) -> list[str]:
    
    raise NotImplementedError("This function is not implemented yet.")
