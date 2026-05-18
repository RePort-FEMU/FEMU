import subprocess
import tempfile
import logging
import time
import os

from collections.abc import Callable
from enum import Enum

from util import mountedImage, unmountImage
from guestUtils import hostToGuestPath, guestToHostPath
from common import Endianess, Architecture
from qemuInterface import Qemu
from kernelLogUtils import findBridges, findInterfaceIps, findPorts, findOutwardInterfaces, findMacChanges, findVLANs

TIMEOUT = 300 # 5 minutes #TODO make this configurable

logger = logging.getLogger("FEMU")

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
        """Run the file command to determine the init type.
        
        Args:
            init (str): The init path to determine the type of.
            
        Returns:
            str: The output of the file command for the init.
        """
        
        # TODO: Maybe use python-magic instead of calling file command
        res = subprocess.run(["file", "-b", init], capture_output=True, text=True)
        
        if res.returncode != 0:
            raise RuntimeError(f"Failed to run file command on {init}: {res.stderr.strip()}")
        
        if "No such file or directory" in res.stdout.strip():
            raise FileNotFoundError(f"File {init}() not found")
                
        output = res.stdout.strip()
        
        return output
    
    def injectInit(self, init: str, initType: str) -> str:
        """Inject firmadyne scripts to the init.
        
        Args:
            init (str): The init to inject.
            initType (str): The type of the init as determined by the file command.
        
        Returns:
            str: the kernel init command line argument to pass to the emulator
        """
        
        def injectFile(filePath:str, extraContent: str = ""):
            with open(filePath, "a") as f:
                f.write("\n# Injected by PreEmulator\n")
                
                f.write("echo 'Init injected by PreEmulator'\n")
                
                if extraContent:
                    f.write(extraContent)
                
                f.write("/firmadyne/network.sh &\n")
                
                if self.servicesFound:
                    f.write('/firmadyne/run_service.sh &\n')
                    
                f.write('/firmadyne/debug.sh &\n')
                
                # Long sleep for devices that need it (TEW-828DRU_1.0.7.2, etc...)
                f.write('/firmadyne/busybox sleep 36000\n')
                
        logger.info(f"Injecting init {init} of type {initType} into image {self.imagePath}")
        # TODO: Refactor this to cover more cases also try with actually setting the init. Currently we only set it some times
        if os.path.basename(init) == "preInit.sh":
            injectFile(guestToHostPath(self.mountPoint, init))
            self.backupFile = None
            self.backupData = None
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
    
    def getKernelPath(self) -> str:
        """Get the kernel path based on architecture and endianness.
        Returns:
            str: The path to the kernel image to use for QEMU.
        """
        # TODO: Make kernelDir configurable
        kernelDir = "/home/georgerg/FEMU/binaries"
        if self.architecture == Architecture.ARM:
            return os.path.join(kernelDir, "zImage.armel")  # Kernel image
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.BIG:
            return os.path.join(kernelDir, "vmlinux.mipseb.4") # Kernel image for big-endian MIPS
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.LITTLE:
            return os.path.join(kernelDir, "vmlinux.mipsel.4")
        else:
            raise ValueError("Unsupported architecture or endianness")
        
    def getNetworkInfo(self, kernelLogPath: str) -> tuple[list[tuple[int, str]], list[tuple[str, str, str, list[str], list[str]]]]:
        """
        Get the network info from the kernel log.
        
        Args:
            kernelLogPath (str): The path to the kernel log file.
            
        Returns:
            tuple[list[tuple[int, str]], list[tuple[str, str, str, list[str], list[str]]]]: A tuple containing a list of ports (number, protocol), 
                                                                                           a list of configuration candidates (IP address, interface name, bridge name, VLAN IDs, MAC addresses).
        """
        logger.debug("Reading kernel log: " + kernelLogPath)
        with open(kernelLogPath, "r") as f:
            kernelLog = f.readlines()
        
        ports = findPorts(kernelLog)
        logger.info(f"Found {len(ports)} ports in kernel log")
        if ports:
            logger.debug(f"Ports found: {', '.join([f'{port}/{proto}' for port, proto in ports])}")
        
        ips = findInterfaceIps(kernelLog, self.endiannes)
        logger.info(f"Found {len(ips)} interfaces with IP addresses in kernel log")
        for iface, addr in ips:
            logger.debug(f"Interface found: {iface} with address {addr}")
            
        macChanges = findMacChanges(kernelLog, self.endiannes)
        logger.info(f"Found {len(macChanges)} MAC address changes in kernel log")
        for iface, newMac in macChanges:
            logger.debug(f"MAC address change found on interface {iface}: {newMac}")
            
        bridges = findBridges(kernelLog)
        logger.info(f"Found {len(bridges)} bridges in kernel log")
        for bridge, netdevs in bridges.items():
            logger.debug(f"Bridge found: {bridge} with netdevs {', '.join(netdevs)}")
            
        vlans = findVLANs(kernelLog)
        logger.info(f"Found {len(vlans)} VLANs in kernel log")
        for iface, vlan_ids in vlans.items():
            logger.debug(f"Interface {iface} is associated with VLANs: {', '.join(map(str, vlan_ids))}")

        # generate possible configurations
        configCandidates = []
        for interface, addr in ips:
            if interface == "lo":
                continue
            
            cleanInterface = interface.split(".")[0] # Remove VLAN id if present
            
            # Find the bridges for this interface
            # Remove the VLAN id from the interface name if it is present (e.g., eth0.1 -> eth0)
            relatedBridges = [bridge for bridge, ifaces in bridges.items() if cleanInterface in [iface.split(".")[0] for iface in ifaces]]
            logger.debug(f"Related bridges for interface {interface}: {', '.join(relatedBridges) if relatedBridges else 'None'}")
            
            candidateFound = False
            for bridge in relatedBridges:
                # Find the VLANs for this bridge
                relatedVlans = []
                for iface, vlan_ids in vlans.items():
                    if iface.split(".")[0] == bridge.split(".")[0] or iface.split(".")[0] == cleanInterface: # Consider VLANs directly on the bridge or on the interface
                        relatedVlans.extend(vlan_ids)
                relatedVlans = list(set(relatedVlans)) # Remove duplicates

                logger.debug(f"Related VLANs for bridge {bridge}: {', '.join(relatedVlans) if relatedVlans else 'None'}")
                
                possibleMacs = macChanges.get(interface, [])
                possibleMacs.extend(m for m in macChanges.get(bridge, []) if m not in possibleMacs) # also consider MAC changes on the bridge 
                candidate = (addr, interface, bridge, relatedVlans, possibleMacs)
                if candidate not in configCandidates:
                    configCandidates.append(candidate)
                    candidateFound = True
                    
            # If no candidates were generated, add a default one 
            if not candidateFound:
                relatedVlans = vlans.get(interface, [])
                possibleMacs = macChanges.get(interface, [])
                candidate = (addr, interface, interface, relatedVlans, possibleMacs)
                if candidate not in configCandidates:
                    configCandidates.append(candidate)
                    logger.debug(f"No related bridge found for interface {interface}, adding default.")
                
        return ports, configCandidates
    
    def runQemu(self, initArg: str, logfile: str):
        qemu = Qemu(self.imagePath, self.architecture, self.endiannes, self.getKernelPath(), self.workDir)

        try:
            startTime = time.time()
            qemu.run(initArg, logfile, timeout=TIMEOUT, on_line=kernelPanicCallback)
            endTime = time.time()
            logger.info(f"QEMU finished after {endTime - startTime:.2f} seconds, processing logs...")
        except subprocess.TimeoutExpired:
            logger.error(f"QEMU timed out after {TIMEOUT} seconds")
        except Exception as e:
            logger.error(f"QEMU failed with error: {e}")
            raise e
            
    def start(self):
        
        logger.info(f"Starting pre-emulator with image {self.imagePath} and inits {self.possibleInits}")
        for init in self.possibleInits:            
            logger.info(f"Processing init: {init}")
            
            with mountedImage(self.imagePath, self.mountPoint) as mp:            
                try:
                    initArg = self.injectInit(init, self.getInitType(guestToHostPath(self.mountPoint, init)))
                except Exception as e:
                    logger.error(f"Failed to inject init {init}: {e}")
                    continue
                                                
            logger.info(f"Running QEMU with init argument: {initArg}")
            os.makedirs(os.path.join(self.workDir, "kernelLogs"), exist_ok=True)
            logfile = os.path.join(self.workDir, "kernelLogs", f"qemu.{init[1:].replace('/', '-')}.serial.log") # Skip the leading /
            self.runQemu(initArg, logfile)
            
            # TODO: Add NVRAM dafault file checking
            
            ports, configCandidates = self.getNetworkInfo(os.path.join(self.workDir, logfile))
            logger.debug(f"Configuration candidates for init {init}:")
            for addr, iface, bridge, vlans, macs in configCandidates:
                logger.debug(f"  Interface: {iface}, Address: {addr}, Bridge: {bridge}, VLANs: {', '.join(map(str, vlans)) if vlans else 'None'}, MAC changes: {', '.join(macs) if macs else 'None'}")
                
            
                
            # Restore the original file if it was modified
            if self.backupFile and self.backupData is not None:
                with mountedImage(self.imagePath, self.mountPoint) as mp:
                    with open(self.backupFile, "w") as f:
                        f.write(self.backupData)
                    logger.debug(f"Restored original file {self.backupFile}")
                self.backupFile = None
                self.backupData = None
            
            
                    
def kernelPanicCallback(line: str | None) -> bool:
    if line and ("Kernel panic" in line or "kernel panic" in line):
        logger.warning(f"Kernel panic detected in QEMU output: {line.strip()}")
        return True
    return False


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
            except Exception:
                fileData += ''

    return fileData
    
