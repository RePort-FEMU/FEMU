import json
import logging
import shutil
import os
import sys
import subprocess

from common import Architecture, Endianess, NetworkResult, ProbeResult, GIGA
from qemuInterface import Qemu
from dbInterface import DBInterface
from emulatorConfig import emulatorConfig
from util import (
    io_md5,
    checkArch,
    strings,
    checkCompatibility,
    getFilesInfo,
    getLinksInfo,
    getObjectIds,
    insertObjectsToImage,
    insertLinksToImage,
    createRawImg,
    mountedImage,
    unmountImage,
)

from prepareImage import prepareImage
from preEmulator import PreEmulator


from femu_extractor import extract
# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger("FEMU")

class Emulator:
    def __init__(self, config: emulatorConfig):
        # Information about the emulator environment
        self.config = config
        self.hash = io_md5(self.config.firmwarePath)
        
        self.imagePath = os.path.join(self.config.outputPath, "images")
        self.workDir = os.path.join(self.config.outputPath, "workDir")
        

        # Create directories for images and scratch space
        self.createDirectories()

        if self.config.brand == "auto":
            if self.config.sqlIP:
                self.brand = self.detectBrand()
            else:
                logger.warning("Brand detection is set to 'auto', but no database IP provided. Defaulting to 'unknown'.")
                self.brand = "unknown"
        else:
            self.brand = self.config.brand
                
        # Information about the firmware image
        self.iid = None
        self.kernelPath = None
        self.filesystemPath = None
        
        self.architecture = Architecture.UNKNOWN
        self.endianess = Endianess.UNKNOWN
        
        self.kernelVersion = ""
        self.kernelVersionString = ""
        self.inferredKernelInit = []
        self.inferredKernelInitStrings = []        
          
    def createDirectories(self):
        # Create necessary directories for images and scratch space
        if not os.path.exists(self.imagePath):
            try:
                os.makedirs(self.imagePath)
                logger.info(f"Image directory created at: {self.imagePath}")
            except Exception as e:
                logger.error(f"Failed to create image directory: {e}")
                raise
            
        if not os.path.exists(self.workDir):
            try:
                os.makedirs(self.workDir)
                logger.info(f"Work directory created at: {self.workDir}")
            except Exception as e:
                logger.error(f"Failed to create work directory: {e}")
                raise
            
    def detectBrand(self):
        # Check if the firmware's hash is in the database
        if not self.config.sqlIP:
            logger.warning("No database IP provided. Cannot detect brand.")
            return "unknown"
        
        with DBInterface(self.config.sqlIP, self.config.sqlPort) as cur:
            cur.execute("SELECT brand_id FROM image WHERE hash = %s", (self.hash,))
            brand_id = cur.fetchone()

            if brand_id:
                cur.execute("SELECT name FROM brand WHERE id = %s", (brand_id[0],))
                brand = cur.fetchone()
                if brand:
                    return brand[0]
        return "unknown"
    
    def updateDbImageInfo(self, field: str, value: str):
        if not self.config.sqlIP:
            return True  # No database IP provided, skip update
        
        logger.debug(f"Updating database image info: {field} = {value} for image ID {self.iid}")
        if not self.iid:
            logger.error("Image ID is not set. Cannot update database image info.")
            return False

        with DBInterface(self.config.sqlIP, self.config.sqlPort) as cur:
            try:
                cur.execute(f"UPDATE image SET {field} = %s WHERE id = %s", (value, self.iid))
                cur.connection.commit()
                logger.info(f"Database updated successfully: {field} = {value}")
                return True
            except Exception as e:
                cur.connection.rollback()
                logger.error(f"Failed to update database: {e}")
                return False
    
    def extract(self):
        # Extract the kernel and rootfs from the firmware image
        logger.info(f"Extracting firmware image: {self.config.firmwarePath}")
        
        # First extract the filesystem without the kernel
        result = extract(self.config.firmwarePath, self.imagePath, kernel=False, sqlIP=self.config.sqlIP, sqlPort=self.config.sqlPort, brand=self.config.brand, quiet=True)[0]
        self.iid = str(result["tag"])
        
        if not result["status"]:
            logger.error(f"Failed to extract filesystem from {self.config.firmwarePath}")
            return False

        self.filesystemPath = str(result["rootfsPath"])
        logger.debug(f"Root filesystem extracted to: {self.filesystemPath}")

        # Now extract the kernel
        logger.info(f"Extracting kernel from firmware image: {self.config.firmwarePath}")
        result = extract(self.config.firmwarePath, self.imagePath, filesystem=False, sqlIP=self.config.sqlIP, sqlPort=self.config.sqlPort, brand=self.config.brand, quiet=True)[0]

        if not result["status"]:
            logger.error(f"Failed to extract kernel from {self.config.firmwarePath}")
            if self.filesystemPath:
                shutil.rmtree(self.filesystemPath, ignore_errors=True)
            return False
        
        self.kernelPath = str(result["kernelPath"])
        logger.debug(f"Kernel extracted to: {self.kernelPath}")

        if not self.kernelPath or not self.filesystemPath:
            logger.error("Extraction failed: Kernel or root filesystem path is empty.")
            return False
        
        logger.info(f"Extraction completed successfully. Kernel: {self.kernelPath}, RootFS: {self.filesystemPath}")

        return True
    
    def inferArchitecture(self):
        # Infer the architecture and endianess of the firmware
        logger.info(f"Inferring architecture for firmware: {self.config.firmwarePath}")
        
        if not self.iid:
            logger.error("Image ID is not set. Cannot infer architecture.")
            return False
        
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot infer architecture.")
            return False
        
        self.architecture, self.endianess = checkArch(self.filesystemPath, self.iid)
        
        if self.architecture == Architecture.UNKNOWN or self.endianess == Endianess.UNKNOWN:
            logger.error("Failed to determine architecture or endianess of the firmware.")
            return False
        
        self.updateDbImageInfo("arch", str(self.architecture) + str(self.endianess))
        
        logger.info(f"Inferred Architecture: {self.architecture}, Endianess: {self.endianess}")
        return True
    
    def inferKernelVersion(self):
        # Infer the kernel version from the kernel image
        logger.info(f"Inferring kernel version for firmware: {self.config.firmwarePath}")
        
        if not self.kernelPath:
            logger.error("Kernel path is not set. Cannot infer kernel version.")
            return False
        
        for string in strings(self.kernelPath, minLength=4):
            if "Linux version" in string:
                temp = string.split("Linux version ")[1].split(" ")[0]
                if temp:
                    if self.kernelVersion and self.kernelVersion != temp:
                        logger.warning(f"Multiple kernel version strings found: {self.kernelVersion} and {temp}. Using the first one.")
                        continue
                    
                    self.kernelVersion = temp
                    self.kernelVersionString = string
                    logger.debug(f"Found kernel version: {self.kernelVersion}")
            elif "init=" in string:
                temp = string.split("init=")[1].split(" ")[0]
                if temp:
                    self.inferredKernelInit.append(temp)
                    self.inferredKernelInitStrings.append(string)
                    logger.debug(f"Found kernel init command: {temp}")

        if not self.kernelVersion:
            logger.warning("Kernel version could not be inferred from the kernel image.")
            return False
        else:
            self.updateDbImageInfo("kernel_version", self.kernelVersion)

        return True

    def collectInfo(self):
        # Collect information about the firmware
        logger.info(f"Collecting information for firmware: {self.config.firmwarePath}")
        
        if not self.iid or not self.kernelPath or not self.filesystemPath:
            logger.error("Image ID, kernel path, or root filesystem path is not set. Cannot collect information.")
            logger.error("Extraction must be run before collecting information.")
            return False

        # Check architecture and endianess
        if not self.inferArchitecture():
            logger.error("Failed to infer architecture.")
            return False
        
        if not self.inferKernelVersion():
            logger.warning("Failed to infer kernel version.")

        return True
    
    def dumpObjectsToDB(self):
        if not self.config.sqlIP:
            logger.warning("No database IP provided, skipping database updates.")
            return True
        
        if not self.iid:
            logger.error("Image ID is not set. Cannot dump objects to database.")
            return False
        
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot dump objects to database.")
            return False
        
        logger.info("Dumping objects to database.")
        
        fileInfo = getFilesInfo(self.filesystemPath)
        objectsIds, _ = getObjectIds(fileInfo, self.config.sqlIP, self.config.sqlPort)

        insertObjectsToImage(self.iid, objectsIds, fileInfo, self.config.sqlIP, self.config.sqlPort)

        linkInfo = getLinksInfo(self.filesystemPath)
        insertLinksToImage(self.iid, linkInfo, self.config.sqlIP, self.config.sqlPort)
        
        return True
        
    def getWorkDir(self) -> str:
        if not self.iid:
            logger.error("Image ID is not set. Cannot create work directory.")
            return ""
            
        if not os.path.exists(os.path.join(self.workDir, self.iid)):
            try:
                os.makedirs(os.path.join(self.workDir, self.iid))
                logger.info(f"Work subdirectory created for IID: {self.iid}")
            except Exception as e:
                logger.error(f"Failed to create work subdirectory: {e}")
                raise

        return os.path.join(self.workDir, self.iid)

    def extractFs(self, dst: str):
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot extract filesystem.")
            return False
        
        if not os.path.exists(dst):
            try:
                os.makedirs(dst)
                logger.info(f"Destination directory created at: {dst}")
            except Exception as e:
                logger.error(f"Failed to create destination directory: {e}")
                return False
        
        try:
            shutil.unpack_archive(self.filesystemPath, dst)
            logger.info(f"Filesystem extracted from {self.filesystemPath} to {dst}")
            return True
        except Exception as e:
            logger.error(f"Failed to extract filesystem: {e}")
            return False

    def _exportFindings(self, probeResult: ProbeResult, kernelPath: str,
                        foundServices: dict, workDir: str) -> dict:
        nr = probeResult.networkResult
        findings = {
            "firmware": {
                "path": self.config.firmwarePath,
                "hash": self.hash,
                "iid": self.iid,
                "brand": self.brand,
            },
            "emulation": {
                "imagePath": os.path.join(workDir, "raw.img"),
                "architecture": str(self.architecture),
                "endianness": str(self.endianess),
                "kernelPath": kernelPath,
                "initArg": probeResult.initArg,
                "workDir": workDir,
            },
            "initInjection": {
                "modifiedGuestFile": probeResult.modifiedGuestFile,
                "injectedContent": probeResult.injectedContent,
            },
            "services": foundServices,
            "network": {
                "networkType": nr.networkType,
                "netBridge": nr.netBridge,
                "netInterface": nr.netInterface,
                "candidates": [
                    {"ip": ip, "interface": iface, "bridge": bridge,
                     "vlans": vlans, "macs": macs}
                    for ip, iface, bridge, vlans, macs in nr.candidates
                ],
                "ports": [
                    {"port": port, "proto": proto}
                    for port, proto in nr.ports
                ],
                "isUserNetwork": nr.isUserNetwork,
                "hostIps": nr.hostIps,
            },
        }

        findingsPath = os.path.join(workDir, "findings.json")
        with open(findingsPath, "w") as f:
            json.dump(findings, f, indent=2)
        logger.info(f"Findings exported to {findingsPath}")
        return findings

    # ------------------------------------------------------------------
    # Findings helpers
    # ------------------------------------------------------------------

    def _loadFindings(self) -> dict | None:
        """
        Return findings dict for the current firmware without re-running exploration.
        Fast path: scan existing workDir subdirs and match by firmware hash.
        Slow path: extract to get iid, then load findings.json.
        """
        if os.path.isdir(self.workDir):
            for subdir in os.listdir(self.workDir):
                candidate = os.path.join(self.workDir, subdir, "findings.json")
                if os.path.exists(candidate):
                    with open(candidate) as f:
                        findings = json.load(f)
                    if findings.get("firmware", {}).get("hash") == self.hash:
                        logger.info(f"Loaded findings from {candidate}")
                        return findings

        logger.info("No cached findings — extracting to locate them")
        if not self.extract():
            return None
        findingsPath = os.path.join(self.getWorkDir(), "findings.json")
        if not os.path.exists(findingsPath):
            logger.error("No findings.json found — run in CHECK mode first")
            return None
        with open(findingsPath) as f:
            return json.load(f)

    def _buildQemuFromFindings(self, findings: dict,
                                debug: bool = False) -> "tuple[Qemu, str, str, NetworkResult] | None":
        """Reconstruct a Qemu instance + run parameters from findings.json."""
        em  = findings["emulation"]
        net = findings["network"]

        arch = next((a for a in Architecture if str(a) == em["architecture"]), None)
        end  = next((e for e in Endianess  if str(e) == em["endianness"]),    None)
        if not arch or not end:
            logger.error(f"Cannot reconstruct architecture from findings: "
                         f"{em['architecture']}/{em['endianness']}")
            return None

        networkResult = NetworkResult(
            networkType  = net["networkType"],
            netBridge    = net["netBridge"],
            netInterface = net["netInterface"],
            candidates   = [(c["ip"], c["interface"], c["bridge"], c["vlans"], c["macs"])
                            for c in net["candidates"]],
            ports        = [(p["port"], p["proto"]) for p in net["ports"]],
            isUserNetwork= net["isUserNetwork"],
            hostIps      = net["hostIps"],
        )
        qemu = Qemu(em["imagePath"], arch, end, em["kernelPath"], em["workDir"], debug=debug)
        return qemu, em["initArg"], em["workDir"], networkResult

    def _applyInjection(self, findings: dict) -> bool:
        """Re-apply the init injection that was restored after explore(). Idempotent."""
        inj = findings.get("initInjection", {})
        guestFile = inj.get("modifiedGuestFile")
        content   = inj.get("injectedContent")
        if not guestFile or not content:
            return True  # nothing to inject (preInit.sh case)

        imagePath = findings["emulation"]["imagePath"]
        workDir   = findings["emulation"]["workDir"]
        mountPoint = os.path.join(workDir, "mnt")
        os.makedirs(mountPoint, exist_ok=True)

        with mountedImage(imagePath, mountPoint) as mp:
            hostPath = mp + guestFile
            if not os.path.exists(hostPath):
                logger.error(f"Cannot re-inject: {hostPath} not found in image")
                return False
            with open(hostPath, "r", errors="replace") as f:
                current = f.read()
            if "# Injected by PreEmulator" in current:
                logger.debug("Injection already present — skipping re-inject")
                return True
            with open(hostPath, "a") as f:
                f.write(content)
            logger.info(f"Re-applied injection to {guestFile}")
        return True

    def _logAccessInfo(self, findings: dict) -> None:
        """Print the URLs and shell access info so the user knows where to point a browser."""
        net = findings["network"]
        webPorts = {p["port"] for p in net["ports"] if p["proto"] == "tcp" and p["port"] in (80, 443, 8080, 8443)}

        if net["isUserNetwork"]:
            baseIps = ["127.0.0.1"]
        else:
            baseIps = [c["ip"] for c in net["candidates"]]

        if webPorts:
            for ip in baseIps:
                for port in sorted(webPorts):
                    scheme = "https" if port in (443, 8443) else "http"
                    suffix = f":{port}" if port not in (80, 443) else ""
                    logger.info(f"  Web UI → {scheme}://{ip}{suffix}/")
        else:
            for ip in baseIps:
                logger.info(f"  Web UI → http://{ip}/  (no web port detected — try manually)")

    # ------------------------------------------------------------------
    # Modes
    # ------------------------------------------------------------------

    def explore(self) -> dict | None:
        logger.info(f"Running emulator for firmware: {self.config.firmwarePath}")
        
        logger.info(f"Step 1: Extracting firmware image {self.config.firmwarePath}")
        if not self.extract():
            logger.error("Extraction failed, aborting emulator run.")
            return

        if not self.collectInfo():
            logger.error("Failed to collect information, aborting emulator run.")
            return
        
        if not checkCompatibility(self.architecture, self.endianess):
            logger.error(f"Incompatible architecture or endianess: {self.architecture}, {self.endianess}")
            return
        
        if not self.dumpObjectsToDB():
            logger.error("Failed to dump objects to database.")
            return
                
        logger.info("Step 2: preparing image for emulation")
        
        workDir = self.getWorkDir()

        findingsPath = os.path.join(workDir, "findings.json")
        if os.path.exists(findingsPath):
            answer = input(f"Findings already exist for this firmware. Re-run exploration? [y/N]: ").strip().lower()
            if answer != "y":
                logger.info("Skipping exploration — loading existing findings.")
                with open(findingsPath) as f:
                    return json.load(f)

        if os.path.isdir(os.path.join(workDir, "mnt")) and len(os.listdir(os.path.join(workDir, "mnt"))) > 0:
            unmountImage(os.path.join(workDir, "mnt"))
            shutil.rmtree(os.path.join(workDir, "mnt"), ignore_errors=True)
            logger.warning("Unmounted and removed existing mount directory.")
                
        if os.path.exists(os.path.join(workDir, "raw.img")):
            logger.info("Removing existing raw image.")
            os.remove(os.path.join(workDir, "raw.img"))
            logger.info("Removed existing raw image successfully.")
            
        createRawImg(os.path.join(workDir, "raw.img"), 1 * GIGA)
        os.makedirs(os.path.join(workDir, "mnt"), exist_ok=True)
        
        with mountedImage(os.path.join(workDir, "raw.img"), os.path.join(workDir, "mnt")) as mp:
            self.extractFs(mp) #TODO Possible leak here. Check return

        res = prepareImage(
            os.path.join(workDir, "raw.img"),
            os.path.join(workDir, "mnt"),
            self.architecture,
            self.endianess,
            self.config.binariesPath,
            os.path.join(self.config.scriptsPath, "firmadyne"),
            self.inferredKernelInit
        )

        if not res:
            logger.error("Failed to prepare image for emulation.")
            return

        foundInits, foundServices = res

        logger.info(f"Step 3: probing emulation with {len(foundInits)} init candidates and {len(foundServices)} found services")

        pre = PreEmulator(
            os.path.join(workDir, "raw.img"),
            foundInits,
            len(foundServices) > 0,
            self.architecture,
            self.endianess,
            self.config.binariesPath,
            os.path.join(workDir, "mnt"),
            workDir,
        )
        probeResult = pre.start()

        if probeResult is None:
            logger.error("Pre-emulation probe failed for all inits — aborting.")
            return

        nr = probeResult.networkResult
        logger.info(
            f"Network ready: type={nr.networkType} "
            f"bridge={nr.netBridge} iface={nr.netInterface} "
            f"userNet={nr.isUserNetwork}"
        )
        if nr.hostIps:
            logger.info(f"Host IPs: {', '.join(nr.hostIps)}")
            
        logger.info(f"Step 4: exporting findings")

        return self._exportFindings(probeResult, pre.getKernelPath(), foundServices, workDir)

    def boot(self) -> None:
        findings = self._loadFindings()
        if not findings:
            return
        result = self._buildQemuFromFindings(findings)
        if not result:
            return
        qemu, initArg, workDir, networkResult = result
        if not self._applyInjection(findings):
            return
        logPath = os.path.join(workDir, "qemu.boot.serial.log")
        self._logAccessInfo(findings)
        logger.info(f"Booting firmware, log → {logPath}")
        try:
            qemu.run(initArg, logPath, networkResult=networkResult, timeout=86400)
        except subprocess.TimeoutExpired:
            logger.info("Boot session timed out")

    def debug(self) -> None:
        findings = self._loadFindings()
        if not findings:
            return
        result = self._buildQemuFromFindings(findings, debug=True)
        if not result:
            return
        qemu, initArg, workDir, networkResult = result
        if not self._applyInjection(findings):
            return
        logPath = os.path.join(workDir, "qemu.debug.serial.log")
        self._logAccessInfo(findings)
        logger.info(f"Booting firmware in debug mode (nc:31337, telnet:31338), log → {logPath}")
        try:
            qemu.run(initArg, logPath, networkResult=networkResult, timeout=86400)
        except subprocess.TimeoutExpired:
            logger.info("Debug session timed out")

    def analyze(self) -> None:
        findings = self._loadFindings()
        if not findings:
            return
        fw  = findings["firmware"]
        net = findings["network"]
        logger.info(f"Firmware : {fw['path']}  iid={fw['iid']}  brand={fw['brand']}")
        logger.info(f"Network  : type={net['networkType']}  userNet={net['isUserNetwork']}")
        logger.info(f"IPs      : {[c['ip'] for c in net['candidates']]}")
        logger.info(f"Ports    : {net['ports']}")
        logger.info("Full analysis tooling not yet implemented")

