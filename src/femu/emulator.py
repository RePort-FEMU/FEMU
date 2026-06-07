import hashlib
import json
import logging
import shutil
import os
import signal
import subprocess
from time import sleep

from .common import Architecture, Endianess, NetworkResult, ProbeResult, GIGA
from .qemuInterface import Qemu
from .emulatorConfig import emulatorConfig
from .db import upsertBrand, upsertImage, updateImageField, getBrandByHash
from .util import (
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

from .prepareImage import prepareImage
from .preEmulator import PreEmulator
from .emulationVerifier import makeNetworkMonitor
from .findings import (
    getExportDir, buildFindings, saveFindings, saveFindingsToDB,
    loadFindings, buildQemuFromFindings,
)


from femu_extractor import extract
# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger(__name__)

class Emulator:
    def __init__(self, config: emulatorConfig):
        self.config = config

        with open(self.config.firmwarePath, "rb") as f:
            self.tag = hashlib.sha256(f.read()).hexdigest()

        self.imagePath = os.path.join(self.config.outputPath, "images")
        self.workDir   = os.path.join(self.config.outputPath, "workDir")

        self.createDirectories()

        if self.config.brand == "auto":
            if self.config.sqlIP:
                self.brand = getBrandByHash(self.tag, self.config.sqlIP, self.config.sqlPort) or "unknown"
            else:
                logger.warning("Brand detection requires a database — defaulting to 'unknown'.")
                self.brand = "unknown"
        else:
            self.brand = self.config.brand

        # Set after extraction
        self.db_id: int | None = None
        self.kernelPath = None
        self.filesystemPath = None

        self.architecture = Architecture.UNKNOWN
        self.endianess    = Endianess.UNKNOWN

        self.kernelVersion = ""
        self.kernelVersionString = ""
        self.inferredKernelInit = []
        self.inferredKernelInitStrings = []
          
# ------------------------------------------------------------------
# Utilities 
# ------------------------------------------------------------------
          
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
            
    def getWorkDir(self) -> str:
        path = os.path.join(self.workDir, self.tag)
        os.makedirs(path, exist_ok=True)
        return path
    
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
                
    def _runQemu(self, qemu: Qemu, initArg: str, logPath: str,
                 networkResult: NetworkResult, timeout: int) -> None:
        """Run QEMU with network-up notification, clean Ctrl+C and SIGTERM handling."""
        def _sigterm(*_):
            raise KeyboardInterrupt

        old_handler = signal.signal(signal.SIGTERM, _sigterm)
        try:
            qemu.run(initArg, logPath, networkResult=networkResult, timeout=timeout,
                     on_line=makeNetworkMonitor(networkResult))
        except subprocess.TimeoutExpired:
            logger.info("Session timed out")
        except KeyboardInterrupt:
            logger.info("Interrupted — QEMU shutting down")
        finally:
            signal.signal(signal.SIGTERM, old_handler)
            
    def _cleanupWorkDir(self) -> None:
        """Remove the raw image and unmount any mounts in the workDir."""
        workDir = self.getWorkDir()
        mntPath = os.path.join(workDir, "mnt")
        if os.path.isdir(mntPath) and len(os.listdir(mntPath)) > 0:
            unmountImage(mntPath)
            shutil.rmtree(mntPath, ignore_errors=True)
            logger.warning("Unmounted and removed existing mount directory.")
        rawImgPath = os.path.join(workDir, "raw.img")
        if os.path.exists(rawImgPath):
            logger.info("Removing existing raw image.")
            os.remove(rawImgPath)
            logger.info("Removed existing raw image successfully.")        
    
# ------------------------------------------------------------------
# DB Helpers
# ------------------------------------------------------------------

    def dumpObjectsToDB(self):
        if not self.config.sqlIP:
            return False

        if not self.db_id or not self.filesystemPath:
            logger.error("DB id or filesystem path not set — run extract() first.")
            return False

        logger.info("Dumping filesystem objects to database.")
        fileInfo = getFilesInfo(self.filesystemPath)
        objectIds, _ = getObjectIds(fileInfo, self.config.sqlIP, self.config.sqlPort)
        insertObjectsToImage(str(self.db_id), objectIds, fileInfo, self.config.sqlIP, self.config.sqlPort)

        linkInfo = getLinksInfo(self.filesystemPath)
        insertLinksToImage(str(self.db_id), linkInfo, self.config.sqlIP, self.config.sqlPort)
        return True
            
    def _updateDbField(self, field: str, value: str) -> bool:
        if not self.config.sqlIP or not self.db_id:
            return True
        return updateImageField(self.db_id, field, value, self.config.sqlIP, self.config.sqlPort)
    
    def registerBrandInDB(self) -> int | None:
        if not self.config.sqlIP:
            return None
        return upsertBrand(self.brand, self.config.sqlIP, self.config.sqlPort)
    
    def registerImageInDB(self) -> bool:
        if not self.config.sqlIP:
            return False
        if not self.db_id:
            brandId = self.registerBrandInDB()
            if brandId is None:
                logger.error("Failed to register brand in database.")
                return False
            self.db_id = upsertImage(
                self.tag,
                os.path.basename(self.config.firmwarePath),
                self.tag,
                brandId,
                self.config.sqlIP,
                self.config.sqlPort,
            )
        return True if self.db_id else False
    
# ------------------------------------------------------------------
# Findings helpers
# ------------------------------------------------------------------

    def _exportFindings(self, stage: str, workDir: str | None = None,
                        probeResult: ProbeResult | None = None,
                        kernelPath: str = "",
                        foundServices: dict | None = None) -> dict:
        if workDir is None:
            workDir = getExportDir(self.workDir, self.tag)
        findings = buildFindings(stage, workDir, self.config.firmwarePath,
                                 self.tag, self.brand, self.architecture, self.endianess,
                                 probeResult, kernelPath, foundServices)
        saveFindings(findings, workDir)
        saveFindingsToDB(findings, self.config.sqlIP, self.config.sqlPort, self.db_id)
        return findings


    def _loadFindings(self) -> dict | None:
        findings = loadFindings(self.workDir, self.tag)
        if not findings:
            logger.error("No findings found — run in check mode first")
            return None
        if findings.get("stage") != "success":
            logger.error(
                f"Cannot boot — findings stage is '{findings.get('stage', 'unknown')}', "
                f"not 'success'. Run in check mode first."
            )
            return None
        return findings

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
    
# ------------------------------------------------------------------
# Extraction and Info Collection
# ------------------------------------------------------------------

    def extract(self) -> bool:
        logger.info(f"Extracting firmware image: {self.config.firmwarePath}")

        result = extract(self.config.firmwarePath, self.imagePath, kernel=False)[0]
        if not result["status"]:
            logger.error(f"Failed to extract filesystem from {self.config.firmwarePath}")
            if self.config.sqlIP and self.db_id:
                updateImageField(self.db_id, "rootfs_extracted", "false", self.config.sqlIP, self.config.sqlPort)
            return False
        else:
            if self.config.sqlIP and self.db_id:
                updateImageField(self.db_id, "rootfs_extracted", "true", self.config.sqlIP, self.config.sqlPort)
                
        self.filesystemPath = str(result["rootfsPath"])
        logger.info(f"Root filesystem extracted to: {self.filesystemPath}")

        result = extract(self.config.firmwarePath, self.imagePath, filesystem=False)[0]
        if not result["status"]:
            logger.warning(f"Failed to extract kernel from {self.config.firmwarePath}")
            if self.config.sqlIP and self.db_id:
                updateImageField(self.db_id, "kernel_extracted", "false", self.config.sqlIP, self.config.sqlPort)
        else:            
            self.kernelPath = str(result["kernelPath"])
            if self.config.sqlIP and self.db_id:
                updateImageField(self.db_id, "kernel_extracted", "true", self.config.sqlIP, self.config.sqlPort)
            logger.info(f"Kernel extracted to: {self.kernelPath}")

        return True
    
    def inferArchitecture(self):
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot infer architecture.")
            return False

        self.architecture, self.endianess = checkArch(self.filesystemPath, self.tag)

        if self.architecture == Architecture.UNKNOWN or self.endianess == Endianess.UNKNOWN:
            logger.error("Failed to determine architecture or endianness.")
            return False

        self._updateDbField("arch", str(self.architecture) + str(self.endianess))
        logger.info(f"Architecture: {self.architecture}, Endianness: {self.endianess}")
        return True
    
    def inferKernelInfo(self):
        # Infer the kernel info from the kernel image
        logger.info(f"Inferring kernel info for firmware: {self.config.firmwarePath}")
        
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
            self._updateDbField("kernel_version", self.kernelVersion)

        return True

    def collectInfo(self):
        logger.info(f"Collecting information for firmware: {self.config.firmwarePath}")

        if not self.filesystemPath:
            logger.error("Extraction must be run before collecting information.")
            return False

        # Check architecture and endianess
        if not self.inferArchitecture():
            logger.error("Failed to infer architecture.")
            return False
        
        if self.kernelPath:
            if not self.inferKernelInfo():
                logger.warning("Failed to infer kernel info.")

        return True

    # ------------------------------------------------------------------
    # Modes
    # ------------------------------------------------------------------

    def explore(self) -> dict | None:
        logger.info(f"Running emulator for firmware: {self.config.firmwarePath}")
        
        # Register image to DB
        if self.config.sqlIP:
            if not self.registerImageInDB():
                logger.error("Failed to register image in database. Skipping database updates for this firmware.")
                self.config.sqlIP = None  # Avoid further DB attempts for this firmware
        else:
            logger.info("No database configured, skipping image registration. No further DB updates will be possible for this firmware.")

        logger.info(f"Step 1: Extracting firmware image {self.config.firmwarePath}")
        if not self.extract():
            logger.error("Extraction failed, aborting emulator run.")
            self._exportFindings("extraction_failed")
            return

        if not self.collectInfo():
            logger.error("Failed to collect information, aborting emulator run.")
            self._exportFindings("collect_info_failed")
            return

        if not checkCompatibility(self.architecture, self.endianess):
            logger.error(f"Incompatible architecture or endianess: {self.architecture}, {self.endianess}")
            self._exportFindings("incompatible_arch")
            return

        if self.config.sqlIP :
            if not self.dumpObjectsToDB():
                logger.error("Failed to dump objects to database.")
                self._exportFindings("db_dump_failed")
                return None

        logger.info("Step 2: preparing image for emulation")

        workDir = self.getWorkDir()

        findingsPath = os.path.join(workDir, "findings.json")
        if os.path.exists(findingsPath) and os.path.isfile(findingsPath):
            with open(findingsPath) as f:
                existing = json.load(f)
            stage = existing.get("stage", "unknown")
            logger.warning(f"Existing findings found at {findingsPath} with stage '{stage}'")
            if stage == "success":
                logger.warning("Previous run was successful — reusing findings and skipping preparation.")
                return existing
            else:
                logger.info("Waiting 5 seconds before overwriting existing findings...")
                sleep(5)
    
        self._cleanupWorkDir()

        createRawImg(os.path.join(workDir, "raw.img"), 1 * GIGA)
        os.makedirs(os.path.join(workDir, "mnt"), exist_ok=True)

        with mountedImage(os.path.join(workDir, "raw.img"), os.path.join(workDir, "mnt")) as mp:
            self.extractFs(mp)

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
            self._exportFindings("prepare_failed", workDir=workDir)
            return

        foundInits, foundServices = res

        logger.info(f"Step 3: probing emulation with {len(foundInits)} init candidates and {len(foundServices)} found services")

        pre = PreEmulator(
            os.path.join(workDir, "raw.img"),
            foundInits,
            len(foundServices) > 0,
            self.architecture,
            self.endianess,
            self.kernelVersion,
            self.config.binariesPath,
            os.path.join(workDir, "mnt"),
            workDir,
        )
        probeResult = pre.start()

        if probeResult is None:
            logger.error("Pre-emulation probe failed for all inits — aborting.")
            self._exportFindings("probe_failed", workDir=workDir, foundServices=foundServices)
            return

        nr = probeResult.networkResult
        logger.info(
            f"Network ready: type={nr.networkType} "
            f"bridge={nr.netBridge} iface={nr.netInterface} "
            f"userNet={nr.isUserNetwork} "
            f"ping={probeResult.pingReachable} service={probeResult.serviceReachable}"
        )
        if nr.hostIps:
            logger.info(f"Host IPs: {', '.join(nr.hostIps)}")

        logger.info(f"Step 4: exporting findings")

        status = "success" if probeResult.serviceReachable else "partial_success"

        return self._exportFindings(status, workDir=workDir,
                                    probeResult=probeResult,
                                    kernelPath=pre.getKernelPath(),
                                    foundServices=foundServices)

    def boot(self) -> None:
        findings = self._loadFindings()
        if not findings:
            return
        result = buildQemuFromFindings(findings)
        if not result:
            return
        qemu, initArg, workDir, networkResult = result
        if not self._applyInjection(findings):
            return
        logPath = os.path.join(workDir, "qemu.boot.serial.log")
        self._logAccessInfo(findings)
        logger.info(f"Booting firmware")
        self._runQemu(qemu, initArg, logPath, networkResult, timeout=86400)

    def debug(self) -> None:
        findings = self._loadFindings()
        if not findings:
            return
        result = buildQemuFromFindings(findings, debug=True)
        if not result:
            return
        qemu, initArg, workDir, networkResult = result
        if not self._applyInjection(findings):
            return
        logPath = os.path.join(workDir, "qemu.debug.serial.log")
        self._logAccessInfo(findings)
        logger.info(f"Booting firmware in debug mode (nc:31337, telnet:31338)")
        self._runQemu(qemu, initArg, logPath, networkResult, timeout=86400)

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

