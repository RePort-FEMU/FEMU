import hashlib
import logging
import shutil
import os
import signal
import subprocess
from time import monotonic
from functools import wraps
from contextlib import contextmanager

from .common import Architecture, Endianess, NetworkResult, GIGA
from .qemuInterface import Qemu
from .emulatorConfig import emulatorConfig
from .db import registerImage, updateImageField, getBrandByHash
from .util import (
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

from .imagePreparation import prepareImage
from .preEmulator.preEmulator import PreEmulator
from .preEmulator.emulationVerifier import makeNetworkMonitor
from .findings import Findings, loadFindings, buildQemuFromFindings
from .extraction import extract, analyzeImage

# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger(__name__)


def dbOperation(func):
    """No-op (returns None) when the instance has no database configured."""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.config.sqlIP:
            logger.debug("No DB configured — skipping %s", func.__name__)
            return None
        return func(self, *args, **kwargs)
    return wrapper


class _Timer:
    seconds: float = 0.0


@contextmanager
def timed():
    """Measure wall-clock seconds of the enclosed block; read result from `.seconds`."""
    t = _Timer()
    start = monotonic()
    try:
        yield t
    finally:
        t.seconds = monotonic() - start


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

        # Findings from a previous run of this firmware, if any (used by
        # _ensureFindings to decide whether a mode can proceed without explore).
        self.existingFindings: dict | None = loadFindings(self.workDir, self.tag)

        # Set after extraction
        self.db_id: int | None = None
        self.kernelPath = None
        self.filesystemPath = None

        # Accumulating findings for this run (write path).
        self.findings = Findings(
            self.config.firmwarePath, self.tag, self.brand, self.getWorkDir(),
            sqlIP=self.config.sqlIP, sqlPort=self.config.sqlPort, dbId=self.db_id,
        )

        self.architecture = Architecture.UNKNOWN
        self.endianess    = Endianess.UNKNOWN

        self.kernelVersion = ""
        self.kernelVersionString = ""
        self.inferredKernelInit = []
          
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

    @dbOperation
    def _dumpObjectsToDB(self):
        assert self.config.sqlIP is not None  # guaranteed by @dbOperation
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
            
    @dbOperation
    def _updateDbField(self, field: str, value: str) -> bool:
        assert self.config.sqlIP is not None  # guaranteed by @dbOperation
        if not self.db_id:
            return True
        return updateImageField(self.db_id, field, value, self.config.sqlIP, self.config.sqlPort)

    @dbOperation
    def registerImageInDB(self) -> bool:
        assert self.config.sqlIP is not None  # guaranteed by @dbOperation
        result = registerImage(
            os.path.basename(self.config.firmwarePath),
            self.tag,
            self.brand,
            self.config.sqlIP,
            self.config.sqlPort
        )
        if result is None:
            logger.error("Failed to register image in database. Skipping DB updates for this run.")
            self.config.sqlIP = None
            self.findings.sqlIP = None
            return False
        self.db_id = result
        self.findings.dbId = result
        logger.info(f"Registered image in database with id {self.db_id}.")
        return True
    
# ------------------------------------------------------------------
# Findings helpers
# ------------------------------------------------------------------

    def _ensureFindings(self) -> dict | None:
        """Return successful findings for the boot/debug/analyze modes.

        Uses findings from a previous run if that run succeeded; otherwise runs
        explore() first and uses its result. Returns None if no successful run
        can be obtained.
        """
        if self.existingFindings and self.existingFindings.get("stage") == "success":
            return self.existingFindings

        logger.info("No successful findings for this firmware — running explore first.")
        findings = self.explore()
        if not findings or findings.get("stage") != "success":
            logger.error("Explore did not produce a successful run — cannot continue.")
            return None
        return findings

    def _applyInjection(self, findings: dict) -> bool:
        """Re-apply the init injection that was restored after explore(). Idempotent."""
        inj = findings.get("initInjection", {})
        guestFile = inj.get("modifiedGuestFile")
        content   = inj.get("injectedContent")
        if not guestFile or not content:
            logger.error("No injection information found in findings — cannot apply injection.")
            return False

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
            with open(hostPath, "w") as f:
                f.write(content)
            logger.info(f"Re-applied injection to {guestFile}")
        return True

    # ------------------------------------------------------------------
    # Modes
    # ------------------------------------------------------------------

    def explore(self) -> dict | None:
        logger.info(f"Running emulator for firmware: {self.config.firmwarePath}")

        if self.existingFindings:
            logger.info("Existing findings found — explore will re-run and overwrite them.")

        self.registerImageInDB()

        logger.info(f"Step 1: Extracting firmware image {self.config.firmwarePath}")
        with timed() as extractionTimer:
            extractionResult = extract(self.config.firmwarePath, self.getWorkDir())
            if extractionResult is None:
                logger.error("Failed to extract filesystem — aborting emulator run.")
                self.findings.export("extract_failed")
                return
            self.filesystemPath, self.kernelPath = extractionResult
        self.findings.extractionSeconds = extractionTimer.seconds
        
        imageInfo = analyzeImage(self.filesystemPath, self.kernelPath)
        self.architecture, self.endianess = self.findings.architecture, self.findings.endianness = imageInfo[0]
        self.kernelVersion = self.findings.kernelVersion = imageInfo[1][0] if imageInfo[1] else ""
        self.inferredKernelInit = imageInfo[1][1] if imageInfo[1] else []

        if not checkCompatibility(self.architecture, self.endianess):
            logger.error(f"Incompatible architecture or endianess: {self.architecture}, {self.endianess}")
            self.findings.export("incompatible_arch")
            return

        # no-ops when no DB; False only on a real dump failure
        self._dumpObjectsToDB()

        logger.info("Step 2: preparing image for emulation")

        with timed() as preparationTimer:
            self._cleanupWorkDir()

            createRawImg(os.path.join(self.getWorkDir(), "raw.img"), 1 * GIGA)
            os.makedirs(os.path.join(self.getWorkDir(), "mnt"), exist_ok=True)

            with mountedImage(os.path.join(self.getWorkDir(), "raw.img"), os.path.join(self.getWorkDir(), "mnt")) as mp:
                self.extractFs(mp)

            res = prepareImage(
                os.path.join(self.getWorkDir(), "raw.img"),
                os.path.join(self.getWorkDir(), "mnt"),
                self.architecture,
                self.endianess,
                self.config.binariesPath,
                os.path.join(self.config.scriptsPath, "firmadyne"),
                self.inferredKernelInit
            )
        self.findings.preparationSeconds = preparationTimer.seconds

        if not res:
            logger.error("Failed to prepare image for emulation.")
            self.findings.export("prepare_failed")
            return

        foundInits, foundServices = res
        self.findings.foundServices = foundServices

        logger.info(f"Step 3: probing emulation with {len(foundInits)} init candidates and {len(foundServices)} found services")

        pre = PreEmulator(
            os.path.join(self.getWorkDir(), "raw.img"),
            foundInits,
            len(foundServices) > 0,
            self.architecture,
            self.endianess,
            self.kernelVersion,
            self.config.binariesPath,
            os.path.join(self.getWorkDir(), "mnt"),
            self.getWorkDir(),
        )
        with timed() as preEmulationTimer:
            probeResult = pre.start()
        self.findings.preEmulationSeconds = preEmulationTimer.seconds

        if probeResult is None:
            logger.error("Pre-emulation probe failed for all inits — aborting.")
            self.findings.export("probe_failed")
            return

        nr = probeResult.networkResult
        reached = [c.label() for c in probeResult.reachedServices] or ["none"]
        logger.info(
            f"Network ready: type={nr.networkType} "
            f"bridge={nr.netBridge} iface={nr.netInterface} "
            f"userNet={nr.isUserNetwork} "
            f"web={probeResult.webReachable} reached={reached}"
        )
        if nr.hostIps:
            logger.info(f"Host IPs: {', '.join(nr.hostIps)}")

        logger.info(f"Step 4: exporting findings")

        # Full success only when a web server responds; any other reachable
        # service (or ping-only) is a partial success.
        status = "success" if probeResult.webReachable else "partial_success"

        self.findings.probeResult = probeResult
        self.findings.kernelPath = pre.getKernelPath()
        return self.findings.export(status)

    def boot(self) -> None:
        findings = self._ensureFindings()
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
        findings = self._ensureFindings()
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
        findings = self._ensureFindings()
        if not findings:
            return
        fw  = findings["firmware"]
        net = findings["network"]
        logger.info(f"Firmware : {fw['path']}  iid={fw['iid']}  brand={fw['brand']}")
        logger.info(f"Network  : type={net['networkType']}  userNet={net['isUserNetwork']}")
        logger.info(f"IPs      : {[c['ip'] for c in net['candidates']]}")
        logger.info(f"Ports    : {net['ports']}")
        logger.info("Full analysis tooling not yet implemented")

