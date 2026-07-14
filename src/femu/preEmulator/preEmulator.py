import subprocess
import tempfile
import logging
import os

from typing import Optional

from ..util import mountedImage
from ..imagePreparation import hostToGuestPath, guestToHostPath, readGuestLink
from ..common import Endianess, Architecture, ProbeResult, FREEZE_RETRIES
from ..qemuInterface import Qemu
from .kernelLogUtils import findBridges, findInterfaceIps, findPorts, findMacChanges, findVLANs
from .emulationVerifier import verifyEmulation
from .nvramInfer import inferNvramDefaults
from .networkClassifier import classifyNetwork

TIMEOUT = 300  # probe run timeout (5 minutes)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result ranking
# ---------------------------------------------------------------------------

def _partialScore(result: ProbeResult) -> tuple[int, int]:
    """Rank reachable-but-not-web results: prefer ones that reached a real TCP
    service over ping-only, then more reached targets overall."""
    reached = result.reachedServices
    services = sum(1 for c in reached if c.kind != "ping")
    return (services, len(reached))


# ---------------------------------------------------------------------------
# Injection Utils
# ---------------------------------------------------------------------------

def injectFile(filePath: str, before: str = "", after: str = "") -> str:
    """
    Wrap the file's content as `before + content + after` and return the
    result. With no `before`, `after` is appended in place; otherwise the
    whole file is rewritten.
    """
    try:
        with open(filePath, "r", errors="replace") as f:
            content = f.read()
        if before:
            with open(filePath, "w") as f:
                f.write(before + content + after)
        else:
            with open(filePath, "a") as f:
                f.write(after)
    except Exception as e:
        logger.error(f"Failed to inject into {filePath}: {e}")
        raise
    return before + content + after

# ---------------------------------------------------------------------------
# PreEmulator
# ---------------------------------------------------------------------------

class PreEmulator:
    def __init__(self, imagePath: str, possibleInits: list[str], servicesFound: bool,
                 arch: Architecture, endiannes: Endianess,  kernelVersion: str, 
                 kernelsPath: str, mountPoint: str = "", workDir: str = ""):

        self.imagePath = imagePath
        self.possibleInits = possibleInits
        self.architecture = arch
        self.endiannes = endiannes
        self.kernelVersion = kernelVersion
        self.servicesFound = servicesFound
        self.kernelsPath = kernelsPath
        
        if len(self.possibleInits) == 0:
            raise ValueError("No possible inits provided")

        self.mountPoint = mountPoint or tempfile.mkdtemp(prefix="femu-mount-", dir="/tmp")
        self.workDir    = workDir    or tempfile.mkdtemp(prefix="femu-work-",  dir="/tmp")

        self.backupFile: str | None = None
        self.backupData: str | None = None
        self.qemu = Qemu(self.imagePath, self.architecture, self.endiannes,
                         self.getKernelPath(), self.workDir, debug=False)

    def getInitType(self, init: str) -> str:
        """Run the file command to determine the init type."""
        res = subprocess.run(["file", "-b", init], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to run file command on {init}: {res.stderr.strip()}")
        if "No such file or directory" in res.stdout.strip():
            raise FileNotFoundError(f"File {init} not found")
        return res.stdout.strip()

    def injectedHelpers(self, withService: bool = True) -> str:
        """Background helper launches shared by the injection variants."""
        lines = "/firmadyne/network.sh &\n"
        if withService and self.servicesFound:
            lines += "/firmadyne/run_service.sh &\n"
        lines += "/firmadyne/debug.sh &\n"
        return lines

    def _preInitInjection(self, filePath: str) -> str:
        """Cold-launch fallback (rdinit=/firmadyne/preInit.sh): append helpers + run_service.sh, then idle."""
        injection = ("\n# Injected by PreEmulator\n"
                     + self.injectedHelpers()
                     + "/firmadyne/busybox sleep 36000\n")
        return injectFile(filePath, after=injection)

    def _scriptInitInjection(self, filePath: str) -> str:
        """Script init: append the firmadyne helpers to the end of the original
        script (original append style; preInit.sh is cold-launched via rdinit)."""
        injection = ("\n# Injected by PreEmulator\n"
                     + self.injectedHelpers()
                     + "/firmadyne/busybox sleep 36000\n")
        return injectFile(filePath, after=injection)
    
    def _nativeInitInjection(self, filePath: str, init: str) -> str:
        """Binary init: setup network and hand over PID 1 to the init."""
        # Many Linksys devices require init to have PID 1 to work
        injection = ("\n# Injected by PreEmulator\n"
                     + self.injectedHelpers(withService=False) # Dont force the service up as it may break init
                     + f"exec {init}\n")
        return injectFile(filePath, after=injection)

    def injectInit(self, init: str) -> tuple[str, str]:
        """Inject firmadyne scripts into the init and return the kernel init argument and injection content."""

        initType = self.getInitType(guestToHostPath(self.mountPoint, init))
        logger.info(f"Injecting init {init} (type: {initType}) into {self.imagePath}")

        initArg = ""
        injection = ""

        if os.path.basename(init) == "preInit.sh":
            self.backupFile = init
            self.backupData = open(guestToHostPath(self.mountPoint, self.backupFile), "r", errors="replace").read()
            injection = self._preInitInjection(guestToHostPath(self.mountPoint, init))
            initArg = "rdinit=/firmadyne/preInit.sh"
        else:
            # TODO: improve script detection
            if "ELF" not in initType and "symbolic link" not in initType: # script init
                self.backupFile = init
                self.backupData = open(guestToHostPath(self.mountPoint, self.backupFile), "r", errors="replace").read()
                injection = self._scriptInitInjection(guestToHostPath(self.mountPoint, init))
                initArg = "rdinit=/firmadyne/preInit.sh"
            elif "ELF" in initType or "symbolic link" in initType: # binary/symlinked native init (e.g. /sbin/init -> rc or -> busybox)
                self.backupFile = "/firmadyne/preInit.sh"
                self.backupData = open(guestToHostPath(self.mountPoint, self.backupFile), "r", errors="replace").read()
                injection = self._nativeInitInjection(guestToHostPath(self.mountPoint, self.backupFile), init)
                initArg = "init=/firmadyne/preInit.sh"

        # FIRMAE diff: script inits (script + preInit fallback) boot via rdinit=/firmadyne/preInit.sh;
        # only native/ELF inits keep init=/firmadyne/preInit.sh (old behavior)
        return initArg, injection

    def getKernelPath(self) -> str:
        """Return the emulation kernel path for the current architecture."""
        # TODO: It seems like kernel 4 is much better on running all the images investigate !
        if self.architecture == Architecture.ARM:
            return os.path.join(self.kernelsPath, "zImage.armel")
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.BIG:
            # if self.kernelVersion.strip().startswith("2."):
            #     return os.path.join(self.kernelsPath, "vmlinux.mipseb.2")
            # else: # default to 4.x for MIPS if version inference fails or is inconclusive
            #     return os.path.join(self.kernelsPath, "vmlinux.mipseb.4")
            return os.path.join(self.kernelsPath, "vmlinux.mipseb.4")
        elif self.architecture == Architecture.MIPS and self.endiannes == Endianess.LITTLE:
            # if self.kernelVersion.strip().startswith("2."):
            #     return os.path.join(self.kernelsPath, "vmlinux.mipsel.2")
            # else: # default to 4.x for MIPS if version inference fails or is inconclusive
            #     return os.path.join(self.kernelsPath, "vmlinux.mipsel.4")
            return os.path.join(self.kernelsPath, "vmlinux.mipsel.4")
        raise ValueError("Unsupported architecture or endianness")

    def getNetworkInfo(self, kernelLogPath: str) -> tuple[list, list]:
        """Parse a kernel log and return (ports, configCandidates)."""
        logger.debug(f"Reading kernel log: {kernelLogPath}")
        # TODO: Consider using binary read
        with open(kernelLogPath, "r", errors="replace") as f:
            kernelLog = f.readlines()

        ports = findPorts(kernelLog)
        logger.info(f"Found {len(ports)} ports in kernel log")

        ips = findInterfaceIps(kernelLog, self.endiannes)
        logger.info(f"Found {len(ips)} interfaces with IPs")

        macChanges = findMacChanges(kernelLog, self.endiannes)
        bridges    = findBridges(kernelLog)
        vlans      = findVLANs(kernelLog)

        configCandidates = []
        for interface, addr in ips:
            if interface == "lo":
                continue

            cleanIface = interface.split(".")[0]
            relatedBridges = [
                bridge for bridge, ifaces in bridges.items()
                if cleanIface in [iface.split(".")[0] for iface in ifaces]
            ]

            candidateFound = False
            for bridge in relatedBridges:
                relatedVlans = list({
                    vid
                    for iface, vids in vlans.items()
                    if iface.split(".")[0] in (bridge.split(".")[0], cleanIface)
                    for vid in vids
                })
                possibleMacs = list(macChanges.get(interface, []))
                for m in macChanges.get(bridge, []):
                    if m not in possibleMacs:
                        possibleMacs.append(m)

                candidate = (addr, interface, bridge, relatedVlans, possibleMacs)
                if candidate not in configCandidates:
                    configCandidates.append(candidate)
                    candidateFound = True

            if not candidateFound:
                relatedVlans  = list(vlans.get(interface, []))
                possibleMacs  = list(macChanges.get(interface, []))
                candidate = (addr, interface, interface, relatedVlans, possibleMacs)
                if candidate not in configCandidates:
                    configCandidates.append(candidate)

        return ports, configCandidates

    def _writeNetworkFiles(self, config: dict[str, str]) -> None:
        """Mount the image and write /firmadyne/network_type, net_bridge, net_interface."""
        with mountedImage(self.imagePath, self.mountPoint) as mp:
            for filename, value in config.items():
                path = os.path.join(mp, "firmadyne", filename)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(value)
        logger.debug(f"Written network files: {config}")

    def _restoreBackupIfNeeded(self) -> None:
        """Restore the injected init file. Called when an init attempt fails."""
        if self.backupFile and self.backupData is not None:
            with mountedImage(self.imagePath, self.mountPoint) as mp:
                with open(guestToHostPath(mp, self.backupFile), "w") as f:
                    f.write(self.backupData)
            logger.debug(f"Restored original init: {self.backupFile}")
        self.backupFile = None
        self.backupData = None

    def start(self) -> Optional[ProbeResult]:
        """
        For each possible init, run the full pre-emulation pipeline:
          1. Inject network.sh into the init script.
          2. Probe QEMU run (network_type="None" — no bridging).
          3. Classify the network from the probe log.
          4. Write final network config files into the image.
          5. Verify run: boot with the classified config and check reachability
             (ping + TCP/HTTP ports), mirroring FirmAE's check_emulation.sh.
          6. Always restores the injected init before returning.
          7. Return as soon as an init is web-reachable (full success). Otherwise
             keep the best reachable-but-not-web result and try the next init,
             returning that partial at the end (or None if nothing was reachable).
        """
        logger.info(f"Starting pre-emulator for {self.imagePath} with inits {self.possibleInits}")

        bestResult: Optional[ProbeResult] = None

        for init in self.possibleInits:
            logger.info(f"Processing init: {init}")

            # --- inject ---
            with mountedImage(self.imagePath, self.mountPoint) as mp:
                try:
                    initArg, injectedContent = self.injectInit(init)
                    injectedFile = self.backupFile
                except Exception as e:
                    logger.error(f"Failed to inject init {init}: {e}")
                    continue

            os.makedirs(os.path.join(self.workDir, "kernelLogs"), exist_ok=True)
            probeLog = os.path.join(
                self.workDir, "kernelLogs",
                f"qemu.{init[1:].replace('/', '-')}.serial.log",
            )

            # --- probe: network.sh reads "None" and does nothing ---
            self._writeNetworkFiles({
                "network_type":  "None",
                "net_bridge":    "",
                "net_interface": "",
            })

            logger.info(f"Running probe QEMU with initarg: {initArg}")
            # Retry on a BUSY/spin freeze (a race — a fresh boot often clears it).
            # Non-final attempts stop early on a freeze; the last attempt lets the
            # guest run the full TIMEOUT regardless, in case it makes progress.
            for attempt in range(FREEZE_RETRIES + 1):
                is_last = attempt == FREEZE_RETRIES
                try:
                    froze = self.qemu.run(initArg, probeLog, timeout=TIMEOUT,
                                          stop_on_freeze=not is_last)
                except subprocess.TimeoutExpired:
                    logger.info(f"Probe timed out after {TIMEOUT}s")
                    froze = False
                if not froze:
                    break
                logger.warning(f"Probe wedged (BUSY/spin freeze) — "
                               f"retry {attempt + 1}/{FREEZE_RETRIES}")

            inferNvramDefaults(self.imagePath, self.mountPoint, probeLog, self.workDir)

            # --- classify ---
            ports, candidates = self.getNetworkInfo(probeLog)
            for addr, iface, bridge, vlns, macs in candidates:
                logger.debug(f"  candidate: iface={iface} addr={addr} bridge={bridge} "
                             f"vlans={vlns} macs={macs}")

            networkResult = classifyNetwork(candidates, ports)
            logger.info(
                f"Network classified: type={networkResult.networkType} "
                f"bridge={networkResult.netBridge} iface={networkResult.netInterface} "
                f"userNet={networkResult.isUserNetwork}"
            )

            # --- write final config ---
            self._writeNetworkFiles({
                "network_type":  networkResult.networkType,
                "net_bridge":    networkResult.netBridge,
                "net_interface": networkResult.netInterface,
            })

            # --- verify reachability (mirrors check_emulation.sh) ---
            reachable, checks = verifyEmulation(
                initArg, networkResult, self.workDir, self.qemu.run, init=init)
            self._restoreBackupIfNeeded()

            result = ProbeResult(initArg, networkResult, injectedFile, injectedContent,
                                 reachable=reachable, checks=checks)

            if result.webReachable:
                logger.info(f"Init {init} produced a web-reachable emulation (full success)")
                return result

            if reachable and (bestResult is None or _partialScore(result) > _partialScore(bestResult)):
                bestResult = result
                logger.info(f"Init {init} reachable but no web server — keeping as best partial")

            logger.warning(f"Init {init} did not produce a web-reachable device — trying next")

        if bestResult:
            logger.warning("No init produced a web-reachable emulation; returning best partial "
                           f"(reached: {[c.label() for c in bestResult.reachedServices]})")
            return bestResult

        logger.error(f"All inits exhausted without producing a reachable emulation")
        return None