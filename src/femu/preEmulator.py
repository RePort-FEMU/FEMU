import subprocess
import tempfile
import logging
import ipaddress
import os

from typing import Optional

from .util import mountedImage
from .guestUtils import hostToGuestPath, guestToHostPath, readGuestLink
from .common import Endianess, Architecture, NetworkResult, ProbeResult
from .qemuInterface import Qemu
from .kernelLogUtils import findBridges, findInterfaceIps, findPorts, findMacChanges, findVLANs
from .emulationVerifier import verifyEmulation
from .nvramInfer import inferNvramDefaults

TIMEOUT = 300  # probe run timeout (5 minutes)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network classification helpers
# ---------------------------------------------------------------------------

def isValidLanIp(ip: str) -> bool:
    """Return True for a usable RFC 1918 unicast address (not network/broadcast)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return False
        octets = ip.split(".")
        if octets[-1] in ("0", "255"):
            return False
        return addr.is_private
    except ValueError:
        return False


def isDhcpLike(ip: str) -> bool:
    """Return True for IPs that are likely DHCP-assigned rather than static LAN addresses."""
    if ip.startswith("10.0.2."):   # QEMU user-mode SLIRP range
        return True
    if ip.startswith("169.254."):  # APIPA / failed DHCP
        return True
    if ip.endswith(".190"):        # Netgear DHCP quirk
        return True
    return False


def computeHostIp(guestIp: str) -> str:
    """
    Derive a usable host-side IP from the guest IP.
    Avoids .0 (network address) for the common .1 guest case.
    """
    octets = guestIp.split(".")
    last = int(octets[-1])
    octets[-1] = "2" if last == 1 else str(last - 1)
    return ".".join(octets)


def classifyNetwork(candidates: list, ports: list) -> NetworkResult:
    """
    Classify pre-emulation network candidates into a NetworkResult.

    Improvements over FirmAE's checkNetwork():
    - Uses bridge==interface as the proxy for "no physical member found in log"
      instead of checking whether the name starts with 'eth'.
    - Proper RFC 1918 + unicast validity check instead of .endswith(".0.0.0").
    - Unified DHCP detection (QEMU SLIRP, APIPA, known quirks) applied
      consistently in one place.
    - DHCP-only → user networking; mixed static+DHCP → drop DHCP (WAN side).
    - Unmatched interface slots fall back to user networking, not dead sockets.
    """
    candidates = [c for c in candidates if c[1] != "lo"]

    if not candidates:
        return NetworkResult(
            "default", "br0", "eth0",
            [("192.168.0.1", "eth0", "br0", [], [])],
            ports, False, ["192.168.0.2"],
        )

    # When both eth* (WAN/physical) and bridge interfaces are present, the eth*
    # ones are the WAN side even if they carry a static IP — keep only bridges.
    # wnr2000v4-V1.0.0.70.zip - mipseb
    # [('192.168.1.1', 'br0', None, None, 'br0'), ('10.0.2.15', 'eth0', None, None, 'br1')]
    # R6900
    # [('192.168.1.1', 'br0', None, None, 'br0'), ('20.45.150.190', 'eth0', None, None, 'eth0')]
    devs = {c[1] for c in candidates}
    if any(d.startswith("eth") for d in devs) and any(not d.startswith("eth") for d in devs):
        candidates = [c for c in candidates if not c[1].startswith("eth")]

    static = [c for c in candidates if not isDhcpLike(c[0])]
    dhcp   = [c for c in candidates if     isDhcpLike(c[0])]

    # Mixed static+DHCP: discard DHCP entries (they are the WAN interface)
    working = static if static else dhcp
    isUserNetwork = not bool(static)

    if isUserNetwork:
        return NetworkResult("default", "br0", "eth0", dhcp, ports, True, [])

    # bridge != iface  →  physical eth member found in log, bridge owns the IP
    # bridge == iface  →  no member logged yet; firmware will add eth0 later
    valid_bridged   = [c for c in working if c[2] != c[1] and     isValidLanIp(c[0])]
    valid_direct    = [c for c in working if c[2] == c[1] and     isValidLanIp(c[0])]
    invalid_bridged = [c for c in working if c[2] != c[1] and not isValidLanIp(c[0])]
    invalid_direct  = [c for c in working if c[2] == c[1] and not isValidLanIp(c[0])]

    ethPool = ["eth0", "eth1", "eth2", "eth3"]

    if valid_bridged:
        hostIps = [computeHostIp(c[0]) for c in valid_bridged]
        chosen = valid_bridged[0]
        return NetworkResult("normal", chosen[2], chosen[1], valid_bridged, ports, False, hostIps)

    if valid_direct:
        # Bridge has the IP but eth0 hasn't joined it yet in the log.
        # Replace interface name with ethX because QEMU NICs are always ethN.
        adjusted = [
            (ip, ethPool[i], bridge, vlans, macs)
            for i, (ip, _, bridge, vlans, macs) in enumerate(valid_direct)
            if i < len(ethPool)
        ]
        hostIps = [computeHostIp(c[0]) for c in adjusted]
        chosen = adjusted[0]
        return NetworkResult("bridge", chosen[2], chosen[1], adjusted, ports, False, hostIps)

    if invalid_bridged:
        adjusted = [("192.168.0.1", iface, bridge, vlans, macs)
                    for _, iface, bridge, vlans, macs in invalid_bridged]
        chosen = adjusted[0]
        return NetworkResult("reload", chosen[2], chosen[1], adjusted, ports, False,
                             ["192.168.0.2"] * len(adjusted))

    if invalid_direct:
        adjusted = [
            ("192.168.0.1", ethPool[i], bridge, vlans, macs)
            for i, (_, _, bridge, vlans, macs) in enumerate(invalid_direct)
            if i < len(ethPool)
        ]
        chosen = adjusted[0]
        return NetworkResult("bridgereload", chosen[2], chosen[1], adjusted, ports, False,
                             ["192.168.0.2"] * len(adjusted))

    return NetworkResult(
        "default", "br0", "eth0",
        [("192.168.0.1", "eth0", "br0", [], [])],
        ports, False, ["192.168.0.2"],
    )


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

        self.partialResult: Optional[ProbeResult] = None  # Incase ping-only success after exhausting all inits

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

    def _wrappingInjection(self, filePath: str, extraContent: str = "") -> str:
        """Inject content into a script file, preserving the original content."""
        preInjection = "#!/bin/sh\n"
        preInjection += "\n# Injected by PreEmulator\n"
        preInjection += "/firmadyne/preInit.sh\n"
        if extraContent:
            preInjection += extraContent
        preInjection += "/firmadyne/network.sh &\n"
        if self.servicesFound:
            preInjection += "/firmadyne/run_service.sh &\n"
        preInjection += "/firmadyne/debug.sh &\n"
        preInjection += "\n/firmadyne/busybox sleep 36000\n"
        preInjection += "\n# End of injection\n"
        
        postInjection = "\n# Post-injection content\n"
        postInjection += "\n/firmadyne/busybox sleep 36000\n"

        try:
            with open(filePath, "r", errors="replace") as f:
                content = f.read()
            with open(filePath, "w") as f:
                f.write(preInjection + content + postInjection)
        except Exception as e:
            logger.error(f"Failed to inject into script {filePath}: {e}")
            raise

        return preInjection + content + postInjection
    
    def _appendingInjection(self, filePath: str, extraContent: str = "") -> str:
        """Inject content by appending to the end of the file."""
        injection = "\n# Injected by PreEmulator\n"
        injection += "/firmadyne/busybox echo 'Init injected by PreEmulator'\n"
        if extraContent:
            injection += extraContent
        injection += "/firmadyne/network.sh &\n"
        if self.servicesFound:
            injection += "/firmadyne/run_service.sh &\n"
        injection += "/firmadyne/debug.sh &\n"
        injection += "/firmadyne/busybox echo 'Entering long sleep to keep init running'\n"
        injection += "/firmadyne/busybox sleep 36000\n"

        try:
            with open(filePath, "r", errors="replace") as f:
                content = f.read()
            with open(filePath, "a") as f:
                f.write(injection)
        except Exception as e:
            logger.error(f"Failed to inject into {filePath}: {e}")
            raise

        return content + injection

    def injectInit(self, init: str) -> tuple[str, str]:
        """Inject firmadyne scripts into the init and return the kernel init argument and injection content."""

        initType = self.getInitType(guestToHostPath(self.mountPoint, init))
        logger.info(f"Injecting init {init} (type: {initType}) into {self.imagePath}")

        initArg = ""
        injection = ""

        if os.path.basename(init) == "preInit.sh":
            self.backupFile = init
            self.backupData = open(guestToHostPath(self.mountPoint, self.backupFile), "r", errors="replace").read()
            injection = self._appendingInjection(guestToHostPath(self.mountPoint, init))
            initArg = f"init={init}"
        else:
            # FIRMAE diff
            # TODO: Check if this can work
            # If the init is a symlink try to dereference it
            dereferencedInit = init
            visited: set[str] = {init}
            while os.path.islink(guestToHostPath(self.mountPoint, dereferencedInit)):
                resolved = readGuestLink(dereferencedInit, self.mountPoint, translateToHost=False)
                if resolved in visited:
                    logger.warning(f"Circular symlink detected at {dereferencedInit} → {resolved}, stopping")
                    break
                visited.add(resolved)
                dereferencedInit = resolved
            
            if dereferencedInit != init and os.path.isfile(guestToHostPath(self.mountPoint, dereferencedInit)):
                logger.debug(f"Init {init} is a symlink to {dereferencedInit} (type: {self.getInitType(guestToHostPath(self.mountPoint, dereferencedInit))})")
            
            # TODO: improve script detection
            if "ELF" not in initType and "symbolic link" not in initType: # script init
                self.backupFile = init
                self.backupData = open(guestToHostPath(self.mountPoint, self.backupFile), "r", errors="replace").read()
                injection = self._wrappingInjection(guestToHostPath(self.mountPoint, init))
                initArg = f"init={init}" 
            elif "ELF" in initType or "symbolic link" in initType: # netgear R6200 
                self.backupFile = "/firmadyne/preInit.sh"
                self.backupData = open(guestToHostPath(self.mountPoint, self.backupFile), "r", errors="replace").read()
                injection = self._appendingInjection(guestToHostPath(self.mountPoint, self.backupFile), f"exec {init} &\n")
                initArg = "init=/firmadyne/preInit.sh"

        # FIRMAE diff: Firmae only used init= for binaries. We use it for everything
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
             (ping + TCP ports), mirroring FirmAE's check_emulation.sh.
          6. Always restores the injected init before returning.
          7. On success: return ProbeResult. On failure: try the next init.
        """
        logger.info(f"Starting pre-emulator for {self.imagePath} with inits {self.possibleInits}")

        for init in self.possibleInits:
            logger.info(f"Processing init: {init}")

            # --- inject ---
            with mountedImage(self.imagePath, self.mountPoint) as mp:
                try:
                    initArg, injectedContent = self.injectInit(init)
                except Exception as e:
                    logger.error(f"Failed to inject init {init}: {e}")
                    continue

            # --- probe: network.sh reads "None" and does nothing ---
            self._writeNetworkFiles({
                "network_type":  "None",
                "net_bridge":    "",
                "net_interface": "",
            })

            os.makedirs(os.path.join(self.workDir, "kernelLogs"), exist_ok=True)
            probeLog = os.path.join(
                self.workDir, "kernelLogs",
                f"qemu.{init[1:].replace('/', '-')}.serial.log",
            )
            logger.info(f"Running probe QEMU with initarg: {initArg}")
            try:
                self.qemu.run(initArg, probeLog, timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.info(f"Probe timed out after {TIMEOUT}s")

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
            pingReachable, serviceReachable = verifyEmulation(
                initArg, networkResult, self.workDir, self.qemu.run)
            self._restoreBackupIfNeeded()

            if pingReachable:
                logger.info(f"Init {init} produced a ping-reachable emulation")
                self.partialResult = ProbeResult(initArg, networkResult, self.backupFile, injectedContent,
                                                 pingReachable=pingReachable, serviceReachable=serviceReachable)

            if serviceReachable:
                return ProbeResult(initArg, networkResult, self.backupFile, injectedContent,
                                   pingReachable=pingReachable, serviceReachable=serviceReachable)

            logger.warning(f"Init {init} did not produce a reachable device — trying next")

        if self.partialResult:
            logger.warning(f"No init produced a fully reachable emulation, but at least one was ping-reachable. Returning partial result.")
            return self.partialResult
        
        logger.error(f"All inits exhausted without producing a reachable emulation")
        return None