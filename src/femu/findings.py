import json
import logging
import os

from .common import Architecture, Endianess, NetworkResult, ProbeResult
from .dbInterface import DBInterface
from .qemuInterface import Qemu

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

def getExportDir(workDir: str, tag: str) -> str:
    path = os.path.join(workDir, tag)
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Findings — accumulate state, then build/export at any point
# ---------------------------------------------------------------------------

class Findings:
    """Mutable holder for a firmware run's findings.

    Set fields as they become known during emulation, then call ``export()``
    at any stage to build the JSON, write ``findings.json`` and (if a database
    is configured) upsert the emulation record. ``build()`` returns the same
    dict without any side effects.
    """

    def __init__(self, firmwarePath: str, tag: str, brand: str, workDir: str, *,
                 sqlIP: str | None = None, sqlPort: int = 5432,
                 dbId: int | None = None) -> None:
        # Identity / target (set once)
        self.firmwarePath = firmwarePath
        self.tag = tag
        self.brand = brand
        self.workDir = workDir
        self.sqlIP = sqlIP
        self.sqlPort = sqlPort
        self.dbId = dbId

        # Accumulated state (set as the run progresses)
        self.stage: str = "unknown"
        self.architecture: Architecture = Architecture.UNKNOWN
        self.endianness: Endianess = Endianess.UNKNOWN
        self.kernelPath: str = ""
        self.kernelVersion: str = ""
        self.probeResult: ProbeResult | None = None
        self.foundServices: dict | None = None
        self.extractionSeconds: float | None = None
        self.preparationSeconds: float | None = None
        self.preEmulationSeconds: float | None = None

    # -- build -------------------------------------------------------------

    def build(self) -> dict:
        """Assemble the findings dict from whatever has been set so far."""
        findings: dict = {
            "stage": self.stage,
            "firmware": {
                "path": self.firmwarePath,
                "tag": self.tag,
                "brand": self.brand,
            },
        }

        if self.architecture != Architecture.UNKNOWN:
            findings["emulation"] = {
                "imagePath": os.path.join(self.workDir, "raw.img"),
                "architecture": str(self.architecture),
                "endianness": str(self.endianness),
                "kernelPath": self.kernelPath,
                "kernelVersion": self.kernelVersion,
                "initArg": self.probeResult.initArg if self.probeResult else "",
                "workDir": self.workDir,
            }

        if self.probeResult:
            pr = self.probeResult
            findings["initInjection"] = {
                "modifiedGuestFile": pr.modifiedGuestFile,
                "injectedContent": pr.injectedContent,
            }
            nr = pr.networkResult
            findings["network"] = {
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
                "reachability": {
                    "reachable": pr.reachable,
                    "webReachable": pr.webReachable,
                    "checks": [
                        {"ip": c.ip, "port": c.port, "kind": c.kind,
                         "reachable": c.reachable, "responseTime": c.responseTime}
                        for c in pr.checks
                    ],
                },
            }

        if self.foundServices is not None:
            findings["services"] = self.foundServices

        findings["timings"] = {
            "extractionSeconds": round(self.extractionSeconds, 1)
                if self.extractionSeconds is not None else None,
            "preparationSeconds": round(self.preparationSeconds, 1)
                if self.preparationSeconds is not None else None,
            "preEmulationSeconds": round(self.preEmulationSeconds, 1)
                if self.preEmulationSeconds is not None else None,
            "serviceResponseSeconds": round(self.probeResult.serviceResponseTime, 1)
                if self.probeResult and self.probeResult.serviceResponseTime is not None else None,
        }

        return findings

    # -- export ------------------------------------------------------------

    def export(self, stage: str | None = None) -> dict:
        """Set ``stage`` (if given), then build, write to disk and DB. Returns the dict."""
        if stage is not None:
            self.stage = stage
        findings = self.build()
        self._saveToDisk(findings)
        self._saveToDB(findings)
        return findings

    def _saveToDisk(self, findings: dict) -> None:
        os.makedirs(self.workDir, exist_ok=True)
        findingsPath = os.path.join(self.workDir, "findings.json")
        with open(findingsPath, "w") as f:
            json.dump(findings, f, indent=2)
        logger.info(f"Findings ({findings.get('stage')}) exported to {findingsPath}")

    def _saveToDB(self, findings: dict) -> None:
        if not self.sqlIP or not self.dbId:
            return
        net = findings.get("network")
        stage = findings.get("stage", "unknown")
        reach = (net or {}).get("reachability", {})

        try:
            with DBInterface(self.sqlIP, self.sqlPort) as cur:
                cur.execute("""
                    INSERT INTO emulation
                        (iid, stage, network_type, net_bridge, net_interface,
                         is_user_network, init_arg, ping_reachable, service_reachable)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (iid) DO UPDATE SET
                        stage            = EXCLUDED.stage,
                        network_type     = EXCLUDED.network_type,
                        net_bridge       = EXCLUDED.net_bridge,
                        net_interface    = EXCLUDED.net_interface,
                        is_user_network  = EXCLUDED.is_user_network,
                        init_arg         = EXCLUDED.init_arg,
                        ping_reachable   = EXCLUDED.ping_reachable,
                        service_reachable= EXCLUDED.service_reachable
                    RETURNING id
                """, (
                    self.dbId,
                    stage,
                    net.get("networkType")   if net else None,
                    net.get("netBridge")     if net else None,
                    net.get("netInterface")  if net else None,
                    net.get("isUserNetwork") if net else None,
                    findings.get("emulation", {}).get("initArg"),
                    reach.get("ping",    False),
                    reach.get("service", False),
                ))
                row = cur.fetchone()
                if not row:
                    return
                emulation_id = row[0]

                if net:
                    cur.execute("DELETE FROM network_candidate WHERE emulation_id = %s", (emulation_id,))
                    for c in net.get("candidates", []):
                        cur.execute("""
                            INSERT INTO network_candidate
                                (emulation_id, ip, interface, bridge, vlans, macs)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (
                            emulation_id, c["ip"], c["interface"], c["bridge"],
                            ",".join(str(v) for v in c.get("vlans", [])),
                            ",".join(str(m) for m in c.get("macs",  [])),
                        ))

                    cur.execute("DELETE FROM network_port WHERE emulation_id = %s", (emulation_id,))
                    for p in net.get("ports", []):
                        cur.execute("""
                            INSERT INTO network_port (emulation_id, port, proto)
                            VALUES (%s, %s, %s)
                        """, (emulation_id, p["port"], p["proto"]))

                cur.connection.commit()
                logger.info(f"Emulation findings written to DB (emulation_id={emulation_id})")
        except Exception as e:
            logger.warning(f"Failed to export findings to DB: {e}")


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def loadFindings(workDir: str, tag: str) -> dict | None:
    """Scan workDir subdirectories for a findings.json matching the firmware tag."""
    if not os.path.isdir(workDir):
        return None
    for subdir in os.listdir(workDir):
        candidate = os.path.join(workDir, subdir, "findings.json")
        if os.path.exists(candidate):
            with open(candidate) as f:
                findings = json.load(f)
            if findings.get("firmware", {}).get("tag") == tag:
                logger.info(f"Loaded findings from {candidate}")
                return findings
    return None


# ---------------------------------------------------------------------------
# Reconstruct Qemu from findings
# ---------------------------------------------------------------------------

def buildQemuFromFindings(findings: dict,
                           debug: bool = False) -> "tuple[Qemu, str, str, NetworkResult] | None":
    if "emulation" not in findings or "network" not in findings:
        logger.error("Findings are missing emulation or network data.")
        return None

    em  = findings["emulation"]
    net = findings["network"]

    arch = next((a for a in Architecture if str(a) == em["architecture"]), None)
    end  = next((e for e in Endianess   if str(e) == em["endianness"]),    None)
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
