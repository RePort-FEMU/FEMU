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
# Build / save
# ---------------------------------------------------------------------------

def buildFindings(
    stage: str,
    workDir: str,
    firmwarePath: str,
    tag: str,
    brand: str,
    architecture: Architecture,
    endianness: Endianess,
    probeResult: ProbeResult | None = None,
    kernelPath: str = "",
    foundServices: dict | None = None,
) -> dict:
    findings: dict = {
        "stage": stage,
        "firmware": {
            "path": firmwarePath,
            "tag": tag,
            "brand": brand,
        },
    }

    if architecture != Architecture.UNKNOWN:
        findings["emulation"] = {
            "imagePath": os.path.join(workDir, "raw.img"),
            "architecture": str(architecture),
            "endianness": str(endianness),
            "kernelPath": kernelPath,
            "initArg": probeResult.initArg if probeResult else "",
            "workDir": workDir,
        }

    if probeResult:
        findings["initInjection"] = {
            "modifiedGuestFile": probeResult.modifiedGuestFile,
            "injectedContent": probeResult.injectedContent,
        }
        nr = probeResult.networkResult
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
                "ping": probeResult.pingReachable,
                "service": probeResult.serviceReachable,
            },
        }

    if foundServices is not None:
        findings["services"] = foundServices

    return findings


def saveFindings(findings: dict, workDir: str) -> None:
    findingsPath = os.path.join(workDir, "findings.json")
    with open(findingsPath, "w") as f:
        json.dump(findings, f, indent=2)
    logger.info(f"Findings ({findings.get('stage')}) exported to {findingsPath}")


def saveFindingsToDB(findings: dict, sqlIP: str | None, sqlPort: int,
                     dbId: int | None) -> None:
    if not sqlIP or not dbId:
        return
    net = findings.get("network")
    stage = findings.get("stage", "unknown")
    reach = (net or {}).get("reachability", {})

    try:
        with DBInterface(sqlIP, sqlPort) as cur:
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
                dbId,
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
