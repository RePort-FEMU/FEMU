import subprocess
import socket
import logging
import time
import os
import ssl
import urllib.request
import urllib.error
from typing import Optional

from collections.abc import Callable
from .common import NetworkResult, FREEZE_RETRIES

logger = logging.getLogger(__name__)

# Shared SSL context — firmware devices always use self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

VERIFY_TIMEOUT = 360   # seconds before giving up on a verify run
BOOT_WAIT      = 10    # minimum seconds before the first connectivity check (mirrors check_emulation.sh sleep 10)
CHECK_INTERVAL = 5     # seconds between consecutive checks


def verifyEmulation(
    initArg: str,
    networkResult: NetworkResult,
    workDir: str,
    runQemu: Callable,
) -> tuple[bool, bool, float | None]:
    """
    Boot the emulated device with the classified network config and verify reachability.

    Returns (pingReachable, serviceReachable, serviceResponseTime):
        pingReachable       — at least one candidate IP responded to ICMP ping.
        serviceReachable    — at least one TCP/HTTP service responded (strong confirmation).
        serviceResponseTime — seconds from QEMU start until service responded, or None.
    QEMU is stopped as soon as serviceReachable becomes True.
    """
    verifyLog = os.path.join(workDir, "kernelLogs", "qemu.verify.serial.log")
    tcpPorts  = [port for port, proto in networkResult.ports if proto == "tcp" and port != 0]

    if networkResult.isUserNetwork:
        checkIps     = ["127.0.0.1"]
        checkPing    = False
        portsToCheck = tcpPorts
        if not portsToCheck:
            logger.warning("User networking with no detected TCP ports — cannot verify reachability")
            return False, True, None
    elif networkResult.candidates:
        checkIps     = [c[0] for c in networkResult.candidates]
        checkPing    = True
        portsToCheck = [80, 443] + [p for p in tcpPorts if p not in (80, 443)]
    else:
        logger.warning("No check IP available — skipping verification")
        return False, True, None

    startTime           = time.monotonic()
    lastCheck           = 0.0
    pingReachable       = [False]
    serviceReachable    = [False]
    serviceResponseTime: list[Optional[float]] = [None]

    def onLine(line: str | None) -> bool:
        nonlocal lastCheck
        elapsed = time.monotonic() - startTime

        if elapsed < BOOT_WAIT:
            return False
        if elapsed > VERIFY_TIMEOUT:
            logger.info(f"Verify timed out after {VERIFY_TIMEOUT}s")
            return True

        if line is not None or elapsed - lastCheck < CHECK_INTERVAL:
            return False
        lastCheck = elapsed

        for ip in checkIps:
            if checkPing and not pingReachable[0] and _checkPing(ip):
                pingReachable[0] = True
                logger.info(f"Ping reachable: {ip} — waiting for service confirmation")

            for port in portsToCheck:
                ok = _checkHttp(ip, port) if port in (80, 443) else _checkTcp(ip, port)
                if ok:
                    proto = "HTTP" if port in (80, 443) else "TCP"
                    logger.info(f"{proto} service reachable: {ip}:{port}")
                    serviceReachable[0] = True
                    serviceResponseTime[0] = round(elapsed, 1)
                    break

            if serviceReachable[0]:
                break

        return serviceReachable[0]

    logger.info(f"Verify run: targets={checkIps}, ping={'yes' if checkPing else 'no'}, "
                f"ports={portsToCheck}, timeout={VERIFY_TIMEOUT}s")
    # Retry on a BUSY/spin freeze (same race as the probe). Reset the per-attempt
    # boot timing each try; the reachability flags persist so a hit on any attempt
    # still counts. Non-final attempts stop early on a freeze; the last attempt
    # runs the full timeout regardless.
    for attempt in range(FREEZE_RETRIES + 1):
        is_last = attempt == FREEZE_RETRIES
        startTime = time.monotonic()
        lastCheck = 0.0
        froze = False
        try:
            froze = runQemu(initArg, verifyLog,
                            networkResult=networkResult,
                            timeout=VERIFY_TIMEOUT + CHECK_INTERVAL,
                            on_line=onLine,
                            stop_on_freeze=not is_last)
        except subprocess.TimeoutExpired:
            logger.warning("Verify QEMU hard timeout — treating as not reachable")
        if serviceReachable[0] or not froze:
            break
        logger.warning(f"Verify wedged (BUSY/spin freeze) — retry {attempt + 1}/{FREEZE_RETRIES}")

    logger.info(f"Verify result: ping={pingReachable[0]} service={serviceReachable[0]} "
                f"responseTime={serviceResponseTime[0]}s")
    return pingReachable[0], serviceReachable[0], serviceResponseTime[0]


_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def makeNetworkMonitor(networkResult: NetworkResult) -> "Callable[[str | None], bool]":
    """
    Return an on_line callback for Qemu.run() during boot/debug.
    Continuously checks all detected ports and logs each service the first time
    it responds. Always returns False — never interrupts QEMU.
    """
    tcpPorts = [port for port, proto in networkResult.ports if proto == "tcp" and port != 0]

    if networkResult.isUserNetwork:
        checkIps     = ["127.0.0.1"]
        checkPing    = False
        portsToCheck = tcpPorts
        if not portsToCheck:
            return lambda _: False
    elif networkResult.candidates:
        checkIps     = [c[0] for c in networkResult.candidates]
        checkPing    = True
        portsToCheck = [80, 443] + [p for p in tcpPorts if p not in (80, 443)]
    else:
        return lambda _: False

    startTime   = time.monotonic()
    lastCheck   = [0.0]
    reported: set[tuple] = set()
    pingReported: set[str] = set()

    def onLine(line: str | None) -> bool:
        elapsed = time.monotonic() - startTime
        if elapsed < BOOT_WAIT:
            return False
        if line is not None or elapsed - lastCheck[0] < CHECK_INTERVAL:
            return False
        lastCheck[0] = elapsed

        for ip in checkIps:
            if checkPing and ip not in pingReported and _checkPing(ip):
                pingReported.add(ip)
                logger.info(f"Ping reachable: {ip}")

            for port in portsToCheck:
                if (ip, port) in reported:
                    continue
                ok = _checkHttp(ip, port) if port in (80, 443) else _checkTcp(ip, port)
                if ok:
                    reported.add((ip, port))
                    if port in _WEB_PORTS:
                        scheme = "https" if port in (443, 8443) else "http"
                        suffix = f":{port}" if port not in (80, 443) else ""
                        logger.info(f"Web UI up → {scheme}://{ip}{suffix}/")
                    else:
                        logger.info(f"Service up → {ip}:{port}/tcp")

        return False

    return onLine


def _checkHttp(ip: str, port: int) -> bool:
    """HTTP/HTTPS GET — any response including error codes means the server is up."""
    scheme = "https" if port == 443 else "http"
    try:
        urllib.request.urlopen(
            f"{scheme}://{ip}:{port}/",
            timeout=2,
            context=_SSL_CTX if port == 443 else None,
        )
        return True
    except urllib.error.HTTPError:
        return True   # 4xx/5xx still means the server responded
    except Exception:
        return False


def _checkPing(ip: str) -> bool:
    """ICMP ping check — mirrors the ping step in FirmAE's check_emulation.sh."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _checkTcp(ip: str, port: int) -> bool:
    """Attempt a TCP connection. Returns True if the port accepts the connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((ip, port))
        return True
    except OSError:
        return False
