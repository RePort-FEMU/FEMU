import subprocess
import socket
import logging
import time
import os
import ssl
import urllib.request
import urllib.error

from collections.abc import Callable
from common import NetworkResult

logger = logging.getLogger("FEMU")

# Shared SSL context — firmware devices always use self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

VERIFY_TIMEOUT = 120   # seconds before giving up on a verify run
BOOT_WAIT      = 10    # minimum seconds before the first connectivity check (mirrors check_emulation.sh sleep 10)
CHECK_INTERVAL = 5     # seconds between consecutive checks


def verifyEmulation(
    initArg: str,
    networkResult: NetworkResult,
    workDir: str,
    runQemu: Callable,
) -> bool:
    """
    Boot the emulated device with the classified network config and verify reachability.

    Mirrors FirmAE's check_emulation.sh:
      - Waits BOOT_WAIT seconds before the first check.
      - Checks ICMP ping (basic reachability).
      - Checks TCP connectivity on web ports first, then all other detected ports.
      - Stops QEMU as soon as the device is confirmed reachable.

    Improvement over FirmAE: checks all detected TCP ports, not only port 80/web.

    Args:
        initArg:       kernel init= argument (injected by PreEmulator).
        networkResult: classified network configuration.
        workDir:       directory for the verify log file.
        runQemu:       callable matching PreEmulator._runQemu's signature:
                       (initArg, logfile, networkResult, timeout, on_line) -> None
    Returns:
        True if the device became reachable within VERIFY_TIMEOUT seconds.
    """
    verifyLog = os.path.join(workDir, "kernelLogs", "qemu.verify.serial.log")
    tcpPorts  = [port for port, proto in networkResult.ports if proto == "tcp" and port != 0]

    if networkResult.isUserNetwork:
        # ICMP cannot be forwarded through QEMU SLIRP, and 127.0.0.1 ping always
        # succeeds (host loopback) — skip ping entirely for user networking.
        checkIps  = ["127.0.0.1"]
        checkPing = False
        # Only the ports QEMU actually forwarded are reachable on the host side.
        portsToCheck = tcpPorts
        if not portsToCheck:
            logger.warning("User networking with no detected TCP ports — cannot verify reachability")
            return True
    elif networkResult.candidates:
        checkIps  = [c[0] for c in networkResult.candidates]   # all guest IPs via TAP
        checkPing = True
        # Prioritise common web ports, then any other detected ports.
        portsToCheck = [80, 443] + [p for p in tcpPorts if p not in (80, 443)]
    else:
        logger.warning("No check IP available — skipping verification")
        return True

    startTime = time.monotonic()
    lastCheck = 0.0
    reachable = [False]

    def onLine(line: str | None) -> bool:
        nonlocal lastCheck
        elapsed = time.monotonic() - startTime

        if elapsed < BOOT_WAIT:
            return False
        if elapsed > VERIFY_TIMEOUT:
            logger.info(f"Verify timed out after {VERIFY_TIMEOUT}s — device not reachable")
            return True                     # signal QEMU to stop

        # Only check on periodic ticks (line is None) and at most every CHECK_INTERVAL seconds
        if line is not None or elapsed - lastCheck < CHECK_INTERVAL:
            return False
        lastCheck = elapsed

        for ip in checkIps:
            # Ping is informational only — mirrors FirmAE: don't stop until a service
            # confirms the device is actually serving traffic.
            if checkPing and _checkPing(ip):
                logger.info(f"Ping reachable: {ip} — waiting for service confirmation")

            for port in portsToCheck:
                # Use HTTP GET for web ports (any response = server is up), raw TCP for others.
                ok = _checkHttp(ip, port) if port in (80, 443) else _checkTcp(ip, port)
                if ok:
                    proto = "HTTP" if port in (80, 443) else "TCP"
                    logger.info(f"{proto} service reachable: {ip}:{port}")
                    reachable[0] = True
                    break

            if reachable[0]:
                break

        return reachable[0]     # stop QEMU early once a service is confirmed

    logger.info(f"Verify run: targets={checkIps}, ping={'yes' if checkPing else 'no'}, "
                f"ports={portsToCheck}, timeout={VERIFY_TIMEOUT}s")
    try:
        runQemu(initArg, verifyLog,
                networkResult=networkResult,
                timeout=VERIFY_TIMEOUT + CHECK_INTERVAL,
                on_line=onLine)
    except subprocess.TimeoutExpired:
        logger.warning("Verify QEMU hard timeout — treating as not reachable")

    if reachable[0]:
        logger.info(f"Device reachable at one of {checkIps}")
    else:
        logger.warning("Device NOT reachable with this init/config")
    return reachable[0]


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
