import subprocess
import socket
import logging
import time
import os


from collections.abc import Callable
from common import NetworkResult

logger = logging.getLogger("FEMU")

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

    if networkResult.isUserNetwork:
        checkIp = "127.0.0.1"            # port-forwarded through QEMU SLIRP
    elif networkResult.candidates:
        checkIp = networkResult.candidates[0][0]   # guest IP, reachable via TAP
    else:
        logger.warning("No check IP available — skipping verification")
        return True

    tcpPorts  = [port for port, proto in networkResult.ports if proto == "tcp"]
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

        if _checkPing(checkIp):
            logger.info(f"Ping reachable: {checkIp}")
            reachable[0] = True

        for port in ([80, 443] + [p for p in tcpPorts if p not in (80, 443)]):
            if _checkTcp(checkIp, port):
                logger.info(f"TCP service reachable: {checkIp}:{port}")
                reachable[0] = True
                break

        return reachable[0]     # stop QEMU early once reachable

    logger.info(f"Verify run: target={checkIp}, timeout={VERIFY_TIMEOUT}s")
    try:
        runQemu(initArg, verifyLog,
                networkResult=networkResult,
                timeout=VERIFY_TIMEOUT + CHECK_INTERVAL,
                on_line=onLine)
    except subprocess.TimeoutExpired:
        logger.warning("Verify QEMU hard timeout — treating as not reachable")

    if reachable[0]:
        logger.info(f"Device reachable at {checkIp}")
    else:
        logger.warning("Device NOT reachable with this init/config")
    return reachable[0]


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
