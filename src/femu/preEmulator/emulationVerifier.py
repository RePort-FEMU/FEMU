import subprocess
import socket
import logging
import time
import os
import ssl
import urllib.request
import urllib.error
from typing import NamedTuple, Optional
from collections.abc import Callable

from ..common import NetworkResult, ServiceCheck, FREEZE_RETRIES

logger = logging.getLogger(__name__)

# ─────────────────────────── Configuration ───────────────────────────

# Ports treated as a web server: reaching one counts as full success, mirroring
# FirmAE (which only checked the web UI). Any other TCP port is a partial success.
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

# Shared SSL context — firmware devices always use self-signed certs.
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

VERIFY_TIMEOUT = 360   # seconds before giving up on a verify run
BOOT_WAIT      = 10    # min seconds before the first check (mirrors check_emulation.sh sleep 10)
CHECK_INTERVAL = 5     # seconds between consecutive checks
HTTP_TIMEOUT   = 5     # per-request timeout for the HTTP service check


# ──────────────────────────── Public API ─────────────────────────────

def verifyEmulation(
    initArg: str,
    networkResult: NetworkResult,
    workDir: str,
    runQemu: Callable,
    init: str = "",
) -> tuple[bool, list[ServiceCheck]]:
    """
    Boot the emulated device and verify reachability. Returns (reachable, checks):

        reachable — True if the device gave any positive signal, or booted with
                    nothing to probe (unverifiable).
        checks    — one ServiceCheck per (ip, port) target plus ping, each flagged
                    reached/unreached. A web hit is full success (see
                    ProbeResult.webReachable); any other TCP service is partial.

    QEMU stops as soon as a web service responds; otherwise it runs the full
    verify window so late-starting services still get recorded.
    """
    # Name the verify log per-init (matching the probe convention) so verify logs
    # for different inits don't overwrite each other.
    verifyName = f"qemu.verify.{init[1:].replace('/', '-')}.serial.log" if init else "qemu.verify.serial.log"
    verifyLog = os.path.join(workDir, "kernelLogs", verifyName)

    targets = _resolveTargets(networkResult)
    if targets is None:
        if networkResult.isUserNetwork:
            logger.warning("User networking with no detected TCP ports — cannot verify reachability")
        else:
            logger.warning("No check IP available — skipping verification")
        return True, []

    # Pre-seed every target as unreached; the sweep flips it on the first hit.
    checks: dict[tuple[str, Optional[int]], ServiceCheck] = {}
    for ip in targets.ips:
        if targets.ping:
            checks[(ip, None)] = ServiceCheck(ip, None, "ping", False)
        for port in targets.ports:
            checks[(ip, port)] = ServiceCheck(ip, port, "web" if _isWebPort(port) else "tcp", False)

    def webUp() -> bool:
        return any(c.reachable and c.kind == "web" for c in checks.values())

    # seen sets mirror "already reachable" and persist across retries, so a hit on
    # any attempt still counts and is never re-probed.
    seenPing: set[str] = set()
    seenPorts: set[tuple[str, int]] = set()
    clock = _CheckClock()

    def onLine(line: str | None) -> bool:
        if clock.elapsed > VERIFY_TIMEOUT:
            logger.info(f"Verify timed out after {VERIFY_TIMEOUT}s")
            return True

        elapsed = clock.due(line)
        if elapsed is None:
            return False

        for kind, ip, port in _probeTargets(targets, seenPing, seenPorts, stopWhenWebUp=True):
            check = checks[(ip, port)]
            check.reachable = True
            check.responseTime = round(elapsed, 1)
            if kind == "ping":
                logger.info(f"Ping reachable: {ip}")
            else:
                logger.info(f"{'HTTP' if kind == 'web' else 'TCP'} service reachable: {ip}:{port}")

        # Full success (web) stops the run; partial hits keep it going for more.
        return webUp()

    logger.info(f"Verify run: targets={targets.ips}, ping={'yes' if targets.ping else 'no'}, "
                f"ports={targets.ports}, timeout={VERIFY_TIMEOUT}s")
    # Retry on a BUSY/spin freeze (same race as the probe). clock.reset() restarts
    # the per-attempt timing; reachability persists. Non-final attempts stop early
    # on a freeze; the last runs the full timeout regardless.
    for attempt in range(FREEZE_RETRIES + 1):
        is_last = attempt == FREEZE_RETRIES
        clock.reset()
        froze = False
        try:
            froze = runQemu(initArg, verifyLog,
                            networkResult=networkResult,
                            timeout=VERIFY_TIMEOUT + CHECK_INTERVAL,
                            on_line=onLine,
                            stop_on_freeze=not is_last)
        except subprocess.TimeoutExpired:
            logger.warning("Verify QEMU hard timeout — treating as not reachable")
        if webUp() or not froze:
            break
        logger.warning(f"Verify wedged (BUSY/spin freeze) — retry {attempt + 1}/{FREEZE_RETRIES}")

    checkList = list(checks.values())
    reachable = any(c.reachable for c in checkList)
    reached = [c.label() for c in checkList if c.reachable] or ["none"]
    logger.info(f"Verify result: reachable={reachable} web={webUp()} reached={reached}")
    return reachable, checkList


def makeNetworkMonitor(networkResult: NetworkResult) -> "Callable[[str | None], bool]":
    """
    on_line callback for Qemu.run() during an interactive boot/debug session.
    Logs each service the first time it responds and never interrupts QEMU
    (always returns False). Unlike verifyEmulation, it does not stop on success.
    """
    targets = _resolveTargets(networkResult)
    if targets is None:
        return lambda _: False

    seenPing: set[str] = set()
    seenPorts: set[tuple[str, int]] = set()
    clock = _CheckClock()

    def onLine(line: str | None) -> bool:
        if clock.due(line) is None:
            return False

        for kind, ip, port in _probeTargets(targets, seenPing, seenPorts, stopWhenWebUp=False):
            if kind == "ping":
                logger.info(f"Ping reachable: {ip}")
            elif kind == "web":
                scheme = "https" if port in (443, 8443) else "http"
                suffix = f":{port}" if port not in (80, 443) else ""
                logger.info(f"Web UI up → {scheme}://{ip}{suffix}/")
            else:
                logger.info(f"Service up → {ip}:{port}/tcp")

        return False

    return onLine


# ──────────────── Target resolution & probe scheduling ────────────────

class _Targets(NamedTuple):
    """What to probe during a run, derived from the classified network config."""
    ips: list[str]      # loopback for user net, candidate IPs for TAP
    ping: bool          # whether ICMP ping is meaningful (TAP only)
    ports: list[int]    # TCP ports to probe, in priority order


def _resolveTargets(networkResult: NetworkResult) -> Optional[_Targets]:
    """Decide what to probe. None → nothing verifiable (user net with no ports,
    or TAP with no candidate IPs)."""
    tcpPorts = [port for port, proto in networkResult.ports if proto == "tcp" and port != 0]

    if networkResult.isUserNetwork:
        # User/SLIRP net is reached via forwarded loopback ports; ping is meaningless.
        return _Targets(["127.0.0.1"], False, tcpPorts) if tcpPorts else None
    if networkResult.candidates:
        # TAP net: probe each candidate IP, web ports first, then the rest.
        ips = [c[0] for c in networkResult.candidates]
        ports = [80, 443] + [p for p in tcpPorts if p not in (80, 443)]
        return _Targets(ips, True, ports)
    return None


class _CheckClock:
    """Throttles the on_line callback to a fixed cadence: waits BOOT_WAIT after
    each (re)start, then allows a check at most once per CHECK_INTERVAL, and only
    on timer ticks (line is None) — never on log lines."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Restart the boot-wait/interval timing (once per QEMU attempt)."""
        self._start = time.monotonic()
        self._last = 0.0

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def due(self, line: str | None) -> Optional[float]:
        """Elapsed seconds if a check should run now, else None."""
        elapsed = self.elapsed
        if elapsed < BOOT_WAIT or line is not None or elapsed - self._last < CHECK_INTERVAL:
            return None
        self._last = elapsed
        return elapsed


def _probeTargets(targets: _Targets, seenPing: set, seenPorts: set, stopWhenWebUp: bool):
    """Probe every not-yet-seen target once, yielding (kind, ip, port) for each
    newly reachable one — ("ping", ip, None) or ("web"|"tcp", ip, port) — and
    recording it in seenPing/seenPorts. If stopWhenWebUp, stop after a web hit."""
    webHit = False
    for ip in targets.ips:
        if targets.ping and ip not in seenPing and _checkPing(ip):
            seenPing.add(ip)
            yield ("ping", ip, None)

        for port in targets.ports:
            if (ip, port) in seenPorts:
                continue
            if _checkService(ip, port):
                seenPorts.add((ip, port))
                kind = "web" if _isWebPort(port) else "tcp"
                webHit = webHit or kind == "web"
                yield (kind, ip, port)

        if stopWhenWebUp and webHit:
            return


# ─────────────────────────── Low-level probes ─────────────────────────

def _isWebPort(port: int) -> bool:
    return port in _WEB_PORTS


def _checkService(ip: str, port: int) -> bool:
    """Probe a port with the right method: HTTP for web ports, raw TCP otherwise."""
    return _checkHttp(ip, port) if _isWebPort(port) else _checkTcp(ip, port)


def _checkHttp(ip: str, port: int) -> bool:
    """Probe an HTTP/HTTPS port for a live web server.

    A parseable response (including 4xx/5xx) counts as up. Many embedded servers
    emit malformed HTTP urllib can't parse (bad status line, early disconnect,
    non-HTTP banner) — a big source of false negatives vs FirmAE. So on any
    non-HTTP failure, fall back to a raw probe and accept any bytes as proof of life.
    """
    https = port in (443, 8443)
    scheme = "https" if https else "http"
    try:
        urllib.request.urlopen(
            f"{scheme}://{ip}:{port}/",
            timeout=HTTP_TIMEOUT,
            context=_SSL_CTX if https else None,
        )
        return True
    except urllib.error.HTTPError:
        return True   # 4xx/5xx still means the server responded
    except Exception:
        return _httpRawProbe(ip, port)


def _httpRawProbe(ip: str, port: int) -> bool:
    """Send a minimal GET over a raw socket; True if the server replies with any
    bytes. Distinguishes a live-but-quirky server from a closed/refused port."""
    try:
        sock = socket.create_connection((ip, port), timeout=HTTP_TIMEOUT)
    except OSError:
        return False   # port closed / refused / unreachable
    try:
        if port in (443, 8443):
            sock = _SSL_CTX.wrap_socket(sock, server_hostname=ip)
        sock.settimeout(HTTP_TIMEOUT)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() +
                     b"\r\nConnection: close\r\n\r\n")
        return len(sock.recv(16)) > 0
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


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
    """Attempt a TCP connection. True if the port accepts it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((ip, port))
        return True
    except OSError:
        return False
