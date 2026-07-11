from enum import Enum
from dataclasses import dataclass, field

# Extra QEMU attempts when a guest hits a BUSY/spin freeze (e.g. the kretprobe
# loop). It's a race, so a fresh boot often clears it. Non-final attempts stop
# early on a freeze; the final attempt runs the full timeout regardless.
FREEZE_RETRIES = 2

GIGA = 1024 * 1024 * 1024
MEGA = 1024 * 1024
KILO = 1024

class Architecture(Enum):
    MIPS= ("MIPS", "mips")
    MIPS64 = ("MIPS64","mips64")
    ARM = ("ARM", "arm")
    ARM64 = ("ARM64", "arm64")
    INTEL_80386 = ("INTEL_80386", "intel")
    X86_64 = ("X86_64", "intel64")
    POWERPC = ("POWERPC", "powerpc")
    UNKNOWN = ("UNKNOWN", "unknown")

    def __str__(self):
        return self.value[1]
    
    # Create a comparison method to check if two architectures are the same
    def __eq__(self, other):
        if isinstance(other, Architecture):
            return self.value[0] == other.value[0]
        return False
    
    def identifier(self):
        return self.value[0]

class Endianess(Enum):
    LITTLE = ("LSB", "el")
    BIG = ("MSB", "eb")
    UNKNOWN = ("UNKNOWN", "unknown")
    
    def __str__(self):
        return self.value[1]
    
    def identifier(self):
        return self.value[0]

@dataclass
class ServiceCheck:
    """One reachability probe run during verification, with its outcome."""
    ip: str
    port: int | None            # None → ICMP ping (no port)
    kind: str                   # "ping" | "web" | "tcp"
    reachable: bool
    responseTime: float | None = None  # seconds from QEMU start until it responded

    def label(self) -> str:
        return f"{self.ip}/ping" if self.port is None else f"{self.ip}:{self.port}/{self.kind}"


@dataclass
class ProbeResult:
    """Returned by PreEmulator.start() — everything needed to reproduce the emulation."""
    initArg: str                    # kernel init= / rdinit= argument
    networkResult: "NetworkResult"
    modifiedGuestFile: str | None   # guest path of the injected init file
    injectedContent: str | None     # content appended to that file
    reachable: bool = False         # device produced at least one positive signal (or booted but was unverifiable)
    checks: list = field(default_factory=list)  # list[ServiceCheck] — every probe attempted, reached or not

    @property
    def webReachable(self) -> bool:
        """True iff a web server (HTTP/HTTPS) responded — the criterion for full success.

        FirmAE only ever checked the web server; we also probe other TCP ports,
        but a non-web service responding is a partial (not full) success.
        """
        return any(c.reachable and c.kind == "web" for c in self.checks)

    @property
    def reachedServices(self) -> list:
        """The checks that responded."""
        return [c for c in self.checks if c.reachable]

    @property
    def serviceResponseTime(self) -> float | None:
        """Seconds from QEMU start to the earliest service that responded, or None."""
        times = [c.responseTime for c in self.checks
                 if c.reachable and c.responseTime is not None]
        return min(times) if times else None

@dataclass
class NetworkResult:
    """Holds the classified network configuration produced by the pre-emulation probe."""
    networkType: str        # "default" | "normal" | "reload" | "bridge" | "bridgereload" | "None"
    netBridge: str          # value written to /firmadyne/net_bridge
    netInterface: str       # value written to /firmadyne/net_interface
    candidates: list        # [(ip, iface, bridge, vlans, macs), ...]
    ports: list             # [(port, proto), ...]
    isUserNetwork: bool     # True → QEMU user/SLIRP networking; False → TAP
    hostIps: list           # host-side IPs (one per candidate, empty for user network)
