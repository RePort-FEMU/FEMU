from enum import Enum
from dataclasses import dataclass, field

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
    
GIGA = 1024 * 1024 * 1024
MEGA = 1024 * 1024
KILO = 1024

@dataclass
class ProbeResult:
    """Returned by PreEmulator.start() — everything needed to reproduce the emulation."""
    initArg: str                    # kernel init= / rdinit= argument
    networkResult: "NetworkResult"
    modifiedGuestFile: str | None   # guest path of the injected init file
    injectedContent: str | None     # content appended to that file
    pingReachable: bool = False     # ICMP ping responded during verify
    serviceReachable: bool = False  # TCP/HTTP service responded during verify

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
