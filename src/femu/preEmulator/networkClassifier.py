import ipaddress

from ..common import NetworkResult


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
