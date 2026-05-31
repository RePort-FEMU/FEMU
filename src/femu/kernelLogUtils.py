import re
import struct
import socket
import logging

from .common import Endianess

logger = logging.getLogger(__name__)

# TODO: Possible optimization: Filter the lines before applying the full regex
def findPorts(kernelLog:list[str]) -> list[tuple[int, str]]:
    """
    Find ports in the kernel log.
    Args:
        kernelLog (list[str]): The kernel log as a list of lines.
    Returns:
        list[tuple[int, str]]: A list of tuples containing the port number and protocol (tcp/udp).
    """
    ports = []
    portFound = {"tcp": {}, "udp": {}} # to avoid duplicates
    pattern = r'inet_bind\[[^\]]+\]: proto:SOCK_(DGRAM|STREAM), port:([0-9]+)' # logs for the inconfig process
    pattern = re.compile(pattern)
    for line in kernelLog:
        match = pattern.search(line)
        if match:
            port = int(match.group(2))
            proto = "tcp" if match.group(1) == "STREAM" else "udp"
            if port not in portFound[proto]:
                ports.append((port, proto))
                portFound[proto][port] = True
                
    return ports

# TODO: Possible optimization: Filter the lines before applying the full regex
def findInterfaceIps(kernelLog: list[str], endianess: Endianess) -> list[tuple[str, str]]:
    """Find interface IP addresses in the kernel log.

    Args:
        kernelLog (list[str]): The kernel log as a list of lines.
        endianess (Endianess): The endianness of the system.

    Returns:
        list[tuple[str, str]]: A list of tuples containing the interface name and IP address.
    """
    interfaces = []
    pattern = r'__inet_insert_ifa\[[^\]]+\]: device:([^ ]+) ifa:0x([0-9a-f]+)' # logs for the inconfig process
    pattern = re.compile(pattern)
    
    for line in kernelLog:
        match = pattern.search(line)
        if match:
            iface = match.group(1)
            addr = socket.inet_ntoa(struct.pack("<I" if endianess == Endianess.LITTLE else ">I", int(match.group(2), 16)))
            
            # Check that it is not a loopback address
            if not addr.startswith("127.") and addr != "0.0.0.0":
                interfaces.append((iface, addr))
                
    return interfaces

# TODO: Possible optimization: Filter the lines before applying the full regex
def findMacChanges(kernelLog: list[str], endianess: Endianess) -> dict[str, list[str]]:
    """Find MAC address changes in the kernel log.

    Args:
        kernelLog (list[str]): The kernel log as a list of lines.
        endianess (Endianess): The endianness of the system.

    Returns:
        dict[str, list[str]]: A dictionary containing the MAC Addresses that where used for each Interface.
    """
    changes = {}
    pattern = r'ioctl_SIOCSIFHWADDR\[[^\]]+\]: dev:([^ ]+) mac:0x([0-9a-f]+) 0x([0-9a-f]+)' # logs for the inconfig process
    pattern = re.compile(pattern)
    
    for line in kernelLog:
        match = pattern.search(line)
        if match:
            iface, macHigh, macLow = match.group(1), match.group(2), match.group(3)
            # Skip the first 2 bytes of the MAC, as they are not used (MACs are 48 bits long)
            macHigh = struct.pack("<I" if endianess == Endianess.LITTLE else ">I", int(macHigh, 16))[2:]
            macLow = struct.pack("<I" if endianess == Endianess.LITTLE else ">I", int(macLow, 16))
            newMac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", macHigh + macLow)
            
            if iface not in changes:
                changes[iface] = [newMac]
            else:
                changes[iface].append(newMac)
                
    return changes

# TODO: Possible optimization: Filter the lines before applying the full regex
def findBridges(kernelLog: list[str]) -> dict[str, list[str]]:
    """Find used bridges in the kernel log.

    Args:
        kernelLog (list[str]): The kernel log as a list of lines.

    Returns:
        dict[str, list[str]]: A dictionary mapping bridge names to lists of associated netdevs.
    """
    bridges = {}
    pattern = r'(br_dev_ioctl|br_add_if)\[[^\]]+\]: br:([^ ]+) dev:([^ ]+)' # logs for the inconfig process
    pattern = re.compile(pattern)
    
    for line in kernelLog:
        match = pattern.search(line)
        if match:
            bridge = match.group(2)
            netdev = match.group(3)
            if bridge == netdev:
                continue # Skip the line where the bridge is created, we only care about netdevs being added to it
            
            if bridge not in bridges:
                bridges[bridge] = [netdev]
            else:
                bridges[bridge].append(netdev)
                
    return bridges

def findVLANs(kernelLog: list[str]) -> dict[str, list[str]]:
    """Find used VLANs in the kernel log.

    Args:
        kernelLog (list[str]): The kernel log as a list of lines.

    Returns:
        dict[str, list[str]]: A dictionary mapping netdev names to their associated VLAN IDs.
    """
    vlans = {}
    pattern = r'register_vlan_dev\[[^\]]+\]: dev:([^ ]+) vlan_id:([0-9]+)' # logs for the inconfig process
    pattern = re.compile(pattern)
    
    for line in kernelLog:
        match = pattern.search(line)
        if match:
            netdev = match.group(1)
            vlan_id = int(match.group(2))
            if netdev not in vlans:
                vlans[netdev] = [vlan_id]
            else:
                vlans[netdev].append(vlan_id)
                
    return vlans