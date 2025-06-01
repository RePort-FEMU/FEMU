import subprocess
import hashlib
import tarfile
import shutil
import string
import os

from common import Architecture, Endianess

def checkCompatibility(arch: Architecture, endianess: Endianess) -> bool:
    """
    Check if the architecture and endianess are compatible with the emulator.
    
    Args:
        arch (Architecture): The architecture of the firmware.
        endianess (Endianess): The endianess of the firmware.
    
    Returns:
        bool: True if compatible, False otherwise.
    """
    if arch == Architecture.UNKNOWN or endianess == Endianess.UNKNOWN:
        return False
    
    # Define compatible architectures and endianess
    compatibleConfigurations = [
        (Architecture.MIPS, Endianess.LITTLE),
        (Architecture.MIPS, Endianess.BIG),
        (Architecture.ARM, Endianess.LITTLE),
    ]
    
    return (arch, endianess) in compatibleConfigurations

def io_md5(target: str) -> str:
    blocksize = 65536
    hasher = hashlib.md5()

    with open(target, 'rb') as ifp:
        buf = ifp.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = ifp.read(blocksize)
        return hasher.hexdigest()

def checkArch(tarballPath: str, tempDirID: str) -> tuple[Architecture, Endianess]:

    tar = tarfile.open(tarballPath, "r")
    
    executables = []
    for member in tar.getmembers():
        if member.isfile():
            if any([member.name.find(binary) != -1 for binary in ["/busybox", "/alphapd", "/boa", "/http", "/hydra", "/helia", "/webs"]]):
                executables.append(member.name)
            elif any([member.name.find(path) != -1 for path in ["/sbin/", "/bin/"]]):
                executables.append(member.name)
    
    try:
        os.mkdir(os.path.join("/tmp", tempDirID))
    except FileExistsError:
        # Check that the user has permission to write to the directory
        if not os.access(os.path.join("/tmp", tempDirID), os.W_OK):
            raise PermissionError(f"Temporary directory {tempDirID} already exists and is not writable.")
        shutil.rmtree(os.path.join("/tmp", tempDirID))
        os.mkdir(os.path.join("/tmp", tempDirID))
    except Exception as e:
        raise RuntimeError(f"Failed to create temporary directory: {e}")
    
    arch = Architecture.UNKNOWN
    endianess = Endianess.UNKNOWN
    
    for executable in executables:
        tar.extract(executable, path=os.path.join("/tmp", tempDirID))
        filePath = os.path.join("/tmp", tempDirID, executable.name)
        filetype = subprocess.check_output(["file", filePath]).decode("utf-8")
        
        for arch in Architecture:
            if arch.identifier() in filetype:
                arch = arch
                break

        for endian in Endianess:
            if endian.identifier() in filetype:
                endianess = endian
                break
            
        if arch != Architecture.UNKNOWN and endianess != Endianess.UNKNOWN:
            break
        
    # Clean up the temporary directory
    tar.close()
    shutil.rmtree(os.path.join("/tmp", tempDirID))

    return arch, endianess

def strings(filePath:str, minLength:int = 4):
    """
    Extracts printable strings from a binary file.
    
    Args:
        filePath (str): Path to the binary file.
        minLength (int): Minimum length of strings to extract.

    Yields:
        str: Printable strings from the binary file that are at least `minLength` characters long.
    """
    try:
        with open(filePath, 'rb') as f:
            result = ""
            for byte in f.read():
                if chr(byte) in string.printable:
                    result += chr(byte)
                else:
                    if len(result) >= minLength:
                        yield result
                    result = ""
            if len(result) >= minLength:
                yield result
    except Exception as e:
        raise RuntimeError(f"Failed to read file {filePath}: {e}")
    
    
