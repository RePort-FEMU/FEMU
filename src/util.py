import subprocess
import logging
import hashlib
import tarfile
import shutil
import string
import os
import re

from common import Architecture, Endianess

from dbInterface import DBInterface

logger = logging.getLogger("emulator")

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
    """
    Calculate the MD5 hash of a file using buffered reading.
    Args:
        target (str): Path to the file.
    Returns:
        str: MD5 hash of the file.
    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    if not os.path.exists(target):
        raise FileNotFoundError(f"File {target} does not exist.")
    if not os.access(target, os.R_OK):
        raise PermissionError(f"File {target} is not readable.")
    if not os.path.isfile(target):
        raise ValueError(f"Target {target} is not a file.")
    
    blocksize = 65536
    hasher = hashlib.md5()

    with open(target, 'rb') as ifp:
        buf = ifp.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = ifp.read(blocksize)
        return hasher.hexdigest()

def checkArch(tarballPath: str, tempDirID: str) -> tuple[Architecture, Endianess]:
    """
    Checks the architecture and endianess of the firmware in a tarball.
    Args:
        tarballPath (str): Path to the tarball file.
        tempDirID (str): Temporary directory identifier for extraction.
    Returns:
        tuple[Architecture, Endianess]: A tuple containing the architecture and endianess.
    Raises:
        RuntimeError: If the tarball cannot be read or if no executables are found."""

    tar = tarfile.open(tarballPath, "r")
    
    executables = []
    for member in tar.getmembers():
        if member.isfile():
            if any([member.name.find(binary) != -1 for binary in ["/busybox", "/alphapd", "/boa", "/http", "/hydra", "/helia", "/webs"]]):
                executables.append(member)
            elif any([member.name.find(path) != -1 for path in ["/sbin/", "/bin/"]]):
                executables.append(member)
    
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
    
    
def getFilesInfo(tarballPath: str) -> list[tuple[str, str, int, int, int]]:
    """
    Extracts file information from a tarball.
    
    Args:
        tarballPath (str): Path to the tarball file.
    
    Returns:
        list[tuple[str, str, int, int, int]]: List of tuples containing file information.
        Each tuple contains:
            - name (str)
            - hash (str)
            - uid  (int)
            - gid  (int)
            - mode (int)
    """
    try:
        with tarfile.open(tarballPath, "r") as tar:
            file_info = []
            for member in tar.getmembers():
                if member.isfile():
                    # we use member.name[1:] to get rid of the . at the beginning of the path
                    fileContent = tar.extractfile(member)
                    if fileContent is None:
                        continue
                    file_hash = hashlib.md5(fileContent.read()).hexdigest()
                    
                    file_info.append((member.name[1:], file_hash, member.uid, member.gid, member.mode))
            return file_info
    except Exception as e:
        raise RuntimeError(f"Failed to read tarball {tarballPath}: {e}")

def getLinksInfo(tarballPath: str) -> list[tuple[str, str]]:
    """
    Extracts symbolic link information from a tarball.
    
    Args:
        tarballPath (str): Path to the tarball file.
    
    Returns:
        list[tuple[str, str]]: List of tuples containing symbolic link information.
        Each tuple contains:
            - name (str)
            - target (str)
    """
    try:
        with tarfile.open(tarballPath, "r") as tar:
            links_info = []
            for member in tar.getmembers():
                if member.issym():
                    links_info.append((member.name[1:], member.linkname))
            return links_info
    except Exception as e:
        raise RuntimeError(f"Failed to read tarball {tarballPath}: {e}")
    
def getObjectIds(fileList: list[tuple[str, str, int, int, int]] | list[str], dbIp: str, dbPort: int = 5432, addMissing: bool = True) -> tuple[dict[str, int], list[str]]:
    """
    Retrieves object IDs from the database for a list of files.
    
    Args:
        fileList (list[tuple[str, str, int, int, int]] | list[str]): List of files to check. Either a list of tuples containing file information or a list of hashes.
        dbIp (str): IP address of the database.
        dbPort (int): Port of the database.
        addMissing (bool): If True, adds missing files to the database.
    
    Returns:
        tuple[dict[str, int], list[str]]: A tuple containing:
            - A dictionary mapping file hashes to their IDs.
            - A list of hashes for which no ID was found.
    """
    if not isinstance(fileList, list):
        raise TypeError("fileList must be a list of tuples or a list of strings.")
    
    if len(fileList) == 0:
        return {}, []
    
    hashes = [] # type: list[str]
    if all(isinstance(file, str) for file in fileList):
        # If fileList is a list of hashes
        hashes = fileList  # type: ignore[assignment]
    elif all(isinstance(file, tuple) and len(file) == 5 for file in fileList):
        # If fileList is a list of tuples
        hashes = [file[1] for file in fileList]
    else:
        raise TypeError("fileList must be a list of tuples or a list of strings.")
    
    hashesStr = ",".join(f"""'{hash}'""" for hash in hashes)
    query = """SELECT id,hash FROM object WHERE hash IN (%s)"""
    with DBInterface(dbIp, dbPort) as cursor:
        cursor.execute(query, (hashesStr,))
        results = cursor.fetchall()
        objectIds = {row[1]: row[0] for row in results}
        
    missingHashes = [hash for hash in hashes if hash not in objectIds]
        
    newObjects = createNewObjects(missingHashes, dbIp, dbPort) if addMissing else {}
    
    objectIds.update(newObjects)
    
    return objectIds, missingHashes
    
        
        
def createNewObjects(hashes: list[str], dbIp: str, dbPort: int) -> dict[str, int]:
    """
    Creates new objects in the database for missing hashes.
    
    Args:
        hashes (list[str]): List of hashes for which no ID was found.
        dbIp (str): IP address of the database.
        dbPort (int): Port of the database.
    
    Returns:
        dict[str, int]: A dictionary mapping file hashes to their newly created IDs.
    """
    if not hashes:
        return {}
    
    query = """INSERT INTO object (hash) VALUES (%s) RETURNING id"""
    newObjects = {}
    
    with DBInterface(dbIp, dbPort) as cursor:
        for hash in hashes:
            cursor.execute(query, (hash,))
            result = cursor.fetchone()
            if result:
                newObjects[hash] = result[0]
            else:
                raise RuntimeError(f"Failed to create new object for hash {hash}.")
    
    return newObjects
    
    
def insertObjectsToImage(imageId: str, objectIds: dict[str, int], fileList: list[tuple[str, str, int, int, int]], dbIp: str, dbPort: int = 5432) -> None:
    """
    Inserts object IDs into the object_to_image table.
    
    Args:
        imageId (str): ID of the image.
        objectIds (dict[str, int]): Dictionary mapping file hashes to their IDs.
        dbIp (str): IP address of the database.
        dbPort (int): Port of the database.
    
    Raises:
        RuntimeError: If the insertion fails.
    """
    if not objectIds:
        return
    
    if not isinstance(fileList, list) or not all(isinstance(file, tuple) and len(file) == 5 for file in fileList):
        raise TypeError("fileList must be a list of tuples containing file information.")
    
    query = """INSERT INTO object_to_image (iid, oid, filename, regular_file, uid, gid, permissions) VALUES (%(iid)s, %(oid)s, %(filename)s, %(regular_file)s, %(uid)s, %(gid)s, %(mode)s)"""
    
    fileDict = {file[1]: file for file in fileList}
    
    with DBInterface(dbIp, dbPort) as cursor:
        for hash, oid in objectIds.items():
            if hash in fileDict:
                fileInfo = fileDict[hash]
                cursor.execute(query, {
                    'iid': imageId,
                    'oid': oid,
                    'filename': fileInfo[0],
                    'regular_file': True,
                    'uid': fileInfo[2],
                    'gid': fileInfo[3],
                    'mode': fileInfo[4]
                })
            else:
                raise RuntimeError(f"File {hash} not found in the provided file list.")
        
        cursor.connection.commit()
        
        
def insertLinksToImage(imageId: str, links: list[tuple[str, str]], dbIp: str, dbPort: int = 5432) -> None:
    """
    Inserts symbolic links into the object_to_image table.
    
    Args:
        imageId (str): ID of the image.
        links (list[tuple[str, str]]): List of tuples containing symbolic link information.
        dbIp (str): IP address of the database.
        dbPort (int): Port of the database.
    
    Raises:
        RuntimeError: If the insertion fails.
    """
    if not links:
        return
    
    if not isinstance(links, list) or not all(isinstance(link, tuple) and len(link) == 2 for link in links):
        raise TypeError("links must be a list of tuples containing symbolic link information.")
    
    query = """INSERT INTO object_to_image (iid, oid, filename, regular_file, uid, gid, permissions) VALUES (%(iid)s, %(oid)s, %(filename)s, %(regular_file)s, %(uid)s, %(gid)s, %(mode)s)"""
    
    with DBInterface(dbIp, dbPort) as cursor:
        for name, target in links:
            cursor.execute(query, {
                'iid': imageId,
                'oid': 0,  # Symbolic links do not have an object ID
                'filename': name,
                'regular_file': False,
                'uid': None,  # Default UID for symbolic links
                'gid': None,  # Default GID for symbolic links
                'mode': 0o777  # Default permissions for symbolic links
            })
        
        cursor.connection.commit()
        
def dd(inputFile: str, outputFile: str, count: int , blockSize: int = 512) -> None:
    """
    Copies data from inputFile to outputFile using dd-like functionality.

    Args:
        inputFile (str): Path to the input file.
        outputFile (str): Path to the output file.
        count (int): Number of blocks to copy.
        blockSize (int): Size of each block in bytes. Default is 512 bytes.

    Raises:
        RuntimeError: If the copy operation fails.
    """
    if not os.path.exists(inputFile):
        raise FileNotFoundError(f"Input file {inputFile} does not exist or is not a file.")

    if not os.access(inputFile, os.R_OK):
        raise PermissionError(f"Input file {inputFile} is not readable.")

    output_dir = os.path.dirname(outputFile) or "./"
    if not os.path.isdir(output_dir):
        raise ValueError(f"Invalid directory for the output file: {output_dir}")

    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Cannot write to the directory: {output_dir}")

    try:
        with open(inputFile, 'rb') as infile, open(outputFile, 'wb') as outfile:
            for _ in range(count):
                data = infile.read(blockSize)
                if not data:
                    break
                outfile.write(data)
    except Exception as e:
        raise RuntimeError(f"Failed to copy data from {inputFile} to {outputFile}: {e}")
        
def createRawImg(path: str, size: int) -> str:
    """
    Creates a raw image file for QEMU.
    
    Args:
        path (str): Path to the raw image file.
        size (int): Size of the image in bytes.
    
    Returns:
        str: Path to the created raw image file.
    
    Raises:
        RuntimeError: If the image creation fails.
    """
    
    # Check that the path is valid
    parentDir = os.path.dirname(path) or "./"
    if not os.access(parentDir, os.W_OK):
        raise PermissionError(f"Cannot write to the directory: {parentDir}")
    if not isinstance(size, int) or size <= 0:
        raise ValueError(f"Invalid size for the raw image: {size}. Size must be a positive integer.")
    
    if os.path.exists(path):
        raise FileExistsError(f"Raw image file {path} already exists. Please choose a different path or remove the existing file.")
    
    # Create the raw image file
    dd(inputFile="/dev/zero", outputFile=path, count=size // 512, blockSize=512)
    if not os.path.exists(path):
        raise RuntimeError(f"Failed to create raw image file at {path}.")
    
    # Create partition table using sfdisk
    try:
        subprocess.run(
            ["sfdisk", path, "--no-reread", "--force"],
            input="label: dos\ntype=83",
            text=True,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to create partition table for raw image {path}: {e}")
    
    # Add a ext2 filesystem to the raw image
    try:
        subprocess.run(
            ["mke2fs", "-E", "root_owner=1000:1000,offset=1048576", path], 
            text=True,
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to create ext2 filesystem on raw image {path}: {e}")
    
    return path

def runAsRoot(command: list[str]) -> subprocess.CompletedProcess:
    """
    Runs a command as root using sudo.
    
    Args:
        command (list[str]): Command to run as root.
    
    Returns:
        subprocess.CompletedProcess: The result of the command execution.
    
    Raises:
        RuntimeError: If the command fails.
    """
    try:
        result = subprocess.run(["sudo"] + command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run command as root: {e}")
    
    if result.returncode != 0:
        raise RuntimeError(f"Command failed with return code {result.returncode}: {result.stderr.strip()}")
    
    return result

def addPartition(rawImagePath: str) -> str:
    runAsRoot(["losetup", "-Pf", rawImagePath]) 
    
    # Find the loop device associated with the raw image
    loopDevices = runAsRoot(["losetup", "-j", rawImagePath]).stdout.strip()
    
    if not loopDevices.strip():
        raise RuntimeError(f"No loop device found for raw image {rawImagePath}. Please check the raw image path and try again.")

    loopDevice = loopDevices.split("\n")[0].split(":")[0].strip() + "p1"  # Assuming the first partition is to be mounted

    if not os.path.exists(loopDevice):
        raise RuntimeError(f"Loop device {loopDevice} does not exist. Please check the raw image path and try again.")

    return loopDevice

def mountImage(rawImagePath: str, mountPoint: str) -> None:
    """
    Mounts a raw image file to a specified mount point.
    
    Args:
        rawImagePath (str): Path to the raw image file.
        mountPoint (str): Directory where the image will be mounted.
    
    Raises:
        RuntimeError: If the mounting fails.
    """
    if not os.path.exists(rawImagePath):
        raise FileNotFoundError(f"Raw image file {rawImagePath} does not exist.")
    
    if not os.path.exists(mountPoint):
        try:
            logger.warning(f"Creating mount point directory: {mountPoint}")
            os.makedirs(mountPoint)
        except OSError as e:
            raise RuntimeError(f"Failed to create mount point {mountPoint}: {e}")
    
    if not os.path.isdir(mountPoint):
        raise ValueError(f"Mount point {mountPoint} is not a directory.")
    
    if not os.access(mountPoint, os.W_OK):
        raise PermissionError(f"Mount point {mountPoint} is not writable.")

    loopDevice = addPartition(rawImagePath)

    runAsRoot(["mount", loopDevice, mountPoint])
    
    os.sync()  # Ensure the mount is complete before returning
    
def removePartition(loopDevice: str) -> None:
    """
    Removes the partition from a raw image file.

    Args:
        loopDevice (str): The loop device associated with the partition.
    """
    if not os.path.exists(loopDevice):
        raise FileNotFoundError(f"Loop device {loopDevice} does not exist.")

    if re.match(r'^/dev/loop\d+p\d+$', loopDevice):
        loopDevice = loopDevice[:-2]  # Remove partition number if present

    runAsRoot(["losetup", "-d", loopDevice])
    
def unmountImage(mountPoint: str) -> None:
    """
    Unmounts a mounted image file from the specified mount point.
    
    Args:
        mountPoint (str): Directory where the image is mounted.
    
    Raises:
        RuntimeError: If the unmounting fails.
    """
    if not os.path.exists(mountPoint):
        raise FileNotFoundError(f"Mount point {mountPoint} does not exist.")
    
    if not os.path.isdir(mountPoint):
        raise ValueError(f"Mount point {mountPoint} is not a directory.")
    
    # Find the loop device associated with the mount point by checking /proc/mounts
    with open("/proc/mounts", "r") as mountsFile:
        mounts = mountsFile.readlines()

    for line in mounts:
        if mountPoint in line:
            loopDevice = line.split()[0]
            break
    else:
        raise RuntimeError(f"Failed to find loop device for mount point {mountPoint}")
    if not loopDevice:
        raise RuntimeError(f"No loop device found for mount point {mountPoint}")
    
    # Unmount the mount point
    runAsRoot(["umount", mountPoint])
    
    removePartition(loopDevice)


def find(searchPath: str | list[str], fileNames: str | list[str]) -> list[str]:
    """
    Finds all occurrences of one or more files in one or more directory trees.

    Args:
        searchPath (str | list[str]): Path or list of paths to the root directories.
        fileNames (str | list[str]): Name or list of names of the files to find.

    Returns:
        list[str]: List of paths where the files are found.
    """
    if isinstance(searchPath, str):
        searchPath = [searchPath]
    elif not isinstance(searchPath, list):
        raise TypeError("searchPath must be a string or a list of strings.")

    if isinstance(fileNames, str):
        fileNames = [fileNames]
    elif not isinstance(fileNames, list):
        raise TypeError("fileNames must be a string or a list of strings.")

    foundFiles = []

    for rootPath in searchPath:
        if not os.path.exists(rootPath):
            raise FileNotFoundError(f"Root path {rootPath} does not exist.")

        for dirpath, _, files in os.walk(rootPath):
            for name in fileNames:
                if name in files:
                    foundFiles.append(os.path.join(dirpath, name))

    return foundFiles

def findDirs(searchPath: str | list[str], dirNames: str | list[str]) -> list[str]:
    """
    Finds all occurrences of one or more directories in one or more directory trees.

    Args:
        searchPath (str | list[str]): Path or list of paths to the root directories.
        dirNames (str | list[str]): Name or list of names of the directories to find.

    Returns:
        list[str]: List of paths where the directories are found.
    """
    if isinstance(searchPath, str):
        searchPath = [searchPath]
    elif not isinstance(searchPath, list):
        raise TypeError("searchPath must be a string or a list of strings.")

    if isinstance(dirNames, str):
        dirNames = [dirNames]
    elif not isinstance(dirNames, list):
        raise TypeError("dirNames must be a string or a list of strings.")

    foundDirs = []

    for rootPath in searchPath:
        if not os.path.exists(rootPath):
            raise FileNotFoundError(f"Root path {rootPath} does not exist.")

        for dirpath, dirnames, _ in os.walk(rootPath):
            for name in dirNames:
                if name in dirnames:
                    foundDirs.append(os.path.join(dirpath, name))

    return foundDirs

def findStringInBinFile(filePath: str, searchString: str) -> bool:
    """
    Checks if a specific string is present in a file.

    Args:
        filePath (str): Path to the file.
        searchString (str): String to search for in the file.

    Returns:
        bool: True if the string is found, False otherwise.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    if not os.path.exists(filePath):
        raise FileNotFoundError(f"File {filePath} does not exist.")
    
    if not os.access(filePath, os.R_OK):
        raise PermissionError(f"File {filePath} is not readable.")
    
    stringsFound = strings(filePath)
    for stringFound in stringsFound:
        if searchString in stringFound:
            return True
    return False

def runFsck(rawImagePath: str) -> None:
    """
    Runs fsck on a mounted raw image file.
    
    Args:
        rawImagePath (str): Path to the raw image file.
        mountPoint (str): Directory where the image is mounted.
    
    Raises:
        RuntimeError: If fsck fails.
    """
    if not os.path.exists(rawImagePath):
        raise FileNotFoundError(f"Raw image file {rawImagePath} does not exist.")
    
    # Check that the raw image is not mounted or used by any other loop device
    loopDevice = runAsRoot(["losetup", "-j", rawImagePath]).stdout.strip()
    
    if loopDevice:
        loopDevice = loopDevice.split("\n")[0].split(":")[0].strip()
        if os.path.exists(loopDevice):
            raise RuntimeError(f"Raw image {rawImagePath} is currently mounted or used by a loop device {loopDevice}. Please unmount it before running fsck.")

    dev = addPartition(rawImagePath)

    try:
        runAsRoot(["e2fsck", "-y", dev])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run fsck on raw image {rawImagePath}: {e}")
    
    finally:
        removePartition(dev)
        
        