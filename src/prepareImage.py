import logging
import os
import re

from util import find, findDirs, strings

logger = logging.getLogger("emulator")

def existsInGuest(imagePath:str, path: str) -> bool:
    """
    Checks if a path exists.
    If the path is a symlink, checks if the target in host exists.
    
    Args:
        path (str): The path to check.
        
    Returns:
        bool: True if the path exists, False otherwise.
    """
    # If path is given as a guest path, correct it to the host path
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    if os.path.exists(path):
        return True
    
    if os.path.islink(path):
        linkTarget = os.readlink(path)
        correctedPath = guestToHostPath(imagePath, linkTarget)
        while os.path.islink(correctedPath):
            linkTarget = os.readlink(correctedPath)
            correctedPath = guestToHostPath(imagePath, linkTarget)
        return os.path.exists(correctedPath)
    
    return False

def isFileInGuest(imagePath:str, path: str) -> bool:
    """
    Checks if a path is a file.
    If the path is a symlink, checks if the target is a file.

    Args:
        imagePath (str): The root path of the image.
        path (str): The path to check.
        
    Returns:
        bool: True if the path is a file, False otherwise.
    """
    
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    if os.path.islink(path):
        linkTarget = os.readlink(path)
        correctedPath = guestToHostPath(imagePath, linkTarget)
        while os.path.islink(correctedPath):
            linkTarget = os.readlink(correctedPath)
            correctedPath = guestToHostPath(imagePath, linkTarget)
        return os.path.isfile(correctedPath)
    
    return os.path.isfile(path)

def isDirInGuest(imagePath: str, path: str) -> bool:
    """
    Checks if a path is a directory.
    If the path is a symlink, checks if the target is a directory.

    Args:
        imagePath (str): The root path of the image.
        path (str): The path to check.
        
    Returns:
        bool: True if the path is a directory, False otherwise.
    """
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    if os.path.islink(path):
        linkTarget = os.readlink(path)
        correctedPath = guestToHostPath(imagePath, linkTarget)
        while os.path.islink(correctedPath):
            linkTarget = os.readlink(correctedPath)
            correctedPath = guestToHostPath(imagePath, linkTarget)
        return os.path.isdir(correctedPath)
    
    return os.path.isdir(path)

def isFileInGuestNotEmpty(imagePath: str, path: str) -> bool:
    """
    Checks if a file exists and is not empty.
    If the path is a symlink, checks if the target is a file and not empty.

    Args:
        imagePath (str): The root path of the image.
        path (str): The path to check.
        
    Returns:
        bool: True if the file exists and is not empty, False otherwise.
    """
    
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    if os.path.islink(path):
        linkTarget = os.readlink(path)
        correctedPath = guestToHostPath(imagePath, linkTarget)
        while os.path.islink(correctedPath):
            linkTarget = os.readlink(correctedPath)
            correctedPath = guestToHostPath(imagePath, linkTarget)
        return os.path.isfile(correctedPath) and os.path.getsize(correctedPath) > 0
    
    return os.path.isfile(path) and os.path.getsize(path) > 0

def recursiveChmod(path: str, mode: int, imagePath: str = "", addPerms = False) -> None:
    """
    Recursively changes the permissions of a file or directory.
    If the imagePath is provided, this function will also change the permissions on possible symlink targets on the guest.
    Also, if the imagePath is provided, the path will be fixed to the host path.
    
    Args:
        path (str): The path to change permissions for.
        mode (int): The mode to set the permissions to.
        imagePath (str): The root path of the image.
        addPerms (bool): If True, adds the permissions to the existing ones, otherwise replaces them.
    
    """
    
    if imagePath and not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
            
    if not os.path.exists(path):
        logger.warning(f"Path {path} does not exist, skipping chmod.")
        return
    
    for root, dirs, files in os.walk(path):
        for d in dirs:
            dirPath = os.path.join(root, d)
            targetPath = dirPath
            if os.path.islink(dirPath) and imagePath:
                linkTarget = os.readlink(dirPath)
                correctedPath = guestToHostPath(imagePath, linkTarget)
                while os.path.islink(correctedPath):
                    linkTarget = os.readlink(correctedPath)
                    correctedPath = guestToHostPath(imagePath, linkTarget)
                targetPath = correctedPath
            if os.path.exists(targetPath):
                if addPerms:
                    current_mode = os.stat(targetPath).st_mode
                    os.chmod(targetPath, current_mode | mode)
                else:
                    os.chmod(targetPath, mode)
            else:
                logger.warning(f"Target dir {targetPath} does not exist, skipping chmod.")

        for f in files:
            filePath = os.path.join(root, f)
            targetPath = filePath
            if os.path.islink(filePath) and imagePath:
                linkTarget = os.readlink(filePath)
                correctedPath = guestToHostPath(imagePath, linkTarget)
                while os.path.islink(correctedPath):
                    linkTarget = os.readlink(correctedPath)
                    correctedPath = guestToHostPath(imagePath, linkTarget)
                targetPath = correctedPath
            if os.path.exists(targetPath):
                if addPerms:
                    current_mode = os.stat(targetPath).st_mode
                    os.chmod(targetPath, current_mode | mode)
                else:
                    os.chmod(targetPath, mode)
            else:
                logger.warning(f"Target file {targetPath} does not exist, skipping chmod.")
    
def hostToGuestPath(imagePath: str, path: str) -> str:
    """
    Fixes the root of a path by replacing the host root with the image root.
    
    Args:
        imagePath (str): The image path at the host.
        path (str): The path to be fixed.
        
    Returns:
        str: The fixed root path.
    """
    
    if not imagePath.startswith("/"):
        logger.error(f"Root path {imagePath} does not start with '/'.")
        raise ValueError(f"Root path {imagePath} does not start with '/'.")
    
    fixedPath = path.replace(imagePath, "/", 1)
    logger.debug(f"Fixed path: {fixedPath}")
    return fixedPath

def guestToHostPath(imagePath: str, path: str) -> str:
    """
    Fixes the root of a path by replacing the root of the image with the host path.
    
    Args:
        imagePath (str): The image path to be fixed.
        path (str): The path to be fixed.

    Returns:
        str: The fixed root path.
    """
    if not imagePath.startswith("/"):
        logger.error(f"Root path {imagePath} does not start with '/'.")
        raise ValueError(f"Root path {imagePath} does not start with '/'.")
    fixedPath = imagePath.replace("/", path, 1)
    logger.debug(f"Fixed path: {fixedPath}")
    return fixedPath

def installFirmadyne(rootPath: str) -> None:
    """
    Installs Firmadyne by creating necessary directories and copying files.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.
    Raises:
        RuntimeError: If the installation fails.
    """
    
    if not os.path.exists(rootPath):
        logger.error(f"Root path {rootPath} does not exist.")
        raise RuntimeError(f"Root path {rootPath} does not exist.")
    
    logger.info("Installing Firmadyne...")
    try:
        os.mkdir(os.path.join(rootPath, "firmadyne"))
        os.mkdir(os.path.join(rootPath, "firmadyne", "libnvram"))
        os.mkdir(os.path.join(rootPath, "firmadyne", "libnvram.override"))
    except OSError as e:
        logger.error(f"Failed to create directories: {e}")
        raise RuntimeError(f"Failed to create directories: {e}")    
    
    
def findInit(rootPath: str, suspectedInits: list[str]) -> list[str]:
    """
    Creates the init list file in the Firmadyne root directory of the emulated image.
    Args:
        rootPath (str): Path to the Firmadyne root directory.
        suspectedInits (list[str]): List of possible kernel init commands.
        
    Returns:
        list[str]: List of init commands found in the image.
        
    Raises:
        RuntimeError: If the init list file cannot be created.
    """
    initListFile = os.path.join(rootPath, "firmadyne", "init")
    
    possibleInits = suspectedInits.copy()
    
    # Add default init commands if not already present
    if existsInGuest(rootPath, "/init") and not isDirInGuest(rootPath, "/init"):
        possibleInits.append(hostToGuestPath(rootPath, "/init"))

    for possibleInit in ["rcS", "preinit", "preinitMT"]:
        results = find(rootPath, possibleInit)
        for result in results:
            possibleInits.append(hostToGuestPath(rootPath, result))

    if len(possibleInits) == 0:
        logger.warning("No init commands found in the image. Using default preInit.sh.")
        with open(initListFile, "w") as f:
            f.write("/firmadyne/preInit.sh\n")
        return ["/firmadyne/preInit.sh"]
        
    # Remove duplicates without changing order
    seen = set()
    uniqueInits = []
    for init in possibleInits:
        if init not in seen:
            seen.add(init)
            uniqueInits.append(init)
    
    foundInits = []
    for init in uniqueInits:
        initHostPath = guestToHostPath(rootPath, init)
            
        if isDirInGuest(rootPath, init):
            continue

        if isFileInGuest(rootPath, init):
            foundInits.append(init)
            continue
            
        # If file does not exist, or symlink is broken, try to locate it 
        filename = os.path.basename(init)
        # TODO: Dereference possible symlinks
        possibleLocations = [guestToHostPath(rootPath, loc) for loc in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]]
        results = find(possibleLocations, filename)

        if len(results) > 0:
            # Create a symlink to the first found result
            linkTarget = results[0]
            if os.path.islink(initHostPath):
                os.remove(initHostPath)
                
            os.symlink(hostToGuestPath(rootPath, linkTarget), initHostPath)
            foundInits.append(init)
            logging.debug(f"Fixed file {init} by creating a symlink to {linkTarget}.")
            continue
        
        # FIRMAE diff
        # If the name of the file was not found, last resort to try to find the old target if it was a symlink
        if os.path.islink(initHostPath):
            linkTarget = os.readlink(initHostPath)
            filename = os.path.basename(linkTarget)
            results = find(possibleLocations, filename)
            if len(results) > 0:
                # Create a symlink to the first found result
                linkTarget = results[0]
                if os.path.islink(initHostPath):
                    os.remove(initHostPath)

                os.symlink(hostToGuestPath(rootPath, linkTarget), initHostPath)
                foundInits.append(init)
                logging.debug(f"Fixed file {init} by creating a symlink to {linkTarget}.")
                continue
            
    if len(foundInits) == 0:
        logger.warning("No init commands found in the image. Using default preInit.sh.")
    
    foundInits.append("/firmadyne/preInit.sh")
    with open(initListFile, "w") as f:
        for init in foundInits:
            f.write(f"{init}\n")
    
    logger.info(f"Init commands found: {foundInits}")
    return foundInits
                
def findServices(rootPath: str) -> dict[str, str]:
    """
    Finds possible services in the image and emits a list of their paths.
            
    Args:
        rootPath (str): Path to the Firmadyne root directory.
        
    Returns:
        dict[str, str]: Dictionary of service paths and their start commands.

    Raises:
        RuntimeError: If the service list file cannot be created.
    """
    
    # TODO: Add ability to firmadyne to run multiple services
    
    serviceFile = os.path.join(rootPath, "firmadyne", "service")
    nameFile = os.path.join(rootPath, "firmadyne", "service_name")
    services = {}
    
    found = False 
    name = ""
    startCommand = ""
    
    if existsInGuest(rootPath, "/etc/init.d/uhttpd"):
        services["/etc/init.d/uhttpd"] = "/etc/init.d/uhttpd start"
        if not found:
            found = True
            name = "uhttpd"
            startCommand = "/etc/init.d/uhttpd start"

    if existsInGuest(rootPath, "/usr/bin/httpd"):
        services["/usr/bin/httpd"] = "/usr/bin/httpd"
        if not found:
            found = True
            name = "httpd"
            startCommand = "/usr/bin/httpd"

    if existsInGuest(rootPath, "/usr/sbin/httpd"):
        services["/usr/sbin/httpd"] = "/usr/sbin/httpd"
        if not found:
            found = True
            name = "httpd"
            startCommand = "/usr/sbin/httpd"

    if existsInGuest(rootPath, "/bin/goahead"):
        services["/bin/goahead"] = "/bin/goahead"
        if not found:
            found = True
            name = "goahead"
            startCommand = "/bin/goahead"

    if existsInGuest(rootPath, "/bin/alphapd"):
        services["/bin/alphapd"] = "/bin/alphapd"
        if not found:
            found = True
            name = "alphapd"
            startCommand = "/bin/alphapd"

    if existsInGuest(rootPath, "/bin/boa"):
        services["/bin/boa"] = "/bin/boa"
        if not found:
            found = True
            name = "boa"
            startCommand = "/bin/boa"

    if existsInGuest(rootPath, "/usr/sbin/lighttpd"):
        services["/usr/sbin/lighttpd"] = "/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf"
        if not found:
            found = True
            name = "lighttpd"
            startCommand = "/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf"
            
    if found:
        with open(serviceFile, "w") as f:
            f.write(f"{startCommand}\n")
        with open(nameFile, "w") as f:
            f.write(f"{name}\n")
        logger.info(f"Found service: {name} with command: {startCommand}")
        return services
            
    else:
        logger.warning("No services found in the image.")
        return {}
    
def readIfLinked(path: str, imagePath: str = "", translateToHost: bool = True) -> str:
    """
    If the path is a symlink, reads the target of the symlink and fixes it to the host path.
    
    Args:
        path (str): The path to check.
        imagePath (str): The image path at the host. If not provided, uses the current working directory.
        translateToHost (bool): If True, translates the path to the host path.
        
    Returns:
        str: The target of the symlink if it exists, otherwise the original path.
    """
    if not os.path.lexists(path):
        return path
    
    if not os.path.islink(path):
        return path
    
    # TODO: Possibly check If new path is a symlink and read it again
    linkTarget = os.readlink(path)
    
    if translateToHost:
        if not imagePath:
            imagePath = os.getcwd()
        
        linkTarget = guestToHostPath(imagePath, linkTarget)

    return linkTarget    
    
def createReferencedDirectories(rootPath: str) -> None:
    """
    Creates directories referenced by binaries in the image.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.
        
    Raises:
        RuntimeError: If the executable locations do not exist.
    """
    pattern = r'^(/var|/etc|/tmp)(.+)/([^/]+)$'
    executableLocations = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
    createdDirs = set()
    for location in executableLocations:
        if not os.path.exists(guestToHostPath(rootPath, location)):
            logger.warning(f"Executable location {location} does not exist")
            continue

        for root, _, files in os.walk(guestToHostPath(rootPath, location)):
            for file in files:
                filePath = os.path.join(root, file)
                # Check if the file has user execute permission
                if not os.access(filePath, os.X_OK):
                    continue
                
                # Get all hardcoded paths in the binary
                possiblePaths = strings(filePath)
                for path in possiblePaths:
                    match = re.match(pattern, path)
                    if match:
                        dirPath = match.group(1) + match.group(2)
                        # Check that the directory is not meant to be used with a function like printf
                        if "%s" in dirPath or "%d" in dirPath or "%c" in dirPath or "/tmp/services" in dirPath:
                            continue
                        fullPath = guestToHostPath(rootPath, dirPath)
                        os.makedirs(readIfLinked(fullPath, rootPath), exist_ok=True)
                        if dirPath not in createdDirs:
                            createdDirs.add(dirPath)
                            logger.debug(f"Created directory: {fullPath} for binary: {hostToGuestPath(rootPath, filePath)}")
                        
    # Emit created directories to the log
    with open(guestToHostPath(rootPath, "/firmadyne/dir_log"), "w") as f:
        f.writelines(f"{d}\n" for d in createdDirs)
        
# def addEssentialFiles(rootPath: str) -> None:
#     """
#     Adds essential files to the image in case they are missing.
    
#     Args:
#         rootPath (str): Path to the Firmadyne root directory.
        
#     Raises:
#         RuntimeError: If the essential files cannot be created.
#     """
    
#     os.makedirs(guestToHostPath(rootPath, "/etc"), exist_ok=True)
#     if not os.path.exists(guestToHostPath(rootPath, "/etc/TZ")) :
    
def fixFileSystem(rootPath: str) -> None:
    # Create links for busybox sh
    if not existsInGuest(rootPath, "/bin/sh"):
        os.symlink("/firmadyne/busybox", guestToHostPath(rootPath, "/bin/sh"))
    os.symlink("/firmadyne/busybox", guestToHostPath(rootPath, "/firmadyne/sh"))

    dirsToCreate = [
        "/proc",
        "/dev/pts",
        "/etc_ro",
        "/tmp",
        "/var",
        "/run",
        "/sys",
        "/root",
        "/tmp/var",
        "/tmp/media",
        "/tmp/etc",
        "/tmp/var/run",
        "/tmp/home/root",
        "/tmp/mnt",
        "/tmp/opt",
        "/tmp/www",
        "/var/run",
        "/var/lock",
        "/usr/bin",
        "/usr/sbin"
    ]

    for dirPath in dirsToCreate:
        fullPath = guestToHostPath(rootPath, dirPath)
        os.makedirs(readIfLinked(fullPath, rootPath), exist_ok=True)

    # Fix permissions on all **/bin and **/sbin directories
    # TODO: make this more robust by checking if the directories are linked
    dirs = findDirs(rootPath, ["bin", "sbin"])
    for dirPath in dirs:
        if os.path.exists(dirPath):
            recursiveChmod(dirPath, 0o111, rootPath, addPerms=True)
            logger.debug(f"Fixed permissions on directory: {dirPath}")
        else:
            logger.warning(f"Directory {dirPath} does not exist, skipping permission fix.")

   # Create directories referenced by binaries in the image
    try:
        createReferencedDirectories(rootPath)
    except RuntimeError as e:
        logger.error(f"Failed to create referenced directories: {e}")
        raise RuntimeError(f"Failed to create referenced directories: {e}")
    
    
                


def prepareImage(rootPath: str, state: dict[str, str | list[str]]) -> bool:
    """
    Prepares the image for emulation by installing Firmadyne, creating necessary directories, and copying files.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.

    Returns:
        bool: True if the preparation is successful, False otherwise.
        
    Raises:
        RuntimeError: If the preparation fails.
    
    """
    
    logger.info("Preparing image for emulation...")
    
    if not os.path.exists(rootPath):
        logger.error(f"Root path {rootPath} does not exist.")
        return False
    
    try:
        installFirmadyne(rootPath)
    except RuntimeError as e:
        logger.error(f"Failed to install Firmadyne: {e}")
        return False

    try:
        findInit(rootPath, list(state.get("inferredKernelInit", [])))
    except RuntimeError as e:
        logger.error(f"Failed to find init commands: {e}")
        return False
    
    try:
        findServices(rootPath)
    except RuntimeError as e:
        logger.error(f"Failed to find services: {e}")
        return False

    return True