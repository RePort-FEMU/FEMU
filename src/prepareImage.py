import logging
import stat
import os
import re

from util import find, findDirs, strings, findStringInBinFile

from guestUtils import  (
    guestToHostPath, 
    hostToGuestPath, 
    existsInGuest,
    isFileInGuest,
    isDirInGuest,
    isFileInGuestNotEmpty,
    recursiveGuestChmod,
    readGuestLink
)

logger = logging.getLogger(__name__)

def initFirmadyne(rootPath: str) -> None:
    """
    Initialize Firmadyne by creating necessary directories.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.
    Raises:
        RuntimeError: If the initialization fails.
    """
    
    if not os.path.exists(rootPath):
        logger.error(f"Root path {rootPath} does not exist.")
        raise RuntimeError(f"Root path {rootPath} does not exist.")

    logger.info("Initializing Firmadyne...")
    try:
        os.mkdir(os.path.join(rootPath, "firmadyne"))
        os.mkdir(os.path.join(rootPath, "firmadyne", "libnvram"))
        os.mkdir(os.path.join(rootPath, "firmadyne", "libnvram.override"))
    except OSError as e:
        logger.error(f"Failed to create directories: {e}")
        raise RuntimeError(f"Failed to create directories: {e}")  
    logger.info("Firmadyne initialized successfully.")  
    
    
def validateInits(rootPath: str, suspectedInits: list[str]) -> list[str]:
    """
    Checks if the suspected init commands exist in the image and creates a list of valid init commands.
    This function will emit a file with the list of init commands to /firmadyne/init in the guest.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.
        suspectedInits (list[str]): List of possible kernel init commands.
        
    Returns:
        list[str]: List of init commands found in the image.
        
    Raises:
        RuntimeError: If the init list file cannot be created.
    """
    logger.info("Finding init commands in the image...")
    
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
                        os.makedirs(readGuestLink(fullPath, rootPath), exist_ok=True)
                        if dirPath not in createdDirs:
                            createdDirs.add(dirPath)
                            logger.debug(f"Created directory: {fullPath} for binary: {hostToGuestPath(rootPath, filePath)}")
                        
    # Emit created directories to the log
    with open(guestToHostPath(rootPath, "/firmadyne/dir_log"), "w") as f:
        f.writelines(f"{d}\n" for d in createdDirs)
        
def populateEtc(rootPath: str) -> None:
    """
    Populates the /etc directory with necessary files.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.
    """

    os.makedirs(readGuestLink(guestToHostPath(rootPath, "/etc"), rootPath), exist_ok=True)

    essentials = {
        "/etc/TZ": "EST5EDT\n",
        "/etc/hosts": "127.0.0.1 localhost\n",
        "/etc/passwd": "root::0:0:root:/root:/bin/sh\n",
    }
    
    for filePath, content in essentials.items():
        if not isFileInGuestNotEmpty(rootPath, filePath):
            fullPath = readGuestLink(guestToHostPath(rootPath, filePath), rootPath)
            os.makedirs(os.path.dirname(fullPath), exist_ok=True)
            with open(fullPath, "w") as f:
                f.write(content)
                logger.debug(f"Created essential file: {fullPath}")  
                
def populateDev(rootPath: str) -> None:
    """
    Populates the /dev directory with necessary files.
    
    Args:
        rootPath (str): Path to the Firmadyne root directory.
    """

    devPath = readGuestLink(guestToHostPath(rootPath, "/dev"), rootPath)

    os.makedirs(devPath, exist_ok=True)
    fileCount = len(os.listdir(devPath))
    
    if fileCount <= 5:
        logger.warning("Creating device nodes!")
        
        os.makedirs(guestToHostPath(rootPath, "/dev/mtd"), exist_ok=True)
        os.makedirs(guestToHostPath(rootPath, "/dev/mtdblock"), exist_ok=True)
        os.makedirs(guestToHostPath(rootPath, "/dev/pts"), exist_ok=True)
        
        nodesToCreate = {
            "/dev/mem": {"type": stat.S_IFCHR, "perms": 0o660, "major": 1, "minor": 1},
            "/dev/kmem": {"type": stat.S_IFCHR, "perms": 0o640, "major": 1, "minor": 2},
            "/dev/null": {"type": stat.S_IFCHR, "perms": 0o666, "major": 1, "minor": 3},
            "/dev/zero": {"type": stat.S_IFCHR, "perms": 0o666, "major": 1, "minor": 5},
            "/dev/random": {"type": stat.S_IFCHR, "perms": 0o444, "major": 1, "minor": 8},
            "/dev/urandom": {"type": stat.S_IFCHR, "perms": 0o444, "major": 1, "minor": 9},
            "/dev/armem": {"type": stat.S_IFCHR, "perms": 0o666, "major": 1, "minor": 13},
            
            "/dev/tty": {"type": stat.S_IFCHR, "perms": 0o666, "major": 5, "minor": 0},
            "/dev/console": {"type": stat.S_IFCHR, "perms": 0o622, "major": 5, "minor": 1},
            "/dev/ptmx": {"type": stat.S_IFCHR, "perms": 0o666, "major": 5, "minor": 2},
            "/dev/tty0": {"type": stat.S_IFCHR, "perms": 0o622, "major": 4, "minor": 0},
            "/dev/ttyS0": {"type": stat.S_IFCHR, "perms": 0o660, "major": 4, "minor": 64},
            "/dev/ttyS1": {"type": stat.S_IFCHR, "perms": 0o660, "major": 4, "minor": 65},
            "/dev/ttyS2": {"type": stat.S_IFCHR, "perms": 0o660, "major": 4, "minor": 66},
            "/dev/ttyS3": {"type": stat.S_IFCHR, "perms": 0o660, "major": 4, "minor": 67},
            "/dev/adsl0": {"type": stat.S_IFCHR, "perms": 0o644, "major": 100, "minor": 0},
            "/dev/ppp": {"type": stat.S_IFCHR, "perms": 0o644, "major": 108, "minor": 0},
            "/dev/hidraw0": {"type": stat.S_IFCHR, "perms": 0o666, "major": 251, "minor": 0},
        }
        
        for i in range(11):
            nodesToCreate[f"/dev/mtd/{i}"] = {"type": stat.S_IFCHR, "perms": 0o644, "major": 90, "minor": i * 2}
            
        for i in range(11):
            nodesToCreate[f"/dev/mtd{i}"] = {"type": stat.S_IFCHR, "perms": 0o644, "major": 90, "minor": i * 2}
            nodesToCreate[f"/dev/mtdr{i}"] = {"type": stat.S_IFCHR, "perms": 0o644, "major": 90, "minor": i * 2 + 1}

        for i in range(11):
            nodesToCreate[f"/dev/mtdblock/{i}"] = {"type": stat.S_IFBLK, "perms": 0o644, "major": 31, "minor": i}
            nodesToCreate[f"/dev/mtdblock{i}"] = {"type": stat.S_IFBLK, "perms": 0o644, "major": 31, "minor": i}

        for i in range(4):
            nodesToCreate[f"/dev/tts/{i}"] = {"type": stat.S_IFCHR, "perms": 0o660, "major": 4, "minor": 64+i}
            
        for node, attrs in nodesToCreate.items():
            nodePath = readGuestLink(guestToHostPath(rootPath, node), rootPath)
            if not os.path.lexists(nodePath):
                os.mknod(nodePath, mode=attrs["type"] | attrs["perms"], device=os.makedev(attrs["major"], attrs["minor"]))
                logger.debug(f"Created device node: {nodePath} with major: {attrs['major']} minor: {attrs['minor']}")


    # Create gpio files
    if (isFileInGuest(rootPath, "/dev/gpio") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/dev/gpio"), rootPath), "/dev/gpio/in")) or \
        (isFileInGuest(rootPath, "/usr/lib/libcm.so") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/usr/lib/libcm.so"), rootPath), "/dev/gpio/in")) or \
        (isFileInGuest(rootPath, "/usr/lib/libshared.so") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/usr/lib/libshared.so"), rootPath), "/dev/gpio/in")):

        logger.info("Creating /dev/gpio files...")
        # Remove old gpio files if they exist
        if isFileInGuest(rootPath, "/dev/gpio"):
            os.remove(readGuestLink(guestToHostPath(rootPath, "/dev/gpio"), rootPath))
            
        os.mkdir(guestToHostPath(rootPath, "/dev/gpio"))
        with open(guestToHostPath(rootPath, "/dev/gpio/in"), "wb") as f:
            f.write(b"\xff" * 4)


def addEssentialFiles(rootPath: str) -> None:
    """
    Adds essential files to the image in case they are missing.

    Args:
        rootPath (str): Path to the Firmadyne root directory.
    Raises:
        RuntimeError: If the essential files cannot be created.
    """

    populateEtc(rootPath)
    populateDev(rootPath)
    
def preventReboot(rootPath: str) -> None:
    os.remove(guestToHostPath(rootPath, "/sbin/reboot")) if existsInGuest(rootPath, "/sbin/reboot") else None
    os.remove(guestToHostPath(rootPath, "/etc/scripts/sys_resetbutton")) if existsInGuest(rootPath, "/etc/scripts/sys_resetbutton") else None

def addNvramEntries(rootPath: str) -> None:
    """
    Tries to add NVRAM entries to the image.
    Args:
        rootPath (str): Path to the Firmadyne root directory.
    Raises:
        RuntimeError: If the NVRAM entries cannot be added.
    """
    logger.info("Adding NVRAM entries...")
    entries = {}
    
    if isFileInGuest(rootPath, "/sbin/rc") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/sbin/rc"), rootPath), "ipv6_6to4_lan_ip"):
        entries["ipv6_6to4_lan_ip"] = "2002:7f00:0001::"

    if isFileInGuest(rootPath, "/lib/libacos_shared.so") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/lib/libacos_shared.so"), rootPath), "time_zone_x"):
        entries["time_zone_x"] = "0"
        
    # rip_multicast
    if isFileInGuest(rootPath, "/usr/sbin/httpd") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/usr/sbin/httpd"), rootPath), "rip_multicast"):
        entries["rip_multicast"] = "0"

    # bs_trustedip_enable
    if isFileInGuest(rootPath, "/usr/sbin/httpd") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/usr/sbin/httpd"), rootPath), "bs_trustedip_enable"):
        entries["bs_trustedip_enable"] = "0"

    # filter_rule_tbl
    if isFileInGuest(rootPath, "/usr/sbin/httpd") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/usr/sbin/httpd"), rootPath), "filter_rule_tbl"):
        entries["filter_rule_tbl"] = ""

    # rip_enable
    if isFileInGuest(rootPath, "/sbin/acos_service") and findStringInBinFile(readGuestLink(guestToHostPath(rootPath, "/sbin/acos_service"), rootPath), "rip_enable"):
        entries["rip_enable"] = "0"

    # Write entries to /firmadyne/libnvram.override/
    nvram_override_dir = guestToHostPath(rootPath, "/firmadyne/libnvram.override")
    os.makedirs(nvram_override_dir, exist_ok=True)
    for key, value in entries.items():
        logger.debug(f"Adding NVRAM entry: {key} = {value}")
        with open(os.path.join(nvram_override_dir, key), "w") as f:
            f.write(value)
    
    logger.info("NVRAM entries added successfully.")

def fixFileSystem(rootPath: str) -> None:
    logger.info("Fixing file system...")

    # Create links for busybox sh
    if not existsInGuest(rootPath, "/bin/sh"):
        #FirmAE diff
        # if broken symlink, remove it before creating a new one
        if os.path.lexists(guestToHostPath(rootPath, "/bin/sh")) and os.path.islink(guestToHostPath(rootPath, "/bin/sh")):
            os.remove(guestToHostPath(rootPath, "/bin/sh"))
        
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
        os.makedirs(readGuestLink(fullPath, rootPath), exist_ok=True)

    # Fix permissions on all **/bin and **/sbin directories
    # TODO: make this more robust by checking if the directories are linked
    dirs = findDirs(rootPath, ["bin", "sbin"])
    for dirPath in dirs:
        if os.path.exists(dirPath):
            recursiveGuestChmod(dirPath, 0o111, rootPath, addPerms=True)
            logger.debug(f"Fixed permissions on directory: {dirPath}")
        else:
            logger.warning(f"Directory {dirPath} does not exist, skipping permission fix.")

   # Create directories referenced by binaries in the image
    try:
        createReferencedDirectories(rootPath)
    except RuntimeError as e:
        logger.error(f"Failed to create referenced directories: {e}")
        raise RuntimeError(f"Failed to create referenced directories: {e}")
    
    try:
        addEssentialFiles(rootPath)
    except RuntimeError as e:
        logger.error(f"Failed to add essential files: {e}")
        raise RuntimeError(f"Failed to add essential files: {e}")
    
    preventReboot(rootPath)
    logger.info("File system fixed successfully.")
    
def prepareImage(rootPath: str, possibleInits: list[str]) -> tuple[list[str], dict[str, str]] | None:
    """
    Prepares the image for emulation by initializing Firmadyne, finding the init commands, fixing the file system, adding vital directories as well as NVRAM entries.

    Args:
        rootPath (str): Path to the Firmadyne root directory.

    Returns:
        None: If the preparation fails.
        tuple[list[str], dict[str, str]]: A tuple containing a list of verified init commands and a dictionary of found services with their start commands.
        
    Raises:
        RuntimeError: If the preparation fails.
    
    """
    
    logger.info("Preparing image for emulation...")
    
    if not os.path.exists(rootPath):
        logger.error(f"Root path {rootPath} does not exist.")
        return None
    
    initFirmadyne(rootPath)

    verifiedInits = validateInits(rootPath, possibleInits)

    foundServices = findServices(rootPath)

    fixFileSystem(rootPath)

    addNvramEntries(rootPath)

    return verifiedInits, foundServices