import logging
import os

logger = logging.getLogger(__name__)

def hostToGuestPath(imagePath: str, path: str) -> str:
    """
    Fixes the root of a path by replacing the host root with the image path.
    
    Args:
        imagePath (str): The image path at the host.
        path (str): The path to be fixed.
        
    Returns:
        str: The fixed root path.
        
    Raises:
        ValueError: If the imagePath does not start with '/'.
    """
    
    if not imagePath.startswith("/") or not path.startswith("/"):
        logger.error(f"Root path {imagePath} or path {path} does not start with '/'.")
        raise ValueError(f"Root path {imagePath} or path {path} does not start with '/'.")
    
    if not imagePath.endswith("/"):
        imagePath = imagePath + "/"
    
    fixedPath = path.replace(imagePath, "/", 1)
    return fixedPath

def guestToHostPath(imagePath: str, path: str) -> str:
    """
    Fixes the root of a path by replacing the root of the image with the host path.
    
    Args:
        imagePath (str): The image path to be fixed.
        path (str): The path to be fixed.

    Returns:
        str: The fixed root path.
        
    Raises:
        ValueError: If the imagePath does not start with '/'.
    """
    if not imagePath.startswith("/"):
        logger.error(f"Root path {imagePath} does not start with '/'.")
        raise ValueError(f"Root path {imagePath} does not start with '/'.")

    return os.path.join(imagePath, path.lstrip("/"))

def resolveGuestPath(imagePath: str, path: str) -> str:
    """
    Resolves a path in the guest filesystem.
    If the path is a symlink, it resolves it to its target.
    
    If the path does not start with the imagePath, it is assumed to be a guest path and thus corrected to the host path.
    
    Args:
        imagePath (str): The root path of the image.
        path (str): The path to resolve.
        
    Returns:
        str: The resolved path.
    """
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    while os.path.islink(path):
        linkTarget = os.readlink(path)
        if os.path.isabs(linkTarget):
            # Guest-absolute target → translate to the corresponding host path.
            path = guestToHostPath(imagePath, linkTarget)
        else:
            # Relative target resolves against the link's own (host) directory.
            # It is already a host path, so do NOT translate again — doing so
            path = os.path.normpath(os.path.join(os.path.dirname(path), linkTarget))

    return path

def existsInGuest(imagePath:str, path: str) -> bool:
    """
    Checks if a path exists in the guest filesystem.
    If the path is a symlink tries to resolve it to its target.
    
    If the path does not start with the imagePath, it is assumed to be a guest path and thus corrected to the host path.
    
    Args:
        path (str): The path to check.
        
    Returns:
        bool: True if the path exists, False otherwise.
    """
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    path = resolveGuestPath(imagePath, path)

    return os.path.exists(path) 
 

def isFileInGuest(imagePath:str, path: str) -> bool:
    """
    Checks if a path is a file.
    If the path is a symlink, checks if the target is a file.
    
    If the path does not start with the imagePath, it is assumed to be a guest path and thus corrected to the host path.

    Args:
        imagePath (str): The root path of the image.
        path (str): The path to check.
        
    Returns:
        bool: True if the path is a file, False otherwise.
    """
    
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    path = resolveGuestPath(imagePath, path)
    
    return os.path.isfile(path)

def isDirInGuest(imagePath: str, path: str) -> bool:
    """
    Checks if a path is a directory.
    If the path is a symlink, checks if the target is a directory.

    If the path does not start with the imagePath, it is assumed to be a guest path and thus corrected to the host path.

    Args:
        imagePath (str): The root path of the image.
        path (str): The path to check.
        
    Returns:
        bool: True if the path is a directory, False otherwise.
    """
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    path = resolveGuestPath(imagePath, path)
    
    return os.path.isdir(path)

def isFileInGuestNotEmpty(imagePath: str, path: str) -> bool:
    """
    Checks if a file exists and is not empty.
    If the path is a symlink, checks if the target is a file and not empty.

    If the path does not start with the imagePath, it is assumed to be a guest path and thus corrected to the host path.

    Args:
        imagePath (str): The root path of the image.
        path (str): The path to check.
        
    Returns:
        bool: True if the file exists and is not empty, False otherwise.
    """
    
    if not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
    
    path = resolveGuestPath(imagePath, path)
    
    return os.path.isfile(path) and os.path.getsize(path) > 0

def recursiveGuestChmod(path: str, mode: int, imagePath: str, addPerms = False) -> None:
    """
    Recursively changes the permissions of a file or directory.
    This function does not follow symlinks unless the input path is a symlink in which case it resolves the symlink to its target
    
    If the path does not start with the imagePath, it is assumed to be a guest path and thus corrected to the host path.
    
    Args:
        path (str): The path to change permissions for.
        mode (int): The mode to set the permissions to.
        imagePath (str): The root path of the image.
        addPerms (bool): If True, adds the permissions to the existing ones, otherwise replaces them.
    """
    
    if imagePath and not path.startswith(imagePath):
        path = guestToHostPath(imagePath, path)
        
    if not os.path.lexists(path):
        logger.warning(f"Path {path} does not exist, skipping chmod.")
        return
            
    # Resolve target if path is a symlink
    path = resolveGuestPath(imagePath, path)
        
    if not os.path.exists(path):
        logger.warning(f"Path {path} does not exist, skipping chmod.")
        return
    
    def changePerms(path: str, mode: int, addPerms: bool) -> None:
        if addPerms:
            current_mode = os.stat(path).st_mode
            os.chmod(path, current_mode | mode)
        else:
            os.chmod(path, mode)
    
    # If the path is a file, change its permissions and return
    if os.path.isfile(path):
        changePerms(path, mode, addPerms)
        return
            
    for root, dirs, files in os.walk(path):
        for d in dirs:
            dirPath = os.path.join(root, d)
            if os.path.islink(dirPath) :
                continue

            changePerms(dirPath, mode, addPerms)

        for f in files:
            filePath = os.path.join(root, f)
            if os.path.islink(filePath):
                continue

            changePerms(filePath, mode, addPerms)

def readGuestLink(path: str, imagePath: str, translateToHost: bool = True) -> str:
    """
    Chroot-aware realpath: resolves symlinks at every component of the path,
    not just the final one. Handles the case where a parent directory is a
    symlink (e.g. /var → /tmp/var) so that makedirs on /var/run doesn't fail.

    NOTE: The original implementation only resolved the final component.
    This extends that behaviour to walk all components, which diverges from
    the original but is necessary for firmware with symlinked parent dirs.

    Args:
        path (str): Host path or guest-absolute path to resolve.
        imagePath (str): Host path to the mounted guest root (the chroot).
        translateToHost (bool): If True, returns a host-absolute path;
                                otherwise returns a guest-absolute path.

    Returns:
        str: The fully resolved path (host or guest depending on translateToHost).
    """
    if not imagePath:
        imagePath = os.getcwd()

    # Accept either a host path or a guest path
    if path.startswith(imagePath.rstrip("/")):
        guestPath = hostToGuestPath(imagePath, path)
    else:
        guestPath = path if path.startswith("/") else "/" + path

    resolved = "/"
    # Components still to process. Symlink targets are expanded *back* onto this
    # queue so that any symlinked component they introduce is itself resolved
    # (e.g. /etc/passwd -> default/passwd where /etc/default -> /tmp/default).
    pending = [p for p in guestPath.strip("/").split("/") if p and p != "."]
    maxHops = 40  # guard against symlink cycles
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            resolved = os.path.dirname(resolved) or "/"
            continue

        candidate = os.path.join(resolved, part)
        hostCandidate = guestToHostPath(imagePath, candidate)

        if os.path.islink(hostCandidate):
            maxHops -= 1
            if maxHops < 0:
                logger.warning(f"Too many symlink hops resolving {path}; stopping at {candidate}")
                resolved = candidate
                break
            target = os.readlink(hostCandidate)
            targetParts = [p for p in target.split("/") if p and p != "."]
            if os.path.isabs(target):
                # Guest-absolute target: restart from the guest root.
                resolved = "/"
            # Relative target resolves against the link's own directory, which is
            # the current `resolved`; leave it unchanged and re-queue the target.
            pending = targetParts + pending
        else:
            resolved = candidate

    return guestToHostPath(imagePath, resolved) if translateToHost else resolved