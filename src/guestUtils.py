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
    
    if imagePath.endswith("/"):
        imagePath = imagePath[:-1]
    
    fixedPath = path.replace(imagePath, "/", 1)
    logger.debug(f"hostToGuestPath Fixed path: {path} to {fixedPath}")
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
    if not imagePath.startswith("/") or not path.startswith("/"):
        logger.error(f"Root path {imagePath} or path {path} does not start with '/'.")
        raise ValueError(f"Root path {imagePath} or path {path} does not start with '/'.")
    
    if not imagePath.endswith("/"):
        imagePath += "/"
        
    fixedPath = path.replace("/", imagePath, 1)
    logger.debug(f"guestToHostPath Fixed path: {path} to {fixedPath}")
    return fixedPath

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
    
    while os.path.islink(path):
        linkTarget = os.readlink(path)
        path = guestToHostPath(imagePath, linkTarget)

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
    
    while os.path.islink(path):
        linkTarget = os.readlink(path)
        path = guestToHostPath(imagePath, linkTarget)
    
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
    
    while os.path.islink(path):
        linkTarget = os.readlink(path)
        path = guestToHostPath(imagePath, linkTarget)
    
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
    
    while os.path.islink(path):
        linkTarget = os.readlink(path)
        path = guestToHostPath(imagePath, linkTarget)
    
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
    while os.path.islink(path):
        linkTarget = os.readlink(path)
        path = guestToHostPath(imagePath, linkTarget)
        
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
    If the path is a symlink, reads the target of the symlink and fixes it to the host path.
    
    Args:
        path (str): The host path to check.
        imagePath (str): The image path at the host.
        translateToHost (bool): If True, translates the path to the host path.
        
    Returns:
        str: The target of the symlink if it exists, otherwise the original path.
    """
    if not os.path.lexists(path):
        return path
    
    if not os.path.islink(path):
        return path
    
    # TODO: Possibly check If new path is a symlink and read it again (against original implementation)
    linkTarget = os.readlink(path)
    
    if translateToHost:
        if not imagePath:
            imagePath = os.getcwd()
        
        linkTarget = guestToHostPath(imagePath, linkTarget)

    return linkTarget 