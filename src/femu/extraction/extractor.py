import logging
import os
from femu_extractor import extract as binwalk_extract

from typing import Optional

from ..common import Architecture, Endianess
from ..util import checkArch, strings

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Extraction and Info Collection
# ------------------------------------------------------------------

def extract(firmwarePath: str, outputPath: str) -> Optional[tuple[str, Optional[str]]]:
    """
    Extracts the firmware image and returns the paths to the extracted filesystem and kernel.
    Arguments:
        firmwarePath: Path to the firmware image.
        outputPath: Path where the extracted files will be stored.
    Returns:
        A tuple containing the path to the extracted filesystem tarball and the path to the extracted kernel (if available). If extraction fails, returns None.
    """
    if not os.path.exists(firmwarePath):
        logger.error(f"Firmware image not found: {firmwarePath}")
        return None
    
    logger.info(f"Extracting firmware image: {firmwarePath}")

    result = binwalk_extract(firmwarePath, outputPath, kernel=False)[0]
    
    # Check that extraction actually happend
    if not os.path.exists(str(result["rootfsPath"])):
        result["status"] = False
        
    if not result["status"]:
        logger.error(f"Failed to extract filesystem from {firmwarePath}")
        return None
    fsPath = str(result["rootfsPath"])
            
    logger.info(f"Root filesystem extracted to: {result["rootfsPath"]}")

    result = binwalk_extract(firmwarePath, outputPath, filesystem=False)[0]
    if not result["status"]:
        kernelPath = None
        logger.warning(f"Failed to extract kernel from {firmwarePath}")
    else:            
        kernelPath = str(result["kernelPath"])
        logger.info(f"Kernel extracted to: {kernelPath}")

    return fsPath, kernelPath

def inferArchitecture(fsImagePath:str) -> Optional[tuple[Architecture, Endianess]]:
    """
    Infers the CPU architecture and endianness of an extracted filesystem.
    Arguments:
        fsImagePath: Path to the extracted root filesystem.
    Returns:
        A tuple of (Architecture, Endianess). Returns None if the filesystem is
        missing or the architecture/endianness could not be determined.
    """
    if not os.path.exists(fsImagePath):
        logger.error(f"Filesystem image not found: {fsImagePath}")
        return None

    tempDir = os.path.join("/tmp", f"femu-tmp-{os.getpid()}")

    try:
        architecture, endianess = checkArch(fsImagePath, tempDir)
    except Exception:
        logger.error("Could not infer architecture")
        return None

    if architecture == Architecture.UNKNOWN or endianess == Endianess.UNKNOWN:
        logger.error("Failed to determine architecture or endianness.")
        return None

    return architecture, endianess

def inferKernelInfo(kernelPath: str) -> Optional[tuple[str, list[str]]]:
    """
    Infers kernel details by scanning the kernel binary's printable strings.
    Arguments:
        kernelPath: Path to the extracted kernel image.
    Returns:
        A tuple of (kernelVersion, inferredKernelInits) where
        kernelVersion is the parsed version (e.g. "5.4.0") and inferredKernelInits is the list of
        init paths found in "init=" arguments. Returns None if the kernel image is
        not found.
    """
    logger.info(f"Inferring kernel at: {kernelPath}")
    
    if not os.path.exists(kernelPath):
        logger.error("Kernel image not found.")
        return None
    
    kernelVersion = ""
    inferredKernelInits = []
    
    for string in strings(kernelPath, minLength=4):
        if "Linux version" in string:
            temp = string.split("Linux version ")[1].split(" ")[0]
            if temp:
                if kernelVersion and kernelVersion != temp:
                    logger.warning(f"Multiple kernel version strings found: {kernelVersion} and {temp}. Using the first one.")
                    continue
                
                kernelVersion = temp
                logger.debug(f"Found kernel version: {kernelVersion}")
        elif "init=" in string:
            temp = string.split("init=")[1].split(" ")[0]
            if temp:
                inferredKernelInits.append(temp)
                logger.debug(f"Found kernel init command: {temp}")

    return kernelVersion, inferredKernelInits

def analyzeImage(fsPath: str, kernelPath: Optional[str] = None) -> tuple[tuple[Architecture, Endianess], Optional[tuple[str, list[str]]]]:
    """
    Runs the available analyses over an extracted image.
    Arguments:
        fsPath: Path to the extracted root filesystem.
        kernelPath: Optional path to the extracted kernel image; kernel info is
            only inferred when provided.
    Returns:
        A tuple of (archInfo, kernelInfo), where archInfo is the result of
        inferArchitecture() and kernelInfo is the result of inferKernelInfo()
        (or None when no kernel path is given). Either element may be None if its
        analysis failed.
    """
    archInfo = inferArchitecture(fsPath)
    
    if archInfo is None:
        archInfo = (Architecture.UNKNOWN, Endianess.UNKNOWN)
    
    kernelInfo = None
    if kernelPath:
        kernelInfo = inferKernelInfo(kernelPath)

    return archInfo, kernelInfo