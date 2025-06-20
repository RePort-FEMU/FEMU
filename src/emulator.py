import logging
import shutil
import os
import sys

from common import RunningMode, Architecture, Endianess, KILO, MEGA, GIGA
from dbInterface import DBInterface
from util import (
    io_md5,
    checkArch,
    strings,
    checkCompatibility,
    getFilesInfo,
    getLinksInfo,
    getObjectIds,
    insertObjectsToImage,
    insertLinksToImage,
    createRawImg,
    mountImage,
    unmountImage,
)


sys.path.append(os.path.join(os.path.dirname(__file__), 'extractor'))
from extractor.extractor import extract
# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger(__name__)

class Emulator:
    def __init__(self, mode: RunningMode, inputPath: str, outputPath: str, brand: str = "auto", toolsPath: str = "../tools", artifactPath: str = "../artifacts", dbIP: str = "", dbPort: int = 5432):
        # Information about the emulator environment
        self.mode = mode
        self.inputPath = inputPath
        self.outputPath = outputPath
        self.imagePath = outputPath + "/images"
        self.scratchPath = outputPath + "/scratch"
        self.toolsPath = toolsPath
        self.artifactPath = artifactPath
        self.brand = brand
        self.dbIP = dbIP
        self.dbPort = dbPort
        self.hash = io_md5(self.inputPath)
        
        # Create directories for images and scratch space
        self.createDirectories()
        
        if brand == "auto":
            if dbIP:
                self.brand = self.detectBrand()
            else:
                logger.warning("Brand detection is set to 'auto', but no database IP provided. Defaulting to 'unknown'.")
                self.brand = "unknown"
                
        # Information about the firmware image
        self.iid = None
        self.kernelPath = None
        self.filesystemPath = None
        
        self.architecture = Architecture.UNKNOWN
        self.endianess = Endianess.UNKNOWN
        
        self.kernelVersion = ""
        self.kernelVersionString = ""
        self.inferredKernelInit = []
        self.inferredKernelInitStrings = []
        
    def state(self) -> dict[str, str | list[str]]:
        # Generate a report of the emulator state
        report = {
            "mode": self.mode.value,
            "inputPath": self.inputPath,
            "outputPath": self.outputPath,
            "imagePath": self.imagePath,
            "scratchPath": self.scratchPath,
            "toolsPath": self.toolsPath,
            "artifactPath": self.artifactPath,
            "brand": self.brand,
            "hash": self.hash,
            "iid": str(self.iid) if self.iid else "",
            "kernelPath": self.kernelPath if self.kernelPath else "",
            "filesystemPath": self.filesystemPath if self.filesystemPath else "",
            "architecture": str(self.architecture),
            "endianess": str(self.endianess),
            "kernelVersion": self.kernelVersion,
            "kernelVersionString": self.kernelVersionString,
            "inferredKernelInit": self.inferredKernelInit,
            "inferredKernelInitStrings": self.inferredKernelInitStrings
        }
        
        return report
          
    def createDirectories(self):
        # Create necessary directories for images and scratch space
        if not os.path.exists(self.imagePath):
            try:
                os.makedirs(self.imagePath)
                logger.info(f"Image directory created at: {self.imagePath}")
            except Exception as e:
                logger.error(f"Failed to create image directory: {e}")
                raise
            
        if not os.path.exists(self.scratchPath):
            try:
                os.makedirs(self.scratchPath)
                logger.info(f"Scratch directory created at: {self.scratchPath}")
            except Exception as e:
                logger.error(f"Failed to create scratch directory: {e}")
                raise
            
    def detectBrand(self):
        # Check if the firmware's hash is in the database
        firmware_hash = io_md5(self.inputPath)

        with DBInterface(self.dbIP, self.dbPort) as cur:
            cur.execute("SELECT brand_id FROM image WHERE hash = %s", (firmware_hash,))
            brand_id = cur.fetchone()

            if brand_id:
                cur.execute("SELECT name FROM brand WHERE id = %s", (brand_id[0],))
                brand = cur.fetchone()
                if brand:
                    return brand[0]
        return "unknown"
    
    def updateDbImageInfo(self, field: str, value: str):
        if not self.dbIP:
            return True  # No database IP provided, skip update
        
        logger.debug(f"Updating database image info: {field} = {value} for image ID {self.iid}")
        if not self.iid:
            logger.error("Image ID is not set. Cannot update database image info.")
            return False
        
        with DBInterface(self.dbIP, self.dbPort) as cur:
            try:
                cur.execute(f"UPDATE image SET {field} = %s WHERE id = %s", (value, self.iid))
                cur.connection.commit()
                logger.info(f"Database updated successfully: {field} = {value}")
                return True
            except Exception as e:
                cur.connection.rollback()
                logger.error(f"Failed to update database: {e}")
                return False
    
    def extract(self):
        # Extract the kernel and rootfs from the firmware image
        logger.info(f"Extracting firmware image: {self.inputPath}")
        
        # First extract the filesystem without the kernel
        result = extract(self.inputPath, self.imagePath, kernel=False, sqlIP=self.dbIP, sqlPort=self.dbPort, brand=self.brand, quiet=True)[0]
        self.iid = str(result["tag"])
        
        if not result["status"]:
            logger.error(f"Failed to extract filesystem from {self.inputPath}")
            return False

        self.filesystemPath = str(result["rootfsPath"])
        logger.debug(f"Root filesystem extracted to: {self.filesystemPath}")

        # Now extract the kernel
        logger.info(f"Extracting kernel from firmware image: {self.inputPath}")
        result = extract(self.inputPath, self.imagePath, filesystem=False, sqlIP=self.dbIP, sqlPort=self.dbPort, brand=self.brand, quiet=True)[0]
        
        if not result["status"]:
            logger.error(f"Failed to extract kernel from {self.inputPath}")
            if self.filesystemPath:
                shutil.rmtree(self.filesystemPath, ignore_errors=True)
            return False
        
        self.kernelPath = str(result["kernelPath"])
        logger.debug(f"Kernel extracted to: {self.kernelPath}")

        if not self.kernelPath or not self.filesystemPath:
            logger.error("Extraction failed: Kernel or root filesystem path is empty.")
            return False
        
        logger.info(f"Extraction completed successfully. Kernel: {self.kernelPath}, RootFS: {self.filesystemPath}")

        return True
    
    def inferArchitecture(self):
        # Infer the architecture and endianess of the firmware
        logger.info(f"Inferring architecture for firmware: {self.inputPath}")
        
        if not self.iid:
            logger.error("Image ID is not set. Cannot infer architecture.")
            return False
        
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot infer architecture.")
            return False
        
        self.architecture, self.endianess = checkArch(self.filesystemPath, self.iid)
        
        if self.architecture == Architecture.UNKNOWN or self.endianess == Endianess.UNKNOWN:
            logger.error("Failed to determine architecture or endianess of the firmware.")
            return False
        
        self.updateDbImageInfo("arch", str(self.architecture) + str(self.endianess))
        
        logger.info(f"Inferred Architecture: {self.architecture}, Endianess: {self.endianess}")
        return True
    
    def inferKernelVersion(self):
        # Infer the kernel version from the kernel image
        logger.info(f"Inferring kernel version for firmware: {self.inputPath}")
        
        if not self.kernelPath:
            logger.error("Kernel path is not set. Cannot infer kernel version.")
            return False
        
        for string in strings(self.kernelPath, minLength=4):
            if "Linux version" in string:
                temp = string.split("Linux version ")[1].split(" ")[0]
                if temp:
                    self.kernelVersion = temp
                    self.kernelVersionString = string
                    logger.debug(f"Found kernel version: {self.kernelVersion}")
            elif "init=" in string:
                temp = string.split("init=")[1].split(" ")[0]
                if temp:
                    self.inferredKernelInit.append(temp)
                    self.inferredKernelInitStrings.append(string)
                    logger.debug(f"Found kernel init command: {temp}")

        if not self.kernelVersion:
            logger.warning("Kernel version could not be inferred from the kernel image.")
            return False
        else:
            self.updateDbImageInfo("kernel_version", self.kernelVersion)

        return True

    def collectInfo(self):
        # Collect information about the firmware
        logger.info(f"Collecting information for firmware: {self.inputPath}")
        
        if not self.iid or not self.kernelPath or not self.filesystemPath:
            logger.error("Image ID, kernel path, or root filesystem path is not set. Cannot collect information.")
            logger.error("Extraction must be run before collecting information.")
            return False

        # Check architecture and endianess
        if not self.inferArchitecture():
            logger.error("Failed to infer architecture.")
            return False
        
        if not self.inferKernelVersion():
            logger.warning("Failed to infer kernel version.")

        return True
    
    def dumpObjectsToDB(self):
        if not self.dbIP:
            logger.warning("No database IP provided, skipping database updates.")
            return True
        
        if not self.iid:
            logger.error("Image ID is not set. Cannot dump objects to database.")
            return False
        
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot dump objects to database.")
            return False
        
        logger.info("Dumping objects to database.")
        
        fileInfo = getFilesInfo(self.filesystemPath)
        objectsIds, _ = getObjectIds(fileInfo, self.dbIP, self.dbPort)
        
        insertObjectsToImage(self.iid, objectsIds, fileInfo, self.dbIP, self.dbPort)
        
        linkInfo = getLinksInfo(self.filesystemPath)
        insertLinksToImage(self.iid, linkInfo, self.dbIP, self.dbPort)
        
    def createScratchDir(self) -> str:
        if not self.iid:
            logger.error("Image ID is not set. Cannot create scratch directory.")
            return ""
        
        if not os.path.exists(self.scratchPath):
            try:
                os.makedirs(self.scratchPath)
                logger.info(f"Scratch directory created at: {self.scratchPath}")
            except Exception as e:
                logger.error(f"Failed to create scratch directory: {e}")
                raise
            
        if not os.path.exists(os.path.join(self.scratchPath, self.iid)):
            try:
                os.makedirs(os.path.join(self.scratchPath, self.iid))
                logger.info(f"Scratch subdirectory created for IID: {self.iid}")
            except Exception as e:
                logger.error(f"Failed to create scratch subdirectory: {e}")
                raise
            
        return os.path.join(self.scratchPath, self.iid)

    def extractFs(self, dst: str):
        if not self.filesystemPath:
            logger.error("Filesystem path is not set. Cannot extract filesystem.")
            return False
        
        if not os.path.exists(dst):
            try:
                os.makedirs(dst)
                logger.info(f"Destination directory created at: {dst}")
            except Exception as e:
                logger.error(f"Failed to create destination directory: {e}")
                return False
        
        try:
            shutil.unpack_archive(self.filesystemPath, dst)
            logger.info(f"Filesystem extracted from {self.filesystemPath} to {dst}")
            return True
        except Exception as e:
            logger.error(f"Failed to extract filesystem: {e}")
            return False

    def run(self):
        logger.info(f"Running emulator for firmware: {self.inputPath}")
        
        logger.info(f"Step 1: Extracting firmware image {self.inputPath}")
        if not self.extract():
            logger.error("Extraction failed, aborting emulator run.")
            return

        if not self.collectInfo():
            logger.error("Failed to collect information, aborting emulator run.")
            return
        
        if not checkCompatibility(self.architecture, self.endianess):
            logger.error(f"Incompatible architecture or endianess: {self.architecture}, {self.endianess}")
            return
        
        if not self.dumpObjectsToDB():
            logger.error("Failed to dump objects to database.")
            return
        
        logger.debug(self.state())
        
        # logger.info("Step 2: preparing image for emulation")
        
        # workDir = self.createScratchDir()
        # createRawImg(os.path.join(workDir, "raw.img"), 1 * GIGA)
        # mountImage(os.path.join(workDir, "raw.img"), os.path.join(workDir, "mnt"))
        # self.extractFs(os.path.join(workDir, "mnt"))

        # installFirmadyne(os.path.join(workDir, "mnt"))