import logging
import shutil
import os
import sys

from common import RunningMode, Architecture, Endianess
from dbInterface import DBInterface
from util import io_md5, checkArch, strings, checkCompatibility

# Add the extractor module to the system path
sys.path.append(os.path.join(os.path.dirname(__file__), 'extractor'))
from extractor.extractor import extract

class Emulator:
    def __init__(self, mode: RunningMode, inputPath: str, outputPath: str, brand: str = "auto", dbIP: str = "", dbPort: int = 5432):
        # Information about the emulator environment
        self.mode = mode
        self.inputPath = inputPath
        self.outputPath = outputPath
        self.imagePath = outputPath + "/images"
        self.scratchPath = outputPath + "/scratch"
        self.brand = brand
        self.dbIP = dbIP
        self.dbPort = dbPort
        
        if not os.path.exists(self.imagePath):
            try:
                os.makedirs(self.imagePath)
                logging.info(f"Image directory created at: {self.imagePath}")
            except Exception as e:
                logging.error(f"Failed to create image directory: {e}")
                raise
            
        if not os.path.exists(self.scratchPath):
            try:
                os.makedirs(self.scratchPath)
                logging.info(f"Scratch directory created at: {self.scratchPath}")
            except Exception as e:
                logging.error(f"Failed to create scratch directory: {e}")
                raise

        if brand == "auto":
            if dbIP:
                self.brand = self.detectBrand()
            else:
                logging.warning("Brand detection is set to 'auto', but no database IP provided. Defaulting to 'unknown'.")
                self.brand = "unknown"
                
        # Information about the firmware image
        self.iid = None
        self.kernelPath = None
        self.filesystemPath = None
        
        self.architecture = Architecture.UNKNOWN
        self.endianess = Endianess.UNKNOWN
        
        self.kernelVersion = ""
        self.kernelVersionString = ""
        self.kernelInit = ""
        self.kernelInitString = ""
            
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
        
        logging.debug(f"Updating database image info: {field} = {value} for image ID {self.iid}")
        if not self.iid:
            logging.error("Image ID is not set. Cannot update database image info.")
            return False
        
        with DBInterface(self.dbIP, self.dbPort) as cur:
            try:
                cur.execute(f"UPDATE image SET {field} = %s WHERE id = %s", (value, self.iid))
                cur.connection.commit()
                logging.info(f"Database updated successfully: {field} = {value}")
                return True
            except Exception as e:
                cur.connection.rollback()
                logging.error(f"Failed to update database: {e}")
                return False
    
    def extract(self):
        # Extract the kernel and rootfs from the firmware image
        logging.info(f"Extracting firmware image: {self.inputPath}")
        
        # First extract the filesystem without the kernel
        result = extract(self.inputPath, self.imagePath, kernel=False, sqlIP=self.dbIP, sqlPort=self.dbPort, brand=self.brand, quiet=True)[0]
        self.iid = str(result["tag"])
        
        if not result["status"]:
            logging.error(f"Failed to extract filesystem from {self.inputPath}")
            return False

        self.filesystemPath = str(result["rootfsPath"])
        logging.debug(f"Root filesystem extracted to: {self.filesystemPath}")

        # Now extract the kernel
        logging.info(f"Extracting kernel from firmware image: {self.inputPath}")
        result = extract(self.inputPath, self.imagePath, filesystem=False, sqlIP=self.dbIP, sqlPort=self.dbPort, brand=self.brand, quiet=True)[0]
        
        if not result["status"]:
            logging.error(f"Failed to extract kernel from {self.inputPath}")
            if self.filesystemPath:
                shutil.rmtree(self.filesystemPath, ignore_errors=True)
            return False
        
        self.kernelPath = str(result["kernelPath"])
        logging.debug(f"Kernel extracted to: {self.kernelPath}")

        if not self.kernelPath or not self.filesystemPath:
            logging.error("Extraction failed: Kernel or root filesystem path is empty.")
            return False
        
        logging.info(f"Extraction completed successfully. Kernel: {self.kernelPath}, RootFS: {self.filesystemPath}")

        return True
    
    def inferArchitecture(self):
        # Infer the architecture and endianess of the firmware
        logging.info(f"Inferring architecture for firmware: {self.inputPath}")
        
        if not self.iid:
            logging.error("Image ID is not set. Cannot infer architecture.")
            return False
        
        if not self.filesystemPath:
            logging.error("Filesystem path is not set. Cannot infer architecture.")
            return False
        
        self.architecture, self.endianess = checkArch(self.filesystemPath, self.iid)
        
        if self.architecture == Architecture.UNKNOWN or self.endianess == Endianess.UNKNOWN:
            logging.error("Failed to determine architecture or endianess of the firmware.")
            return False
        
        self.updateDbImageInfo("arch", str(self.architecture) + str(self.endianess))
        
        logging.info(f"Inferred Architecture: {self.architecture}, Endianess: {self.endianess}")
        return True
    
    def inferKernelVersion(self):
        # Infer the kernel version from the kernel image
        logging.info(f"Inferring kernel version for firmware: {self.inputPath}")
        
        if not self.kernelPath:
            logging.error("Kernel path is not set. Cannot infer kernel version.")
            return False
        
        for string in strings(self.kernelPath, minLength=4):
            if "Linux version" in string:
                temp = string.split("Linux version ")[1].split(" ")[0]
                if temp:
                    self.kernelVersion = temp
                    self.kernelVersionString = string
                    logging.debug(f"Found kernel version: {self.kernelVersion}")
            elif "init=" in string:
                temp = string.split("init=")[1].split(" ")[0]
                if temp:
                    self.kernelInit = temp
                    self.kernelInitString = string
                    logging.debug(f"Found kernel init command: {self.kernelInit}")

        if not self.kernelVersion:
            logging.warning("Kernel version could not be inferred from the kernel image.")
            return False
        else:
            self.updateDbImageInfo("kernel_version", self.kernelVersion)

        return True

    def collectInfo(self):
        # Collect information about the firmware
        logging.info(f"Collecting information for firmware: {self.inputPath}")
        
        if not self.iid or not self.kernelPath or not self.filesystemPath:
            logging.error("Image ID, kernel path, or root filesystem path is not set. Cannot collect information.")
            logging.error("Extraction must be run before collecting information.")
            return False

        # Check architecture and endianess
        if not self.inferArchitecture():
            logging.error("Failed to infer architecture.")
            return False
        
        if not self.inferKernelVersion():
            logging.warning("Failed to infer kernel version.")

        return True

    def run(self):
        logging.info(f"Running emulator for firmware: {self.inputPath}")
        
        if not self.extract():
            logging.error("Extraction failed, aborting emulator run.")
            return

        if not self.collectInfo():
            logging.error("Failed to collect information, aborting emulator run.")
            return
        
        if not checkCompatibility(self.architecture, self.endianess):
            logging.error(f"Incompatible architecture or endianess: {self.architecture}, {self.endianess}")
            return
        
        


