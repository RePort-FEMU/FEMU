import logging
import os

from common import RunningMode
from dbInterface import checkConnection

# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger(__name__)

class emulatorConfig:
    def __init__(self,
    runningMode: RunningMode, 
    firmwarePath: str,
    outputPath: str = "./output",
    brand: str = "auto",
    scriptsPath: str = "../scripts",
    binariesPath: str = "../binaries",
    sqlIP: str | None = None,
    sqlPort: int = 5432,
    ):
        self.runningMode: RunningMode = runningMode
        self.firmwarePath: str = firmwarePath
        self.outputPath: str = outputPath
        self.brand: str = brand
        self.scriptsPath: str = scriptsPath
        self.binariesPath: str = binariesPath
        self.sqlIP: str | None = sqlIP
        self.sqlPort: int = sqlPort
        
        # For all paths, get the absolute path
        self.firmwarePath = firmwarePath if firmwarePath.startswith("/") else os.path.abspath(f"./{firmwarePath}")
        self.outputPath = outputPath if outputPath.startswith("/") else os.path.abspath(f"./{outputPath}")
        self.scriptsPath = scriptsPath if scriptsPath.startswith("/") else os.path.abspath(f"./{scriptsPath}")
        self.binariesPath = binariesPath if binariesPath.startswith("/") else os.path.abspath(f"./{binariesPath}")
        
        if self.sqlIP is None or self.sqlIP == "":
            logger.warning("No PostgreSQL IP provided. Some features may not work.")
            self.sqlIP = None
            
        if self.sqlIP is not None:
            if not checkConnection(self.sqlIP, self.sqlPort):
                logger.error("Failed to connect to PostgreSQL database.")
                raise ConnectionError("Could not connect to PostgreSQL database.")

