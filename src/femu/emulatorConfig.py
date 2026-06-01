import logging
import os

from .dbInterface import checkConnection

# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger(__name__)

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))

_DEFAULT_BINARIES = "./binaries"                        # resolved at runtime from CWD
_DEFAULT_SCRIPTS  = os.path.join(_PKG_DIR, "scripts")  # bundled inside the package

class emulatorConfig:
    def __init__(self,
    firmwarePath: str,
    outputPath: str = "./output",
    brand: str = "auto",
    scriptsPath: str = _DEFAULT_SCRIPTS,
    binariesPath: str = _DEFAULT_BINARIES,
    sqlIP: str | None = None,
    sqlPort: int = 5432,
    debug: bool = False,
    ):
        self.firmwarePath: str = firmwarePath
        self.outputPath: str = outputPath
        self.brand: str = brand
        self.scriptsPath: str = scriptsPath
        self.binariesPath: str = binariesPath
        self.sqlIP: str | None = sqlIP
        self.sqlPort: int = sqlPort
        self.debug: bool = debug
        
        # Normalise all paths to absolute
        self.firmwarePath  = os.path.abspath(firmwarePath)
        self.outputPath    = os.path.abspath(outputPath)
        self.scriptsPath   = os.path.abspath(scriptsPath)
        self.binariesPath  = os.path.abspath(binariesPath)
        
        if not os.path.isdir(self.binariesPath) or not os.listdir(self.binariesPath):
            raise FileNotFoundError(
                f"Binaries directory not found or empty: {self.binariesPath}\n\n"
                f"Download the required binaries with:\n"
                f"  curl -fsSL https://raw.githubusercontent.com/RePort-FEMU/FEMU/main/download.sh | sh\n\n"
                f"Or clone the repo and run download.sh directly:\n"
                f"  git clone https://github.com/RePort-FEMU/FEMU && cd FEMU && ./download.sh\n\n"
                f"To use a custom binaries directory:\n"
                f"  femu --binaries <path> ...\n"
            )

        if self.sqlIP is None or self.sqlIP == "":
            logger.warning("No PostgreSQL IP provided. Some features may not work.")
            self.sqlIP = None
            
        if self.sqlIP is not None:
            if not checkConnection(self.sqlIP, self.sqlPort):
                logger.error("Failed to connect to PostgreSQL database.")
                raise ConnectionError("Could not connect to PostgreSQL database.")

