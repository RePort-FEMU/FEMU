import logging
import os

from .dbInterface import checkConnection

# Use the root logger, do not set up a separate logger or handler here.
logger = logging.getLogger(__name__)

# Resolve resource directories relative to this file so the package works
# both as an editable dev install (src/femu/ → ../../binaries) and when
# binaries/scripts are bundled alongside the package.
_PKG_DIR  = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_PKG_DIR))

def _default_resource(name: str) -> str:
    bundled = os.path.join(_PKG_DIR, name)
    if os.path.isdir(bundled):
        return bundled
    return os.path.join(_REPO_ROOT, name)

_DEFAULT_BINARIES = _default_resource("binaries")
_DEFAULT_SCRIPTS  = _default_resource("scripts")

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
        
        if self.sqlIP is None or self.sqlIP == "":
            logger.warning("No PostgreSQL IP provided. Some features may not work.")
            self.sqlIP = None
            
        if self.sqlIP is not None:
            if not checkConnection(self.sqlIP, self.sqlPort):
                logger.error("Failed to connect to PostgreSQL database.")
                raise ConnectionError("Could not connect to PostgreSQL database.")

