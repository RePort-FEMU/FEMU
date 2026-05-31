import logging
import os
import argparse

from .dbInterface import checkConnection
from .emulator import Emulator
from .emulatorConfig import emulatorConfig

logger = logging.getLogger(__name__)

# Configure the top-level "femu" logger so all femu.* submodules inherit the
# handler and level, plus the extractor package.
_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
_handler = logging.StreamHandler()
_handler.setFormatter(_formatter)

logging.getLogger("femu").setLevel(logging.DEBUG)
logging.getLogger("femu").addHandler(_handler)

logging.getLogger("femu_extractor").setLevel(logging.DEBUG)
logging.getLogger("femu_extractor").addHandler(_handler)

def parseArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FEMU: A tool for emulating and analyzing firmware.")
    parser.add_argument("-m", "--mode", type=str, choices=["check", "boot", "debug", "analyze"], help="Running mode: check (explore), boot, debug (boot+shell), analyze.", default="boot")
    parser.add_argument("-i", "--input", type=str, required=True, help="Path to the firmware image or directory.")
    parser.add_argument("-o", "--output", type=str, help="Output path for the results and images.", default="./output")
    parser.add_argument("-b", "--brand", type=str, help="Brand of the firmware (e.g., 'TP-Link', 'Netgear').", default="auto")
    parser.add_argument("-s", "--scripts", type=str, help="Path to the scripts directory.", default="../scripts")
    parser.add_argument("-bin", "--binaries", type=str, help="Path to the binaries directory.", default="../binaries")
    parser.add_argument("-sql", type=str, help="IP of postgreSQL database.", default=None)
    parser.add_argument("-p", "--port", type=int, help="Port of the postgreSQL database.", default=5432)
    parser.add_argument("--debug", action="store_true", help="Enable debug mode (nc/telnet shell access in guest).", default=False)
    
    args = parser.parse_args()
    return args

def checkArguments(args: argparse.Namespace):
    if args.sql is None:
        logger.warning("No PostgreSQL IP provided. Some features may not work.")
    else:
        # Check connection to PostgreSQL database
        if checkConnection(args.sql, args.port):
            logger.info("Successfully connected to PostgreSQL database.")
        else:
            logger.error("Failed to connect to PostgreSQL database.")
            exit(1)
            
    if not os.path.exists(args.input):
        logger.error(f"Input path '{args.input}' does not exist.")
        exit(1)
        
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
            logger.info(f"Output directory '{args.output}' created.")
        except Exception as e:
            logger.error(f"Failed to create output directory '{args.output}': {e}")
            exit(1)

def main():
    args = parseArguments()
    checkArguments(args)
    
    if os.path.isdir(args.input):
        inputFiles = [os.path.join(args.input, f) for f in os.listdir(args.input) if os.path.isfile(os.path.join(args.input, f))]
    else:
        inputFiles = [args.input]
        
    for inputFile in inputFiles:
        em = Emulator(emulatorConfig(
            firmwarePath=inputFile,
            outputPath=args.output,
            brand=args.brand,
            scriptsPath=args.scripts,
            binariesPath=args.binaries,
            sqlIP=args.sql,
            sqlPort=args.port,
            debug=args.debug,
        ))
        logger.info(f"Initialized emulator for {inputFile} in mode {args.mode} with brand {args.brand}.")

        modes = {
            "check":   em.explore,
            "boot":    em.boot,
            "debug":   em.debug,
            "analyze": em.analyze,
        }
        modes[args.mode]()
    
    

if __name__ == "__main__":
    main()