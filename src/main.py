import logging
import os
import argparse

from common import RunningMode
from dbInterface import checkConnection
from emulator import Emulator
from emulatorConfig import emulatorConfig

logger = logging.getLogger("FEMU")

logger.setLevel(logging.DEBUG)
formater = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger.addHandler(logging.StreamHandler())
logger.handlers[0].setFormatter(formater)

extractorLogger = logging.getLogger("femu_extractor")
extractorLogger.setLevel(logging.DEBUG)
extractorLogger.addHandler(logging.StreamHandler())
extractorLogger.handlers[0].setFormatter(formater)

def parseArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FEMU: A tool for emulating and analyzing firmware.")
    parser.add_argument("-m", "--mode", type=str, choices=[mode.value for mode in RunningMode], help="Running mode of the emulator.", default=RunningMode.RUN.value)
    parser.add_argument("-i", "--input", type=str, required=True, help="Path to the firmware image or directory.")
    parser.add_argument("-o", "--output", type=str, help="Output path for the results and images.", default="./output")
    parser.add_argument("-b", "--brand", type=str, help="Brand of the firmware (e.g., 'TP-Link', 'Netgear').", default="auto")
    parser.add_argument("-s", "--scripts", type=str, help="Path to the scripts directory.", default="../scripts")
    parser.add_argument("-bin", "--binaries", type=str, help="Path to the binaries directory.", default="../binaries")
    parser.add_argument("-sql", type=str, help="IP of postgreSQL database.", default=None)
    parser.add_argument("-p", "--port", type=int, help="Port of the postgreSQL database.", default=5432)
    
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
            runningMode=RunningMode(args.mode),
            firmwarePath=inputFile,
            outputPath=args.output,
            brand=args.brand,
            scriptsPath=args.scripts,
            binariesPath=args.binaries,
            sqlIP=args.sql,
            sqlPort=args.port
        ))
        logger.info(f"Initialized emulator for {inputFile} in mode {args.mode} with brand {args.brand}.")
        
        em.run()
    
    

if __name__ == "__main__":
    main()