import logging
import os
import argparse

from common import RunningMode
from dbInterface import checkConnection
from emulator import Emulator

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(filename)s - %(message)s'
)

def parseArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FEMU: A tool for emulating and analyzing firmware.")
    parser.add_argument("-m", "--mode", type=str, choices=[mode.value for mode in RunningMode], help="Running mode of the emulator.", default=RunningMode.RUN.value)
    parser.add_argument("-i", "--input", type=str, required=True, help="Path to the firmware image or directory.")
    parser.add_argument("-o", "--output", type=str, help="Output path for the results and images.", default="./output")
    parser.add_argument("-b", "--brand", type=str, help="Brand of the firmware (e.g., 'TP-Link', 'Netgear').", default="auto")
    parser.add_argument("-sql", type=str, help="IP of postgreSQL database.", default=None)
    parser.add_argument("-p", "--port", type=int, help="Port of the postgreSQL database.", default=5432)
    
    args = parser.parse_args()
    return args

def checkArguments(args: argparse.Namespace):
    if args.sql is None:
        logging.warning("No PostgreSQL IP provided. Some features may not work.")
    else:
        # Check connection to PostgreSQL database
        if checkConnection(args.sql, args.port):
            logging.info("Successfully connected to PostgreSQL database.")
        else:
            logging.error("Failed to connect to PostgreSQL database.")
            exit(1)
            
    if not os.path.exists(args.input):
        logging.error(f"Input path '{args.input}' does not exist.")
        exit(1)
        
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
            logging.info(f"Output directory '{args.output}' created.")
        except Exception as e:
            logging.error(f"Failed to create output directory '{args.output}': {e}")
            exit(1)

def main():
    args = parseArguments()
    checkArguments(args)
    
    if os.path.isdir(args.input):
        inputFiles = [os.path.join(args.input, f) for f in os.listdir(args.input) if os.path.isfile(os.path.join(args.input, f))]
    else:
        inputFiles = [args.input]
        
    for inputFile in inputFiles:
        em = Emulator(
            mode=RunningMode(args.mode),
            inputPath=inputFile,
            outputPath=args.output,
            brand=args.brand,
            dbIP=args.sql,
            dbPort=args.port
        )
        logging.info(f"Initialized emulator for {inputFile} in mode {args.mode} with brand {args.brand}.")
        
        em.run()
    
    

if __name__ == "__main__":
    main()