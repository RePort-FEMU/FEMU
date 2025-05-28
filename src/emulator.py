from common import RunningMode
from dbInterface import DBInterface
from util import io_md5
import logging

class Emulator:
    def __init__(self, mode: RunningMode, inputPath: str, brand: str, dbIP: str = "", dbPort: int = 5432):
        self.mode = mode
        self.inputPath = inputPath
        self.brand = brand
        self.dbIP = dbIP
        self.dbPort = dbPort

        if brand == "auto":
            if dbIP:
                self.brand = self.detectBrand()
            else:
                logging.warning("Brand detection is set to 'auto', but no database IP provided. Defaulting to 'unknown'.")
                self.brand = "unknown"
            
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