import psycopg2
import logging

from typing import Optional

logger = logging.getLogger("FEMU")

# TODO: Make these configurable
USERNAME = "femu"
PASSWORD = "femu"
DBNAME = "firmware"

def checkConnection(host:str, port:int) -> bool:
    conn = None
    ret = True
    try:
        conn = psycopg2.connect(
            dbname=DBNAME,
            user=USERNAME,
            password=PASSWORD,
            host=host,
            port=port
        )
    except Exception as e:
        logger.error(f"Error connecting to PostgreSQL database: {e}")
        ret = False
    
    finally:
        if conn:
            conn.close()

    return ret

class DBInterface:
    def __init__(self, host: str, port: int = 5432):
        self.host: str = host
        self.port: int = port
        self.conn: Optional[psycopg2.extensions.connection] = None
        self.cursor: Optional[psycopg2.extensions.cursor] = None

    def connect(self) -> Optional[psycopg2.extensions.cursor]:
        try:
            self.conn = psycopg2.connect(
                dbname=DBNAME,
                user=USERNAME,
                password=PASSWORD,
                host=self.host,
                port=self.port
            )
            self.cursor = self.conn.cursor()
            return self.cursor
        except Exception as e:
            logger.error(f"Error connecting to PostgreSQL database: {e}")
            raise e

    def __enter__(self):
        cur = self.connect()
        if not cur:
            raise Exception("Failed to connect to the database.")
        return cur

    def __exit__(self, exc_type, exc_value, traceback):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
