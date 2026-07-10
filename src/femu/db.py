"""All PostgreSQL operations for FEMU. No DB logic should live outside this module."""
import logging

from .dbInterface import DBInterface

logger = logging.getLogger(__name__)


def getOrCreateBrand(name: str, sqlIP: str, sqlPort: int) -> int | None:
    """Return the brand's id, inserting the brand if it isn't already present."""
    try:
        with DBInterface(sqlIP, sqlPort) as cur:
            # Already there?
            cur.execute("SELECT id FROM brand WHERE name = %s", (name,))
            row = cur.fetchone()
            if row:
                return row[0]

            # Otherwise insert it. DO NOTHING guards against a concurrent insert
            # of the same name racing between the SELECT above and this INSERT.
            cur.execute(
                "INSERT INTO brand (name) VALUES (%s) ON CONFLICT (name) DO NOTHING RETURNING id",
                (name,),
            )
            row = cur.fetchone()
            cur.connection.commit()
            if row:
                return row[0]

            # Lost the race — another writer created it; read their row back.
            cur.execute("SELECT id FROM brand WHERE name = %s", (name,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to get or create brand '{name}': {e}")
        return None


def getOrCreateImage(filename: str, firmwareHash: str,
                     brandId: int, sqlIP: str, sqlPort: int) -> int | None:
    """
    Return the image's id (keyed on firmwareHash), inserting it if not present.
    An already-registered image is returned unchanged.
    """
    try:
        with DBInterface(sqlIP, sqlPort) as cur:
            # Already there?
            cur.execute("SELECT id FROM image WHERE hash = %s", (firmwareHash,))
            row = cur.fetchone()
            if row:
                return row[0]

            # Otherwise insert it. DO NOTHING guards against a concurrent insert
            # of the same hash racing between the SELECT above and this INSERT.
            cur.execute(
                """
                INSERT INTO image (filename, brand_id, hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (hash) DO NOTHING
                RETURNING id
                """,
                (filename, brandId, firmwareHash),
            )
            row = cur.fetchone()
            cur.connection.commit()
            if row:
                return row[0]

            # Lost the race — another writer created it; read their row back.
            cur.execute("SELECT id FROM image WHERE hash = %s", (firmwareHash,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to get or create image '{filename}': {e}")
        return None


def updateImageField(dbId: int, field: str, value: str,
                     sqlIP: str, sqlPort: int) -> bool:
    """Update a single field on an image row. field must be a known column name."""
    _ALLOWED = {"arch", "kernel_version", "rootfs_extracted", "kernel_extracted"}
    if field not in _ALLOWED:
        logger.error(f"updateImageField: unknown field '{field}'")
        return False
    try:
        with DBInterface(sqlIP, sqlPort) as cur:
            cur.execute(f"UPDATE image SET {field} = %s WHERE id = %s", (value, dbId))
            cur.connection.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to update image field '{field}': {e}")
        return False


def getBrandByHash(firmwareHash: str, sqlIP: str, sqlPort: int) -> str | None:
    """Return the brand name for a previously seen firmware hash, or None."""
    try:
        with DBInterface(sqlIP, sqlPort) as cur:
            cur.execute("SELECT brand_id FROM image WHERE hash = %s", (firmwareHash,))
            row = cur.fetchone()
            if not row:
                return None
            cur.execute("SELECT name FROM brand WHERE id = %s", (row[0],))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.warning(f"Brand lookup failed: {e}")
        return None
    
def registerImage(fileName: str, firmwareHash: str, brandName:str, sqlIP: str, sqlPort: int) -> int | None:
    """
    Registers a firmware image in the database, inserting brand and image records as needed.
    Returns the image's DB id, or None on failure.
    """
    # None here means the DB call failed (exception path), not "not found".
    brandId = getOrCreateBrand(brandName, sqlIP, sqlPort)
    if brandId is None:
        logger.error(f"Failed to register brand '{brandName}'")
        return None
    imageId = getOrCreateImage(fileName, firmwareHash, brandId, sqlIP, sqlPort)
    if imageId is None:
        logger.error(f"Failed to register image '{fileName}'")
        return None
    return imageId