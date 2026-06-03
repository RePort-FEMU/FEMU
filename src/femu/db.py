"""All PostgreSQL operations for FEMU. No DB logic should live outside this module."""
import logging

from .dbInterface import DBInterface

logger = logging.getLogger(__name__)


def upsertBrand(name: str, sqlIP: str, sqlPort: int) -> int | None:
    """Insert brand if not present, return its id."""
    try:
        with DBInterface(sqlIP, sqlPort) as cur:
            cur.execute(
                "INSERT INTO brand (name) VALUES (%s) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
                (name,),
            )
            row = cur.fetchone()
            cur.connection.commit()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to upsert brand '{name}': {e}")
        return None


def upsertImage(tag: str, filename: str, firmwareHash: str,
                brandId: int, sqlIP: str, sqlPort: int) -> int | None:
    """
    Insert image record if not already present (keyed on firmwareHash).
    Returns the integer DB id.
    """
    try:
        with DBInterface(sqlIP, sqlPort) as cur:
            cur.execute(
                """
                INSERT INTO image (filename, brand_id, hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (hash) DO UPDATE SET filename = EXCLUDED.filename
                RETURNING id
                """,
                (filename, brandId, firmwareHash),
            )
            row = cur.fetchone()
            cur.connection.commit()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to upsert image '{filename}': {e}")
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
