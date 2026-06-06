import logging
import os
import shutil

from .util import mountedImage

logger = logging.getLogger(__name__)

_MIN_KEYS = 10
_MATCH_THRESHOLD = 0.5


def _parseNvramKeys(probeLog: str) -> list[bytes]:
    keys: list[bytes] = []
    try:
        with open(probeLog, "rb") as f:
            for line in f.read().split(b"\n"):
                if not line.startswith(b"[NVRAM]"):
                    continue
                parts = line.split(b" ")
                if len(parts) < 3 or not parts[1].decode(errors="ignore").isnumeric():
                    continue
                key = parts[2][: int(parts[1])]
                try:
                    key.decode()
                except Exception:
                    continue
                if key not in keys:
                    keys.append(key)
    except OSError as e:
        logger.warning(f"Could not read probe log for NVRAM inference: {e}")
    return keys


def inferNvramDefaults(imagePath: str, mountPoint: str, probeLog: str, workDir: str) -> bool:
    """
    Parse the probe serial log for NVRAM key reads, find the firmware file that
    contains the most of those keys, and copy it to /firmadyne/nvram_defaults.

    Returns True if a defaults file was found and installed.
    """
    keys = _parseNvramKeys(probeLog)

    if len(keys) < _MIN_KEYS:
        logger.debug(f"Only {len(keys)} NVRAM keys found — skipping defaults inference")
        return False

    logger.info(f"Inferring NVRAM defaults from {len(keys)} keys")

    # Save key list for debugging / findings
    keysOut = os.path.join(workDir, "nvram_keys")
    with open(keysOut, "w") as f:
        f.write(f"{len(keys)}\n")
        for k in keys:
            f.write(k.decode() + "\n")

    bestFile: str | None = None
    bestCount = 0

    with mountedImage(imagePath, mountPoint) as mp:
        for dirpath, _, filenames in os.walk(mp):
            if os.path.join(mp, "firmadyne") in dirpath:
                continue
            for filename in filenames:
                fullPath = os.path.join(dirpath, filename)
                if not os.path.isfile(fullPath) or os.path.islink(fullPath):
                    continue
                try:
                    data = open(fullPath, "rb").read()
                except OSError:
                    continue
                count = sum(1 for k in keys if k in data)
                if count > len(keys) * _MATCH_THRESHOLD and count > bestCount:
                    bestCount = count
                    bestFile = fullPath

        if bestFile:
            dest = os.path.join(mp, "firmadyne", "nvram_defaults")
            shutil.copy2(bestFile, dest)
            logger.info(
                f"Installed NVRAM defaults: {bestFile.replace(mp, '')} "
                f"({bestCount}/{len(keys)} keys matched)"
            )

    if not bestFile:
        logger.debug("No NVRAM defaults file found in firmware")
        return False

    return True
