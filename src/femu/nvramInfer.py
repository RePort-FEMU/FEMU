import logging
import os
import subprocess

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
                # If parts2 does is not long enough to contain the key, skip it. This can happen if the log is truncated or malformed.
                if len(key) < int(parts[1]):
                    continue
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
    Parse the probe serial log for NVRAM key reads, find all firmware files that
    contain more than half of those keys, and write a manifest to /firmadyne/nvram_files.

    The manifest format mirrors FirmAE: one line per file, space-separated:
        <guest_path> <matched_key_count> <file_type>

    libnvram reads /firmadyne/nvram_files to locate candidate default-value files.

    Returns True if at least one defaults file was found and the manifest was installed.
    """
    keys = _parseNvramKeys(probeLog)

    if len(keys) < _MIN_KEYS:
        logger.debug(f"Only {len(keys)} NVRAM keys found — skipping defaults inference")
        return False

    logger.info(f"Inferring NVRAM defaults from {len(keys)} keys")

    keysOut = os.path.join(workDir, "nvram_keys")
    with open(keysOut, "w") as f:
        f.write(f"{len(keys)}\n")
        for k in keys:
            f.write(k.decode() + "\n")

    matches: list[tuple[str, int, str]] = []  # (guest_path, count, file_type)

    with mountedImage(imagePath, mountPoint) as mp:
        for dirpath, _, filenames in os.walk(mp):
            if os.path.join(mp, "firmadyne") in dirpath:
                continue
            for filename in filenames:
                # If the directory is /dev/null or similar, skip it to avoid reading special files
                if filename in ("null", "zero", "random", "urandom"):
                    continue
                
                fullPath = os.path.join(dirpath, filename)
                
                if not os.path.isfile(fullPath) or os.path.islink(fullPath):
                    continue
                try:
                    data = open(fullPath, "rb").read()
                except OSError:
                    continue
                count = sum(1 for k in keys if k in data)
                if count > len(keys) * _MATCH_THRESHOLD:
                    guestPath = fullPath[len(mp):]  # strip mount point prefix
                    try:
                        result = subprocess.check_output(
                            ["file", fullPath], stderr=subprocess.DEVNULL
                        ).decode(errors="replace").strip()
                        fileType = result.split(" ", 1)[1].replace(" ", "_") if " " in result else "unknown"
                    except Exception:
                        fileType = "unknown"
                    if "symbolic" not in fileType:
                        matches.append((guestPath, count, fileType))

        if not matches:
            logger.debug("No NVRAM defaults files found in firmware")
            return False

        manifestOut = os.path.join(workDir, "nvram_files")
        with open(manifestOut, "w") as f:
            for guestPath, count, fileType in matches:
                f.write(f"{guestPath} {count} {fileType}\n")

        dest = os.path.join(mp, "firmadyne", "nvram_files")
        with open(manifestOut, "r") as src, open(dest, "w") as dst:
            dst.write(src.read())

        logger.info(
            f"Installed NVRAM defaults manifest: {len(matches)} file(s) → /firmadyne/nvram_files"
        )

    return True
