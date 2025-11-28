"""File hashing utilities for computing SHA256 checksums."""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger("modelaudit")


def compute_sha256_hash(file_path: Path | str, chunk_size: int = 8192) -> str:
    """
    Compute SHA-256 hash of a file using streaming to handle large files efficiently.

    Args:
        file_path: Path to the file to hash
        chunk_size: Size of chunks to read (default: 8KB)

    Returns:
        Hex-encoded SHA-256 hash string

    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError as e:
        logger.error(f"Error reading file {file_path} for hashing: {e}")
        raise
