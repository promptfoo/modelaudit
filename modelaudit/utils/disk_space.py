"""Utilities for checking disk space before downloads."""

import shutil
from pathlib import Path
from typing import Optional


def get_free_space_bytes(path: Path) -> int:
    """Get free space available on the filesystem containing the given path.

    Args:
        path: Path to check (can be file or directory)

    Returns:
        Free space in bytes
    """
    # Get the disk usage statistics for the filesystem containing the path
    stat = shutil.disk_usage(str(path.resolve()))
    return stat.free


def check_disk_space(path: Path, required_bytes: int, safety_margin: float = 1.2) -> tuple[bool, str]:
    """Check if there's enough disk space for a download.

    Args:
        path: Path where the download will be stored
        required_bytes: Number of bytes needed for the download
        safety_margin: Multiplier for safety (default 1.2 = 20% extra space)

    Returns:
        Tuple of (has_enough_space, human_readable_message)
    """
    free_bytes = get_free_space_bytes(path)
    required_with_margin = int(required_bytes * safety_margin)

    if free_bytes >= required_with_margin:
        return True, f"Sufficient disk space available ({format_bytes(free_bytes)})"

    return False, (
        f"Insufficient disk space. "
        f"Required: {format_bytes(required_with_margin)} "
        f"(including {int((safety_margin - 1) * 100)}% safety margin), "
        f"Available: {format_bytes(free_bytes)}"
    )


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human readable string."""
    value = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(value) < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def estimate_model_size(url: str) -> Optional[int]:
    """Estimate the size of a model based on URL or metadata.

    This is a best-effort estimation. Returns None if size cannot be determined.

    Args:
        url: URL of the model

    Returns:
        Estimated size in bytes, or None if cannot estimate
    """
    # For now, we'll return None and let the actual implementation
    # handle size estimation based on the specific source (HF API, cloud storage headers, etc.)
    # This can be enhanced later with actual API calls
    return None
