"""Git LFS pointer detection utilities.

This module detects when a file is a Git LFS pointer (a small text file)
rather than the actual model content. This is a common issue when:
- Users clone repos without `git lfs pull`
- Downloads are interrupted or misconfigured
- Cache serves stale pointer files

LFS pointers are ~130-200 byte text files with this format:
    version https://git-lfs.github.com/spec/v1
    oid sha256:4d7c5a28a...
    size 7516192768
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from os import PathLike

logger = logging.getLogger(__name__)

# Git LFS pointer signature (first line)
LFS_SIGNATURE = b"version https://git-lfs.github.com/spec/v1"

# Maximum size for a valid LFS pointer file
# Real pointers are ~130-200 bytes; we allow up to 512 for safety
LFS_MAX_POINTER_SIZE = 512

# Minimum file header to check for LFS signature
LFS_HEADER_CHECK_SIZE = 50

# Regex patterns for parsing LFS pointer content
_VERSION_PATTERN = re.compile(r"^version\s+(.+)$", re.MULTILINE)
_OID_PATTERN = re.compile(r"^oid\s+(.+)$", re.MULTILINE)
_SIZE_PATTERN = re.compile(r"^size\s+(\d+)$", re.MULTILINE)


@dataclass(frozen=True)
class LFSPointerInfo:
    """Information extracted from a Git LFS pointer file.

    Attributes:
        version: The LFS specification version URL
        oid: The object identifier (usually sha256:hash)
        size: The actual file size in bytes
    """

    version: str
    oid: str
    size: int

    @property
    def hash_algorithm(self) -> str:
        """Extract the hash algorithm from the oid (e.g., 'sha256')."""
        if ":" in self.oid:
            return self.oid.split(":", 1)[0]
        return "unknown"

    @property
    def content_hash(self) -> str:
        """Extract the hash value from the oid (without algorithm prefix)."""
        if ":" in self.oid:
            return self.oid.split(":", 1)[1]
        return self.oid

    def format_expected_size(self) -> str:
        """Format the expected size in human-readable form."""
        size_float = float(self.size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size_float < 1024:
                return f"{size_float:.1f} {unit}" if unit != "B" else f"{int(size_float)} {unit}"
            size_float /= 1024
        return f"{size_float:.1f} PB"


def is_lfs_pointer(path: str | PathLike[str]) -> bool:
    """Check if a file is a Git LFS pointer.

    This is a fast check that only reads the first 50 bytes of the file.

    Args:
        path: Path to the file to check

    Returns:
        True if the file appears to be a Git LFS pointer, False otherwise

    Examples:
        >>> is_lfs_pointer("model.bin")
        False
        >>> is_lfs_pointer("lfs_pointer.bin")  # Git LFS pointer
        True
    """
    file_path = Path(path)

    # Quick checks to avoid unnecessary I/O
    if not file_path.is_file():
        return False

    try:
        # Check file size first - LFS pointers are tiny
        file_size = file_path.stat().st_size
        if file_size > LFS_MAX_POINTER_SIZE:
            return False

        # Read just enough bytes to check the signature
        with file_path.open("rb") as f:
            header = f.read(LFS_HEADER_CHECK_SIZE)

        return header.startswith(LFS_SIGNATURE)

    except OSError as e:
        logger.debug(f"Error checking LFS pointer status for {path}: {e}")
        return False


def parse_lfs_pointer(path: str | PathLike[str]) -> LFSPointerInfo | None:
    """Parse a Git LFS pointer file and extract its metadata.

    Args:
        path: Path to the LFS pointer file

    Returns:
        LFSPointerInfo with the pointer metadata, or None if not a valid pointer

    Raises:
        No exceptions are raised; returns None on any error

    Examples:
        >>> info = parse_lfs_pointer("model.bin")
        >>> if info:
        ...     print(f"Actual size: {info.format_expected_size()}")
    """
    file_path = Path(path)

    try:
        # Size check first
        file_size = file_path.stat().st_size
        if file_size > LFS_MAX_POINTER_SIZE:
            return None

        # Read and decode content
        content = file_path.read_text(encoding="utf-8")

        # Parse required fields using regex
        version_match = _VERSION_PATTERN.search(content)
        oid_match = _OID_PATTERN.search(content)
        size_match = _SIZE_PATTERN.search(content)

        # All three fields are required for a valid LFS pointer
        if version_match is None or oid_match is None or size_match is None:
            return None

        return LFSPointerInfo(
            version=version_match.group(1).strip(),
            oid=oid_match.group(1).strip(),
            size=int(size_match.group(1)),
        )

    except (OSError, UnicodeDecodeError, ValueError) as e:
        logger.debug(f"Error parsing LFS pointer {path}: {e}")
        return None


def check_lfs_pointer(path: str | PathLike[str]) -> tuple[bool, LFSPointerInfo | None]:
    """Check if a file is an LFS pointer and parse it if so.

    This is a convenience function that combines is_lfs_pointer and parse_lfs_pointer.

    Args:
        path: Path to the file to check

    Returns:
        Tuple of (is_pointer, pointer_info) where:
        - is_pointer: True if the file is an LFS pointer
        - pointer_info: LFSPointerInfo if is_pointer is True, None otherwise

    Examples:
        >>> is_pointer, info = check_lfs_pointer("model.bin")
        >>> if is_pointer:
        ...     print(f"This is a pointer to a {info.format_expected_size()} file")
    """
    if not is_lfs_pointer(path):
        return False, None

    info = parse_lfs_pointer(path)
    # If parsing fails, it's still an LFS pointer (just malformed)
    return True, info


def get_lfs_issue_details(
    file_path: str | PathLike[str],
    pointer_info: LFSPointerInfo | None,
) -> dict:
    """Generate issue details for an LFS pointer detection.

    Args:
        file_path: Path to the LFS pointer file
        pointer_info: Parsed LFS pointer info (may be None if malformed)

    Returns:
        Dictionary with issue details for reporting
    """
    path = Path(file_path)
    actual_size = path.stat().st_size if path.exists() else 0

    details: dict = {
        "file_path": str(path),
        "actual_size_bytes": actual_size,
        "issue_type": "lfs_pointer",
    }

    if pointer_info:
        details.update(
            {
                "lfs_version": pointer_info.version,
                "lfs_oid": pointer_info.oid,
                "expected_size_bytes": pointer_info.size,
                "expected_size_human": pointer_info.format_expected_size(),
                "hash_algorithm": pointer_info.hash_algorithm,
                "content_hash": pointer_info.content_hash,
            }
        )

    return details


def get_lfs_remediation_steps(repo_hint: str | None = None) -> list[str]:
    """Get remediation steps for resolving an LFS pointer issue.

    Args:
        repo_hint: Optional repository name/path to include in instructions

    Returns:
        List of remediation step strings
    """
    steps = [
        "Run 'git lfs pull' in the repository to download the actual file",
    ]

    if repo_hint:
        steps.append(f"Download directly: huggingface-cli download {repo_hint}")
    else:
        steps.append("Download directly using huggingface-cli download <repo-id> <filename>")

    steps.extend(
        [
            "Use the HuggingFace web interface to download the file",
            "Check your Git LFS installation: git lfs install && git lfs pull",
        ]
    )

    return steps
