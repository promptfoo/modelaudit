"""Helpers for deciding which scan results are safe to persist in cache."""

from typing import Any

_OPERATIONAL_ERROR_INDICATORS = (
    "error during scan",
    "error checking file size",
    "error scanning file",
    "scanning error",
    "memory-mapped scan error",
    "error scanning shard",
    "scanner crashed",
    "scan timeout",
    "path does not exist",
    "path is not readable",
    "permission denied",
    "file not found",
    "not installed, cannot scan",
    "missing dependency",
    "import error",
    "module not found",
    "not a valid",
    "invalid file format",
    "corrupted file",
    "bad file signature",
    "unable to parse",
    "out of memory",
    "disk space",
    "too many open files",
)


def should_cache_scan_result(scan_result: dict[str, Any]) -> bool:
    """Return True when a scan result is stable enough to cache safely."""
    for collection_name in ("issues", "checks"):
        collection = scan_result.get(collection_name)
        if not isinstance(collection, list):
            continue

        for entry in collection:
            if not isinstance(entry, dict):
                continue

            message = entry.get("message")
            if isinstance(message, str) and any(
                indicator in message.lower() for indicator in _OPERATIONAL_ERROR_INDICATORS
            ):
                return False

    return True
