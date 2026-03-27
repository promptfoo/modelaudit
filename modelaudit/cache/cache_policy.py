"""Helpers for deciding which scan results are safe to persist in cache."""

from typing import Any

_OPERATIONAL_ERROR_INDICATORS = (
    "Error during scan",
    "Error checking file size",
    "Error scanning file",
    "Scanner crashed",
    "Scan timeout",
    "Path does not exist",
    "Path is not readable",
    "Permission denied",
    "File not found",
    "not installed, cannot scan",
    "Missing dependency",
    "Import error",
    "Module not found",
    "not a valid",
    "Invalid file format",
    "Corrupted file",
    "Bad file signature",
    "Unable to parse",
    "Out of memory",
    "Disk space",
    "Too many open files",
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
            if isinstance(message, str) and any(indicator in message for indicator in _OPERATIONAL_ERROR_INDICATORS):
                return False

    return True
