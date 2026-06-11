"""Helpers for deciding which scan results are safe to persist in cache."""

from typing import Any

from modelaudit.scanner_results import (
    INCONCLUSIVE_SCAN_OUTCOME,
    SCAN_OUTCOME_REASONS_METADATA_KEY,
    SCANNER_DEPENDENCY_IDS_METADATA_KEY,
)

_OPERATIONAL_ERROR_INDICATORS = (
    "error during scan",
    "error checking file size",
    "error scanning file",
    "scanning error",
    "memory-mapped scan error",
    "error scanning shard",
    "scanner crashed",
    "scan timeout",
    "scan timed out",
    "scanning timed out",
    "path does not exist",
    "path is not readable",
    "permission denied",
    "no such file or directory",
    "not a directory",
    "is a directory",
    "directory not empty",
    "not installed, cannot scan",
    "package not installed",
    "missing dependency",
    "import error",
    "module not found",
    "out of memory",
    "disk space",
    "too many open files",
    "associated .bin weights file not found",
)


def should_cache_scan_result(scan_result: dict[str, Any]) -> bool:
    """Return True when a scan result is stable enough to cache safely."""
    if scan_result.get("success") is False:
        return False

    metadata = scan_result.get("metadata")
    if isinstance(metadata, dict) and (bool(metadata.get("operational_error")) or _has_incomplete_coverage(metadata)):
        return False

    for collection_name in ("issues", "checks"):
        collection = scan_result.get(collection_name)
        if not isinstance(collection, list):
            continue

        for entry in collection:
            if not isinstance(entry, dict):
                continue

            details = entry.get("details")
            if isinstance(details, dict) and (
                bool(details.get("operational_error")) or _has_incomplete_coverage(details)
            ):
                return False

            message = entry.get("message")
            if isinstance(message, str) and any(
                indicator in message.lower() for indicator in _OPERATIONAL_ERROR_INDICATORS
            ):
                return False

    return True


def _has_incomplete_coverage(metadata: dict[str, Any]) -> bool:
    if metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
        return True
    if metadata.get("analysis_incomplete") is True:
        return True

    reason = metadata.get("scan_outcome_reason")
    if isinstance(reason, str):
        return bool(reason)

    reasons = metadata.get(SCAN_OUTCOME_REASONS_METADATA_KEY)
    if isinstance(reasons, str):
        return bool(reasons)
    if isinstance(reasons, (list, tuple, set, frozenset)):
        return any(bool(item) for item in reasons)

    return False


def cached_scan_result_dependencies_available(scan_result: dict[str, Any]) -> bool:
    """Return whether every registered scanner required by a cached result still loads."""
    scanner_ids: set[str] = set()
    scanner_name = scan_result.get("scanner")
    if isinstance(scanner_name, str):
        scanner_ids.add(scanner_name)

    metadata = scan_result.get("metadata")
    if isinstance(metadata, dict):
        dependency_ids = metadata.get(SCANNER_DEPENDENCY_IDS_METADATA_KEY)
        if isinstance(dependency_ids, list):
            scanner_ids.update(scanner_id for scanner_id in dependency_ids if isinstance(scanner_id, str))

    try:
        from modelaudit.scanners import _registry

        for scanner_id in scanner_ids:
            if _registry.get_scanner_info(scanner_id) is None:
                continue
            if _registry.load_scanner_by_id(scanner_id) is None:
                return False
    except Exception:
        return False

    return True
