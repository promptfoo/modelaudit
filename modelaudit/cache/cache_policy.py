"""Helpers for deciding which scan results are safe to persist in cache."""

from typing import Any

from modelaudit.scanner_results import (
    ACTIONABLE_FAILED_CHECKS_METADATA_KEY,
    INCONCLUSIVE_SCAN_OUTCOME,
    SCAN_OUTCOME_REASONS_METADATA_KEY,
    SCANNER_DEPENDENCY_IDS_METADATA_KEY,
    SUPPRESSED_FAILED_CHECKS_METADATA_KEY,
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
_PRIVATE_EVIDENCE_METADATA_KEYS = (
    ACTIONABLE_FAILED_CHECKS_METADATA_KEY,
    SUPPRESSED_FAILED_CHECKS_METADATA_KEY,
)


def should_cache_scan_result(scan_result: dict[str, Any]) -> bool:
    """Return True when a scan result is stable enough to cache safely."""
    if scan_result.get("success") is False:
        return False

    if _metadata_disqualifies_cache(scan_result.get("metadata"), allow_bare_analysis_incomplete=True):
        return False

    private_metadata = scan_result.get("_private_metadata")
    if isinstance(private_metadata, dict) and any(key in private_metadata for key in _PRIVATE_EVIDENCE_METADATA_KEYS):
        return False

    for collection_name in ("issues", "checks"):
        collection = scan_result.get(collection_name)
        if not isinstance(collection, list):
            continue

        for entry in collection:
            if not isinstance(entry, dict):
                continue

            if _metadata_disqualifies_cache(entry.get("details"), allow_bare_analysis_incomplete=False):
                return False

            message = entry.get("message")
            if isinstance(message, str) and any(
                indicator in message.lower() for indicator in _OPERATIONAL_ERROR_INDICATORS
            ):
                return False

    return True


def _metadata_disqualifies_cache(metadata: Any, *, allow_bare_analysis_incomplete: bool) -> bool:
    if not isinstance(metadata, dict):
        return False
    if (
        bool(metadata.get("operational_error"))
        or metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        or _has_incomplete_coverage_reasons(
            metadata,
            allow_bare_analysis_incomplete=allow_bare_analysis_incomplete,
        )
    ):
        return True

    findings = metadata.get("findings")
    if isinstance(findings, dict):
        return _metadata_disqualifies_cache(
            findings,
            allow_bare_analysis_incomplete=allow_bare_analysis_incomplete,
        )
    if isinstance(findings, (list, tuple, set, frozenset)):
        return any(
            _metadata_disqualifies_cache(
                finding,
                allow_bare_analysis_incomplete=allow_bare_analysis_incomplete,
            )
            for finding in findings
        )

    details = metadata.get("details")
    if isinstance(details, dict):
        return _metadata_disqualifies_cache(
            details,
            allow_bare_analysis_incomplete=allow_bare_analysis_incomplete,
        )

    return False


def _has_incomplete_coverage_reasons(
    metadata: dict[str, Any],
    *,
    allow_bare_analysis_incomplete: bool,
) -> bool:
    reason = metadata.get("scan_outcome_reason")
    if isinstance(reason, str) and reason:
        return True
    if allow_bare_analysis_incomplete and metadata.get("analysis_incomplete") is True:
        return True

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
