"""Utilities for converting between ScanResult objects and dictionaries.

This module provides functions to convert ScanResult objects to/from dictionary
representations for caching and serialization purposes. It helps break circular
import dependencies between core.py and scanners/base.py.
"""

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..scanners.base import ScanResult

logger = logging.getLogger(__name__)


def scan_result_from_dict(result_dict: dict[str, Any]) -> "ScanResult":
    """
    Convert a dictionary representation back to a ScanResult object.

    This is used when retrieving cached scan results that were stored as dictionaries.

    Args:
        result_dict: Dictionary representation of a ScanResult

    Returns:
        Reconstructed ScanResult object
    """
    from ..scanners.base import Check, CheckStatus, Issue, IssueSeverity, ScanResult

    # Create new ScanResult with the same scanner name
    scanner_name = result_dict.get("scanner", "cached")
    result = ScanResult(scanner_name=scanner_name)

    # For end_time: preserve None only if it was explicitly stored as None
    # If missing entirely (common with current to_dict), set to start_time + duration
    if "end_time" in result_dict:
        result.end_time = result_dict["end_time"]
    elif "duration" in result_dict:
        result.end_time = result.start_time + result_dict["duration"]
    else:
        result.end_time = time.time()
    result.metadata.update(result_dict.get("metadata", {}))

    # Restore bytes_scanned from cache
    result.bytes_scanned = result_dict.get("bytes_scanned", 0)
    result.success = result_dict.get("success", True)

    # Helpers to normalize incoming cached values
    def _normalize_issue_severity(val: Any) -> IssueSeverity:
        if isinstance(val, IssueSeverity):
            return val
        s = str(val).lower() if val is not None else "warning"
        # Back-compat synonyms
        if s in ("warn",):
            s = "warning"
        if s in ("error", "err"):  # older caches sometimes used "error"
            s = "critical"
        try:
            return IssueSeverity(s)
        except Exception:
            return IssueSeverity.WARNING

    def _coerce_details(val: Any) -> dict[str, Any]:
        if isinstance(val, dict):
            return val
        if hasattr(val, "model_dump"):
            try:
                result = val.model_dump()
                return result if isinstance(result, dict) else {"value": result}
            except Exception:
                pass
        if hasattr(val, "dict"):
            try:
                result = val.dict()
                return result if isinstance(result, dict) else {"value": result}
            except Exception:
                pass
        return {"value": val}

    def _normalize_check_status(val: Any) -> CheckStatus:
        if isinstance(val, CheckStatus):
            return val
        s = str(val).lower() if val is not None else "passed"
        if s in ("ok", "success"):
            s = "passed"
        if s in ("error", "fail", "failed"):
            s = "failed"
        if s not in ("passed", "failed", "skipped"):
            s = "passed"
        try:
            return CheckStatus(s)
        except Exception:
            return CheckStatus.PASSED

    # Restore issues from cached data
    for issue_dict in result_dict.get("issues", []):
        try:
            issue = Issue(
                message=issue_dict.get("message", ""),
                severity=_normalize_issue_severity(issue_dict.get("severity", "warning")),
                location=issue_dict.get("location"),
                details=_coerce_details(issue_dict.get("details", {})),
                why=issue_dict.get("why"),
                type=issue_dict.get("type", f"{scanner_name}_cached"),
                timestamp=issue_dict.get("timestamp", time.time()),
            )
            result.issues.append(issue)
        except Exception as e:
            logger.debug(f"Could not reconstruct issue from cache: {e}")

    # Restore checks from cached data
    for check_dict in result_dict.get("checks", []):
        try:
            check = Check(
                name=check_dict.get("name", ""),
                status=_normalize_check_status(check_dict.get("status", "passed")),
                message=check_dict.get("message", ""),
                severity=_normalize_issue_severity(check_dict.get("severity")) if check_dict.get("severity") else None,
                location=check_dict.get("location"),
                details=_coerce_details(check_dict.get("details", {})),
                why=check_dict.get("why"),
                timestamp=check_dict.get("timestamp", time.time()),
            )
            result.checks.append(check)
        except Exception as e:
            # If we can't reconstruct a check, log and continue
            logger.debug(f"Could not reconstruct check from cache (name={check_dict.get('name', '')}): {e}")

    return result


def scan_result_to_dict(scan_result: "ScanResult") -> dict[str, Any]:
    """
    Convert a ScanResult object to a dictionary representation.

    This is used when storing scan results in cache.

    Args:
        scan_result: ScanResult object to convert

    Returns:
        Dictionary representation of the ScanResult
    """
    if hasattr(scan_result, "to_dict"):
        return scan_result.to_dict()

    # Fallback manual conversion if to_dict() method doesn't exist
    result_dict: dict[str, Any] = {
        "scanner": getattr(scan_result, "scanner_name", "unknown"),
        "success": getattr(scan_result, "success", True),
        "bytes_scanned": getattr(scan_result, "bytes_scanned", 0),
        "start_time": getattr(scan_result, "start_time", time.time()),
        "end_time": getattr(scan_result, "end_time", time.time()),
        "metadata": getattr(scan_result, "metadata", {}),
        "issues": [],
        "checks": [],
    }

    # Convert issues
    for issue in getattr(scan_result, "issues", []):
        issue_dict = {
            "message": getattr(issue, "message", ""),
            "severity": getattr(issue, "severity", "warning"),
            "location": getattr(issue, "location", ""),
            "details": getattr(issue, "details", {}),
            "why": getattr(issue, "why", ""),
        }
        result_dict["issues"].append(issue_dict)

    # Convert checks
    for check in getattr(scan_result, "checks", []):
        check_dict = {
            "name": getattr(check, "name", ""),
            "status": getattr(check, "status", "passed"),
            "message": getattr(check, "message", ""),
            "severity": getattr(check, "severity", None),
            "location": getattr(check, "location", ""),
            "details": getattr(check, "details", {}),
            "why": getattr(check, "why", ""),
            "timestamp": getattr(check, "timestamp", time.time()),
        }
        result_dict["checks"].append(check_dict)

    return result_dict
