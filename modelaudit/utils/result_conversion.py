"""Utilities for converting between ScanResult objects and dictionaries."""

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
    from ..scanners.base import Check, CheckStatus, IssueSeverity, ScanResult

    # Create new ScanResult with the same scanner name
    scanner_name = result_dict.get("scanner", "cached")
    result = ScanResult(scanner_name=scanner_name)

    # Restore basic properties
    result.success = result_dict.get("success", True)
    result.bytes_scanned = result_dict.get("bytes_scanned", 0)
    result.start_time = result_dict.get("start_time", time.time())
    result.end_time = result_dict.get("end_time", time.time())
    result.metadata.update(result_dict.get("metadata", {}))

    # Restore issues from cached data
    for issue_dict in result_dict.get("issues", []):
        from ..scanners.base import Issue

        issue = Issue(
            message=issue_dict.get("message", ""),
            severity=IssueSeverity(issue_dict.get("severity", "warning")),
            location=issue_dict.get("location"),
            details=issue_dict.get("details", {}),
            why=issue_dict.get("why"),
            type=issue_dict.get("type", f"{scanner_name}_cached"),
            timestamp=issue_dict.get("timestamp", time.time()),
        )
        result.issues.append(issue)

    # Restore checks from cached data
    for check_dict in result_dict.get("checks", []):
        try:
            check = Check(
                name=check_dict.get("name", ""),
                status=CheckStatus(check_dict.get("status", "passed")),
                message=check_dict.get("message", ""),
                severity=IssueSeverity(check_dict.get("severity")) if check_dict.get("severity") else None,
                location=check_dict.get("location"),
                details=check_dict.get("details", {}),
                why=check_dict.get("why"),
                timestamp=check_dict.get("timestamp", time.time()),
            )
            result.checks.append(check)
        except Exception as e:
            # If we can't reconstruct a check, log and continue
            logger.debug(f"Could not reconstruct check from cache: {e}")

    return result
