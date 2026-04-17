"""Result aggregation helpers for core scanning flows."""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from typing import Any

from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import (
    INCONCLUSIVE_SCAN_OUTCOME,
    Check,
    Issue,
    IssueSeverity,
    ScanResult,
    mark_inconclusive_scan_result,
    normalize_unclassified_scan_failure,
)
from modelaudit.telemetry import record_issue_found
from modelaudit.utils.helpers.assets import asset_from_scan_result

logger = logging.getLogger("modelaudit.core.results")

OPERATIONAL_ERROR_METADATA_KEY = "operational_error"
OPERATIONAL_ERROR_REASON_METADATA_KEY = "operational_error_reason"
SCAN_OUTCOME_METADATA_KEY = "scan_outcome"


def mark_operational_scan_error(scan_result: ScanResult, reason: str) -> None:
    """Mark a scan result as an operational failure for exit-code aggregation."""
    scan_result.metadata[OPERATIONAL_ERROR_METADATA_KEY] = True
    scan_result.metadata[OPERATIONAL_ERROR_REASON_METADATA_KEY] = reason
    scan_result._refresh_metadata_dependent_state()


def mark_inconclusive_scan_outcome(scan_result: ScanResult, reason: str) -> None:
    """Mark a scan result as explicitly inconclusive for exit-code aggregation."""
    mark_inconclusive_scan_result(scan_result, reason)


def scan_result_has_operational_error(scan_result: ScanResult) -> bool:
    """Return True when a scan result represents an operational failure."""
    metadata = scan_result.metadata or {}
    explicit_flag = metadata.get(OPERATIONAL_ERROR_METADATA_KEY)
    if explicit_flag is not None:
        return bool(explicit_flag)

    return False


def results_have_operational_error(results: ModelAuditResultModel) -> bool:
    """Return True when aggregated results include an operational failure."""
    if getattr(results, "has_errors", False):
        return True

    return any(
        bool(metadata.get(OPERATIONAL_ERROR_METADATA_KEY)) for metadata in (results.file_metadata or {}).values()
    )


def _metadata_has_scan_outcome(metadata: Any, outcome: str) -> bool:
    """Return True when metadata reports the requested scan outcome."""
    if metadata is None:
        return False
    if isinstance(metadata, dict):
        return metadata.get(SCAN_OUTCOME_METADATA_KEY) == outcome

    getter = getattr(metadata, "get", None)
    if callable(getter):
        try:
            value = getter(SCAN_OUTCOME_METADATA_KEY)
            return bool(value == outcome)
        except Exception:
            return False

    return getattr(metadata, SCAN_OUTCOME_METADATA_KEY, None) == outcome


def results_have_inconclusive_outcome(results: ModelAuditResultModel) -> bool:
    """Return True when any scanned file completed with an explicit inconclusive outcome."""
    return any(
        _metadata_has_scan_outcome(metadata, INCONCLUSIVE_SCAN_OUTCOME)
        for metadata in (results.file_metadata or {}).values()
    )


def results_have_security_findings(results: ModelAuditResultModel) -> bool:
    """Return True when WARNING/CRITICAL issues were reported."""
    return any(
        hasattr(issue, "severity") and issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        for issue in (results.issues or [])
    )


def results_should_be_unsuccessful(results: ModelAuditResultModel) -> bool:
    """Return True when the aggregate result should not be considered successful."""
    if results_have_operational_error(results):
        return True

    return results_have_inconclusive_outcome(results) and not results_have_security_findings(results)


def to_telemetry_severity(severity: Any) -> str:
    """Normalize severity values to stable telemetry strings."""
    if hasattr(severity, "value"):
        return str(severity.value).lower()
    if hasattr(severity, "name"):
        return str(severity.name).lower()

    severity_str = str(severity).lower()
    if severity_str.startswith("issueseverity."):
        severity_str = severity_str.split(".", 1)[1]
    return severity_str


def add_asset_to_results(
    results: ModelAuditResultModel,
    file_path: str,
    file_result: ScanResult,
) -> None:
    """Add an asset entry to the aggregate results."""
    from .models import AssetModel

    asset_dict = asset_from_scan_result(file_path, file_result)
    asset = AssetModel(**asset_dict)
    results.assets.append(asset)


def add_error_asset_to_results(results: ModelAuditResultModel, file_path: str) -> None:
    """Add an error asset entry to the aggregate results."""
    from .models import AssetModel

    asset = AssetModel(path=file_path, type="error", size=None, tensors=None, keys=None, contents=None)
    results.assets.append(asset)


def add_scan_result_to_model(
    results: ModelAuditResultModel, scan_metadata: dict[str, Any], file_result: ScanResult, file_path: str
) -> None:
    """Add a single scan result to the aggregate results model."""
    from .models import FileMetadataModel

    results.bytes_scanned += file_result.bytes_scanned
    normalize_unclassified_scan_failure(file_result)

    if file_result.scanner_name and file_result.scanner_name not in scan_metadata.get("scanners", []):
        scan_metadata.setdefault("scanners", []).append(file_result.scanner_name)
    if (
        file_result.scanner_name
        and file_result.scanner_name not in results.scanner_names
        and file_result.scanner_name != "unknown"
    ):
        results.scanner_names.append(file_result.scanner_name)
    if scan_result_has_operational_error(file_result):
        scan_metadata["has_operational_errors"] = True

    for issue in file_result.issues:
        issue_dict = issue.to_dict() if hasattr(issue, "to_dict") else issue
        if isinstance(issue_dict, dict):
            issue_details = issue_dict.get("details")
            issue_details = issue_details if isinstance(issue_details, dict) else {}
            record_issue_found(
                issue_type=str(issue_dict.get("type") or "unknown_issue"),
                severity=to_telemetry_severity(issue_dict.get("severity", "unknown")),
                scanner=file_result.scanner_name,
                file_path=file_path,
                rule_code=issue_dict.get("rule_code") if isinstance(issue_dict.get("rule_code"), str) else None,
                cve_id=issue_details.get("cve_id") if isinstance(issue_details.get("cve_id"), str) else None,
                issue_message=issue_dict.get("message") if isinstance(issue_dict.get("message"), str) else None,
            )
            results.issues.append(Issue(**issue_dict))

    for check in file_result.checks:
        check_dict = check.to_dict() if hasattr(check, "to_dict") else check
        if isinstance(check_dict, dict):
            results.checks.append(Check(**check_dict))

    if hasattr(file_result, "metadata") and file_result.metadata:
        metadata_dict = file_result.metadata.copy()
        if "ml_context" in metadata_dict and isinstance(metadata_dict["ml_context"], dict):
            from .models import MLContextModel

            metadata_dict["ml_context"] = MLContextModel(**metadata_dict["ml_context"])
        results.file_metadata[file_path] = FileMetadataModel(**metadata_dict)


def add_issue_to_model(
    results: ModelAuditResultModel,
    message: str,
    severity: str | IssueSeverity | None = "info",
    location: str | None = None,
    details: dict | None = None,
    issue_type: str | None = None,
) -> None:
    """Add an issue directly to the aggregate results model."""
    if isinstance(severity, IssueSeverity):
        severity_enum = severity
    else:
        severity_str = str(severity).lower() if severity is not None else "info"
        if severity_str == "warn":
            severity_str = "warning"
        if severity_str in {"error", "err"}:
            severity_str = "critical"
        severity_enum = {
            "debug": IssueSeverity.DEBUG,
            "info": IssueSeverity.INFO,
            "warning": IssueSeverity.WARNING,
            "critical": IssueSeverity.CRITICAL,
        }.get(severity_str, IssueSeverity.INFO)

    issue = Issue(
        message=message,
        severity=severity_enum,
        location=location,
        details=details or {},
        timestamp=time.time(),
        why=None,
        type=issue_type,
    )
    results.issues.append(issue)


def normalize_streamed_location(location: str | None, report_path: str, resolved_path: str) -> str | None:
    """Rewrite streamed result locations to the original source path when needed."""
    if not location or report_path == resolved_path:
        return location

    if location == resolved_path:
        return report_path

    if not location.startswith(resolved_path):
        return location

    suffix = location[len(resolved_path) :]
    if suffix and suffix[0] not in {":", " ", "(", "[", "/", "\\"}:
        return location

    return f"{report_path}{suffix}"


def serialize_streamed_records(records: list[Any], report_path: str, resolved_path: str) -> list[dict[str, Any]]:
    """Convert streamed issues/checks into dicts with source-path locations."""
    serialized: list[dict[str, Any]] = []
    for record in records:
        record_dict = record.to_dict() if hasattr(record, "to_dict") else record
        if not isinstance(record_dict, dict):
            continue

        normalized_record = dict(record_dict)
        location = normalized_record.get("location")
        if isinstance(location, str):
            normalized_record["location"] = normalize_streamed_location(location, report_path, resolved_path)

        serialized.append(normalized_record)

    return serialized


def _extract_primary_asset_from_location(location: str) -> str:
    """Extract primary asset path from location string."""
    if not location or not isinstance(location, str):
        return "unknown"

    primary_location = location.strip()

    if not primary_location:
        return "unknown"

    drive, tail = os.path.splitdrive(primary_location)
    if ":" in tail:
        tail = tail.split(":", 1)[0]
    primary_asset = f"{drive}{tail}"

    return primary_asset.strip() if primary_asset.strip() else "unknown"


def _group_checks_by_asset(checks_list: list[Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Group checks by check name and primary asset path."""
    check_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for i, check in enumerate(checks_list):
        if not isinstance(check, dict):
            logger.warning(f"Invalid check format at index {i}, skipping: {type(check)}")
            continue

        check_name = check.get("name", "Unknown Check")
        location = check.get("location", "")
        primary_asset = _extract_primary_asset_from_location(location)
        details = check.get("details")
        zip_entry_id = details.get("zip_entry_id") if isinstance(details, dict) else None
        zip_entry = details.get("zip_entry") if isinstance(details, dict) else None

        if isinstance(zip_entry_id, str) and zip_entry_id:
            asset_group = f"{primary_asset}:{zip_entry_id}"
        elif isinstance(zip_entry, str) and zip_entry:
            asset_group = f"{primary_asset}:{zip_entry}"
        else:
            asset_group = primary_asset

        group_key = (check_name, asset_group)
        check_groups[group_key].append(check)

    return check_groups


def _create_consolidated_message(
    check_name: str, group_checks: list[dict[str, Any]], consolidated_status: str, failed_count: int
) -> str:
    """Create an appropriate consolidated check message."""
    if consolidated_status == "passed":
        messages = {c.get("message", "") for c in group_checks if c.get("status") == "passed"}

        if len(messages) == 1:
            return str(next(iter(messages)))
        return f"{check_name} completed successfully"

    failed_messages = {c.get("message", "") for c in group_checks if c.get("status") == "failed"}

    if len(failed_messages) == 1:
        return str(next(iter(failed_messages)))
    if failed_count == 1:
        return f"{check_name} found 1 issue"
    return f"{check_name} found {failed_count} issues"


def _collect_consolidated_details(group_checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Collect details from failed checks in a consolidation group."""
    consolidated_details: dict[str, Any] = {"component_count": len(group_checks)}
    failed_details: list[Any] = []

    for check in group_checks:
        if check.get("status") == "failed" and check.get("details"):
            failed_details.append(check["details"])

    if failed_details:
        consolidated_details["findings"] = failed_details

    return consolidated_details


def _extract_failure_context(group_checks: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """Extract severity and explanation from failed checks."""
    consolidated_severity = None
    consolidated_why = None

    for check in group_checks:
        if check.get("status") == "failed":
            if not consolidated_severity and check.get("severity"):
                consolidated_severity = check["severity"]
            if not consolidated_why and check.get("why"):
                consolidated_why = check["why"]

            if consolidated_severity and consolidated_why:
                break

    return consolidated_severity, consolidated_why


def _get_consolidated_timestamp(group_checks: list[dict[str, Any]]) -> float:
    """Get the most recent timestamp from a consolidation group."""
    timestamps = [c.get("timestamp", 0) for c in group_checks if isinstance(c.get("timestamp"), int | float)]
    return max(timestamps) if timestamps else time.time()


def _update_result_counts(
    results: ModelAuditResultModel, consolidated_checks: list[dict[str, Any]], original_count: int
) -> None:
    """Update aggregate check counts after consolidation."""

    def is_failed_info_or_debug(check):
        if check.get("status") != "failed":
            return False
        severity = check.get("severity", "")
        return severity in ("info", "debug", IssueSeverity.INFO.value, IssueSeverity.DEBUG.value)

    security_checks = [c for c in consolidated_checks if not is_failed_info_or_debug(c)]

    total_checks = len(security_checks)
    passed_checks = sum(1 for c in security_checks if c.get("status") == "passed")
    failed_checks = sum(1 for c in security_checks if c.get("status") == "failed")
    skipped_checks = total_checks - passed_checks - failed_checks

    info_debug_excluded = len(consolidated_checks) - len(security_checks)
    logger.debug(
        f"Check statistics: {total_checks} total ({info_debug_excluded} INFO/DEBUG excluded), "
        f"{passed_checks} passed, {failed_checks} failed"
    )

    if passed_checks + failed_checks + skipped_checks != total_checks:
        logger.warning(
            f"Check count mismatch: {passed_checks}P + {failed_checks}F + {skipped_checks}S != {total_checks}T"
        )

    results.total_checks = total_checks
    results.passed_checks = passed_checks
    results.failed_checks = failed_checks

    reduction_count = original_count - total_checks
    logger.debug(f"Check consolidation: {original_count} -> {total_checks} ({reduction_count} duplicates removed)")

    if skipped_checks > 0:
        logger.debug(f"Check status distribution: {passed_checks}P, {failed_checks}F, {skipped_checks}S")


def consolidate_checks(results: ModelAuditResultModel) -> None:
    """Consolidate duplicate checks by name and asset for cleaner reporting."""
    checks_list = [check.model_dump() if hasattr(check, "model_dump") else check for check in results.checks]
    if not checks_list:
        logger.debug("No checks to consolidate")
        return

    logger.debug(f"Starting consolidation of {len(checks_list)} checks")
    check_groups = _group_checks_by_asset(checks_list)
    consolidated_checks: list[dict[str, Any]] = []

    for (check_name, primary_asset), group_checks in check_groups.items():
        if len(group_checks) == 1:
            consolidated_checks.append(group_checks[0])
            continue

        statuses = [c.get("status") for c in group_checks]
        failed_count = sum(s == "failed" for s in statuses)
        passed_count = sum(s == "passed" for s in statuses)
        if failed_count:
            consolidated_status = "failed"
        elif passed_count:
            consolidated_status = "passed"
        else:
            consolidated_status = "skipped"

        consolidated_check = {
            "name": check_name,
            "status": consolidated_status,
            "message": _create_consolidated_message(check_name, group_checks, consolidated_status, failed_count),
            "location": group_checks[0].get("location", primary_asset),
            "details": _collect_consolidated_details(group_checks),
            "timestamp": _get_consolidated_timestamp(group_checks),
        }

        consolidated_severity, consolidated_why = _extract_failure_context(group_checks)
        if consolidated_severity:
            consolidated_check["severity"] = consolidated_severity
        if consolidated_why:
            consolidated_check["why"] = consolidated_why

        consolidated_checks.append(consolidated_check)

        logger.debug(
            f"Consolidated {len(group_checks)} '{check_name}' checks for {primary_asset} "
            f"({passed_count} passed, {failed_count} failed)"
        )

    from .models import Check

    results.checks = [Check(**check) if isinstance(check, dict) else check for check in consolidated_checks]
    _update_result_counts(results, consolidated_checks, len(checks_list))


def determine_exit_code(results: ModelAuditResultModel) -> int:
    """
    Determine the appropriate exit code based on scan results.

    Exit codes:
    - 0: Success, no security issues found
    - 1: Security issues found (scan completed successfully)
    - 2: Operational errors occurred during scanning, the scan outcome was
         inconclusive without any WARNING/CRITICAL findings, or no files were
         scanned and no security issues were found
    """
    if results_have_operational_error(results):
        return 2

    if results_have_security_findings(results):
        return 1

    if results_have_inconclusive_outcome(results):
        return 2

    if results.success is False:
        return 2

    if results.files_scanned == 0:
        return 2

    return 0


def merge_scan_result(
    results: ModelAuditResultModel,
    scan_result: ScanResult | dict[str, Any],
) -> None:
    """Merge a ScanResult object or dict into the aggregate results model."""
    if isinstance(scan_result, ScanResult):
        file_path = scan_result.file_path if hasattr(scan_result, "file_path") else None
        for issue in scan_result.issues:
            issue_details = issue.details if isinstance(issue.details, dict) else {}
            record_issue_found(
                issue.type or "unknown_issue",
                issue.severity.name if hasattr(issue.severity, "name") else str(issue.severity),
                scan_result.scanner_name,
                file_path=file_path,
                rule_code=issue.rule_code,
                cve_id=issue_details.get("cve_id") if isinstance(issue_details.get("cve_id"), str) else None,
                issue_message=issue.message,
            )
        results.aggregate_scan_result_direct(scan_result)
    else:
        file_path = scan_result.get("file_path")
        for issue in scan_result.get("issues", []):
            raw_issue_details = issue.get("details") if isinstance(issue, dict) else None
            issue_details = raw_issue_details if isinstance(raw_issue_details, dict) else {}
            record_issue_found(
                issue.get("type") or "unknown_issue",
                issue.get("severity", "unknown"),
                scan_result.get("scanner_name", "unknown"),
                file_path=file_path,
                rule_code=issue.get("rule_code") if isinstance(issue.get("rule_code"), str) else None,
                cve_id=issue_details.get("cve_id") if isinstance(issue_details.get("cve_id"), str) else None,
                issue_message=issue.get("message") if isinstance(issue.get("message"), str) else None,
            )
        results.aggregate_scan_result(scan_result)
