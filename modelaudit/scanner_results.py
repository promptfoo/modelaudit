"""Low-level scan result contracts shared by core, models, and scanners."""

import json
import logging
import time
from collections.abc import Mapping
from copy import deepcopy
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_serializer

logger = logging.getLogger("modelaudit.scanners")

INCONCLUSIVE_SCAN_OUTCOME: Final[str] = "inconclusive"
SCAN_OUTCOME_METADATA_KEY: Final[str] = "scan_outcome"
SCAN_OUTCOME_REASONS_METADATA_KEY: Final[str] = "scan_outcome_reasons"
SCAN_OUTCOME_MESSAGE_METADATA_KEY: Final[str] = "scan_outcome_message"
SCANNER_DEPENDENCY_IDS_METADATA_KEY: Final[str] = "scanner_dependency_ids"
OPERATIONAL_ERROR_METADATA_KEY: Final[str] = "operational_error"
RAW_DETECTOR_ANALYSIS_INCOMPLETE_REASON: Final[str] = "raw_detector_analysis_incomplete"
RAW_DETECTOR_FAILURES_METADATA_KEY: Final[str] = "raw_detector_analysis_failures"
RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY: Final[str] = "raw_detector_failed_detectors"
UNCLASSIFIED_SCAN_FAILURE_REASON: Final[str] = "scanner_reported_unsuccessful_without_outcome"
CALL_GRAPH_SOURCE_FINGERPRINTS_METADATA_KEY: Final[str] = "call_graph_source_fingerprints"
MEMBER_FILE_HASHES_METADATA_KEY: Final[str] = "member_file_hashes"
MEMBER_FILE_HASHES_TOTAL_METADATA_KEY: Final[str] = "member_file_hashes_total"
MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY: Final[str] = "member_file_hashes_truncated"
MEMBER_FILE_HASHES_OMITTED_METADATA_KEY: Final[str] = "member_file_hashes_omitted"
FILE_HASHES_COMPLETE_METADATA_KEY: Final[str] = "file_hashes_complete"
FILE_HASHES_BYTES_HASHED_METADATA_KEY: Final[str] = "file_hashes_bytes_hashed"
MAX_MEMBER_FILE_HASH_RECORDS: Final[int] = 4096
_MEMBER_FILE_HASH_OCCURRENCES_PRIVATE_KEY: Final[str] = "member_file_hash_occurrences"
_MEMBER_FILE_HASH_STORED_COUNT_PRIVATE_KEY: Final[str] = "member_file_hashes_stored_count"
_MEMBER_FILE_HASH_PRIVATE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        _MEMBER_FILE_HASH_OCCURRENCES_PRIVATE_KEY,
        _MEMBER_FILE_HASH_STORED_COUNT_PRIVATE_KEY,
    }
)
_PARENT_INTEGRITY_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "file_hashes",
        "file_size",
        FILE_HASHES_COMPLETE_METADATA_KEY,
        FILE_HASHES_BYTES_HASHED_METADATA_KEY,
    }
)
_HASH_FIELD_NAMES: Final[frozenset[str]] = frozenset({"md5", "sha1", "sha256", "sha512"})
_MEMBER_FILE_HASH_SUMMARY_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        MEMBER_FILE_HASHES_TOTAL_METADATA_KEY,
        MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY,
        MEMBER_FILE_HASHES_OMITTED_METADATA_KEY,
    }
)


def _deep_mutable_copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _deep_mutable_copy(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_deep_mutable_copy(item) for item in value]
    if isinstance(value, set | frozenset):
        return [_deep_mutable_copy(item) for item in value]
    return deepcopy(value)


def _member_file_hashes_from_metadata(metadata: Mapping[str, Any], scanner_name: str | None) -> dict[str, Any] | None:
    raw_hashes = metadata.get("file_hashes")
    if not isinstance(raw_hashes, Mapping):
        return None

    hashes = {
        str(algorithm): value
        for algorithm, value in raw_hashes.items()
        if algorithm in _HASH_FIELD_NAMES and isinstance(value, str) and value
    }
    if not hashes:
        return None

    hash_complete = metadata.get(FILE_HASHES_COMPLETE_METADATA_KEY)
    bytes_hashed = metadata.get(FILE_HASHES_BYTES_HASHED_METADATA_KEY)
    record: dict[str, Any] = {}
    if scanner_name:
        record["scanner_name"] = scanner_name
    if isinstance(metadata.get("file_size"), int):
        record["file_size"] = metadata["file_size"]
    elif hash_complete is not False and isinstance(bytes_hashed, int):
        record["file_size"] = bytes_hashed
    if isinstance(bytes_hashed, int):
        record["bytes_hashed"] = bytes_hashed

    if hash_complete is False:
        record["hash_complete"] = False
        record["hash_status"] = "partial"
    else:
        record["file_hashes"] = _deep_mutable_copy(hashes)
        if hash_complete is True:
            record["hash_complete"] = True

    return record


def _member_path_segments_key(path_segments: list[str]) -> str:
    return json.dumps(path_segments, separators=(",", ":"), sort_keys=True)


def _member_file_hash_identity_key(path_segments: list[str], occurrence: int) -> str:
    return json.dumps({"occurrence": occurrence, "path": path_segments}, separators=(",", ":"), sort_keys=True)


def _logical_member_path(path_segments: list[str]) -> str:
    if not path_segments:
        return "<archive-member>"
    return ":".join(path_segments)


def _member_path_segments_from_record(member_key: str, record: Mapping[str, Any]) -> list[str]:
    raw_segments = record.get("path_segments")
    if isinstance(raw_segments, list) and all(isinstance(segment, str) for segment in raw_segments):
        return list(raw_segments)

    try:
        decoded_key = json.loads(member_key)
    except (TypeError, ValueError):
        decoded_key = None
    if isinstance(decoded_key, Mapping):
        decoded_segments = decoded_key.get("path")
        if isinstance(decoded_segments, list) and all(isinstance(segment, str) for segment in decoded_segments):
            return list(decoded_segments)

    return [member_key]


def _member_occurrence_from_record(record: Mapping[str, Any]) -> int:
    occurrence = record.get("occurrence")
    if isinstance(occurrence, int) and occurrence > 0 and not isinstance(occurrence, bool):
        return occurrence
    return 1


def _iter_child_member_file_hash_records(metadata: Mapping[str, Any]) -> list[tuple[list[str], Mapping[str, Any]]]:
    raw_member_hashes = metadata.get(MEMBER_FILE_HASHES_METADATA_KEY)
    if not isinstance(raw_member_hashes, Mapping):
        return []
    records: list[tuple[list[str], Mapping[str, Any]]] = []
    for member_path, record in raw_member_hashes.items():
        if isinstance(member_path, str) and member_path and isinstance(record, Mapping):
            records.append((_member_path_segments_from_record(member_path, record), record))
    return records


def _is_source_independent_call_graph_fingerprint_metadata(metadata: Mapping[str, Any]) -> bool:
    return dict(metadata) == {
        "reusable": True,
        "source_independent": True,
        "fingerprints": {},
        "read_fingerprints": {},
        "module_sources": {},
        "loaded_module_sources": {},
        "loaded_package_paths": {},
    }


def _merge_call_graph_source_fingerprints_metadata(
    existing: Mapping[str, Any], incoming: Mapping[str, Any]
) -> dict[str, Any]:
    if _is_source_independent_call_graph_fingerprint_metadata(incoming):
        return {key: _deep_mutable_copy(value) for key, value in existing.items()}
    if _is_source_independent_call_graph_fingerprint_metadata(existing):
        return {key: _deep_mutable_copy(value) for key, value in incoming.items()}

    merged: dict[str, Any] = _deep_mutable_copy(existing)
    existing_fingerprints = existing.get("fingerprints")
    incoming_fingerprints = incoming.get("fingerprints")
    fingerprints = _deep_mutable_copy(existing_fingerprints) if isinstance(existing_fingerprints, Mapping) else {}
    fingerprint_conflict = False
    if isinstance(incoming_fingerprints, Mapping):
        for path, fingerprint in incoming_fingerprints.items():
            if path in fingerprints and fingerprints[path] != fingerprint:
                fingerprint_conflict = True
                continue
            fingerprints[path] = _deep_mutable_copy(fingerprint)
    merged["fingerprints"] = fingerprints

    existing_read_fingerprints = existing.get("read_fingerprints")
    incoming_read_fingerprints = incoming.get("read_fingerprints")
    read_fingerprints = (
        _deep_mutable_copy(existing_read_fingerprints) if isinstance(existing_read_fingerprints, Mapping) else {}
    )
    read_fingerprint_conflict = False
    if isinstance(incoming_read_fingerprints, Mapping):
        for path, fingerprint_record in incoming_read_fingerprints.items():
            if path in read_fingerprints and read_fingerprints[path] != fingerprint_record:
                read_fingerprint_conflict = True
                continue
            read_fingerprints[path] = _deep_mutable_copy(fingerprint_record)
    merged["read_fingerprints"] = read_fingerprints

    existing_module_sources = existing.get("module_sources")
    incoming_module_sources = incoming.get("module_sources")
    module_sources = _deep_mutable_copy(existing_module_sources) if isinstance(existing_module_sources, Mapping) else {}
    module_source_conflict = False
    if isinstance(incoming_module_sources, Mapping):
        for module_name, source_path in incoming_module_sources.items():
            if module_name in module_sources and module_sources[module_name] != source_path:
                module_source_conflict = True
                continue
            module_sources[module_name] = _deep_mutable_copy(source_path)
    merged["module_sources"] = module_sources

    existing_loaded_sources = existing.get("loaded_module_sources")
    incoming_loaded_sources = incoming.get("loaded_module_sources")
    loaded_sources = _deep_mutable_copy(existing_loaded_sources) if isinstance(existing_loaded_sources, Mapping) else {}
    loaded_source_conflict = False
    if isinstance(incoming_loaded_sources, Mapping):
        for module_name, source_path in incoming_loaded_sources.items():
            if module_name in loaded_sources and loaded_sources[module_name] != source_path:
                loaded_source_conflict = True
                continue
            loaded_sources[module_name] = _deep_mutable_copy(source_path)
    merged["loaded_module_sources"] = loaded_sources

    existing_loaded_package_paths = existing.get("loaded_package_paths")
    incoming_loaded_package_paths = incoming.get("loaded_package_paths")
    loaded_package_paths = (
        _deep_mutable_copy(existing_loaded_package_paths) if isinstance(existing_loaded_package_paths, Mapping) else {}
    )
    loaded_package_path_conflict = False
    if isinstance(incoming_loaded_package_paths, Mapping):
        for module_name, search_path in incoming_loaded_package_paths.items():
            if module_name in loaded_package_paths and loaded_package_paths[module_name] != search_path:
                loaded_package_path_conflict = True
                continue
            loaded_package_paths[module_name] = _deep_mutable_copy(search_path)
    merged["loaded_package_paths"] = loaded_package_paths

    existing_search_context = existing.get("search_context")
    incoming_search_context = incoming.get("search_context")
    existing_resolution_context = existing.get("resolution_context")
    incoming_resolution_context = incoming.get("resolution_context")
    if existing_search_context != incoming_search_context or existing_resolution_context != incoming_resolution_context:
        merged["reusable"] = False
    else:
        merged["reusable"] = (
            existing.get("reusable") is True
            and incoming.get("reusable") is True
            and not fingerprint_conflict
            and not read_fingerprint_conflict
            and not module_source_conflict
            and not loaded_source_conflict
            and not loaded_package_path_conflict
        )
        merged["search_context"] = existing_search_context
        merged["resolution_context"] = _deep_mutable_copy(existing_resolution_context)
    if (
        fingerprint_conflict
        or read_fingerprint_conflict
        or module_source_conflict
        or loaded_source_conflict
        or loaded_package_path_conflict
    ):
        merged["reusable"] = False

    return merged


_MAX_RAW_DETECTOR_FAILURES: Final[int] = 20


def scan_result_has_inconclusive_outcome(scan_result: "ScanResult") -> bool:
    """Return True when the scanner explicitly marked coverage as inconclusive."""
    return scan_result.metadata.get(SCAN_OUTCOME_METADATA_KEY) == INCONCLUSIVE_SCAN_OUTCOME


def mark_inconclusive_scan_result(scan_result: "ScanResult", reason: str) -> None:
    """Mark a scan result as inconclusive while preserving existing reasons."""
    scan_result.metadata["analysis_incomplete"] = True
    scan_result.metadata[SCAN_OUTCOME_METADATA_KEY] = INCONCLUSIVE_SCAN_OUTCOME
    scan_result.metadata.setdefault(
        SCAN_OUTCOME_MESSAGE_METADATA_KEY,
        "Scan analysis incomplete; failed closed because full coverage was not available.",
    )

    existing_reasons = scan_result.metadata.get(SCAN_OUTCOME_REASONS_METADATA_KEY)
    reasons = existing_reasons if isinstance(existing_reasons, list) else []
    if reason not in reasons:
        reasons.append(reason)
    scan_result.metadata[SCAN_OUTCOME_REASONS_METADATA_KEY] = reasons
    scan_result._refresh_metadata_dependent_state()


def normalize_unclassified_scan_failure(scan_result: "ScanResult") -> None:
    """Fail closed when a scanner reports success=False without explicit outcome metadata."""
    if scan_result.success:
        return
    if bool(scan_result.metadata.get(OPERATIONAL_ERROR_METADATA_KEY)):
        return
    if scan_result_has_inconclusive_outcome(scan_result):
        return
    mark_inconclusive_scan_result(scan_result, UNCLASSIFIED_SCAN_FAILURE_REASON)


class IssueSeverity(Enum):
    """Enum for issue severity levels"""

    DEBUG = "debug"  # Debug information
    INFO = "info"  # Informational, not a security concern
    WARNING = "warning"  # Potential issue, needs review
    CRITICAL = "critical"  # Definite security concern


class CheckStatus(Enum):
    """Enum for check status"""

    PASSED = "passed"  # Check passed successfully
    FAILED = "failed"  # Check failed (issue found)
    SKIPPED = "skipped"  # Check was skipped


class Check(BaseModel):
    """Pydantic model representing a single security check performed during scanning"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow extra fields for extensibility
    )

    name: str = Field(..., description="Name of the check performed")
    status: CheckStatus = Field(..., description="Whether the check passed or failed")
    message: str = Field(..., description="Description of what was checked")
    severity: IssueSeverity | None = Field(None, description="Severity (only for failed checks)")
    location: str | None = Field(None, description="File position, line number, etc.")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional check details")
    why: str | None = Field(None, description="Explanation (mainly for failed checks)")
    rule_code: str | None = Field(default=None, description="Rule code associated with this check")
    timestamp: float = Field(default_factory=time.time, description="Timestamp when check was performed")

    @field_serializer("status")
    def serialize_status(self, status: CheckStatus) -> str:
        """Serialize status enum to string value"""
        return status.value

    @field_serializer("severity")
    def serialize_severity(self, severity: IssueSeverity | None) -> str | None:
        """Serialize severity enum to string value"""
        return severity.value if severity else None

    def to_dict(self) -> dict[str, Any]:
        """Convert the check to a dictionary for serialization (backward compatibility)"""
        return self.model_dump(exclude_none=True, mode="json")

    def __str__(self) -> str:
        """String representation of the check"""
        status_symbol = "✓" if self.status == CheckStatus.PASSED else "✗"
        prefix = f"[{status_symbol}] {self.name}"
        if self.rule_code:
            prefix = f"[{self.rule_code}] {prefix}"
        if self.location:
            prefix += f" ({self.location})"
        return f"{prefix}: {self.message}"


class Issue(BaseModel):
    """Pydantic model representing a single issue found during scanning"""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",  # Allow extra fields for extensibility
    )

    message: str = Field(..., description="Description of the issue")
    severity: IssueSeverity = Field(default=IssueSeverity.WARNING, description="Issue severity level")
    location: str | None = Field(None, description="File position, line number, etc.")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details about the issue")
    why: str | None = Field(None, description="Explanation of why this is a security concern")
    timestamp: float = Field(default_factory=time.time, description="Timestamp when issue was detected")
    type: str | None = Field(None, description="Type of issue for categorization")
    rule_code: str | None = Field(default=None, description="Rule code associated with this issue")

    @field_serializer("severity")
    def serialize_severity(self, severity: IssueSeverity) -> str:
        """Serialize severity enum to string value"""
        return severity.value

    def to_dict(self) -> dict[str, Any]:
        """Convert the issue to a dictionary for serialization (backward compatibility)"""
        return self.model_dump(exclude_none=True, mode="json")

    def __str__(self) -> str:
        """String representation of the issue"""
        severity_str = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        prefix = f"[{severity_str.upper()}]"
        if self.rule_code:
            prefix = f"[{self.rule_code}] {prefix}"
        if self.location:
            prefix += f" ({self.location})"
        return f"{prefix}: {self.message}"


class ScanResult:
    """Collects and manages issues found during scanning"""

    def __init__(self, scanner_name: str = "unknown", scanner: Any | None = None):
        self.scanner_name = scanner_name
        self.scanner = scanner  # Reference to the scanner for whitelist checks
        self.issues: list[Issue] = []
        self.checks: list[Check] = []  # All checks performed (passed and failed)
        self.start_time = time.time()
        self.end_time: float | None = None
        self.bytes_scanned: int = 0
        self.success: bool = True
        self.metadata: dict[str, Any] = {
            SCANNER_DEPENDENCY_IDS_METADATA_KEY: [scanner_name],
        }
        self._private_metadata: dict[str, Any] = {}
        self._metadata_restored_critical: bool = False
        self._merged_children_success: bool = True

    def add_check(
        self,
        name: str,
        passed: bool,
        message: str,
        severity: IssueSeverity | None = None,
        location: str | None = None,
        details: dict[str, Any] | None = None,
        why: str | None = None,
        rule_code: str | None = None,
    ) -> None:
        """Add a check result (passed or failed) with rule support and rule-based severity."""
        from .config import get_config
        from .config.explanations import get_message_explanation
        from .rules import RuleRegistry, Severity

        severity_map = {
            Severity.CRITICAL: IssueSeverity.CRITICAL,
            Severity.HIGH: IssueSeverity.CRITICAL,
            Severity.MEDIUM: IssueSeverity.WARNING,
            Severity.LOW: IssueSeverity.INFO,
            Severity.INFO: IssueSeverity.INFO,
        }

        # Auto-detect rule code if not provided.
        # Preserve scanner-provided severity semantics by only attaching the
        # code here, not remapping severity from rule defaults.
        if not rule_code and not passed:
            match = RuleRegistry.find_matching_rule(message)
            if match:
                rule_code, _rule = match

        config = get_config()

        # Check if rule is suppressed
        if rule_code and config.is_suppressed(rule_code, location):
            # Messages can include matched secrets or attacker-controlled model content.
            logger.debug("Suppressed security finding")
            return

        # Apply severity override only when explicitly configured by the user.
        if rule_code and rule_code in config.severity:
            configured_severity = config.get_severity(rule_code, Severity.MEDIUM)
            mapped = severity_map.get(configured_severity)
            if mapped is not None:
                severity = mapped

        status = CheckStatus.PASSED if passed else CheckStatus.FAILED

        # For failed checks, ensure we have a severity
        if not passed and severity is None:
            severity = IssueSeverity.WARNING

        # Apply whitelist downgrading logic for failed checks if scanner is available
        if not passed and self.scanner:
            # At this point severity cannot be None due to the check above
            assert severity is not None
            severity, details = self.scanner._apply_whitelist_downgrade(
                severity,
                details,
                result_metadata=self.metadata,
                message=message,
                rule_code=rule_code,
                check_name=name,
            )

        check = Check(
            name=name,
            status=status,
            message=message,
            severity=severity,
            location=location,
            details=details or {},
            why=why,
            rule_code=rule_code,
        )
        self.checks.append(check)

        # If the check failed, also add it as an issue for backward compatibility
        if not passed:
            if why is None:
                why = get_message_explanation(message, context=self.scanner_name)
            # Severity should never be None here due to check above, but add assertion for type checker
            assert severity is not None

            # Note: whitelist downgrading was already applied above (lines 160-163)
            # before creating the Check, so we use the same downgraded severity here

            issue = Issue(
                message=message,
                severity=severity,
                location=location,
                details=details or {},
                why=why,
                type=f"{self.scanner_name}_check",
                rule_code=rule_code,
            )
            self.issues.append(issue)

            log_level = (
                logging.CRITICAL
                if severity == IssueSeverity.CRITICAL
                else (
                    logging.WARNING
                    if severity == IssueSeverity.WARNING
                    else (logging.INFO if severity == IssueSeverity.INFO else logging.DEBUG)
                )
            )
            logger.log(log_level, "Security finding recorded")
        else:
            # Log successful checks at DEBUG level
            logger.debug("Security check passed")

    def _add_issue(
        self,
        message: str,
        severity: IssueSeverity = IssueSeverity.WARNING,
        location: str | None = None,
        details: dict[str, Any] | None = None,
        why: str | None = None,
        rule_code: str | None = None,
    ) -> None:
        """Add an issue to the result with rule support"""
        # For backward compatibility: INFO/DEBUG severities are treated as passing checks
        passed = severity in (IssueSeverity.DEBUG, IssueSeverity.INFO)
        self.add_check(
            name="Legacy Security Check",
            passed=passed,
            message=message,
            severity=severity,
            location=location,
            details=details,
            why=why,
            rule_code=rule_code,
        )
        if passed:
            return

    def add_issue(
        self,
        message: str,
        severity: IssueSeverity = IssueSeverity.WARNING,
        location: str | None = None,
        details: dict[str, Any] | None = None,
        why: str | None = None,
        rule_code: str | None = None,
    ) -> None:
        """Backward-compatible public issue adder."""
        self._add_issue(message, severity=severity, location=location, details=details, why=why, rule_code=rule_code)

    def reconcile_raw_detector_checks(self) -> None:
        """Reconcile clean and coverage checks after raw-detector result aggregation."""
        failed_detectors = self.metadata.get(RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY)
        failed_clean_checks: set[str] = set()
        if isinstance(failed_detectors, list):
            clean_check_names = {
                "embedded_secrets": {"Embedded Secrets Detection"},
                "jit_script": {"JIT/Script Code Execution Detection", "JIT/Script Code Execution Summary"},
                "network_communication": {"Network Communication Detection", "Network Communication Summary"},
            }
            failed_clean_checks = {
                check_name for detector in failed_detectors for check_name in clean_check_names.get(detector, set())
            }

        seen_coverage_detectors: set[str] = set()
        reconciled_checks: list[Check] = []
        for check in self.checks:
            if check.name in failed_clean_checks and check.status == CheckStatus.PASSED:
                continue
            detector = check.details.get("detector")
            if (
                check.name == "Raw Detector Analysis Coverage"
                and check.details.get("scan_outcome_reason") == RAW_DETECTOR_ANALYSIS_INCOMPLETE_REASON
                and isinstance(detector, str)
            ):
                if detector in seen_coverage_detectors:
                    continue
                seen_coverage_detectors.add(detector)
            reconciled_checks.append(check)
        self.checks = reconciled_checks

        seen_issue_detectors: set[str] = set()
        reconciled_issues: list[Issue] = []
        for issue in self.issues:
            detector = issue.details.get("detector")
            if issue.details.get("scan_outcome_reason") == RAW_DETECTOR_ANALYSIS_INCOMPLETE_REASON and isinstance(
                detector, str
            ):
                if detector in seen_issue_detectors:
                    continue
                seen_issue_detectors.add(detector)
            reconciled_issues.append(issue)
        self.issues = reconciled_issues

    def remove_failed_raw_detector_clean_checks(self) -> None:
        """Backward-compatible wrapper for raw-detector check reconciliation."""
        self.reconcile_raw_detector_checks()

    def _ensure_member_file_hash_state(self) -> tuple[dict[str, int], int]:
        occurrences = self._private_metadata.get(_MEMBER_FILE_HASH_OCCURRENCES_PRIVATE_KEY)
        stored_count = self._private_metadata.get(_MEMBER_FILE_HASH_STORED_COUNT_PRIVATE_KEY)
        if isinstance(occurrences, dict) and isinstance(stored_count, int):
            return occurrences, stored_count

        occurrences = {}
        raw_member_hashes = self.metadata.get(MEMBER_FILE_HASHES_METADATA_KEY)
        if isinstance(raw_member_hashes, Mapping):
            for member_key, record in raw_member_hashes.items():
                if not isinstance(member_key, str) or not isinstance(record, Mapping):
                    continue
                path_segments = _member_path_segments_from_record(member_key, record)
                path_key = _member_path_segments_key(path_segments)
                occurrences[path_key] = max(occurrences.get(path_key, 0), _member_occurrence_from_record(record))
            stored_count = len(raw_member_hashes)
        else:
            stored_count = 0

        self._private_metadata[_MEMBER_FILE_HASH_OCCURRENCES_PRIVATE_KEY] = occurrences
        self._private_metadata[_MEMBER_FILE_HASH_STORED_COUNT_PRIVATE_KEY] = stored_count
        return occurrences, stored_count

    def _record_member_file_hash_omission(self, omitted_count: int = 1) -> None:
        if omitted_count <= 0:
            return
        self.metadata[MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY] = True
        existing_omitted = self.metadata.get(MEMBER_FILE_HASHES_OMITTED_METADATA_KEY)
        self.metadata[MEMBER_FILE_HASHES_OMITTED_METADATA_KEY] = (
            existing_omitted if isinstance(existing_omitted, int) and not isinstance(existing_omitted, bool) else 0
        ) + omitted_count

    def _add_member_file_hash_record(self, path_segments: list[str], record: Mapping[str, Any]) -> None:
        member_hashes = self.metadata.setdefault(MEMBER_FILE_HASHES_METADATA_KEY, {})
        if not isinstance(member_hashes, dict):
            member_hashes = {}
            self.metadata[MEMBER_FILE_HASHES_METADATA_KEY] = member_hashes

        occurrences, stored_count = self._ensure_member_file_hash_state()
        normalized_segments = [str(segment) for segment in path_segments]
        path_key = _member_path_segments_key(normalized_segments)
        occurrence = occurrences.get(path_key, 0) + 1
        occurrences[path_key] = occurrence

        existing_total = self.metadata.get(MEMBER_FILE_HASHES_TOTAL_METADATA_KEY)
        self.metadata[MEMBER_FILE_HASHES_TOTAL_METADATA_KEY] = (
            existing_total if isinstance(existing_total, int) and not isinstance(existing_total, bool) else stored_count
        ) + 1

        if stored_count >= MAX_MEMBER_FILE_HASH_RECORDS:
            self._record_member_file_hash_omission()
            return

        stored_record = _deep_mutable_copy(record)
        stored_record["path_segments"] = normalized_segments
        stored_record["logical_path"] = _logical_member_path(normalized_segments)
        stored_record["occurrence"] = occurrence
        member_hashes[_member_file_hash_identity_key(normalized_segments, occurrence)] = stored_record
        self._private_metadata[_MEMBER_FILE_HASH_STORED_COUNT_PRIVATE_KEY] = stored_count + 1

    def _absorb_member_file_hash_summary(self, metadata: Mapping[str, Any]) -> None:
        omitted = metadata.get(MEMBER_FILE_HASHES_OMITTED_METADATA_KEY)
        if isinstance(omitted, int) and omitted > 0 and not isinstance(omitted, bool):
            existing_total = self.metadata.get(MEMBER_FILE_HASHES_TOTAL_METADATA_KEY)
            self.metadata[MEMBER_FILE_HASHES_TOTAL_METADATA_KEY] = (
                existing_total if isinstance(existing_total, int) and not isinstance(existing_total, bool) else 0
            ) + omitted
            self._record_member_file_hash_omission(omitted)

    def _merge_member_file_hash_records(self, records: Mapping[str, Any]) -> None:
        sortable_records: list[tuple[str, int, str, list[str], Mapping[str, Any]]] = []
        for member_key, record in records.items():
            if not isinstance(member_key, str) or not isinstance(record, Mapping):
                continue
            path_segments = _member_path_segments_from_record(member_key, record)
            sortable_records.append(
                (
                    _member_path_segments_key(path_segments),
                    _member_occurrence_from_record(record),
                    member_key,
                    path_segments,
                    record,
                )
            )
        for _, _, _, path_segments, record in sorted(sortable_records):
            self._add_member_file_hash_record(path_segments, record)

    def merge_member_result(self, other: "ScanResult", member_path: str) -> None:
        """Merge an archive-member scan without letting member hashes become parent hashes."""
        parent_identity = {
            key: _deep_mutable_copy(self.metadata[key])
            for key in _PARENT_INTEGRITY_METADATA_KEYS
            if key in self.metadata
        }
        child_integrity_record = _member_file_hashes_from_metadata(other.metadata, other.scanner_name)
        child_member_hashes = _iter_child_member_file_hash_records(other.metadata)

        missing = object()
        other_member_hashes = other.metadata.pop(MEMBER_FILE_HASHES_METADATA_KEY, missing)
        other_summary_values = {
            key: other.metadata.pop(key, missing) for key in _MEMBER_FILE_HASH_SUMMARY_METADATA_KEYS
        }
        try:
            self.merge(other)
        finally:
            if other_member_hashes is not missing:
                other.metadata[MEMBER_FILE_HASHES_METADATA_KEY] = other_member_hashes
            for key, value in other_summary_values.items():
                if value is not missing:
                    other.metadata[key] = value

        for key in _PARENT_INTEGRITY_METADATA_KEYS:
            if key in parent_identity:
                self.metadata[key] = _deep_mutable_copy(parent_identity[key])
            else:
                self.metadata.pop(key, None)

        if child_integrity_record is not None:
            self._add_member_file_hash_record([member_path], child_integrity_record)
        for child_segments, record in child_member_hashes:
            self._add_member_file_hash_record([member_path, *child_segments], record)
        summary_metadata = {key: value for key, value in other_summary_values.items() if value is not missing}
        self._absorb_member_file_hash_summary(summary_metadata)

    def merge(self, other: "ScanResult") -> None:
        """Merge another scan result into this one"""
        self.issues.extend(other.issues)
        self.checks.extend(other.checks)  # Merge checks as well
        self.bytes_scanned += other.bytes_scanned
        self._merged_children_success = self._merged_children_success and other.success
        self.success = self.success and other.success
        # Merge metadata dictionaries
        list_union_metadata_keys = {
            RAW_DETECTOR_FAILURES_METADATA_KEY,
            RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY,
            SCAN_OUTCOME_REASONS_METADATA_KEY,
            SCANNER_DEPENDENCY_IDS_METADATA_KEY,
            "skipped_scanner_ids",
        }
        for key, value in other.metadata.items():
            if (
                key == CALL_GRAPH_SOURCE_FINGERPRINTS_METADATA_KEY
                and isinstance(self._private_metadata.get(key), Mapping)
                and isinstance(value, Mapping)
            ):
                self._private_metadata[key] = _merge_call_graph_source_fingerprints_metadata(
                    self._private_metadata[key], value
                )
                continue
            if key == CALL_GRAPH_SOURCE_FINGERPRINTS_METADATA_KEY and isinstance(value, Mapping):
                self._private_metadata[key] = _deep_mutable_copy(value)
                continue
            if key in list_union_metadata_keys and isinstance(self.metadata.get(key), list) and isinstance(value, list):
                existing_values = self.metadata[key]
                for item in value:
                    if key == RAW_DETECTOR_FAILURES_METADATA_KEY and len(existing_values) >= _MAX_RAW_DETECTOR_FAILURES:
                        break
                    if item not in existing_values:
                        existing_values.append(item)
                if key == RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY:
                    existing_values.sort(key=str)
                continue
            if key == RAW_DETECTOR_FAILURES_METADATA_KEY and isinstance(value, list):
                bounded_failures: list[Any] = []
                for item in value:
                    if item not in bounded_failures:
                        bounded_failures.append(item)
                    if len(bounded_failures) >= _MAX_RAW_DETECTOR_FAILURES:
                        break
                self.metadata[key] = bounded_failures
                continue
            if key == RAW_DETECTOR_FAILED_DETECTORS_METADATA_KEY and isinstance(value, list):
                self.metadata[key] = sorted({item for item in value if isinstance(item, str)})
                continue
            if key == MEMBER_FILE_HASHES_METADATA_KEY and isinstance(value, Mapping):
                self._merge_member_file_hash_records(value)
                continue
            if key == MEMBER_FILE_HASHES_OMITTED_METADATA_KEY:
                self._absorb_member_file_hash_summary({key: value})
                continue
            if key == MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY and value is True:
                self.metadata[MEMBER_FILE_HASHES_TRUNCATED_METADATA_KEY] = True
                continue
            if key == MEMBER_FILE_HASHES_TOTAL_METADATA_KEY and isinstance(value, int) and not isinstance(value, bool):
                continue
            if key in self.metadata and isinstance(self.metadata[key], dict) and isinstance(value, dict):
                self.metadata[key].update(value)
            else:
                self.metadata[key] = value
        for key, value in other._private_metadata.items():
            if key in _MEMBER_FILE_HASH_PRIVATE_METADATA_KEYS:
                continue
            if (
                key == CALL_GRAPH_SOURCE_FINGERPRINTS_METADATA_KEY
                and isinstance(self._private_metadata.get(key), Mapping)
                and isinstance(value, Mapping)
            ):
                self._private_metadata[key] = _merge_call_graph_source_fingerprints_metadata(
                    self._private_metadata[key], value
                )
            else:
                self._private_metadata[key] = _deep_mutable_copy(value)
        self.reconcile_raw_detector_checks()

    def trust_merged_child_failures(self) -> None:
        """Allow a parent scanner to explicitly accept child failures it has reclassified as benign."""
        self._merged_children_success = True

    def finish(self, success: bool = True) -> None:
        """Mark the scan as finished"""
        restored_critical = self._restore_result_metadata_whitelist_downgrades()
        self.end_time = time.time()
        self.success = success and self._merged_children_success
        if (restored_critical or self._metadata_restored_critical) and self.has_errors:
            self.success = False

    @staticmethod
    def _severity_from_original_whitelist_value(value: Any) -> IssueSeverity | None:
        if isinstance(value, IssueSeverity):
            return value
        if not isinstance(value, str):
            return None
        try:
            return IssueSeverity[value]
        except KeyError:
            try:
                return IssueSeverity(value.lower())
            except ValueError:
                return None

    def _restore_result_metadata_whitelist_downgrades(self) -> bool:
        """Restore downgraded severities when result metadata later marks incomplete coverage."""
        metadata_exempt = getattr(self.scanner, "_result_metadata_whitelist_downgrade_exempt", None)
        if not callable(metadata_exempt) or not metadata_exempt(self.metadata):
            return False

        restored_critical = False

        def restore_finding(finding: Check | Issue) -> None:
            nonlocal restored_critical
            if finding.details.get("whitelist_downgrade") is not True:
                return
            original_severity = self._severity_from_original_whitelist_value(finding.details.get("original_severity"))
            if original_severity is None:
                return
            finding.severity = original_severity
            finding.details.pop("whitelist_downgrade", None)
            finding.details["whitelist_downgrade_restored"] = True
            if original_severity == IssueSeverity.CRITICAL:
                restored_critical = True

        for check in self.checks:
            restore_finding(check)
        for issue in self.issues:
            restore_finding(issue)
        if restored_critical:
            self._metadata_restored_critical = True
        return restored_critical

    def _refresh_metadata_dependent_state(self) -> None:
        """Reconcile severities and success after metadata changes outside finish()."""
        restored_critical = self._restore_result_metadata_whitelist_downgrades()
        if self.end_time is not None and restored_critical and self.has_errors:
            self.success = False

    @property
    def duration(self) -> float:
        """Return the duration of the scan in seconds"""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    @property
    def has_errors(self) -> bool:
        """Return True if there are any critical-level issues"""
        return any(issue.severity == IssueSeverity.CRITICAL for issue in self.issues)

    @property
    def has_warnings(self) -> bool:
        """Return True if there are any warning-level issues"""
        return any(issue.severity == IssueSeverity.WARNING for issue in self.issues)

    def to_dict(self, *, include_private_metadata: bool = False) -> dict[str, Any]:
        """Convert the scan result to a dictionary for serialization"""
        # Only count WARNING and CRITICAL severity checks as failures
        # INFO and DEBUG are informational - they should not count as failures
        failed_checks_count = sum(
            1
            for c in self.checks
            if c.status == CheckStatus.FAILED and c.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        )

        result = {
            "scanner": self.scanner_name,
            "success": self.success,
            "duration": self.duration,
            "bytes_scanned": self.bytes_scanned,
            "issues": [issue.to_dict() for issue in self.issues],
            "checks": [check.to_dict() for check in self.checks],  # Include all checks
            "metadata": self.metadata,
            "has_errors": self.has_errors,
            "has_warnings": self.has_warnings,
            "total_checks": len(self.checks),
            "passed_checks": sum(1 for c in self.checks if c.status == CheckStatus.PASSED),
            "failed_checks": failed_checks_count,
        }
        if include_private_metadata and self._private_metadata:
            result["_private_metadata"] = _deep_mutable_copy(self._private_metadata)
        return result

    def to_json(self, indent: int = 2) -> str:
        """Convert the scan result to a JSON string"""
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """Return a human-readable summary of the scan result"""
        error_count = sum(1 for issue in self.issues if issue.severity == IssueSeverity.CRITICAL)
        warning_count = sum(1 for issue in self.issues if issue.severity == IssueSeverity.WARNING)
        info_count = sum(1 for issue in self.issues if issue.severity == IssueSeverity.INFO)

        result = []
        result.append(f"Scan completed in {self.duration:.2f}s")
        result.append(
            f"Scanned {self.bytes_scanned} bytes with scanner '{self.scanner_name}'",
        )
        result.append(
            f"Found {len(self.issues)} issues ({error_count} critical, {warning_count} warnings, {info_count} info)",
        )

        # If there are any issues, show them
        if self.issues:
            result.append("\nIssues:")
            for issue in self.issues:
                result.append(f"  {issue}")

        return "\n".join(result)

    def __str__(self) -> str:
        """String representation of the scan result"""
        return self.summary()
