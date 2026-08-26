"""
Security Asset Integration Tests

Tests that integrate with the organized test asset structure.
Focuses on security-specific scanning scenarios.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import metadata_has_coverage_only_operational_error
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import Check, CheckStatus, Issue
from modelaudit.scanners.base import IssueSeverity

EXPECTED_UNAVAILABLE_SCANNER_MESSAGE = "Recognized format could not be scanned because no scanner was available"
OPERATIONAL_FAILURE_REASON_SUFFIXES = ("_failed", "_error", "_exceeded", "_timeout", "_interrupted")
EXPECTED_AGPL_SOURCE_STABILITY_ASSET = (
    Path(__file__).parent / "assets" / "scenarios" / "license_scenarios" / "agpl_component" / "agpl_model.pkl"
).resolve()
EXPECTED_AGPL_SOURCE_STABILITY_REASON = "source_search_context_changed"
EXPECTED_AGPL_SOURCE_STABILITY_OUTCOME_REASONS = frozenset(
    {
        "call_graph_analysis_error",
        "flax_msgpack_routing_incomplete",
        "nested_pickle_incomplete",
        "nested_probe_limit",
    }
)
EXPECTED_DEPENDENCY_OUTCOMES = {
    "defusedxml": frozenset({"pmml_safe_xml_parser_unavailable"}),
    "h5py": frozenset(
        {
            "keras_h5_h5py_unavailable",
            "keras_zip_embedded_weights_h5py_unavailable",
            "keras_zip_embedded_weights_hdf5_signature_probe_incomplete",
        }
    ),
    "onnx": frozenset(
        {
            "onnx_dependency_unavailable",
            "onnx_tentative_candidate_analysis_unavailable",
        }
    ),
    "py7zr": frozenset({"sevenzip_analysis_incomplete"}),
    "tflite": frozenset({"tflite_dependency_unavailable"}),
    "ubjson": frozenset({"xgboost_ubj_dependency_missing"}),
    "xgboost": frozenset({"xgboost_binary_load_dependency_missing"}),
}
EXPECTED_DEPENDENCY_OUTCOME_REASONS = frozenset(
    reason for outcomes in EXPECTED_DEPENDENCY_OUTCOMES.values() for reason in outcomes
)
EXPECTED_COVERAGE_AGGREGATION_OUTCOME_REASONS = frozenset({"zip_analysis_incomplete"})
EXPECTED_SECURITY_FINDING_OUTCOME_REASONS = frozenset({"nested_pickle_incomplete", "nested_probe_limit"})
EXPECTED_SECURITY_FINDING_OUTCOME_MESSAGES = {
    "nested_pickle_incomplete": "Nested pickle analysis did not complete",
    "nested_probe_limit": "Nested pickle probe candidate limit exceeded",
}
EXPECTED_PICKLE_INCOMPLETE_MESSAGES = frozenset(
    {
        "Nested pickle analysis did not complete",
        "Nested pickle payload exceeds deep-scan byte limit",
        "Nested pickle probe candidate limit exceeded",
    }
)
EXPECTED_DEPENDENCY_MESSAGE_MARKERS = {
    "defusedxml": ("defusedxml is unavailable",),
    "h5py": ("h5py is required", "h5py is unavailable"),
    "onnx": ("onnx analysis dependency is unavailable",),
    "py7zr": ("py7zr library not installed", "py7zr package is not installed"),
    "tflite": ("tflite package not installed",),
    "ubjson": ("ubjson package is not installed",),
    "xgboost": ("xgboost library not available",),
}


def describe_operational_errors(results: ModelAuditResultModel) -> str:
    """Summarize which files carried operational errors, for assertion messages.

    ``has_errors`` alone truncates to an unhelpful model repr in CI logs, which
    hides whichever file actually failed. Naming the paths and reasons keeps a
    recurrence diagnosable from the log without a Windows reproduction.
    """
    offenders = []
    for path, metadata in results.file_metadata.items():
        dump = getattr(metadata, "model_dump", None)
        payload = dump() if callable(dump) else metadata
        if not isinstance(payload, dict) or not payload.get("operational_error"):
            continue
        offenders.append(f"{path}: {payload.get('operational_error_reason', 'unknown reason')}")
    return "; ".join(sorted(offenders)) or "no per-file operational_error metadata recorded"


def _nested_diagnostic_details(details: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    pending = [details]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        normalized.append(current)

        nested_details = current.get("details")
        if isinstance(nested_details, dict):
            pending.append(nested_details)
        nested_findings = current.get("findings")
        if isinstance(nested_findings, dict):
            pending.append(nested_findings)
        elif isinstance(nested_findings, (list, tuple, set, frozenset)):
            pending.extend(finding for finding in nested_findings if isinstance(finding, dict))
    return normalized


def _is_expected_missing_dependency_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
    metadata: dict[str, Any] | None,
) -> bool:
    required_package = details.get("required_package")
    error_type = details.get("error_type")
    if not isinstance(required_package, str) or not required_package.strip():
        return False
    normalized_package = required_package.strip().casefold().replace("-", "_")
    message = diagnostic.message
    message_markers = EXPECTED_DEPENDENCY_MESSAGE_MARKERS.get(normalized_package, ())
    if not (
        isinstance(message, str) and message.strip() and any(marker in message.casefold() for marker in message_markers)
    ):
        return False
    if not isinstance(metadata, dict):
        return False
    scan_outcome_reasons = metadata.get("scan_outcome_reasons")
    tentative_onnx_candidate = (
        normalized_package == "onnx"
        and metadata.get("tentative_protobuf_candidate_unanalyzed") == "onnx_dependency_unavailable"
        and scan_outcome_reasons == ["onnx_tentative_candidate_analysis_unavailable"]
    )
    if not (
        (metadata.get("analysis_incomplete") is True or tentative_onnx_candidate)
        and metadata.get("scan_outcome") == "inconclusive"
        and isinstance(scan_outcome_reasons, list)
        and bool(scan_outcome_reasons)
        and all(isinstance(reason, str) and bool(reason) for reason in scan_outcome_reasons)
    ):
        return False
    expected_reasons = EXPECTED_DEPENDENCY_OUTCOMES.get(normalized_package, frozenset())
    detail_reason = details.get("scan_outcome_reason")
    if detail_reason is not None and (
        not isinstance(detail_reason, str)
        or not detail_reason
        or detail_reason not in scan_outcome_reasons
        or detail_reason not in expected_reasons
    ):
        return False
    return (
        (not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED)
        and bool(expected_reasons.intersection(scan_outcome_reasons))
        and "error" not in details
        and "exception" not in details
        and "exception_type" not in details
        and (error_type is None or error_type == "missing_dependency")
        and "operational_error" not in details
        and "interrupted" not in details
    )


def _file_metadata_for_diagnostic(
    results: ModelAuditResultModel,
    location: str,
) -> tuple[str, dict[str, Any]] | None:
    matching_paths = [path for path in results.file_metadata if location == path or location.startswith(f"{path}:")]
    if not matching_paths:
        return None
    owner_path = max(matching_paths, key=len)
    metadata = results.file_metadata[owner_path]
    return owner_path, metadata.model_dump(exclude_none=True)


def _expected_security_outcome_reason(
    diagnostic: Issue | Check,
    details: dict[str, Any],
) -> str | None:
    notice_code = details.get("notice_code")
    if notice_code not in EXPECTED_SECURITY_FINDING_OUTCOME_REASONS:
        notice_code = details.get("pickle_notice_code")
    if not isinstance(notice_code, str):
        return None
    expected_message = EXPECTED_SECURITY_FINDING_OUTCOME_MESSAGES.get(notice_code)
    diagnostic_is_failed = not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED
    if (
        diagnostic_is_failed
        and expected_message is not None
        and diagnostic.message == expected_message
        and details.get("analysis_incomplete") is True
        and isinstance(details.get("pickle_source"), str)
        and isinstance(diagnostic.location, str)
    ):
        return notice_code
    return None


def _is_expected_pickle_incomplete_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
) -> bool:
    if not (
        (not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED)
        and diagnostic.message in EXPECTED_PICKLE_INCOMPLETE_MESSAGES
        and details.get("analysis_incomplete") is True
        and isinstance(details.get("pickle_source"), str)
    ):
        return False
    if diagnostic.message == "Nested pickle analysis did not complete":
        return details.get("nested_status") == "inconclusive" and isinstance(details.get("nested_encoding"), str)
    if diagnostic.message == "Nested pickle payload exceeds deep-scan byte limit":
        return (
            isinstance(details.get("encoding"), str)
            and isinstance(details.get("max_nested_pickle_bytes"), int)
            and details.get("nested_has_execution_opcode") is True
        )
    return isinstance(details.get("encoding"), str) and isinstance(details.get("max_nested_payload_probes"), int)


def _is_expected_call_graph_source_unavailable_diagnostic(
    diagnostic: Issue | Check,
    details: dict[str, Any],
) -> bool:
    return (
        isinstance(diagnostic, Check)
        and diagnostic.status == CheckStatus.PASSED
        and diagnostic.message == "Python call-graph analysis could not inspect invoked callable source"
        and details.get("notice_code") == "call_graph_source_unavailable"
        and details.get("pickle_notice_code") == "call_graph_source_unavailable"
        and details.get("reason") == "source_unavailable"
        and details.get("analysis_incomplete") is True
        and isinstance(details.get("pickle_source"), str)
    )


def assert_no_unexpected_asset_scan_errors(results: ModelAuditResultModel, scan_description: str) -> None:
    expected_source_changes = set()
    expected_dependency_outcomes: set[tuple[str, str]] = set()
    dependency_incomplete_paths: set[str] = set()
    security_incomplete_paths: set[str] = set()
    security_finding_locations = {
        issue.location for issue in results.issues if issue.rule_code == "S204" and issue.location is not None
    }
    actionable_security_finding_locations = {
        issue.location
        for issue in results.issues
        if issue.severity == IssueSeverity.CRITICAL and issue.location is not None
    }
    root_diagnostics: list[Issue | Check] = [*results.issues, *results.checks]
    diagnostics = [
        (diagnostic, details)
        for diagnostic in root_diagnostics
        for details in _nested_diagnostic_details(diagnostic.details)
    ]
    security_outcome_diagnostics: set[tuple[str, str, str]] = set()
    for diagnostic, details in diagnostics:
        notice_code = _expected_security_outcome_reason(diagnostic, details)
        pickle_source = details.get("pickle_source")
        location = diagnostic.location
        if notice_code is not None and isinstance(pickle_source, str) and isinstance(location, str):
            security_outcome_diagnostics.add((pickle_source, location, notice_code))
    coverage_only_paths = set()
    unavailable_scanner_paths = set()
    diagnosed_dependency_outcomes: set[tuple[str, str]] = set()
    unexpected_errors = {asset.path for asset in results.assets if asset.type == "error"}
    for path, metadata in results.file_metadata.items():
        payload = metadata.model_dump(exclude_none=True)
        scan_outcome_reasons = payload.get("scan_outcome_reasons")
        if scan_outcome_reasons is None:
            if payload.get("analysis_incomplete") is True or payload.get("scan_outcome") == "inconclusive":
                unexpected_errors.add(path)
        else:
            if (
                not isinstance(scan_outcome_reasons, list)
                or not scan_outcome_reasons
                or not all(isinstance(reason, str) and bool(reason) for reason in scan_outcome_reasons)
            ):
                unexpected_errors.add(path)
                continue
            string_reasons = set(scan_outcome_reasons)
            dependency_reasons = string_reasons.intersection(EXPECTED_DEPENDENCY_OUTCOME_REASONS)
            coverage_reasons = {
                reason
                for reason in string_reasons
                if metadata_has_coverage_only_operational_error(
                    {"operational_error": True, "operational_error_reason": reason}
                )
            }
            if metadata_has_coverage_only_operational_error(payload):
                coverage_reasons.update(string_reasons.intersection(EXPECTED_COVERAGE_AGGREGATION_OUTCOME_REASONS))
            path_has_actionable_security_finding = any(
                finding_location == path
                or finding_location.startswith(f"{path} (")
                or finding_location.startswith(f"{path}:")
                for finding_location in actionable_security_finding_locations
            )
            diagnosed_security_reasons = {
                reason
                for pickle_source, diagnostic_location, reason in security_outcome_diagnostics
                if (
                    pickle_source == path
                    or pickle_source.startswith(f"{path} (")
                    or pickle_source.startswith(f"{path}:")
                )
                and (
                    diagnostic_location == path
                    or diagnostic_location.startswith(f"{path} (")
                    or diagnostic_location.startswith(f"{path}:")
                )
            }
            security_reasons = string_reasons.intersection(EXPECTED_SECURITY_FINDING_OUTCOME_REASONS)
            if security_reasons and not (
                payload.get("analysis_incomplete") is True
                and payload.get("scan_outcome") == "inconclusive"
                and payload.get("pickle_report_status") == "inconclusive"
                and payload.get("pickle_verdict") == "malicious"
                and path_has_actionable_security_finding
                and security_reasons <= diagnosed_security_reasons
            ):
                security_reasons = set()
            allowed_reasons = dependency_reasons | coverage_reasons | security_reasons
            if Path(path).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET:
                allowed_reasons.update(string_reasons.intersection({"call_graph_analysis_error"}))
            if string_reasons - allowed_reasons:
                unexpected_errors.add(path)
            if dependency_reasons:
                dependency_incomplete_paths.add(path)
                expected_dependency_outcomes.update((path, reason) for reason in dependency_reasons)
            if security_reasons:
                security_incomplete_paths.add(path)
        operational_error_reason = payload.get("operational_error_reason")
        scan_outcome_reason = payload.get("scan_outcome_reason")
        has_failed_outcome_reason = isinstance(scan_outcome_reasons, list) and any(
            isinstance(reason, str) and reason.endswith(OPERATIONAL_FAILURE_REASON_SUFFIXES)
            for reason in scan_outcome_reasons
        )
        has_noncoverage_outcome_reason = (
            isinstance(scan_outcome_reason, str)
            and bool(scan_outcome_reason)
            and not metadata_has_coverage_only_operational_error(
                {"operational_error": True, "operational_error_reason": scan_outcome_reason}
            )
        )
        if payload.get("operational_error") is not True:
            has_unflagged_coverage_reason = (
                isinstance(scan_outcome_reason, str)
                and bool(scan_outcome_reason)
                and not has_noncoverage_outcome_reason
            ) or (
                isinstance(scan_outcome_reasons, list)
                and any(
                    isinstance(reason, str)
                    and reason
                    and metadata_has_coverage_only_operational_error(
                        {"operational_error": True, "operational_error_reason": reason}
                    )
                    for reason in scan_outcome_reasons
                )
            )
            path_has_security_finding = any(
                finding_location == path
                or finding_location.startswith(f"{path} (")
                or finding_location.startswith(f"{path}:")
                for finding_location in security_finding_locations
            )
            unflagged_coverage_is_inconclusive = (
                payload.get("analysis_incomplete") is True
                and payload.get("scan_outcome") == "inconclusive"
                and isinstance(scan_outcome_reasons, list)
                and bool(scan_outcome_reasons)
            )
            if (
                (isinstance(operational_error_reason, str) and operational_error_reason)
                or has_failed_outcome_reason
                or has_noncoverage_outcome_reason
                or (
                    has_unflagged_coverage_reason
                    and (not path_has_security_finding or not unflagged_coverage_is_inconclusive)
                )
            ):
                unexpected_errors.add(path)
            continue
        if metadata_has_coverage_only_operational_error(payload):
            coverage_only_is_inconclusive = (
                payload.get("analysis_incomplete") is True
                and payload.get("scan_outcome") == "inconclusive"
                and isinstance(scan_outcome_reasons, list)
                and all(isinstance(reason, str) for reason in scan_outcome_reasons)
                and operational_error_reason in scan_outcome_reasons
                and not any(reason.endswith(OPERATIONAL_FAILURE_REASON_SUFFIXES) for reason in scan_outcome_reasons)
            )
            if coverage_only_is_inconclusive:
                coverage_only_paths.add(path)
                if operational_error_reason == "recognized_format_scanner_unavailable":
                    unavailable_scanner_paths.add(path)
            else:
                unexpected_errors.add(path)
            continue

        if (
            Path(path).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET
            and payload.get("operational_error_reason") == "call_graph_analysis_error"
            and payload.get("analysis_incomplete") is True
            and payload.get("scan_outcome") == "inconclusive"
            and isinstance(scan_outcome_reasons, list)
            and all(isinstance(reason, str) for reason in scan_outcome_reasons)
            and len(scan_outcome_reasons) == len(EXPECTED_AGPL_SOURCE_STABILITY_OUTCOME_REASONS)
            and frozenset(scan_outcome_reasons) == EXPECTED_AGPL_SOURCE_STABILITY_OUTCOME_REASONS
            and payload.get("pickle_report_status") == "inconclusive"
            and payload.get("pickle_verdict") == "malicious"
            and isinstance(payload.get("pickle_source"), str)
            and Path(payload["pickle_source"]).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET
        ):
            expected_source_changes.add(path)
        else:
            unexpected_errors.add(path)

    diagnosed_source_changes = set()
    diagnosed_unavailable_scanners = set()
    for diagnostic, details in diagnostics:
        location = diagnostic.location or "unknown scan location"
        pickle_source = details.get("pickle_source")
        category = details.get("category")
        scan_outcome_reason = details.get("scan_outcome_reason")
        scan_outcome_reasons = details.get("scan_outcome_reasons")
        coverage_only_diagnostic = metadata_has_coverage_only_operational_error(
            {
                "operational_error": True,
                "operational_error_reason": scan_outcome_reason,
            }
        )
        has_noncoverage_outcome_reason = (
            isinstance(scan_outcome_reason, str) and bool(scan_outcome_reason) and not coverage_only_diagnostic
        )
        has_operational_marker = (
            details.get("operational_error") is True
            or details.get("interrupted") is True
            or (isinstance(scan_outcome_reason, str) and bool(scan_outcome_reason))
        )
        diagnostic_is_failed = not isinstance(diagnostic, Check) or diagnostic.status == CheckStatus.FAILED
        expected_security_outcome_reason = _expected_security_outcome_reason(diagnostic, details)
        expected_pickle_incomplete = _is_expected_pickle_incomplete_diagnostic(diagnostic, details)
        expected_call_graph_source_unavailable = _is_expected_call_graph_source_unavailable_diagnostic(
            diagnostic, details
        )
        expected_coverage_incomplete = (
            diagnostic_is_failed
            and details.get("analysis_incomplete") is True
            and isinstance(scan_outcome_reason, str)
            and coverage_only_diagnostic
        )
        if "exception" in details:
            unexpected_errors.add(location)
            continue

        if not diagnostic_is_failed and has_operational_marker:
            unexpected_errors.add(location)
            continue

        if (
            location in unavailable_scanner_paths
            and diagnostic_is_failed
            and diagnostic.message == EXPECTED_UNAVAILABLE_SCANNER_MESSAGE
            and details.get("path") == location
        ):
            diagnosed_unavailable_scanners.add(location)

        if category == "call_graph_analysis_error" or (
            pickle_source and category not in {None, "parse_error"} and "exception_type" in details
        ):
            matching_paths = {path for path in expected_source_changes if location == path}
            if (
                matching_paths
                and isinstance(pickle_source, str)
                and Path(pickle_source).resolve() == EXPECTED_AGPL_SOURCE_STABILITY_ASSET
                and diagnostic.message
                == "Python call-graph analysis could not complete: source changed during shared call-graph analysis"
                and category == "call_graph_analysis_error"
                and details.get("exception_type") == "_CallGraphAnalysisLimitError"
                and details.get("analysis") == "python_call_graph_source_stability"
                and details.get("analysis_incomplete") is True
                and details.get("source_stability_reason") == EXPECTED_AGPL_SOURCE_STABILITY_REASON
                and diagnostic_is_failed
                and any(
                    finding_location == location or finding_location.startswith(f"{location} (")
                    for finding_location in security_finding_locations
                )
            ):
                diagnosed_source_changes.update(matching_paths)
            else:
                unexpected_errors.add(location)
            continue

        if "required_package" in details:
            diagnostic_owner = _file_metadata_for_diagnostic(results, location)
            diagnostic_metadata = diagnostic_owner[1] if diagnostic_owner is not None else None
            if diagnostic_owner is not None and _is_expected_missing_dependency_diagnostic(
                diagnostic, details, diagnostic_metadata
            ):
                owner_path = diagnostic_owner[0]
                required_package = details.get("required_package")
                normalized_package = (
                    required_package.strip().casefold().replace("-", "_") if isinstance(required_package, str) else ""
                )
                expected_reasons = EXPECTED_DEPENDENCY_OUTCOMES.get(normalized_package, frozenset())
                owner_expected_reasons = {
                    reason
                    for path, reason in expected_dependency_outcomes
                    if path == owner_path and reason in expected_reasons
                }
                detail_reason = details.get("scan_outcome_reason")
                if isinstance(detail_reason, str):
                    diagnostic_reasons = {detail_reason} & owner_expected_reasons
                elif len(owner_expected_reasons) == 1:
                    diagnostic_reasons = owner_expected_reasons
                else:
                    diagnostic_reasons = set()
                diagnosed_dependency_outcomes.update((owner_path, reason) for reason in diagnostic_reasons)
                continue
            unexpected_errors.add(location)
            continue

        has_unexplained_operational_marker = (
            (
                isinstance(category, str)
                and category != "parse_error"
                and category.endswith(OPERATIONAL_FAILURE_REASON_SUFFIXES)
            )
            or "operational_error_reason" in details
            or "scan_outcome_reasons" in details
            or details.get("scan_outcome") == "inconclusive"
            or (
                details.get("analysis_incomplete") is True
                and category != "parse_error"
                and expected_security_outcome_reason is None
                and not expected_pickle_incomplete
                and not expected_call_graph_source_unavailable
                and not expected_coverage_incomplete
            )
        )
        if has_unexplained_operational_marker:
            unexpected_errors.add(location)
            continue

        explicit_operational_failure = (
            (details.get("operational_error") is True and not coverage_only_diagnostic)
            or details.get("interrupted") is True
            or has_noncoverage_outcome_reason
            or (
                details.get("analysis_incomplete") is True
                and ("max_total_size" in details or ("scan_outcome_reason" in details and not coverage_only_diagnostic))
            )
        )
        if explicit_operational_failure:
            unexpected_errors.add(location)
            continue

        if category == "parse_error":
            continue
        if pickle_source:
            if details.get("exception_type") or details.get("error_type") or "error" in details:
                unexpected_errors.add(location)
            continue

        scan_budget_failure = (diagnostic.rule_code == "S902" or diagnostic.severity == IssueSeverity.INFO) and (
            any(key.startswith("max_") for key in details)
            or details.get("security_check") == "compression_bomb_detection"
        )
        if (
            (scan_budget_failure and not coverage_only_diagnostic)
            or details.get("exception_type")
            or details.get("error_type")
            or "error" in details
            or details.get("operational_error") is True
            or details.get("interrupted") is True
            or (
                details.get("analysis_incomplete") is True
                and ("max_total_size" in details or ("scan_outcome_reason" in details and not coverage_only_diagnostic))
            )
        ):
            unexpected_errors.add(location)
            continue

    unexpected_errors.update(path for path, _reason in expected_dependency_outcomes - diagnosed_dependency_outcomes)
    unexpected_errors.update(unavailable_scanner_paths - diagnosed_unavailable_scanners)
    incomplete_asset_paths = coverage_only_paths | dependency_incomplete_paths | security_incomplete_paths
    if incomplete_asset_paths and (results.success is not False or determine_exit_code(results) == 0):
        unexpected_errors.update(incomplete_asset_paths)
    error_message = (
        f"{scan_description} should not have unexpected operational errors: {describe_operational_errors(results)}"
    )
    assert not unexpected_errors, error_message
    if expected_source_changes:
        assert results.has_errors and expected_source_changes == diagnosed_source_changes, error_message
        assert results.success is False, f"{scan_description} must fail closed when source stability changes"
        assert determine_exit_code(results) == 2, f"{scan_description} must preserve its operational-error exit code"
        return
    assert not results.has_errors and not diagnosed_source_changes, error_message


class TestSecurityAssetIntegration:
    """Integration tests for security assets using organized structure."""

    @pytest.fixture
    def assets_dir(self):
        """Get the path to organized test assets."""
        return Path(__file__).parent / "assets"

    @pytest.fixture
    def samples_dir(self, assets_dir):
        """Get the samples directory for individual test files."""
        return assets_dir / "samples"

    @pytest.fixture
    def scenarios_dir(self, assets_dir):
        """Get the scenarios directory for complex test scenarios."""
        return assets_dir / "scenarios"

    def get_malicious_samples(self, samples_dir: Path) -> list[Path]:
        """Get all malicious sample files from organized structure."""
        malicious_files = []

        # Check different sample categories
        categories = [
            "pickles",
            "keras",
            "pytorch",
            "tensorflow",
            "manifests",
            "archives",
        ]

        for category in categories:
            category_dir = samples_dir / category
            if category_dir.exists():
                # Look for files with malicious indicators
                for file_path in category_dir.iterdir():
                    if any(
                        indicator in file_path.name.lower() for indicator in ["malicious", "evil", "suspicious", "bad"]
                    ):
                        malicious_files.append(file_path)

        return malicious_files

    def get_safe_samples(self, samples_dir: Path) -> list[Path]:
        """Get all safe sample files from organized structure."""
        safe_files = []
        explicitly_malicious_fixtures = {
            "custom_layer_attack.h5",
            "loss_injection.h5",
            "metric_injection.h5",
        }

        categories = [
            "pickles",
            "keras",
            "pytorch",
            "tensorflow",
            "manifests",
            "archives",
        ]

        for category in categories:
            category_dir = samples_dir / category
            if category_dir.exists():
                for file_path in category_dir.iterdir():
                    # Exclude malicious files and problematic files like dill_func.pkl
                    exclusions = [
                        "malicious",
                        "evil",
                        "suspicious",
                        "bad",
                        "dill_func",
                        "path_traversal",
                        "nested_pickle",  # Our intentionally malicious nested pickle test files
                        "decode_exec",  # Our intentionally malicious decode-exec test files
                        "simple_nested",  # Our intentionally malicious simple nested pickle test file
                    ]
                    if (
                        not any(indicator in file_path.name.lower() for indicator in exclusions)
                        and file_path.name not in explicitly_malicious_fixtures
                        and file_path.is_file()
                        and not file_path.name.startswith(".")
                    ):
                        safe_files.append(file_path)

        return safe_files

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_malicious_sample_detection(self, samples_dir):
        """Test that all malicious samples are properly detected."""
        from modelaudit.scanners import _registry

        def has_tensorflow():
            """Check if TensorFlow is available with timeout protection."""
            # In CI environments, skip TensorFlow detection to prevent hanging
            import os

            if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
                return False

            try:
                # Use subprocess for maximum isolation and cross-platform timeout
                import subprocess
                import sys

                # Try to import TensorFlow in a separate process with strict timeout
                cmd = [sys.executable, "-c", "import tensorflow; print('SUCCESS')"]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3,  # Even shorter timeout
                    cwd=None,
                )

                return result.returncode == 0 and "SUCCESS" in result.stdout

            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
                return False
            except Exception:
                return False

        malicious_files = self.get_malicious_samples(samples_dir)

        if not malicious_files:
            pytest.skip("No malicious sample files found")

        # Get failed scanners to handle compatibility issues
        failed_scanners = _registry.get_failed_scanners()
        tensorflow_available = has_tensorflow() and not any(
            "tf_savedmodel" in scanner_id for scanner_id in failed_scanners
        )

        # Track files that were tested vs skipped
        tested_files = []
        skipped_files = []

        for malicious_file in malicious_files:
            # Skip TensorFlow-specific malicious files if TensorFlow scanner is not available
            if not tensorflow_available and (
                "pyfunc" in malicious_file.name.lower() or "tensorflow" in str(malicious_file.parent).lower()
            ):
                skipped_files.append(f"{malicious_file.name} (TensorFlow scanner unavailable)")
                continue

            # Skip h5/HDF5 files if h5py is not installed
            try:
                import h5py  # noqa: F401

                h5py_available = True
            except ImportError:
                h5py_available = False

            if not h5py_available and malicious_file.suffix.lower() in [".h5", ".hdf5", ".keras"]:
                skipped_files.append(f"{malicious_file.name} (h5py not installed)")
                continue

            # Skip manifest JSON files from the manifests category - they may not trigger security issues
            # depending on scanner configuration (blacklist patterns, etc.)
            if "manifests" in str(malicious_file.parent) and malicious_file.suffix.lower() == ".json":
                skipped_files.append(f"{malicious_file.name} (manifest scanner may not flag generic JSON)")
                continue

            # Scan the malicious file
            results = scan_model_directory_or_file(str(malicious_file), cache_enabled=False)
            exit_code = determine_exit_code(results)

            # Should scan successfully
            assert results.success is True, f"Scan failed for {malicious_file.name}"

            # For files that can be scanned with available scanners, should detect issues
            if exit_code == 0:
                # If no issues detected, check if this might be due to missing scanners
                file_ext = malicious_file.suffix.lower()
                if file_ext in [".pb"] and not tensorflow_available:
                    skipped_files.append(f"{malicious_file.name} (required .pb scanner unavailable)")
                    continue

            # Should detect security issues for files that can be properly scanned
            tested_files.append(malicious_file.name)
            assert exit_code == 1, f"Failed to detect malicious content in {malicious_file.name}"
            assert len(results.issues) > 0, f"No issues found in {malicious_file.name}"

            # Check for security-level issues
            security_issues = [
                issue
                for issue in results.issues
                if getattr(issue, "severity", None) in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
            ]
            assert len(security_issues) > 0, f"No security issues found in {malicious_file.name}"

        # Ensure we tested at least some files
        if not tested_files and skipped_files:
            pytest.skip(f"All malicious files skipped due to scanner unavailability: {skipped_files}")

        assert len(tested_files) > 0, (
            f"Should have tested at least some malicious files. Tested: {tested_files}, Skipped: {skipped_files}"
        )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_safe_sample_validation(self, samples_dir):
        """Test that safe samples pass validation without false positives."""
        safe_files = self.get_safe_samples(samples_dir)
        try:
            import h5py  # noqa: F401

            h5py_available = True
        except Exception:
            h5py_available = False
        if not h5py_available:
            safe_files = [path for path in safe_files if path.suffix.lower() not in {".h5", ".hdf5"}]

        if not safe_files:
            pytest.skip("No safe sample files found")

        for safe_file in safe_files:
            # Scan the safe file
            results = scan_model_directory_or_file(str(safe_file), cache_enabled=False)
            exit_code = determine_exit_code(results)

            assert results.success is True, f"Scan failed for {safe_file.name}"

            # Any issues should be low-severity only (allow warnings but not critical/error)
            high_severity_issues = [
                issue for issue in results.issues if getattr(issue, "severity", None) in ["critical", "error"]
            ]
            assert len(high_severity_issues) == 0, (
                f"High-severity false positive in {safe_file.name}: {high_severity_issues}"
            )

            # Exit code should be 0 for clean files, or 1 for warnings-only (which is acceptable)
            assert exit_code in [0, 1], f"Unexpected exit code {exit_code} for {safe_file.name}: {results.issues}"

            # If exit code is 1, make sure it's only due to warnings or info, not high-severity issues
            if exit_code == 1:
                assert len(high_severity_issues) == 0, (
                    f"Exit code 1 should only be for warnings, not high-severity issues in {safe_file.name}"
                )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_existing_pickle_assets(self, assets_dir):
        """Test existing pickle assets in the organized structure."""
        pickles_dir = assets_dir / "samples" / "pickles"

        if not pickles_dir.exists():
            pytest.skip("Pickles directory not found")

        # Test the existing evil.pickle (should be malicious)
        evil_pickle = pickles_dir / "evil.pickle"
        if evil_pickle.exists():
            results = scan_model_directory_or_file(str(evil_pickle), cache_enabled=False)
            exit_code = determine_exit_code(results)
            assert exit_code == 1, "Should detect evil.pickle as malicious"

        # Test dill_func.pkl (intentionally incomplete but still security-positive)
        dill_func = pickles_dir / "dill_func.pkl"
        if dill_func.exists():
            results = scan_model_directory_or_file(str(dill_func), cache_enabled=False)
            exit_code = determine_exit_code(results)
            assert results.success is False, "dill_func.pkl should preserve its incomplete scan outcome"
            # The detected dill usage should still preserve the security exit code.
            assert exit_code == 1, "dill_func.pkl should be flagged as suspicious due to dill usage"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_license_scenarios_integration(self, scenarios_dir: Path) -> None:
        """Test that license scenarios still work with new structure."""
        license_scenarios = scenarios_dir / "license_scenarios"

        if not license_scenarios.exists():
            pytest.skip("License scenarios directory not found")

        # Test a few license scenarios
        for scenario_dir in license_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir), cache_enabled=False)
                # License scenarios must scan to completion. Some fixtures (e.g.
                # agpl_component) embed pickles that reference __main__ globals and
                # are now correctly flagged as security findings, so success may be
                # False; the scan must still have run and processed the files.
                assert results.files_scanned > 0, f"License scenario produced no scanned files: {scenario_dir.name}"
                assert results.has_errors is False, f"License scenario had operational errors: {scenario_dir.name}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_security_scenarios(self, scenarios_dir):
        """Test complex security scenarios if they exist."""
        security_scenarios = scenarios_dir / "security_scenarios"

        if not security_scenarios.exists():
            pytest.skip("Security scenarios directory not found")

        for scenario_dir in security_scenarios.iterdir():
            if scenario_dir.is_dir():
                results = scan_model_directory_or_file(str(scenario_dir), cache_enabled=False)
                exit_code = determine_exit_code(results)

                # Security scenarios should be detected as malicious
                assert exit_code == 1, f"Security scenario not detected: {scenario_dir.name}"
                assert results.success is True, f"Scan failed for {scenario_dir.name}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_cli_organized_structure(self, samples_dir):
        """Test CLI scanning with organized structure."""
        if not samples_dir.exists():
            pytest.skip("Samples directory not found")

        runner = CliRunner()

        # Test scanning samples directory
        result = runner.invoke(cli, ["scan", str(samples_dir), "--format", "json"])
        assert result.exit_code in [0, 1], f"CLI scan failed: {result.output}"

        # Should produce valid JSON
        try:
            output_data = json.loads(result.output)
            assert "files_scanned" in output_data
            assert "issues" in output_data
            assert output_data["files_scanned"] > 0
        except json.JSONDecodeError:
            pytest.fail(f"CLI did not produce valid JSON: {result.output}")

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_mixed_directory_scanning(self, assets_dir):
        """Test scanning directory with both safe and malicious assets."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Create temporary directory with mix of files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Copy a few files from different categories
            samples_dir = assets_dir / "samples"
            if samples_dir.exists():
                copied_files = []

                # Try to copy some files from different categories
                for category_dir in samples_dir.iterdir():
                    if category_dir.is_dir():
                        category_files = [
                            path for path in category_dir.iterdir() if path.is_file() and not path.name.startswith(".")
                        ][:2]
                        for file_path in category_files:
                            dest = temp_path / f"{category_dir.name}_{file_path.name}"
                            shutil.copy2(file_path, dest)
                            copied_files.append(dest)

                if copied_files:
                    # Scan the mixed directory
                    results = scan_model_directory_or_file(str(temp_path), cache_enabled=False)
                    assert results.files_scanned >= len(copied_files)
                    assert results.has_errors is False, (
                        f"Mixed directory scan should not have operational errors: "
                        f"{describe_operational_errors(results)}"
                    )

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_asset_discovery_completeness(self, assets_dir: Path) -> None:
        """Test that asset discovery finds all expected file types."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        # Scan the entire assets directory. The tree intentionally contains
        # exploits/ and malicious samples/, so success is expected to be False;
        # what matters for discovery is that the scan ran and processed files.
        results = scan_model_directory_or_file(str(assets_dir), cache_enabled=False)

        # Should find various file types
        assert results.files_scanned > 0, "Should find some files to scan"
        assert_no_unexpected_asset_scan_errors(results, "Assets directory scan")
        assert len(results.issues) > 0, "Assets tree contains exploits; findings expected"

        # Check for different file extensions in issues (indicates they were processed)
        scanned_extensions = set()
        for issue in results.issues:
            location = getattr(issue, "location", "")
            if location:
                ext = Path(location).suffix.lower()
                if ext:
                    scanned_extensions.add(ext)

        # Should have processed various file types
        expected_extensions = {".pkl", ".h5", ".pt", ".json", ".zip"}
        found_expected = expected_extensions.intersection(scanned_extensions)

        # Don't require all extensions, but should find some that we expect
        if scanned_extensions:
            assert len(found_expected) > 0, f"Should find some expected file types. Found: {scanned_extensions}"

    @pytest.mark.skipif(
        sys.version_info[:2] in [(3, 10), (3, 12)],
        reason="Integration test hangs on Python 3.10 and 3.12 in CI - core functionality tested in unit tests",
    )
    def test_performance_with_organized_structure(self, assets_dir: Path) -> None:
        """Test that organized structure doesn't significantly impact performance."""
        if not assets_dir.exists():
            pytest.skip("Assets directory not found")

        import time

        start_time = time.perf_counter()
        results = scan_model_directory_or_file(str(assets_dir), cache_enabled=False)
        duration = time.perf_counter() - start_time

        # Should complete in reasonable time. The assets tree contains exploits,
        # so success is expected to be False; assert the scan ran and produced
        # findings rather than demanding success on malicious inputs.
        assert results.files_scanned > 0, "Performance test scan should process files"
        assert_no_unexpected_asset_scan_errors(results, "Performance test scan")
        assert len(results.issues) > 0, "Assets tree contains exploits; findings expected"
        is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
        threshold = 120 if is_ci else 60
        assert duration < threshold, f"Scan took too long: {duration:.2f}s"

        # Should provide performance metrics
        assert hasattr(results, "duration"), "Results should include timing information"
        assert results.duration > 0, "Duration should be positive"
