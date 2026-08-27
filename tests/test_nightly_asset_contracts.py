"""Coverage contracts for committed assets consumed by Nightly scans."""

import hashlib
import io
import shutil
import sys
import tarfile
import tempfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from typing import Any

import modelaudit_picklescan.api as package_api
import msgpack
import pytest
from modelaudit_picklescan.call_graph import _CallGraphAnalysisLimitError

import modelaudit.core as core_module
import modelaudit.scanners.keras_h5_scanner as keras_h5_scanner_module
import modelaudit.scanners.keras_zip_scanner as keras_zip_scanner_module
import modelaudit.scanners.onnx_scanner as onnx_scanner_module
import modelaudit.scanners.pmml_scanner as pmml_scanner_module
import modelaudit.scanners.sevenzip_scanner as sevenzip_scanner_module
import modelaudit.scanners.tf_metagraph_scanner as tf_metagraph_scanner_module
import modelaudit.scanners.tflite_scanner as tflite_scanner_module
import modelaudit.scanners.xgboost_scanner as xgboost_scanner_module
import modelaudit.scanners.zip_scanner as zip_scanner_module
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core_results import metadata_has_coverage_only_operational_error, results_have_inconclusive_outcome
from modelaudit.models import FileMetadataModel, ModelAuditResultModel
from modelaudit.scanner_results import Check, CheckStatus, Issue, IssueSeverity, ScanResult
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY
from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner
from modelaudit.scanners.manifest_scanner import ManifestScanner
from modelaudit.utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from tests import test_security_asset_integration

ASSETS = Path(__file__).parent / "assets" / "samples" / "pickles"
AGPL_ASSET = Path(__file__).parent / "assets" / "scenarios" / "license_scenarios" / "agpl_component" / "agpl_model.pkl"
AMBIGUOUS_XML_PAYLOAD = (
    "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>"
).encode()
COMPRESSION_BOMB_PAYLOAD = b"x" * (1024 * 1024 + 64)


def _source_stability_error() -> _CallGraphAnalysisLimitError:
    return _CallGraphAnalysisLimitError(
        "source changed during shared call-graph analysis",
        stability_reason=test_security_asset_integration.EXPECTED_AGPL_SOURCE_STABILITY_REASON,
    )


def _scan_asset(name: str) -> ModelAuditResultModel:
    return core_module.scan_model_directory_or_file(str(ASSETS / name), cache_enabled=False)


def _scan_ambiguous_xml_archive(
    tmp_path: Path,
    member_names: tuple[str, ...],
    *,
    unrelated_members: tuple[str, ...] = (),
    compression: int = zipfile.ZIP_STORED,
) -> tuple[Path, ModelAuditResultModel]:
    archive_path = tmp_path / f"ambiguous-xml-{len(member_names)}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=compression) as archive:
        for member_name in member_names:
            archive.writestr(member_name, AMBIGUOUS_XML_PAYLOAD)
        for member_name in unrelated_members:
            archive.writestr(member_name, b"ordinary unknown archive member")
    return archive_path, test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )


def _zip_payload(entries: tuple[tuple[str, bytes], ...], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for member_name, member_payload in entries:
            archive.writestr(member_name, member_payload)
    return payload.getvalue()


def _corrupt_zip_payload() -> bytes:
    valid_payload = _zip_payload((("ordinary.txt", b"ordinary"),))
    eocd_offset = valid_payload.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    return valid_payload[: eocd_offset + 10]


def _scan_nested_zip_archive(
    tmp_path: Path,
    inner_entries: tuple[tuple[str, bytes], ...],
    *,
    inner_compression: int = zipfile.ZIP_STORED,
) -> tuple[Path, ModelAuditResultModel]:
    archive_path = tmp_path / "nested-archive.zip"
    inner_payload = _zip_payload(inner_entries, compression=inner_compression)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("inner.zip", inner_payload)
    return archive_path, test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )


def _scan_duplicate_nested_zip_archives(
    tmp_path: Path,
    first_entries: tuple[tuple[str, bytes], ...],
    second_entries: tuple[tuple[str, bytes], ...],
    *,
    inner_compression: int = zipfile.ZIP_STORED,
) -> tuple[Path, ModelAuditResultModel]:
    archive_path = tmp_path / "duplicate-nested-archives.zip"
    first_payload = _zip_payload(first_entries, compression=inner_compression)
    second_payload = _zip_payload(second_entries, compression=inner_compression)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("inner.zip", first_payload)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("inner.zip", second_payload)
    return archive_path, test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )


def _merge_with_canonical_agpl_source_change(result: ModelAuditResultModel) -> ModelAuditResultModel:
    expected_source_change = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    expected_source_change.aggregate_scan_result(result)
    test_security_asset_integration._merge_test_zip_extraction_manifests(expected_source_change, result)
    return expected_source_change


def _assert_otherwise_accepted_archive_control(
    result: ModelAuditResultModel,
    failed_member: str,
    hidden_reason: str | None = None,
    *,
    hidden_reasons: frozenset[str] = frozenset(),
) -> None:
    control = result.model_copy(deep=True)
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    if manifest is not None:
        test_security_asset_integration._set_test_zip_extraction_manifest(
            control,
            manifest,
            source=result,
        )
    control.issues = [issue for issue in control.issues if issue.location != failed_member]
    control.checks = [check for check in control.checks if check.location != failed_member]
    for archive_path, metadata in control.file_metadata.items():
        if not failed_member.startswith(f"{archive_path}:") or metadata.model_extra is None:
            continue
        reported_coverage_reasons: set[str] = set()
        remaining_diagnostics: list[Issue | Check] = [*control.issues, *control.checks]
        for diagnostic in remaining_diagnostics:
            if diagnostic.location is None or not (
                diagnostic.location == archive_path or diagnostic.location.startswith(f"{archive_path}:")
            ):
                continue
            for details in test_security_asset_integration._nested_diagnostic_details(diagnostic.details):
                reason = details.get("scan_outcome_reason")
                if isinstance(reason, str) and metadata_has_coverage_only_operational_error(
                    {"operational_error": True, "operational_error_reason": reason}
                ):
                    reported_coverage_reasons.add(reason)
            if diagnostic.message == (
                "XML model routing was inconclusive because the bounded probe ended before "
                "the first structural root element"
            ):
                reported_coverage_reasons.update({"xml_model_routing_incomplete", "zip_analysis_incomplete"})
        reasons = metadata.model_extra.get("scan_outcome_reasons")
        if isinstance(reasons, list):
            remaining_reasons = [
                reason
                for reason in reasons
                if reason != hidden_reason
                and reason not in hidden_reasons
                and not (
                    isinstance(reason, str)
                    and reason.endswith(("_failed", "_error", "_exceeded", "_timeout", "_interrupted"))
                )
                and not (
                    isinstance(reason, str)
                    and metadata_has_coverage_only_operational_error(
                        {"operational_error": True, "operational_error_reason": reason}
                    )
                    and reason not in reported_coverage_reasons
                )
            ]
            metadata.model_extra["scan_outcome_reasons"] = remaining_reasons
            operational_error_reason = metadata.model_extra.get("operational_error_reason")
            if operational_error_reason not in remaining_reasons:
                metadata.model_extra.pop("operational_error", None)
                metadata.model_extra.pop("operational_error_reason", None)
            if metadata.model_extra.get("scan_outcome_reason") not in remaining_reasons:
                metadata.model_extra.pop("scan_outcome_reason", None)
            if not remaining_reasons:
                for marker in (
                    "analysis_incomplete",
                    "scan_outcome",
                    "scan_outcome_message",
                    "scan_outcome_reasons",
                ):
                    metadata.model_extra.pop(marker, None)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(control, "mixed archive negative control")


def test_complete_benign_asset_scans_cleanly() -> None:
    """The committed benign fixture must remain complete and issue-free."""
    result = _scan_asset("safe_data.pkl")

    assert result.has_errors is False
    assert results_have_inconclusive_outcome(result) is False
    assert core_module.determine_exit_code(result) == 0
    assert result.issues == []


@pytest.mark.parametrize(
    ("name", "rule_code", "message"),
    [
        (
            "evil.pickle",
            "S201",
            "Found REDUCE opcode invoking dangerous global: posix.system",
        ),
        (
            "malicious_model_realistic.pkl",
            "S601",
            "Encoded pickle payload detected",
        ),
        (
            "nested_pickle_base64.pkl",
            "S601",
            "Encoded pickle payload detected",
        ),
    ],
)
def test_complete_malicious_assets_preserve_security_signal(
    name: str,
    rule_code: str,
    message: str,
) -> None:
    """Nightly benchmark inputs must remain complete and security-positive."""
    result = _scan_asset(name)

    assert result.has_errors is False
    assert results_have_inconclusive_outcome(result) is False
    assert core_module.determine_exit_code(result) == 1
    assert any(issue.rule_code == rule_code and issue.message == message for issue in result.issues)


def test_intentional_incomplete_pickle_asset_preserves_security_exit() -> None:
    """The dill fixture is intentionally incomplete but still security-positive."""
    result = _scan_asset("dill_func.pkl")
    path = str(ASSETS / "dill_func.pkl")
    metadata = result.file_metadata[path].model_dump(exclude_none=True)

    assert result.has_errors is False
    assert result.success is False
    assert results_have_inconclusive_outcome(result) is True
    assert metadata["scan_outcome"] == "inconclusive"
    assert metadata["scan_outcome_reasons"] == ["nested_pickle_incomplete"]
    assert any(issue.message == "Nested pickle analysis did not complete" for issue in result.issues)
    assert any(
        issue.rule_code == "S201"
        and issue.message == "Found REDUCE opcode invoking dangerous global: dill._dill._create_code"
        for issue in result.issues
    )
    assert core_module.determine_exit_code(result) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "intentional incomplete pickle asset",
    )


@pytest.mark.parametrize("outcome_state", ["missing", "contradictory"])
def test_incomplete_pickle_security_signal_requires_aggregate_outcome_state(
    outcome_state: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    path = str(ASSETS / "dill_func.pkl")
    metadata = result.file_metadata[path]
    assert metadata.model_extra is not None
    assert metadata.model_extra["scan_outcome_reasons"] == ["nested_pickle_incomplete"]

    if outcome_state == "missing":
        metadata.model_extra.pop("analysis_incomplete", None)
        metadata.model_extra.pop("scan_outcome", None)
    else:
        metadata.model_extra["analysis_incomplete"] = False
        metadata.model_extra["scan_outcome"] = "complete"

    assert result.has_errors is False
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.rule_code == "S201"
        and issue.message == "Found REDUCE opcode invoking dangerous global: dill._dill._create_code"
        for issue in result.issues
    )
    assert core_module.determine_exit_code(result) == 1
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"incomplete pickle with {outcome_state} aggregate outcome state",
        )


@pytest.mark.parametrize("reason", ["nested_pickle_incomplete", "nested_probe_limit"])
@pytest.mark.parametrize("malformation", ["missing-state", "contradictory-state", "missing-diagnostic"])
def test_agpl_nested_security_outcomes_require_complete_state_and_diagnostic(
    reason: str,
    malformation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    path = str(AGPL_ASSET)
    metadata = result.file_metadata[path]
    assert metadata.model_extra is not None
    metadata.model_extra["scan_outcome_reasons"] = [reason, "flax_msgpack_routing_incomplete"]

    if malformation == "missing-state":
        metadata.model_extra.pop("analysis_incomplete", None)
        metadata.model_extra.pop("scan_outcome", None)
    elif malformation == "contradictory-state":
        metadata.model_extra["analysis_incomplete"] = False
        metadata.model_extra["scan_outcome"] = "complete"
    else:
        result.issues = [issue for issue in result.issues if issue.details.get("notice_code") != reason]
        result.checks = [check for check in result.checks if check.details.get("notice_code") != reason]

    assert result.has_errors is False
    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.rule_code == "S204"
        and issue.location is not None
        and (issue.location == path or issue.location.startswith(f"{path} ("))
        for issue in result.issues
    )
    assert core_module.determine_exit_code(result) == 1
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"AGPL {reason} with {malformation}",
        )


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize("source_changes", [False, True], ids=["stable-source", "changed-source"])
def test_organized_asset_scans_preserve_fail_closed_source_stability(
    integration_test: str,
    source_changes: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if source_changes:

        def raise_source_stability_error(_report_generation: int | None) -> None:
            raise _source_stability_error()

        monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    else:
        monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)

    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    metadata = result.file_metadata[str(AGPL_ASSET)].model_dump(exclude_none=True)

    assert result.has_errors is source_changes
    assert result.success is False
    assert results_have_inconclusive_outcome(result) is True
    assert core_module.determine_exit_code(result) == (2 if source_changes else 1)
    assert metadata["pickle_verdict"] == "malicious"
    assert any(issue.rule_code == "S204" for issue in result.issues)

    if source_changes:
        assert metadata["operational_error"] is True
        assert metadata["operational_error_reason"] == "call_graph_analysis_error"
        assert metadata["analysis_incomplete"] is True
        assert metadata["scan_outcome"] == "inconclusive"
        assert "call_graph_analysis_error" in metadata["scan_outcome_reasons"]
        assert any(
            issue.message
            == "Python call-graph analysis could not complete: source changed during shared call-graph analysis"
            and issue.details.get("category") == "call_graph_analysis_error"
            and issue.details.get("exception_type") == "_CallGraphAnalysisLimitError"
            and issue.details.get("analysis") == "python_call_graph_source_stability"
            and issue.details.get("analysis_incomplete") is True
            and issue.details.get("source_stability_reason")
            == test_security_asset_integration.EXPECTED_AGPL_SOURCE_STABILITY_REASON
            for issue in result.issues
        )

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    ("diagnostic_kind", "include_operational_error"),
    [
        ("issue", True),
        ("failed-check", True),
        ("marker-only", False),
    ],
)
def test_organized_asset_scans_reject_hidden_operational_diagnostics_without_has_errors(
    diagnostic_kind: str,
    include_operational_error: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    assert result.has_errors is False

    details = {
        "analysis_incomplete": True,
        "scan_outcome": "inconclusive",
        "scan_outcome_reason": "scanner_error",
    }
    if include_operational_error:
        details["operational_error"] = True

    if diagnostic_kind == "failed-check":
        result.checks.append(
            Check(
                name="Hidden operational failure",
                status=CheckStatus.FAILED,
                message="Hidden operational failure",
                severity=IssueSeverity.INFO,
                location=str(AGPL_ASSET),
                details=details,
            )
        )
    else:
        result.issues.append(
            Issue(
                message="Hidden operational failure",
                severity=IssueSeverity.INFO,
                location=str(AGPL_ASSET),
                details=details,
            )
        )

    assert result.has_errors is False
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, diagnostic_kind)


@pytest.mark.parametrize(
    "metadata_marker",
    [
        pytest.param(
            {"operational_error_reason": "scanner_read_failed"},
            id="operational-error-reason",
        ),
        pytest.param(
            {"scan_outcome_reasons": ["scanner_read_failed"]},
            id="failed-outcome-reason",
        ),
        pytest.param(
            {"scan_outcome_reason": "scanner_read_failed"},
            id="single-failed-outcome-reason",
        ),
        pytest.param(
            {
                "operational_error": False,
                "operational_error_reason": "scanner_read_failed",
                "scan_outcome_reasons": ["scanner_read_failed"],
            },
            id="false-operational-error-flag",
        ),
        pytest.param(
            {
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reasons": ["xml_model_routing_incomplete"],
            },
            id="unflagged-coverage-only-outcome-list",
        ),
        pytest.param(
            {
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "xml_model_routing_incomplete",
            },
            id="unflagged-coverage-only-outcome-single",
        ),
    ],
)
def test_organized_asset_scans_reject_unflagged_operational_metadata(
    metadata_marker: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    assert result.has_errors is False
    result.file_metadata[str(tmp_path / "secondary.bin")] = FileMetadataModel(**metadata_marker)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "unflagged metadata")


@pytest.mark.parametrize("diagnostic_kind", ["issue", "failed-check"])
def test_organized_asset_scans_reject_bare_noncoverage_outcome_reason(
    diagnostic_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    details = {"scan_outcome_reason": "scanner_read_failed"}

    if diagnostic_kind == "failed-check":
        result.checks.append(
            Check(
                name="Hidden scanner failure",
                status=CheckStatus.FAILED,
                message="Hidden scanner failure",
                severity=IssueSeverity.INFO,
                location=str(AGPL_ASSET),
                details=details,
            )
        )
    else:
        result.issues.append(
            Issue(
                message="Hidden scanner failure",
                severity=IssueSeverity.INFO,
                location=str(AGPL_ASSET),
                details=details,
            )
        )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, diagnostic_kind)


@pytest.mark.parametrize(
    "details",
    [
        pytest.param({"operational_error": True}, id="operational-error"),
        pytest.param({"interrupted": True}, id="interrupted"),
        pytest.param({"scan_outcome_reason": "scanner_read_failed"}, id="outcome-reason"),
    ],
)
def test_organized_asset_scans_reject_operational_markers_on_passed_checks(
    details: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    result.checks.append(
        Check(
            name="Inconsistent passed check",
            status=CheckStatus.PASSED,
            message="Scanner claims this check passed",
            location=str(AGPL_ASSET),
            details=details,
        )
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "passed check")


def test_organized_asset_scans_preserve_plain_passed_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    result.checks.append(
        Check(
            name="Benign passed check",
            status=CheckStatus.PASSED,
            message="Scanner completed normally",
            details={"format": "pickle"},
        )
    )

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "plain passed check")


def _append_contract_diagnostic(
    result: ModelAuditResultModel,
    diagnostic_kind: str,
    *,
    message: str,
    location: str,
    details: dict[str, Any],
    rule_code: str | None = None,
) -> None:
    root_details = details if diagnostic_kind != "nested" else {"findings": [{"details": details}]}
    if diagnostic_kind == "failed-check":
        result.checks.append(
            Check(
                name="Synthetic contract diagnostic",
                status=CheckStatus.FAILED,
                message=message,
                severity=IssueSeverity.INFO,
                location=location,
                details=root_details,
                rule_code=rule_code,
            )
        )
        return
    result.issues.append(
        Issue(
            message=message,
            severity=IssueSeverity.INFO,
            location=location,
            details=root_details,
            rule_code=rule_code,
        )
    )


def test_organized_asset_scans_reject_unavailable_scanner_diagnostic_without_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    missing_path = str(tmp_path / "missing.keras")
    result.checks.append(
        Check(
            name="Format Detection",
            status=CheckStatus.FAILED,
            message=test_security_asset_integration.EXPECTED_UNAVAILABLE_SCANNER_MESSAGE,
            severity=IssueSeverity.INFO,
            location=missing_path,
            details={"format": "keras", "path": missing_path},
        )
    )

    assert result.success is True
    assert core_module.determine_exit_code(result) == 0
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "unavailable scanner diagnostic without metadata",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "failed-check", "nested"])
def test_organized_asset_scans_reject_coverage_diagnostic_without_metadata(
    diagnostic_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    _append_contract_diagnostic(
        result,
        diagnostic_kind,
        message="Recognized format scan coverage is incomplete",
        location=model_path,
        details={
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "recognized_format_scanner_unavailable",
        },
    )

    assert result.success is True
    assert core_module.determine_exit_code(result) == 2
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{diagnostic_kind} coverage diagnostic without metadata",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "failed-check", "nested"])
def test_organized_asset_scans_reject_security_incomplete_diagnostic_without_metadata(
    diagnostic_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    result.issues.append(
        Issue(
            message="Embedded pickle finding",
            severity=IssueSeverity.CRITICAL,
            location=model_path,
            rule_code="S204",
        )
    )
    _append_contract_diagnostic(
        result,
        diagnostic_kind,
        message="Nested pickle analysis did not complete",
        location=model_path,
        details={
            "analysis_incomplete": True,
            "notice_code": "nested_pickle_incomplete",
            "pickle_notice_code": "nested_pickle_incomplete",
            "pickle_source": model_path,
            "nested_status": "inconclusive",
            "nested_encoding": "raw",
        },
        rule_code="S902",
    )

    assert result.success is True
    assert core_module.determine_exit_code(result) == 1
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{diagnostic_kind} security diagnostic without metadata",
        )


@pytest.mark.parametrize("contract_kind", ["source-change", "unflagged-coverage"])
def test_organized_asset_scans_require_diagnostic_for_each_coverage_reason(
    contract_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if contract_kind == "source-change":

        def raise_source_stability_error(_report_generation: int | None) -> None:
            raise _source_stability_error()

        monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
        result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
        model_path = str(AGPL_ASSET)
    else:
        monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
        result = _scan_asset("safe_data.pkl")
        model_path = str(tmp_path / "missing-flax-diagnostic.pkl")
        result.file_metadata[model_path] = FileMetadataModel(
            analysis_incomplete=True,
            scan_outcome="inconclusive",
            scan_outcome_reasons=["flax_msgpack_routing_incomplete"],
        )
        result.issues.append(
            Issue(
                message="Embedded pickle finding",
                severity=IssueSeverity.CRITICAL,
                location=model_path,
                rule_code="S204",
            )
        )
        result.success = False

    def reports_flax_incomplete(diagnostic: Issue | Check) -> bool:
        return any(
            details.get("scan_outcome_reason") == "flax_msgpack_routing_incomplete"
            for details in test_security_asset_integration._nested_diagnostic_details(diagnostic.details)
        )

    result.issues = [diagnostic for diagnostic in result.issues if not reports_flax_incomplete(diagnostic)]
    result.checks = [diagnostic for diagnostic in result.checks if not reports_flax_incomplete(diagnostic)]
    remaining_diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert not any(reports_flax_incomplete(diagnostic) for diagnostic in remaining_diagnostics)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{contract_kind} metadata without its coverage diagnostic",
        )


@pytest.mark.parametrize(
    ("contract_kind", "field", "value"),
    [
        pytest.param("dependency", "analysis_incomplete", False, id="dependency-complete-flag"),
        pytest.param("dependency", "scan_outcome", "complete", id="dependency-complete-outcome"),
        pytest.param("security", "analysis_incomplete", False, id="security-complete-flag"),
        pytest.param("security", "scan_outcome", "complete", id="security-complete-outcome"),
        pytest.param("coverage", "analysis_incomplete", False, id="coverage-complete-flag"),
        pytest.param("coverage", "scan_outcome", "complete", id="coverage-complete-outcome"),
    ],
)
def test_organized_asset_scans_reject_contradictory_incomplete_diagnostic_state(
    contract_kind: str,
    field: str,
    value: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    if contract_kind == "security":
        result = _scan_asset("dill_func.pkl")
        diagnostic: Issue | Check = next(
            issue for issue in result.issues if issue.details.get("notice_code") == "nested_pickle_incomplete"
        )
    elif contract_kind == "dependency":
        result, model_path, _reason = _synthetic_direct_h5py_dependency_profile(
            "h5",
            tmp_path,
            monkeypatch,
        )
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        diagnostic = next(
            check
            for check in result.checks
            if check.location == model_path and check.details.get("required_package") == "h5py"
        )
    else:
        result = _scan_asset("safe_data.pkl")
        model_path = str(tmp_path / f"{contract_kind}-incomplete.model")
        reason = "flax_msgpack_routing_incomplete"
        result.file_metadata[model_path] = FileMetadataModel(
            analysis_incomplete=True,
            scan_outcome="inconclusive",
            scan_outcome_reasons=[reason],
        )
        result.success = False
        result.issues.append(
            Issue(
                message="Embedded pickle finding",
                severity=IssueSeverity.CRITICAL,
                location=model_path,
                rule_code="S204",
            )
        )
        diagnostic = Issue(
            message="Flax MessagePack analysis incomplete because bounded routing inspection could not complete",
            severity=IssueSeverity.INFO,
            location=model_path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
        result.issues.append(diagnostic)

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"valid {contract_kind} incomplete diagnostic control",
    )
    diagnostic.details[field] = value

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{contract_kind} diagnostic with contradictory {field}",
        )


@pytest.mark.parametrize("contract_kind", ["standalone", "duplicate"])
def test_organized_asset_scans_reject_aliasless_security_incomplete_diagnostics(
    contract_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    if contract_kind == "duplicate":
        result = _scan_asset("dill_func.pkl")
        diagnostic: Issue | Check = next(
            issue for issue in result.issues if issue.details.get("notice_code") == "nested_pickle_incomplete"
        )
        diagnostic.details.pop("notice_code")
        diagnostic.details.pop("pickle_notice_code")
    else:
        result = _scan_asset("safe_data.pkl")
        model_path = str(ASSETS / "safe_data.pkl")
        result.issues.append(
            Issue(
                message="Embedded pickle finding",
                severity=IssueSeverity.CRITICAL,
                location=model_path,
                rule_code="S204",
            )
        )
        _append_contract_diagnostic(
            result,
            "issue",
            message="Nested pickle analysis did not complete",
            location=model_path,
            details={
                "analysis_incomplete": True,
                "pickle_source": model_path,
                "nested_status": "inconclusive",
                "nested_encoding": "raw",
            },
            rule_code="S902",
        )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{contract_kind} aliasless security diagnostic",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "failed-check", "nested"])
@pytest.mark.parametrize(
    "malformed_details",
    [
        pytest.param({"operational_error": "yes"}, id="non-boolean-operational-error"),
        pytest.param({"interrupted": "yes"}, id="non-boolean-interrupted"),
        pytest.param({"exception_type": ""}, id="empty-exception-type"),
        pytest.param({"error_type": None}, id="null-error-type"),
    ],
)
def test_organized_asset_scans_reject_malformed_diagnostic_markers(
    diagnostic_kind: str,
    malformed_details: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    _append_contract_diagnostic(
        result,
        diagnostic_kind,
        message="Malformed scanner diagnostic",
        location=model_path,
        details=malformed_details,
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{diagnostic_kind} malformed diagnostic marker",
        )


@pytest.mark.parametrize(
    ("notice_code", "pickle_notice_code"),
    [
        pytest.param("nested_pickle_incomplete", "nested_probe_limit", id="mismatched-pickle-alias"),
        pytest.param("unrelated_notice", "nested_pickle_incomplete", id="fallback-from-mismatched-notice"),
    ],
)
def test_organized_asset_scans_reject_mismatched_security_notice_aliases(
    notice_code: str,
    pickle_notice_code: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    diagnostic = next(
        issue for issue in result.issues if issue.details.get("notice_code") == "nested_pickle_incomplete"
    )
    diagnostic.details["notice_code"] = notice_code
    diagnostic.details["pickle_notice_code"] = pickle_notice_code

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "mismatched nested security notice aliases",
        )


@pytest.mark.parametrize("removed_alias", ["notice_code", "pickle_notice_code"])
def test_organized_asset_scans_preserve_single_security_notice_alias(
    removed_alias: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    matching_diagnostics = [
        diagnostic for diagnostic in diagnostics if diagnostic.details.get("notice_code") == "nested_pickle_incomplete"
    ]
    assert matching_diagnostics
    for diagnostic in matching_diagnostics:
        diagnostic.details.pop(removed_alias)

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"single nested security notice alias after removing {removed_alias}",
    )


def test_organized_asset_scans_reject_mismatched_security_diagnostic_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    diagnostic = next(
        issue for issue in result.issues if issue.details.get("notice_code") == "nested_pickle_incomplete"
    )
    diagnostic.details["scan_outcome_reason"] = "recognized_format_scanner_unavailable"

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "mismatched nested security diagnostic reason",
        )


@pytest.mark.parametrize("findings_container", ["dict", "list", "tuple"])
def test_organized_asset_scans_reject_nested_finding_operational_diagnostics_without_has_errors(
    findings_container: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    nested_finding = {
        "details": {
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "scanner_error",
            "operational_error": True,
        }
    }
    findings: Any = nested_finding
    if findings_container == "list":
        findings = [nested_finding]
    elif findings_container == "tuple":
        findings = (nested_finding,)
    result.issues.append(
        Issue(
            message="Serialized scanner findings",
            severity=IssueSeverity.INFO,
            location=str(AGPL_ASSET),
            details={"findings": findings},
        )
    )

    assert result.has_errors is False
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "nested finding")


@pytest.mark.parametrize(
    ("benign_detail", "nested"),
    [
        pytest.param({"pickle_source": str(AGPL_ASSET)}, False, id="pickle-source-top-level"),
        pytest.param({"pickle_source": str(AGPL_ASSET)}, True, id="pickle-source-nested"),
        pytest.param({"category": "parse_error"}, False, id="parse-error-top-level"),
        pytest.param({"category": "parse_error"}, True, id="parse-error-nested"),
    ],
)
def test_organized_asset_scans_reject_operational_markers_before_benign_detail_skip(
    benign_detail: dict[str, Any],
    nested: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    operational_details = {
        **benign_detail,
        "analysis_incomplete": True,
        "scan_outcome": "inconclusive",
        "scan_outcome_reason": "scanner_error",
        "operational_error": True,
    }
    details: dict[str, Any] = operational_details
    if nested:
        details = {"findings": [{"details": operational_details}]}
    result.issues.append(
        Issue(
            message="Operational failure with otherwise benign details",
            severity=IssueSeverity.INFO,
            location=str(AGPL_ASSET),
            details=details,
        )
    )

    assert result.has_errors is False
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "operational marker")


def test_organized_asset_scans_reject_source_stability_diagnostic_without_has_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)

    assert result.has_errors is True
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    result.has_errors = False
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "source-stability diagnostic without has_errors",
        )


def test_organized_asset_scans_reject_bare_exception_on_source_stability_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    source_stability_issue = next(
        issue for issue in result.issues if issue.details.get("analysis") == "python_call_graph_source_stability"
    )
    source_stability_issue.details["exception"] = "scanner blew up"

    assert result.has_errors is True
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "source-stability diagnostic with bare exception",
        )


def test_organized_asset_scans_reject_mutated_source_stability_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "canonical source-stability identity",
    )

    accepted_mutations: list[str] = []
    for mutation in (
        "issue-rule",
        "issue-severity",
        "issue-type",
        "check-rule",
        "check-severity",
        "check-name",
        "issue-as-check",
        "check-as-issue",
        "duplicate-issue",
        "duplicate-check",
        "cross-owner",
    ):
        mutated = result.model_copy(deep=True)
        issue = next(
            candidate
            for candidate in mutated.issues
            if candidate.details.get("analysis") == "python_call_graph_source_stability"
        )
        check = next(
            candidate
            for candidate in mutated.checks
            if candidate.details.get("analysis") == "python_call_graph_source_stability"
        )
        if mutation == "issue-rule":
            issue.rule_code = "S999"
        elif mutation == "issue-severity":
            issue.severity = IssueSeverity.WARNING
        elif mutation == "issue-type":
            issue.type = "generic"
        elif mutation == "check-rule":
            check.rule_code = "S999"
        elif mutation == "check-severity":
            check.severity = IssueSeverity.WARNING
        elif mutation == "check-name":
            check.name = "Generic Operational Failure"
        elif mutation == "issue-as-check":
            mutated.issues.remove(issue)
            mutated.checks.append(check.model_copy(deep=True))
        elif mutation == "check-as-issue":
            mutated.checks.remove(check)
            mutated.issues.append(issue.model_copy(deep=True))
        elif mutation == "duplicate-issue":
            mutated.issues.append(issue.model_copy(deep=True))
        elif mutation == "duplicate-check":
            mutated.checks.append(check.model_copy(deep=True))
        else:
            copied_issue = issue.model_copy(deep=True)
            copied_issue.location = str(tmp_path / "unrelated.pkl")
            mutated.issues.append(copied_issue)

        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"source-stability diagnostic with {mutation}",
            )
        except AssertionError:
            continue
        accepted_mutations.append(mutation)

    assert not accepted_mutations, f"source-stability identity mutations were accepted: {accepted_mutations}"


def test_organized_asset_scans_reject_passed_source_stability_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    result.issues = [
        issue for issue in result.issues if issue.details.get("analysis") != "python_call_graph_source_stability"
    ]
    source_stability_check = next(
        check for check in result.checks if check.details.get("analysis") == "python_call_graph_source_stability"
    )
    source_stability_check.status = CheckStatus.PASSED

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "passed source-stability check",
        )


def test_organized_asset_scans_reject_additional_source_outcome_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    metadata = result.file_metadata[str(AGPL_ASSET)]
    assert metadata.model_extra is not None
    reasons = metadata.model_extra["scan_outcome_reasons"]
    assert isinstance(reasons, list)
    reasons.append("scanner_read_failed")

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "additional source outcome reason",
        )


@pytest.mark.parametrize(
    "error_details",
    [
        pytest.param({"error": "independent scanner failure"}, id="error"),
        pytest.param({"error_type": "RuntimeError"}, id="error-type"),
        pytest.param({"exception_type": "RuntimeError"}, id="exception-type"),
    ],
)
def test_organized_asset_scans_reject_pickle_diagnostic_error_fields(
    error_details: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    result.issues.append(
        Issue(
            message="Independent pickle scanner failure",
            severity=IssueSeverity.INFO,
            location=str(AGPL_ASSET),
            details={"pickle_source": str(AGPL_ASSET), **error_details},
        )
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "pickle diagnostic error field",
        )


@pytest.mark.parametrize("source_owner", ["metadata", "diagnostic"])
def test_organized_asset_scans_reject_mismatched_source_stability_pickle_source(
    source_owner: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    unrelated_source = str(tmp_path / "different.pkl")
    if source_owner == "metadata":
        metadata = result.file_metadata[str(AGPL_ASSET)]
        assert metadata.model_extra is not None
        metadata.model_extra["pickle_source"] = unrelated_source
    else:
        source_stability_issue = next(
            issue for issue in result.issues if issue.details.get("analysis") == "python_call_graph_source_stability"
        )
        source_stability_issue.details["pickle_source"] = unrelated_source

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"mismatched {source_owner} pickle source",
        )


@pytest.mark.parametrize(
    ("first_source_changes", "second_source_changes"),
    [(False, True), (True, False)],
    ids=["stable-to-changed", "changed-to-stable"],
)
def test_organized_asset_cache_preserves_source_stability_transitions(
    first_source_changes: bool,
    second_source_changes: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_changes = first_source_changes

    def enforce_source_stability(_report_generation: int | None) -> None:
        if source_changes:
            raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", enforce_source_stability)
    scan_results: list[tuple[bool, ModelAuditResultModel]] = []
    reset_cache_manager()
    try:
        for source_changes in (first_source_changes, second_source_changes):
            result = core_module.scan_model_directory_or_file(
                str(AGPL_ASSET),
                cache_enabled=True,
                cache_dir=str(tmp_path / "cache"),
                min_cache_file_size=0,
            )
            scan_results.append((source_changes, result))
        cache_stats = get_cache_manager(str(tmp_path / "cache"), enabled=True).get_stats()
    finally:
        reset_cache_manager()

    assert cache_stats["total_entries"] == 0
    assert cache_stats["cache_hits"] == 0
    assert cache_stats["cache_misses"] >= 2
    for expected_source_changes, result in scan_results:
        metadata = result.file_metadata[str(AGPL_ASSET)].model_dump(exclude_none=True)
        assert result.has_errors is expected_source_changes
        assert metadata["pickle_report_status"] == "inconclusive"
        assert metadata["pickle_verdict"] == "malicious"
        assert core_module.determine_exit_code(result) == (2 if expected_source_changes else 1)
        assert any(issue.rule_code == "S204" for issue in result.issues)
        assert (
            any(issue.details.get("analysis") == "python_call_graph_source_stability" for issue in result.issues)
            is expected_source_changes
        )
        assert result.success is False


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
def test_organized_asset_scans_reject_embedded_source_stability(
    integration_test: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    archive_path = tmp_path / "nested.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(AGPL_ASSET, "model.pkl")

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)

    assert result.has_errors is True
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    assert metadata["operational_error_reason"] == "call_graph_analysis_error"
    assert metadata["pickle_source"] != str(archive_path)
    assert any(
        issue.location == f"{archive_path}:model.pkl"
        and issue.details.get("pickle_source") == metadata["pickle_source"]
        and issue.details.get("analysis") == "python_call_graph_source_stability"
        for issue in result.issues
    )

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize("corruption", ["truncated-eocd", "overwritten-eocd-signature"])
def test_organized_asset_scans_require_corrupt_root_zip_evidence(
    corruption: str,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / f"{corruption}.zip"
    valid_payload = _zip_payload((("ordinary.txt", b"ordinary"),))
    eocd_offset = valid_payload.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    if corruption == "truncated-eocd":
        archive_path.write_bytes(valid_payload[: eocd_offset + 10])
    else:
        archive_path.write_bytes(valid_payload[:eocd_offset] + b"NOPE" + valid_payload[eocd_offset + 4 :])

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    assert metadata.model_extra["analysis_incomplete"] is True
    assert metadata.model_extra["scan_outcome"] == "inconclusive"
    assert metadata.model_extra["scan_outcome_reasons"] == ["zip_analysis_incomplete"]
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    assert any(issue.rule_code == "S902" for issue in result.issues)
    assert any(check.rule_code == "S902" and check.status == CheckStatus.FAILED for check in result.checks)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"canonical corrupt root ZIP ({corruption})",
    )

    without_hint = result.model_copy(deep=True)
    without_hint_metadata = without_hint.file_metadata[str(archive_path)]
    assert without_hint_metadata.model_extra is not None
    assert "zip" in without_hint_metadata.model_extra["scanner_dependency_ids"]
    without_hint_metadata.model_extra.pop("scanner_dependency_ids")
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        without_hint,
        f"canonical corrupt root ZIP without scanner hint ({corruption})",
    )

    for mutation in ("stripped", "corrupt", "duplicate"):
        mutated = result.model_copy(deep=True)
        mutated_metadata = mutated.file_metadata[str(archive_path)]
        assert mutated_metadata.model_extra is not None
        if mutation == "stripped":
            mutated.issues = [issue for issue in mutated.issues if issue.rule_code != "S902"]
            mutated.checks = [check for check in mutated.checks if check.rule_code != "S902"]
            for field in ("analysis_incomplete", "scan_outcome", "scan_outcome_reasons"):
                mutated_metadata.model_extra.pop(field, None)
            mutated.success = True
            assert core_module.determine_exit_code(mutated) == 0
        elif mutation == "corrupt":
            s902_issue = next(issue for issue in mutated.issues if issue.rule_code == "S902")
            s902_issue.details["path"] = f"{archive_path}.forged"
        else:
            s902_check = next(check for check in mutated.checks if check.rule_code == "S902")
            mutated.checks.append(s902_check.model_copy(deep=True))

        with pytest.raises(AssertionError, match="unexpected operational errors"):
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"corrupt root ZIP with {mutation} evidence ({corruption})",
            )

    for diagnostic_kind in ("issue", "check"):
        misplaced = result.model_copy(deep=True)
        if diagnostic_kind == "issue":
            source_issue = next(issue for issue in misplaced.issues if issue.rule_code == "S902")
            misplaced_issue = source_issue.model_copy(deep=True)
            misplaced_issue.location = f"{archive_path}:fake-member"
            misplaced.issues.append(misplaced_issue)
        else:
            source_check = next(check for check in misplaced.checks if check.rule_code == "S902")
            misplaced_check = source_check.model_copy(deep=True)
            misplaced_check.location = f"{archive_path}:fake-member"
            misplaced.checks.append(misplaced_check)

        with pytest.raises(AssertionError, match="unexpected operational errors"):
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                misplaced,
                f"corrupt root ZIP with misplaced {diagnostic_kind} ({corruption})",
            )

    archive_path.write_bytes(b"ordinary non-ZIP source")
    for keep_scanner_hint in (False, True):
        replaced_source = result.model_copy(deep=True)
        replaced_metadata = replaced_source.file_metadata[str(archive_path)]
        assert replaced_metadata.model_extra is not None
        if not keep_scanner_hint:
            replaced_metadata.model_extra.pop("scanner_dependency_ids", None)
        with pytest.raises(AssertionError, match="unexpected operational errors"):
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                replaced_source,
                f"non-ZIP source with retained corrupt diagnostics (hint={keep_scanner_hint})",
            )


def test_organized_asset_scans_preserve_nested_corrupt_zip_evidence(tmp_path: Path) -> None:
    valid_inner = _zip_payload((("ordinary.txt", b"ordinary"),))
    eocd_offset = valid_inner.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    corrupt_inner = valid_inner[: eocd_offset + 10]
    archive_path = tmp_path / "nested-corrupt.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("inner.zip", corrupt_inner)

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    assert result.success is False
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert any(
        diagnostic.rule_code == "S902" and diagnostic.location == f"{archive_path}:inner.zip"
        for diagnostic in diagnostics
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "canonical nested corrupt ZIP",
    )


def test_organized_asset_scans_preserve_nested_corrupt_zip_evidence_for_windows_path(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "nested-corrupt.zip"
    assert archive_path.parent == tmp_path
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("inner.zip", _corrupt_zip_payload())

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    nested_location = rf"{archive_path}:inner.zip"
    issues = [issue for issue in result.issues if issue.rule_code == "S902" and issue.location == nested_location]
    checks = [
        check
        for check in result.checks
        if check.name == "ZIP File Format Validation" and check.location == nested_location
    ]
    assert result.success is False
    assert len(issues) == 1
    assert len(checks) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "canonical nested corrupt ZIP with a Windows path",
    )


def test_organized_asset_scans_preserve_duplicate_nested_corrupt_zip_occurrences(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "duplicate-nested-corrupt.zip"
    corrupt_inner = _corrupt_zip_payload()
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("inner.zip", corrupt_inner)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("inner.zip", corrupt_inner)

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    nested_location = f"{archive_path}:inner.zip"
    issues = [issue for issue in result.issues if issue.rule_code == "S902" and issue.location == nested_location]
    checks = [
        check
        for check in result.checks
        if check.name == "ZIP File Format Validation" and check.location == nested_location
    ]
    assert len(issues) == 2
    assert len(checks) == 1
    assert checks[0].details == {
        "component_count": 2,
        "findings": [issue.details for issue in issues],
    }
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "canonical duplicate nested corrupt ZIP",
    )

    for mutation in (
        "missing-issue",
        "missing-check",
        "corrupt-check",
        "extra-issue",
        "extra-check",
        "duplicate-issue",
        "duplicate-check",
    ):
        mutated = result.model_copy(deep=True)
        nested_issues = [
            issue for issue in mutated.issues if issue.rule_code == "S902" and issue.location == nested_location
        ]
        nested_check = next(
            check
            for check in mutated.checks
            if check.name == "ZIP File Format Validation" and check.location == nested_location
        )
        if mutation == "missing-issue":
            mutated.issues.remove(nested_issues[0])
        elif mutation == "missing-check":
            mutated.checks.remove(nested_check)
        elif mutation == "corrupt-check":
            nested_check.details["findings"][0]["zip_entry"] = "forged.zip"
        elif mutation == "extra-issue":
            extra_issue = nested_issues[0].model_copy(deep=True)
            extra_issue.location = f"{nested_location}:fake"
            mutated.issues.append(extra_issue)
        elif mutation == "extra-check":
            extra_check = nested_check.model_copy(deep=True)
            extra_check.location = f"{nested_location}:fake"
            mutated.checks.append(extra_check)
        elif mutation == "duplicate-issue":
            mutated.issues.append(nested_issues[0].model_copy(deep=True))
        else:
            mutated.checks.append(nested_check.model_copy(deep=True))

        with pytest.raises(AssertionError, match="unexpected operational errors"):
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"duplicate nested corrupt ZIP with {mutation}",
            )


def test_organized_asset_scans_preserve_colon_bearing_nested_corrupt_zip_siblings(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "colon-bearing-nested-corrupt.zip"
    member_names = ("inner.zip", "inner.zip:other.zip")
    corrupt_inner = _corrupt_zip_payload()
    with zipfile.ZipFile(archive_path, "w") as archive:
        for member_name in member_names:
            archive.writestr(member_name, corrupt_inner)

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    expected_locations = {f"{archive_path}:{member_name}" for member_name in member_names}
    issues = [issue for issue in result.issues if issue.rule_code == "S902" and issue.location in expected_locations]
    checks = [
        check
        for check in result.checks
        if check.name == "ZIP File Format Validation" and check.location in expected_locations
    ]
    assert {issue.location for issue in issues} == expected_locations
    assert {check.location for check in checks} == expected_locations
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "canonical colon-bearing nested corrupt ZIP siblings",
    )

    for anchor_location in expected_locations:
        source_issue = next(issue for issue in issues if issue.location == anchor_location)
        source_check = next(check for check in checks if check.location == anchor_location)
        for diagnostic_kind in ("issue", "check"):
            mutated = result.model_copy(deep=True)
            fake_location = f"{anchor_location}:fake"
            if diagnostic_kind == "issue":
                fake_issue = source_issue.model_copy(deep=True)
                fake_issue.location = fake_location
                mutated.issues.append(fake_issue)
            else:
                fake_check = source_check.model_copy(deep=True)
                fake_check.location = fake_location
                mutated.checks.append(fake_check)

            with pytest.raises(AssertionError, match="unexpected operational errors"):
                test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                    mutated,
                    f"colon-bearing nested corrupt ZIP with fake {diagnostic_kind} at {fake_location}",
                )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "check"])
@pytest.mark.parametrize("marker_profile", ["canonical", "structural"])
def test_organized_asset_scans_reject_unbacked_nested_corrupt_zip_diagnostics(
    diagnostic_kind: str,
    marker_profile: str,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "nested-corrupt-with-safe-member.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("inner.zip", _corrupt_zip_payload())
        archive.writestr("ordinary.bin", b"ordinary")

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    nested_location = f"{archive_path}:inner.zip"
    source_issue = next(
        issue for issue in result.issues if issue.rule_code == "S902" and issue.location == nested_location
    )
    source_check = next(
        check
        for check in result.checks
        if check.name == "ZIP File Format Validation" and check.location == nested_location
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "canonical nested corrupt ZIP with safe sibling",
    )

    invalid_locations = (
        f"{archive_path}:ordinary.bin",
        f"{archive_path}:fabricated.zip",
        str(archive_path),
        str(tmp_path / "unrelated.zip"),
    )
    for invalid_location in invalid_locations:
        mutated = result.model_copy(deep=True)
        if diagnostic_kind == "issue":
            copied_issue = source_issue.model_copy(deep=True)
            copied_issue.location = invalid_location
            if marker_profile == "structural":
                copied_issue.message = "Corrupt archive payload"
            mutated.issues.append(copied_issue)
        else:
            copied_check = source_check.model_copy(deep=True)
            copied_check.location = invalid_location
            if marker_profile == "structural":
                copied_check.name = "Archive Payload Validation"
                copied_check.message = "Corrupt archive payload"
            mutated.checks.append(copied_check)

        with pytest.raises(AssertionError, match="unexpected operational errors"):
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"nested corrupt ZIP with unbacked {marker_profile} {diagnostic_kind} at {invalid_location}",
            )


def test_organized_asset_scans_reject_zip_shaped_s902_on_clean_zip(
    tmp_path: Path,
) -> None:
    source_archive_path = tmp_path / "source-nested-corrupt.zip"
    with zipfile.ZipFile(source_archive_path, "w") as archive:
        archive.writestr("inner.zip", _corrupt_zip_payload())
    source_result = core_module.scan_model_directory_or_file(str(source_archive_path), cache_enabled=False)
    source_issue = next(issue for issue in source_result.issues if issue.rule_code == "S902")

    clean_archive_path = tmp_path / "clean.zip"
    with zipfile.ZipFile(clean_archive_path, "w") as archive:
        archive.writestr("ordinary.bin", b"ordinary")
    clean_result = core_module.scan_model_directory_or_file(str(clean_archive_path), cache_enabled=False)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        clean_result,
        "canonical clean ZIP",
    )

    copied_issue = source_issue.model_copy(deep=True)
    copied_issue.location = f"{clean_archive_path}:fabricated.zip"
    copied_issue.message = "Corrupt archive payload"
    clean_result.issues.append(copied_issue)
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            clean_result,
            "clean ZIP with structurally ZIP-shaped S902 issue",
        )


def test_zip_format_marker_does_not_classify_non_zip_s902(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "msgpack-s902.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("weights.msgpack", b"\x81\xa6params\x80" * 2)

    result = core_module.scan_model_directory_or_file(
        str(archive_path),
        cache_enabled=False,
        max_msgpack_stream_objects=1,
    )
    diagnostics: list[Issue | Check] = list(result.issues)
    diagnostics.extend(result.checks)
    diagnostics = [diagnostic for diagnostic in diagnostics if diagnostic.rule_code == "S902"]
    assert len(diagnostics) == 2
    for diagnostic in diagnostics:
        assert not test_security_asset_integration._zip_format_diagnostic_has_explicit_marker(diagnostic)

        mutated = diagnostic.model_copy(deep=True)
        mutated.message = "Corrupt archive payload"
        mutated.details["path_hint"] = str(tmp_path / "not-a-zip-source")
        if isinstance(mutated, Check):
            mutated.name = "Archive Payload Validation"
        assert not test_security_asset_integration._zip_format_diagnostic_has_explicit_marker(mutated)


def _plausible_hdf5_v0_payload(
    signature_offset: int = 0,
    *,
    file_size: int | None = None,
    signature: bytes = b"\x89HDF\r\n\x1a\n",
) -> bytes:
    payload_size = max(signature_offset + 144, file_size or 0)
    payload = bytearray(payload_size)
    payload[signature_offset : signature_offset + len(signature)] = signature
    payload[signature_offset + 13] = 8
    payload[signature_offset + 14] = 8
    payload[signature_offset + 16 : signature_offset + 18] = (4).to_bytes(2, "little")
    payload[signature_offset + 18 : signature_offset + 20] = (16).to_bytes(2, "little")
    payload[signature_offset + 24 : signature_offset + 32] = signature_offset.to_bytes(8, "little")
    payload[signature_offset + 40 : signature_offset + 48] = payload_size.to_bytes(8, "little")
    return bytes(payload)


def _write_sparse_plausible_hdf5_v0(
    path: Path,
    signature_offset: int,
    *,
    file_size: int | None = None,
) -> None:
    payload_size = max(signature_offset + 144, file_size or 0)
    superblock = bytearray(144)
    superblock[:8] = b"\x89HDF\r\n\x1a\n"
    superblock[13] = 8
    superblock[14] = 8
    superblock[16:18] = (4).to_bytes(2, "little")
    superblock[18:20] = (16).to_bytes(2, "little")
    superblock[24:32] = signature_offset.to_bytes(8, "little")
    superblock[40:48] = payload_size.to_bytes(8, "little")
    with path.open("wb") as source:
        source.truncate(payload_size)
        source.seek(signature_offset)
        source.write(superblock)


def _scan_nested_hdf5_with_missing_h5py(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_ambiguous_xml: bool = False,
    signature_offset: int = 0,
    member_payload: bytes | None = None,
    nested_archive_name: str | None = None,
) -> tuple[Path, ModelAuditResultModel]:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "nested-hdf5-missing-h5py.zip"
    hdf5_payload = _plausible_hdf5_v0_payload(signature_offset) if member_payload is None else member_payload
    with zipfile.ZipFile(archive_path, "w") as archive:
        if nested_archive_name is None:
            archive.writestr("weights.h5", hdf5_payload)
        else:
            archive.writestr(nested_archive_name, _zip_payload((("weights.h5", hdf5_payload),)))
        if include_ambiguous_xml:
            archive.writestr("ambiguous.txt", AMBIGUOUS_XML_PAYLOAD)
    return archive_path, test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )


def test_organized_asset_scans_preserve_nested_hdf5_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(tmp_path, monkeypatch)
    member_location = f"{archive_path}:weights.h5"
    metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
    dependency_issues = [
        issue
        for issue in result.issues
        if issue.location == member_location
        and issue.rule_code == "S902"
        and issue.details.get("required_package") == "h5py"
    ]
    dependency_checks = [
        check
        for check in result.checks
        if check.location == member_location
        and check.name == "H5PY Library Check"
        and check.status == CheckStatus.FAILED
    ]
    assert metadata["analysis_incomplete"] is True
    assert metadata["scan_outcome"] == "inconclusive"
    assert metadata["scan_outcome_reasons"] == ["keras_h5_h5py_unavailable", "zip_analysis_incomplete"]
    assert len(dependency_issues) == 1
    assert len(dependency_checks) == 1
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "nested HDF5 with h5py unavailable",
    )


@pytest.mark.parametrize("signature_offset", [2 * 1024 * 1024, 8 * 1024 * 1024])
def test_organized_asset_scans_preserve_bounded_hdf5_userblock_dependency(
    signature_offset: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        signature_offset=signature_offset,
    )
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"nested HDF5 with {signature_offset}-byte userblock",
    )


def test_organized_asset_scans_preserve_second_level_nested_hdf5_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    member_location = f"{archive_path}:inner.zip:weights.h5"
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert any(
        diagnostic.location == member_location
        and diagnostic.details.get("scan_outcome_reason") == "keras_h5_h5py_unavailable"
        for diagnostic in diagnostics
    )
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "second-level nested HDF5 with h5py unavailable",
    )


def test_organized_asset_scans_preserve_bounded_hdf5_dependency_with_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        signature_offset=8 * 1024 * 1024,
    )
    result.issues.append(
        Issue(
            message="Embedded executable payload",
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:payload.pkl",
            rule_code="S204",
        )
    )
    assert result.success is False
    assert core_module.determine_exit_code(result) == 1

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "bounded HDF5 dependency with a security finding",
    )


@pytest.mark.parametrize(
    "source_shape",
    ["beyond-bound", "non-power-offset", "near-magic", "truncated-superblock"],
)
def test_organized_asset_scans_reject_unproven_hdf5_dependency_sources(
    source_shape: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if source_shape == "beyond-bound":
        payload = _plausible_hdf5_v0_payload(16 * 1024 * 1024)
    elif source_shape == "non-power-offset":
        payload = _plausible_hdf5_v0_payload(3 * 1024 * 1024)
    elif source_shape == "near-magic":
        payload = _plausible_hdf5_v0_payload(
            2 * 1024 * 1024,
            signature=b"\x89HDF\r\n\x1a\x00",
        )
    else:
        payload = b"\x89HDF\r\n\x1a\n\x00\x00\x00\x00"

    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        member_payload=payload,
    )
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert any(
        diagnostic.location == f"{archive_path}:weights.h5" and diagnostic.details.get("required_package") == "h5py"
        for diagnostic in diagnostics
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"unproven HDF5 dependency source: {source_shape}",
        )


@pytest.mark.parametrize("nested_archive_name", ["inner.zip", "dir:inner.zip"])
def test_organized_asset_scans_preserve_nested_archive_hdf5_provenance(
    nested_archive_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name=nested_archive_name,
    )
    member_location = f"{archive_path}:{nested_archive_name}:weights.h5"
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert any(
        diagnostic.location == member_location
        and diagnostic.details.get("zip_entry") == f"{nested_archive_name}:weights.h5"
        for diagnostic in diagnostics
    )

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"nested archive HDF5 provenance for {nested_archive_name}",
    )


def test_organized_asset_scans_preserve_duplicate_nested_hdf5_occurrences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    payload = _plausible_hdf5_v0_payload()
    archive_path, result = _scan_duplicate_nested_zip_archives(
        tmp_path,
        (("weights.h5", payload),),
        (("weights.h5", payload),),
    )
    member_location = f"{archive_path}:inner.zip:weights.h5"
    dependency_issues = [
        issue
        for issue in result.issues
        if issue.location == member_location and issue.details.get("required_package") == "h5py"
    ]
    dependency_checks = [
        check for check in result.checks if check.location == member_location and check.name == "H5PY Library Check"
    ]
    assert len(dependency_issues) == 1
    assert len(dependency_checks) == 1
    assert dependency_checks[0].details.get("component_count") == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "duplicate nested HDF5 occurrences",
    )


def test_organized_asset_scans_preserve_independent_nested_hdf5_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results: list[ModelAuditResultModel] = []
    for index in range(2):
        root = tmp_path / str(index)
        root.mkdir()
        _archive_path, result = _scan_nested_hdf5_with_missing_h5py(
            root,
            monkeypatch,
            nested_archive_name=f"inner-{index}.zip",
        )
        results.append(result)
    results[0].aggregate_scan_result(results[1])
    test_security_asset_integration._merge_test_zip_extraction_manifests(
        results[0],
        *results,
    )

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        results[0],
        "independent nested HDF5 roots",
    )


@pytest.mark.parametrize("record_kind", ["issue", "check"])
@pytest.mark.parametrize("severity", [IssueSeverity.WARNING, IssueSeverity.CRITICAL])
def test_organized_asset_scans_preserve_nested_hdf5_aggregate_security_precedence(
    severity: IssueSeverity,
    record_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results: list[tuple[Path, ModelAuditResultModel]] = []
    for index in range(2):
        root = tmp_path / str(index)
        root.mkdir()
        results.append(_scan_nested_hdf5_with_missing_h5py(root, monkeypatch))
    second_archive, second_result = results[1]
    finding_location = f"{second_archive}:payload.pkl"
    if record_kind == "issue":
        second_result.issues.append(
            Issue(
                message="Separate-root security finding",
                severity=severity,
                location=finding_location,
                rule_code="S204",
            )
        )
    else:
        second_result.checks.append(
            Check(
                name="Separate Root Security Check",
                status=CheckStatus.FAILED,
                message="Separate-root security finding",
                severity=severity,
                location=finding_location,
                rule_code="S204",
            )
        )
    aggregate = results[0][1]
    aggregate.aggregate_scan_result(second_result)
    test_security_asset_integration._merge_test_zip_extraction_manifests(
        aggregate,
        aggregate,
        second_result,
    )

    assert aggregate.success is False
    assert core_module.determine_exit_code(aggregate) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        aggregate,
        f"nested HDF5 aggregate with separate-root {severity.value} {record_kind}",
    )


@pytest.mark.parametrize("archive_profile", ["root", "nested"])
@pytest.mark.parametrize("record_kind", ["issue", "check"])
@pytest.mark.parametrize("severity", [IssueSeverity.WARNING, IssueSeverity.CRITICAL])
def test_organized_asset_scans_preserve_corrupt_zip_aggregate_security_precedence(
    severity: IssueSeverity,
    record_kind: str,
    archive_profile: str,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / f"{archive_profile}-corrupt.zip"
    if archive_profile == "root":
        archive_path.write_bytes(_corrupt_zip_payload())
    else:
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("inner.zip", _corrupt_zip_payload())
    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)

    security_result = _scan_asset("safe_data.pkl")
    finding_location = str(ASSETS / "safe_data.pkl")
    if record_kind == "issue":
        security_result.issues.append(
            Issue(
                message="Separate-root security finding",
                severity=severity,
                location=finding_location,
                rule_code="S204",
            )
        )
    else:
        security_result.checks.append(
            Check(
                name="Separate Root Security Check",
                status=CheckStatus.FAILED,
                message="Separate-root security finding",
                severity=severity,
                location=finding_location,
                rule_code="S204",
            )
        )
    result.aggregate_scan_result(security_result)

    assert result.success is False
    assert core_module.determine_exit_code(result) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"{archive_profile} corrupt ZIP aggregate with separate-root {severity.value} {record_kind}",
    )


def test_zip_archive_contract_closes_nested_temp_before_recursive_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _archive_path, result = _scan_nested_zip_archive(tmp_path, (("ordinary.txt", b"ordinary"),))
    opened_files: list[Any] = []
    real_named_temporary_file = tempfile.NamedTemporaryFile
    real_open_preflighted_zip = test_security_asset_integration.open_preflighted_zip

    def tracked_named_temporary_file(*args: Any, **kwargs: Any) -> Any:
        handle = real_named_temporary_file(*args, **kwargs)
        opened_files.append(handle)
        return handle

    def guarded_open_preflighted_zip(archive_path: str, config: dict[str, int]) -> Any:
        assert all(handle.closed for handle in opened_files if handle.name == archive_path)
        return real_open_preflighted_zip(archive_path, config)

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", tracked_named_temporary_file)
    monkeypatch.setattr(test_security_asset_integration, "open_preflighted_zip", guarded_open_preflighted_zip)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "nested archive whose temporary file must be closed before recursion",
    )
    assert opened_files
    assert all(not Path(handle.name).exists() for handle in opened_files)


@pytest.mark.parametrize("malformation", ["success", "has-errors"])
def test_organized_asset_scans_reject_malformed_nested_hdf5_aggregate_state(
    malformation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _archive_path, result = _scan_nested_hdf5_with_missing_h5py(tmp_path, monkeypatch)
    assert result.success is False
    assert core_module.determine_exit_code(result) == 2
    if malformation == "success":
        result.success = True
    else:
        result.has_errors = True

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"nested HDF5 aggregate with malformed {malformation} state",
        )


def test_organized_asset_scans_reject_forged_nested_hdf5_temp_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _archive_path, result = _scan_nested_hdf5_with_missing_h5py(tmp_path, monkeypatch)
    temp_root = Path(tempfile.gettempdir())
    forged_paths = {
        "attacker-parent": tmp_path / "attacker" / "fake_weights.h5",
        "wrong-parent": tmp_path / "tmpabcdefgh_weights.h5",
        "wrong-generated-name": temp_root / "fake_weights.h5",
        "correct-shape-nonexistent": temp_root / f"{tempfile.gettempprefix()}zzzzzzzz_weights.h5",
    }
    accepted_mutations: list[str] = []
    for mutation, forged_path in forged_paths.items():
        mutated = result.model_copy(deep=True)
        diagnostics: list[Issue | Check] = [*mutated.issues, *mutated.checks]
        for diagnostic in diagnostics:
            if diagnostic.details.get("required_package") == "h5py":
                diagnostic.details["path"] = str(forged_path)
        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"nested HDF5 with {mutation} temp path",
            )
        except AssertionError:
            continue
        accepted_mutations.append(mutation)

    assert not accepted_mutations, f"forged nested HDF5 temp paths were accepted: {accepted_mutations}"


def test_organized_asset_scans_reject_cross_occurrence_nested_hdf5_temp_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "distinct-hdf5-occurrences.zip"
    payload = _plausible_hdf5_v0_payload()
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("left/weights.h5", payload)
        archive.writestr("right/weights.h5", payload)
    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "distinct nested HDF5 temp-path occurrences",
    )

    issues = [issue for issue in result.issues if issue.details.get("required_package") == "h5py"]
    assert len(issues) == 2
    first_path = issues[0].details["path"]
    second_location = issues[1].location
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.location == second_location and diagnostic.details.get("required_package") == "h5py":
            diagnostic.details["path"] = first_path

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "cross-occurrence nested HDF5 temp path",
        )


def test_organized_asset_scans_reject_distinct_nonexistent_nested_hdf5_temp_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "distinct-forged-hdf5-occurrences.zip"
    payload = _plausible_hdf5_v0_payload()
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("left/weights.h5", payload)
        archive.writestr("right/weights.h5", payload)
    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    issues = [issue for issue in result.issues if issue.details.get("required_package") == "h5py"]
    assert len(issues) == 2
    temp_root = Path(tempfile.gettempdir())
    forged_paths = {
        issue.location: temp_root / f"{tempfile.gettempprefix()}zzzzzzz{index}_weights.h5"
        for index, issue in enumerate(issues)
    }
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.location in forged_paths and diagnostic.details.get("required_package") == "h5py":
            diagnostic.details["path"] = str(forged_paths[diagnostic.location])

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "distinct nonexistent nested HDF5 temp paths",
        )


@pytest.mark.parametrize("profile", ["nested-hdf5", "xml"])
@pytest.mark.parametrize("manifest_mutation", ["missing-event", "duplicate-event"])
def test_organized_asset_scans_require_exact_extraction_manifest_events(
    profile: str,
    manifest_mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if profile == "nested-hdf5":
        _archive_path, result = _scan_nested_hdf5_with_missing_h5py(tmp_path, monkeypatch)
        source_path = next(
            issue.details["path"] for issue in result.issues if issue.details.get("required_package") == "h5py"
        )
    else:
        _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("ambiguous.txt",))
        source_path = next(
            issue.details["path"] for issue in result.issues if issue.details.get("format") == "xml_model_inconclusive"
        )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"{profile} with exact extraction manifest",
    )
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    assert manifest is not None
    event_index = next(index for index, event in enumerate(manifest.events) if event.temp_path == source_path)
    mutated = result.model_copy(deep=True)
    if manifest_mutation == "missing-event":
        mutated_manifest = manifest.without_event(event_index)
    else:
        mutated_manifest = manifest.with_duplicate_event(event_index)
    test_security_asset_integration._set_test_zip_extraction_manifest(
        mutated,
        mutated_manifest,
        source=result,
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            mutated,
            f"{profile} with {manifest_mutation} extraction manifest",
        )


@pytest.mark.parametrize(
    "manifest_mutation",
    [
        "coherent-fake-path",
        "zero-size",
        "wrong-size",
        "source-crc",
        "extracted-crc",
        "occurrence-index",
        "wrong-member",
    ],
)
def test_organized_asset_scans_reject_unverified_extraction_manifest_events(
    manifest_mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _archive_path, result = _scan_nested_hdf5_with_missing_h5py(tmp_path, monkeypatch)
    source_path = next(
        issue.details["path"] for issue in result.issues if issue.details.get("required_package") == "h5py"
    )
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    assert manifest is not None
    event_index = next(index for index, event in enumerate(manifest.events) if event.temp_path == source_path)
    event = manifest.events[event_index]

    def build_event(
        *,
        verified: bool = False,
        temp_path: str | None = None,
        entry_name: str | None = None,
        entry_occurrence: int | None = None,
        source_occurrence_count: int | None = None,
        source_size: int | None = None,
        source_crc32: int | None = None,
        extracted_size: int | None = None,
        extracted_crc32: int | None = None,
    ) -> test_security_asset_integration._ZipExtractionEvent:
        resolved_temp_path = event.temp_path if temp_path is None else temp_path
        resolved_entry_name = event.entry_name if entry_name is None else entry_name
        resolved_entry_occurrence = event.entry_occurrence if entry_occurrence is None else entry_occurrence
        resolved_source_occurrence_count = (
            event.source_occurrence_count if source_occurrence_count is None else source_occurrence_count
        )
        resolved_source_size = event.source_size if source_size is None else source_size
        resolved_source_crc32 = event.source_crc32 if source_crc32 is None else source_crc32
        resolved_extracted_size = event.extracted_size if extracted_size is None else extracted_size
        resolved_extracted_crc32 = event.extracted_crc32 if extracted_crc32 is None else extracted_crc32
        if verified:
            return test_security_asset_integration._captured_zip_extraction_event(
                generation_id=event.generation_id,
                temp_path=resolved_temp_path,
                archive_path=event.archive_path,
                entry_name=resolved_entry_name,
                entry_occurrence=resolved_entry_occurrence,
                source_occurrence_count=resolved_source_occurrence_count,
                source_header_offset=event.source_header_offset,
                source_size=resolved_source_size,
                source_crc32=resolved_source_crc32,
                extracted_size=resolved_extracted_size,
                extracted_crc32=resolved_extracted_crc32,
            )
        return test_security_asset_integration._ZipExtractionEvent(
            generation_id=event.generation_id,
            temp_path=resolved_temp_path,
            archive_path=event.archive_path,
            entry_name=resolved_entry_name,
            entry_occurrence=resolved_entry_occurrence,
            source_occurrence_count=resolved_source_occurrence_count,
            source_header_offset=event.source_header_offset,
            source_size=resolved_source_size,
            source_crc32=resolved_source_crc32,
            extracted_size=resolved_extracted_size,
            extracted_crc32=resolved_extracted_crc32,
        )

    if manifest_mutation == "coherent-fake-path":
        forged_path = str(Path(tempfile.gettempdir()) / f"{tempfile.gettempprefix()}zzzzzzzz_weights.h5")
        diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
        for diagnostic in diagnostics:
            if diagnostic.details.get("required_package") == "h5py":
                diagnostic.details["path"] = forged_path
        mutated_event = build_event(temp_path=forged_path)
    elif manifest_mutation == "occurrence-index":
        mutated_event = build_event(
            entry_occurrence=event.entry_occurrence + 1,
            source_occurrence_count=max(event.source_occurrence_count, 2),
        )
    elif manifest_mutation == "wrong-member":
        mutated_event = build_event(entry_name="other/weights.h5")
    elif manifest_mutation == "zero-size":
        mutated_event = build_event(verified=True, extracted_size=0)
    elif manifest_mutation == "wrong-size":
        mutated_event = build_event(verified=True, extracted_size=event.extracted_size + 1)
    elif manifest_mutation == "source-crc":
        mutated_event = build_event(verified=True, source_crc32=event.source_crc32 ^ 1)
    else:
        mutated_event = build_event(verified=True, extracted_crc32=event.extracted_crc32 ^ 1)
    mutated_events = list(manifest.events)
    mutated_events[event_index] = mutated_event
    test_security_asset_integration._set_test_zip_extraction_manifest(
        result,
        test_security_asset_integration._ZipExtractionManifest(tuple(mutated_events)),
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"nested HDF5 with {manifest_mutation} extraction event",
        )


def test_organized_asset_scans_reject_cross_assigned_extraction_manifest_occurrences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "cross-assigned-extraction-events.zip"
    left_payload = bytearray(_plausible_hdf5_v0_payload(file_size=256))
    right_payload = bytearray(left_payload)
    right_payload[-1] = 1
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("left/weights.h5", left_payload)
        archive.writestr("right/weights.h5", right_payload)
    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    assert manifest is not None
    event_indices = {
        event.entry_name: index
        for index, event in enumerate(manifest.events)
        if event.entry_name in {"left/weights.h5", "right/weights.h5"}
    }
    assert set(event_indices) == {"left/weights.h5", "right/weights.h5"}
    left_event = manifest.events[event_indices["left/weights.h5"]]
    right_event = manifest.events[event_indices["right/weights.h5"]]
    assert left_event.source_size == right_event.source_size
    assert left_event.source_crc32 != right_event.source_crc32
    swapped_paths = {
        f"{archive_path}:left/weights.h5": right_event.temp_path,
        f"{archive_path}:right/weights.h5": left_event.temp_path,
    }
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.location in swapped_paths and diagnostic.details.get("required_package") == "h5py":
            diagnostic.details["path"] = swapped_paths[diagnostic.location]
    mutated_events = list(manifest.events)
    mutated_events[event_indices["left/weights.h5"]] = test_security_asset_integration._ZipExtractionEvent(
        generation_id=left_event.generation_id,
        temp_path=right_event.temp_path,
        archive_path=left_event.archive_path,
        entry_name=left_event.entry_name,
        entry_occurrence=left_event.entry_occurrence,
        source_occurrence_count=left_event.source_occurrence_count,
        source_header_offset=left_event.source_header_offset,
        source_size=right_event.source_size,
        source_crc32=right_event.source_crc32,
        extracted_size=right_event.extracted_size,
        extracted_crc32=right_event.extracted_crc32,
    )
    mutated_events[event_indices["right/weights.h5"]] = test_security_asset_integration._ZipExtractionEvent(
        generation_id=right_event.generation_id,
        temp_path=left_event.temp_path,
        archive_path=right_event.archive_path,
        entry_name=right_event.entry_name,
        entry_occurrence=right_event.entry_occurrence,
        source_occurrence_count=right_event.source_occurrence_count,
        source_header_offset=right_event.source_header_offset,
        source_size=left_event.source_size,
        source_crc32=left_event.source_crc32,
        extracted_size=left_event.extracted_size,
        extracted_crc32=left_event.extracted_crc32,
    )
    test_security_asset_integration._set_test_zip_extraction_manifest(
        result,
        test_security_asset_integration._ZipExtractionManifest(tuple(mutated_events)),
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "cross-assigned extraction event occurrences",
        )


def test_organized_asset_scans_preserve_skipped_duplicate_extraction_occurrence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "skipped-duplicate-extraction.zip"
    hdf5_payload = _plausible_hdf5_v0_payload()
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("weights.h5", COMPRESSION_BOMB_PAYLOAD)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("weights.h5", hdf5_payload)

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    assert manifest is not None
    extracted_events = [event for event in manifest.events if event.entry_name == "weights.h5"]
    assert len(extracted_events) == 1
    assert extracted_events[0].entry_occurrence == 1
    assert any(issue.rule_code == "S410" for issue in result.issues)
    assert any(issue.details.get("required_package") == "h5py" for issue in result.issues)
    assert core_module.determine_exit_code(result) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "skipped first duplicate extraction occurrence",
    )


def test_organized_asset_scans_bind_skipped_identical_duplicate_to_actual_source_occurrence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "skipped-identical-duplicate-extraction.zip"
    hdf5_payload = _plausible_hdf5_v0_payload(file_size=2 * 1024 * 1024)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("weights.h5", hdf5_payload, compress_type=zipfile.ZIP_DEFLATED)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("weights.h5", hdf5_payload, compress_type=zipfile.ZIP_STORED)
    with zipfile.ZipFile(archive_path) as archive:
        source_entries = archive.infolist()
    assert len(source_entries) == 2
    assert source_entries[0].CRC == source_entries[1].CRC
    assert source_entries[0].file_size == source_entries[1].file_size

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    assert manifest is not None
    event = next(event for event in manifest.events if event.entry_name == "weights.h5")
    assert event.entry_occurrence == 1
    assert event.source_header_offset == source_entries[1].header_offset
    assert any(issue.rule_code == "S410" for issue in result.issues)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "skipped identical duplicate extraction occurrence",
    )

    mutated = result.model_copy(deep=True)
    mutated_event = test_security_asset_integration._captured_zip_extraction_event(
        generation_id=event.generation_id,
        temp_path=event.temp_path,
        archive_path=event.archive_path,
        entry_name=event.entry_name,
        entry_occurrence=0,
        source_occurrence_count=event.source_occurrence_count,
        source_header_offset=source_entries[0].header_offset,
        source_size=event.source_size,
        source_crc32=event.source_crc32,
        extracted_size=event.extracted_size,
        extracted_crc32=event.extracted_crc32,
    )
    event_index = manifest.events.index(event)
    mutated_events = list(manifest.events)
    mutated_events[event_index] = mutated_event
    test_security_asset_integration._set_test_zip_extraction_manifest(
        mutated,
        test_security_asset_integration._ZipExtractionManifest(tuple(mutated_events)),
        source=result,
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            mutated,
            "tampered skipped identical duplicate extraction occurrence",
        )


def test_organized_asset_scans_preserve_identical_duplicate_extraction_occurrences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "identical-duplicate-extraction.zip"
    hdf5_payload = _plausible_hdf5_v0_payload()
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("weights.h5", hdf5_payload)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("weights.h5", hdf5_payload)

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    assert manifest is not None
    extracted_events = [event for event in manifest.events if event.entry_name == "weights.h5"]
    assert len(extracted_events) == 2
    assert [event.entry_occurrence for event in extracted_events] == [0, 1]
    assert len({event.source_header_offset for event in extracted_events}) == 2
    assert len({event.source_crc32 for event in extracted_events}) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "identical duplicate extraction occurrences",
    )


@pytest.mark.parametrize("nested_archive_name", [None, "inner.zip"])
def test_organized_asset_scans_reject_root_zip_changed_before_manifest_freeze(
    nested_archive_name: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "changed-before-manifest-freeze.zip"
    first_payload = bytearray(_plausible_hdf5_v0_payload(file_size=256))
    second_payload = bytearray(first_payload)
    second_payload[-1] = 1

    def write_root(member_payload: bytes) -> None:
        with zipfile.ZipFile(archive_path, "w") as archive:
            if nested_archive_name is None:
                archive.writestr("weights.h5", member_payload)
            else:
                archive.writestr(nested_archive_name, _zip_payload((("weights.h5", member_payload),)))

    write_root(bytes(first_payload))
    original_freeze = test_security_asset_integration._ZipExtractionRecorder.freeze

    def overwrite_before_freeze(
        recorder: test_security_asset_integration._ZipExtractionRecorder,
    ) -> tuple[
        test_security_asset_integration._ZipExtractionManifest,
        test_security_asset_integration._ZipExtractionGeneration | None,
    ]:
        write_root(bytes(second_payload))
        return original_freeze(recorder)

    monkeypatch.setattr(
        test_security_asset_integration._ZipExtractionRecorder,
        "freeze",
        overwrite_before_freeze,
    )
    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"root ZIP changed before manifest freeze for {nested_archive_name or 'direct member'}",
        )


@pytest.mark.parametrize("nested_archive_name", [None, "inner.zip"])
def test_organized_asset_scans_reject_stale_extraction_manifest_replay(
    nested_archive_name: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_payload = bytearray(_plausible_hdf5_v0_payload(file_size=256))
    second_payload = bytearray(first_payload)
    second_payload[-1] = 1
    archive_path, first_result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        member_payload=bytes(first_payload),
        nested_archive_name=nested_archive_name,
    )
    first_manifest = test_security_asset_integration._test_zip_extraction_manifest(first_result)
    assert first_manifest is not None
    first_source_path = next(
        issue.details["path"] for issue in first_result.issues if issue.details.get("required_package") == "h5py"
    )

    rewritten_archive_path, second_result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        member_payload=bytes(second_payload),
        nested_archive_name=nested_archive_name,
    )
    assert rewritten_archive_path == archive_path
    second_manifest = test_security_asset_integration._test_zip_extraction_manifest(second_result)
    assert second_manifest is not None
    second_hdf_event = next(event for event in second_manifest.events if event.entry_name == "weights.h5")
    first_hdf_event = next(event for event in first_manifest.events if event.entry_name == "weights.h5")
    assert first_hdf_event.source_crc32 != second_hdf_event.source_crc32
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            first_result,
            f"changed extraction source snapshot for {nested_archive_name or 'direct member'}",
        )
    diagnostics: list[Issue | Check] = [*second_result.issues, *second_result.checks]
    for diagnostic in diagnostics:
        if diagnostic.details.get("required_package") == "h5py":
            diagnostic.details["path"] = first_source_path
    test_security_asset_integration._set_test_zip_extraction_manifest(second_result, first_manifest)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            second_result,
            f"stale extraction manifest replay for {nested_archive_name or 'direct member'}",
        )


@pytest.mark.parametrize(
    "rewrite_before_freeze",
    [False, True],
    ids=["after-freeze", "before-freeze"],
)
def test_organized_asset_scans_reject_root_zip_crc32_collision_rewrite(
    rewrite_before_freeze: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    archive_path = tmp_path / "crc32-collision-rewrite.zip"
    payload_prefix = _plausible_hdf5_v0_payload(file_size=256)[:-8]
    first_payload = payload_prefix + bytes.fromhex("fa3cfb3f1bb823aa")
    second_payload = payload_prefix + bytes.fromhex("af84d31d6d078015")
    assert first_payload != second_payload
    assert len(first_payload) == len(second_payload)
    assert zlib.crc32(first_payload) == zlib.crc32(second_payload)

    def write_root(payload: bytes) -> None:
        entry = zipfile.ZipInfo("weights.h5", date_time=(2020, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_STORED
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(entry, payload)

    write_root(first_payload)
    if rewrite_before_freeze:
        original_freeze = test_security_asset_integration._ZipExtractionRecorder.freeze

        def overwrite_before_freeze(
            recorder: test_security_asset_integration._ZipExtractionRecorder,
        ) -> tuple[
            test_security_asset_integration._ZipExtractionManifest,
            test_security_asset_integration._ZipExtractionGeneration | None,
        ]:
            write_root(second_payload)
            return original_freeze(recorder)

        monkeypatch.setattr(
            test_security_asset_integration._ZipExtractionRecorder,
            "freeze",
            overwrite_before_freeze,
        )
    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_path),
        cache_enabled=False,
    )
    generation = next(iter(test_security_asset_integration._test_zip_extraction_generations(result).values()))
    root_snapshot = next(
        snapshot for snapshot in generation.root_snapshots if snapshot.archive_path == str(archive_path)
    )
    assert root_snapshot.unchanged_at_freeze is not rewrite_before_freeze

    if not rewrite_before_freeze:
        write_root(second_payload)
    assert (
        test_security_asset_integration._zip_central_directory_fingerprint(str(archive_path))
        == root_snapshot.central_directory_fingerprint
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "root ZIP rewritten with a distinct same-length CRC32 collision "
            f"{'before' if rewrite_before_freeze else 'after'} manifest freeze",
        )


def test_zip_extraction_manifest_normalization_has_bounded_work() -> None:
    event_count = test_security_asset_integration._TEST_ZIP_EXTRACTION_MANIFEST_MAX_EVENTS
    manifest = test_security_asset_integration._ZipExtractionManifest(
        tuple(
            test_security_asset_integration._captured_zip_extraction_event(
                temp_path=f"/not-a-real-temp-root/extracted-{index}.bin",
                archive_path="/archives/root.zip",
                entry_name=f"member-{index}.bin",
                entry_occurrence=0,
                source_occurrence_count=1,
                source_size=1,
                source_crc32=index & test_security_asset_integration.UINT32_MASK,
                extracted_size=1,
                extracted_crc32=index & test_security_asset_integration.UINT32_MASK,
            )
            for index in range(event_count)
        )
    )
    work_counter = [0]

    source_paths_by_location, errors = manifest.source_paths_by_logical_location(
        _work_counter=work_counter,
    )

    assert not errors
    assert len(source_paths_by_location) == event_count
    assert work_counter[0] <= 4 * event_count


def test_zip_extraction_source_revalidation_budget_is_shared_across_generations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_byte_budget = 10
    source_size = 6
    fixed_central_directory_fingerprint = b"f" * 32
    monkeypatch.setattr(
        test_security_asset_integration,
        "_TEST_ZIP_EXTRACTION_FINGERPRINT_MAX_TOTAL_BYTES",
        source_byte_budget,
    )
    monkeypatch.setattr(
        test_security_asset_integration,
        "_zip_central_directory_fingerprint",
        lambda _archive_path: fixed_central_directory_fingerprint,
    )

    events: list[test_security_asset_integration._ZipExtractionEvent] = []
    generations: dict[bytes, test_security_asset_integration._ZipExtractionGeneration] = {}
    for index in range(2):
        archive_path = tmp_path / f"source-{index}.zip"
        entry_name = f"member-{index}.bin"
        payload = bytes([index]) * source_size
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(entry_name, payload)
        with zipfile.ZipFile(archive_path) as archive:
            entry = archive.infolist()[0]

        generation_id = index.to_bytes(32, "big")
        event = test_security_asset_integration._captured_zip_extraction_event(
            generation_id=generation_id,
            temp_path=str(tmp_path / f"extracted-{index}.bin"),
            archive_path=str(archive_path),
            entry_name=entry_name,
            entry_occurrence=0,
            source_occurrence_count=1,
            source_header_offset=entry.header_offset,
            source_size=source_size,
            source_crc32=entry.CRC,
            extracted_size=source_size,
            extracted_crc32=entry.CRC,
            extracted_sha256=hashlib.sha256(payload).digest(),
        )
        events.append(event)
        root_snapshot = test_security_asset_integration._ZipRootArchiveSnapshot(
            archive_path=str(archive_path),
            central_directory_fingerprint=fixed_central_directory_fingerprint,
            source_event_fingerprint=test_security_asset_integration._zip_root_event_fingerprint((event,)),
            unchanged_at_freeze=True,
        )
        generations[generation_id] = test_security_asset_integration._ZipExtractionGeneration(
            generation_id=generation_id,
            root_snapshots=(root_snapshot,),
            event_proofs=(event._capture_proof,),
        )

    _source_paths, errors = test_security_asset_integration._ZipExtractionManifest(
        tuple(events)
    ).source_paths_by_logical_location(
        _authorized_generations=generations,
    )

    assert any(error.startswith("ZIP extraction source content changed after capture:") for error in errors)


def test_zip_extraction_capture_builds_each_central_directory_index_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry_count = test_security_asset_integration._TEST_ZIP_EXTRACTION_MANIFEST_MAX_EVENTS
    archive_payload = io.BytesIO()
    with zipfile.ZipFile(archive_payload, "w") as archive:
        for index in range(entry_count):
            archive.writestr(f"member-{index}.bin", b"")
    archive_payload.seek(0)
    fingerprint_work = 0

    def bounded_fingerprint(entries: tuple[zipfile.ZipInfo, ...]) -> bytes:
        nonlocal fingerprint_work
        fingerprint_work += len(entries)
        if fingerprint_work > entry_count:
            raise AssertionError("central directory fingerprint was rebuilt")
        return b"f" * 32

    monkeypatch.setattr(
        test_security_asset_integration,
        "_zip_central_directory_fingerprint_from_entries",
        bounded_fingerprint,
    )
    recorder = test_security_asset_integration._ZipExtractionRecorder()
    with zipfile.ZipFile(archive_payload) as archive:
        entries = archive.infolist()
        for index, entry in enumerate(entries):
            temp_path = f"/not-a-real-temp-root/member-{index}.bin"
            recorder.begin_temp_path(temp_path)
            try:
                recorder.record_source_entry(archive, entry)
            finally:
                recorder.end_temp_path(temp_path)

    assert fingerprint_work == entry_count
    assert recorder.capture_work_units <= 2 * entry_count


def test_zip_extraction_manifest_preserves_windows_nested_path_provenance() -> None:
    inner_archive_path = r"C:\Temp\tmpabcd1234\inner.zip"
    member_temp_path = r"C:\Temp\tmpefgh5678_weights.h5"
    manifest = test_security_asset_integration._ZipExtractionManifest(
        (
            test_security_asset_integration._captured_zip_extraction_event(
                temp_path=member_temp_path,
                archive_path=inner_archive_path,
                entry_name=r"dir\weights.h5",
                entry_occurrence=0,
                source_occurrence_count=1,
                source_size=144,
                source_crc32=1,
                extracted_size=144,
                extracted_crc32=1,
            ),
            test_security_asset_integration._captured_zip_extraction_event(
                temp_path=inner_archive_path,
                archive_path=r"C:\models\outer.zip",
                entry_name="inner.zip",
                entry_occurrence=0,
                source_occurrence_count=1,
                source_size=262,
                source_crc32=2,
                extracted_size=262,
                extracted_crc32=2,
            ),
        )
    )

    source_paths_by_location, errors = manifest.source_paths_by_logical_location()

    assert not errors
    assert source_paths_by_location[r"C:\models\outer.zip:inner.zip:dir\weights.h5"] == Counter({member_temp_path: 1})


def test_organized_asset_scans_reject_coherent_nested_hdf5_temp_path_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    temp_root = Path(tempfile.gettempdir())
    forged_inner_archive = temp_root / f"{tempfile.gettempprefix()}yyyyyyyy" / "inner.zip"
    forged_member = temp_root / f"{tempfile.gettempprefix()}zzzzzzzz_weights.h5"
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.details.get("required_package") == "h5py":
            diagnostic.details["path"] = str(forged_member)

    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    outer_contents = metadata.model_extra["contents"]
    nested_contents = outer_contents[0]["contents"]
    nested_contents[0]["path"] = f"{forged_inner_archive}:weights.h5"

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "coherent nested HDF5 diagnostic and metadata temp-path rewrite",
        )


@pytest.mark.parametrize(
    "path_mutation",
    [
        "wrong-archive-basename",
        "wrong-member-chain",
        "extra-level",
        "missing-level",
        "arbitrary-suffix",
        "arbitrary-temp-prefix",
    ],
)
def test_organized_asset_scans_reject_unproven_nested_hdf5_metadata_paths(
    path_mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    outer_contents = metadata.model_extra["contents"]
    nested_contents = outer_contents[0]["contents"]
    nested_path = nested_contents[0]["path"]
    assert isinstance(nested_path, str)
    archive_marker = "inner.zip:"
    marker_offset = nested_path.rfind(archive_marker)
    assert marker_offset >= 0
    extracted_prefix = nested_path[:marker_offset]
    if path_mutation == "wrong-archive-basename":
        nested_contents[0]["path"] = f"{extracted_prefix}other.zip:weights.h5"
    elif path_mutation == "wrong-member-chain":
        nested_contents[0]["path"] = f"{extracted_prefix}{archive_marker}other.h5"
    elif path_mutation == "extra-level":
        nested_contents[0]["path"] = f"{extracted_prefix}{archive_marker}extra:weights.h5"
    elif path_mutation == "missing-level":
        nested_contents[0]["path"] = f"{extracted_prefix}weights.h5"
    elif path_mutation == "arbitrary-suffix":
        nested_contents[0]["path"] = f"{nested_path}:extra"
    else:
        nested_contents[0]["path"] = str(tmp_path / "fabricated" / "inner.zip:weights.h5")

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"nested HDF5 metadata path with {path_mutation}",
        )


def test_organized_asset_scans_reject_cross_assigned_duplicate_nested_hdf5_contents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    payload = _plausible_hdf5_v0_payload()
    archive_path, result = _scan_duplicate_nested_zip_archives(
        tmp_path,
        (("first.h5", payload),),
        (("second.h5", payload),),
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "distinct duplicate nested HDF5 occurrences",
    )

    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    outer_contents = metadata.model_extra["contents"]
    outer_contents[0]["contents"], outer_contents[1]["contents"] = (
        outer_contents[1]["contents"],
        outer_contents[0]["contents"],
    )
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "cross-assigned duplicate nested HDF5 contents",
        )


def _nested_hdf5_content(
    result: ModelAuditResultModel,
    archive_path: Path,
) -> dict[str, Any]:
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    outer_contents = metadata.model_extra["contents"]
    nested_contents = outer_contents[0]["contents"]
    content = nested_contents[0]
    assert isinstance(content, dict)
    return content


def _erase_nested_h5py_dependency_result(
    result: ModelAuditResultModel,
    archive_path: Path,
) -> None:
    result.issues = [issue for issue in result.issues if issue.details.get("required_package") != "h5py"]
    result.checks = [check for check in result.checks if check.name != "H5PY Library Check"]
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    for field in ("analysis_incomplete", "scan_outcome", "scan_outcome_reasons"):
        metadata.model_extra.pop(field, None)
    result.success = True


@pytest.mark.parametrize("metadata_mutation", ["unknown-type", "wrong-size"])
def test_organized_asset_scans_reject_coherent_erasure_of_source_hdf5_dependency(
    metadata_mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    content = _nested_hdf5_content(result, archive_path)
    if metadata_mutation == "unknown-type":
        content["type"] = "unknown"
    else:
        content["size"] += 1
    _erase_nested_h5py_dependency_result(result, archive_path)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"coherently erased source HDF5 dependency with {metadata_mutation}",
        )


def test_organized_asset_scans_require_missing_h5py_profile_for_source_hdf5(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    _erase_nested_h5py_dependency_result(result, archive_path)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "source HDF5 with omitted missing-h5py profile",
        )


@pytest.mark.parametrize(
    "metadata_mutation",
    [
        "missing-type",
        "wrong-type",
        "missing-size",
        "wrong-size",
        "string-size",
        "boolean-size",
        "missing-item",
        "duplicate-item",
        "wrong-logical-path",
    ],
)
def test_organized_asset_scans_reject_malformed_source_hdf5_metadata(
    metadata_mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    nested_contents = metadata.model_extra["contents"][0]["contents"]
    content = nested_contents[0]
    original_size = content["size"]
    if metadata_mutation == "missing-type":
        content.pop("type")
    elif metadata_mutation == "wrong-type":
        content["type"] = "unknown"
    elif metadata_mutation == "missing-size":
        content.pop("size")
    elif metadata_mutation == "wrong-size":
        content["size"] = original_size + 1
    elif metadata_mutation == "string-size":
        content["size"] = str(original_size)
    elif metadata_mutation == "boolean-size":
        content["size"] = True
    elif metadata_mutation == "missing-item":
        nested_contents.clear()
    elif metadata_mutation == "duplicate-item":
        nested_contents.append(content.copy())
    else:
        content["path"] = content["path"].replace("weights.h5", "other.h5")

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"source HDF5 metadata with {metadata_mutation}",
        )


def test_organized_asset_scans_preserve_non_hdf5_unknown_member_near_match(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "non-hdf5-unknown-near-match.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("ordinary.txt", b"ordinary unknown archive member")
    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    assert metadata.model_extra["contents"][0]["type"] == "unknown"

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "non-HDF5 unknown archive member near match",
    )


def test_organized_asset_scans_reject_stale_h5py_unavailable_profile_when_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "stale h5py-unavailable profile while h5py is available",
        )


@pytest.mark.parametrize("stale_fragment", ["issue", "check", "reason", "incomplete"])
def test_organized_asset_scans_reject_stale_h5py_unavailable_fragments_when_available(
    stale_fragment: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    if stale_fragment != "issue":
        result.issues = [issue for issue in result.issues if issue.details.get("required_package") != "h5py"]
    if stale_fragment != "check":
        result.checks = [check for check in result.checks if check.name != "H5PY Library Check"]
    for field in ("analysis_incomplete", "scan_outcome", "scan_outcome_reasons"):
        metadata.model_extra.pop(field, None)
    if stale_fragment == "reason":
        metadata.model_extra["scan_outcome_reasons"] = ["keras_h5_h5py_unavailable"]
    elif stale_fragment == "incomplete":
        metadata.model_extra["analysis_incomplete"] = True
        metadata.model_extra["scan_outcome"] = "inconclusive"
    result.success = True
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"stale h5py-unavailable {stale_fragment} fragment while h5py is available",
        )


def test_organized_asset_scans_preserve_source_hdf5_without_unavailable_profile_when_h5py_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        nested_archive_name="inner.zip",
    )
    _erase_nested_h5py_dependency_result(result, archive_path)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)
    assert result.success is True
    assert core_module.determine_exit_code(result) == 0

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "source HDF5 without unavailable profile while h5py is available",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-issue",
        "missing-check",
        "missing-both",
        "wrong-reason",
        "wrong-package",
        "wrong-path",
        "wrong-status",
        "owner-missing-dependency-reason",
        "owner-missing-zip-reason",
        "fabricated-known-dependency",
        "fabricated-arbitrary-dependency",
    ],
)
def test_organized_asset_scans_reject_malformed_nested_hdf5_dependency_profiles(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path, result = _scan_nested_hdf5_with_missing_h5py(tmp_path, monkeypatch)
    member_location = f"{archive_path}:weights.h5"
    dependency_issue = next(
        issue
        for issue in result.issues
        if issue.location == member_location and issue.details.get("required_package") == "h5py"
    )
    dependency_check = next(
        check for check in result.checks if check.location == member_location and check.name == "H5PY Library Check"
    )
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None

    if mutation == "missing-issue":
        result.issues.remove(dependency_issue)
    elif mutation == "missing-check":
        result.checks.remove(dependency_check)
    elif mutation == "missing-both":
        result.issues.remove(dependency_issue)
        result.checks.remove(dependency_check)
    elif mutation == "wrong-reason":
        dependency_issue.details["scan_outcome_reason"] = "unrelated_dependency_unavailable"
    elif mutation == "wrong-package":
        dependency_issue.details["required_package"] = "other"
    elif mutation == "wrong-path":
        dependency_issue.details["path"] = str(tmp_path / "fabricated.h5")
    elif mutation == "wrong-status":
        dependency_check.status = CheckStatus.PASSED
    elif mutation == "owner-missing-dependency-reason":
        metadata.model_extra["scan_outcome_reasons"] = ["zip_analysis_incomplete"]
    elif mutation == "owner-missing-zip-reason":
        metadata.model_extra["scan_outcome_reasons"] = ["keras_h5_h5py_unavailable"]
    else:
        fabricated = dependency_issue.model_copy(deep=True)
        fabricated.location = f"{archive_path}:fabricated.h5"
        fabricated.message = "Corrupt archive payload"
        if mutation == "fabricated-arbitrary-dependency":
            fabricated.details["required_package"] = "other"
            fabricated.details["scan_outcome_reason"] = "other_dependency_unavailable"
        result.issues.append(fabricated)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"nested HDF5 missing-dependency profile with {mutation}",
        )


def test_organized_asset_scans_reject_nested_hdf5_owner_aggregate_without_source_child(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "owner-only-hdf5-dependency.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("ordinary.bin", b"ordinary")
    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    metadata.model_extra.update(
        {
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reasons": ["keras_h5_h5py_unavailable", "zip_analysis_incomplete"],
        }
    )
    result.success = False

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "nested HDF5 owner aggregate without a source-backed child",
        )


def test_organized_asset_scans_preserve_independent_nested_corrupt_zip_roots(
    tmp_path: Path,
) -> None:
    results: list[ModelAuditResultModel] = []
    for index in range(2):
        archive_path = tmp_path / f"nested-corrupt-root-{index}.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(f"inner-{index}.zip", _corrupt_zip_payload())
        results.append(core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False))

    results[0].aggregate_scan_result(results[1])
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        results[0],
        "two independent nested corrupt ZIP roots",
    )


@pytest.mark.parametrize("security_profile", ["s405", "s410"])
def test_organized_asset_scans_preserve_duplicate_nested_archive_security_occurrences(
    security_profile: str,
    tmp_path: Path,
) -> None:
    if security_profile == "s405":
        first_entries = (("../escape-one.txt", b"unsafe"),)
        second_entries = (("../escape-two.txt", b"unsafe"),)
        compression = zipfile.ZIP_STORED
        check_name = "Path Traversal Protection"
    else:
        first_entries = (("bomb-one.txt", COMPRESSION_BOMB_PAYLOAD),)
        second_entries = (("bomb-two.txt", COMPRESSION_BOMB_PAYLOAD),)
        compression = zipfile.ZIP_DEFLATED
        check_name = "Compression Ratio Check"
    archive_path, result = _scan_duplicate_nested_zip_archives(
        tmp_path,
        first_entries,
        second_entries,
        inner_compression=compression,
    )
    rule_code = security_profile.upper()
    issues = [issue for issue in result.issues if issue.rule_code == rule_code]
    checks = [check for check in result.checks if check.name == check_name and check.status == CheckStatus.FAILED]
    assert len(issues) == 2
    assert len(checks) == 1
    assert checks[0].location == f"{archive_path}:inner.zip:{first_entries[0][0]}"
    assert checks[0].details["component_count"] == 2
    assert len(checks[0].details["findings"]) == 2
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"duplicate nested {rule_code} baseline",
    )
    extraction_manifest = test_security_asset_integration._test_zip_extraction_manifest(result)
    source_generations = test_security_asset_integration._test_zip_extraction_generations(result)
    assert extraction_manifest is not None
    assert source_generations

    for mutation in ("missing", "corrupt", "duplicate"):
        mutated = result.model_copy(deep=True)
        test_security_asset_integration._set_test_zip_extraction_manifest(
            mutated,
            extraction_manifest,
            source=result,
        )
        assert test_security_asset_integration._test_zip_extraction_manifest(mutated) is extraction_manifest, (
            "archive mutation copy must preserve its extraction-manifest authorization"
        )
        assert test_security_asset_integration._test_zip_extraction_generations(mutated) == source_generations, (
            "archive mutation copy must preserve its authorized extraction generations"
        )
        mutated_issues = [issue for issue in mutated.issues if issue.rule_code == rule_code]
        mutated_check = next(
            check for check in mutated.checks if check.name == check_name and check.status == CheckStatus.FAILED
        )
        if mutation == "missing":
            mutated.issues.remove(mutated_issues[0])
        elif mutation == "corrupt":
            mutated_check.details["findings"][0]["entry"] = "forged-member.txt"
        else:
            mutated.checks.append(mutated_check.model_copy(deep=True))
        with pytest.raises(AssertionError, match="unexpected operational errors"):
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"duplicate nested {rule_code} with {mutation} evidence",
            )


@pytest.mark.parametrize(
    "operational_details",
    [
        {"error": "compression scanner failed"},
        {"error_type": "CompressionError"},
        {"exception": "compression scanner failed"},
        {"exception_type": "CompressionError"},
        {"operational_error": True},
        {"interrupted": True},
    ],
)
@pytest.mark.parametrize("candidate_profile", ["rule-code", "compression-shaped"])
def test_organized_asset_scans_reject_unvalidated_compression_diagnostic_errors(
    candidate_profile: str,
    operational_details: dict[str, Any],
) -> None:
    result = _scan_asset("safe_data.pkl")
    details: dict[str, Any] = dict(operational_details)
    rule_code: str | None = "S410"
    if candidate_profile == "compression-shaped":
        rule_code = None
        details["ratio"] = 999.0
    result.issues.append(
        Issue(
            message="Unvalidated compression diagnostic",
            severity=IssueSeverity.INFO,
            location=str(ASSETS / "safe_data.pkl"),
            rule_code=rule_code,
            details=details,
        )
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{candidate_profile} diagnostic with {next(iter(operational_details))}",
        )


def test_organized_asset_scans_preserve_duplicate_nested_xml_occurrences(tmp_path: Path) -> None:
    archive_path, result = _scan_duplicate_nested_zip_archives(
        tmp_path,
        (("ambiguous.txt", AMBIGUOUS_XML_PAYLOAD),),
        (("ambiguous.txt", AMBIGUOUS_XML_PAYLOAD),),
    )
    checks = [
        check for check in result.checks if check.name == "XML Model Routing" and check.status == CheckStatus.FAILED
    ]
    assert len(checks) == 1
    assert checks[0].location == f"{archive_path}:inner.zip:ambiguous.txt"
    assert checks[0].details["component_count"] == 2
    assert len(checks[0].details["findings"]) == 2
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "duplicate nested XML baseline",
    )

    result.checks.remove(checks[0])
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "duplicate nested XML without consolidated evidence",
        )


@pytest.mark.parametrize(
    ("member_name", "nested", "expected_safe_name"),
    [
        ("dir/ambiguous.txt", False, "ambiguous.txt"),
        ("dir\\ambiguous.txt", False, "ambiguous.txt"),
        ("dir:ambiguous.txt", False, "dir_ambiguous.txt"),
        ("dir\\ambiguous.txt", True, "ambiguous.txt"),
    ],
)
def test_organized_asset_scans_preserve_xml_zip_member_path_semantics(
    member_name: str,
    nested: bool,
    expected_safe_name: str,
    tmp_path: Path,
) -> None:
    if nested:
        archive_path, result = _scan_nested_zip_archive(
            tmp_path,
            ((member_name, AMBIGUOUS_XML_PAYLOAD),),
        )
        expected_zip_entry = f"inner.zip:{member_name}"
    else:
        archive_path, result = _scan_ambiguous_xml_archive(tmp_path, (member_name,))
        expected_zip_entry = member_name
    diagnostics: list[Issue | Check] = [
        *[
            issue
            for issue in result.issues
            if issue.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ],
        *[
            check
            for check in result.checks
            if check.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ],
    ]
    assert diagnostics
    assert all(diagnostic.location == f"{archive_path}:{expected_zip_entry}" for diagnostic in diagnostics)
    assert all(diagnostic.details["zip_entry"] == expected_zip_entry for diagnostic in diagnostics)
    assert all(Path(diagnostic.details["path"]).name.endswith(f"_{expected_safe_name}") for diagnostic in diagnostics)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"XML member path semantics for {member_name!r} (nested={nested})",
    )


def test_organized_asset_scans_reject_colon_member_xml_source_with_wrong_safe_name(tmp_path: Path) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("dir:ambiguous.txt",))
    diagnostics: list[Issue | Check] = [
        *[
            issue
            for issue in result.issues
            if issue.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ],
        *[
            check
            for check in result.checks
            if check.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ],
    ]
    assert diagnostics
    for diagnostic in diagnostics:
        diagnostic.details["path"] = "/tmp/fake_ambiguous.txt"

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "colon member XML diagnostics with the wrong safe extracted name",
        )


def test_organized_asset_contract_does_not_trust_zip_temp_name_helpers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_security_asset_integration.ZipScanner,
        "_archive_entry_basename",
        staticmethod(lambda _name: "forged.txt"),
    )
    _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("dir:ambiguous.txt",))
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert any(
        Path(diagnostic.details["path"]).name.endswith("_forged.txt")
        for diagnostic in diagnostics
        if diagnostic.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
    )
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "XML archive with perturbed production temp-name helper",
        )


@pytest.mark.parametrize("security_profile", ["s405", "s410"])
@pytest.mark.parametrize("mutation", ["missing", "corrupt"])
def test_organized_asset_scans_require_archive_security_evidence_without_result_opt_in(
    security_profile: str,
    mutation: str,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / f"pure-{security_profile}.zip"
    compression = zipfile.ZIP_DEFLATED if security_profile == "s410" else zipfile.ZIP_STORED
    member_name = "bomb.txt" if security_profile == "s410" else "../escape.txt"
    payload = COMPRESSION_BOMB_PAYLOAD if security_profile == "s410" else b"unsafe"
    with zipfile.ZipFile(archive_path, "w", compression=compression) as archive:
        archive.writestr(member_name, payload)
    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    rule_code = security_profile.upper()
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"pure {rule_code} baseline",
    )

    if security_profile == "s410":
        metadata = result.file_metadata[str(archive_path)]
        assert metadata.model_extra is not None
        for field in ("analysis_incomplete", "scan_outcome", "scan_outcome_reasons"):
            metadata.model_extra.pop(field, None)
        result.success = True
    matching_issues: list[Issue] = [issue for issue in result.issues if issue.rule_code == rule_code.upper()]
    matching_checks: list[Check] = [check for check in result.checks if check.rule_code == rule_code.upper()]
    assert matching_issues and matching_checks
    if mutation == "missing":
        result.issues = [issue for issue in result.issues if issue.rule_code != rule_code.upper()]
        result.checks = [check for check in result.checks if check.rule_code != rule_code.upper()]
    else:
        matching_diagnostics: list[Issue | Check] = [*matching_issues, *matching_checks]
        for diagnostic in matching_diagnostics:
            diagnostic.details["entry"] = "forged-member.txt"

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"pure {rule_code} with {mutation} evidence",
        )


@pytest.mark.parametrize("security_profile", ["xml", "s405", "s410"])
@pytest.mark.parametrize("mutation", ["missing", "corrupt"])
def test_organized_asset_scans_preserve_nested_archive_security_provenance(
    security_profile: str,
    mutation: str,
    tmp_path: Path,
) -> None:
    if security_profile == "xml":
        entries = (("ambiguous.txt", AMBIGUOUS_XML_PAYLOAD),)
        compression = zipfile.ZIP_STORED
    elif security_profile == "s405":
        entries = (("../escape.txt", b"unsafe"),)
        compression = zipfile.ZIP_STORED
    else:
        entries = (("bomb.txt", COMPRESSION_BOMB_PAYLOAD),)
        compression = zipfile.ZIP_DEFLATED
    archive_path, result = _scan_nested_zip_archive(
        tmp_path,
        entries,
        inner_compression=compression,
    )
    nested_location = f"{archive_path}:inner.zip:{entries[0][0]}"
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"nested {security_profile} baseline",
    )

    matching_issues: list[Issue]
    matching_checks: list[Check]
    if security_profile == "xml":
        matching_issues = [
            issue
            for issue in result.issues
            if issue.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ]
        matching_checks = [
            check
            for check in result.checks
            if check.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ]
    else:
        rule_code = security_profile.upper()
        matching_issues = [issue for issue in result.issues if issue.rule_code == rule_code]
        matching_checks = [check for check in result.checks if check.rule_code == rule_code]
    assert matching_issues and matching_checks
    matching_diagnostics: list[Issue | Check] = [*matching_issues, *matching_checks]
    assert all(diagnostic.location == nested_location for diagnostic in matching_diagnostics)
    if mutation == "missing":
        result.issues = [issue for issue in result.issues if issue not in matching_issues]
        result.checks = [check for check in result.checks if check not in matching_checks]
    elif security_profile == "xml":
        for diagnostic in matching_diagnostics:
            diagnostic.details["zip_entry"] = "inner.zip:forged.txt"
    else:
        for diagnostic in matching_diagnostics:
            diagnostic.details["entry"] = "forged.txt"

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"nested {security_profile} with {mutation} evidence",
        )


@pytest.mark.parametrize("mutation", ["missing-issue", "missing-check", "component-count", "duplicate-check"])
def test_organized_asset_scans_preserve_mixed_compression_check_group(
    mutation: str,
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "mixed-compression.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.txt", COMPRESSION_BOMB_PAYLOAD)
        archive.writestr("safe.txt", b"ordinary")
    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    issue = next(candidate for candidate in result.issues if candidate.rule_code == "S410")
    check = next(candidate for candidate in result.checks if candidate.name == "Compression Ratio Check")
    assert check.details["component_count"] == 2
    assert check.details["findings"] == [issue.details]
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "mixed compression-check group baseline",
    )

    if mutation == "missing-issue":
        result.issues = [candidate for candidate in result.issues if candidate is not issue]
    elif mutation == "missing-check":
        result.checks = [candidate for candidate in result.checks if candidate is not check]
    elif mutation == "component-count":
        check.details["component_count"] = 1
    else:
        result.checks.append(check.model_copy(deep=True))
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"mixed compression-check group with {mutation}",
        )


def test_organized_asset_scans_bind_xml_diagnostic_path_to_member_provenance(tmp_path: Path) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("ambiguous.txt",))
    diagnostics: list[Issue | Check] = [
        *[
            issue
            for issue in result.issues
            if issue.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ],
        *[
            check
            for check in result.checks
            if check.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        ],
    ]
    assert len(diagnostics) == 2
    for diagnostic in diagnostics:
        diagnostic.details["path"] = "/tmp/coherent-but-unrelated.txt"

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "XML diagnostics with coherent forged source path",
        )


def test_organized_asset_scans_reject_forged_xml_temp_paths(tmp_path: Path) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("ambiguous.txt",))
    temp_root = Path(tempfile.gettempdir())
    forged_paths = {
        "attacker-parent": tmp_path / "attacker" / "fake_ambiguous.txt",
        "wrong-parent": tmp_path / "tmpabcdefgh_ambiguous.txt",
        "wrong-generated-name": temp_root / "fake_ambiguous.txt",
        "correct-shape-nonexistent": temp_root / f"{tempfile.gettempprefix()}zzzzzzzz_ambiguous.txt",
    }
    accepted_mutations: list[str] = []
    for mutation, forged_path in forged_paths.items():
        mutated = result.model_copy(deep=True)
        diagnostics: list[Issue | Check] = [*mutated.issues, *mutated.checks]
        for diagnostic in diagnostics:
            if diagnostic.details.get("format") == "xml_model_inconclusive":
                diagnostic.details["path"] = str(forged_path)
        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"XML diagnostic with {mutation} temp path",
            )
        except AssertionError:
            continue
        accepted_mutations.append(mutation)

    assert not accepted_mutations, f"forged XML temp paths were accepted: {accepted_mutations}"


def test_organized_asset_scans_reject_cross_occurrence_xml_temp_path(tmp_path: Path) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("left/ambiguous.txt", "right/ambiguous.txt"),
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "distinct XML temp-path occurrences",
    )
    issues = [issue for issue in result.issues if issue.details.get("format") == "xml_model_inconclusive"]
    assert len(issues) == 2
    first_path = issues[0].details["path"]
    second_location = issues[1].location
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.location == second_location and diagnostic.details.get("format") == "xml_model_inconclusive":
            diagnostic.details["path"] = first_path

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "cross-occurrence XML temp path",
        )


def test_organized_asset_scans_reject_distinct_nonexistent_xml_temp_paths(tmp_path: Path) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("left/ambiguous.txt", "right/ambiguous.txt"),
    )
    issues = [issue for issue in result.issues if issue.details.get("format") == "xml_model_inconclusive"]
    assert len(issues) == 2
    temp_root = Path(tempfile.gettempdir())
    forged_paths = {
        issue.location: temp_root / f"{tempfile.gettempprefix()}zzzzzzz{index}_ambiguous.txt"
        for index, issue in enumerate(issues)
    }
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.location in forged_paths and diagnostic.details.get("format") == "xml_model_inconclusive":
            diagnostic.details["path"] = str(forged_paths[diagnostic.location])

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "distinct nonexistent XML temp paths",
        )


def test_organized_asset_scans_reject_extra_malformed_xml_diagnostic(tmp_path: Path) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("ambiguous.txt",))
    issue = next(
        candidate
        for candidate in result.issues
        if candidate.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
    )
    malformed = issue.model_copy(deep=True)
    malformed.message = "XML routing coverage record was corrupted"
    result.issues.append(malformed)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "XML archive with an extra malformed diagnostic",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "check"])
def test_organized_asset_scans_reject_mutated_xml_archive_coverage_diagnostics(
    diagnostic_kind: str,
    tmp_path: Path,
) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("ambiguous.txt",))
    message = (
        "XML model routing was inconclusive because the bounded probe ended before the first structural root element"
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "ambiguous XML archive control")

    accepted_mutations = []
    mutations: list[tuple[str, Any]] = [
        ("analysis_incomplete", False),
        ("scan_outcome", "complete"),
        ("scan_outcome_reason", "scanner_read_failed"),
        ("scan_outcome_reasons", ["scanner_read_failed"]),
        ("operational_error", True),
        ("interrupted", True),
        ("error", "boom"),
        ("error_type", "Boom"),
        ("exception_type", "Boom"),
    ]
    for field, value in mutations:
        mutated = result.model_copy(deep=True)
        diagnostics = mutated.issues if diagnostic_kind == "issue" else mutated.checks
        diagnostic = next(candidate for candidate in diagnostics if candidate.message == message)
        diagnostic.details[field] = value
        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"{diagnostic_kind} XML archive diagnostic with {field}",
            )
        except AssertionError:
            pass
        else:
            accepted_mutations.append(field)

    assert accepted_mutations == []


def test_organized_asset_scans_require_xml_diagnostic_for_each_archive_member(tmp_path: Path) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("first.txt", "second.txt"),
        unrelated_members=("unrelated.txt",),
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "two-member XML archive control")
    unrelated_location = f"{archive_path}:unrelated.txt"
    contents = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)["contents"]
    assert any(content["path"] == unrelated_location and content["type"] == "unknown" for content in contents)
    root_diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert not any(diagnostic.location == unrelated_location for diagnostic in root_diagnostics)

    accepted_missing_members = []
    for member_name in ("first.txt", "second.txt"):
        member_location = f"{archive_path}:{member_name}"
        mutated = result.model_copy(deep=True)
        mutated.issues = [issue for issue in mutated.issues if issue.location != member_location]
        mutated.checks = [check for check in mutated.checks if check.location != member_location]
        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"XML archive missing diagnostic for {member_name}",
            )
        except AssertionError:
            pass
        else:
            accepted_missing_members.append(member_name)

    assert accepted_missing_members == []


def test_organized_asset_scans_count_duplicate_xml_member_occurrences(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("same.txt", "same.txt"))
    member_location = f"{archive_path}:same.txt"
    metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
    assert [content["path"] for content in metadata["contents"]].count(member_location) == 2
    aggregate_check = next(
        check
        for check in result.checks
        if check.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
        and check.details.get("component_count") == 2
    )
    assert len(aggregate_check.details["findings"]) == 2

    baseline_rejected = False
    try:
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "duplicate-name XML archive control",
        )
    except AssertionError:
        baseline_rejected = True

    missing_aggregate = result.model_copy(deep=True)
    missing_aggregate.checks = [
        check
        for check in missing_aggregate.checks
        if not (
            check.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
            and check.details.get("component_count") == 2
        )
    ]
    missing_aggregate_accepted = True
    try:
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            missing_aggregate,
            "duplicate-name XML archive missing consolidated check",
        )
    except AssertionError:
        missing_aggregate_accepted = False

    assert {
        "baseline_rejected": baseline_rejected,
        "missing_aggregate_accepted": missing_aggregate_accepted,
    } == {
        "baseline_rejected": False,
        "missing_aggregate_accepted": False,
    }


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate"])
def test_organized_asset_scans_reconcile_xml_archive_metadata_occurrences(
    mutation: str,
    tmp_path: Path,
) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=("ordinary.bin",),
    )
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    contents = metadata.model_extra["contents"]
    assert isinstance(contents, list) and len(contents) == 2
    if mutation == "missing":
        contents.pop()
    elif mutation == "extra":
        contents.append(
            {
                "path": f"{archive_path}:not-in-central-directory.bin",
                "size": 1,
                "type": "unknown",
            }
        )
    else:
        contents.append(dict(contents[0]))

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"XML archive metadata occurrence {mutation}",
        )


def test_organized_asset_scans_reject_deleted_duplicate_xml_metadata_occurrence(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive_path, result = _scan_ambiguous_xml_archive(tmp_path, ("same.txt", "same.txt"))
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    contents = metadata.model_extra["contents"]
    assert isinstance(contents, list) and len(contents) == 2
    contents.pop()

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "duplicate-name XML archive with deleted metadata occurrence",
        )


def test_organized_asset_scans_reject_safe_member_sheltered_by_fake_traversal_issue(tmp_path: Path) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=("ordinary.bin",),
    )
    ordinary_location = f"{archive_path}:ordinary.bin"
    metadata = result.file_metadata[str(archive_path)]
    assert metadata.model_extra is not None
    contents = metadata.model_extra["contents"]
    assert isinstance(contents, list)
    metadata.model_extra["contents"] = [content for content in contents if content["path"] != ordinary_location]
    result.issues.append(
        Issue(
            message="Archive entry ordinary.bin attempted path traversal outside the archive",
            severity=IssueSeverity.CRITICAL,
            rule_code="S405",
            location=ordinary_location,
            details={"entry": "ordinary.bin"},
        )
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "safe member hidden behind fake path-traversal evidence",
        )


@pytest.mark.parametrize(
    "unsafe_member",
    [
        "../escape.txt",
        "dir/../../escape.txt",
        r"..\escape.txt",
        "/absolute.txt",
        r"\\server\share.txt",
        r"C:\escape.txt",
        "C:/escape.txt",
    ],
)
def test_organized_asset_scans_preserve_xml_coverage_with_rejected_unsafe_member(
    unsafe_member: str,
    tmp_path: Path,
) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=(unsafe_member,),
    )
    member_location = f"{archive_path}:{unsafe_member}"
    assert result.success is False
    assert core_module.determine_exit_code(result) == 1
    issue = next(issue for issue in result.issues if issue.rule_code == "S405")
    check = next(check for check in result.checks if check.rule_code == "S405")
    assert {
        "issue": (issue.location, issue.details),
        "check": (check.name, check.location, check.details),
    } == {
        "issue": (member_location, {"entry": unsafe_member}),
        "check": ("Path Traversal Protection", member_location, {"entry": unsafe_member}),
    }
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"XML archive with rejected unsafe member {unsafe_member}",
    )


@pytest.mark.parametrize(
    "benign_member",
    [
        "dir/../safe.txt",
        "..safe/file.txt",
        "dir/.../safe.txt",
        r"dir\..\safe.txt",
    ],
)
def test_organized_asset_scans_preserve_benign_normalized_archive_members(
    benign_member: str,
    tmp_path: Path,
) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=(benign_member,),
    )
    assert not any(issue.rule_code == "S405" for issue in result.issues)
    assert not any(check.rule_code == "S405" for check in result.checks)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"XML archive with benign normalized member {benign_member}",
    )


def test_organized_asset_contract_does_not_trust_production_path_sanitizer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def permissive_sanitizer(entry_name: str, base_dir: str) -> tuple[str, bool]:
        return str(Path(base_dir) / Path(entry_name.replace("\\", "/")).name), True

    monkeypatch.setattr(zip_scanner_module, "sanitize_archive_path", permissive_sanitizer)
    monkeypatch.setattr(
        test_security_asset_integration,
        "sanitize_archive_path",
        permissive_sanitizer,
        raising=False,
    )
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=("../escape.txt",),
    )
    assert not any(issue.rule_code == "S405" for issue in result.issues)
    assert not any(check.rule_code == "S405" for check in result.checks)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"path-sanitizer perturbation for {archive_path}",
        )


def test_organized_asset_scans_preserve_consolidated_path_traversal_occurrences(tmp_path: Path) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=("../first.txt", "/second.txt"),
    )
    s405_issues = [issue for issue in result.issues if issue.rule_code == "S405"]
    aggregate_check = next(
        check
        for check in result.checks
        if check.name == "Path Traversal Protection" and check.details.get("component_count") == 2
    )
    assert [issue.details for issue in s405_issues] == [
        {"entry": "../first.txt"},
        {"entry": "/second.txt"},
    ]
    assert aggregate_check.details["findings"] == [
        {"entry": "../first.txt"},
        {"entry": "/second.txt"},
    ]
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "two-member path-traversal control",
    )

    missing_second = result.model_copy(deep=True)
    missing_second.issues = [
        issue for issue in missing_second.issues if issue.location != f"{archive_path}:/second.txt"
    ]
    check = next(candidate for candidate in missing_second.checks if candidate.name == "Path Traversal Protection")
    check.rule_code = "S405"
    check.location = f"{archive_path}:../first.txt"
    check.message = "Archive entry ../first.txt attempted path traversal outside the archive"
    check.details = {"entry": "../first.txt"}
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            missing_second,
            "two-member path traversal missing second occurrence",
        )


def test_organized_asset_scans_preserve_duplicate_path_traversal_occurrences(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        _archive_path, result = _scan_ambiguous_xml_archive(
            tmp_path,
            ("ambiguous.txt",),
            unrelated_members=("../same.txt", "../same.txt"),
        )
    assert [issue.details for issue in result.issues if issue.rule_code == "S405"] == [{"entry": "../same.txt"}]
    aggregate_check = next(
        check
        for check in result.checks
        if check.name == "Path Traversal Protection" and check.details.get("component_count") == 2
    )
    assert aggregate_check.details["findings"] == [
        {"entry": "../same.txt"},
        {"entry": "../same.txt"},
    ]
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "duplicate-name path-traversal control",
    )

    missing_aggregate = result.model_copy(deep=True)
    missing_aggregate.checks = [
        check for check in missing_aggregate.checks if check.name != "Path Traversal Protection"
    ]
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            missing_aggregate,
            "duplicate-name path traversal missing consolidated check",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "check"])
def test_organized_asset_scans_reject_duplicate_path_traversal_representations(
    diagnostic_kind: str,
    tmp_path: Path,
) -> None:
    _archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        unrelated_members=("../escape.txt",),
    )
    if diagnostic_kind == "issue":
        issue = next(issue for issue in result.issues if issue.rule_code == "S405")
        result.issues.append(issue.model_copy(deep=True))
    else:
        check = next(check for check in result.checks if check.rule_code == "S405")
        result.checks.append(check.model_copy(deep=True))

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"duplicate path-traversal {diagnostic_kind} representation",
        )


def test_organized_asset_scans_preserve_exact_compression_bomb_contract(tmp_path: Path) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        compression=zipfile.ZIP_DEFLATED,
    )
    member_location = f"{archive_path}:ambiguous.txt"
    metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
    assert metadata["scan_outcome_reasons"] == ["zip_analysis_incomplete"]
    assert metadata["contents"] == []
    assert result.success is False
    assert core_module.determine_exit_code(result) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "compression bomb control")

    accepted_mutations = []
    mutations = (
        "issue-error",
        "check-error",
        "issue-ratio",
        "check-ratio",
        "issue-severity",
        "check-status",
        "missing-issue",
        "missing-check",
        "successful-result",
    )
    for mutation in mutations:
        mutated = result.model_copy(deep=True)
        issue = next(candidate for candidate in mutated.issues if candidate.rule_code == "S410")
        check = next(candidate for candidate in mutated.checks if candidate.rule_code == "S410")
        if mutation == "issue-error":
            issue.details["error"] = "boom"
        elif mutation == "check-error":
            check.details["error"] = "boom"
        elif mutation == "issue-ratio":
            issue.details["ratio"] = 1.0
        elif mutation == "check-ratio":
            check.details["ratio"] = 1.0
        elif mutation == "issue-severity":
            issue.severity = IssueSeverity.INFO
        elif mutation == "check-status":
            check.status = CheckStatus.PASSED
        elif mutation == "missing-issue":
            mutated.issues = [candidate for candidate in mutated.issues if candidate.rule_code != "S410"]
        elif mutation == "missing-check":
            mutated.checks = [candidate for candidate in mutated.checks if candidate.rule_code != "S410"]
        else:
            mutated.success = True
        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"compression bomb with {mutation}",
            )
        except AssertionError:
            pass
        else:
            accepted_mutations.append(mutation)

    assert accepted_mutations == []


@pytest.mark.parametrize("mutation", ["member", "metrics", "threshold", "minimum"])
def test_organized_asset_scans_ground_compression_bomb_details_in_central_directory(
    mutation: str,
    tmp_path: Path,
) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        compression=zipfile.ZIP_DEFLATED,
    )
    diagnostics: list[Issue | Check] = [
        *[issue for issue in result.issues if issue.rule_code == "S410"],
        *[check for check in result.checks if check.rule_code == "S410"],
    ]
    assert len(diagnostics) == 2
    for diagnostic in diagnostics:
        if mutation == "member":
            diagnostic.details["entry"] = "not-present.txt"
            diagnostic.location = f"{archive_path}:not-present.txt"
        elif mutation == "metrics":
            diagnostic.details["compressed_size"] += 1
            diagnostic.details["ratio"] = (
                diagnostic.details["uncompressed_size"] / diagnostic.details["compressed_size"]
            )
        elif mutation == "threshold":
            diagnostic.details["threshold"] -= 1
        else:
            diagnostic.details["min_uncompressed_size"] -= 1
        details = diagnostic.details
        diagnostic.message = (
            f"Suspicious compression ratio ({details['ratio']:.1f}x) and uncompressed size "
            f"({details['uncompressed_size']} bytes) in entry: {details['entry']}; skipping extraction"
        )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"compression bomb with self-consistent fake {mutation}",
        )


def test_organized_asset_scans_preserve_consolidated_multi_bomb_contract(tmp_path: Path) -> None:
    archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("first.txt", "second.txt"),
        compression=zipfile.ZIP_DEFLATED,
    )
    assert len([issue for issue in result.issues if issue.rule_code == "S410"]) == 2
    aggregate_check = next(
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.details.get("component_count") == 2
    )
    assert len(aggregate_check.details["findings"]) == 2
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "two-member compression bomb control",
    )

    missing_second = result.model_copy(deep=True)
    missing_second.issues = [issue for issue in missing_second.issues if issue.location != f"{archive_path}:second.txt"]
    check = next(candidate for candidate in missing_second.checks if candidate.name == "Compression Ratio Check")
    first_details = dict(check.details["findings"][0])
    check.details = first_details
    check.location = f"{archive_path}:first.txt"
    check.rule_code = "S410"
    check.message = (
        f"Suspicious compression ratio ({first_details['ratio']:.1f}x) and uncompressed size "
        f"({first_details['uncompressed_size']} bytes) in entry: first.txt; skipping extraction"
    )
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            missing_second,
            "two-member compression bomb missing second occurrence",
        )


def test_organized_asset_scans_preserve_duplicate_name_multi_bomb_occurrences(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive_path, result = _scan_ambiguous_xml_archive(
            tmp_path,
            ("same.txt", "same.txt"),
            compression=zipfile.ZIP_DEFLATED,
        )
    member_location = f"{archive_path}:same.txt"
    assert len([issue for issue in result.issues if issue.rule_code == "S410"]) == 1
    aggregate_check = next(
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.details.get("component_count") == 2
    )
    assert len(aggregate_check.details["findings"]) == 2
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "duplicate-name compression bomb control",
    )

    missing_aggregate = result.model_copy(deep=True)
    missing_aggregate.checks = [check for check in missing_aggregate.checks if check.name != "Compression Ratio Check"]
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            missing_aggregate,
            "duplicate-name compression bomb missing consolidated check",
        )


@pytest.mark.parametrize("profile", ["xml", "compression"])
@pytest.mark.parametrize("diagnostic_kind", ["issue", "check"])
def test_organized_asset_scans_reject_duplicate_archive_diagnostic_representations(
    profile: str,
    diagnostic_kind: str,
    tmp_path: Path,
) -> None:
    compression = zipfile.ZIP_DEFLATED if profile == "compression" else zipfile.ZIP_STORED
    _archive_path, result = _scan_ambiguous_xml_archive(
        tmp_path,
        ("ambiguous.txt",),
        compression=compression,
    )
    if diagnostic_kind == "issue":
        if profile == "xml":
            issue = next(
                candidate
                for candidate in result.issues
                if candidate.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
            )
        else:
            issue = next(candidate for candidate in result.issues if candidate.rule_code == "S410")
        result.issues.append(issue.model_copy(deep=True))
    else:
        if profile == "xml":
            check = next(
                candidate
                for candidate in result.checks
                if candidate.message == test_security_asset_integration.EXPECTED_XML_ARCHIVE_DIAGNOSTIC_MESSAGE
            )
        else:
            check = next(candidate for candidate in result.checks if candidate.rule_code == "S410")
        result.checks.append(check.model_copy(deep=True))

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"duplicate {profile} {diagnostic_kind} representation",
        )


def test_organized_asset_scans_reject_mutated_unavailable_scanner_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    coverage_path = str(tmp_path / "missing.keras")
    result.file_metadata[coverage_path] = FileMetadataModel(
        operational_error=True,
        operational_error_reason="recognized_format_scanner_unavailable",
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["recognized_format_scanner_unavailable"],
    )
    result.checks.append(
        Check(
            name="Format Detection",
            status=CheckStatus.FAILED,
            message=test_security_asset_integration.EXPECTED_UNAVAILABLE_SCANNER_MESSAGE,
            severity=IssueSeverity.INFO,
            location=coverage_path,
            details={"format": "keras", "path": coverage_path},
        )
    )
    result.success = False
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "unavailable scanner control")

    accepted_mutations = []
    mutations: list[tuple[str, Any]] = [
        ("analysis_incomplete", False),
        ("scan_outcome", "complete"),
        ("scan_outcome_reason", "scanner_read_failed"),
        ("scan_outcome_reasons", ["scanner_read_failed"]),
        ("operational_error", True),
        ("interrupted", True),
        ("error", "boom"),
        ("error_type", "Boom"),
        ("exception_type", "Boom"),
    ]
    for field, value in mutations:
        mutated = result.model_copy(deep=True)
        diagnostic = next(
            check
            for check in mutated.checks
            if check.message == test_security_asset_integration.EXPECTED_UNAVAILABLE_SCANNER_MESSAGE
        )
        diagnostic.details[field] = value
        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                mutated,
                f"unavailable scanner diagnostic with {field}",
            )
        except AssertionError:
            pass
        else:
            accepted_mutations.append(field)

    assert accepted_mutations == []


def test_organized_asset_scans_reject_aliases_on_aliasless_pickle_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, "aliasless pickle control")
    alias_mutations: list[dict[str, Any]] = [
        {"notice_code": "bogus"},
        {"notice_code": None},
        {"notice_code": 123},
        {"pickle_notice_code": "bogus"},
        {"pickle_notice_code": None},
        {"pickle_notice_code": 123},
        {"notice_code": "nested_pickle_incomplete", "pickle_notice_code": "nested_probe_limit"},
    ]

    accepted_mutations = []
    for diagnostic_kind in ("issue", "check"):
        for mutation in alias_mutations:
            mutated = result.model_copy(deep=True)
            diagnostics = mutated.issues if diagnostic_kind == "issue" else mutated.checks
            diagnostic = next(
                candidate
                for candidate in diagnostics
                if candidate.rule_code == "S213" and candidate.message == "Nested pickle analysis did not complete"
            )
            diagnostic.details.update(mutation)
            try:
                test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                    mutated,
                    f"{diagnostic_kind} aliasless pickle finding with {mutation}",
                )
            except AssertionError:
                pass
            else:
                accepted_mutations.append((diagnostic_kind, mutation))

    assert accepted_mutations == []


def test_organized_asset_scans_reject_duplicate_metadata_outcome_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    metadata = result.file_metadata[str(ASSETS / "dill_func.pkl")]
    assert metadata.model_extra is not None
    metadata.model_extra["scan_outcome_reasons"].append("nested_pickle_incomplete")

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "duplicate metadata outcome reasons",
        )


def test_organized_asset_scans_reject_contradictory_aliasless_pickle_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    cases: list[tuple[ModelAuditResultModel, str, str, list[tuple[str, Any]]]] = [
        (
            _scan_asset("dill_func.pkl"),
            "S213",
            "Nested pickle analysis did not complete",
            [("scan_outcome", "complete")],
        ),
        (
            _scan_asset("dill_func.pkl"),
            "S213",
            "Nested pickle payload exceeds deep-scan byte limit",
            [("analysis_incomplete", False), ("scan_outcome", "complete")],
        ),
        (
            core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False),
            "S601",
            "Nested pickle probe candidate limit exceeded",
            [("analysis_incomplete", False), ("scan_outcome", "complete")],
        ),
    ]

    accepted_mutations = []
    for result, rule_code, message, mutations in cases:
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{rule_code} aliasless pickle finding control",
        )
        for diagnostic_kind in ("issue", "check"):
            for field, value in mutations:
                mutated = result.model_copy(deep=True)
                diagnostics = mutated.issues if diagnostic_kind == "issue" else mutated.checks
                diagnostic = next(
                    candidate
                    for candidate in diagnostics
                    if candidate.rule_code == rule_code and candidate.message == message
                )
                diagnostic.details[field] = value
                try:
                    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                        mutated,
                        f"{diagnostic_kind} {rule_code} aliasless pickle finding with {field}",
                    )
                except AssertionError:
                    pass
                else:
                    accepted_mutations.append((rule_code, message, diagnostic_kind, field))

    assert accepted_mutations == []


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
def test_organized_asset_scans_preserve_security_threshold_findings(
    integration_test: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    weights = tmp_path / "weights.msgpack"
    weights.write_bytes(msgpack.packb({"params": {"shape": [1_000_000_001]}}))
    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
    result = _merge_with_canonical_agpl_source_change(result)

    assert result.file_metadata[str(weights)].get("operational_error") is None
    assert any(
        issue.rule_code == "S804" and issue.details.get("max_safe_dimension") == 10**9 for issue in result.issues
    )

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize(
    "archive_failure",
    [
        "object-budget",
        "format-read",
        "file-size",
        "operational-dependency",
        "check-only-dependency",
        "consolidated-check-dependency",
        "metadata-only-budget",
    ],
)
def test_organized_asset_scans_reject_unrelated_archive_failures(
    integration_test: str,
    archive_failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    archive_path = tmp_path / "unrelated-archive-failure.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        if archive_failure == "object-budget":
            archive.writestr("weights.msgpack", b"\x81\xa6params\x80" * 2)
        elif archive_failure == "operational-dependency":
            archive.writestr("weights.tflite", b"\x00\x00\x00\x00TFL3" + bytes(100))
        elif archive_failure in {"check-only-dependency", "consolidated-check-dependency", "metadata-only-budget"}:
            nemo_payload = io.BytesIO()
            member_names = (
                ("oversized.meta",)
                if archive_failure == "metadata-only-budget"
                else (
                    ("weights1.tflite", "weights2.tflite")
                    if archive_failure == "consolidated-check-dependency"
                    else ("weights.tflite",)
                )
            )
            references = ", ".join(f"nemo:{name}" for name in member_names)
            with tarfile.open(fileobj=nemo_payload, mode="w") as nemo_archive:
                members = [("model_config.yaml", f"model:\n  artifacts: [{references}]\n".encode())]
                members.extend(
                    (name, b"A" * 129 if name.endswith(".meta") else b"\x00\x00\x00\x00TFL3" + bytes(100))
                    for name in member_names
                )
                for member_name, member_payload in members:
                    member = tarfile.TarInfo(member_name)
                    member.size = len(member_payload)
                    nemo_archive.addfile(member, io.BytesIO(member_payload))
            archive.writestr("inner.nemo", nemo_payload.getvalue())
        else:
            archive.writestr("unowned.payload", b"file format cannot be read")
        archive.writestr(
            "ambiguous.txt",
            "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
        )

    if archive_failure == "format-read":
        original_detect_file_format = core_module.detect_file_format

        def raise_nested_read_failure(path: str) -> str:
            if path.endswith(".payload"):
                raise OSError("independent nested format read failure")
            return original_detect_file_format(path)

        monkeypatch.setattr(core_module, "detect_file_format", raise_nested_read_failure)
    elif archive_failure == "file-size":
        original_getsize = core_module.os.path.getsize

        def raise_nested_size_failure(path: str) -> int:
            if str(path).endswith(".payload") and sys._getframe(1).f_code is core_module._scan_file_internal.__code__:
                raise OSError("independent nested file-size read failure")
            return original_getsize(path)

        monkeypatch.setattr(core_module.os.path, "getsize", raise_nested_size_failure)
    elif archive_failure in {"operational-dependency", "check-only-dependency", "consolidated-check-dependency"}:
        monkeypatch.setattr(tflite_scanner_module, "HAS_TFLITE", False)
    elif archive_failure == "metadata-only-budget":
        monkeypatch.setattr(tf_metagraph_scanner_module, "_MAX_PARSE_BYTES", 128)

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(tmp_path),
        cache_enabled=False,
        max_msgpack_stream_objects=1,
    )
    result = _merge_with_canonical_agpl_source_change(result)
    archive_metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
    assert archive_metadata["operational_error_reason"] == "xml_model_routing_incomplete"
    if archive_failure == "object-budget":
        failed_member = f"{archive_path}:weights.msgpack"
        assert any(
            issue.location == failed_member
            and issue.rule_code == "S902"
            and issue.details.get("max_msgpack_stream_objects") == 1
            for issue in result.issues
        )
    elif archive_failure == "format-read":
        failed_member = f"{archive_path}:unowned.payload"
        assert "format_detection_read_failed" in archive_metadata["scan_outcome_reasons"]
        assert any("independent nested format read failure" in issue.message for issue in result.issues)
    elif archive_failure == "file-size":
        failed_member = f"{archive_path}:unowned.payload"
        assert any("independent nested file-size read failure" in issue.message for issue in result.issues)
    elif archive_failure == "operational-dependency":
        failed_member = f"{archive_path}:weights.tflite"
        assert any(
            issue.details.get("required_package") == "tflite" and issue.details.get("operational_error") is True
            for issue in result.issues
        )
    elif archive_failure == "check-only-dependency":
        failed_member = f"{archive_path}:inner.nemo:weights.tflite"
        assert not any(issue.details.get("required_package") == "tflite" for issue in result.issues)
        assert any(
            check.location == failed_member
            and check.details.get("required_package") == "tflite"
            and check.details.get("operational_error") is True
            for check in result.checks
        )
    elif archive_failure == "consolidated-check-dependency":
        failed_member = f"{archive_path}:inner.nemo:weights1.tflite"
        assert not any(issue.details.get("required_package") == "tflite" for issue in result.issues)
        assert any(
            check.location == failed_member
            and check.details.get("component_count") == 2
            and all(finding.get("operational_error") is True for finding in check.details.get("findings", []))
            for check in result.checks
        )
    else:
        failed_member = f"{archive_path}:inner.nemo:oversized.meta"
        assert "metagraph_parse_budget_exceeded" in archive_metadata["scan_outcome_reasons"]
        assert not any("max_parse_bytes" in issue.details for issue in result.issues)
        assert not any("max_parse_bytes" in check.details for check in result.checks)

    hidden_reason = {
        "operational-dependency": "tflite_dependency_unavailable",
        "check-only-dependency": "tflite_dependency_unavailable",
        "consolidated-check-dependency": "tflite_dependency_unavailable",
        "metadata-only-budget": "metagraph_parse_budget_exceeded",
    }.get(archive_failure)
    _assert_otherwise_accepted_archive_control(result, failed_member, hidden_reason)
    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize("asset_name", ["other.pkl", "agpl_model.pkl"])
def test_organized_asset_scans_reject_source_changes_outside_agpl_fixture(
    integration_test: str,
    asset_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    other_pickle = tmp_path / asset_name
    shutil.copy2(AGPL_ASSET, other_pickle)
    result = core_module.scan_model_directory_or_file(str(other_pickle), cache_enabled=False)
    assert any(issue.rule_code == "S204" for issue in result.issues)

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
def test_organized_asset_scans_reject_mixed_archive_member_errors(
    integration_test: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        report = sys._getframe(1).f_locals["report"]
        if Path(str(report.source)).name == "agpl_model.pkl":
            raise _source_stability_error()

    real_find_call_graphs = package_api.find_dangerous_call_graphs
    analyzed_members = 0

    def fail_unexpected_member(*args: Any, **kwargs: Any) -> Any:
        nonlocal analyzed_members
        analyzed_members += 1
        report = sys._getframe(1).f_locals["report"]
        if str(report.source).endswith("unexpected.pkl"):
            raise RuntimeError("independent archive-member call-graph regression")
        return real_find_call_graphs(*args, **kwargs)

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    monkeypatch.setattr(package_api, "find_dangerous_call_graphs", fail_unexpected_member)
    archive_path = tmp_path / "multiple-pickles.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(AGPL_ASSET, "unexpected.pkl")
        archive.writestr(
            "ambiguous.txt",
            "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
        )

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(tmp_path),
        cache_enabled=False,
    )
    result = _merge_with_canonical_agpl_source_change(result)

    assert analyzed_members == 2
    assert result.has_errors is True
    assert any(
        issue.location == f"{archive_path}:unexpected.pkl"
        and issue.details.get("analysis") == "python_call_graph"
        and issue.details.get("exception_type") == "RuntimeError"
        for issue in result.issues
    )
    assert any(
        issue.location == str(AGPL_ASSET) and issue.details.get("analysis") == "python_call_graph_source_stability"
        for issue in result.issues
    )

    _assert_otherwise_accepted_archive_control(
        result,
        f"{archive_path}:unexpected.pkl",
        hidden_reasons=test_security_asset_integration.EXPECTED_SECURITY_FINDING_OUTCOME_REASONS,
    )
    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize("timeout_source", ["manifest-scanner", "core-wrapper"])
def test_organized_asset_scans_reject_mixed_archive_member_timeouts(
    integration_test: str,
    timeout_source: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    def raise_manifest_timeout(_scanner: ManifestScanner, *_args: object, **_kwargs: object) -> None:
        raise TimeoutError("independent manifest timeout")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    monkeypatch.setattr(
        ManifestScanner,
        "_check_timeout" if timeout_source == "manifest-scanner" else "scan",
        raise_manifest_timeout,
    )
    archive_path = tmp_path / "manifest-timeout.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("config.json", '{"model_type":"bert"}')
        archive.writestr(
            "ambiguous.txt",
            "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
        )

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(tmp_path),
        cache_enabled=False,
    )
    result = _merge_with_canonical_agpl_source_change(result)
    if timeout_source == "manifest-scanner":
        assert any(
            issue.location == f"{archive_path}:config.json"
            and issue.details.get("scan_outcome_reason") == "manifest_scan_timeout"
            for issue in result.issues
        )
    else:
        assert any(
            issue.location == f"{archive_path}:config.json"
            and "timeout" in issue.details
            and issue.details.get("error") == "independent manifest timeout"
            for issue in result.issues
        )

    _assert_otherwise_accepted_archive_control(result, f"{archive_path}:config.json")
    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize("scanner_error", ["msgpack-object-limit", "metagraph-parse-budget", "flax-exception"])
def test_organized_asset_scans_reject_mixed_archive_scanner_errors(
    integration_test: str,
    scanner_error: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    def raise_flax_error(_scanner: FlaxMsgpackScanner, _path: str, _result: ScanResult) -> None:
        raise RuntimeError("independent flax regression")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    if scanner_error == "flax-exception":
        monkeypatch.setattr(FlaxMsgpackScanner, "_scan_msgpack_stream_from_path", raise_flax_error)
    archive_path = tmp_path / "scanner-limit.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        if scanner_error in {"msgpack-object-limit", "flax-exception"}:
            archive.writestr("weights.msgpack", b"\x81\xa6params\x80" * 2)
        else:
            monkeypatch.setattr(tf_metagraph_scanner_module, "_MAX_PARSE_BYTES", 128)
            archive.writestr("oversized.meta", b"A" * 129)
        archive.writestr(
            "ambiguous.txt",
            "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
        )

    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(tmp_path),
        cache_enabled=False,
        max_msgpack_stream_objects=1,
    )
    result = _merge_with_canonical_agpl_source_change(result)
    if scanner_error == "msgpack-object-limit":
        assert any(
            issue.location == f"{archive_path}:weights.msgpack"
            and issue.rule_code == "S902"
            and issue.details.get("max_msgpack_stream_objects") == 1
            for issue in result.issues
        )
    elif scanner_error == "flax-exception":
        assert any(
            issue.location == f"{archive_path}:weights.msgpack" and issue.details.get("error_type") == "RuntimeError"
            for issue in result.issues
        )
    else:
        assert any(
            issue.location == f"{archive_path}:oversized.meta" and issue.details.get("max_parse_bytes") == 128
            for issue in result.issues
        )

    failed_member = "oversized.meta" if scanner_error == "metagraph-parse-budget" else "weights.msgpack"
    _assert_otherwise_accepted_archive_control(result, f"{archive_path}:{failed_member}")
    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize("h5_available", [False, True], ids=["windows-no-h5py", "h5py-installed"])
def test_organized_asset_scans_preserve_existing_h5_diagnostics(
    integration_test: str,
    h5_available: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if h5_available and not keras_h5_scanner_module.HAS_H5PY:
        pytest.skip("h5py is not installed in this CI profile")

    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", h5_available)
    shutil.copy2(ASSETS.parent / "keras" / "malicious_lambda.h5", tmp_path / "malicious_lambda.h5")
    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
    result = _merge_with_canonical_agpl_source_change(result)

    expected_detail = "suspicious_term" if h5_available else "required_package"
    assert any(issue.rule_code == "S902" and expected_detail in issue.details for issue in result.issues)

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    getattr(test_case, integration_test)(tmp_path)


def test_organized_asset_scans_reject_coverage_only_contract_without_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    assert result.has_errors is False
    coverage_path = str(tmp_path / "missing.keras")
    result.success = False
    result.file_metadata[coverage_path] = FileMetadataModel(
        operational_error=True,
        operational_error_reason="recognized_format_scanner_unavailable",
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["recognized_format_scanner_unavailable"],
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "coverage-only outcome without diagnostic",
        )


@pytest.mark.parametrize(
    "malformation",
    [
        "missing-outcome-fields",
        "missing-analysis-incomplete",
        "complete-outcome",
        "missing-corresponding-reason",
        "successful-result",
    ],
)
def test_organized_asset_scans_reject_incomplete_coverage_only_contract(
    malformation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    assert result.has_errors is False
    assert result.success is True

    coverage_payload: dict[str, Any] = {
        "operational_error": True,
        "operational_error_reason": "recognized_format_scanner_unavailable",
        "analysis_incomplete": True,
        "scan_outcome": "inconclusive",
        "scan_outcome_reasons": ["recognized_format_scanner_unavailable"],
    }
    result.success = False
    if malformation == "missing-outcome-fields":
        coverage_payload.pop("analysis_incomplete")
        coverage_payload.pop("scan_outcome")
        coverage_payload.pop("scan_outcome_reasons")
        result.success = True
    elif malformation == "missing-analysis-incomplete":
        coverage_payload.pop("analysis_incomplete")
    elif malformation == "complete-outcome":
        coverage_payload["scan_outcome"] = "complete"
    elif malformation == "missing-corresponding-reason":
        coverage_payload["scan_outcome_reasons"] = ["xml_model_routing_incomplete"]
    else:
        result.success = True
    result.file_metadata[str(tmp_path / "missing.keras")] = FileMetadataModel(**coverage_payload)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "malformed coverage-only outcome",
        )


def test_organized_asset_scans_preserve_complete_coverage_only_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    assert result.has_errors is False
    result.success = False
    coverage_path = str(tmp_path / "missing.keras")
    result.file_metadata[coverage_path] = FileMetadataModel(
        operational_error=True,
        operational_error_reason="recognized_format_scanner_unavailable",
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["recognized_format_scanner_unavailable"],
    )
    result.checks.append(
        Check(
            name="Format Detection",
            status=CheckStatus.FAILED,
            message=test_security_asset_integration.EXPECTED_UNAVAILABLE_SCANNER_MESSAGE,
            severity=IssueSeverity.INFO,
            location=coverage_path,
            details={"format": "keras", "path": coverage_path},
        )
    )

    assert results_have_inconclusive_outcome(result) is True
    assert core_module.determine_exit_code(result) == 2
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "complete coverage-only outcome",
    )


@pytest.mark.parametrize(
    "error_details",
    [
        pytest.param({"error": "independent scanner failure"}, id="error"),
        pytest.param({"exception": "independent scanner failure"}, id="exception"),
        pytest.param({"error_type": "RuntimeError"}, id="error-type"),
        pytest.param({"exception_type": "RuntimeError"}, id="exception-type"),
        pytest.param({"operational_error": True}, id="operational-error"),
        pytest.param({"interrupted": True}, id="interrupted"),
        pytest.param({"error_type": None}, id="explicit-null-error-type"),
        pytest.param({"scan_outcome_reason": None}, id="explicit-null-outcome-reason"),
    ],
)
def test_organized_asset_scans_reject_dependency_diagnostic_error_fields(
    error_details: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    dependency_path = str(tmp_path / "missing.h5")
    result.file_metadata[dependency_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["keras_h5_h5py_unavailable"],
    )
    result.checks.append(
        Check(
            name="H5PY Library Check",
            status=CheckStatus.FAILED,
            message="h5py is required for Keras H5 scanning.",
            severity=IssueSeverity.INFO,
            location=dependency_path,
            details={
                "required_package": "h5py",
                "analysis_incomplete": True,
                "scan_outcome_reason": "keras_h5_h5py_unavailable",
                **error_details,
            },
            rule_code="S902",
        )
    )
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "dependency diagnostic with error field",
        )


def test_organized_asset_scans_preserve_missing_dependency_error_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    dependency_path = str(tmp_path / "missing.7z")
    result.file_metadata[dependency_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["sevenzip_analysis_incomplete"],
    )
    result.checks.append(
        Check(
            name="7-Zip Dependency Check",
            status=CheckStatus.FAILED,
            message="py7zr package is not installed.",
            severity=IssueSeverity.INFO,
            location=dependency_path,
            details={
                "required_package": "py7zr",
                "error_type": "missing_dependency",
                "analysis_incomplete": True,
                "scan_outcome_reason": "sevenzip_analysis_incomplete",
            },
            rule_code="S902",
        )
    )
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "known missing dependency diagnostic",
    )


@pytest.mark.parametrize(
    "malformation",
    [
        "empty-message",
        "wrong-message",
        "missing-incomplete-flag",
        "missing-inconclusive-outcome",
        "missing-outcome-reason",
        "unknown-outcome-reason",
    ],
)
def test_organized_asset_scans_reject_malformed_dependency_diagnostic(
    malformation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    dependency_path = str(tmp_path / "missing.h5")
    message = "h5py is required for Keras H5 scanning."
    reason = "keras_h5_h5py_unavailable"
    metadata_kwargs: dict[str, Any] = {
        "analysis_incomplete": True,
        "scan_outcome": "inconclusive",
        "scan_outcome_reasons": [reason],
    }
    if malformation == "empty-message":
        message = ""
    elif malformation == "wrong-message":
        message = "An unrelated optional dependency is unavailable."
    elif malformation == "missing-incomplete-flag":
        metadata_kwargs.pop("analysis_incomplete")
    elif malformation == "missing-inconclusive-outcome":
        metadata_kwargs.pop("scan_outcome")
    elif malformation == "missing-outcome-reason":
        metadata_kwargs["scan_outcome_reasons"] = []
    else:
        reason = "keras_h5_unknown_incomplete"
        metadata_kwargs["scan_outcome_reasons"] = [reason]
    result.file_metadata[dependency_path] = FileMetadataModel(**metadata_kwargs)
    result.checks.append(
        Check(
            name="H5PY Library Check",
            status=CheckStatus.FAILED,
            message=message,
            severity=IssueSeverity.INFO,
            location=dependency_path,
            details={
                "required_package": "h5py",
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"malformed dependency diagnostic: {malformation}",
        )


def test_organized_asset_scans_preserve_real_sevenzip_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(sevenzip_scanner_module, "HAS_PY7ZR", False)
    archive_path = tmp_path / "missing-dependency.7z"
    archive_path.write_bytes(sevenzip_scanner_module.SevenZipScanner._SEVENZIP_MAGIC + bytes(26))

    result = core_module.scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    dependency_issue = next(issue for issue in result.issues if issue.details.get("required_package") == "py7zr")
    assert dependency_issue.rule_code is None
    assert dependency_issue.details["error_type"] == "missing_dependency"
    assert dependency_issue.details["scan_outcome_reason"] == "sevenzip_analysis_incomplete"

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real SevenZip missing dependency",
    )


def test_organized_asset_scans_preserve_real_xgboost_ubjson_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(xgboost_scanner_module, "_check_ubjson_available", lambda: False)
    model_path = tmp_path / "missing-dependency.ubj"
    model_path.write_bytes(b"\x7b\x55")

    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    dependency_issue = next(issue for issue in result.issues if issue.details.get("required_package") == "ubjson")
    assert dependency_issue.rule_code is None
    assert "error_type" not in dependency_issue.details
    assert dependency_issue.details["detected_format"] == "ubjson"

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real XGBoost UBJSON missing dependency",
    )


def test_organized_asset_scans_preserve_real_pmml_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(pmml_scanner_module, "HAS_DEFUSEDXML", False)
    monkeypatch.setattr(pmml_scanner_module, "DefusedET", None)
    model_path = tmp_path / "missing-dependency.pmml"
    model_path.write_text(
        "<?xml version='1.0'?><PMML version='4.4'><Header/><DataDictionary numberOfFields='0'/></PMML>",
        encoding="utf-8",
    )

    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    dependency_issue = next(issue for issue in result.issues if issue.details.get("required_package") == "defusedxml")
    assert dependency_issue.rule_code is None
    assert "error_type" not in dependency_issue.details
    assert (
        dependency_issue.details["scan_outcome_reason"]
        == pmml_scanner_module.PmmlScanner.XML_PARSER_UNAVAILABLE_INCOMPLETE_REASON
    )

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real PMML missing dependency",
    )


def test_organized_asset_scans_preserve_real_tentative_onnx_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(onnx_scanner_module, "_check_onnx", lambda: False)
    candidate_path = tmp_path / "tentative-protobuf.jpg"
    candidate_path.write_bytes(b"\x42\x00" * 4097)
    scanner = onnx_scanner_module.OnnxScanner(
        config={FORMAT_VALIDATION_CONFIG_KEY: {"routed_format": PROTOBUF_MODEL_CANDIDATE_FORMAT}}
    )

    scan_result = scanner.scan(str(candidate_path))
    scan_result.metadata["source_path"] = str(candidate_path)
    result = _scan_asset("safe_data.pkl")
    result.aggregate_scan_result_direct(scan_result)
    metadata = result.file_metadata[str(candidate_path)].model_dump(exclude_none=True)
    dependency_check = next(check for check in result.checks if check.details.get("required_package") == "onnx")
    assert metadata["scan_outcome"] == "inconclusive"
    assert "analysis_incomplete" not in metadata
    assert metadata["scan_outcome_reasons"] == [onnx_scanner_module.ONNX_TENTATIVE_CANDIDATE_UNAVAILABLE_REASON]
    assert dependency_check.details["analysis_incomplete"] is True
    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real tentative ONNX missing dependency",
    )


def test_organized_asset_scans_reject_real_direct_onnx_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(onnx_scanner_module, "_check_onnx", lambda: False)
    model_path = tmp_path / "direct.onnx"
    model_path.write_bytes(b"not-a-real-onnx-model")

    scan_result = onnx_scanner_module.OnnxScanner().scan(str(model_path))
    scan_result.metadata["source_path"] = str(model_path)
    result = _scan_asset("safe_data.pkl")
    result.aggregate_scan_result_direct(scan_result)
    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    assert metadata["operational_error"] is True
    assert metadata["operational_error_reason"] == onnx_scanner_module.ONNX_DEPENDENCY_UNAVAILABLE_REASON
    assert result.has_errors is True
    assert core_module.determine_exit_code(result) == 2

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "real direct ONNX missing dependency",
        )


def _scan_direct_h5_with_missing_h5py(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    signature_offset: int = 0,
) -> tuple[ModelAuditResultModel, Path]:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    model_path = tmp_path / "direct-missing-h5py.h5"
    if signature_offset:
        _write_sparse_plausible_hdf5_v0(model_path, signature_offset)
    else:
        model_path.write_bytes(_plausible_hdf5_v0_payload())
    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    return result, model_path


def _scan_keras_zip_with_missing_h5py(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    *,
    hdf5_signature_offset: int = 16 * 1024 * 1024,
) -> tuple[ModelAuditResultModel, Path]:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    model_path = tmp_path / filename
    if hdf5_signature_offset == 0:
        weights_payload = bytearray(_plausible_hdf5_v0_payload())
    else:
        weights_payload = bytearray(hdf5_signature_offset + 8)
        weights_payload[hdf5_signature_offset : hdf5_signature_offset + 8] = b"\x89HDF\r\n\x1a\n"
    with zipfile.ZipFile(model_path, "w") as archive:
        archive.writestr("config.json", '{"class_name":"Sequential","config":{"layers":[]}}')
        archive.writestr("metadata.json", '{"keras_version":"3.12.0"}')
        archive.writestr("model.weights.h5", bytes(weights_payload))

    scan_result = keras_zip_scanner_module.KerasZipScanner().scan(str(model_path))
    scan_result.metadata["source_path"] = str(model_path)
    result = _scan_asset("safe_data.pkl")
    result.aggregate_scan_result_direct(scan_result)
    return result, model_path


def _synthetic_direct_h5py_dependency_profile(
    profile_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModelAuditResultModel, str, str]:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    if profile_kind == "h5":
        source_path = tmp_path / "missing.h5"
        source_path.write_bytes(_plausible_hdf5_v0_payload())
        owner_path = str(source_path)
        location = owner_path
        reason = "keras_h5_h5py_unavailable"
        check_name = "H5PY Library Check"
        message = "h5py is required for Keras H5 scanning. Install with 'pip install modelaudit[h5]'."
        details: dict[str, Any] = {"path": owner_path}
        metadata_extra: dict[str, Any] = {
            "file_size": source_path.stat().st_size,
            "scanner_dependency_ids": ["keras_h5"],
        }
    else:
        assert profile_kind in {"keras", "keras-h5py"}
        source_path = tmp_path / "missing.keras"
        weights_payload = _plausible_hdf5_v0_payload() if profile_kind == "keras-h5py" else bytes(16 * 1024 * 1024 + 8)
        with zipfile.ZipFile(source_path, "w") as archive:
            archive.writestr("config.json", '{"class_name":"Sequential","config":{"layers":[]}}')
            archive.writestr("metadata.json", '{"keras_version":"3.12.0"}')
            archive.writestr("model.weights.h5", weights_payload)
        owner_path = str(source_path)
        location = f"{owner_path}:model.weights.h5"
        details = {"entry": "model.weights.h5"}
        metadata_extra = {
            "file_size": source_path.stat().st_size,
            "scanner_dependency_ids": ["keras_zip"],
            "contents": [
                {
                    "path": f"{owner_path}:config.json",
                    "type": "security_only",
                    "size": 50,
                },
                {
                    "path": f"{owner_path}:metadata.json",
                    "type": "unknown",
                    "size": 26,
                },
                {
                    "path": location,
                    "type": "security_only" if profile_kind == "keras-h5py" else "flax_msgpack",
                    "size": len(weights_payload),
                },
            ],
        }
        if profile_kind == "keras-h5py":
            reason = "keras_zip_embedded_weights_h5py_unavailable"
            check_name = "Embedded Weights H5PY Library Check"
            message = (
                "Skipping embedded model.weights.h5 inspection because h5py is required for HDF5 weights "
                "analysis. Install with 'pip install modelaudit[h5]'."
            )
            details["hdf5_signature_offset"] = 0
            metadata_extra["embedded_weights_hdf5_signature_offset"] = 0
        else:
            reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"
            check_name = "Embedded Weights HDF5 Signature Probe"
            message = (
                "Skipping embedded model.weights.h5 inspection because h5py is unavailable and the weights entry "
                "is too large to rule out a valid HDF5 user-block signature within the bounded probe window. "
                "Install with 'pip install modelaudit[h5]'."
            )
            details.update(
                {
                    "file_size": 16 * 1024 * 1024 + 8,
                    "hdf5_signature_probe_max_bytes": 10 * 1024 * 1024,
                }
            )
    details.update(
        {
            "required_package": "h5py",
            "analysis_incomplete": True,
            "scan_outcome_reason": reason,
        }
    )
    result.file_metadata[owner_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=[reason],
        **metadata_extra,
    )
    result.issues.append(
        Issue(
            message=message,
            severity=IssueSeverity.INFO,
            location=location,
            details=details.copy(),
            rule_code="S902",
        )
    )
    result.checks.append(
        Check(
            name=check_name,
            status=CheckStatus.FAILED,
            message=message,
            severity=IssueSeverity.INFO,
            location=location,
            details=details.copy(),
            rule_code="S902",
        )
    )
    result.success = False
    return result, owner_path, reason


def test_organized_asset_scans_preserve_real_direct_h5_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_direct_h5_with_missing_h5py(tmp_path, monkeypatch)
    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    assert metadata["scan_outcome_reasons"] == ["keras_h5_h5py_unavailable"]
    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real direct H5 missing dependency",
    )


@pytest.mark.parametrize(
    "signature_offset",
    [16 * 1024 * 1024, 32 * 1024 * 1024, 64 * 1024 * 1024],
    ids=["16-mib", "32-mib", "64-mib"],
)
def test_organized_asset_scans_preserve_sparse_direct_h5_userblock_dependency(
    signature_offset: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_direct_h5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        signature_offset=signature_offset,
    )
    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    expected_reasons = [
        "keras_h5_h5py_unavailable",
        "hdf5_userblock_zip_probe_incomplete",
    ]
    diagnostics: list[Issue | Check] = list(result.issues)
    diagnostics.extend(result.checks)
    assert metadata["scan_outcome_reasons"] == expected_reasons
    probe_diagnostics: list[Issue | Check] = [
        diagnostic
        for diagnostic in diagnostics
        if diagnostic.details.get("scan_outcome_reason") == "hdf5_userblock_zip_probe_incomplete"
    ]
    assert len(probe_diagnostics) == 2
    assert {type(diagnostic) for diagnostic in probe_diagnostics} == {Issue, Check}
    for diagnostic in probe_diagnostics:
        assert diagnostic.location == str(model_path)
        assert diagnostic.details == {
            "analysis_incomplete": True,
            "scan_outcome_reason": "hdf5_userblock_zip_probe_incomplete",
            "hdf5_signature_offset": signature_offset,
            "zip_probe_bytes_scanned": 10 * 1024 * 1024,
            "zip_probe_max_bytes": 10 * 1024 * 1024,
        }
    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"sparse direct H5 with {signature_offset}-byte userblock",
    )


def test_organized_asset_scans_preserve_real_h5py_direct_userblock_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h5py = pytest.importorskip("h5py")
    model_path = tmp_path / "real-userblock.h5"
    with h5py.File(model_path, "w", userblock_size=16 * 1024 * 1024) as model:
        model.create_dataset("weights", data=[1.0])
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)

    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    assert metadata["scan_outcome_reasons"] == [
        "keras_h5_h5py_unavailable",
        "hdf5_userblock_zip_probe_incomplete",
    ]
    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 2
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real h5py direct H5 with a 16 MiB userblock",
    )


def test_organized_asset_scans_preserve_direct_h5_userblock_with_fully_covered_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_direct_h5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        signature_offset=8 * 1024 * 1024,
    )

    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    assert metadata["scan_outcome_reasons"] == ["keras_h5_h5py_unavailable"]
    diagnostics: list[Issue | Check] = list(result.issues)
    diagnostics.extend(result.checks)
    assert not any(
        diagnostic.details.get("scan_outcome_reason") == "hdf5_userblock_zip_probe_incomplete"
        for diagnostic in diagnostics
    )
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "direct H5 with a fully covered 8 MiB userblock probe",
    )


@pytest.mark.parametrize(
    "source_mutation",
    ["near-magic", "truncated", "invalid-superblock", "non-power-offset", "signature-past-eof"],
)
def test_direct_hdf5_sparse_signature_proof_rejects_invalid_sources(
    source_mutation: str,
    tmp_path: Path,
) -> None:
    signature_offset = 16 * 1024 * 1024
    if source_mutation == "non-power-offset":
        signature_offset = 3 * 1024 * 1024
    model_path = tmp_path / f"invalid-{source_mutation}.h5"
    _write_sparse_plausible_hdf5_v0(model_path, signature_offset)

    if source_mutation == "near-magic":
        with model_path.open("r+b") as source:
            source.seek(signature_offset)
            source.write(b"XHDF\r\n\x1a\n")
    elif source_mutation == "truncated":
        with model_path.open("r+b") as source:
            source.truncate(signature_offset + 8)
    elif source_mutation == "invalid-superblock":
        with model_path.open("r+b") as source:
            source.seek(signature_offset + 13)
            source.write(b"\x03")
    elif source_mutation == "signature-past-eof":
        with model_path.open("r+b") as source:
            source.truncate(signature_offset - 1)

    assert test_security_asset_integration._direct_hdf5_signature_offset(str(model_path)) is None


@pytest.mark.parametrize(
    "malformation",
    [
        "missing-issue",
        "missing-check",
        "extra-profile",
        "mutated-message",
        "mutated-details",
        "cross-root",
        "duplicate-issue",
    ],
)
def test_organized_asset_scans_reject_malformed_direct_hdf5_userblock_probe_profile(
    malformation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _model_path = _scan_direct_h5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        signature_offset=16 * 1024 * 1024,
    )
    probe_issues = [
        issue
        for issue in result.issues
        if issue.details.get("scan_outcome_reason") == "hdf5_userblock_zip_probe_incomplete"
    ]
    probe_checks = [
        check
        for check in result.checks
        if check.details.get("scan_outcome_reason") == "hdf5_userblock_zip_probe_incomplete"
    ]
    assert len(probe_issues) == len(probe_checks) == 1

    if malformation == "missing-issue":
        result.issues.remove(probe_issues[0])
    elif malformation == "missing-check":
        result.checks.remove(probe_checks[0])
    elif malformation == "extra-profile":
        extra_issue = probe_issues[0].model_copy(deep=True)
        extra_issue.message = "Additional user-block probe record"
        result.issues.append(extra_issue)
    elif malformation == "mutated-message":
        probe_issues[0].message = "User-block probe stopped"
        probe_checks[0].message = "User-block probe stopped"
    elif malformation == "mutated-details":
        probe_issues[0].details["zip_probe_bytes_scanned"] = 1
        probe_checks[0].details["zip_probe_bytes_scanned"] = 1
    elif malformation == "cross-root":
        other_path = tmp_path / "other.h5"
        _write_sparse_plausible_hdf5_v0(other_path, 16 * 1024 * 1024)
        probe_issues[0].location = str(other_path)
        probe_checks[0].location = str(other_path)
    else:
        result.issues.append(probe_issues[0].model_copy(deep=True))

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"direct H5 user-block probe with {malformation}",
        )


def test_organized_asset_scans_preserve_direct_hdf5_userblock_security_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_direct_h5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        signature_offset=16 * 1024 * 1024,
    )
    result.issues.append(
        Issue(
            message="Detected malicious content in the HDF5 user block",
            severity=IssueSeverity.CRITICAL,
            location=str(model_path),
            details={},
            rule_code="S201",
        )
    )

    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "direct H5 user-block dependency with a critical security finding",
    )


def test_organized_asset_scans_preserve_real_keras_zip_hdf5_probe_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_keras_zip_with_missing_h5py(
        tmp_path,
        monkeypatch,
        "missing-hdf5-probe-dependency.keras",
    )
    reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"
    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    dependency_check = next(check for check in result.checks if check.details.get("required_package") == "h5py")
    assert metadata["scan_outcome_reasons"] == [reason]
    assert dependency_check.details["scan_outcome_reason"] == reason
    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real Keras ZIP HDF5 probe missing dependency",
    )


def test_organized_asset_scans_preserve_real_keras_zip_h5py_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_keras_zip_with_missing_h5py(
        tmp_path,
        monkeypatch,
        "missing-embedded-h5py.keras",
        hdf5_signature_offset=0,
    )
    reason = "keras_zip_embedded_weights_h5py_unavailable"
    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    dependency_check = next(check for check in result.checks if check.details.get("required_package") == "h5py")
    assert metadata["scan_outcome_reasons"] == [reason]
    assert metadata["scanner_dependency_ids"] == ["keras_zip"]
    assert dependency_check.name == "Embedded Weights H5PY Library Check"
    assert dependency_check.details["scan_outcome_reason"] == reason
    assert result.success is False
    assert result.has_errors is False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "real Keras ZIP embedded HDF5 missing dependency",
    )


@pytest.mark.parametrize("artifact_kind", ["h5", "keras"], ids=["h5-to-keras", "keras-to-h5"])
def test_organized_asset_scans_reject_h5py_reason_artifact_owner_swaps(
    artifact_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if artifact_kind == "h5":
        result, owner_path = _scan_direct_h5_with_missing_h5py(tmp_path, monkeypatch)
        replacement_reason = "keras_zip_embedded_weights_h5py_unavailable"
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
    else:
        result, owner_path = _scan_keras_zip_with_missing_h5py(
            tmp_path,
            monkeypatch,
            "reason-owner-swap.keras",
        )
        replacement_reason = "keras_h5_h5py_unavailable"
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)

    metadata = result.file_metadata[str(owner_path)].model_extra
    assert metadata is not None
    metadata["scan_outcome_reasons"] = [replacement_reason]
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.details.get("required_package") == "h5py":
            diagnostic.details["scan_outcome_reason"] = replacement_reason

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{artifact_kind} h5py reason reassigned to another artifact owner",
        )


@pytest.mark.parametrize(
    ("profile_kind", "malformation"),
    [
        pytest.param("h5", "wrong-scanner", id="h5-wrong-scanner"),
        pytest.param("h5", "extra-scanner", id="h5-extra-scanner"),
        pytest.param("h5", "wrong-check-name", id="h5-wrong-check-name"),
        pytest.param("h5", "wrong-message", id="h5-wrong-message"),
        pytest.param("h5", "wrong-source", id="h5-wrong-source"),
        pytest.param("h5", "both-reasons", id="h5-both-reasons"),
        pytest.param("h5", "metadata-diagnostic-mismatch", id="h5-metadata-diagnostic-mismatch"),
        pytest.param("keras-h5py", "wrong-source", id="keras-h5py-wrong-source"),
        pytest.param("keras", "wrong-scanner", id="keras-probe-wrong-scanner"),
    ],
)
def test_organized_asset_scans_reject_h5py_dependency_artifact_profile_malformations(
    profile_kind: str,
    malformation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, owner_path, reason = _synthetic_direct_h5py_dependency_profile(
        profile_kind,
        tmp_path,
        monkeypatch,
    )
    metadata = result.file_metadata[owner_path].model_extra
    assert metadata is not None
    h5py_issues = [issue for issue in result.issues if issue.details.get("required_package") == "h5py"]
    h5py_checks = [check for check in result.checks if check.details.get("required_package") == "h5py"]
    diagnostics: list[Issue | Check] = [*h5py_issues, *h5py_checks]
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)

    if malformation == "wrong-scanner":
        metadata["scanner_dependency_ids"] = ["keras_zip" if profile_kind == "h5" else "keras_h5"]
    elif malformation == "extra-scanner":
        metadata["scanner_dependency_ids"] = ["keras_h5", "keras_zip"]
    elif malformation == "wrong-check-name":
        h5py_checks[0].name = "Unrelated Dependency Check"
    elif malformation == "wrong-message":
        for diagnostic in diagnostics:
            diagnostic.message = "h5py is required for an unrelated artifact"
    elif malformation == "wrong-source":
        Path(owner_path).write_bytes(b"ordinary non-model payload")
    elif malformation == "both-reasons":
        other_reason = "keras_zip_embedded_weights_h5py_unavailable"
        metadata["scan_outcome_reasons"] = [reason, other_reason]
        for issue in h5py_issues:
            duplicate_issue = issue.model_copy(deep=True)
            duplicate_issue.details["scan_outcome_reason"] = other_reason
            result.issues.append(duplicate_issue)
        for check in h5py_checks:
            duplicate_check = check.model_copy(deep=True)
            duplicate_check.details["scan_outcome_reason"] = other_reason
            result.checks.append(duplicate_check)
    else:
        replacement_reason = "keras_zip_embedded_weights_h5py_unavailable"
        for diagnostic in diagnostics:
            diagnostic.details["scan_outcome_reason"] = replacement_reason

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{profile_kind} h5py dependency with {malformation}",
        )


def test_organized_asset_scans_reject_cross_assigned_h5py_dependency_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, owner_path, _reason = _synthetic_direct_h5py_dependency_profile("h5", tmp_path, monkeypatch)
    keras_result, keras_path = _scan_keras_zip_with_missing_h5py(
        tmp_path,
        monkeypatch,
        "cross-assigned-root.keras",
    )
    del keras_result
    metadata = result.file_metadata.pop(owner_path)
    result.file_metadata[str(keras_path)] = metadata
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    for diagnostic in diagnostics:
        if diagnostic.details.get("required_package") == "h5py":
            diagnostic.location = str(keras_path)
            diagnostic.details["path"] = str(keras_path)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "direct H5 dependency profile cross-assigned to a Keras ZIP root",
        )


@pytest.mark.parametrize("profile_kind", ["h5", "keras"])
def test_organized_asset_scans_reject_stale_direct_h5py_profile_when_available(
    profile_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if profile_kind == "h5":
        result, _model_path = _scan_direct_h5_with_missing_h5py(tmp_path, monkeypatch)
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)
    else:
        result, _model_path = _scan_keras_zip_with_missing_h5py(
            tmp_path,
            monkeypatch,
            "stale-direct-profile.keras",
        )
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"stale direct {profile_kind} h5py-unavailable profile",
        )


@pytest.mark.parametrize(
    ("profile_kind", "h5_state", "zip_state"),
    [
        pytest.param("h5", None, False, id="h5-none"),
        pytest.param("h5", 1, False, id="h5-one"),
        pytest.param("h5", "missing", False, id="h5-string"),
        pytest.param("keras-h5py", False, None, id="keras-h5py-none"),
        pytest.param("keras-h5py", False, 1, id="keras-h5py-one"),
        pytest.param("keras-h5py", False, "missing", id="keras-h5py-string"),
        pytest.param("keras", False, None, id="keras-none"),
        pytest.param("keras", False, 1, id="keras-one"),
        pytest.param("keras", False, "missing", id="keras-string"),
    ],
)
def test_organized_asset_scans_reject_non_boolean_h5py_dependency_states(
    profile_kind: str,
    h5_state: object,
    zip_state: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _owner_path, _reason = _synthetic_direct_h5py_dependency_profile(
        profile_kind,
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", h5_state)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", zip_state)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{profile_kind} h5py dependency with non-boolean live state",
        )


@pytest.mark.parametrize(
    ("profile_kind", "h5_state", "zip_state"),
    [
        pytest.param("h5", False, True, id="direct-h5"),
        pytest.param("keras-h5py", True, False, id="keras-h5py"),
        pytest.param("keras", True, False, id="keras-signature-probe"),
    ],
)
def test_organized_asset_scans_preserve_h5py_dependency_when_owning_scanner_is_unavailable(
    profile_kind: str,
    h5_state: object,
    zip_state: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _owner_path, _reason = _synthetic_direct_h5py_dependency_profile(
        profile_kind,
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", h5_state)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", zip_state)

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"{profile_kind} h5py dependency with owning scanner unavailable",
    )


@pytest.mark.parametrize("profile_kind", ["h5", "keras-h5py", "keras"])
@pytest.mark.parametrize("stale_fragment", ["issue", "check", "reason", "incomplete"])
def test_organized_asset_scans_reject_stale_direct_h5py_fragments_when_available(
    profile_kind: str,
    stale_fragment: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, owner_path, reason = _synthetic_direct_h5py_dependency_profile(
        profile_kind,
        tmp_path,
        monkeypatch,
    )
    dependency_issue = next(issue for issue in result.issues if issue.details.get("required_package") == "h5py")
    dependency_check = next(check for check in result.checks if check.details.get("required_package") == "h5py")
    result.issues = [issue for issue in result.issues if issue is not dependency_issue]
    result.checks = [check for check in result.checks if check is not dependency_check]
    if stale_fragment == "issue":
        result.issues.append(dependency_issue)
        result.file_metadata[owner_path] = FileMetadataModel()
    elif stale_fragment == "check":
        result.checks.append(dependency_check)
        result.file_metadata[owner_path] = FileMetadataModel()
    elif stale_fragment == "reason":
        result.file_metadata[owner_path] = FileMetadataModel(scan_outcome_reasons=[reason])
    else:
        result.file_metadata[owner_path] = FileMetadataModel(
            analysis_incomplete=True,
            scan_outcome="inconclusive",
        )
    result.success = True
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"stale direct {profile_kind} {stale_fragment} fragment",
        )


@pytest.mark.parametrize("profile_kind", ["h5", "keras"])
def test_organized_asset_scans_preserve_direct_models_without_h5py_unavailable_profile(
    profile_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)
    if profile_kind == "h5":
        if "h5py" not in sys.modules:
            pytest.skip("h5py is required for the direct H5 positive")
        model_path = Path(__file__).parent / "assets" / "samples" / "keras" / "safe_model.h5"
    else:
        model_path = tmp_path / "normal.keras"
        with zipfile.ZipFile(model_path, "w") as archive:
            archive.writestr("config.json", '{"class_name":"Sequential","config":{"layers":[]}}')
            archive.writestr("metadata.json", '{"keras_version":"3.12.0"}')
    result = core_module.scan_model_directory_or_file(str(model_path.resolve()), cache_enabled=False)
    assert result.success is True
    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert not any(diagnostic.details.get("required_package") == "h5py" for diagnostic in diagnostics)

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        f"direct {profile_kind} model without h5py-unavailable profile",
    )


def test_organized_asset_scans_reject_duplicate_diagnostic_outcome_reasons_before_exemption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _model_path = _scan_keras_zip_with_missing_h5py(
        tmp_path,
        monkeypatch,
        "duplicate-diagnostic-outcome-reasons.keras",
    )
    dependency_check = next(check for check in result.checks if check.details.get("required_package") == "h5py")
    reason = dependency_check.details["scan_outcome_reason"]
    dependency_check.details["scan_outcome_reasons"] = [reason, reason]

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "duplicate diagnostic outcome reasons",
        )


def test_organized_asset_scans_require_exact_member_dependency_for_nested_routing_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, model_path = _scan_keras_zip_with_missing_h5py(
        tmp_path,
        monkeypatch,
        "member-routing-coverage.keras",
    )
    all_diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    routing_diagnostics = [
        diagnostic
        for diagnostic in all_diagnostics
        if diagnostic.details.get("scan_outcome_reason") == "flax_msgpack_routing_incomplete"
    ]
    assert routing_diagnostics
    member_path = f"{model_path}:model.weights.h5"
    assert all(diagnostic.location == member_path for diagnostic in routing_diagnostics)
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "exact listed member with matching dependency diagnostic",
    )

    accepted_malformations: list[str] = []
    for malformation in (
        "wrong-member",
        "unlisted-member",
        "mismatched-location",
        "wrong-coverage-reason",
        "wrong-coverage-message",
        "coherent-listed-nonweights-member",
        "self-authorizing-nested-marker",
        "missing-dependency-diagnostic",
        "invalid-dependency-diagnostic",
    ):
        malformed = result.model_copy(deep=True)
        malformed_diagnostics: list[Issue | Check] = [*malformed.issues, *malformed.checks]
        malformed_routing = [
            diagnostic
            for diagnostic in malformed_diagnostics
            if diagnostic.details.get("scan_outcome_reason") == "flax_msgpack_routing_incomplete"
        ]
        if malformation == "wrong-member":
            for diagnostic in malformed_routing:
                diagnostic.details["zip_entry"] = "config.json"
        elif malformation == "unlisted-member":
            for diagnostic in malformed_routing:
                diagnostic.location = f"{model_path}:unlisted.weights.h5"
                diagnostic.details["zip_entry"] = "unlisted.weights.h5"
        elif malformation == "mismatched-location":
            for diagnostic in malformed_routing:
                diagnostic.location = f"{model_path}:config.json"
        elif malformation == "wrong-coverage-reason":
            for diagnostic in malformed_routing:
                diagnostic.details["scan_outcome_reason"] = "xml_model_routing_incomplete"
        elif malformation == "wrong-coverage-message":
            for diagnostic in malformed_routing:
                diagnostic.message = "Unrelated routing message"
        elif malformation == "coherent-listed-nonweights-member":
            config_path = f"{model_path}:config.json"
            for diagnostic in malformed_routing:
                diagnostic.location = config_path
                diagnostic.details["zip_entry"] = "config.json"
            for diagnostic in malformed_diagnostics:
                if diagnostic.details.get("required_package") == "h5py":
                    diagnostic.location = config_path
                    if "zip_entry" in diagnostic.details:
                        diagnostic.details["zip_entry"] = "config.json"
        elif malformation == "self-authorizing-nested-marker":
            malformed.issues = [
                issue
                for issue in malformed.issues
                if issue.details.get("scan_outcome_reason") != "flax_msgpack_routing_incomplete"
            ]
            malformed.checks = [
                check
                for check in malformed.checks
                if check.details.get("scan_outcome_reason") != "flax_msgpack_routing_incomplete"
            ]
            dependency_check = next(
                check for check in malformed.checks if check.details.get("required_package") == "h5py"
            )
            dependency_check.details["findings"] = [
                {
                    "details": {
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "flax_msgpack_routing_incomplete",
                        "zip_entry": "model.weights.h5",
                    }
                }
            ]
        elif malformation == "missing-dependency-diagnostic":
            malformed.issues = [issue for issue in malformed.issues if issue.details.get("required_package") != "h5py"]
            malformed.checks = [check for check in malformed.checks if check.details.get("required_package") != "h5py"]
        else:
            for diagnostic in malformed_diagnostics:
                if diagnostic.details.get("required_package") == "h5py":
                    diagnostic.message = "Unrelated dependency message"

        try:
            test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
                malformed,
                f"nested routing coverage with {malformation}",
            )
        except AssertionError:
            continue
        accepted_malformations.append(malformation)

    assert accepted_malformations == [], (
        f"nested routing coverage contract accepted malformed cases: {accepted_malformations}"
    )


def test_organized_asset_scans_reject_missing_dependency_metadata_without_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(pmml_scanner_module, "HAS_DEFUSEDXML", False)
    monkeypatch.setattr(pmml_scanner_module, "DefusedET", None)
    model_path = tmp_path / "missing-dependency-without-diagnostic.pmml"
    model_path.write_text(
        "<?xml version='1.0'?><PMML version='4.4'><Header/><DataDictionary numberOfFields='0'/></PMML>",
        encoding="utf-8",
    )

    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
    reason = pmml_scanner_module.PmmlScanner.XML_PARSER_UNAVAILABLE_INCOMPLETE_REASON
    assert metadata["scan_outcome_reasons"] == [reason]
    assert result.success is False
    assert result.has_errors is False
    assert any(diagnostic.details.get("required_package") == "defusedxml" for diagnostic in result.issues)
    result.issues = [
        diagnostic for diagnostic in result.issues if diagnostic.details.get("required_package") != "defusedxml"
    ]
    result.checks = [
        diagnostic for diagnostic in result.checks if diagnostic.details.get("required_package") != "defusedxml"
    ]

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "missing dependency metadata without diagnostic",
        )


def test_organized_asset_scans_reject_successful_missing_dependency_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(pmml_scanner_module, "HAS_DEFUSEDXML", False)
    monkeypatch.setattr(pmml_scanner_module, "DefusedET", None)
    model_path = tmp_path / "successful-missing-dependency.pmml"
    model_path.write_text(
        "<?xml version='1.0'?><PMML version='4.4'><Header/><DataDictionary numberOfFields='0'/></PMML>",
        encoding="utf-8",
    )

    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    assert result.success is False
    assert result.has_errors is False
    result.success = True

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "successful missing dependency result",
        )


def test_organized_asset_scans_reject_unaccounted_missing_dependency_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(pmml_scanner_module, "HAS_DEFUSEDXML", False)
    monkeypatch.setattr(pmml_scanner_module, "DefusedET", None)
    model_path = tmp_path / "unaccounted-missing-dependency-reason.pmml"
    model_path.write_text(
        "<?xml version='1.0'?><PMML version='4.4'><Header/><DataDictionary numberOfFields='0'/></PMML>",
        encoding="utf-8",
    )

    result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    metadata = result.file_metadata[str(model_path)]
    assert metadata.model_extra is not None
    reason = pmml_scanner_module.PmmlScanner.XML_PARSER_UNAVAILABLE_INCOMPLETE_REASON
    assert metadata.model_extra["scan_outcome_reasons"] == [reason]
    metadata.model_extra["scan_outcome_reasons"].append("unrelated_coverage_incomplete")
    result.checks.append(
        Check(
            name="Spoofed XML Parser Security Check",
            status=CheckStatus.FAILED,
            message="PMML XML parsing skipped because defusedxml is unavailable",
            severity=IssueSeverity.INFO,
            location=str(model_path),
            details={
                "required_package": "defusedxml",
                "scan_outcome_reason": "unrelated_coverage_incomplete",
            },
            rule_code="S902",
        )
    )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "missing dependency with unaccounted reason",
        )


def test_organized_asset_scans_require_each_nested_dependency_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    monkeypatch.setattr(pmml_scanner_module, "HAS_DEFUSEDXML", False)
    monkeypatch.setattr(pmml_scanner_module, "DefusedET", None)
    archive_file = tmp_path / "multiple-missing-dependencies.zip"
    with zipfile.ZipFile(archive_file, "w") as archive:
        archive.writestr("weights.h5", _plausible_hdf5_v0_payload())
        archive.writestr(
            "model.pmml",
            '<?xml version="1.0"?><PMML version="4.4"><Header/><DataDictionary numberOfFields="0"/></PMML>',
        )
    result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
        str(archive_file),
        cache_enabled=False,
    )
    archive_path = str(archive_file)
    h5py_reason = "keras_h5_h5py_unavailable"
    defusedxml_reason = "pmml_safe_xml_parser_unavailable"
    metadata = result.file_metadata[archive_path].model_dump(exclude_none=True)
    assert set(metadata["scan_outcome_reasons"]) == {
        h5py_reason,
        defusedxml_reason,
        "zip_analysis_incomplete",
    }
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "nested missing dependencies",
    )

    missing_diagnostic = result.model_copy(deep=True)
    missing_diagnostic.issues = [
        issue for issue in missing_diagnostic.issues if issue.details.get("required_package") != "defusedxml"
    ]
    missing_diagnostic.checks = [
        check for check in missing_diagnostic.checks if check.details.get("required_package") != "defusedxml"
    ]
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            missing_diagnostic,
            "nested missing dependency diagnostic",
        )


def test_organized_asset_scans_preserve_mixed_dependency_and_coverage_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_file, result = _scan_nested_hdf5_with_missing_h5py(
        tmp_path,
        monkeypatch,
        include_ambiguous_xml=True,
    )
    archive_path = str(archive_file)
    dependency_reason = "keras_h5_h5py_unavailable"
    metadata = result.file_metadata[archive_path].model_dump(exclude_none=True)
    assert dependency_reason in metadata["scan_outcome_reasons"]
    assert "xml_model_routing_incomplete" in metadata["scan_outcome_reasons"]
    assert "zip_analysis_incomplete" in metadata["scan_outcome_reasons"]
    dependency_diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    assert any(
        diagnostic.location == f"{archive_path}:weights.h5"
        and diagnostic.details.get("scan_outcome_reason") == dependency_reason
        for diagnostic in dependency_diagnostics
    )
    result.issues.append(
        Issue(
            message="Embedded pickle finding",
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:payload.pkl",
            rule_code="S204",
        )
    )
    assert result.success is False
    assert core_module.determine_exit_code(result) == 1

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "mixed dependency and coverage outcomes",
    )


def test_organized_asset_scans_reject_cross_package_dependency_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    archive_path = str(tmp_path / "cross-package-dependency-reason.zip")
    h5py_reason = "keras_h5_h5py_unavailable"
    defusedxml_reason = "pmml_safe_xml_parser_unavailable"
    result.file_metadata[archive_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=[h5py_reason, defusedxml_reason],
    )
    result.checks.extend(
        [
            Check(
                name="H5PY Library Check",
                status=CheckStatus.FAILED,
                message="h5py is required for Keras H5 scanning.",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:weights.h5",
                details={"required_package": "h5py", "scan_outcome_reason": h5py_reason},
                rule_code="S902",
            ),
            Check(
                name="XML Parser Security Check",
                status=CheckStatus.FAILED,
                message="PMML XML parsing skipped because defusedxml is unavailable",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:model.pmml",
                details={"required_package": "defusedxml", "scan_outcome_reason": defusedxml_reason},
                rule_code="S902",
            ),
            Check(
                name="Mismatched H5PY Library Check",
                status=CheckStatus.FAILED,
                message="h5py is required for Keras H5 scanning.",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:weights.h5",
                details={"required_package": "h5py", "scan_outcome_reason": defusedxml_reason},
                rule_code="S902",
            ),
        ]
    )
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "cross-package dependency reason",
        )


@pytest.mark.parametrize(
    ("scan_outcome_reasons", "operational_error_reason", "include_security_finding", "expected_exit"),
    [
        pytest.param(
            ["xml_model_routing_incomplete", "unrelated_coverage_incomplete"],
            None,
            True,
            1,
            id="unflagged-coverage-with-extra",
        ),
        pytest.param(
            ["unrelated_coverage_incomplete"],
            None,
            True,
            1,
            id="unknown-only",
        ),
        pytest.param(
            ["xml_model_routing_incomplete", "unrelated_coverage_incomplete"],
            "xml_model_routing_incomplete",
            False,
            2,
            id="operational-coverage-with-extra",
        ),
        pytest.param([None], None, True, 1, id="null-reason"),
        pytest.param([""], None, True, 1, id="empty-reason"),
        pytest.param(
            ["xml_model_routing_incomplete", None],
            None,
            True,
            1,
            id="coverage-with-null-reason",
        ),
        pytest.param(
            ["xml_model_routing_incomplete", ""],
            None,
            True,
            1,
            id="coverage-with-empty-reason",
        ),
    ],
)
def test_organized_asset_scans_reject_unaccounted_coverage_outcomes(
    scan_outcome_reasons: list[Any],
    operational_error_reason: str | None,
    include_security_finding: bool,
    expected_exit: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    archive_path = str(tmp_path / "unaccounted-coverage-outcome.zip")
    metadata: dict[str, Any] = {
        "analysis_incomplete": True,
        "scan_outcome": "inconclusive",
        "scan_outcome_reasons": scan_outcome_reasons,
    }
    if operational_error_reason is not None:
        metadata.update(
            operational_error=True,
            operational_error_reason=operational_error_reason,
        )
    result.file_metadata[archive_path] = FileMetadataModel(**metadata)
    if include_security_finding:
        result.issues.append(
            Issue(
                message="Embedded pickle finding",
                severity=IssueSeverity.CRITICAL,
                location=f"{archive_path}:payload.pkl",
                rule_code="S204",
            )
        )
    result.success = False
    assert core_module.determine_exit_code(result) == expected_exit

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "unaccounted coverage outcome",
        )


@pytest.mark.parametrize("outcome_state", ["missing", "contradictory"])
def test_organized_asset_scans_reject_incomplete_unflagged_coverage_with_security_finding(
    outcome_state: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(tmp_path / "malicious-with-incomplete-routing.pkl")
    result.file_metadata[model_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["flax_msgpack_routing_incomplete"],
    )
    metadata = result.file_metadata[model_path]
    assert metadata.model_extra is not None
    if outcome_state == "missing":
        metadata.model_extra.pop("analysis_incomplete")
        metadata.model_extra.pop("scan_outcome")
    else:
        metadata.model_extra["analysis_incomplete"] = False
        metadata.model_extra["scan_outcome"] = "complete"
    result.issues.append(
        Issue(
            message="Embedded pickle finding",
            severity=IssueSeverity.CRITICAL,
            location=model_path,
            rule_code="S204",
        )
    )
    result.success = False

    assert core_module.determine_exit_code(result) == 1
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"security-positive unflagged coverage with {outcome_state} state",
        )


@pytest.mark.parametrize(
    "scan_outcome_reason",
    [
        pytest.param("xml_model_routing_incomplete", id="mismatched-string"),
        pytest.param(123, id="non-string"),
        pytest.param("", id="empty-string"),
    ],
)
def test_organized_asset_scans_reject_mismatched_unflagged_coverage_reasons(
    scan_outcome_reason: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(tmp_path / "malicious-with-mismatched-routing.pkl")
    result.file_metadata[model_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reason=scan_outcome_reason,
        scan_outcome_reasons=["flax_msgpack_routing_incomplete"],
    )
    result.issues.append(
        Issue(
            message="Embedded pickle finding",
            severity=IssueSeverity.CRITICAL,
            location=model_path,
            rule_code="S204",
        )
    )
    result.success = False

    assert core_module.determine_exit_code(result) == 1
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "security-positive mismatched unflagged coverage reasons",
        )


@pytest.mark.parametrize(
    "metadata",
    [
        pytest.param(
            {"analysis_incomplete": True, "scan_outcome": "inconclusive"},
            id="incomplete-and-inconclusive",
        ),
        pytest.param({"scan_outcome": "inconclusive"}, id="inconclusive-only"),
        pytest.param({"analysis_incomplete": True}, id="incomplete-only"),
    ],
)
def test_organized_asset_scans_reject_missing_outcome_reasons(
    metadata: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(tmp_path / "missing-outcome-reasons.pkl")
    result.file_metadata[model_path] = FileMetadataModel(**metadata)
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "missing outcome reasons",
        )


@pytest.mark.parametrize(
    "details",
    [
        pytest.param({"exception": "scanner blew up"}, id="root-diagnostic"),
        pytest.param(
            {
                "pickle_source": str(ASSETS / "safe_data.pkl"),
                "exception": "scanner blew up",
            },
            id="pickle-source-diagnostic",
        ),
        pytest.param(
            {"category": "parse_error", "exception": "scanner blew up"},
            id="parse-error-diagnostic",
        ),
    ],
)
def test_organized_asset_scans_reject_bare_exception_diagnostics(
    details: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    result.issues.append(
        Issue(
            message="Scanner failed without structured error metadata",
            severity=IssueSeverity.INFO,
            location=model_path,
            details=details,
        )
    )

    assert result.has_errors is False
    assert result.success is True
    assert core_module.determine_exit_code(result) == 0
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "bare exception diagnostic",
        )


@pytest.mark.parametrize("unexpected_field", ["error", "error_type"])
def test_organized_asset_scans_reject_parse_error_with_additional_error(
    unexpected_field: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    result.issues.append(
        Issue(
            message="Pickle parsing failed",
            severity=IssueSeverity.INFO,
            location=model_path,
            rule_code="S901",
            details={
                "pickle_source": model_path,
                "category": "parse_error",
                "parse_error": "invalid pickle stream",
                "exception_type": "ValueError",
                "analysis_incomplete": True,
                unexpected_field: "independent scanner failure",
            },
        )
    )

    assert result.has_errors is False
    assert result.success is True
    assert core_module.determine_exit_code(result) == 2
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "parse-error diagnostic with an additional error",
        )


@pytest.mark.parametrize(
    ("reason", "expected_message"),
    [
        pytest.param(
            "nested_pickle_incomplete",
            "Nested pickle analysis did not complete",
            id="nested-pickle-incomplete",
        ),
        pytest.param(
            "nested_probe_limit",
            "Nested pickle probe candidate limit exceeded",
            id="nested-probe-limit",
        ),
    ],
)
@pytest.mark.parametrize("message_state", ["missing", "corrupted"])
def test_organized_asset_scans_reject_invalid_nested_security_messages(
    reason: str,
    expected_message: str,
    message_state: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("dill_func.pkl")
    model_path = str(ASSETS / "dill_func.pkl")
    metadata = result.file_metadata[model_path]
    assert metadata.model_extra is not None
    metadata.model_extra["scan_outcome_reasons"] = [reason]

    diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
    matching_diagnostics = [
        diagnostic for diagnostic in diagnostics if diagnostic.details.get("notice_code") == "nested_pickle_incomplete"
    ]
    assert matching_diagnostics
    for diagnostic in matching_diagnostics:
        diagnostic.details["notice_code"] = reason
        diagnostic.message = "" if message_state == "missing" else f"{expected_message} (message corrupted)"

    assert result.success is False
    assert core_module.determine_exit_code(result) == 1
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{reason} with {message_state} user-facing message",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "failed-check", "passed-check"])
@pytest.mark.parametrize(
    "details",
    [
        pytest.param({"analysis_incomplete": True}, id="analysis-incomplete"),
        pytest.param({"scan_outcome": "inconclusive"}, id="inconclusive-outcome"),
    ],
)
def test_organized_asset_scans_reject_reasonless_incomplete_diagnostics(
    diagnostic_kind: str,
    details: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    if diagnostic_kind != "issue":
        result.checks.append(
            Check(
                name="Unexplained incomplete scan",
                status=CheckStatus.FAILED if diagnostic_kind == "failed-check" else CheckStatus.PASSED,
                message="Scanner analysis is incomplete",
                severity=IssueSeverity.INFO,
                location=model_path,
                details=details,
            )
        )
    else:
        result.issues.append(
            Issue(
                message="Scanner analysis is incomplete",
                severity=IssueSeverity.INFO,
                location=model_path,
                details=details,
            )
        )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{diagnostic_kind} with unexplained incomplete state",
        )


@pytest.mark.parametrize("diagnostic_kind", ["issue", "failed-check", "passed-check"])
@pytest.mark.parametrize(
    "details",
    [
        pytest.param({"category": "scanner_read_failed"}, id="failure-category"),
        pytest.param({"category": "io_error"}, id="error-category"),
        pytest.param({"operational_error_reason": "scanner_read_failed"}, id="operational-error-reason"),
        pytest.param({"scan_outcome_reasons": ["scanner_read_failed"]}, id="outcome-reasons"),
    ],
)
def test_organized_asset_scans_reject_diagnostic_only_operational_markers(
    diagnostic_kind: str,
    details: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(ASSETS / "safe_data.pkl")
    if diagnostic_kind != "issue":
        result.checks.append(
            Check(
                name="Hidden operational failure",
                status=CheckStatus.FAILED if diagnostic_kind == "failed-check" else CheckStatus.PASSED,
                message="Scanner operation failed",
                severity=IssueSeverity.INFO,
                location=model_path,
                details=details,
            )
        )
    else:
        result.issues.append(
            Issue(
                message="Scanner operation failed",
                severity=IssueSeverity.INFO,
                location=model_path,
                details=details,
            )
        )

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"{diagnostic_kind} with diagnostic-only operational marker",
        )


def test_organized_asset_scans_do_not_share_nested_dependency_diagnostic_with_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    archive_path = str(tmp_path / "outer.zip")
    nested_archive_path = f"{archive_path}:inner.zip"
    reason = "keras_h5_h5py_unavailable"
    for path in (archive_path, nested_archive_path):
        result.file_metadata[path] = FileMetadataModel(
            analysis_incomplete=True,
            scan_outcome="inconclusive",
            scan_outcome_reasons=[reason],
        )
    result.checks.append(
        Check(
            name="Nested H5PY Library Check",
            status=CheckStatus.FAILED,
            message="h5py is required for Keras H5 scanning.",
            severity=IssueSeverity.INFO,
            location=f"{nested_archive_path}:weights.h5",
            details={"required_package": "h5py", "scan_outcome_reason": reason},
            rule_code="S902",
        )
    )
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "nested dependency diagnostic must not satisfy parent",
        )


def test_organized_asset_scans_reject_reasonless_diagnostic_for_multiple_dependency_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    model_path = str(tmp_path / "multiple-h5py-outcomes.keras")
    result.file_metadata[model_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=[
            "keras_zip_embedded_weights_h5py_unavailable",
            "keras_zip_embedded_weights_hdf5_signature_probe_incomplete",
        ],
    )
    result.checks.append(
        Check(
            name="H5PY Library Check",
            status=CheckStatus.FAILED,
            message="h5py is unavailable for Keras weights analysis.",
            severity=IssueSeverity.INFO,
            location=model_path,
            details={"required_package": "h5py"},
            rule_code="S902",
        )
    )
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            "reasonless diagnostic for multiple dependency outcomes",
        )


def test_organized_asset_scans_preserve_security_exit_with_stable_coverage_only_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    coverage_path = str(tmp_path / "missing.keras")
    result.file_metadata[coverage_path] = FileMetadataModel(
        operational_error=True,
        operational_error_reason="recognized_format_scanner_unavailable",
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=["recognized_format_scanner_unavailable"],
    )
    result.checks.append(
        Check(
            name="Format Detection",
            status=CheckStatus.FAILED,
            message=test_security_asset_integration.EXPECTED_UNAVAILABLE_SCANNER_MESSAGE,
            severity=IssueSeverity.INFO,
            location=coverage_path,
            details={"format": "keras", "path": coverage_path},
        )
    )

    metadata = result.file_metadata[str(AGPL_ASSET)].model_dump(exclude_none=True)
    assert result.has_errors is False
    assert result.success is False
    assert metadata["pickle_verdict"] == "malicious"
    assert any(issue.rule_code == "S204" for issue in result.issues)
    assert core_module.determine_exit_code(result) == 1
    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "stable source with coverage-only outcome",
    )


@pytest.mark.parametrize(
    ("first_unavailable", "second_unavailable"),
    [(False, True), (True, False)],
    ids=["complete-to-incomplete", "incomplete-to-complete"],
)
def test_organized_asset_cache_preserves_missing_dependency_transitions(
    first_unavailable: bool,
    second_unavailable: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    safe_parser = pmml_scanner_module.DefusedET
    assert safe_parser is not None
    model_path = tmp_path / "cache-transition.pmml"
    model_path.write_text(
        "<?xml version='1.0'?><PMML version='4.4'><Header/><DataDictionary numberOfFields='0'/></PMML>",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"
    scan_results: list[tuple[bool, ModelAuditResultModel]] = []
    entry_counts: list[int] = []
    reset_cache_manager()
    try:
        for unavailable in (first_unavailable, second_unavailable):
            monkeypatch.setattr(pmml_scanner_module, "HAS_DEFUSEDXML", not unavailable)
            monkeypatch.setattr(pmml_scanner_module, "DefusedET", None if unavailable else safe_parser)
            result = core_module.scan_model_directory_or_file(
                str(model_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            scan_results.append((unavailable, result))
            cache_stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            entry_counts.append(cache_stats["total_entries"])
        final_cache_stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
    finally:
        reset_cache_manager()

    prior_entries = 0
    for (unavailable, result), entry_count in zip(scan_results, entry_counts, strict=True):
        metadata = result.file_metadata[str(model_path)].model_dump(exclude_none=True)
        root_diagnostics: list[Issue | Check] = [*result.issues, *result.checks]
        dependency_diagnostics = [
            diagnostic for diagnostic in root_diagnostics if diagnostic.details.get("required_package") == "defusedxml"
        ]
        assert result.has_errors is False
        assert result.success is not unavailable
        assert core_module.determine_exit_code(result) == (2 if unavailable else 0)
        assert bool(dependency_diagnostics) is unavailable
        assert (metadata.get("scan_outcome") == "inconclusive") is unavailable
        if unavailable:
            assert entry_count == prior_entries
        else:
            assert entry_count > prior_entries
        prior_entries = entry_count
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
            result,
            f"PMML cache transition unavailable={unavailable}",
        )
    assert final_cache_stats["cache_hits"] == 0
    assert final_cache_stats["cache_misses"] >= 4


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize("coverage_case", ["unavailable-scanner", "nested-routing"])
def test_organized_asset_scans_preserve_coverage_only_outcomes(
    integration_test: str,
    coverage_case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)

    if coverage_case == "nested-routing":
        archive_path = tmp_path / "mixed-routing.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "ambiguous.txt",
                "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
            )
        result = test_security_asset_integration.scan_model_directory_or_file_with_extraction_manifest(
            str(tmp_path),
            cache_enabled=False,
        )
        result = _merge_with_canonical_agpl_source_change(result)
        archive_metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
        assert "xml_model_routing_incomplete" in archive_metadata["scan_outcome_reasons"]
    else:
        result = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
        coverage_metadata = FileMetadataModel(
            operational_error=True,
            operational_error_reason="recognized_format_scanner_unavailable",
            analysis_incomplete=True,
            scan_outcome="inconclusive",
            scan_outcome_reasons=["recognized_format_scanner_unavailable"],
        )
        assert metadata_has_coverage_only_operational_error(coverage_metadata) is True
        coverage_path = str(tmp_path / "missing.keras")
        result.file_metadata[coverage_path] = coverage_metadata
        result.checks.append(
            Check(
                name="Format Detection",
                status=CheckStatus.FAILED,
                message=test_security_asset_integration.EXPECTED_UNAVAILABLE_SCANNER_MESSAGE,
                severity=IssueSeverity.INFO,
                location=coverage_path,
                details={"format": "keras", "path": coverage_path},
            )
        )

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    getattr(test_case, integration_test)(tmp_path)


@pytest.mark.parametrize(
    "integration_test",
    [
        "test_asset_discovery_completeness",
        "test_performance_with_organized_structure",
    ],
)
@pytest.mark.parametrize(
    "unexpected_error",
    [
        "different-category",
        "different-analysis",
        "clean-verdict",
        "unknown-verdict",
        "missing-security-signal",
        "additional-analysis",
        "issue-only-error",
        "marker-only-error",
        "directory-coverage-error",
        "interrupted-scan",
        "total-size-limit",
    ],
)
def test_organized_asset_scans_reject_unexpected_operational_errors(
    integration_test: str,
    unexpected_error: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _source_stability_error()

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)

    asset_path = AGPL_ASSET
    scan_target = AGPL_ASSET
    if unexpected_error == "additional-analysis":

        def raise_unexpected_call_graph_error(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("independent call-graph regression")

        monkeypatch.setattr(package_api, "find_dangerous_call_graphs", raise_unexpected_call_graph_error)
    elif unexpected_error == "issue-only-error":
        scan_target = tmp_path
        shutil.copy2(ASSETS / "safe_data.pkl", tmp_path / "safe_data.pkl")
        real_scan_file = core_module.scan_file

        def fail_secondary_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            if Path(path).name == "safe_data.pkl":
                raise RuntimeError("independent scanner regression")
            return real_scan_file(path, config)

        monkeypatch.setattr(core_module, "scan_file", fail_secondary_file)

    if unexpected_error == "total-size-limit":
        scan_target = tmp_path
        shutil.copy2(ASSETS / "safe_data.pkl", tmp_path / "safe_data.pkl")
        result = core_module.scan_model_directory_or_file(str(scan_target), cache_enabled=False, max_total_size=1)
        result = _merge_with_canonical_agpl_source_change(result)
    else:
        result = core_module.scan_model_directory_or_file(str(scan_target), cache_enabled=False)
        if unexpected_error == "issue-only-error":
            result = _merge_with_canonical_agpl_source_change(result)
    metadata = result.file_metadata[str(asset_path)]
    assert metadata.model_extra is not None

    if unexpected_error == "different-category":
        metadata.model_extra["operational_error_reason"] = "io_error"
    elif unexpected_error == "different-analysis":
        issue = next(issue for issue in result.issues if issue.details.get("category") == "call_graph_analysis_error")
        issue.details["analysis"] = "python_call_graph"
    elif unexpected_error == "clean-verdict":
        metadata.model_extra["pickle_verdict"] = "clean"
    elif unexpected_error == "unknown-verdict":
        metadata.model_extra["pickle_verdict"] = "unknown"
    elif unexpected_error == "missing-security-signal":
        result.issues = [issue for issue in result.issues if issue.rule_code != "S204"]
    elif unexpected_error == "additional-analysis":
        assert {
            issue.details.get("analysis")
            for issue in result.issues
            if issue.details.get("category") == "call_graph_analysis_error"
        } == {"python_call_graph", "python_call_graph_source_stability"}
    elif unexpected_error == "issue-only-error":
        assert str(tmp_path / "safe_data.pkl") not in result.file_metadata
        assert any(issue.message == "Error scanning file: independent scanner regression" for issue in result.issues)
    elif unexpected_error == "marker-only-error":
        result.issues.append(
            Issue(
                message="Special directory entry could not be scanned",
                severity=IssueSeverity.INFO,
                location=str(tmp_path / "unscanned-special-file"),
                details={
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "directory_special_file_unscanned",
                },
            )
        )
    elif unexpected_error == "directory-coverage-error":
        result.issues.append(
            Issue(
                message="Broken symlink encountered",
                severity=IssueSeverity.INFO,
                location=str(tmp_path / "unavailable-directory-entry"),
                details={
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "directory_entry_unavailable",
                },
            )
        )
    elif unexpected_error == "total-size-limit":
        assert any(
            issue.details.get("max_total_size") == 1 and issue.details.get("analysis_incomplete") is True
            for issue in result.issues
        )
    else:
        result.issues.append(
            Issue(
                message="Scan interrupted by user",
                severity=IssueSeverity.INFO,
                details={"interrupted": True},
            )
        )

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)
