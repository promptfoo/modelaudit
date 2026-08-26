"""Coverage contracts for committed assets consumed by Nightly scans."""

import io
import shutil
import sys
import tarfile
import zipfile
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


def _source_stability_error() -> _CallGraphAnalysisLimitError:
    return _CallGraphAnalysisLimitError(
        "source changed during shared call-graph analysis",
        stability_reason=test_security_asset_integration.EXPECTED_AGPL_SOURCE_STABILITY_REASON,
    )


def _scan_asset(name: str) -> ModelAuditResultModel:
    return core_module.scan_model_directory_or_file(str(ASSETS / name), cache_enabled=False)


def _merge_with_canonical_agpl_source_change(result: ModelAuditResultModel) -> ModelAuditResultModel:
    expected_source_change = core_module.scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    expected_source_change.aggregate_scan_result(result)
    return expected_source_change


def _assert_otherwise_accepted_archive_control(
    result: ModelAuditResultModel,
    failed_member: str,
    hidden_reason: str | None = None,
    *,
    hidden_reasons: frozenset[str] = frozenset(),
) -> None:
    control = result.model_copy(deep=True)
    control.issues = [issue for issue in control.issues if issue.location != failed_member]
    control.checks = [check for check in control.checks if check.location != failed_member]
    for archive_path, metadata in control.file_metadata.items():
        if not failed_member.startswith(f"{archive_path}:") or metadata.model_extra is None:
            continue
        reasons = metadata.model_extra.get("scan_outcome_reasons")
        if isinstance(reasons, list):
            metadata.model_extra["scan_outcome_reasons"] = [
                reason
                for reason in reasons
                if reason != hidden_reason
                and reason not in hidden_reasons
                and not (
                    isinstance(reason, str)
                    and reason.endswith(("_failed", "_error", "_exceeded", "_timeout", "_interrupted"))
                )
            ]
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

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False, max_msgpack_stream_objects=1)
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

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
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

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
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

    result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False, max_msgpack_stream_objects=1)
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


def test_organized_asset_scans_preserve_real_keras_zip_hdf5_probe_missing_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
    model_path = tmp_path / "missing-hdf5-probe-dependency.keras"
    hdf5_signature_offset = 16 * 1024 * 1024
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
    result = _scan_asset("safe_data.pkl")
    archive_path = str(tmp_path / "multiple-missing-dependencies.zip")
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
        ]
    )
    result.success = False
    assert core_module.determine_exit_code(result) == 2

    test_security_asset_integration.assert_no_unexpected_asset_scan_errors(
        result,
        "nested missing dependencies",
    )

    missing_diagnostic = result.model_copy(deep=True)
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
    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)
    result = _scan_asset("safe_data.pkl")
    archive_path = str(tmp_path / "mixed-dependency-and-coverage.zip")
    dependency_reason = "keras_h5_h5py_unavailable"
    coverage_reason = "xml_model_routing_incomplete"
    result.file_metadata[archive_path] = FileMetadataModel(
        analysis_incomplete=True,
        scan_outcome="inconclusive",
        scan_outcome_reasons=[dependency_reason, coverage_reason],
    )
    result.checks.append(
        Check(
            name="H5PY Library Check",
            status=CheckStatus.FAILED,
            message="h5py is required for Keras H5 scanning.",
            severity=IssueSeverity.INFO,
            location=f"{archive_path}:weights.h5",
            details={"required_package": "h5py", "scan_outcome_reason": dependency_reason},
            rule_code="S902",
        )
    )
    result.issues.append(
        Issue(
            message="Embedded pickle finding",
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:payload.pkl",
            rule_code="S204",
        )
    )
    result.success = False
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
        result = core_module.scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
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
