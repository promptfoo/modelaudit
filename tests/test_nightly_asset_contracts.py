"""Coverage contracts for committed assets consumed by Nightly scans."""

import shutil
import zipfile
from pathlib import Path
from typing import Any

import modelaudit_picklescan.api as package_api
import pytest
from modelaudit_picklescan.call_graph import _CallGraphAnalysisLimitError

import modelaudit.core as core_module
import modelaudit.scanners.keras_h5_scanner as keras_h5_scanner_module
import modelaudit.scanners.tf_metagraph_scanner as tf_metagraph_scanner_module
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import metadata_has_coverage_only_operational_error, results_have_inconclusive_outcome
from modelaudit.models import FileMetadataModel, ModelAuditResultModel
from modelaudit.scanner_results import Issue, IssueSeverity, ScanResult
from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner
from modelaudit.scanners.manifest_scanner import ManifestScanner
from tests import test_security_asset_integration

ASSETS = Path(__file__).parent / "assets" / "samples" / "pickles"
AGPL_ASSET = Path(__file__).parent / "assets" / "scenarios" / "license_scenarios" / "agpl_component" / "agpl_model.pkl"


def _scan_asset(name: str) -> ModelAuditResultModel:
    return scan_model_directory_or_file(str(ASSETS / name), cache_enabled=False)


def test_complete_benign_asset_scans_cleanly() -> None:
    """The committed benign fixture must remain complete and issue-free."""
    result = _scan_asset("safe_data.pkl")

    assert result.has_errors is False
    assert results_have_inconclusive_outcome(result) is False
    assert determine_exit_code(result) == 0
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
    assert determine_exit_code(result) == 1
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
    assert determine_exit_code(result) == 1


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
            raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

        monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    else:
        monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", lambda _report_generation: None)

    result = scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    metadata = result.file_metadata[str(AGPL_ASSET)].model_dump(exclude_none=True)

    assert result.has_errors is source_changes
    assert result.success is False
    assert results_have_inconclusive_outcome(result) is True
    assert determine_exit_code(result) == (2 if source_changes else 1)
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
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    archive_path = tmp_path / "nested.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(AGPL_ASSET, "model.pkl")

    result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)
    metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)

    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
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
def test_organized_asset_scans_reject_unrelated_archive_budget_failures(
    integration_test: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    shutil.copy2(AGPL_ASSET, tmp_path / "agpl_model.pkl")
    archive_path = tmp_path / "unrelated-budget-failure.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("weights.msgpack", b"\x81\xa6params\x80" * 2)
        archive.writestr(
            "ambiguous.txt",
            "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
        )

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, max_msgpack_stream_objects=1)
    archive_metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
    assert archive_metadata["operational_error_reason"] == "xml_model_routing_incomplete"
    assert any(
        issue.location == f"{archive_path}:weights.msgpack"
        and issue.rule_code == "S902"
        and issue.details.get("max_msgpack_stream_objects") == 1
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
def test_organized_asset_scans_reject_source_changes_outside_agpl_fixture(
    integration_test: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    other_pickle = tmp_path / "other.pkl"
    shutil.copy2(AGPL_ASSET, other_pickle)
    result = scan_model_directory_or_file(str(other_pickle), cache_enabled=False)
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
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    real_find_call_graphs = package_api.find_dangerous_call_graphs
    analyzed_members = 0

    def fail_first_member(*args: Any, **kwargs: Any) -> Any:
        nonlocal analyzed_members
        analyzed_members += 1
        if analyzed_members == 1:
            raise RuntimeError("independent archive-member call-graph regression")
        return real_find_call_graphs(*args, **kwargs)

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    monkeypatch.setattr(package_api, "find_dangerous_call_graphs", fail_first_member)
    archive_path = tmp_path / "multiple-pickles.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(AGPL_ASSET, "unexpected.pkl")
        archive.write(AGPL_ASSET, "expected.pkl")

    result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

    assert analyzed_members == 2
    assert result.has_errors is True
    assert any(
        issue.location == f"{archive_path}:unexpected.pkl"
        and issue.details.get("analysis") == "python_call_graph"
        and issue.details.get("exception_type") == "RuntimeError"
        for issue in result.issues
    )
    assert any(
        issue.location == f"{archive_path}:expected.pkl"
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
@pytest.mark.parametrize("timeout_source", ["manifest-scanner", "core-wrapper"])
def test_organized_asset_scans_reject_mixed_archive_member_timeouts(
    integration_test: str,
    timeout_source: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

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
        archive.write(AGPL_ASSET, "model.pkl")

    result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)
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
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

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
        archive.write(AGPL_ASSET, "model.pkl")

    result = scan_model_directory_or_file(str(archive_path), cache_enabled=False, max_msgpack_stream_objects=1)
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
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", h5_available)
    shutil.copy2(AGPL_ASSET, tmp_path / "agpl_model.pkl")
    shutil.copy2(ASSETS.parent / "keras" / "malicious_lambda.h5", tmp_path / "malicious_lambda.h5")
    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

    expected_detail = "suspicious_term" if h5_available else "required_package"
    assert any(issue.rule_code == "S902" and expected_detail in issue.details for issue in result.issues)

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
@pytest.mark.parametrize("coverage_case", ["unavailable-scanner", "nested-routing"])
def test_organized_asset_scans_preserve_coverage_only_outcomes(
    integration_test: str,
    coverage_case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)

    if coverage_case == "nested-routing":
        archive_path = tmp_path / "mixed-routing.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "ambiguous.txt",
                "<?xml version='1.0'?><!--" + "x" * (1024 * 1024 + 64) + "--><PMML version='4.4'></PMML>",
            )
        shutil.copy2(AGPL_ASSET, tmp_path / "agpl_model.pkl")
        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)
        archive_metadata = result.file_metadata[str(archive_path)].model_dump(exclude_none=True)
        assert "xml_model_routing_incomplete" in archive_metadata["scan_outcome_reasons"]
    else:
        result = scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
        coverage_metadata = FileMetadataModel(
            operational_error=True,
            operational_error_reason="recognized_format_scanner_unavailable",
            analysis_incomplete=True,
            scan_outcome="inconclusive",
            scan_outcome_reasons=["recognized_format_scanner_unavailable"],
        )
        assert metadata_has_coverage_only_operational_error(coverage_metadata) is True
        result.file_metadata[str(tmp_path / "missing.keras")] = coverage_metadata

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
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)

    asset_path = AGPL_ASSET
    scan_target = AGPL_ASSET
    if unexpected_error == "additional-analysis":

        def raise_unexpected_call_graph_error(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("independent call-graph regression")

        monkeypatch.setattr(package_api, "find_dangerous_call_graphs", raise_unexpected_call_graph_error)
    elif unexpected_error == "issue-only-error":
        asset_path = tmp_path / "agpl_model.pkl"
        scan_target = tmp_path
        shutil.copy2(AGPL_ASSET, asset_path)
        shutil.copy2(ASSETS / "safe_data.pkl", tmp_path / "safe_data.pkl")
        real_scan_file = core_module.scan_file

        def fail_secondary_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            if Path(path).name == "safe_data.pkl":
                raise RuntimeError("independent scanner regression")
            return real_scan_file(path, config)

        monkeypatch.setattr(core_module, "scan_file", fail_secondary_file)

    if unexpected_error == "total-size-limit":
        asset_path = tmp_path / "agpl_model.pkl"
        scan_target = tmp_path
        shutil.copy2(AGPL_ASSET, asset_path)
        result = scan_model_directory_or_file(str(scan_target), cache_enabled=False, max_total_size=1)
    else:
        result = scan_model_directory_or_file(str(scan_target), cache_enabled=False)
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
