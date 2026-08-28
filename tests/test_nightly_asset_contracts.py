"""Coverage contracts for committed assets consumed by Nightly scans."""

import shutil
from pathlib import Path

import modelaudit_picklescan.api as package_api
import pytest
from modelaudit_picklescan.call_graph import _CallGraphAnalysisLimitError

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import results_have_inconclusive_outcome
from modelaudit.models import AssetModel, ModelAuditResultModel
from modelaudit.scanner_results import CheckStatus, IssueSeverity
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


def _scan_agpl(path: Path, source_changes: bool, monkeypatch: pytest.MonkeyPatch) -> ModelAuditResultModel:
    def enforce_source_stability(_report_generation: int | None) -> None:
        if source_changes:
            raise _CallGraphAnalysisLimitError(
                "source changed during shared call-graph analysis",
                stability_reason="source_search_context_changed",
            )

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", enforce_source_stability)
    return scan_model_directory_or_file(str(path), cache_enabled=False)


def _mutate_changed_source_result(result: ModelAuditResultModel, case: str, tmp_path: Path) -> None:
    if case.startswith(("root-", "nested-", "bare-")):
        key = case.partition("-")[2].replace("-", "_")
        details: dict[str, object] = {key: "scanner_error" if key == "category" else "path_is_directory"}
        if case == "root-operational-diagnostics":
            details = {"findings": [{"details": {"scan_outcome_reason": "scanner_error"}}]}
        elif case == "bare-incomplete":
            details = {"analysis_incomplete": True, "scan_outcome": "inconclusive"}
        elif case == "root-tuple-error":
            details = {"findings": ({"details": {"error": "scanner failure"}},)}
        elif case.startswith("nested-"):
            details = {"findings": [{"details": details}]}
        result.issues.append(result.issues[0].model_copy(update={"details": details}))
        result.checks.append(result.checks[0].model_copy(update={"details": details}))
        return
    if case == "error-asset":
        asset = result.assets[0] if result.assets else AssetModel(path=str(tmp_path / "other.pkl"), type="error")
        result.assets.append(asset.model_copy(update={"type": "error"}))
        return
    metadata = result.file_metadata[str(AGPL_ASSET)]
    assert metadata.model_extra is not None
    if case.endswith("metadata-error"):
        metadata_path = AGPL_ASSET if case.startswith("canonical") else tmp_path / "other.pkl"
        result.file_metadata[str(metadata_path)] = metadata.model_copy(update={"error": "unrelated scanner failure"})
        return
    if case.startswith("scan-reason"):
        key = "scan_outcome_reasons" if case.endswith("s") else "scan_outcome_reason"
        metadata.model_extra[key] = ["scanner_error"] if key.endswith("reasons") else "scanner_error"
        return
    if case == "wrong-s204-location" or case.startswith("extra-s204-") or case == "extra-source-identity":
        other = str(tmp_path / "other.pkl")
        for records in (getattr(result, name) for name in ("issues", "checks")):
            candidate = next(item for item in records if item.rule_code == "S204")
            if case == "wrong-s204-location":
                candidate.location = other
            elif case == "extra-source-identity":
                candidate.location = str(AGPL_ASSET)
                records.append(candidate.model_copy(update={"rule_code": "S902", "message": "changed", "details": {}}))
            else:
                key = "pickle_source" if case.endswith("source") else "associated_global"
                details = {} if case.endswith("identity") else {**candidate.details, key: other}
                update = {"location": other} if case.endswith("candidate") else {"details": details}
                records.append(candidate.model_copy(update=update))
        return
    if case.startswith("missing-s204-"):
        records = getattr(result, f"{case.rpartition('-')[2]}s")
        records[:] = [item for item in records if item.rule_code != "S204"]
        return
    if case in {"additional-operational-owner", "false-operational-reason"} or "mixed" in case:
        metadata_update: dict[str, object] = {}
        if case != "additional-operational-owner":
            reason = "recognized_format_scanner_unavailable" if "mixed" in case else "path_is_directory"
            metadata_update = {"operational_error": "mixed" in case, "operational_error_reason": reason}
            if "mixed" in case:
                metadata_update["scan_outcome_reasons"] = [reason, "scanner_error"]
        metadata_path = AGPL_ASSET if case.endswith("-mixed") else tmp_path / "other.pkl"
        result.file_metadata[str(metadata_path)] = metadata.model_copy(deep=True, update=metadata_update)
        return
    issue = next(item for item in result.issues if item.details.get("analysis") == "python_call_graph_source_stability")
    check = next(item for item in result.checks if item.details.get("analysis") == "python_call_graph_source_stability")
    reasons = list(metadata.model_extra["scan_outcome_reasons"])
    if case == "wrong-operational-reason":
        metadata.model_extra["operational_error_reason"] = "scanner_error"
    elif case == "missing-outcome-reason":
        metadata.model_extra["scan_outcome_reasons"] = reasons[:-1]
    elif case == "duplicate-outcome-reason":
        metadata.model_extra["scan_outcome_reasons"] = [*reasons, reasons[0]]
    elif case in {"wrong-report-status", "wrong-verdict"}:
        key = "pickle_report_status" if case == "wrong-report-status" else "pickle_verdict"
        metadata.model_extra[key] = "complete" if case == "wrong-report-status" else "clean"
    elif case in {"wrong-message", "wrong-diagnostic-location"}:
        value = "Python call-graph analysis failed" if case == "wrong-message" else str(tmp_path / "agpl_model.pkl")
        setattr(issue, "message" if case == "wrong-message" else "location", value)
    elif case in {"wrong-analysis", "wrong-category", "wrong-exception", "extra-diagnostic-detail"}:
        detail_key, detail_value = {
            "wrong-analysis": ("analysis", "python_call_graph"),
            "wrong-category": ("category", "scanner_error"),
            "wrong-exception": ("exception_type", "RuntimeError"),
            "extra-diagnostic-detail": ("unexpected", True),
        }[case]
        issue.details[detail_key] = detail_value
    elif case == "wrong-stability-reason":
        issue.details["source_stability_reason"] = "source_file_changed"
    elif case == "wrong-diagnostic-source":
        issue.details["pickle_source"] = str(tmp_path / "agpl_model.pkl")
    elif case == "wrong-rule-severity":
        issue.rule_code = "S901"
        check.severity = IssueSeverity.WARNING
    elif case == "wrong-issue-type":
        issue.type = "scanner_error"
    elif case == "wrong-check-contract":
        check.name = "Pickle Error"
        check.status = CheckStatus.PASSED
    elif case in {"missing-source-issue", "missing-source-check"}:
        target = case.removeprefix("missing-source-")
        getattr(result, f"{target}s").remove(issue if target == "issue" else check)
    elif case == "extra-source-candidate":
        result.issues.append(issue.model_copy(deep=True))
    elif case in {"has-errors-false", "success-true"}:
        setattr(result, "has_errors" if case == "has-errors-false" else "success", case == "success-true")
    else:
        raise AssertionError(f"unknown mutation: {case}")


@pytest.mark.parametrize("source_changes", [False, True], ids=["stable-source", "changed-source"])
def test_organized_asset_scans_preserve_fail_closed_source_stability(
    source_changes: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _scan_agpl(AGPL_ASSET, source_changes, monkeypatch)
    assert determine_exit_code(result) == (2 if source_changes else 1)
    monkeypatch.setattr(test_security_asset_integration, "scan_model_directory_or_file", lambda *_a, **_kw: result)
    test_security_asset_integration.TestSecurityAssetIntegration().test_asset_discovery_completeness(tmp_path)
    test_security_asset_integration.TestSecurityAssetIntegration().test_performance_with_organized_structure(tmp_path)


def test_organized_asset_scans_reject_noncanonical_or_malformed_source_stability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied_asset = tmp_path / AGPL_ASSET.name
    shutil.copy2(AGPL_ASSET, copied_asset)
    copied_result = _scan_agpl(copied_asset, True, monkeypatch)
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        test_security_asset_integration.assert_no_unexpected_asset_scan_errors(copied_result, "copied AGPL")
    cases = (  # noqa: SIM905
        "additional-operational-owner wrong-diagnostic-location wrong-operational-reason duplicate-outcome-reason "
        "wrong-diagnostic-source extra-diagnostic-detail missing-outcome-reason wrong-stability-reason wrong-exception "
        "extra-source-candidate wrong-check-contract missing-source-issue has-errors-false wrong-verdict wrong-message "
        "missing-source-check wrong-report-status wrong-rule-severity wrong-issue-type wrong-analysis wrong-category "
        "success-true root-operational-error-reason root-operational-diagnostics mixed-operational-reasons error-asset "
        "false-operational-reason extra-s204-wrong-source extra-s204-wrong-global canonical-mixed root-exception "
        "extra-s204-candidate root-exception-type wrong-s204-location missing-s204-issue missing-s204-check root-error "
        "extra-s204-identity root-tuple-error bare-incomplete root-category nested-error scan-reasons scan-reason "
        "extra-source-identity canonical-metadata-error noncanonical-metadata-error"
    ).split()
    for source_changes, mutations in ((True, cases), (False, cases[-25:])):
        baseline = _scan_agpl(AGPL_ASSET, source_changes, monkeypatch)
        for case in mutations:
            result = baseline.model_copy(deep=True)
            _mutate_changed_source_result(result, case, tmp_path)
            with pytest.raises(AssertionError, match="unexpected operational errors"):
                test_security_asset_integration.assert_no_unexpected_asset_scan_errors(result, case)
