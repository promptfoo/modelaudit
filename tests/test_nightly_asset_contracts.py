"""Coverage contracts for committed assets consumed by Nightly scans."""

from pathlib import Path

import modelaudit_picklescan.api as package_api
import pytest
from modelaudit_picklescan.call_graph import _CallGraphAnalysisLimitError

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import results_have_inconclusive_outcome
from modelaudit.models import ModelAuditResultModel
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
@pytest.mark.parametrize("unexpected_error", ["different-category", "different-analysis", "clean-verdict"])
def test_organized_asset_scans_reject_unexpected_operational_errors(
    integration_test: str,
    unexpected_error: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_source_stability_error(_report_generation: int | None) -> None:
        raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")

    monkeypatch.setattr(package_api, "_ensure_shared_source_snapshot_stable", raise_source_stability_error)
    result = scan_model_directory_or_file(str(AGPL_ASSET), cache_enabled=False)
    metadata = result.file_metadata[str(AGPL_ASSET)]
    assert metadata.model_extra is not None

    if unexpected_error == "different-category":
        metadata.model_extra["operational_error_reason"] = "io_error"
    elif unexpected_error == "different-analysis":
        issue = next(issue for issue in result.issues if issue.details.get("category") == "call_graph_analysis_error")
        issue.details["analysis"] = "python_call_graph"
    else:
        metadata.model_extra["pickle_verdict"] = "clean"

    monkeypatch.setattr(
        test_security_asset_integration,
        "scan_model_directory_or_file",
        lambda *_args, **_kwargs: result,
    )

    test_case = test_security_asset_integration.TestSecurityAssetIntegration()
    with pytest.raises(AssertionError, match="unexpected operational errors"):
        getattr(test_case, integration_test)(tmp_path)
