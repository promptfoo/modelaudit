"""Coverage contracts for committed assets consumed by performance scans."""

from pathlib import Path

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import results_have_inconclusive_outcome
from modelaudit.models import ModelAuditResultModel

ASSETS = Path(__file__).parent / "assets" / "samples" / "pickles"


def _scan_asset(name: str) -> ModelAuditResultModel:
    return scan_model_directory_or_file(str(ASSETS / name), cache_enabled=False)


def test_complete_performance_pickle_assets_are_not_inconclusive() -> None:
    """Complete benign and malicious fixture scans must not hide coverage gaps."""
    safe_result = _scan_asset("safe_data.pkl")
    malicious_result = _scan_asset("evil.pickle")

    for result in (safe_result, malicious_result):
        assert result.has_errors is False
        assert results_have_inconclusive_outcome(result) is False

    assert determine_exit_code(safe_result) == 0
    assert safe_result.issues == []
    assert determine_exit_code(malicious_result) == 1
    assert any(
        issue.rule_code == "S201" and issue.message == "Found REDUCE opcode invoking dangerous global: posix.system"
        for issue in malicious_result.issues
    )


def test_intentional_incomplete_pickle_asset_preserves_security_exit() -> None:
    """The dill fixture is intentionally incomplete but still security-positive."""
    result = _scan_asset("dill_func.pkl")
    path = str(ASSETS / "dill_func.pkl")
    metadata = result.file_metadata[path].model_dump(exclude_none=True)

    assert result.has_errors is False
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
