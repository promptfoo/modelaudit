from pathlib import Path

import pytest
from modelaudit_picklescan import Finding, PickleReport, SafetyVerdict, ScanStatus, Severity

from scripts import compare_pickle_scanners


def test_legacy_baseline_pickle_scanner_bypasses_package_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(b"\x80\x04}q\x00.")
    scanner = compare_pickle_scanners.LegacyBaselinePickleScanner()

    def fail_if_package_engine_runs(*_args: object, **_kwargs: object) -> PickleReport:
        raise AssertionError("legacy baseline must not invoke the package pickle scanner")

    monkeypatch.setattr(
        scanner._standalone_pickle_scanner,
        "scan_stream",
        fail_if_package_engine_runs,
    )

    result = scanner.scan(str(path))

    assert result.success is True
    assert not result.issues


def test_scan_fixture_surfaces_package_only_findings_as_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(b"\x80\x04}q\x00.")

    def fake_package_scan_file(_path: Path) -> PickleReport:
        return PickleReport(
            source=str(_path),
            status=ScanStatus.COMPLETE,
            verdict=SafetyVerdict.MALICIOUS,
            findings=(
                Finding(
                    message="package-only synthetic finding",
                    severity=Severity.CRITICAL,
                    location=str(_path),
                    rule_code="S999",
                ),
            ),
        )

    monkeypatch.setattr(compare_pickle_scanners, "package_scan_file", fake_package_scan_file)

    legacy_result, package_result, adapter_result = compare_pickle_scanners._scan_fixture(
        path,
        compare_pickle_scanners.LegacyBaselinePickleScanner(),
    )

    assert legacy_result.rule_codes == ()
    assert package_result.rule_codes == ("S999",)
    assert adapter_result.rule_codes == ("S999",)
    assert compare_pickle_scanners._classify_delta("safe", legacy_result, package_result) == "potential_fp"
    assert compare_pickle_scanners._classify_delta("safe", legacy_result, adapter_result) == "potential_fp"
