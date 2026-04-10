import json
import logging
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


def test_legacy_baseline_pickle_scanner_accepts_reuse_seekable_keyword(tmp_path: Path) -> None:
    path = tmp_path / "safe.pkl"
    path.write_bytes(b"\x80\x04}q\x00.")
    scanner = compare_pickle_scanners.LegacyBaselinePickleScanner()

    with path.open("rb") as handle:
        result = scanner._scan_pickle_stream_with_package_engine(
            handle,
            path.stat().st_size,
            source=str(path),
            reuse_seekable_stream_for_legacy=True,
        )

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


def test_classify_delta_does_not_treat_unknown_to_clean_as_false_positive() -> None:
    legacy_result = compare_pickle_scanners.NormalizedResult(
        engine="legacy",
        status="inconclusive",
        verdict="unknown",
        success=False,
        warning_count=0,
        critical_count=0,
        info_count=0,
        rule_codes=(),
        messages=(),
        metadata={},
    )
    package_result = compare_pickle_scanners.NormalizedResult(
        engine="package",
        status="complete",
        verdict="clean",
        success=True,
        warning_count=0,
        critical_count=0,
        info_count=0,
        rule_codes=(),
        messages=(),
        metadata={},
    )

    assert compare_pickle_scanners._classify_delta("safe", legacy_result, package_result) == "verdict_drift"


def test_status_drift_fails_harness_exit_gate() -> None:
    report = {
        "comparisons": [
            {
                "package_delta": "status_drift",
                "adapter_delta": "match",
            }
        ]
    }

    assert compare_pickle_scanners._has_exit_failure_drift(report) is True


def test_build_report_summarizes_drift_by_fixture_label_and_preserves_safe_fp_audit() -> None:
    report = compare_pickle_scanners._build_report()

    assert report["summary_by_label"]["package"]["safe"] == {"match": 6}
    assert report["summary_by_label"]["adapter"]["safe"] == {"match": 6}
    assert "potential_fp" not in report["summary_by_label"]["package"]["safe"]
    assert "potential_fp" not in report["summary_by_label"]["adapter"]["safe"]

    exploit4 = next(
        item
        for item in report["comparisons"]
        if item["path"] == "tests/assets/exploits/exploit4_supply_chain_attack.pkl"
    )
    assert exploit4["package_delta"] == "rule_drift"
    assert exploit4["adapter_delta"] == "rule_drift"
    assert "S310" in exploit4["legacy"]["rule_codes"]


def test_build_report_can_include_root_standalone_primary_mode() -> None:
    report = compare_pickle_scanners._build_report(
        include_root=True,
        root_config={"use_standalone_pickle_primary": True},
    )

    assert "root" in report["summary"]
    assert report["summary_by_label"]["root"]["safe"] == {"match": 6}
    first_comparison = report["comparisons"][0]
    assert "root_delta" in first_comparison
    assert first_comparison["root"]["engine"] == "root"
    assert first_comparison["root"]["metadata"]["pickle_primary_engine"] == "standalone"


def test_fixture_label_marks_clear_malicious_paths_without_overlabeling_license_fixtures() -> None:
    assert (
        compare_pickle_scanners._fixture_label(
            Path("tests/assets/scenarios/security_scenarios/mixed_malicious_model/model.pkl")
        )
        == "malicious"
    )
    assert compare_pickle_scanners._fixture_label(Path("tests/assets/samples/pickles/evil.pickle")) == "malicious"
    assert (
        compare_pickle_scanners._fixture_label(
            Path("tests/assets/scenarios/license_scenarios/agpl_component/agpl_model.pkl")
        )
        == "unknown"
    )


def test_fixture_label_rejects_missing_manifest_entries() -> None:
    with pytest.raises(KeyError, match="missing pickle fixture label"):
        compare_pickle_scanners._fixture_label(Path("tests/assets/samples/pickles/new_fixture.pkl"))


def test_fixture_label_loads_manifest_lazily(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "fixture-labels.json"
    manifest.write_text(
        json.dumps({"tests/assets/samples/pickles/new_fixture.pkl": "safe"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(compare_pickle_scanners, "FIXTURE_LABELS_MANIFEST", manifest)
    monkeypatch.setattr(compare_pickle_scanners, "_FIXTURE_LABELS_BY_PATH", None)

    assert compare_pickle_scanners._fixture_label(Path("tests/assets/samples/pickles/new_fixture.pkl")) == "safe"


def test_build_report_suppresses_scanner_logs_and_restores_logging_disable_level(
    capsys: pytest.CaptureFixture[str],
) -> None:
    previous_disable_level = logging.root.manager.disable
    logging.disable(logging.WARNING)
    try:
        report = compare_pickle_scanners._build_report()
        captured = capsys.readouterr()
        assert report["fixture_count"] > 0
        assert captured.out == ""
        assert captured.err == ""
        assert logging.root.manager.disable == logging.WARNING
    finally:
        logging.disable(previous_disable_level)
