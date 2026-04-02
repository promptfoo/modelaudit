from __future__ import annotations

import pytest
from modelaudit_picklescan import (
    CoverageSummary,
    Finding,
    Notice,
    PickleReport,
    SafetyVerdict,
    ScanError,
    ScanStatus,
    Severity,
)


def test_clean_report_requires_complete_status_and_clean_verdict() -> None:
    report = PickleReport(
        source="safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        notices=(Notice(message="Raw scan complete"),),
        coverage=CoverageSummary(bytes_scanned=128, bytes_total=128, raw_scan_complete=True, opcode_scan_complete=True),
    )

    assert report.is_clean is True
    assert report.has_security_findings is False
    assert report.to_dict()["is_clean"] is True


def test_inconclusive_report_is_not_clean_even_without_findings() -> None:
    report = PickleReport(
        source="large.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(Notice(message="Opcode budget reached", severity=Severity.INFO, code="opcode_budget"),),
    )

    assert report.is_clean is False
    assert report.has_security_findings is False


def test_malicious_report_separates_findings_notices_and_errors() -> None:
    report = PickleReport(
        source="payload.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found REDUCE opcode invoking dangerous global: os.system",
                severity=Severity.CRITICAL,
                location="payload.pkl (pos 42)",
                rule_code="S201",
                details={"global": "os.system"},
                why="REDUCE can invoke attacker-controlled callables during unpickling.",
            ),
        ),
        notices=(Notice(message="ML context not detected", severity=Severity.INFO),),
        errors=(ScanError(message="post-budget scan skipped", category="coverage", location="payload.pkl"),),
    )

    serialized = report.to_dict()

    assert report.is_clean is False
    assert report.has_security_findings is True
    assert serialized["findings"][0]["rule_code"] == "S201"
    assert serialized["notices"][0]["severity"] == "info"
    assert serialized["errors"][0]["category"] == "coverage"


def test_findings_and_notices_reject_the_wrong_severity_band() -> None:
    with pytest.raises(ValueError, match="finding severity must be warning/critical"):
        Finding(message="debug detail", severity=Severity.INFO)

    with pytest.raises(ValueError, match="notice severity must be debug/info"):
        Notice(message="actual security issue", severity=Severity.WARNING)
