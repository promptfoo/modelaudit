from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any, cast

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
from modelaudit_picklescan.api import _report_from_native_dict


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


def test_pickle_report_preserves_positional_duration_s_compatibility() -> None:
    report = PickleReport(
        "safe.pkl",
        ScanStatus.COMPLETE,
        SafetyVerdict.CLEAN,
        (),
        (),
        (),
        CoverageSummary(),
        {},
        0.1,
    )

    assert report.duration_s == 0.1
    assert report.private_metadata == {}


def test_inconclusive_report_is_not_clean_even_without_findings() -> None:
    report = PickleReport(
        source="large.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(Notice(message="Opcode budget reached", severity=Severity.INFO, code="opcode_budget"),),
    )

    assert report.is_clean is False
    assert report.has_security_findings is False


def test_complete_unknown_report_without_findings_is_not_clean() -> None:
    report = PickleReport(
        source="unknown.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.UNKNOWN,
    )

    assert report.is_clean is False
    assert report.has_security_findings is False


def test_complete_clean_report_with_findings_is_not_clean() -> None:
    report = PickleReport(
        source="contradictory.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        findings=(
            Finding(
                message="Suspicious reference",
                severity=Severity.WARNING,
                location="contradictory.pkl (pos 3)",
                rule_code="S203",
            ),
        ),
    )

    assert report.is_clean is False
    assert report.has_security_findings is True


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


def test_report_mappings_are_read_only_after_construction() -> None:
    details: dict[str, Any] = {"symbol": "os.system", "nested": {"symbols": ["os.system"]}}
    metadata: dict[str, Any] = {"opcode_count": 3, "nested": {"globals": ["os.system"]}}
    finding = Finding(message="Suspicious reference", severity=Severity.WARNING, details=details)
    report = PickleReport(
        source="payload.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(finding,),
        metadata=metadata,
    )

    details["nested"]["symbols"][0] = "builtins.eval"
    metadata["nested"]["globals"][0] = "builtins.eval"

    with pytest.raises(TypeError):
        cast(MutableMapping[str, object], finding.details)["symbol"] = "builtins.eval"

    with pytest.raises(TypeError):
        cast(MutableMapping[str, object], report.metadata)["opcode_count"] = 4

    with pytest.raises(TypeError):
        cast(MutableMapping[str, object], finding.details["nested"])["symbols"] = []

    with pytest.raises(TypeError):
        cast(MutableMapping[str, object], report.metadata["nested"])["globals"] = []

    serialized_finding = finding.to_dict()["details"]
    serialized_metadata = report.to_dict()["metadata"]
    serialized_finding["nested"]["symbols"].append("mutated")
    serialized_metadata["nested"]["globals"].append("mutated")

    assert finding.to_dict()["details"] == {"symbol": "os.system", "nested": {"symbols": ["os.system"]}}
    assert report.to_dict()["metadata"] == {"opcode_count": 3, "nested": {"globals": ["os.system"]}}


def test_rust_report_conversion_rejects_non_bool_coverage_flags() -> None:
    raw_report = {
        "source": "native.pkl",
        "status": "complete",
        "verdict": "clean",
        "findings": [],
        "notices": [],
        "errors": [],
        "coverage": {
            "bytes_scanned": 0,
            "raw_scan_complete": "false",
            "opcode_scan_complete": True,
        },
        "metadata": {},
        "duration_s": 0.0,
    }

    with pytest.raises(TypeError, match="expected bool or None"):
        _report_from_native_dict(raw_report)
