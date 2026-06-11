from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from modelaudit_picklescan import (
    CoverageSummary,
    Finding,
    Notice,
    PickleReport,
    SafetyVerdict,
    ScanError,
    ScanOptions,
    ScanStatus,
    Severity,
    scan_bytes,
)

from modelaudit.cache.cache_policy import should_cache_scan_result
from modelaudit.config.rule_config import ModelAuditConfig, set_config
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.executorch_scanner import ExecuTorchScanner
from modelaudit.scanners.picklescan_adapter import (
    apply_pickle_member_context,
    pickle_report_to_scan_result,
    scan_options_from_config,
)
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
from tests.helpers import create_mock_pytorch_zip

_PINNED_DISTILBERT_URL = (
    "https://huggingface.co/distilbert/distilbert-base-uncased/resolve/"
    "12040accade4e8a0f71eabdb258fecc2e7e948be/pytorch_model.bin"
)


def _benign_tail_import_references() -> list[dict[str, object]]:
    return [
        {
            "import_reference": "numpy.core.multiarray.scalar",
            "module": "numpy.core.multiarray",
            "name": "scalar",
            "opcode": "GLOBAL",
            "position": 3,
            "is_dangerous": False,
        },
    ]


@dataclass(frozen=True, slots=True)
class _LegacyPickleReport:
    source: str
    status: ScanStatus
    verdict: SafetyVerdict
    findings: tuple[Finding, ...] = ()
    notices: tuple[Notice, ...] = ()
    errors: tuple[ScanError, ...] = ()
    coverage: CoverageSummary = field(default_factory=CoverageSummary)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    @property
    def has_security_findings(self) -> bool:
        return bool(self.findings)

    @property
    def is_clean(self) -> bool:
        return self.status == ScanStatus.COMPLETE and self.verdict == SafetyVerdict.CLEAN and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "notices": [notice.to_dict() for notice in self.notices],
            "errors": [error.to_dict() for error in self.errors],
            "coverage": self.coverage.to_dict(),
            "metadata": dict(self.metadata),
            "duration_s": self.duration_s,
            "has_security_findings": self.has_security_findings,
            "is_clean": self.is_clean,
        }


def test_scan_options_from_config_parses_string_values() -> None:
    parsed = scan_options_from_config(
        {
            "timeout": "2.5",
            "max_opcodes": "4096",
            "max_nested_pickle_bytes": "2",
            "post_budget_global_scan_limit_bytes": "8192",
        }
    )

    assert parsed.timeout_s == 2.5
    assert parsed.max_opcodes == 4096
    assert parsed.max_nested_pickle_bytes == 2
    assert parsed.post_budget_scan_bytes == 8192


def test_scan_options_from_config_accepts_legacy_expansion_limit_key() -> None:
    parsed = scan_options_from_config({"post_budget_expansion_scan_limit_bytes": "4096"})

    assert parsed.post_budget_scan_bytes == 4096


def test_scan_options_from_config_falls_back_for_bad_values() -> None:
    defaults = ScanOptions()

    fallback = scan_options_from_config(
        {
            "timeout": float("inf"),
            "max_opcodes": 0,
            "max_nested_pickle_bytes": 0,
            "post_budget_global_scan_limit_bytes": -1,
        }
    )

    assert fallback.timeout_s == defaults.timeout_s
    assert fallback.max_opcodes == defaults.max_opcodes
    assert fallback.max_nested_pickle_bytes == defaults.max_nested_pickle_bytes
    assert fallback.post_budget_scan_bytes == defaults.post_budget_scan_bytes

    nan_fallback = scan_options_from_config({"timeout": "nan"})
    assert nan_fallback.timeout_s == defaults.timeout_s

    non_integral_fallback = scan_options_from_config(
        {
            "max_opcodes": 1.9,
            "post_budget_global_scan_limit_bytes": "4.5",
        }
    )
    assert non_integral_fallback.max_opcodes == defaults.max_opcodes
    assert non_integral_fallback.post_budget_scan_bytes == defaults.post_budget_scan_bytes


def test_pickle_report_to_scan_result_maps_clean_report_to_successful_result() -> None:
    report = PickleReport(
        source="safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        coverage=CoverageSummary(bytes_scanned=12, bytes_total=12, opcode_count=3),
        metadata={"protocols": [4], "opcode_count": 3},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.bytes_scanned == 12
    assert result.metadata["pickle_report_status"] == "complete"
    assert result.metadata["pickle_verdict"] == "clean"
    assert result.metadata["pickle_coverage"]["opcode_count"] == 3
    assert result.issues == []
    assert any(check.name == "Standalone Pickle Scan" and check.status.value == "passed" for check in result.checks)


def test_pickle_report_to_scan_result_tolerates_legacy_report_without_private_metadata() -> None:
    report = _LegacyPickleReport(
        source="legacy-safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        coverage=CoverageSummary(bytes_scanned=12, bytes_total=12, opcode_count=3),
        metadata={"protocols": [4], "opcode_count": 3},
    )

    result = pickle_report_to_scan_result(cast(PickleReport, report))

    assert result.success is True
    assert result.bytes_scanned == 12
    assert result.metadata["protocols"] == [4]
    assert result.metadata["pickle_report_status"] == "complete"
    assert result.metadata["pickle_verdict"] == "clean"
    assert result.metadata["pickle_coverage"]["opcode_count"] == 3
    assert result.issues == []
    assert "_private_metadata" not in result.to_dict(include_private_metadata=True)


def test_pickle_report_to_scan_result_preserves_legacy_report_findings_without_private_metadata() -> None:
    report = _LegacyPickleReport(
        source="legacy-malicious.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found REDUCE opcode invoking dangerous global: os.system",
                severity=Severity.CRITICAL,
                location="legacy-malicious.pkl (pos 4)",
                rule_code="DANGEROUS_CALL",
                details={
                    "opcode": "REDUCE",
                    "module": "os",
                    "name": "system",
                    "import_reference": "os.system",
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(cast(PickleReport, report))

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S201"
    assert result.issues[0].details["pickle_rule_code"] == "DANGEROUS_CALL"
    assert "_private_metadata" not in result.to_dict(include_private_metadata=True)


def test_pickle_report_to_scan_result_treats_malformed_private_metadata_as_absent() -> None:
    report = PickleReport(
        source="malformed-private-metadata.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={"opcode_count": 1},
    )
    object.__setattr__(report, "private_metadata", "not-a-mapping")

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.metadata["opcode_count"] == 1
    assert result.issues == []
    assert "_private_metadata" not in result.to_dict(include_private_metadata=True)


def test_pickle_report_to_scan_result_deep_copies_private_metadata_for_cache_serialization() -> None:
    report = PickleReport(
        source="safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={"opcode_count": 3, "protocols": [4]},
        private_metadata={
            "call_graph_source_fingerprints": {
                "reusable": True,
                "search_context": ["/tmp/src"],
                "resolution_context": {
                    "meta_path": ["importlib.PathFinder"],
                    "path_hooks": [],
                    "path_importers": [],
                },
                "module_sources": {"helper": "/tmp/src/helper.py"},
                "loaded_module_sources": {},
                "fingerprints": {"/tmp/src/helper.py": "1111"},
                "read_fingerprints": {
                    "/tmp/src/helper.py": {
                        "read_limit": 1024,
                        "require_complete": True,
                        "fingerprint": "2222",
                    }
                },
            }
        },
    )

    result = pickle_report_to_scan_result(report)
    serialized = result.to_dict(include_private_metadata=True)

    json.dumps(serialized)
    assert serialized["_private_metadata"]["call_graph_source_fingerprints"] == {
        "reusable": True,
        "search_context": ["/tmp/src"],
        "resolution_context": {
            "meta_path": ["importlib.PathFinder"],
            "path_hooks": [],
            "path_importers": [],
        },
        "module_sources": {"helper": "/tmp/src/helper.py"},
        "loaded_module_sources": {},
        "fingerprints": {"/tmp/src/helper.py": "1111"},
        "read_fingerprints": {
            "/tmp/src/helper.py": {
                "read_limit": 1024,
                "require_complete": True,
                "fingerprint": "2222",
            }
        },
    }
    assert result.to_dict()["metadata"]["opcode_count"] == 3
    assert result.to_dict()["metadata"]["protocols"] == [4]
    assert "call_graph_source_fingerprints" not in result.to_dict()["metadata"]

    result.merge(
        pickle_report_to_scan_result(
            PickleReport(
                source="other.pkl",
                status=ScanStatus.COMPLETE,
                verdict=SafetyVerdict.CLEAN,
                private_metadata={
                    "call_graph_source_fingerprints": {
                        "reusable": True,
                        "search_context": ["/tmp/src"],
                        "resolution_context": {
                            "meta_path": ["importlib.PathFinder"],
                            "path_hooks": [],
                            "path_importers": [],
                        },
                        "module_sources": {"other": "/tmp/src/other.py"},
                        "loaded_module_sources": {},
                        "fingerprints": {"/tmp/src/other.py": "2222"},
                    }
                },
            )
        )
    )
    assert result.to_dict(include_private_metadata=True)["_private_metadata"]["call_graph_source_fingerprints"][
        "fingerprints"
    ] == {
        "/tmp/src/helper.py": "1111",
        "/tmp/src/other.py": "2222",
    }


def test_pickle_report_to_scan_result_preserves_security_findings() -> None:
    report = PickleReport(
        source="payload.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found dangerous global reference: posix.system",
                severity=Severity.CRITICAL,
                location="payload.pkl (pos 12)",
                rule_code="DANGEROUS_GLOBAL",
                details={"module": "posix", "name": "system"},
                why="Dangerous globals can execute code.",
            ),
        ),
        coverage=CoverageSummary(bytes_scanned=42, bytes_total=42, opcode_count=9),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].rule_code == "S101"
    assert result.issues[0].details["function"] == "system"
    assert result.issues[0].details["pickle_rule_code"] == "DANGEROUS_GLOBAL"
    assert result.issues[0].details["pickle_source"] == "payload.pkl"


@pytest.mark.parametrize(
    ("case_name", "payload", "expected_pickle_rule", "expected_legacy_rule", "expected_details"),
    [
        ("reduce", b"cos\nsystem\n)R.", "DANGEROUS_CALL", "S201", {"opcode": "REDUCE"}),
        ("constructor", b"\x80\x04cos\nsystem\n)}\x92.", "DANGEROUS_CALL", "S204", {"opcode": "NEWOBJ_EX"}),
        ("extension", b"\x80\x04\x82\x01)R.", "DANGEROUS_CALL", "S201", {"opaque_extension": True}),
        ("unsafe-global", b"cos\nsystem\n.", "DANGEROUS_GLOBAL", "S101", {"function": "system"}),
    ],
)
def test_pickle_report_to_scan_result_preserves_live_malicious_picklescan_controls(
    case_name: str,
    payload: bytes,
    expected_pickle_rule: str,
    expected_legacy_rule: str,
    expected_details: dict[str, object],
) -> None:
    report = scan_bytes(payload, source=f"{case_name}.pkl")

    assert report.status == ScanStatus.COMPLETE
    assert any(finding.rule_code == expected_pickle_rule for finding in report.findings)

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert any(
        issue.rule_code == expected_legacy_rule
        and issue.details.get("pickle_rule_code") == expected_pickle_rule
        and all(issue.details.get(key) == value for key, value in expected_details.items())
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_preserves_legacy_import_rule_for_global_opcode() -> None:
    report = PickleReport(
        source="payload.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found dangerous global reference: posix.system",
                severity=Severity.CRITICAL,
                location="payload.pkl (pos 12)",
                rule_code="DANGEROUS_GLOBAL",
                details={"opcode": "GLOBAL", "module": "posix", "name": "system"},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert {issue.rule_code for issue in result.issues} >= {"S101", "S206"}


def test_pickle_report_to_scan_result_preserves_reduce_associated_global_alias() -> None:
    report = PickleReport(
        source="runpy.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found REDUCE opcode invoking dangerous global: runpy.run_module",
                severity=Severity.CRITICAL,
                location="runpy.pkl (pos 45)",
                rule_code="DANGEROUS_CALL",
                details={
                    "opcode": "REDUCE",
                    "module": "runpy",
                    "name": "run_module",
                    "import_reference": "runpy.run_module",
                    "global_position": 2,
                },
            ),
        ),
        coverage=CoverageSummary(bytes_scanned=48, bytes_total=48, opcode_count=9),
    )

    result = pickle_report_to_scan_result(report)

    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S201"
    assert result.issues[0].details["function"] == "run_module"
    assert result.issues[0].details["associated_global"] == "runpy.run_module"
    assert result.issues[0].details["import_reference"] == "runpy.run_module"


@pytest.mark.parametrize(
    ("name", "expected_primary_rule"),
    [
        ("eval", "S104"),
        ("exec", "S104"),
        ("compile", "S105"),
        ("__import__", "S106"),
    ],
)
def test_pickle_report_to_scan_result_preserves_legacy_builtin_call_rule_alias(
    name: str,
    expected_primary_rule: str,
) -> None:
    report = PickleReport(
        source=f"{name}.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message=f"Found REDUCE opcode invoking dangerous global: builtins.{name}",
                severity=Severity.CRITICAL,
                location="eval.pkl (pos 12)",
                rule_code="DANGEROUS_CALL",
                details={"opcode": "REDUCE", "module": "builtins", "name": name},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert [issue.rule_code for issue in result.issues] == [expected_primary_rule, "S201"]
    assert all(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert all(issue.details["legacy_rule_aliases"] == ["S115"] for issue in result.issues)
    assert result.issues[0].details.get("supporting_rule_code") is None
    assert result.issues[1].details["supporting_rule_code"] is True
    assert result.issues[1].details["primary_rule_code"] == expected_primary_rule


def test_pickle_report_to_scan_result_preserves_warning_dangerous_calls() -> None:
    report = PickleReport(
        source="partial.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Found REDUCE opcode invoking dangerous global: functools.partial",
                severity=Severity.WARNING,
                location="partial.pkl (pos 34)",
                rule_code="DANGEROUS_CALL",
                details={
                    "opcode": "REDUCE",
                    "module": "functools",
                    "name": "partial",
                    "import_reference": "functools.partial",
                    "global_position": 0,
                },
            ),
        ),
        coverage=CoverageSummary(bytes_scanned=37, bytes_total=37, opcode_count=5),
    )

    result = pickle_report_to_scan_result(report)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].rule_code == "S201"
    assert result.issues[0].details["pickle_rule_code"] == "DANGEROUS_CALL"
    assert result.issues[0].details["associated_global"] == "functools.partial"


def test_pickle_report_to_scan_result_derives_legacy_import_explanation() -> None:
    report = PickleReport(
        source="system.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found REDUCE opcode invoking dangerous global: posix.system",
                severity=Severity.CRITICAL,
                location="system.pkl (pos 45)",
                rule_code="DANGEROUS_CALL",
                details={
                    "opcode": "REDUCE",
                    "module": "posix",
                    "name": "system",
                    "import_reference": "posix.system",
                    "global_position": 2,
                },
            ),
        ),
        coverage=CoverageSummary(bytes_scanned=48, bytes_total=48, opcode_count=9),
    )

    result = pickle_report_to_scan_result(report)

    assert len(result.issues) == 1
    assert result.issues[0].why is not None
    assert "system" in result.issues[0].why.lower()


def test_pickle_report_to_scan_result_maps_post_budget_rule_codes_to_legacy_namespace() -> None:
    report = PickleReport(
        source="budget.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Dangerous global-like byte pattern found beyond opcode budget",
                severity=Severity.WARNING,
                location="budget.pkl (pos 128)",
                rule_code="POST_BUDGET_GLOBAL",
                details={"pattern": "posix\nsystem"},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S101"
    assert result.issues[0].details["pickle_rule_code"] == "POST_BUDGET_GLOBAL"


def test_pickle_report_to_scan_result_falls_back_for_unmapped_persistent_id_opcode() -> None:
    report = PickleReport(
        source="persistent-id.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Found custom opcode using a persistent_load callback",
                severity=Severity.WARNING,
                location="persistent-id.pkl (pos 4)",
                rule_code="PERSISTENT_ID",
                details={"opcode": "CUSTOM_PERSISTENT_OPCODE"},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S212"
    assert result.issues[0].details["pickle_rule_code"] == "PERSISTENT_ID"


@pytest.mark.parametrize(
    ("pickle_rule_code", "details", "expected_legacy_rule_code"),
    [
        ("S203", {}, "S203"),
        ("MALFORMED_STACK_GLOBAL", {}, "S205"),
        ("EXTENSION_REF", {"opcode": "EXT1"}, "S211"),
        ("EXTENSION_REF", {}, "S211"),
        ("PERSISTENT_ID", {"opcode": "BINPERSID"}, "S212"),
        ("PERSISTENT_ID", {"opcode": "CUSTOM_PERSISTENT_OPCODE"}, "S212"),
        ("DANGEROUS_CALL", {"opcode": "REDUCE"}, "S201"),
        ("DANGEROUS_CALL", {"opcode": "NEWOBJ_EX"}, "S204"),
        ("DANGEROUS_CALL", {"module": "sys", "name": "exit"}, "S102"),
        ("DANGEROUS_CALL", {"module": "builtins", "name": "exec"}, "S104"),
        ("DANGEROUS_CALL", {"module": "custom", "name": "loader"}, "S201"),
        ("DANGEROUS_GLOBAL", {"opcode": "GLOBAL"}, "S206"),
        ("DANGEROUS_GLOBAL", {"module": "posix", "name": "system"}, "S101"),
        ("DANGEROUS_GLOBAL", {"module": "custom", "name": "loader"}, "S206"),
        ("SUSPICIOUS_STRING", {"pattern": "eval(user_input)"}, "S104"),
        ("SUSPICIOUS_STRING", {"pattern": "os.system(payload)"}, "S101"),
        ("SUSPICIOUS_STRING", {"pattern": "subprocess.Popen(payload)"}, "S103"),
        ("SUSPICIOUS_STRING", {"pattern": "__import__('os')"}, "S106"),
        ("SUSPICIOUS_STRING", {"pattern": "compile(source, path, mode)"}, "S105"),
        ("SUSPICIOUS_STRING", {"pattern": "base64 encoded string literal"}, "S601"),
        ("SUSPICIOUS_STRING", {"pattern": "ordinary string literal"}, None),
        ("POST_BUDGET_GLOBAL", {"pattern": "posix\nsystem"}, "S101"),
        ("POST_BUDGET_GLOBAL", {"pattern": "custom\nloader"}, "S206"),
        ("PICKLE_EXPANSION", {}, "S214"),
        ("UNKNOWN_PICKLE_RULE", {}, "UNKNOWN_PICKLE_RULE"),
    ],
)
def test_pickle_report_to_scan_result_maps_pickle_rule_codes_to_legacy_namespace(
    pickle_rule_code: str,
    details: dict[str, str],
    expected_legacy_rule_code: str | None,
) -> None:
    """Verify standalone pickle findings preserve legacy rule-code mappings."""
    report = PickleReport(
        source="mapped.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Mapped pickle finding",
                severity=Severity.WARNING,
                location="mapped.pkl (pos 1)",
                rule_code=pickle_rule_code,
                details=details,
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == expected_legacy_rule_code
    assert result.issues[0].details["pickle_rule_code"] == pickle_rule_code


def test_pickle_report_to_scan_result_does_not_suppress_newobj_ex_as_reduce() -> None:
    set_config(ModelAuditConfig(suppress={"S201"}))
    report = PickleReport(
        source="newobj-ex.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found NEWOBJ_EX opcode invoking dangerous global: custom.loader",
                severity=Severity.CRITICAL,
                location="newobj-ex.pkl (pos 1)",
                rule_code="DANGEROUS_CALL",
                details={
                    "opcode": "NEWOBJ_EX",
                    "module": "custom",
                    "name": "loader",
                    "import_reference": "custom.loader",
                },
            ),
        ),
        metadata={"opcode_counts": {"NEWOBJ_EX": 1}},
    )

    result = pickle_report_to_scan_result(report)

    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S204"
    assert result.issues[0].details["opcode"] == "NEWOBJ_EX"


def test_pickle_report_to_scan_result_emits_passed_import_checks() -> None:
    report = PickleReport(
        source="safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": [
                {
                    "import_reference": "collections.OrderedDict",
                    "module": "collections",
                    "name": "OrderedDict",
                    "opcode": "GLOBAL",
                    "position": 12,
                    "is_dangerous": False,
                }
            ]
        },
    )

    result = pickle_report_to_scan_result(report)

    import_checks = [check for check in result.checks if check.name == "Standalone Pickle Import"]
    assert len(import_checks) == 1
    assert import_checks[0].status.value == "passed"
    assert import_checks[0].location == "safe.pkl (pos 12)"
    assert import_checks[0].details["function"] == "OrderedDict"
    assert import_checks[0].details["import_reference"] == "collections.OrderedDict"


def test_pickle_report_to_scan_result_suppresses_passed_import_checks_for_references_with_findings() -> None:
    report = PickleReport(
        source="warning.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Found non-allowlisted __main__ global reference: __main__.CustomModel",
                severity=Severity.WARNING,
                location="warning.pkl (pos 7)",
                rule_code="S203",
                details={
                    "opcode": "GLOBAL",
                    "module": "__main__",
                    "name": "CustomModel",
                    "import_reference": "__main__.CustomModel",
                },
            ),
        ),
        metadata={
            "import_references": [
                {
                    "import_reference": "__main__.CustomModel",
                    "module": "__main__",
                    "name": "CustomModel",
                    "opcode": "GLOBAL",
                    "position": 7,
                    "is_dangerous": False,
                }
            ]
        },
    )

    result = pickle_report_to_scan_result(report)

    assert not any(check.name == "Standalone Pickle Import" for check in result.checks)
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S203"


def test_pickle_report_to_scan_result_suppresses_passed_import_checks_for_module_name_findings() -> None:
    report = PickleReport(
        source="danger.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found dangerous global reference: posix.system",
                severity=Severity.CRITICAL,
                location="danger.pkl (pos 3)",
                rule_code="DANGEROUS_GLOBAL",
                details={
                    "module": "posix",
                    "name": "system",
                },
            ),
        ),
        metadata={
            "import_references": [
                {
                    "import_reference": "posix.system",
                    "module": "posix",
                    "name": "system",
                    "opcode": "GLOBAL",
                    "position": 3,
                    "is_dangerous": False,
                }
            ]
        },
    )

    result = pickle_report_to_scan_result(report)

    assert not any(check.name == "Standalone Pickle Import" for check in result.checks)
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S101"


def test_pickle_report_to_scan_result_fails_closed_for_inconclusive_report_without_findings() -> None:
    report = PickleReport(
        source="budget.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Opcode budget reached",
                severity=Severity.INFO,
                location="budget.pkl",
                code="opcode_budget",
                details={"analysis_incomplete": True},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["opcode_budget_exceeded"]
    assert result.metadata["analysis_incomplete"] is True
    assert any(
        check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "opcode_budget"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("report_status", "report_verdict"),
    [
        (ScanStatus.INCONCLUSIVE, SafetyVerdict.UNKNOWN),
        (ScanStatus.COMPLETE, SafetyVerdict.CLEAN),
    ],
    ids=["native-inconclusive", "legacy-complete"],
)
def test_pickle_report_to_scan_result_fails_closed_for_protocol5_buffer_notice(
    report_status: ScanStatus,
    report_verdict: SafetyVerdict,
) -> None:
    report = PickleReport(
        source="buffer.pkl",
        status=report_status,
        verdict=report_verdict,
        notices=(
            Notice(
                message="Encountered 1 protocol 5 buffer opcode(s); external buffer context is opaque",
                severity=Severity.INFO,
                location="buffer.pkl (pos 2)",
                code="buffer_opcode",
                details={
                    "buffer_opcode_count": 1,
                    "next_buffer_count": 1,
                    "readonly_buffer_count": 0,
                    "requires_external_buffer_context": True,
                    "analysis_incomplete": True,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["protocol5_external_buffer_context"]
    assert result.metadata["analysis_incomplete"] is True
    assert any(
        check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "buffer_opcode"
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_pickle_report_to_scan_result_preserves_complete_in_band_readonly_buffer_notice() -> None:
    report = PickleReport(
        source="in-band-readonly-buffer.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        notices=(
            Notice(
                message="Encountered 1 in-band protocol 5 buffer opcode(s)",
                severity=Severity.INFO,
                location="in-band-readonly-buffer.pkl (pos 12)",
                code="buffer_opcode",
                details={
                    "buffer_opcode_count": 1,
                    "next_buffer_count": 0,
                    "readonly_buffer_count": 1,
                    "readonly_buffer_empty_stack_count": 0,
                    "readonly_buffer_invalid_stack_count": 0,
                    "requires_external_buffer_context": False,
                    "analysis_incomplete": False,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    notice_check = next(check for check in result.checks if check.name == "Standalone Pickle Notice")
    assert notice_check.status.value == "passed"


def test_pickle_report_to_scan_result_fails_closed_for_legacy_invalid_readonly_buffer_notice() -> None:
    report = PickleReport(
        source="invalid-readonly-buffer.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        notices=(
            Notice(
                message="Encountered 1 malformed protocol 5 buffer opcode(s); stack context is opaque",
                severity=Severity.INFO,
                location="invalid-readonly-buffer.pkl (pos 3)",
                code="buffer_opcode",
                details={
                    "buffer_opcode_count": 1,
                    "next_buffer_count": 0,
                    "readonly_buffer_count": 1,
                    "readonly_buffer_empty_stack_count": 0,
                    "readonly_buffer_invalid_stack_count": 1,
                    "requires_external_buffer_context": False,
                    "analysis_incomplete": True,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["protocol5_external_buffer_context"]
    assert result.metadata["analysis_incomplete"] is True


def test_pickle_report_to_scan_result_fails_closed_for_legacy_missing_invalid_readonly_counter() -> None:
    report = PickleReport(
        source="legacy-invalid-readonly-buffer.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        notices=(
            Notice(
                message="Encountered 1 protocol 5 readonly buffer opcode(s)",
                severity=Severity.INFO,
                location="legacy-invalid-readonly-buffer.pkl (pos 3)",
                code="buffer_opcode",
                details={
                    "buffer_opcode_count": 1,
                    "next_buffer_count": 0,
                    "readonly_buffer_count": 1,
                    "readonly_buffer_empty_stack_count": 0,
                    "requires_external_buffer_context": False,
                    "analysis_incomplete": False,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["protocol5_external_buffer_context"]
    assert result.metadata["analysis_incomplete"] is True


def test_pickle_report_to_scan_result_fails_closed_for_truncated_literal_scan_notice() -> None:
    report = PickleReport(
        source="large-string.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="String literal scan truncated at configured limit",
                severity=Severity.INFO,
                location="large-string.pkl (pos 16)",
                code="literal_scan_truncated",
                details={"analysis_incomplete": True},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["literal_scan_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    notice_check = next(
        check
        for check in result.checks
        if check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "literal_scan_truncated"
    )
    assert notice_check.message == "String literal scan truncated at configured limit"


def test_pickle_report_to_scan_result_fails_closed_for_truncated_import_references() -> None:
    report = PickleReport(
        source="import-reference-cap.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Import reference metadata exceeded the scanner reporting limit",
                severity=Severity.INFO,
                location="import-reference-cap.pkl",
                code="import_references_truncated",
                details={"analysis_incomplete": True, "max_import_references": 10_000},
            ),
        ),
        metadata={"analysis_incomplete": True, "import_references_truncated": True},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["import_references_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    assert should_cache_scan_result(result.to_dict()) is False
    notice_check = next(
        check
        for check in result.checks
        if check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "import_references_truncated"
    )
    assert notice_check.message == "Import reference metadata exceeded the scanner reporting limit"


def test_pickle_report_to_scan_result_fails_closed_for_legacy_complete_truncated_import_references() -> None:
    report = PickleReport(
        source="legacy-import-reference-cap.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        notices=(
            Notice(
                message="Import reference metadata exceeded the scanner reporting limit",
                severity=Severity.INFO,
                location="legacy-import-reference-cap.pkl",
                code="import_references_truncated",
                details={"analysis_incomplete": True, "max_import_references": 10_000},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["import_references_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    assert should_cache_scan_result(result.to_dict()) is False


def test_pickle_report_to_scan_result_keeps_legacy_truncated_findings_successful() -> None:
    report = PickleReport(
        source="legacy-import-reference-cap-finding.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Dangerous global reference found: posix.system",
                severity=Severity.WARNING,
                location="legacy-import-reference-cap-finding.pkl (pos 0)",
                rule_code="DANGEROUS_GLOBAL",
                details={"module": "posix", "name": "system"},
            ),
        ),
        notices=(
            Notice(
                message="Import reference metadata exceeded the scanner reporting limit",
                severity=Severity.INFO,
                location="legacy-import-reference-cap-finding.pkl",
                code="import_references_truncated",
                details={"analysis_incomplete": True, "max_import_references": 10_000},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["import_references_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    assert should_cache_scan_result(result.to_dict()) is False
    assert any(issue.rule_code == "S101" for issue in result.issues)


def test_pickle_report_to_scan_result_keeps_operational_errors_unsuccessful_with_truncation_notice() -> None:
    report = PickleReport(
        source="short-read-import-reference-cap.pkl",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Dangerous global reference found: posix.system",
                severity=Severity.WARNING,
                location="short-read-import-reference-cap.pkl (pos 0)",
                rule_code="DANGEROUS_GLOBAL",
                details={"module": "posix", "name": "system"},
            ),
        ),
        notices=(
            Notice(
                message="Import reference metadata exceeded the scanner reporting limit",
                severity=Severity.INFO,
                location="short-read-import-reference-cap.pkl",
                code="import_references_truncated",
                details={"analysis_incomplete": True, "max_import_references": 10_000},
            ),
        ),
        errors=(
            ScanError(
                message="Could not read remainder of pickle stream",
                category="short_read",
                location="short-read-import-reference-cap.pkl",
                exception_type="OSError",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["import_references_truncated", "short_read"]
    assert result.metadata["analysis_incomplete"] is True
    assert should_cache_scan_result(result.to_dict()) is False
    assert any(issue.rule_code == "S101" for issue in result.issues)


def test_pickle_report_to_scan_result_fails_closed_for_legacy_complete_truncated_callable_invocations() -> None:
    report = PickleReport(
        source="legacy-callable-invocation-cap.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        notices=(
            Notice(
                message="Callable invocation metadata exceeded the scanner reporting limit",
                severity=Severity.INFO,
                location="legacy-callable-invocation-cap.pkl",
                code="callable_invocations_truncated",
                details={"analysis_incomplete": True, "max_callable_invocations": 10_000},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["callable_invocations_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    assert should_cache_scan_result(result.to_dict()) is False


def test_pickle_report_to_scan_result_fails_closed_for_encoded_nested_truncation_notice() -> None:
    report = PickleReport(
        source="oversized-encoded.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Encoded pickle payload exceeds deep-scan byte limit",
                severity=Severity.CRITICAL,
                location="oversized-encoded.pkl (pos 16)",
                rule_code="S601",
                details={"analysis_incomplete": True},
            ),
        ),
        notices=(
            Notice(
                message="Encoded pickle payload exceeds configured deep-scan byte limit",
                severity=Severity.INFO,
                location="oversized-encoded.pkl (pos 16)",
                code="encoded_nested_payload_truncated",
                details={"analysis_incomplete": True},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["encoded_nested_payload_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    notice_check = next(
        check
        for check in result.checks
        if check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "encoded_nested_payload_truncated"
    )
    assert notice_check.message == "Encoded pickle payload exceeds configured deep-scan byte limit"


def test_pickle_report_to_scan_result_preserves_critical_s601_for_encoded_nested_payload_missing_encoding() -> None:
    report = PickleReport(
        source="encoded.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Encoded pickle payload detected in string literal",
                severity=Severity.CRITICAL,
                location="encoded.pkl (pos 16)",
                rule_code="S601",
                details={},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].rule_code == "S601"


def test_pickle_report_to_scan_result_preserves_nested_payload_finding_severity() -> None:
    report = PickleReport(
        source="nested-benign.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Nested pickle payload detected",
                severity=Severity.CRITICAL,
                location="nested-benign.pkl (pos 16)",
                rule_code="S213",
                details={"encoding": "raw", "nested_has_execution_opcode": False},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].rule_code == "S213"
    assert result.issues[0].details["pickle_rule_code"] == "S213"


def test_pickle_report_to_scan_result_fails_closed_for_raw_nested_truncation_notice() -> None:
    report = PickleReport(
        source="oversized-raw.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Nested pickle payload exceeds deep-scan byte limit",
                severity=Severity.CRITICAL,
                location="oversized-raw.pkl (pos 16)",
                rule_code="S213",
                details={"analysis_incomplete": True},
            ),
        ),
        notices=(
            Notice(
                message="Nested pickle payload exceeds configured deep-scan byte limit",
                severity=Severity.INFO,
                location="oversized-raw.pkl (pos 16)",
                code="nested_payload_truncated",
                details={"analysis_incomplete": True},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["nested_payload_truncated"]
    assert result.metadata["analysis_incomplete"] is True
    notice_check = next(
        check
        for check in result.checks
        if check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "nested_payload_truncated"
    )
    assert notice_check.message == "Nested pickle payload exceeds configured deep-scan byte limit"


def test_pickle_report_to_scan_result_fails_closed_for_nested_probe_limit_notice() -> None:
    report = PickleReport(
        source="probe-limit.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Nested pickle probe candidate limit exceeded",
                severity=Severity.CRITICAL,
                location="probe-limit.pkl (pos 16)",
                rule_code="S213",
                details={"analysis_incomplete": True, "max_nested_payload_probes": 64},
            ),
        ),
        notices=(
            Notice(
                message="Nested pickle probe candidate limit exceeded",
                severity=Severity.INFO,
                location="probe-limit.pkl (pos 16)",
                code="nested_probe_limit",
                details={"analysis_incomplete": True, "max_nested_payload_probes": 64},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["nested_probe_limit"]
    assert result.metadata["analysis_incomplete"] is True
    finding_issue = next(
        issue
        for issue in result.issues
        if issue.message == "Nested pickle probe candidate limit exceeded" and issue.rule_code == "S213"
    )
    assert finding_issue.severity == IssueSeverity.CRITICAL
    assert finding_issue.details["analysis_incomplete"] is True
    notice_check = next(
        check
        for check in result.checks
        if check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "nested_probe_limit"
    )
    assert notice_check.message == "Nested pickle probe candidate limit exceeded"


def test_pickle_report_to_scan_result_fails_closed_for_nested_incomplete_notice() -> None:
    report = PickleReport(
        source="nested-incomplete.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Nested pickle analysis did not complete",
                severity=Severity.INFO,
                location="nested-incomplete.pkl (nested raw pickle at pos 16)",
                code="nested_pickle_incomplete",
                details={"analysis_incomplete": True},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["nested_pickle_incomplete"]
    assert result.metadata["analysis_incomplete"] is True
    notice_check = next(
        check
        for check in result.checks
        if check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "nested_pickle_incomplete"
    )
    assert notice_check.message == "Nested pickle analysis did not complete"


def test_pickle_report_to_scan_result_keeps_parse_incomplete_notices_inconclusive() -> None:
    report = PickleReport(
        source="truncated.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="truncated.pkl (pos 4)",
                code="parse_incomplete",
                details={
                    "exception": "pickle exhausted before seeing STOP",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["pickle_analysis_incomplete"]
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity == IssueSeverity.WARNING
    assert parse_issue.rule_code == "S901"
    assert parse_issue.location == "truncated.pkl (pos 4)"
    assert parse_issue.details["category"] == "parse_error"
    assert parse_issue.details["parse_error"] == "pickle exhausted before seeing STOP"
    assert parse_issue.details["failure_reason"] == "unknown_opcode_or_format_error"
    assert parse_issue.details["analysis_incomplete"] is True


def test_pickle_report_to_scan_result_keeps_truncated_bin_parse_failure_inconclusive() -> None:
    report = PickleReport(
        source="truncated.bin",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: EOFError",
                severity=Severity.INFO,
                location="truncated.bin (pos 57)",
                code="parse_incomplete",
                details={
                    "exception": "pickle exhausted before seeing STOP",
                    "exception_type": "EOFError",
                    "analysis_incomplete": True,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity == IssueSeverity.WARNING
    assert parse_issue.rule_code == "S901"
    assert parse_issue.location == "truncated.bin (pos 57)"
    assert parse_issue.details["category"] == "parse_error"
    assert parse_issue.details["parse_error"] == "pickle exhausted before seeing STOP"
    assert parse_issue.details["failure_reason"] == "unknown_opcode_or_format_error"
    assert parse_issue.details["analysis_incomplete"] is True


def test_pickle_report_to_scan_result_keeps_trusted_bin_padding_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="weights.bin",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="weights.bin (pos 57)",
                code="parse_incomplete",
                details={
                    "exception": "at position 4096, opcode b'\\x00' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 56, "import_references": _benign_tail_import_references()},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_unicode_decode_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="benign-tail.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: UnicodeDecodeError",
                severity=Severity.INFO,
                location="benign-tail.pkl (pos 21)",
                code="parse_incomplete",
                details={
                    "exception": "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
                    "exception_type": "UnicodeDecodeError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 20, "import_references": _benign_tail_import_references()},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: UnicodeDecodeError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_zero_padding_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="padding.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="padding.pkl (pos 20)",
                code="parse_incomplete",
                details={
                    "exception": "at position 4096, opcode b'\\x00' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 19, "import_references": _benign_tail_import_references()},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("source", "exception_type", "exception_message"),
    [
        ("dangerous-unicode-tail.pkl", "UnicodeDecodeError", "'utf-8' codec can't decode byte 0xff in position 0"),
        ("dangerous-padding-tail.pkl", "ValueError", "at position 4096, opcode b'\\x00' unknown"),
    ],
)
def test_pickle_report_to_scan_result_requires_no_dangerous_imports_for_tail_suppression(
    source: str,
    exception_type: str,
    exception_message: str,
) -> None:
    report = PickleReport(
        source=source,
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message=f"Pickle parsing stopped before the stream was fully consumed: {exception_type}",
                severity=Severity.INFO,
                location=f"{source} (pos 20)",
                code="parse_incomplete",
                details={
                    "exception": exception_message,
                    "exception_type": exception_type,
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={
            "first_pickle_end_pos": 19,
            "import_references": [
                {
                    "import_reference": "posix.system",
                    "module": "posix",
                    "name": "system",
                    "opcode": "GLOBAL",
                    "position": 3,
                    "is_dangerous": True,
                },
            ],
        },
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert "trusted_incomplete_tail" not in result.metadata
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity == IssueSeverity.WARNING
    assert parse_issue.rule_code == "S901"
    assert parse_issue.details["analysis_incomplete"] is True


@pytest.mark.parametrize(
    ("source", "exception_type", "exception_message"),
    [
        ("empty-evidence-unicode-tail.pkl", "UnicodeDecodeError", "'utf-8' codec can't decode byte 0xff in position 0"),
        ("empty-evidence-padding-tail.pkl", "ValueError", "at position 4096, opcode b'\\x00' unknown"),
    ],
)
def test_pickle_report_to_scan_result_requires_import_metadata_for_tail_suppression(
    source: str,
    exception_type: str,
    exception_message: str,
) -> None:
    report = PickleReport(
        source=source,
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message=f"Pickle parsing stopped before the stream was fully consumed: {exception_type}",
                severity=Severity.INFO,
                location=f"{source} (pos 20)",
                code="parse_incomplete",
                details={
                    "exception": exception_message,
                    "exception_type": exception_type,
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 19},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert "trusted_incomplete_tail" not in result.metadata
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity == IssueSeverity.WARNING
    assert parse_issue.rule_code == "S901"
    assert parse_issue.details["analysis_incomplete"] is True


@pytest.mark.parametrize(
    ("source", "exception_type", "exception_message"),
    [
        ("empty-imports-unicode-tail.pkl", "UnicodeDecodeError", "'utf-8' codec can't decode byte 0xff in position 0"),
        ("empty-imports-padding-tail.pkl", "ValueError", "at position 4096, opcode b'\\x00' unknown"),
    ],
)
def test_pickle_report_to_scan_result_suppresses_trusted_tails_with_empty_imports(
    source: str,
    exception_type: str,
    exception_message: str,
) -> None:
    report = PickleReport(
        source=source,
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message=f"Pickle parsing stopped before the stream was fully consumed: {exception_type}",
                severity=Severity.INFO,
                location=f"{source} (pos 20)",
                code="parse_incomplete",
                details={
                    "exception": exception_message,
                    "exception_type": exception_type,
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 19, "import_references": []},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["trusted_incomplete_tail"] is True
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == f"Pickle parsing stopped before the stream was fully consumed: {exception_type}"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_fails_closed_for_raw_pickle_unknown_opcode_tail() -> None:
    report = PickleReport(
        source="unknown-tail.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="unknown-tail.pkl (pos 20)",
                code="parse_incomplete",
                details={
                    "exception": "at position 20, opcode b'A' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 19},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert "trusted_incomplete_tail" not in result.metadata
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity == IssueSeverity.WARNING
    assert parse_issue.rule_code == "S901"
    assert parse_issue.details["category"] == "parse_error"
    assert parse_issue.details["failure_reason"] == "unknown_opcode_or_format_error"
    assert parse_issue.details["analysis_incomplete"] is True


def test_pickle_report_to_scan_result_keeps_joblib_unknown_opcode_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="numpy_arrays.joblib",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="numpy_arrays.joblib (pos 231)",
                code="parse_incomplete",
                details={
                    "exception": "at position 230, opcode b'\\t' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={
            "first_pickle_end_pos": 230,
            "import_references": [
                {
                    "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
                    "module": "joblib.numpy_pickle",
                    "name": "NumpyArrayWrapper",
                    "opcode": "STACK_GLOBAL",
                    "position": 66,
                    "is_dangerous": False,
                },
                {
                    "import_reference": "numpy.ndarray",
                    "module": "numpy",
                    "name": "ndarray",
                    "opcode": "STACK_GLOBAL",
                    "position": 103,
                    "is_dangerous": False,
                },
            ],
        },
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_ignores_decompressed_wrapper_suffix_for_joblib_tail_suppression() -> None:
    report = PickleReport(
        source="numpy_arrays.joblib (decompressed)",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="numpy_arrays.joblib (decompressed) (pos 231)",
                code="parse_incomplete",
                details={
                    "exception": "at position 230, opcode b'\\t' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={
            "first_pickle_end_pos": 230,
            "import_references": [
                {
                    "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
                    "module": "joblib.numpy_pickle",
                    "name": "NumpyArrayWrapper",
                    "opcode": "STACK_GLOBAL",
                    "position": 66,
                    "is_dangerous": False,
                },
                {
                    "import_reference": "numpy.ndarray",
                    "module": "numpy",
                    "name": "ndarray",
                    "opcode": "STACK_GLOBAL",
                    "position": 103,
                    "is_dangerous": False,
                },
            ],
        },
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["trusted_incomplete_tail"] is True
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_requires_boundary_for_joblib_serialization_tail() -> None:
    report = PickleReport(
        source="numpy_arrays.joblib",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="numpy_arrays.joblib (pos 231)",
                code="parse_incomplete",
                details={
                    "exception": "at position 230, opcode b'\\t' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={
            "import_references": [
                {
                    "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
                    "module": "joblib.numpy_pickle",
                    "name": "NumpyArrayWrapper",
                    "opcode": "STACK_GLOBAL",
                    "position": 66,
                    "is_dangerous": False,
                },
            ],
        },
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert "trusted_incomplete_tail" not in result.metadata
    assert any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)


def test_pickle_report_to_scan_result_requires_boundary_for_non_joblib_tail_suppression() -> None:
    report = PickleReport(
        source="numpy_arrays.dill",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="numpy_arrays.dill (pos 231)",
                code="parse_incomplete",
                details={
                    "exception": "at position 230, opcode b'\\t' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={
            "import_references": [
                {
                    "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
                    "module": "joblib.numpy_pickle",
                    "name": "NumpyArrayWrapper",
                    "opcode": "STACK_GLOBAL",
                    "position": 66,
                    "is_dangerous": False,
                },
            ],
        },
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert "trusted_incomplete_tail" not in result.metadata
    parse_issue = next(
        issue for issue in result.issues if issue.message == "Pickle parsing failed before full scan completion"
    )
    assert parse_issue.severity == IssueSeverity.WARNING
    assert parse_issue.rule_code == "S901"
    assert parse_issue.details["category"] == "parse_error"
    assert parse_issue.details["analysis_incomplete"] is True


def test_pickle_report_to_scan_result_maps_empty_input_to_info_issue() -> None:
    report = PickleReport(
        source="empty.pkl",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message="Input is empty and does not contain a pickle stream",
                category="empty_input",
                location="empty.pkl",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "empty_input"
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["empty_input"]
    assert result.has_errors is False
    issue = next(issue for issue in result.issues if issue.details.get("category") == "empty_input")
    assert issue.severity == IssueSeverity.INFO


def test_pickle_report_to_scan_result_keeps_parse_errors_inconclusive() -> None:
    report = PickleReport(
        source="bad.bin",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message="Could not parse pickle stream",
                category="parse_error",
                location="bad.bin (pos 0)",
                exception_type="ValueError",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["pickle_analysis_incomplete"]
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["parsing_failed"] is True
    assert result.metadata["failure_reason"] == "unknown_opcode_or_format_error"
    assert "operational_error" not in result.metadata
    assert "operational_error_reason" not in result.metadata
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].rule_code == "S901"
    assert result.issues[0].details["category"] == "parse_error"
    assert result.issues[0].details["analysis_incomplete"] is True
    assert result.issues[0].details["parsing_failed"] is True


def test_pickle_report_to_scan_result_maps_non_parse_errors_to_inconclusive_info_issues() -> None:
    report = PickleReport(
        source="broken.pkl",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message="Could not read pickle stream",
                category="io_error",
                location="broken.pkl",
                exception_type="OSError",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "io_error"
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["io_error"]
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].rule_code == "S902"


def test_pickle_report_to_scan_result_preserves_security_finding_with_operational_error() -> None:
    report = PickleReport(
        source="partially-read.pkl",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found dangerous global reference: posix.system",
                severity=Severity.CRITICAL,
                location="partially-read.pkl (pos 12)",
                rule_code="DANGEROUS_GLOBAL",
                details={"module": "posix", "name": "system"},
                why="Dangerous globals can execute code.",
            ),
        ),
        errors=(
            ScanError(
                message="Could not read remainder of pickle stream",
                category="io_error",
                location="partially-read.pkl",
                exception_type="OSError",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "io_error"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.details.get("category") == "io_error" and issue.severity == IssueSeverity.INFO for issue in result.issues
    )


def test_pytorch_zip_scanner_does_not_duplicate_member_path_in_pickle_locations(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    result = PyTorchZipScanner().scan(str(model_path))

    duplicated_location = f"{model_path}:data.pkl {model_path}:data.pkl"
    assert result.issues
    assert all(duplicated_location not in (issue.location or "") for issue in result.issues)
    assert all(duplicated_location not in (check.location or "") for check in result.checks)
    assert all(
        issue.details.get("pickle_filename") == "data.pkl"
        for issue in result.issues
        if issue.details.get("pickle_source") == f"{model_path}:data.pkl"
    )


def test_executorch_scanner_does_not_duplicate_member_path_in_pickle_locations(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pte", malicious=True)

    result = ExecuTorchScanner().scan(str(model_path))

    duplicated_location = f"{model_path}:data.pkl {model_path}:data.pkl"
    assert result.issues
    assert all(duplicated_location not in (issue.location or "") for issue in result.issues)
    assert all(duplicated_location not in (check.location or "") for check in result.checks)
    assert all(
        issue.details.get("pickle_filename") == "data.pkl"
        for issue in result.issues
        if issue.details.get("pickle_source") == f"{model_path}:data.pkl"
    )


def test_apply_pickle_member_context_prepends_member_location_without_position_markers() -> None:
    report = PickleReport(
        source="data.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Found non-allowlisted __main__ global reference: __main__.CustomType",
                severity=Severity.WARNING,
                location="custom-location",
                rule_code="S203",
            ),
        ),
    )
    result = pickle_report_to_scan_result(report)

    apply_pickle_member_context(result, archive_path="archive.pt", member_name="data.pkl")

    assert result.issues[0].location == "archive.pt:data.pkl custom-location"
    assert result.issues[0].details["pickle_filename"] == "data.pkl"


@pytest.mark.integration
@pytest.mark.slow
def test_pinned_distilbert_hf_scan_completes_without_private_metadata_error(tmp_path: Path) -> None:
    if os.environ.get("MODELAUDIT_RUN_HF_INTEGRATION") != "1":
        pytest.skip("set MODELAUDIT_RUN_HF_INTEGRATION=1 to run the pinned Hugging Face scan")

    from click.testing import CliRunner

    from modelaudit.cli import cli

    output_path = tmp_path / "distilbert-report.json"
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--no-cache",
            "--cache-dir",
            str(tmp_path / "modelaudit-cache"),
            "--max-size",
            "2GB",
            "--timeout",
            "3600",
            "--format",
            "json",
            "--output",
            str(output_path),
            _PINNED_DISTILBERT_URL,
        ],
        env={
            "PROMPTFOO_DISABLE_TELEMETRY": "1",
            "HF_HOME": str(tmp_path / "hf-home"),
            "HF_HUB_CACHE": str(tmp_path / "hf-cache"),
        },
    )

    assert result.exit_code in {0, 1}, result.output[-2000:]
    assert "AttributeError" not in result.output
    assert "private_metadata" not in result.output

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["success"] is True
    assert report["has_errors"] is False
    assert report["files_scanned"] == 1
    assert "12040accade4e8a0f71eabdb258fecc2e7e948be" in json.dumps(report)
