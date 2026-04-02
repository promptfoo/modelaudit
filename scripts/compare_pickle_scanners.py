"""Differential harness for legacy PickleScanner vs modelaudit_picklescan.

This script compares the in-repo legacy pickle scanner against the standalone
package on committed pickle fixtures and reports potential false-positive,
false-negative, and status/verdict drift.

Usage:
    PYTHONPATH=packages/modelaudit-picklescan/src uv run python scripts/compare_pickle_scanners.py
    PYTHONPATH=packages/modelaudit-picklescan/src uv run python scripts/compare_pickle_scanners.py --json
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from modelaudit_picklescan import PickleReport, ScanStatus
from modelaudit_picklescan import scan_file as package_scan_file

from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.scanners.picklescan_adapter import pickle_report_to_scan_result

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS_DIR = REPO_ROOT / "tests" / "assets"

SAFE_FIXTURE_NAMES = {
    "safe_data.pkl",
    "safe_large_model.pkl",
    "safe_model_with_binary.pkl",
    "safe_model_with_encoding.pkl",
    "safe_model_with_tokens.pkl",
    "safe_nested_structure.pkl",
}

MALICIOUS_FIXTURE_NAMES = {
    "dill_func.pkl",
    "decode_exec_chain.pkl",
    "evil.pickle",
    "exploit1_basic_torch_bypass.pkl",
    "exploit2_advanced_torch_bypass.pkl",
    "exploit3_sophisticated_hybrid.pkl",
    "exploit4_supply_chain_attack.pkl",
    "exploit5_ultra_high_confidence.pkl",
    "exploit6_ordereddict_bypass.pkl",
    "exploit7_nested_collections.pkl",
    "exploit9_manual_construction.pkl",
    "exploit_ultimate_50pct.pkl",
    "malicious_model_realistic.pkl",
    "malicious_system_call.pkl",
    "memo_attack.pkl",
    "multiple_stream_attack.pkl",
    "nested_pickle_base64.pkl",
    "nested_pickle_hex.pkl",
    "nested_pickle_multistage.pkl",
    "nested_pickle_raw.pkl",
    "nt_alias_attack.pkl",
    "posix_alias_attack.pkl",
    "stack_global_attack.pkl",
}

VERDICT_RANK = {
    "clean": 0,
    "suspicious": 1,
    "malicious": 2,
    "unknown": -1,
}
FIXTURE_LABELS = ("safe", "malicious", "unknown")
EXIT_FAILURE_DELTAS = frozenset({"potential_fp", "potential_fn", "verdict_drift"})


@dataclass(frozen=True)
class NormalizedResult:
    engine: str
    status: str
    verdict: str
    success: bool
    warning_count: int
    critical_count: int
    info_count: int
    rule_codes: tuple[str, ...]
    messages: tuple[str, ...]
    metadata: dict[str, Any]


class LegacyBaselinePickleScanner(PickleScanner):
    """PickleScanner baseline that bypasses package-result merging."""

    def _scan_pickle_stream_with_package_engine(
        self,
        file_obj: BinaryIO,
        file_size: int,
        *,
        source: str,
    ) -> ScanResult:
        self.current_file_path = source
        return self._scan_pickle_bytes(file_obj, file_size)


def _discover_pickle_fixtures() -> list[Path]:
    return sorted(
        path for path in ASSETS_DIR.rglob("*") if path.is_file() and path.suffix.lower() in {".pkl", ".pickle", ".dill"}
    )


def _fixture_label(path: Path) -> str:
    if path.name in SAFE_FIXTURE_NAMES or path.name.startswith("safe_"):
        return "safe"

    path_text = path.as_posix().lower()
    if (
        path.name in MALICIOUS_FIXTURE_NAMES
        or "exploit" in path_text
        or "malicious" in path_text
        or "evil" in path.name.lower()
        or "security_scenarios" in path_text
    ):
        return "malicious"
    return "unknown"


def _legacy_status(result: ScanResult) -> str:
    if result.metadata.get("operational_error"):
        return "error"
    if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
        return "inconclusive"
    return "complete"


def _legacy_verdict(result: ScanResult) -> str:
    severities = [issue.severity for issue in result.issues]
    if IssueSeverity.CRITICAL in severities:
        return "malicious"
    if IssueSeverity.WARNING in severities:
        return "suspicious"
    if _legacy_status(result) == "complete":
        return "clean"
    return "unknown"


def _normalize_scan_result(result: ScanResult, *, engine: str) -> NormalizedResult:
    return NormalizedResult(
        engine=engine,
        status=_legacy_status(result),
        verdict=_legacy_verdict(result),
        success=bool(result.success),
        warning_count=sum(1 for issue in result.issues if issue.severity == IssueSeverity.WARNING),
        critical_count=sum(1 for issue in result.issues if issue.severity == IssueSeverity.CRITICAL),
        info_count=sum(1 for issue in result.issues if issue.severity == IssueSeverity.INFO),
        rule_codes=tuple(sorted(issue.rule_code for issue in result.issues if issue.rule_code)),
        messages=tuple(sorted(issue.message for issue in result.issues)),
        metadata=dict(result.metadata),
    )


def _normalize_package_report(report: PickleReport) -> NormalizedResult:
    return NormalizedResult(
        engine="package",
        status=report.status.value,
        verdict=report.verdict.value,
        success=report.status == ScanStatus.COMPLETE
        or (report.status == ScanStatus.INCONCLUSIVE and report.has_security_findings),
        warning_count=sum(1 for finding in report.findings if finding.severity.value == "warning"),
        critical_count=sum(1 for finding in report.findings if finding.severity.value == "critical"),
        info_count=len(report.notices),
        rule_codes=tuple(sorted(finding.rule_code for finding in report.findings if finding.rule_code)),
        messages=tuple(sorted(finding.message for finding in report.findings)),
        metadata=dict(report.metadata),
    )


def _scan_fixture(
    path: Path,
    legacy_scanner: LegacyBaselinePickleScanner,
) -> tuple[NormalizedResult, NormalizedResult, NormalizedResult]:
    legacy_result = _normalize_scan_result(legacy_scanner.scan(str(path)), engine="legacy")
    package_report = package_scan_file(path)
    package_result = _normalize_package_report(package_report)
    adapter_result = _normalize_scan_result(
        pickle_report_to_scan_result(package_report, scanner_name="pickle"),
        engine="adapter",
    )
    return legacy_result, package_result, adapter_result


def _classify_delta(label: str, legacy: NormalizedResult, package: NormalizedResult) -> str:
    legacy_rank = VERDICT_RANK[legacy.verdict]
    package_rank = VERDICT_RANK[package.verdict]

    if label == "safe" and package_rank > legacy_rank:
        return "potential_fp"
    if label == "malicious" and package_rank < legacy_rank:
        return "potential_fn"
    if legacy.verdict != package.verdict:
        return "verdict_drift"
    if legacy.status != package.status:
        return "status_drift"
    if legacy.rule_codes != package.rule_codes:
        return "rule_drift"
    return "match"


def _build_report() -> dict[str, Any]:
    fixtures: list[Path] = []
    comparisons: list[dict[str, Any]] = []
    previous_logging_disable_level = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        fixtures = _discover_pickle_fixtures()
        legacy_scanner = LegacyBaselinePickleScanner()

        for path in fixtures:
            label = _fixture_label(path)
            legacy_result, package_result, adapter_result = _scan_fixture(path, legacy_scanner)
            package_delta = _classify_delta(label, legacy_result, package_result)
            adapter_delta = _classify_delta(label, legacy_result, adapter_result)
            comparisons.append(
                {
                    "path": path.relative_to(REPO_ROOT).as_posix(),
                    "label": label,
                    "package_delta": package_delta,
                    "adapter_delta": adapter_delta,
                    "legacy": legacy_result.__dict__,
                    "package": package_result.__dict__,
                    "adapter": adapter_result.__dict__,
                }
            )
    finally:
        logging.disable(previous_logging_disable_level)

    summary: dict[str, dict[str, int]] = {
        "package": {},
        "adapter": {},
    }
    by_label: dict[str, dict[str, dict[str, int]]] = {
        "package": {label: {} for label in FIXTURE_LABELS},
        "adapter": {label: {} for label in FIXTURE_LABELS},
    }
    for comparison in comparisons:
        package_summary = summary["package"]
        adapter_summary = summary["adapter"]
        package_delta = comparison["package_delta"]
        adapter_delta = comparison["adapter_delta"]
        package_summary[package_delta] = package_summary.get(package_delta, 0) + 1
        adapter_summary[adapter_delta] = adapter_summary.get(adapter_delta, 0) + 1

        label = comparison["label"]
        package_label_summary = by_label["package"][label]
        adapter_label_summary = by_label["adapter"][label]
        package_label_summary[package_delta] = package_label_summary.get(package_delta, 0) + 1
        adapter_label_summary[adapter_delta] = adapter_label_summary.get(adapter_delta, 0) + 1

    return {
        "fixture_count": len(fixtures),
        "summary": {
            "package": dict(sorted(summary["package"].items())),
            "adapter": dict(sorted(summary["adapter"].items())),
        },
        "summary_by_label": {
            engine_name: {label: dict(sorted(label_summary.items())) for label, label_summary in engine_summary.items()}
            for engine_name, engine_summary in by_label.items()
        },
        "comparisons": comparisons,
    }


def _print_text_report(report: dict[str, Any]) -> None:
    print(f"Compared {report['fixture_count']} pickle fixtures")
    print("Summary:")
    for engine_name, engine_summary in report["summary"].items():
        print(f"  {engine_name}:")
        for delta, count in engine_summary.items():
            print(f"    {delta}: {count}")

    print("Summary by fixture label:")
    for engine_name, engine_summary in report["summary_by_label"].items():
        print(f"  {engine_name}:")
        for label in FIXTURE_LABELS:
            label_summary = engine_summary.get(label, {})
            if label_summary:
                deltas = ", ".join(f"{delta}={count}" for delta, count in label_summary.items())
            else:
                deltas = "none"
            print(f"    {label}: {deltas}")

    interesting = [
        item for item in report["comparisons"] if item["package_delta"] != "match" or item["adapter_delta"] != "match"
    ]
    if not interesting:
        print("\nNo verdict/status/rule drift found.")
        return

    print("\nDeltas:")
    for item in interesting:
        print(f"\n[package={item['package_delta']} adapter={item['adapter_delta']}] {item['path']} ({item['label']})")
        legacy = item["legacy"]
        package = item["package"]
        adapter = item["adapter"]
        print(
            "  legacy : "
            f"status={legacy['status']} verdict={legacy['verdict']} "
            f"warnings={legacy['warning_count']} criticals={legacy['critical_count']} "
            f"success={legacy['success']}"
        )
        print(
            "  package: "
            f"status={package['status']} verdict={package['verdict']} "
            f"warnings={package['warning_count']} criticals={package['critical_count']} "
            f"success={package['success']}"
        )
        print(
            "  adapter: "
            f"status={adapter['status']} verdict={adapter['verdict']} "
            f"warnings={adapter['warning_count']} criticals={adapter['critical_count']} "
            f"success={adapter['success']}"
        )
        legacy_rules = Counter(legacy["rule_codes"])
        package_rules = Counter(package["rule_codes"])
        adapter_rules = Counter(adapter["rule_codes"])
        print(f"  legacy-only rules : {sorted((legacy_rules - package_rules).elements())}")
        print(f"  package-only rules: {sorted((package_rules - legacy_rules).elements())}")
        print(f"  adapter-only rules: {sorted((adapter_rules - legacy_rules).elements())}")
        for message in package["messages"][:5]:
            print(f"  package finding: {message}")
        for message in adapter["messages"][:5]:
            print(f"  adapter finding: {message}")


def _has_exit_failure_drift(report: dict[str, Any]) -> bool:
    return any(
        item["package_delta"] in EXIT_FAILURE_DELTAS or item["adapter_delta"] in EXIT_FAILURE_DELTAS
        for item in report["comparisons"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare legacy PickleScanner and modelaudit_picklescan on repo fixtures."
    )
    parser.add_argument("--json", action="store_true", help="Print the full diff report as JSON")
    args = parser.parse_args()

    report = _build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_text_report(report)

    return 1 if _has_exit_failure_drift(report) else 0


if __name__ == "__main__":
    raise SystemExit(main())
