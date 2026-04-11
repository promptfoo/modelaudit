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

from modelaudit_picklescan import PickleReport, ScanStatus, Severity
from modelaudit_picklescan import scan_file as package_scan_file

from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.scanners.picklescan_adapter import pickle_report_to_scan_result

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS_DIR = REPO_ROOT / "tests" / "assets"
FIXTURE_LABELS_MANIFEST = REPO_ROOT / "scripts" / "compare_pickle_scanners_fixture_labels.json"

VERDICT_RANK = {
    "clean": 0,
    "suspicious": 1,
    "malicious": 2,
    "unknown": -1,
}
FIXTURE_LABELS = ("safe", "malicious", "unknown")
EXIT_FAILURE_DELTAS = frozenset({"potential_fp", "potential_fn", "verdict_drift", "status_drift"})


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
        reuse_seekable_stream_for_legacy: bool = False,
    ) -> ScanResult:
        del reuse_seekable_stream_for_legacy
        self.current_file_path = source
        return self._scan_pickle_bytes(file_obj, file_size)


def _discover_pickle_fixtures() -> list[Path]:
    return sorted(
        path for path in ASSETS_DIR.rglob("*") if path.is_file() and path.suffix.lower() in {".pkl", ".pickle", ".dill"}
    )


def _load_fixture_labels_manifest() -> dict[str, str]:
    with FIXTURE_LABELS_MANIFEST.open("r", encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    if not isinstance(manifest, dict):
        raise ValueError(f"fixture label manifest must be a JSON object: {FIXTURE_LABELS_MANIFEST}")
    return {str(path): str(label) for path, label in manifest.items()}


_FIXTURE_LABELS_BY_PATH: dict[str, str] | None = None


def _fixture_labels_by_path() -> dict[str, str]:
    global _FIXTURE_LABELS_BY_PATH
    if _FIXTURE_LABELS_BY_PATH is None:
        _FIXTURE_LABELS_BY_PATH = _load_fixture_labels_manifest()
    return _FIXTURE_LABELS_BY_PATH


def _fixture_label(path: Path) -> str:
    fixture_path = path
    if path.is_absolute():
        fixture_path = path.relative_to(REPO_ROOT)

    fixture_key = fixture_path.as_posix()
    label = _fixture_labels_by_path().get(fixture_key)
    if label is None:
        raise KeyError(f"missing pickle fixture label for {fixture_key} in {FIXTURE_LABELS_MANIFEST}")
    return label


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
        warning_count=sum(1 for finding in report.findings if finding.severity == Severity.WARNING),
        critical_count=sum(1 for finding in report.findings if finding.severity == Severity.CRITICAL),
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


def _scan_root_fixture(path: Path, *, config: dict[str, Any] | None = None) -> NormalizedResult:
    return _normalize_scan_result(PickleScanner(config=config).scan(str(path)), engine="root")


def _classify_delta(label: str, legacy: NormalizedResult, package: NormalizedResult) -> str:
    legacy_rank = VERDICT_RANK[legacy.verdict]
    package_rank = VERDICT_RANK[package.verdict]

    if label == "safe" and package.verdict in {"suspicious", "malicious"} and package_rank > legacy_rank:
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


def _build_report(
    *,
    include_root: bool = False,
    root_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
            comparison = {
                "path": path.relative_to(REPO_ROOT).as_posix(),
                "label": label,
                "package_delta": package_delta,
                "adapter_delta": adapter_delta,
                "legacy": legacy_result.__dict__,
                "package": package_result.__dict__,
                "adapter": adapter_result.__dict__,
            }
            if include_root:
                root_result = _scan_root_fixture(path, config=root_config)
                comparison["root_delta"] = _classify_delta(label, legacy_result, root_result)
                comparison["root"] = root_result.__dict__
            comparisons.append(comparison)
    finally:
        logging.disable(previous_logging_disable_level)

    summary: dict[str, dict[str, int]] = {
        "package": {},
        "adapter": {},
    }
    if include_root:
        summary["root"] = {}
    by_label: dict[str, dict[str, dict[str, int]]] = {
        "package": {label: {} for label in FIXTURE_LABELS},
        "adapter": {label: {} for label in FIXTURE_LABELS},
    }
    if include_root:
        by_label["root"] = {label: {} for label in FIXTURE_LABELS}
    for comparison in comparisons:
        label = comparison["label"]
        for engine_name, engine_summary in summary.items():
            delta = comparison[f"{engine_name}_delta"]
            engine_summary[delta] = engine_summary.get(delta, 0) + 1

            label_summary = by_label[engine_name][label]
            label_summary[delta] = label_summary.get(delta, 0) + 1

    return {
        "fixture_count": len(fixtures),
        "summary": {
            engine_name: dict(sorted(engine_summary.items())) for engine_name, engine_summary in summary.items()
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
        item
        for item in report["comparisons"]
        if any(key.endswith("_delta") and value != "match" for key, value in item.items())
    ]
    if not interesting:
        print("\nNo verdict/status/rule drift found.")
        return

    print("\nDeltas:")
    for item in interesting:
        delta_summary = " ".join(
            f"{key.removesuffix('_delta')}={value}" for key, value in item.items() if key.endswith("_delta")
        )
        print(f"\n[{delta_summary}] {item['path']} ({item['label']})")
        for engine_name in ("legacy", "package", "adapter", "root"):
            engine_result = item.get(engine_name)
            if not isinstance(engine_result, dict):
                continue
            print(
                f"  {engine_name:7}: "
                f"status={engine_result['status']} verdict={engine_result['verdict']} "
                f"warnings={engine_result['warning_count']} criticals={engine_result['critical_count']} "
                f"success={engine_result['success']}"
            )
        legacy = item["legacy"]
        package = item["package"]
        adapter = item["adapter"]
        legacy_rules = Counter(legacy["rule_codes"])
        package_rules = Counter(package["rule_codes"])
        adapter_rules = Counter(adapter["rule_codes"])
        print(f"  legacy-only rules : {sorted((legacy_rules - package_rules).elements())}")
        print(f"  package-only rules: {sorted((package_rules - legacy_rules).elements())}")
        print(f"  adapter-only rules: {sorted((adapter_rules - legacy_rules).elements())}")
        root = item.get("root")
        if isinstance(root, dict):
            root_rules = Counter(root["rule_codes"])
            print(f"  root-only rules   : {sorted((root_rules - legacy_rules).elements())}")
        for message in package["messages"][:5]:
            print(f"  package finding: {message}")
        for message in adapter["messages"][:5]:
            print(f"  adapter finding: {message}")
        if isinstance(root, dict):
            for message in root["messages"][:5]:
                print(f"  root finding: {message}")


def _has_exit_failure_drift(report: dict[str, Any]) -> bool:
    return any(
        value in EXIT_FAILURE_DELTAS
        for item in report["comparisons"]
        for key, value in item.items()
        if key.endswith("_delta")
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare legacy PickleScanner and modelaudit_picklescan on repo fixtures."
    )
    parser.add_argument("--json", action="store_true", help="Print the full diff report as JSON")
    parser.add_argument("--include-root", action="store_true", help="Also compare the actual root PickleScanner")
    parser.add_argument(
        "--root-standalone-primary",
        action="store_true",
        help="Compare the root scanner with use_standalone_pickle_primary=True",
    )
    args = parser.parse_args()

    root_config = {"use_standalone_pickle_primary": True} if args.root_standalone_primary else None
    report = _build_report(include_root=args.include_root or args.root_standalone_primary, root_config=root_config)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_text_report(report)

    return 1 if _has_exit_failure_drift(report) else 0


if __name__ == "__main__":
    raise SystemExit(main())
