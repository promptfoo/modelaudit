from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BenchmarkRecord:
    name: str
    median: float
    mean: float
    rounds: int
    extra_info: dict[str, Any]


def _load_records(path: Path) -> dict[str, BenchmarkRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    records: dict[str, BenchmarkRecord] = {}
    for benchmark in payload.get("benchmarks", []):
        stats = benchmark.get("stats", {})
        fullname = benchmark.get("fullname") or benchmark.get("name")
        if not isinstance(fullname, str):
            continue
        median = float(stats.get("median", 0.0))
        mean = float(stats.get("mean", 0.0))
        rounds = int(stats.get("rounds", 0))
        extra_info = benchmark.get("extra_info", {})
        records[fullname] = BenchmarkRecord(
            name=fullname,
            median=median,
            mean=mean,
            rounds=rounds,
            extra_info=extra_info if isinstance(extra_info, dict) else {},
        )
    return records


def _format_duration(seconds: float) -> str:
    if seconds >= 1.0:
        return f"{seconds:.3f}s"
    milliseconds = seconds * 1_000
    if milliseconds >= 1.0:
        return f"{milliseconds:.2f}ms"
    microseconds = seconds * 1_000_000
    return f"{microseconds:.1f}us"


def _build_summary(
    current: dict[str, BenchmarkRecord],
    baseline: dict[str, BenchmarkRecord] | None,
    *,
    threshold: float,
) -> tuple[str, bool]:
    lines = ["## Performance Benchmarks", ""]

    if baseline is None:
        lines.append(f"Captured `{len(current)}` benchmark results.")
        if current:
            slowest = max(current.values(), key=lambda record: record.median)
            fastest = min(current.values(), key=lambda record: record.median)
            lines.append(
                f"Slowest median: `{slowest.name}` at {_format_duration(slowest.median)}. "
                f"Fastest median: `{fastest.name}` at {_format_duration(fastest.median)}."
            )
        lines.append("")
        lines.append("| Benchmark | Median | Mean | Rounds |")
        lines.append("| --- | ---: | ---: | ---: |")

        for name, record in sorted(current.items()):
            lines.append(
                f"| `{name}` | {_format_duration(record.median)} | {_format_duration(record.mean)} | {record.rounds} |"
            )

        return "\n".join(lines), False

    common_names = sorted(set(current) & set(baseline))
    missing_from_current = sorted(set(baseline) - set(current))
    new_in_current = sorted(set(current) - set(baseline))
    regression_count = 0
    improved_count = 0
    stable_count = 0

    sortable_rows: list[tuple[float, str, str, float, str, float, float]] = []
    for name in common_names:
        baseline_record = baseline[name]
        current_record = current[name]

        if baseline_record.median == 0:
            delta_ratio = 0.0
        else:
            delta_ratio = (current_record.median - baseline_record.median) / baseline_record.median

        if delta_ratio > threshold:
            status = "regression"
            regression_count += 1
        elif delta_ratio < -threshold:
            status = "improved"
            improved_count += 1
        else:
            status = "stable"
            stable_count += 1

        row = (
            abs(delta_ratio),
            name,
            (
                f"| `{name}` | {_format_duration(baseline_record.median)} | "
                f"{_format_duration(current_record.median)} | {delta_ratio:+.1%} | {status} |"
            ),
            delta_ratio,
            status,
            baseline_record.median,
            current_record.median,
        )
        sortable_rows.append(row)

    lines.append(f"Compared `{len(common_names)}` shared benchmarks with a regression threshold of `{threshold:.0%}`.")
    lines.append(f"Status: `{regression_count}` regressions, `{improved_count}` improved, `{stable_count}` stable.")
    key_rows = [row for row in sorted(sortable_rows, reverse=True) if row[4] != "stable"][:3]
    if key_rows:
        lines.append("")
        lines.append("Key changes:")
        for _abs_delta, name, _row, delta_ratio, status, baseline_median, current_median in key_rows:
            lines.append(
                f"- {status}: `{name}` {delta_ratio:+.1%} "
                f"({_format_duration(baseline_median)} -> {_format_duration(current_median)})"
            )
        lines.append("")

    lines.append("")
    lines.append("| Benchmark | Baseline | Current | Change | Status |")
    lines.append("| --- | ---: | ---: | ---: | --- |")

    for _abs_delta, _name, row, _delta_ratio, _status, _baseline_median, _current_median in sorted(
        sortable_rows, reverse=True
    ):
        lines.append(row)

    if new_in_current:
        lines.append("")
        lines.append("New benchmarks:")
        for name in new_in_current:
            lines.append(f"- `{name}`")

    if missing_from_current:
        lines.append("")
        lines.append("Missing benchmarks:")
        for name in missing_from_current:
            lines.append(f"- `{name}`")

    return "\n".join(lines), regression_count > 0


def _write_summary(summary: str, summary_file: Path | None) -> None:
    print(summary)
    if summary_file is not None:
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text(summary + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize or compare pytest-benchmark JSON results.")
    parser.add_argument("--current", required=True, type=Path, help="Path to the current benchmark JSON file.")
    parser.add_argument("--baseline", type=Path, help="Optional path to the baseline benchmark JSON file.")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.15,
        help="Fail when a benchmark median regresses by more than this ratio. Default: 0.15",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional path to write Markdown output, such as $GITHUB_STEP_SUMMARY.",
    )
    args = parser.parse_args(argv)

    current = _load_records(args.current)
    if not current:
        parser.error(f"No benchmark records found in {args.current}")

    baseline = _load_records(args.baseline) if args.baseline is not None else None
    summary, has_regressions = _build_summary(current, baseline, threshold=args.threshold)
    _write_summary(summary, args.summary_file)

    if has_regressions:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
