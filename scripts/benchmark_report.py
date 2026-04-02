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


@dataclass(frozen=True)
class ComparisonRow:
    name: str
    target: str
    size: str
    files: str
    baseline_median: float
    current_median: float
    delta_ratio: float
    status: str


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


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return None


def _format_bytes(size_bytes: int | None) -> str:
    if size_bytes is None:
        return "-"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MiB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GiB"


def _record_context(record: BenchmarkRecord | None) -> tuple[str, str, str]:
    if record is None:
        return "-", "-", "-"

    target = record.extra_info.get("path")
    target_label = target if isinstance(target, str) and target else "-"

    size_bytes = _coerce_int(record.extra_info.get("bytes"))
    file_count = _coerce_int(record.extra_info.get("files"))
    file_count_label = str(file_count) if file_count is not None else "-"

    return target_label, _format_bytes(size_bytes), file_count_label


def _merged_record_context(current_record: BenchmarkRecord, baseline_record: BenchmarkRecord) -> tuple[str, str, str]:
    current_target, current_size, current_files = _record_context(current_record)
    baseline_target, baseline_size, baseline_files = _record_context(baseline_record)
    target = current_target if current_target != "-" else baseline_target
    size = current_size if current_size != "-" else baseline_size
    files = current_files if current_files != "-" else baseline_files
    return target, size, files


def _format_change(delta_ratio: float) -> str:
    return f"{delta_ratio:+.1%}"


def _build_summary(
    current: dict[str, BenchmarkRecord],
    baseline: dict[str, BenchmarkRecord] | None,
    *,
    threshold: float,
    fail_on_regression: bool = False,
    fail_on_missing: bool = False,
) -> tuple[str, bool]:
    lines = ["## Performance Benchmarks", ""]

    if baseline is None:
        sorted_current = sorted(current.values(), key=lambda item: item.median, reverse=True)
        lines.append(f"Captured `{len(current)}` benchmark results.")
        if sorted_current:
            total_median = sum(record.median for record in sorted_current)
            lines.append(f"Aggregate median across all benchmarks: {_format_duration(total_median)}.")
            lines.append("")
            lines.append("Slowest benchmarks:")
            for record in sorted_current[:3]:
                target, size, files = _record_context(record)
                lines.append(
                    f"- `{record.name}` at {_format_duration(record.median)} ({target}, size={size}, files={files})"
                )
        lines.append("")
        lines.append("| Benchmark | Target | Size | Files | Median | Mean | Rounds |")
        lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")

        for record in sorted_current:
            target, size, files = _record_context(record)
            lines.append(
                f"| `{record.name}` | `{target}` | {size} | {files} | "
                f"{_format_duration(record.median)} | {_format_duration(record.mean)} | {record.rounds} |"
            )

        return "\n".join(lines), False

    common_names = sorted(set(current) & set(baseline))
    missing_from_current = sorted(set(baseline) - set(current))
    new_in_current = sorted(set(current) - set(baseline))
    regression_count = 0
    improved_count = 0
    stable_count = 0

    comparison_rows: list[ComparisonRow] = []
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

        target, size, files = _merged_record_context(current_record, baseline_record)
        comparison_rows.append(
            ComparisonRow(
                name=name,
                target=target,
                size=size,
                files=files,
                baseline_median=baseline_record.median,
                current_median=current_record.median,
                delta_ratio=delta_ratio,
                status=status,
            )
        )

    sorted_rows = sorted(comparison_rows, key=lambda row: abs(row.delta_ratio), reverse=True)
    lines.append(f"Compared `{len(common_names)}` shared benchmarks with a regression threshold of `{threshold:.0%}`.")
    lines.append(
        f"Status: `{regression_count}` regressions, `{improved_count}` improved, `{stable_count}` stable, "
        f"`{len(new_in_current)}` new, `{len(missing_from_current)}` missing."
    )
    if sorted_rows:
        baseline_total = sum(row.baseline_median for row in sorted_rows)
        current_total = sum(row.current_median for row in sorted_rows)
        total_delta_ratio = 0.0 if baseline_total == 0 else (current_total - baseline_total) / baseline_total
        lines.append(
            f"Aggregate shared-benchmark median: {_format_duration(baseline_total)} "
            f"-> {_format_duration(current_total)} ({_format_change(total_delta_ratio)})."
        )

    top_regressions = [row for row in sorted_rows if row.status == "regression"][:3]
    if top_regressions:
        lines.append("")
        lines.append("Top regressions:")
        for row in top_regressions:
            lines.append(
                f"- `{row.name}` {_format_change(row.delta_ratio)} "
                f"({_format_duration(row.baseline_median)} -> {_format_duration(row.current_median)}, "
                f"{row.target}, size={row.size}, files={row.files})"
            )

    lines.append("")
    top_improvements = [row for row in sorted_rows if row.status == "improved"][:3]
    if top_improvements:
        lines.append("Top improvements:")
        for row in top_improvements:
            lines.append(
                f"- `{row.name}` {_format_change(row.delta_ratio)} "
                f"({_format_duration(row.baseline_median)} -> {_format_duration(row.current_median)}, "
                f"{row.target}, size={row.size}, files={row.files})"
            )
        lines.append("")

    lines.append("| Benchmark | Target | Size | Files | Baseline | Current | Change | Status |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |")

    for row in sorted_rows:
        lines.append(
            f"| `{row.name}` | `{row.target}` | {row.size} | {row.files} | "
            f"{_format_duration(row.baseline_median)} | {_format_duration(row.current_median)} | "
            f"{_format_change(row.delta_ratio)} | {row.status} |"
        )

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

    should_fail = (fail_on_regression and regression_count > 0) or (fail_on_missing and bool(missing_from_current))
    return "\n".join(lines), should_fail


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
        help="Mark regressions and improvements when a benchmark median changes by more than this ratio. Default: 0.15",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional path to write Markdown output, such as $GITHUB_STEP_SUMMARY.",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit non-zero when one or more benchmarks are classified as regressions.",
    )
    parser.add_argument(
        "--fail-on-missing",
        action="store_true",
        help="Fail when a baseline benchmark is missing from the current results.",
    )
    args = parser.parse_args(argv)

    current = _load_records(args.current)
    if not current:
        parser.error(f"No benchmark records found in {args.current}")

    baseline = _load_records(args.baseline) if args.baseline is not None else None
    summary, has_regressions = _build_summary(
        current,
        baseline,
        threshold=args.threshold,
        fail_on_regression=args.fail_on_regression,
        fail_on_missing=args.fail_on_missing,
    )
    _write_summary(summary, args.summary_file)

    if has_regressions:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
