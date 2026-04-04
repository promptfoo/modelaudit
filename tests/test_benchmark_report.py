from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_benchmark_json(path: Path, benchmarks: list[dict[str, object]]) -> None:
    payload = {
        "benchmarks": benchmarks,
        "commit_info": {},
        "datetime": "2026-03-30T00:00:00+00:00",
        "machine_info": {},
        "version": "1.0.0",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _benchmark_entry(
    name: str,
    median: float,
    mean: float,
    *,
    extra_info: dict[str, object] | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {"path": name.split("::")[-1]}
    if extra_info is not None:
        metadata.update(extra_info)

    return {
        "name": name.split("::")[-1],
        "fullname": name,
        "group": None,
        "param": None,
        "params": None,
        "options": {},
        "extra_info": metadata,
        "stats": {
            "min": median,
            "max": median,
            "mean": mean,
            "median": median,
            "stddev": 0.0,
            "rounds": 5,
            "iterations": 1,
            "ops": 1.0 / mean if mean else 0.0,
            "q1": median,
            "q3": median,
            "iqr": 0.0,
            "iqr_outliers": 0,
            "stddev_outliers": 0,
            "outliers": "0;0",
            "ld15iqr": median,
            "hd15iqr": median,
            "total": mean * 5,
            "data": [median] * 5,
        },
    }


def test_benchmark_report_summary_only(tmp_path: Path) -> None:
    current_json = tmp_path / "current.json"
    summary_file = tmp_path / "summary.md"
    _write_benchmark_json(
        current_json,
        [
            _benchmark_entry(
                "tests/benchmarks/test_scan_benchmarks.py::test_scan_safe_pickle",
                0.020,
                0.021,
                extra_info={"path": "safe_model.pkl", "bytes": 1024, "files": 1},
            ),
            _benchmark_entry(
                "tests/benchmarks/test_scan_benchmarks.py::test_scan_pytorch_zip",
                0.045,
                0.046,
                extra_info={"path": "state_dict.pt", "bytes": 2048, "files": 1},
            ),
        ],
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--summary-file",
            str(summary_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "Performance Benchmarks" in completed.stdout
    assert "Aggregate median across all benchmarks" in completed.stdout
    summary_text = summary_file.read_text(encoding="utf-8")
    assert "| Benchmark | Target | Size | Files | Median | Mean | Rounds |" in summary_text
    assert "safe_model.pkl" in summary_text
    assert "2.0 KiB" in summary_text
    table_rows = [
        line for line in summary_text.splitlines() if line.startswith("| `tests/benchmarks/test_scan_benchmarks.py::")
    ]
    assert table_rows == [
        (
            "| `tests/benchmarks/test_scan_benchmarks.py::test_scan_pytorch_zip` | "
            "`state_dict.pt` | 2.0 KiB | 1 | 45.00ms | 46.00ms | 5 |"
        ),
        (
            "| `tests/benchmarks/test_scan_benchmarks.py::test_scan_safe_pickle` | "
            "`safe_model.pkl` | 1.0 KiB | 1 | 20.00ms | 21.00ms | 5 |"
        ),
    ]


def test_benchmark_report_reports_regression_without_failing(tmp_path: Path) -> None:
    baseline_json = tmp_path / "baseline.json"
    current_json = tmp_path / "current.json"

    benchmark_name = "tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory"
    _write_benchmark_json(baseline_json, [_benchmark_entry(benchmark_name, 0.100, 0.101)])
    _write_benchmark_json(current_json, [_benchmark_entry(benchmark_name, 0.135, 0.136)])

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--baseline",
            str(baseline_json),
            "--threshold",
            "0.10",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "Status:" in completed.stdout
    assert "Top regressions:" in completed.stdout
    assert "regression" in completed.stdout
    assert "+35.0%" in completed.stdout


def test_benchmark_report_can_fail_on_regression(tmp_path: Path) -> None:
    baseline_json = tmp_path / "baseline.json"
    current_json = tmp_path / "current.json"

    benchmark_name = "tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory"
    _write_benchmark_json(baseline_json, [_benchmark_entry(benchmark_name, 0.100, 0.101)])
    _write_benchmark_json(current_json, [_benchmark_entry(benchmark_name, 0.135, 0.136)])

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--baseline",
            str(baseline_json),
            "--threshold",
            "0.10",
            "--fail-on-regression",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "Top regressions:" in completed.stdout
    assert "+35.0%" in completed.stdout


def test_benchmark_report_reports_missing_benchmark_without_failing(tmp_path: Path) -> None:
    baseline_json = tmp_path / "baseline.json"
    current_json = tmp_path / "current.json"

    kept_benchmark = "tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory"
    missing_benchmark = "tests/benchmarks/test_scan_benchmarks.py::test_scan_mixed_directory"
    _write_benchmark_json(
        baseline_json,
        [
            _benchmark_entry(kept_benchmark, 0.100, 0.101),
            _benchmark_entry(missing_benchmark, 0.200, 0.201),
        ],
    )
    _write_benchmark_json(current_json, [_benchmark_entry(kept_benchmark, 0.095, 0.096)])

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--baseline",
            str(baseline_json),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "Missing benchmarks:" in completed.stdout
    assert missing_benchmark in completed.stdout


def test_benchmark_report_can_fail_on_missing_benchmark(tmp_path: Path) -> None:
    baseline_json = tmp_path / "baseline.json"
    current_json = tmp_path / "current.json"

    kept_benchmark = "tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory"
    missing_benchmark = "tests/benchmarks/test_scan_benchmarks.py::test_scan_mixed_directory"
    _write_benchmark_json(
        baseline_json,
        [
            _benchmark_entry(kept_benchmark, 0.100, 0.101),
            _benchmark_entry(missing_benchmark, 0.200, 0.201),
        ],
    )
    _write_benchmark_json(current_json, [_benchmark_entry(kept_benchmark, 0.095, 0.096)])

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--baseline",
            str(baseline_json),
            "--fail-on-missing",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "Missing benchmarks:" in completed.stdout
    assert missing_benchmark in completed.stdout


def test_benchmark_report_uses_baseline_size_when_current_metadata_partial(tmp_path: Path) -> None:
    baseline_json = tmp_path / "baseline.json"
    current_json = tmp_path / "current.json"

    benchmark_name = "tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory"
    _write_benchmark_json(
        baseline_json,
        [
            _benchmark_entry(
                benchmark_name,
                0.100,
                0.101,
                extra_info={"path": "baseline_dir", "bytes": 2048, "files": 4},
            )
        ],
    )
    _write_benchmark_json(
        current_json,
        [_benchmark_entry(benchmark_name, 0.110, 0.111, extra_info={"path": "current_dir"})],
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--baseline",
            str(baseline_json),
            "--threshold",
            "0.05",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    expected_row_prefix = (
        "| `tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory` | `current_dir` | 2.0 KiB | 4 |"
    )
    assert expected_row_prefix in completed.stdout


def test_benchmark_report_top_improvements_and_mixed_metadata_fallback(tmp_path: Path) -> None:
    baseline_json = tmp_path / "baseline.json"
    current_json = tmp_path / "current.json"

    improved_name = "tests/benchmarks/test_scan_benchmarks.py::test_scan_duplicate_directory"
    missing_name = "tests/benchmarks/test_scan_benchmarks.py::test_scan_mixed_directory"
    new_name = "tests/benchmarks/test_scan_benchmarks.py::test_scan_safe_pickle"
    _write_benchmark_json(
        baseline_json,
        [
            _benchmark_entry(
                improved_name,
                0.100,
                0.101,
                extra_info={"path": "baseline_dir", "bytes": 4096, "files": 10},
            ),
            _benchmark_entry(missing_name, 0.200, 0.201),
        ],
    )
    _write_benchmark_json(
        current_json,
        [
            _benchmark_entry(
                improved_name,
                0.080,
                0.081,
                # Boolean `bytes` is intentional invalid metadata; this verifies
                # that the report falls back to the baseline size value.
                extra_info={"path": "current_dir", "bytes": True, "files": 2},
            ),
            _benchmark_entry(new_name, 0.050, 0.051),
        ],
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_report.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--current",
            str(current_json),
            "--baseline",
            str(baseline_json),
            "--threshold",
            "0.10",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "Status: `0` regressions, `1` improved, `0` stable, `1` new, `1` missing." in completed.stdout
    assert "Top improvements:" in completed.stdout
    assert f"- `{improved_name}` -20.0%" in completed.stdout
    expected_row_prefix = f"| `{improved_name}` | `current_dir` | 4.0 KiB | 2 |"
    assert expected_row_prefix in completed.stdout
