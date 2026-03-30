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


def _benchmark_entry(name: str, median: float, mean: float) -> dict[str, object]:
    return {
        "name": name.split("::")[-1],
        "fullname": name,
        "group": None,
        "param": None,
        "params": None,
        "options": {},
        "extra_info": {"path": name.split("::")[-1]},
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
            _benchmark_entry("tests/benchmarks/test_scan_benchmarks.py::test_scan_safe_pickle", 0.020, 0.021),
            _benchmark_entry("tests/benchmarks/test_scan_benchmarks.py::test_scan_pytorch_zip", 0.045, 0.046),
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
    assert "Slowest median" in completed.stdout
    assert "test_scan_safe_pickle" in summary_file.read_text(encoding="utf-8")


def test_benchmark_report_fails_on_regression(tmp_path: Path) -> None:
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

    assert completed.returncode == 1
    assert "Status:" in completed.stdout
    assert "Key changes:" in completed.stdout
    assert "regression" in completed.stdout
    assert "+35.0%" in completed.stdout
