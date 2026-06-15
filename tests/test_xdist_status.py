from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
import yaml

from tests.xdist_status import (
    REPORT_INTERVAL_ENV,
    XdistWorkerStatus,
    XdistWorkerStatusReporter,
    clear_worker_status,
    collect_long_running_worker_statuses,
    format_worker_status_report,
    status_file_for_worker,
    write_worker_status,
)


def _load_root_conftest() -> ModuleType:
    conftest_path = Path(__file__).with_name("conftest.py")
    spec = importlib.util.spec_from_file_location("_modelaudit_test_conftest", conftest_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_nightly_workflow() -> dict[str, Any]:
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "nightly.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def _step_by_name(job: dict[str, Any], name: str) -> dict[str, Any]:
    steps = cast(list[dict[str, Any]], job["steps"])
    for step in steps:
        if step.get("name") == name:
            return step
    raise AssertionError(f"Step {name!r} not found")


def test_collect_long_running_worker_statuses_sorts_by_elapsed_desc(
    tmp_path: Path,
) -> None:
    gw0_status = status_file_for_worker(tmp_path, "gw0")
    gw1_status = status_file_for_worker(tmp_path, "gw1")
    write_worker_status(
        gw0_status,
        "gw0",
        "tests/test_alpha.py::test_fast",
        started_at=100.0,
    )
    write_worker_status(
        gw1_status,
        "gw1",
        "tests/test_beta.py::test_slower",
        started_at=95.0,
    )

    statuses = collect_long_running_worker_statuses(
        tmp_path,
        min_elapsed_seconds=10.0,
        now=120.0,
    )

    assert statuses == [
        XdistWorkerStatus(
            workerid="gw1",
            nodeid="tests/test_beta.py::test_slower",
            elapsed_seconds=25.0,
        ),
        XdistWorkerStatus(
            workerid="gw0",
            nodeid="tests/test_alpha.py::test_fast",
            elapsed_seconds=20.0,
        ),
    ]


def test_collect_long_running_worker_statuses_skips_invalid_and_short_entries(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    write_worker_status(
        status_file_for_worker(tmp_path, "gw0"),
        "gw0",
        "tests/test_alpha.py::test_recent",
        started_at=119.5,
    )

    statuses = collect_long_running_worker_statuses(
        tmp_path,
        min_elapsed_seconds=10.0,
        now=120.0,
    )

    assert statuses == []


def test_collect_long_running_worker_statuses_skips_non_finite_elapsed(
    tmp_path: Path,
) -> None:
    nan_status_file = status_file_for_worker(tmp_path, "gw0")
    nan_status_file.write_text(
        '{"workerid": "gw0", "nodeid": "tests/test_alpha.py::test_nan", "started_at": NaN}',
        encoding="utf-8",
    )
    write_worker_status(
        status_file_for_worker(tmp_path, "gw1"),
        "gw1",
        "tests/test_beta.py::test_negative_inf",
        started_at=math.inf,
    )

    statuses = collect_long_running_worker_statuses(
        tmp_path,
        min_elapsed_seconds=10.0,
        now=120.0,
    )

    assert statuses == []


def test_format_worker_status_report_limits_worker_entries() -> None:
    report = format_worker_status_report(
        [
            XdistWorkerStatus("gw1", "tests/test_beta.py::test_slower", 25.0),
            XdistWorkerStatus("gw0", "tests/test_alpha.py::test_fast", 20.0),
            XdistWorkerStatus("gw2", "tests/test_gamma.py::test_tail", 19.0),
        ],
        limit=2,
    )

    assert report == (
        "[pytest-xdist] long-running workers: "
        "gw1 25.0s tests/test_beta.py::test_slower | "
        "gw0 20.0s tests/test_alpha.py::test_fast | +1 more"
    )


def test_clear_worker_status_removes_existing_file(tmp_path: Path) -> None:
    status_file = status_file_for_worker(tmp_path, "gw0")
    write_worker_status(
        status_file,
        "gw0",
        "tests/test_alpha.py::test_running",
        started_at=100.0,
    )

    clear_worker_status(status_file)

    assert not status_file.exists()


def test_worker_status_reporter_can_be_disabled_with_zero_interval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(REPORT_INTERVAL_ENV, "0")

    assert XdistWorkerStatusReporter.from_environment(tmp_path) is None


def test_worker_status_reporter_stop_joins_thread_and_removes_status_dir(
    tmp_path: Path,
) -> None:
    status_dir = tmp_path / "xdist-status"
    reporter = XdistWorkerStatusReporter(
        status_dir,
        report_interval_seconds=10.0,
        min_elapsed_seconds=0.0,
    )
    reporter.start()
    write_worker_status(
        reporter.status_file_for_worker("gw0"),
        "gw0",
        "tests/test_alpha.py::test_running",
        started_at=100.0,
    )

    reporter.stop()

    assert reporter._thread is None
    assert not status_dir.exists()


def test_pytest_sessionfinish_clears_worker_status_and_stops_reporter(
    tmp_path: Path,
) -> None:
    root_conftest = _load_root_conftest()
    root_conftest_state = cast(Any, root_conftest)
    status_dir = tmp_path / "sessionfinish-status"
    reporter = XdistWorkerStatusReporter(
        status_dir,
        report_interval_seconds=10.0,
        min_elapsed_seconds=0.0,
    )
    reporter.start()
    worker_status_file = reporter.status_file_for_worker("gw0")
    write_worker_status(
        worker_status_file,
        "gw0",
        "tests/test_alpha.py::test_running",
        started_at=100.0,
    )
    root_conftest_state._xdist_status_reporter = reporter
    root_conftest_state._xdist_worker_status_file = worker_status_file

    root_conftest.pytest_sessionfinish(cast(pytest.Session, object()), 0)

    assert root_conftest_state._xdist_status_reporter is None
    assert not worker_status_file.exists()
    assert not status_dir.exists()


def test_check_framework_returns_false_when_package_import_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    broken_package_dir = tmp_path / "broken_framework"
    broken_package_dir.mkdir()
    (broken_package_dir / "__init__.py").write_text(
        'raise RuntimeError("broken optional dependency")\n',
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    root_conftest = _load_root_conftest()

    assert root_conftest._check_framework("broken_framework") is False


def test_nodeid_sharding_is_stable_disjoint_and_exhaustive() -> None:
    root_conftest = _load_root_conftest()
    nodeids = [f"tests/test_example.py::test_case[{index}]" for index in range(1_000)]

    first_assignment = [root_conftest._nodeid_shard(nodeid, 5) for nodeid in nodeids]
    second_assignment = [root_conftest._nodeid_shard(nodeid, 5) for nodeid in nodeids]

    assert first_assignment == second_assignment
    assert set(first_assignment) == set(range(5))
    for nodeid in nodeids:
        assert sum(root_conftest._nodeid_shard(nodeid, 5) == index for index in range(5)) == 1


def test_nightly_correctness_matrix_uses_exhaustive_two_way_shards() -> None:
    jobs = _load_nightly_workflow()["jobs"]
    correctness = jobs["correctness"]

    assert correctness["timeout-minutes"] == 45
    assert correctness["runs-on"] == "${{ matrix.os }}"
    assert correctness["strategy"]["fail-fast"] is False
    matrix = correctness["strategy"]["matrix"]
    assert matrix == {
        "os": ["ubuntu-latest", "windows-latest"],
        "python-version": ["3.10", "3.11", "3.12", "3.13"],
        "shard": [0, 1],
        "exclude": [
            {"os": "windows-latest", "python-version": "3.10"},
            {"os": "windows-latest", "python-version": "3.12"},
            {"os": "windows-latest", "python-version": "3.13"},
        ],
    }
    assert "3.11" in matrix["python-version"]
    assert "uv python pin ${{ matrix.python-version }}" in _step_by_name(correctness, "Pin Python version")["run"]

    sync_run = _step_by_name(correctness, "Sync dependencies")["run"]
    assert "matrix.os == 'windows-latest'" in sync_run
    assert "'all-ci-windows' || 'all-ci'" in sync_run

    run = _step_by_name(correctness, "Run correctness shard (fast + slow + integration)")["run"]
    assert run.count('-m "not performance"') == 1
    assert "-m performance" not in run
    assert "pytest -n auto" in run
    assert "--modelaudit-shard-count 2" in run
    assert "--modelaudit-shard-index ${{ matrix.shard }}" in run
    assert "tests" not in run.split()
    for fail_fast_option in (" -x", "--maxfail", "--ignore", "--deselect"):
        assert fail_fast_option not in run


def test_nightly_runs_unsharded_performance_and_rust_once_and_fails_closed() -> None:
    jobs = _load_nightly_workflow()["jobs"]

    performance = jobs["performance"]
    assert performance["timeout-minutes"] == 45
    assert performance["runs-on"] == "ubuntu-latest"
    assert "strategy" not in performance
    assert _step_by_name(performance, "Pin Python version")["run"].strip() == "uv python pin 3.11"
    performance_run = _step_by_name(performance, "Run performance tests once without xdist")["run"]
    assert performance_run.count("pytest -n 0 -m performance") == 1
    assert '-m "not performance"' not in performance_run
    assert "--modelaudit-shard" not in performance_run
    assert "tests" not in performance_run.split()
    for fail_fast_option in (" -x", "--maxfail", "--ignore", "--deselect"):
        assert fail_fast_option not in performance_run

    assert "strategy" not in jobs["picklescan-rust"]
    rust_run = _step_by_name(jobs["picklescan-rust"], "Run standalone picklescan Rust tests once")["run"]
    assert "cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml" in rust_run

    gate = jobs["nightly-success"]
    assert gate["if"] == "always()"
    assert gate["needs"] == ["correctness", "performance", "picklescan-rust"]
    check_step = _step_by_name(gate, "Require every Nightly lane to succeed")
    assert check_step["env"] == {
        "CORRECTNESS_RESULT": "${{ needs.correctness.result }}",
        "PERFORMANCE_RESULT": "${{ needs.performance.result }}",
        "PICKLESCAN_RUST_RESULT": "${{ needs.picklescan-rust.result }}",
    }
    assert 'if [[ "$result" != "success" ]]' in check_step["run"]
    assert max(job["timeout-minutes"] for job in jobs.values()) == 45
    for job in jobs.values():
        assert "continue-on-error" not in job
        assert all("continue-on-error" not in step for step in job["steps"])


def test_nodeid_sharding_rejects_non_positive_count() -> None:
    root_conftest = _load_root_conftest()

    with pytest.raises(ValueError, match="shard_count must be positive"):
        root_conftest._nodeid_shard("tests/test_example.py::test_case", 0)
