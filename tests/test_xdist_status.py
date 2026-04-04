from __future__ import annotations

from pathlib import Path

import pytest

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
) -> None:
    monkeypatch.setenv(REPORT_INTERVAL_ENV, "0")

    assert XdistWorkerStatusReporter.from_environment() is None
