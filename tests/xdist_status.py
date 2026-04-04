from __future__ import annotations

import json
import math
import os
import shutil
import sys
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

WORKER_STATUS_DIR_KEY = "modelaudit_xdist_worker_status_dir"
REPORT_INTERVAL_ENV = "MODELAUDIT_PYTEST_XDIST_STATUS_INTERVAL"
MIN_ELAPSED_ENV = "MODELAUDIT_PYTEST_XDIST_STATUS_MIN_SECONDS"

DEFAULT_REPORT_INTERVAL_SECONDS = 30.0
DEFAULT_MIN_ELAPSED_SECONDS = 30.0
MAX_REPORTED_WORKERS = 8


@dataclass(frozen=True)
class XdistWorkerStatus:
    workerid: str
    nodeid: str
    elapsed_seconds: float


def _parse_non_negative_seconds(raw_value: str | None, default: float) -> float:
    if raw_value is None:
        return default

    try:
        parsed = float(raw_value)
    except ValueError:
        return default

    return parsed if parsed >= 0 and math.isfinite(parsed) else default


def status_file_for_worker(status_dir: Path, workerid: str) -> Path:
    return status_dir / f"{workerid}.json"


def write_worker_status(
    status_file: Path,
    workerid: str,
    nodeid: str,
    *,
    started_at: float | None = None,
) -> None:
    started_at = time.time() if started_at is None else started_at
    payload = {
        "workerid": workerid,
        "nodeid": nodeid,
        "started_at": started_at,
    }
    temp_file = status_file.with_suffix(".tmp")

    try:
        status_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        temp_file.replace(status_file)
    except OSError:
        return


def clear_worker_status(status_file: Path) -> None:
    try:
        status_file.unlink(missing_ok=True)
    except OSError:
        return


def collect_long_running_worker_statuses(
    status_dir: Path,
    min_elapsed_seconds: float,
    *,
    now: float | None = None,
) -> list[XdistWorkerStatus]:
    if not status_dir.is_dir():
        return []

    current_time = time.time() if now is None else now
    statuses: list[XdistWorkerStatus] = []

    for status_file in status_dir.glob("*.json"):
        try:
            payload = json.loads(status_file.read_text(encoding="utf-8"))
            workerid = str(payload["workerid"])
            nodeid = str(payload["nodeid"])
            started_at = float(payload["started_at"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if not math.isfinite(started_at):
            continue

        elapsed_seconds = current_time - started_at
        if not math.isfinite(elapsed_seconds) or elapsed_seconds < min_elapsed_seconds:
            continue

        statuses.append(
            XdistWorkerStatus(
                workerid=workerid,
                nodeid=nodeid,
                elapsed_seconds=elapsed_seconds,
            )
        )

    return sorted(statuses, key=lambda status: (-status.elapsed_seconds, status.workerid))


def format_worker_status_report(
    statuses: Iterable[XdistWorkerStatus],
    *,
    limit: int = MAX_REPORTED_WORKERS,
) -> str | None:
    ordered_statuses = list(statuses)
    if not ordered_statuses:
        return None

    rendered_workers = [
        f"{status.workerid} {status.elapsed_seconds:.1f}s {status.nodeid}" for status in ordered_statuses[:limit]
    ]
    extra_count = len(ordered_statuses) - limit
    if extra_count > 0:
        rendered_workers.append(f"+{extra_count} more")

    return "[pytest-xdist] long-running workers: " + " | ".join(rendered_workers)


class XdistWorkerStatusReporter:
    def __init__(
        self,
        status_dir: Path,
        *,
        report_interval_seconds: float,
        min_elapsed_seconds: float,
    ) -> None:
        self.status_dir = status_dir
        self._report_interval_seconds = report_interval_seconds
        self._min_elapsed_seconds = min_elapsed_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @classmethod
    def from_environment(
        cls,
        status_dir: Path,
    ) -> XdistWorkerStatusReporter | None:
        report_interval_seconds = _parse_non_negative_seconds(
            os.environ.get(REPORT_INTERVAL_ENV),
            DEFAULT_REPORT_INTERVAL_SECONDS,
        )
        min_elapsed_seconds = _parse_non_negative_seconds(
            os.environ.get(MIN_ELAPSED_ENV),
            DEFAULT_MIN_ELAPSED_SECONDS,
        )

        if report_interval_seconds == 0:
            return None

        return cls(
            status_dir,
            report_interval_seconds=report_interval_seconds,
            min_elapsed_seconds=min_elapsed_seconds,
        )

    def start(self) -> None:
        if self._thread is not None:
            return

        self._thread = threading.Thread(
            target=self._report_loop,
            name="modelaudit-pytest-xdist-status",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._report_interval_seconds + 1)
            self._thread = None

        shutil.rmtree(self.status_dir, ignore_errors=True)

    def status_file_for_worker(self, workerid: str) -> Path:
        return status_file_for_worker(self.status_dir, workerid)

    def remove_worker_status(self, workerid: str) -> None:
        clear_worker_status(self.status_file_for_worker(workerid))

    def _report_loop(self) -> None:
        while not self._stop_event.wait(self._report_interval_seconds):
            report = format_worker_status_report(
                collect_long_running_worker_statuses(
                    self.status_dir,
                    self._min_elapsed_seconds,
                )
            )
            if report is not None:
                print(report, file=sys.stderr, flush=True)
