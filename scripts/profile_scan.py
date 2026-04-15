from __future__ import annotations

import argparse
import cProfile
import json
import pstats
import resource
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from modelaudit.core import scan_model_directory_or_file


@dataclass(frozen=True)
class ScanProfileRecord:
    path: str
    repeat_index: int
    wall_seconds: float
    cpu_seconds: float
    bytes_scanned: int
    files_scanned: int
    checks: int
    issues: int
    success: bool


def _max_rss_bytes() -> int:
    max_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(max_rss)
    return int(max_rss) * 1024


def _scan_once(path: Path, *, repeat_index: int, cache_enabled: bool) -> ScanProfileRecord:
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    result = scan_model_directory_or_file(str(path), cache_enabled=cache_enabled)
    return ScanProfileRecord(
        path=str(path),
        repeat_index=repeat_index,
        wall_seconds=time.perf_counter() - wall_start,
        cpu_seconds=time.process_time() - cpu_start,
        bytes_scanned=result.bytes_scanned,
        files_scanned=result.files_scanned,
        checks=len(result.checks),
        issues=len(result.issues),
        success=result.success,
    )


def _format_seconds(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:.3f}s"
    return f"{seconds * 1000:.2f}ms"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Profile ModelAudit scans with wall-clock, CPU, RSS, and cProfile.")
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan.")
    parser.add_argument("--repeat", type=int, default=1, help="Number of scan repetitions per path.")
    parser.add_argument("--cache-enabled", action="store_true", help="Enable ModelAudit's scan cache during profiling.")
    parser.add_argument("--profile-out", type=Path, help="Write cProfile stats to this path.")
    parser.add_argument("--json-out", type=Path, help="Write machine-readable profile summary JSON to this path.")
    parser.add_argument("--sort", default="cumtime", help="pstats sort key for printed profile output.")
    parser.add_argument("--limit", type=int, default=25, help="Number of cProfile rows to print.")
    parser.add_argument("--no-profile-print", action="store_true", help="Suppress pstats output on stdout.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")

    missing_paths = [str(path) for path in args.paths if not path.exists()]
    if missing_paths:
        raise SystemExit(f"Path does not exist: {', '.join(missing_paths)}")

    profiler = cProfile.Profile()
    records: list[ScanProfileRecord] = []
    profiler.enable()
    try:
        for repeat_index in range(args.repeat):
            for path in args.paths:
                records.append(
                    _scan_once(
                        path,
                        repeat_index=repeat_index,
                        cache_enabled=args.cache_enabled,
                    )
                )
    finally:
        profiler.disable()

    if args.profile_out:
        args.profile_out.parent.mkdir(parents=True, exist_ok=True)
        profiler.dump_stats(args.profile_out)

    total_wall = sum(record.wall_seconds for record in records)
    total_cpu = sum(record.cpu_seconds for record in records)
    payload = {
        "cache_enabled": args.cache_enabled,
        "repeat": args.repeat,
        "max_rss_bytes": _max_rss_bytes(),
        "total_wall_seconds": total_wall,
        "total_cpu_seconds": total_cpu,
        "records": [asdict(record) for record in records],
    }

    if args.json_out:
        _write_json(args.json_out, payload)

    print(
        f"Profiled {len(records)} scan(s): wall={_format_seconds(total_wall)}, "
        f"cpu={_format_seconds(total_cpu)}, max_rss={payload['max_rss_bytes']} bytes"
    )
    for record in records:
        print(
            f"- {record.path} repeat={record.repeat_index}: wall={_format_seconds(record.wall_seconds)}, "
            f"cpu={_format_seconds(record.cpu_seconds)}, files={record.files_scanned}, "
            f"bytes={record.bytes_scanned}, checks={record.checks}, issues={record.issues}, "
            f"success={record.success}"
        )

    if not args.no_profile_print:
        pstats.Stats(profiler).sort_stats(args.sort).print_stats(args.limit)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
