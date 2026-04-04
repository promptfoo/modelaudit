"""Stdlib-only Joblib scanner regressions for raw and compressed pickle payloads."""

from __future__ import annotations

import bz2
import gzip
import pickle
import zlib
from pathlib import Path

from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.joblib_scanner import JoblibScanner


class _Payload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        import os

        return (os.system, ("echo owned",))


def _has_system_reduce_failure(result: ScanResult) -> bool:
    return any(
        check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.name == "REDUCE Opcode Safety Check"
        and check.details.get("associated_global") in {"os.system", "posix.system", "nt.system"}
        for check in result.checks
    )


def _scan_payload(tmp_path: Path, payload: bytes, filename: str) -> ScanResult:
    path = tmp_path / filename
    path.write_bytes(payload)
    return JoblibScanner().scan(str(path))


def _compression_failures(result: ScanResult) -> list[Check]:
    return [
        check
        for check in result.checks
        if check.name == "Compression Bomb Detection" and check.status == CheckStatus.FAILED
    ]


def test_scan_detects_raw_protocol0_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(_Payload(), protocol=0)

    result = _scan_payload(tmp_path, payload, "raw_protocol0.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_accepts_raw_protocol4_primitive_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(7, protocol=4)

    result = _scan_payload(tmp_path, payload, "raw_protocol4_primitive.joblib")

    assert result.success is True
    assert _compression_failures(result) == []
    assert not _has_system_reduce_failure(result)


def test_scan_accepts_raw_protocol0_int_pickle_joblib(tmp_path: Path) -> None:
    payload = pickle.dumps(7, protocol=0)

    result = _scan_payload(tmp_path, payload, "raw_protocol0_int.joblib")

    assert result.success is True
    assert _compression_failures(result) == []
    assert not _has_system_reduce_failure(result)


def test_scan_detects_gzip_compressed_pickle_joblib(tmp_path: Path) -> None:
    payload = gzip.compress(pickle.dumps(_Payload(), protocol=4))

    result = _scan_payload(tmp_path, payload, "gzip_protocol4.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_detects_bz2_compressed_pickle_joblib(tmp_path: Path) -> None:
    payload = bz2.compress(pickle.dumps(_Payload(), protocol=4))

    result = _scan_payload(tmp_path, payload, "bz2_protocol4.joblib")

    assert result.success is False
    assert _has_system_reduce_failure(result)


def test_scan_detects_zlib_trailer_after_compressed_joblib_stream(tmp_path: Path) -> None:
    payload = zlib.compress(pickle.dumps({"safe": [1, 2, 3]}, protocol=4)) + pickle.dumps(_Payload(), protocol=0)

    result = _scan_payload(tmp_path, payload, "zlib_trailer.joblib")

    compression_failures = _compression_failures(result)
    assert result.success is False
    assert len(compression_failures) == 1
    assert "Trailing data found after compressed joblib stream" in compression_failures[0].message
    assert not _has_system_reduce_failure(result)


def test_scan_reports_plain_text_joblib_without_critical_pickle_noise(tmp_path: Path) -> None:
    result = _scan_payload(tmp_path, b"not a pickle", "plain_text.joblib")

    compression_failures = _compression_failures(result)
    assert result.success is False
    assert len(compression_failures) == 1
    assert compression_failures[0].severity == IssueSeverity.INFO
    assert not _has_system_reduce_failure(result)
