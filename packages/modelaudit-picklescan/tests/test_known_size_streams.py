from __future__ import annotations

import io
import os
import pickle
from pathlib import Path
from typing import Any

import pytest

from modelaudit_picklescan import PickleScanner, SafetyVerdict, ScanStatus, scan_file


class MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


def test_scan_stream_declared_size_trailing_payload_fails_closed() -> None:
    benign_prefix = pickle.dumps({"safe": True}, protocol=4)
    payload = benign_prefix + pickle.dumps(MaliciousPayload(), protocol=4)
    stream = io.BytesIO(payload)

    report = PickleScanner().scan_stream(
        stream,
        source="known-size-with-trailing-payload.pkl",
        size=len(benign_prefix),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert report.findings == ()
    notice = next(notice for notice in report.notices if notice.code == "known_stream_truncated")
    assert notice.details["bytes_scanned"] == len(benign_prefix)
    assert notice.details["bytes_total"] == len(benign_prefix)
    assert notice.details["analysis_incomplete"] is True
    assert report.coverage.bytes_scanned == len(benign_prefix)
    assert report.coverage.bytes_total == len(benign_prefix)
    assert not report.coverage.raw_scan_complete
    assert stream.tell() == len(benign_prefix)


def test_scan_stream_exact_declared_size_stays_clean() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)
    stream = io.BytesIO(payload)

    report = PickleScanner().scan_stream(
        stream,
        source="exact-known-size.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(notice.code == "known_stream_truncated" for notice in report.notices)
    assert report.coverage.bytes_scanned == len(payload)
    assert report.coverage.bytes_total == len(payload)
    assert stream.tell() == len(payload)


def test_scan_file_uses_open_descriptor_size_after_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_path = tmp_path / "race.pkl"
    benign_prefix = pickle.dumps({"safe": True}, protocol=4)
    replacement_payload = benign_prefix + pickle.dumps(MaliciousPayload(), protocol=4)
    payload_path.write_bytes(benign_prefix)
    original_open = Path.open
    replaced = False

    def replace_before_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        nonlocal replaced
        if self == payload_path and not replaced:
            replaced = True
            payload_path.write_bytes(replacement_payload)
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", replace_before_open)

    report = scan_file(payload_path)

    assert replaced
    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert report.coverage.bytes_total == len(replacement_payload)
