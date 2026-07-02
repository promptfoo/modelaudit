from __future__ import annotations

import contextlib
import io
import os
import pickle
import zipfile
from pathlib import Path
from typing import Any

import pytest

import modelaudit_picklescan.api as package_api
from modelaudit_picklescan import PickleScanner, SafetyVerdict, ScanStatus, scan_file


class MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        # Deliberately unsafe reducer used to verify malicious pickle handling.
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


def test_scan_stream_exact_size_does_not_require_redundant_eof_rewind() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    class BrokenRewindStream(io.BytesIO):
        def seek(self, *_args: object, **_kwargs: object) -> int:
            raise OSError("rewind failed")

    report = PickleScanner().scan_stream(
        BrokenRewindStream(payload),
        source="exact-known-size-broken-rewind.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.CLEAN
    assert not any(notice.code == "known_stream_truncated" for notice in report.notices)


def test_scan_stream_nonseekable_declared_boundary_fails_closed_without_probe() -> None:
    payload = pickle.dumps({"safe": True}, protocol=4)

    class NonSeekableStream:
        def __init__(self, data: bytes) -> None:
            self.data = data
            self.position = 0

        def read(self, size: int = -1) -> bytes:
            if self.position >= len(self.data):
                raise AssertionError("known-size non-seekable stream must not be probed past its boundary")
            end = len(self.data) if size < 0 else min(self.position + size, len(self.data))
            chunk = self.data[self.position : end]
            self.position = end
            return chunk

        def seekable(self) -> bool:
            return False

        def tell(self) -> int:
            raise OSError("stream position unavailable")

    report = PickleScanner().scan_stream(
        NonSeekableStream(payload),  # type: ignore[arg-type]
        source="nonseekable-known-size.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.UNKNOWN
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)


def test_scan_stream_probe_error_preserves_malicious_declared_payload() -> None:
    payload = pickle.dumps(MaliciousPayload(), protocol=4)

    class ProbeErrorStream(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            if self.tell() >= len(payload):
                raise OSError("trailing boundary unavailable")
            return super().read(size)

    report = PickleScanner().scan_stream(
        ProbeErrorStream(payload),
        source="probe-error-known-size.pkl",
        size=len(payload),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert any(notice.code == "known_stream_truncated" for notice in report.notices)


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


def test_scan_file_keeps_plain_descriptor_after_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_path = tmp_path / "descriptor.pkl"
    replacement_path = tmp_path / "replacement.pkl"
    malicious_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    payload_path.write_bytes(malicious_payload)
    replacement_path.write_bytes(pickle.dumps({"safe": True}, protocol=4))
    original_is_zipfile = package_api.zipfile.is_zipfile

    def replace_and_check_zipfile(candidate: Any) -> bool:
        # Windows refuses to replace a file that the scanner holds open; the
        # scanner keeps reading its original descriptor either way, which is the
        # property under test.
        with contextlib.suppress(OSError):
            replacement_path.replace(payload_path)
        return original_is_zipfile(candidate)

    monkeypatch.setattr(package_api.zipfile, "is_zipfile", replace_and_check_zipfile)

    report = scan_file(payload_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert report.coverage.bytes_total == len(malicious_payload)


def test_scan_file_keeps_zip_descriptor_after_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "descriptor.pt"
    replacement_path = tmp_path / "replacement.pkl"
    malicious_payload = pickle.dumps(MaliciousPayload(), protocol=4)
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", malicious_payload)
        archive.writestr("version", "3\n")
    original_size = archive_path.stat().st_size
    replacement_path.write_bytes(pickle.dumps({"safe": True}, protocol=4))
    original_is_zipfile = package_api.zipfile.is_zipfile

    def replace_and_check_zipfile(candidate: Any) -> bool:
        # Windows refuses to replace a file that the scanner holds open; the
        # scanner keeps reading its original descriptor either way, which is the
        # property under test.
        with contextlib.suppress(OSError):
            replacement_path.replace(archive_path)
        return original_is_zipfile(candidate)

    monkeypatch.setattr(package_api.zipfile, "is_zipfile", replace_and_check_zipfile)

    report = scan_file(archive_path)

    assert report.status == ScanStatus.COMPLETE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(finding.rule_code == "DANGEROUS_CALL" for finding in report.findings)
    assert report.coverage.bytes_total == original_size
