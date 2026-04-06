from pathlib import Path

import fsspec
import pytest
from fsspec.implementations.local import LocalFileSystem

from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.utils.file import streaming


def test_stream_analyze_file_uses_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    called: dict[str, bool] = {"called": False}

    def fake_scan_stream(
        self: PickleScanner,
        file_obj: object,
        size: int,
        source: str = "<stream>",
    ) -> ScanResult:
        called["called"] = True
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Test Check",
            passed=False,
            message="scanner issue",
            severity=IssueSeverity.WARNING,
            location=source,
        )
        result.metadata["scanner_used"] = True
        result.bytes_scanned = size
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner)

    assert was_complete is True
    assert result is not None
    assert called["called"] is True
    assert any(issue.message == "scanner issue" for issue in result.issues)
    assert all(issue.location == url for issue in result.issues)
    assert result.metadata.get("scanner_used") is True


def test_stream_analyze_file_falls_back_to_bytes_to_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00." * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    called: dict[str, bool] = {"called": False}

    def fake_scan_stream(self: PickleScanner, file_obj: object, size: int) -> ScanResult:
        called["called"] = True
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Test Check", passed=False, message="scanner issue", severity=IssueSeverity.WARNING, location="memory"
        )
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner, max_bytes=4)

    assert called["called"] is True
    assert was_complete is False
    assert result is not None
    assert result.bytes_scanned == 4


def test_stream_analyze_file_does_not_retry_sourceful_scan_stream_typeerror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    call_count = 0

    def fake_scan_stream(
        self: PickleScanner,
        file_obj: object,
        size: int,
        source: str = "<stream>",
    ) -> ScanResult:
        del self, file_obj, size, source
        nonlocal call_count
        call_count += 1
        raise TypeError("simulated runtime type error")

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner)

    assert call_count == 1
    assert was_complete is True
    assert result is not None
