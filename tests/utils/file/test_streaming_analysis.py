from pathlib import Path

import fsspec
import pytest
from fsspec.implementations.local import LocalFileSystem

from modelaudit.scanners.base import BaseScanner, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.utils.file import streaming


class HeaderOnlyScanner(BaseScanner):
    name = "header_only"

    def scan(self, path: str) -> ScanResult:
        del path
        raise RuntimeError("full scan is not available for streaming fallback")


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
    assert result.success is False
    assert result.has_warnings is True
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_returns_clean_partial_scanner_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00." * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    def fake_scan_stream(self: PickleScanner, file_obj: object, size: int) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = size
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner, max_bytes=4)

    assert was_complete is False
    assert result is not None
    assert result.issues == []
    assert result.bytes_scanned == 4
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_returns_clean_partial_header_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.joblib"
    file_path.write_bytes(b"model-header-only" * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, was_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner(), max_bytes=4)

    assert was_complete is False
    assert result is not None
    assert result.issues == []
    assert result.bytes_scanned == 4
    assert result.success is False
    assert result.has_warnings is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["streaming_analysis"] is True
    assert result.metadata["bytes_analyzed"] == 4
    assert result.metadata["analysis_complete"] is False
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_protocol_marker_only_does_not_emit_protocol_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "protocol_only.pkl"
    file_path.write_bytes(b"\x80\x03")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, was_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner())

    assert was_complete is True
    assert result is not None
    assert not any(issue.type == "streaming_pickle_protocol_check" for issue in result.issues)
    assert result.has_warnings is False


def test_stream_analyze_file_protocol_with_payload_still_emits_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "protocol_payload.pkl"
    file_path.write_bytes(b"\x80\x03N.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, was_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner())

    assert was_complete is True
    assert result is not None
    assert any(issue.type == "streaming_pickle_protocol_check" for issue in result.issues)
    assert result.has_warnings is True


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
