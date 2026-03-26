"""Tests for LargeFileHandler chunked scanning."""

from __future__ import annotations

from pathlib import Path

import pytest

from modelaudit.scanners.base import ScanResult
from modelaudit.utils.file import large_file_handler


class DummyScanner:
    """Minimal scanner that supports chunk analysis."""

    name = "dummy"

    def _analyze_chunk(self, chunk: bytes, bytes_processed: int) -> ScanResult:
        """Return a successful chunk scan result."""
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = len(chunk)
        result.finish(success=True)
        return result


class DummyNonChunkScanner:
    """Minimal scanner without chunk analysis support."""

    name = "dummy_non_chunk"

    def __init__(self) -> None:
        """Track calls to the full scan method."""
        self.scan_calls = 0

    def scan(self, file_path: str) -> ScanResult:
        """Return a successful full-file scan result."""
        self.scan_calls += 1
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = Path(file_path).stat().st_size
        result.finish(success=True)
        return result


def test_chunked_scan_populates_end_time_and_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure chunked scans set end_time and success."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 50)

    monkeypatch.setattr(large_file_handler, "SMALL_FILE_THRESHOLD", 1)
    monkeypatch.setattr(large_file_handler, "MEDIUM_FILE_THRESHOLD", 100)
    monkeypatch.setattr(large_file_handler, "DEFAULT_CHUNK_SIZE", 10)

    handler = large_file_handler.LargeFileHandler(str(test_file), DummyScanner())
    result = handler.scan()

    assert result.end_time is not None
    assert result.success is True


def test_chunked_scan_falls_back_to_normal_for_non_chunk_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure chunked routing still runs scanner.scan() when chunk analysis is unavailable."""
    test_file = tmp_path / "model.bin"
    test_file.write_bytes(b"0" * 50)

    monkeypatch.setattr(large_file_handler, "SMALL_FILE_THRESHOLD", 1)
    monkeypatch.setattr(large_file_handler, "MEDIUM_FILE_THRESHOLD", 100)

    scanner = DummyNonChunkScanner()
    handler = large_file_handler.LargeFileHandler(str(test_file), scanner)
    result = handler.scan()

    assert scanner.scan_calls == 1
    assert result.bytes_scanned == 50
    assert result.end_time is not None
    assert result.success is True
