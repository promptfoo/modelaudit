"""Tests for LargeFileHandler chunked scanning."""

from __future__ import annotations

from pathlib import Path

from modelaudit.scanners.base import ScanResult
from modelaudit.utils import large_file_handler


class DummyScanner:
    """Minimal scanner that supports chunk analysis."""

    name = "dummy"

    def _analyze_chunk(self, chunk: bytes, bytes_processed: int) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = len(chunk)
        result.finish(success=True)
        return result


def test_chunked_scan_populates_end_time_and_success(tmp_path: Path, monkeypatch) -> None:
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
