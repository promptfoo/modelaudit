from pathlib import Path

import numpy as np
import pytest

# Skip if joblib is not available before importing it
pytest.importorskip("joblib")

import joblib

from modelaudit.scanners.joblib_scanner import JoblibScanner


def test_joblib_scanner_basic(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    scanner = JoblibScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.bytes_scanned > 0


def test_joblib_scanner_closes_bytesio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure BytesIO objects used for pickles are closed."""
    import io

    closed = {}

    class TrackedBytesIO(io.BytesIO):
        def close(self) -> None:
            closed["closed"] = True
            super().close()

    monkeypatch.setattr(io, "BytesIO", TrackedBytesIO)

    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    scanner = JoblibScanner()
    scanner.scan(str(path))

    assert closed.get("closed") is True


def test_joblib_scanner_fails_closed_on_incomplete_pickle_without_dangerous_findings(tmp_path: Path) -> None:
    path = tmp_path / "truncated.joblib"
    path.write_bytes(b"\x80\x04}q\x00")

    result = JoblibScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert any(
        issue.severity.value == "critical"
        and issue.message == "Pickle parsing failed before full scan completion"
        and issue.details.get("failure_reason") == "unknown_opcode_or_format_error"
        for issue in result.issues
    )
