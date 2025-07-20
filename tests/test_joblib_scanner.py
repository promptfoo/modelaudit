import joblib
import numpy as np
import pytest

from modelaudit.scanners.joblib_scanner import JoblibScanner

pytest.importorskip("joblib")


def test_joblib_scanner_basic(tmp_path):
    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    scanner = JoblibScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.bytes_scanned > 0


def test_joblib_scanner_closes_bytesio(tmp_path, monkeypatch):
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
