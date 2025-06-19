import numpy as np
import pytest

pytest.importorskip("joblib")

import joblib

from modelaudit.scanners.joblib_scanner import JoblibScanner


def test_joblib_scanner_basic(tmp_path):
    path = tmp_path / "model.joblib"
    joblib.dump({"a": np.arange(5)}, path, compress=3)

    scanner = JoblibScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.bytes_scanned > 0
