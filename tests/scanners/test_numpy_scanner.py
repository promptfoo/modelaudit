import numpy as np

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.numpy_scanner import NumPyScanner


def test_numpy_scanner_valid(tmp_path):
    arr = np.arange(10)
    path = tmp_path / "array.npy"
    np.save(path, arr)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.bytes_scanned == path.stat().st_size
    assert not any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_numpy_scanner_truncated(tmp_path):
    arr = np.arange(10)
    path = tmp_path / "bad.npy"
    np.save(path, arr)
    data = path.read_bytes()[:-5]
    path.write_bytes(data)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
