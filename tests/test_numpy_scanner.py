import numpy as np

from modelaudit.scanners.numpy_scanner import NumpyScanner


def test_numpy_scanner_npy(tmp_path):
    path = tmp_path / "arr.npy"
    np.save(path, np.array([1, 2, 3], dtype=np.int32))

    scanner = NumpyScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert not result.has_errors
    assert result.metadata["dtype"] == "int32"
    assert result.metadata["shape"] == (3,)


def test_numpy_scanner_npz(tmp_path):
    path = tmp_path / "arrs.npz"
    np.savez(path, a=np.arange(5), b=np.ones((2, 2)))

    scanner = NumpyScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert "a.npy" in result.metadata["entries"]
    assert "b.npy" in result.metadata["entries"]


def test_numpy_scanner_zip_bomb(tmp_path):
    path = tmp_path / "bomb.npz"
    big = np.zeros(1_000_000, dtype=np.uint8)
    np.savez_compressed(path, big=big)

    scanner = NumpyScanner()
    result = scanner.scan(str(path))

    assert any("compression ratio" in i.message for i in result.issues)
