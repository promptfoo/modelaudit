import struct
from modelaudit.scanners.gguf_scanner import GgufScanner
from modelaudit.scanners.base import IssueSeverity


def _write_minimal_gguf(path, n_kv=1, kv_key=b"test", kv_value=b"val"):
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<q", 0))
        f.write(struct.pack("<q", n_kv))
        if n_kv:
            f.write(struct.pack("<Q", len(kv_key)))
            f.write(kv_key)
            f.write(struct.pack("<i", 8))
            f.write(struct.pack("<Q", len(kv_value)))
            f.write(kv_value)


def test_gguf_scanner_can_handle(tmp_path):
    path = tmp_path / "model.gguf"
    _write_minimal_gguf(path)
    assert GgufScanner.can_handle(str(path))


def test_gguf_scanner_basic_scan(tmp_path):
    path = tmp_path / "model.gguf"
    _write_minimal_gguf(path)
    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["n_kv"] == 1


def test_gguf_scanner_large_kv(tmp_path):
    path = tmp_path / "bad.gguf"
    _write_minimal_gguf(path, n_kv=2**31)
    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.ERROR for i in result.issues)


def test_gguf_scanner_truncated(tmp_path):
    path = tmp_path / "trunc.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<q", 0))
        f.write(struct.pack("<q", 5))
    result = GgufScanner().scan(str(path))
    assert not result.success or any(i.severity == IssueSeverity.ERROR for i in result.issues)

