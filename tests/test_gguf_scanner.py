import struct

from modelaudit.scanners.gguf_scanner import GGUFScanner


def create_minimal_gguf(path):
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))
        f.write(struct.pack("<I", 32))
        # align to 32
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)
        name = b"weight"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<Q", 8))
        f.write(struct.pack("<I", 0))  # f32
        offset = f.tell() + 8
        f.write(struct.pack("<Q", offset))
        f.write(b"\0" * 32)  # tensor data


def test_gguf_scanner_can_handle(tmp_path):
    file_path = tmp_path / "test.gguf"
    create_minimal_gguf(file_path)
    assert GGUFScanner.can_handle(str(file_path)) is True


def test_gguf_scanner_scan(tmp_path):
    file_path = tmp_path / "model.gguf"
    create_minimal_gguf(file_path)
    scanner = GGUFScanner()
    result = scanner.scan(str(file_path))
    assert result.success is True
    assert result.metadata["tensor_count"] == 1
