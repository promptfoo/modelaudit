import json
import struct
from pathlib import Path

import numpy as np
from safetensors.numpy import save_file

from modelaudit.scanners.safetensors_scanner import SafeTensorsScanner
from modelaudit.scanners.base import IssueSeverity


def create_safetensors_file(path: Path) -> None:
    data = {
        "t1": np.arange(10, dtype=np.float32),
        "t2": np.ones((2, 2), dtype=np.int64),
    }
    save_file(data, str(path))


def test_valid_safetensors_file(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is True
    assert not result.has_errors
    assert result.metadata.get("tensor_count") == 2


def test_corrupted_header(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    corrupt_path = tmp_path / "corrupt.safetensors"
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    header_len = struct.unpack("<Q", data[:8])[0]
    header = data[8 : 8 + header_len]
    corrupt_header = header[:-10]  # truncate more to break JSON
    new_len = struct.pack("<Q", len(corrupt_header))
    corrupt_path.write_bytes(new_len + corrupt_header + data[8 + header_len :])

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(corrupt_path))

    assert result.has_errors
    assert any(
        "json" in issue.message.lower() or "header" in issue.message.lower()
        for issue in result.issues
    )


def test_bad_offsets(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    bad_path = tmp_path / "bad_offsets.safetensors"
    with open(file_path, "rb") as f:
        header_len = struct.unpack("<Q", f.read(8))[0]
        header_bytes = f.read(header_len)
        rest = f.read()

    header = json.loads(header_bytes.decode("utf-8"))
    first = next(k for k in header.keys() if k != "__metadata__")
    header[first]["data_offsets"] = [0, 2]  # incorrect
    new_header_bytes = json.dumps(header).encode("utf-8")
    new_len = struct.pack("<Q", len(new_header_bytes))
    bad_path.write_bytes(new_len + new_header_bytes + rest)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(bad_path))

    assert result.has_errors
    assert any("offset" in issue.message.lower() for issue in result.issues)
