"""GGUF / GGML scanner."""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Map ggml_type enum to (block_size, type_size)
# Values derived from ggml source
_GGML_TYPE_INFO = {
    0: (1, 4),  # F32
    1: (1, 2),  # F16
    2: (32, 18),  # Q4_0
    3: (32, 20),  # Q4_1
    6: (32, 22),  # Q5_0
    7: (32, 24),  # Q5_1
    8: (32, 34),  # Q8_0
    9: (32, 36),  # Q8_1
    10: (256, 84),  # Q2_K
    11: (256, 110),  # Q3_K
    12: (256, 144),  # Q4_K
    13: (256, 176),  # Q5_K
    14: (256, 210),  # Q6_K
    15: (256, 292),  # Q8_K
}


class GGUFScanner(BaseScanner):
    """Scanner for GGUF / GGML model files."""

    name = "gguf"
    description = "Scans GGUF model headers for consistency"
    supported_extensions = [".gguf", ".ggml"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.max_uncompressed = self.config.get(
            "max_uncompressed", 2 * 1024 * 1024 * 1024
        )

    @staticmethod
    def _read_string(f) -> str:
        (length,) = struct.unpack("<Q", f.read(8))
        data = f.read(length)
        return data.decode("utf-8")

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                return magic == b"GGUF"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != b"GGUF":
                    result.add_issue(
                        "Not a GGUF file", IssueSeverity.ERROR, location=path
                    )
                    result.finish(success=False)
                    return result
                (version,) = struct.unpack("<I", f.read(4))
                (tensor_count,) = struct.unpack("<Q", f.read(8))
                (kv_count,) = struct.unpack("<Q", f.read(8))
                result.metadata.update(
                    {
                        "version": version,
                        "tensor_count": tensor_count,
                        "kv_count": kv_count,
                    }
                )

                metadata: Dict[str, Any] = {}
                for _ in range(kv_count):
                    key = self._read_string(f)
                    (value_type,) = struct.unpack("<I", f.read(4))
                    metadata[key] = self._read_value(f, value_type)
                result.metadata["metadata"] = metadata

                alignment = metadata.get("general.alignment", 32)
                if alignment < 8 or alignment % 8 != 0:
                    result.add_issue("Invalid alignment", IssueSeverity.WARNING, path)
                current = f.tell()
                pad = (alignment - (current % alignment)) % alignment
                if pad:
                    f.seek(pad, os.SEEK_CUR)

                tensors = []
                for _ in range(tensor_count):
                    t_name = self._read_string(f)
                    (nd,) = struct.unpack("<I", f.read(4))
                    dims = [struct.unpack("<Q", f.read(8))[0] for _ in range(nd)]
                    (t_type,) = struct.unpack("<I", f.read(4))
                    (offset,) = struct.unpack("<Q", f.read(8))
                    tensors.append(
                        {
                            "name": t_name,
                            "dims": dims,
                            "type": t_type,
                            "offset": offset,
                        }
                    )
                result.metadata["tensors"] = [
                    {"name": t["name"], "type": t["type"]} for t in tensors
                ]

                for idx, tensor in enumerate(tensors):
                    nelements = 1
                    for d in tensor["dims"]:
                        nelements *= d
                    uncompressed = nelements * 4
                    if uncompressed > self.max_uncompressed:
                        result.add_issue(
                            f"Tensor {tensor['name']} too large", IssueSeverity.ERROR
                        )
                    info = _GGML_TYPE_INFO.get(tensor["type"])
                    if info:
                        blck, ts = info
                        if nelements % blck != 0:
                            result.add_issue(
                                f"Tensor {tensor['name']} not aligned to block size",
                                IssueSeverity.WARNING,
                            )
                        expected = ((nelements + blck - 1) // blck) * ts
                        next_offset = (
                            tensors[idx + 1]["offset"]
                            if idx + 1 < len(tensors)
                            else file_size
                        )
                        actual = next_offset - tensor["offset"]
                        if expected != actual:
                            result.add_issue(
                                f"Size mismatch for tensor {tensor['name']}",
                                IssueSeverity.ERROR,
                                details={"expected": expected, "actual": actual},
                            )
                result.bytes_scanned = f.tell()
        except Exception as e:
            result.add_issue(
                f"Error reading GGUF file: {e}", IssueSeverity.ERROR, location=path
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    def _read_value(self, f, vtype):
        if vtype == 0:
            return struct.unpack("<B", f.read(1))[0]
        if vtype == 1:
            return struct.unpack("<b", f.read(1))[0]
        if vtype == 2:
            return struct.unpack("<H", f.read(2))[0]
        if vtype == 3:
            return struct.unpack("<h", f.read(2))[0]
        if vtype == 4:
            return struct.unpack("<I", f.read(4))[0]
        if vtype == 5:
            return struct.unpack("<i", f.read(4))[0]
        if vtype == 6:
            return struct.unpack("<f", f.read(4))[0]
        if vtype == 7:
            return struct.unpack("<Q", f.read(8))[0]
        if vtype == 8:
            return struct.unpack("<q", f.read(8))[0]
        if vtype == 9:
            return struct.unpack("<d", f.read(8))[0]
        if vtype == 10:
            return self._read_string(f)
        if vtype == 11:
            subtype = struct.unpack("<I", f.read(4))[0]
            (count,) = struct.unpack("<Q", f.read(8))
            return [self._read_value(f, subtype) for _ in range(count)]
        raise ValueError(f"Unknown metadata type {vtype}")
