"""SafeTensors model scanner."""

from __future__ import annotations

import json
import os
import struct
from typing import Any, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Map SafeTensors dtypes to byte sizes for integrity checking
_DTYPE_SIZES = {
    "F16": 2,
    "F32": 4,
    "F64": 8,
    "I8": 1,
    "I16": 2,
    "I32": 4,
    "I64": 8,
    "U8": 1,
    "U16": 2,
    "U32": 4,
    "U64": 8,
}


class SafeTensorsScanner(BaseScanner):
    """Scanner for SafeTensors model files."""

    name = "safetensors"
    description = "Scans SafeTensors model files for integrity issues"
    supported_extensions = [".safetensors"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path."""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True

        try:
            from modelaudit.utils.filetype import detect_file_format

            return detect_file_format(path) == "safetensors"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a SafeTensors file."""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                header_len_bytes = f.read(8)
                if len(header_len_bytes) != 8:
                    result.add_issue(
                        "File too small to contain SafeTensors header length",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                if header_len <= 0 or header_len > file_size - 8:
                    result.add_issue(
                        "Invalid SafeTensors header length",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"header_len": header_len},
                    )
                    result.finish(success=False)
                    return result

                header_bytes = f.read(header_len)
                if len(header_bytes) != header_len:
                    result.add_issue(
                        "Failed to read SafeTensors header",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result

                if not header_bytes.strip().startswith(b"{"):
                    result.add_issue(
                        "SafeTensors header does not start with '{'",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result

                try:
                    header = json.loads(header_bytes.decode("utf-8"))
                except json.JSONDecodeError as e:
                    result.add_issue(
                        f"Invalid JSON header: {str(e)}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result

                result.metadata["tensor_count"] = len(
                    [k for k in header.keys() if k != "__metadata__"]
                )

                # Validate tensor offsets and sizes
                tensor_entries: list[tuple[str, Any]] = [
                    (k, v) for k, v in header.items() if k != "__metadata__"
                ]

                data_size = file_size - (8 + header_len)
                offsets = []
                for name, info in tensor_entries:
                    if not isinstance(info, dict):
                        result.add_issue(
                            f"Invalid tensor entry for {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                        )
                        continue

                    begin, end = info.get("data_offsets", [0, 0])
                    dtype = info.get("dtype")
                    shape = info.get("shape", [])

                    if not isinstance(begin, int) or not isinstance(end, int):
                        result.add_issue(
                            f"Invalid data_offsets for {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                        )
                        continue

                    if begin < 0 or end <= begin or end > data_size:
                        result.add_issue(
                            f"Tensor {name} offsets out of bounds",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"begin": begin, "end": end},
                        )
                        continue

                    offsets.append((begin, end))

                    # Validate dtype/shape size
                    expected_size = self._expected_size(dtype, shape)
                    if expected_size is not None and expected_size != end - begin:
                        result.add_issue(
                            f"Size mismatch for tensor {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "expected_size": expected_size,
                                "actual_size": end - begin,
                            },
                        )

                # Check offset continuity
                offsets.sort(key=lambda x: x[0])
                last_end = 0
                for begin, end in offsets:
                    if begin != last_end:
                        result.add_issue(
                            "Tensor data offsets have gaps or overlap",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                        )
                        break
                    last_end = end

                data_size = file_size - (8 + header_len)
                if last_end != data_size:
                    result.add_issue(
                        "Tensor data does not cover entire file",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )

                # Check metadata
                metadata = header.get("__metadata__", {})
                if isinstance(metadata, dict):
                    for key, value in metadata.items():
                        if isinstance(value, str) and len(value) > 1000:
                            result.add_issue(
                                f"Metadata value for {key} is very long",
                                severity=IssueSeverity.INFO,
                                location=path,
                            )
                        if isinstance(value, str) and any(
                            s in value.lower() for s in ["import ", "#!/", "\\"]
                        ):
                            result.add_issue(
                                f"Suspicious metadata value for {key}",
                                severity=IssueSeverity.INFO,
                                location=path,
                            )

                # Bytes scanned = file size
                result.bytes_scanned = file_size

        except Exception as e:
            result.add_issue(
                f"Error scanning SafeTensors file: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    @staticmethod
    def _expected_size(dtype: Optional[str], shape: list[int]) -> Optional[int]:
        """Return expected tensor byte size from dtype and shape."""
        if dtype not in _DTYPE_SIZES:
            return None
        size = _DTYPE_SIZES[dtype]
        total = 1
        for dim in shape:
            if not isinstance(dim, int) or dim < 0:
                return None
            total *= dim
        return total * size
