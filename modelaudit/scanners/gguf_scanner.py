"""GGUF/GGML scanner that combines comprehensive parsing with security checks."""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Map ggml_type enum to (block_size, type_size) for comprehensive validation
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

# Type sizes for metadata parsing
_TYPE_SIZES = {
    0: 1,  # UINT8
    1: 1,  # INT8
    2: 2,  # UINT16
    3: 2,  # INT16
    4: 4,  # UINT32
    5: 4,  # INT32
    6: 4,  # FLOAT32
    7: 1,  # BOOL
    8: 8,  # STRING
    9: 0,  # ARRAY (variable size)
    10: 8,  # UINT64
    11: 8,  # INT64
    12: 8,  # FLOAT64
}


class GgufScanner(BaseScanner):
    """Scanner for GGUF/GGML model files with comprehensive parsing and security checks."""

    name = "gguf"
    description = (
        "Validates GGUF/GGML model file headers, metadata, and tensor integrity"
    )
    supported_extensions = [".gguf", ".ggml"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.max_uncompressed = self.config.get(
            "max_uncompressed", 2 * 1024 * 1024 * 1024
        )

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
            return magic in (b"GGUF", b"GGML")
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
                if magic == b"GGUF":
                    self._scan_gguf(f, file_size, result)
                elif magic == b"GGML":
                    self._scan_ggml(f, file_size, magic, result)
                else:
                    result.add_issue(
                        f"Unrecognized file format: {magic!r}",
                        IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result
        except Exception as e:
            result.add_issue(
                f"Error scanning GGUF/GGML file: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(
            success=not any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
        )
        return result

    def _read_string(self, f, max_length: int = 1024 * 1024) -> str:
        """Read a string with length checking for security."""
        (length,) = struct.unpack("<Q", f.read(8))
        if length > max_length:
            raise ValueError(f"String length {length} exceeds maximum {max_length}")
        data = f.read(length)
        if len(data) != length:
            raise ValueError("Unexpected end of file while reading string")
        return data.decode("utf-8", "ignore")

    def _scan_gguf(self, f, file_size: int, result: ScanResult) -> None:
        """Comprehensive GGUF file scanning with security checks."""
        # Read header
        version = struct.unpack("<I", f.read(4))[0]
        n_tensors = struct.unpack("<Q", f.read(8))[0]
        n_kv = struct.unpack("<Q", f.read(8))[0]

        result.metadata.update(
            {
                "format": "gguf",
                "version": version,
                "n_tensors": n_tensors,
                "n_kv": n_kv,
            }
        )

        # Security checks on header values
        if n_kv > 1_000_000:
            result.add_issue(
                f"GGUF header appears invalid (declared {n_kv} KV entries)",
                severity=IssueSeverity.CRITICAL,
            )
            return

        if n_tensors > 100_000:
            result.add_issue(
                f"GGUF header appears invalid (declared {n_tensors} tensors)",
                severity=IssueSeverity.CRITICAL,
            )
            return

        if file_size < 24:
            result.add_issue(
                "File too small to contain GGUF metadata",
                severity=IssueSeverity.CRITICAL,
            )
            return

        # Parse metadata with security checks
        metadata: Dict[str, Any] = {}
        try:
            for i in range(min(n_kv, 10000)):  # Limit to prevent DoS
                key = self._read_string(f)

                # Security check for suspicious keys
                if any(x in key for x in ("../", "..\\", "/", "\\")):
                    result.add_issue(
                        f"Suspicious metadata key with path traversal: {key}",
                        severity=IssueSeverity.WARNING,
                    )

                (value_type,) = struct.unpack("<I", f.read(4))
                value = self._read_value(f, value_type)
                metadata[key] = value

                # Security check for suspicious values
                if isinstance(value, str) and any(
                    p in value for p in ("/", "\\", ";", "&&", "|", "`")
                ):
                    result.add_issue(
                        f"Suspicious metadata value for key '{key}': {value}",
                        severity=IssueSeverity.INFO,
                    )

            result.metadata["metadata"] = metadata
        except Exception as e:
            result.add_issue(
                f"GGUF metadata parse error: {e}",
                severity=IssueSeverity.CRITICAL,
            )
            return

        # Validate alignment
        alignment = metadata.get("general.alignment", 32)
        if alignment < 8 or alignment % 8 != 0 or alignment > 1024:
            result.add_issue(
                f"Invalid alignment value: {alignment}",
                IssueSeverity.WARNING,
            )

        # Align to tensor data
        current = f.tell()
        pad = (alignment - (current % alignment)) % alignment
        if pad:
            f.seek(pad, os.SEEK_CUR)

        # Parse tensor information
        tensors = []
        try:
            for i in range(min(n_tensors, 10000)):  # Limit to prevent DoS
                t_name = self._read_string(f)
                (nd,) = struct.unpack("<I", f.read(4))

                if nd > 8:  # Reasonable limit for tensor dimensions
                    result.add_issue(
                        f"Tensor {t_name} has suspicious number of dimensions: {nd}",
                        IssueSeverity.WARNING,
                    )

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
                {"name": t["name"], "type": t["type"], "dims": t["dims"]}
                for t in tensors
            ]
        except Exception as e:
            result.add_issue(
                f"GGUF tensor parse error: {e}",
                severity=IssueSeverity.CRITICAL,
            )
            return

        # Validate tensor sizes and offsets
        for idx, tensor in enumerate(tensors):
            try:
                nelements = 1
                has_invalid_dimension = False
                for d in tensor["dims"]:
                    if d <= 0 or d > 2**31:
                        result.add_issue(
                            f"Tensor {tensor['name']} has invalid dimension: {d}",
                            IssueSeverity.WARNING,
                        )
                        has_invalid_dimension = True
                        break
                    nelements *= d

                # Skip tensor validation if any dimension is invalid
                if has_invalid_dimension:
                    continue

                # Check for extremely large tensors
                uncompressed = nelements * 4
                if uncompressed > self.max_uncompressed:
                    result.add_issue(
                        f"Tensor {tensor['name']} uncompressed size ({uncompressed}) exceeds limit",
                        IssueSeverity.CRITICAL,
                    )

                # Validate tensor type and size
                info = _GGML_TYPE_INFO.get(tensor["type"])
                if info:
                    blck, ts = info
                    if nelements % blck != 0:
                        result.add_issue(
                            f"Tensor {tensor['name']} not aligned to block size {blck}",
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
                            IssueSeverity.CRITICAL,
                            details={"expected": expected, "actual": actual},
                        )
            except (OverflowError, ValueError) as e:
                result.add_issue(
                    f"Error validating tensor {tensor['name']}: {e}",
                    IssueSeverity.WARNING,
                )

        result.bytes_scanned = f.tell()

    def _scan_ggml(self, f, file_size: int, magic: bytes, result: ScanResult) -> None:
        """Basic GGML file validation with security checks."""
        result.metadata["format"] = "ggml"
        result.metadata["magic"] = magic.decode("ascii", "ignore")

        if file_size < 32:
            result.add_issue(
                "File too small to be valid GGML",
                severity=IssueSeverity.CRITICAL,
            )
            return

        # Basic heuristic validation
        try:
            version_bytes = f.read(4)
            if len(version_bytes) < 4:
                result.add_issue(
                    "Truncated GGML header",
                    severity=IssueSeverity.CRITICAL,
                )
                return

            version = struct.unpack("<I", version_bytes)[0]
            result.metadata["version"] = version

            if version > 10000:  # Reasonable upper bound
                result.add_issue(
                    f"Suspicious GGML version: {version}",
                    severity=IssueSeverity.WARNING,
                )
        except Exception as e:
            result.add_issue(
                f"Error parsing GGML header: {e}",
                severity=IssueSeverity.CRITICAL,
            )

        result.bytes_scanned = file_size

    def _read_value(self, f, vtype: int):
        """Read a value of the specified type with security checks."""
        if vtype == 0:  # UINT8
            return struct.unpack("<B", f.read(1))[0]
        elif vtype == 1:  # INT8
            return struct.unpack("<b", f.read(1))[0]
        elif vtype == 2:  # UINT16
            return struct.unpack("<H", f.read(2))[0]
        elif vtype == 3:  # INT16
            return struct.unpack("<h", f.read(2))[0]
        elif vtype == 4:  # UINT32
            return struct.unpack("<I", f.read(4))[0]
        elif vtype == 5:  # INT32
            return struct.unpack("<i", f.read(4))[0]
        elif vtype == 6:  # FLOAT32
            return struct.unpack("<f", f.read(4))[0]
        elif vtype == 7:  # BOOL
            return struct.unpack("<B", f.read(1))[0] != 0
        elif vtype == 8:  # STRING
            return self._read_string(f)
        elif vtype == 9:  # ARRAY
            subtype = struct.unpack("<I", f.read(4))[0]
            (count,) = struct.unpack("<Q", f.read(8))
            if count > 10000:  # Prevent DoS
                raise ValueError(f"Array too large: {count} elements")
            return [self._read_value(f, subtype) for _ in range(count)]
        elif vtype == 10:  # UINT64
            return struct.unpack("<Q", f.read(8))[0]
        elif vtype == 11:  # INT64
            return struct.unpack("<q", f.read(8))[0]
        elif vtype == 12:  # FLOAT64
            return struct.unpack("<d", f.read(8))[0]
        else:
            raise ValueError(f"Unknown metadata type {vtype}")
