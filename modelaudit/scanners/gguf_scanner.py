"""GGUF/GGML scanner that combines comprehensive parsing with security checks."""

from __future__ import annotations

import os
import struct
from typing import Any, BinaryIO, ClassVar

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

# Accepted GGML variant magic bytes
GGML_VARIANT_MAGICS = {
    b"GGML",
    b"GGMF",
    b"GGJT",
    b"GGLA",
    b"GGSA",
}


class GgufScanner(BaseScanner):
    """Scanner for GGUF/GGML model files with comprehensive parsing and security checks."""

    name = "gguf"
    description = "Validates GGUF/GGML model file headers, metadata, and tensor integrity"
    # Include common GGML variant extensions as well
    supported_extensions: ClassVar[list[str]] = [
        ".gguf",
        ".ggml",
        ".ggmf",
        ".ggjt",
        ".ggla",
        ".ggsa",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_uncompressed = self.config.get(
            "max_uncompressed",
            100 * 1024 * 1024 * 1024,
        )  # 100GB for large GGUF models

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
            return magic == b"GGUF" or magic in GGML_VARIANT_MAGICS
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == b"GGUF":
                    self._scan_gguf(f, file_size, result)
                elif magic in GGML_VARIANT_MAGICS:
                    self._scan_ggml(f, file_size, magic, result)
                else:
                    result.add_check(
                        name="File Format Recognition",
                        passed=False,
                        message=f"Unrecognized file format: {magic!r}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"magic_bytes": magic.hex()},
                    )
                    result.finish(success=False)
                    return result
        except Exception as e:
            result.add_check(
                name="GGUF/GGML File Scan",
                passed=False,
                message=f"Error scanning GGUF/GGML file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(
            success=not any(i.severity == IssueSeverity.CRITICAL for i in result.issues),
        )
        return result

    def _read_string(self, f: BinaryIO, max_length: int = 1024 * 1024) -> str:
        """Read a string with length checking for security."""
        (length,) = struct.unpack("<Q", f.read(8))
        if length > max_length:
            raise ValueError(f"String length {length} exceeds maximum {max_length}")
        data = f.read(length)
        if len(data) != length:
            raise ValueError("Unexpected end of file while reading string")
        return data.decode("utf-8", "ignore")

    def _scan_gguf(self, f: BinaryIO, file_size: int, result: ScanResult) -> None:
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
            },
        )

        # Security checks on header values
        if n_kv > 1_000_000:
            result.add_check(
                name="GGUF Header KV Count Validation",
                passed=False,
                message=f"GGUF header appears invalid (declared {n_kv} KV entries)",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"kv_count": n_kv, "max_allowed": 1_000_000},
            )
            return

        if n_tensors > 100_000:
            result.add_check(
                name="GGUF Header Tensor Count Validation",
                passed=False,
                message=f"GGUF header appears invalid (declared {n_tensors} tensors)",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"tensor_count": n_tensors, "max_allowed": 100_000},
            )
            return

        if file_size < 24:
            result.add_check(
                name="GGUF File Size Validation",
                passed=False,
                message="File too small to contain GGUF metadata",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"file_size": file_size, "min_required": 24},
            )
            return

        # Parse metadata with security checks
        metadata: dict[str, Any] = {}
        try:
            for _i in range(min(n_kv, 10000)):  # Limit to prevent DoS
                key = self._read_string(f)

                # Security check for suspicious keys
                if any(x in key for x in ("../", "..\\", "/", "\\")):
                    result.add_check(
                        name="Metadata Key Security Check",
                        passed=False,
                        message=f"Suspicious metadata key with path traversal: {key}",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"suspicious_key": key},
                    )

                (value_type,) = struct.unpack("<I", f.read(4))
                value = self._read_value(f, value_type)
                metadata[key] = value

                # Security check for suspicious values
                if isinstance(value, str) and any(p in value for p in ("/", "\\", ";", "&&", "|", "`")):
                    result.add_check(
                        name="Metadata Value Security Check",
                        passed=False,
                        message=f"Suspicious metadata value for key '{key}': {value}",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"key": key, "value": str(value)[:200]},
                    )

            result.metadata["metadata"] = metadata
        except Exception as e:
            result.add_check(
                name="GGUF Metadata Parsing",
                passed=False,
                message=f"GGUF metadata parse error: {e}",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
            )
            return

        # Validate alignment
        alignment = metadata.get("general.alignment", 32)
        if alignment < 8 or alignment % 8 != 0 or alignment > 1024:
            result.add_check(
                name="GGUF Alignment Validation",
                passed=False,
                message=f"Invalid alignment value: {alignment}",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={"alignment": alignment, "valid_range": "8-1024, multiple of 8"},
            )

        # Align to tensor data
        current = f.tell()
        pad = (alignment - (current % alignment)) % alignment
        if pad:
            f.seek(pad, os.SEEK_CUR)

        # Parse tensor information
        tensors = []
        try:
            for _i in range(min(n_tensors, 10000)):  # Limit to prevent DoS
                t_name = self._read_string(f)
                (nd,) = struct.unpack("<I", f.read(4))

                # Hard limit on dimensions to prevent DoS attacks
                if nd > 1000:  # Extremely large dimension count - skip this tensor
                    result.add_check(
                        name="Tensor Dimension Validation",
                        passed=False,
                        message=f"Tensor {t_name} has excessive dimensions ({nd}), skipping for security",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={"tensor_name": t_name, "dimensions": nd, "max_allowed": 1000},
                    )
                    # Skip the rest of this tensor's data to prevent DoS
                    f.seek(nd * 8 + 4 + 8, os.SEEK_CUR)  # Skip dims + type + offset
                    continue

                if nd > 8:  # Reasonable limit for tensor dimensions
                    result.add_check(
                        name="Tensor Dimension Count Check",
                        passed=False,
                        message=f"Tensor {t_name} has suspicious number of dimensions: {nd}",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"tensor_name": t_name, "dimensions": nd, "max_normal": 8},
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
                    },
                )

            result.metadata["tensors"] = [{"name": t["name"], "type": t["type"], "dims": t["dims"]} for t in tensors]
        except Exception as e:
            result.add_check(
                name="GGUF Tensor Parsing",
                passed=False,
                message=f"GGUF tensor parse error: {e}",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
            )
            return

        # Validate tensor sizes and offsets
        for idx, tensor in enumerate(tensors):
            try:
                nelements = 1
                has_invalid_dimension = False
                for d in tensor["dims"]:
                    if d <= 0 or d > 2**31:
                        result.add_check(
                            name="Tensor Dimension Value Validation",
                            passed=False,
                            message=f"Tensor {tensor['name']} has invalid dimension: {d}",
                            severity=IssueSeverity.WARNING,
                            location=self.current_file_path,
                            details={"tensor_name": tensor["name"], "invalid_dimension": d},
                        )
                        has_invalid_dimension = True
                        break
                    nelements *= d

                # Skip tensor validation if any dimension is invalid
                if has_invalid_dimension:
                    continue

                # Check for extremely large tensors using correct size calculation
                # For quantized types, use the actual type information
                info = _GGML_TYPE_INFO.get(tensor["type"])
                if info:
                    # For quantized types, calculate based on block and type size
                    blck, ts = info
                    estimated_size = ((nelements + blck - 1) // blck) * ts
                else:
                    # Fallback for unknown types - assume 4 bytes per element
                    estimated_size = nelements * 4

                if estimated_size > self.max_uncompressed:
                    result.add_check(
                        name="Tensor Size Limit Check",
                        passed=False,
                        message=f"Tensor {tensor['name']} estimated size ({estimated_size}) exceeds limit",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={
                            "tensor_name": tensor["name"],
                            "estimated_size": estimated_size,
                            "limit": self.max_uncompressed,
                        },
                    )

                # Validate tensor type and size
                info = _GGML_TYPE_INFO.get(tensor["type"])
                if info:
                    blck, ts = info
                    if nelements % blck != 0:
                        result.add_check(
                            name="Tensor Block Alignment Check",
                            passed=False,
                            message=f"Tensor {tensor['name']} not aligned to block size {blck}",
                            severity=IssueSeverity.WARNING,
                            location=self.current_file_path,
                            details={"tensor_name": tensor["name"], "block_size": blck, "elements": nelements},
                        )

                    expected = ((nelements + blck - 1) // blck) * ts
                    next_offset = tensors[idx + 1]["offset"] if idx + 1 < len(tensors) else file_size
                    actual = next_offset - tensor["offset"]

                    if expected != actual:
                        result.add_check(
                            name="Tensor Size Consistency Check",
                            passed=False,
                            message=f"Size mismatch for tensor {tensor['name']}",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={"tensor_name": tensor["name"], "expected": expected, "actual": actual},
                        )
            except (OverflowError, ValueError) as e:
                result.add_check(
                    name="Tensor Validation Error",
                    passed=False,
                    message=f"Error validating tensor {tensor['name']}: {e}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"tensor_name": tensor["name"], "error": str(e)},
                )

        result.bytes_scanned = f.tell()

    def _scan_ggml(
        self,
        f: BinaryIO,
        file_size: int,
        magic: bytes,
        result: ScanResult,
    ) -> None:
        """Basic GGML file validation with security checks."""
        result.metadata["format"] = "ggml"
        result.metadata["magic"] = magic.decode("ascii", "ignore")

        if file_size < 32:
            result.add_check(
                name="GGML File Size Validation",
                passed=False,
                message="File too small to be valid GGML",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"file_size": file_size, "min_required": 32},
            )
            return

        # Basic heuristic validation
        try:
            version_bytes = f.read(4)
            if len(version_bytes) < 4:
                result.add_check(
                    name="GGML Header Integrity Check",
                    passed=False,
                    message="Truncated GGML header",
                    severity=IssueSeverity.CRITICAL,
                    location=self.current_file_path,
                    details={"header_bytes_read": len(version_bytes), "expected": 4},
                )
                return

            version = struct.unpack("<I", version_bytes)[0]
            result.metadata["version"] = version

            if version > 10000:  # Reasonable upper bound
                result.add_check(
                    name="GGML Version Check",
                    passed=False,
                    message=f"Suspicious GGML version: {version}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"version": version, "max_expected": 10000},
                )
        except Exception as e:
            result.add_check(
                name="GGML Header Parsing",
                passed=False,
                message=f"Error parsing GGML header: {e}",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
            )

        result.bytes_scanned = file_size

    def _read_value(self, f: BinaryIO, vtype: int) -> Any:
        """Read a value of the specified type with security checks."""
        if vtype == 0:  # UINT8
            return struct.unpack("<B", f.read(1))[0]
        if vtype == 1:  # INT8
            return struct.unpack("<b", f.read(1))[0]
        if vtype == 2:  # UINT16
            return struct.unpack("<H", f.read(2))[0]
        if vtype == 3:  # INT16
            return struct.unpack("<h", f.read(2))[0]
        if vtype == 4:  # UINT32
            return struct.unpack("<I", f.read(4))[0]
        if vtype == 5:  # INT32
            return struct.unpack("<i", f.read(4))[0]
        if vtype == 6:  # FLOAT32
            return struct.unpack("<f", f.read(4))[0]
        if vtype == 7:  # BOOL
            return struct.unpack("<B", f.read(1))[0] != 0
        if vtype == 8:  # STRING
            return self._read_string(f)
        if vtype == 9:  # ARRAY
            subtype = struct.unpack("<I", f.read(4))[0]
            (count,) = struct.unpack("<Q", f.read(8))
            if count > 10000:  # Prevent DoS
                raise ValueError(f"Array too large: {count} elements")
            return [self._read_value(f, subtype) for _ in range(count)]
        if vtype == 10:  # UINT64
            return struct.unpack("<Q", f.read(8))[0]
        if vtype == 11:  # INT64
            return struct.unpack("<q", f.read(8))[0]
        if vtype == 12:  # FLOAT64
            return struct.unpack("<d", f.read(8))[0]

        raise ValueError(f"Unknown metadata type {vtype}")
