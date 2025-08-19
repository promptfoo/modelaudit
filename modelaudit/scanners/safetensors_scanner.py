"""SafeTensors model scanner."""

from __future__ import annotations

import json
import os
import re
import struct
from typing import ClassVar

from modelaudit.suspicious_symbols import SUSPICIOUS_METADATA_PATTERNS

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
    supported_extensions: ClassVar[list[str]] = [".safetensors"]

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
                header_len_bytes = f.read(8)
                if len(header_len_bytes) != 8:
                    result.add_check(
                        name="SafeTensors Header Size Check",
                        passed=False,
                        message="File too small to contain SafeTensors header length",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"bytes_read": len(header_len_bytes), "required": 8},
                    )
                    result.finish(success=False)
                    return result

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                if header_len <= 0 or header_len > file_size - 8:
                    result.add_check(
                        name="Header Length Validation",
                        passed=False,
                        message="Invalid SafeTensors header length",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"header_len": header_len, "max_allowed": file_size - 8},
                    )
                    result.finish(success=False)
                    return result
                else:
                    result.add_check(
                        name="Header Length Validation",
                        passed=True,
                        message="SafeTensors header length is valid",
                        location=path,
                        details={"header_len": header_len},
                    )

                header_bytes = f.read(header_len)
                if len(header_bytes) != header_len:
                    result.add_check(
                        name="SafeTensors Header Read",
                        passed=False,
                        message="Failed to read SafeTensors header",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"bytes_read": len(header_bytes), "expected": header_len},
                    )
                    result.finish(success=False)
                    return result

                if not header_bytes.strip().startswith(b"{"):
                    result.add_check(
                        name="Header Format Validation",
                        passed=False,
                        message="SafeTensors header does not start with '{'",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result
                else:
                    result.add_check(
                        name="Header Format Validation",
                        passed=True,
                        message="SafeTensors header format is valid JSON",
                        location=path,
                    )

                try:
                    header = json.loads(header_bytes.decode("utf-8"))
                except (json.JSONDecodeError, RecursionError) as e:
                    is_recursion = isinstance(e, RecursionError)
                    message = (
                        "SafeTensors header too deeply nested or invalid JSON"
                        if is_recursion
                        else f"Invalid JSON header: {e!s}"
                    )
                    why = (
                        "SafeTensors header JSON exceeded parser recursion limits, "
                        "indicating a malformed or malicious file."
                        if is_recursion
                        else "SafeTensors header contained invalid JSON."
                    )
                    result.add_check(
                        name="SafeTensors JSON Parse",
                        passed=False,
                        message=message,
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"exception": str(e), "exception_type": type(e).__name__},
                        why=why,
                    )
                    result.finish(success=False)
                    return result

                tensor_names = [k for k in header if k != "__metadata__"]
                result.metadata["tensor_count"] = len(tensor_names)
                # Limit tensor names to prevent memory issues with very large models
                max_tensor_names = 1000
                if len(tensor_names) > max_tensor_names:
                    result.metadata["tensors"] = tensor_names[:max_tensor_names]
                    result.metadata["tensors_truncated"] = len(tensor_names) - max_tensor_names
                else:
                    result.metadata["tensors"] = tensor_names

                # Validate ALL tensor offsets and sizes (comprehensive but memory-efficient)
                tensor_entries = [(k, v) for k, v in header.items() if k != "__metadata__"]
                data_size = file_size - (8 + header_len)
                offsets = []

                # Stream-process all tensors for memory efficiency
                invalid_entries = []
                invalid_offsets = []
                invalid_sizes = []
                valid_tensor_count = 0
                total_tensor_count = len(tensor_entries)

                # Process tensors in chunks to avoid memory issues while validating ALL of them
                chunk_size = 1000
                for i in range(0, len(tensor_entries), chunk_size):
                    chunk = tensor_entries[i : i + chunk_size]

                    for name, info in chunk:
                        if not isinstance(info, dict):
                            invalid_entries.append(name)
                            continue

                        begin, end = info.get("data_offsets", [0, 0])
                        dtype = info.get("dtype")
                        shape = info.get("shape", [])

                        if not isinstance(begin, int) or not isinstance(end, int):
                            invalid_entries.append(f"{name} (invalid offset types)")
                            continue

                        if begin < 0 or end <= begin or end > data_size:
                            invalid_offsets.append(f"{name} [{begin}:{end}]")
                            continue

                        offsets.append((begin, end))

                        # Validate dtype/shape size for EVERY tensor
                        expected_size = self._expected_size(dtype, shape)
                        if expected_size is not None and expected_size != end - begin:
                            invalid_sizes.append(f"{name} (expected: {expected_size}, actual: {end - begin})")
                        else:
                            valid_tensor_count += 1

                    # Trim lists if they get too large to prevent memory issues (keep first occurrences for debugging)
                    if len(invalid_entries) > 100:
                        invalid_entries = [*invalid_entries[:50], f"... and {len(invalid_entries) - 50} more"]
                    if len(invalid_offsets) > 100:
                        invalid_offsets = [*invalid_offsets[:50], f"... and {len(invalid_offsets) - 50} more"]
                    if len(invalid_sizes) > 100:
                        invalid_sizes = [*invalid_sizes[:50], f"... and {len(invalid_sizes) - 50} more"]

                # Report comprehensive validation results (ALL tensors processed)
                if invalid_entries:
                    result.add_check(
                        name="Tensor Entry Type Validation",
                        passed=False,
                        message=f"Found invalid tensor entries in {len(invalid_entries)} tensors",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"invalid_tensors": invalid_entries[:20], "total_processed": total_tensor_count},
                    )

                if invalid_offsets:
                    result.add_check(
                        name="Tensor Offset Validation",
                        passed=False,
                        message=f"Found invalid offsets in {len(invalid_offsets)} tensors",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"invalid_offsets": invalid_offsets[:20], "total_processed": total_tensor_count},
                    )

                if invalid_sizes:
                    result.add_check(
                        name="Tensor Size Consistency Check",
                        passed=False,
                        message=f"Found size mismatches in {len(invalid_sizes)} tensors",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"size_mismatches": invalid_sizes[:20], "total_processed": total_tensor_count},
                    )

                # Report successful comprehensive validation
                if not invalid_entries and not invalid_offsets and not invalid_sizes and valid_tensor_count > 0:
                    result.add_check(
                        name="Comprehensive Tensor Validation",
                        passed=True,
                        message=f"Successfully validated ALL {valid_tensor_count} tensors",
                        location=path,
                        details={
                            "valid_tensors": valid_tensor_count,
                            "total_tensors": total_tensor_count,
                            "comprehensive_scan": True,
                            "all_tensors_checked": True,
                        },
                    )

                # Check offset continuity
                offsets.sort(key=lambda x: x[0])
                last_end = 0
                has_gap_or_overlap = False
                for begin, end in offsets:
                    if begin != last_end:
                        has_gap_or_overlap = True
                        result.add_check(
                            name="Offset Continuity Check",
                            passed=False,
                            message="Tensor data offsets have gaps or overlap",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"gap_at": begin, "expected": last_end},
                        )
                        break
                    last_end = end

                if not has_gap_or_overlap and offsets:
                    result.add_check(
                        name="Offset Continuity Check",
                        passed=True,
                        message="Tensor offsets are continuous without gaps",
                        location=path,
                        details={"total_offsets": len(offsets)},
                    )

                data_size = file_size - (8 + header_len)
                if last_end != data_size:
                    result.add_check(
                        name="Tensor Data Coverage Check",
                        passed=False,
                        message="Tensor data does not cover entire file",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"last_offset": last_end, "data_size": data_size},
                    )

                # Check metadata
                metadata = header.get("__metadata__", {})
                if isinstance(metadata, dict):
                    for key, value in metadata.items():
                        if isinstance(value, str) and len(value) > 1000:
                            result.add_check(
                                name="Metadata Length Check",
                                passed=False,
                                message=f"Metadata value for {key} is very long",
                                severity=IssueSeverity.INFO,
                                location=path,
                                details={"key": key, "length": len(value), "threshold": 1000},
                                why=(
                                    "Metadata fields over 1000 characters are unusual in model files. Long strings "
                                    "in metadata could contain encoded payloads, scripts, or data exfiltration "
                                    "attempts."
                                ),
                            )

                        if isinstance(value, str):
                            lower_val = value.lower()

                            # Check for simple code-like patterns
                            if any(s in lower_val for s in ["import ", "#!/", "\\"]):
                                result.add_check(
                                    name="Metadata Code Pattern Check",
                                    passed=False,
                                    message=f"Suspicious metadata value for {key}",
                                    severity=IssueSeverity.INFO,
                                    location=path,
                                    details={"key": key, "pattern": "code-like"},
                                    why=(
                                        "Metadata containing code-like patterns (import statements, shebangs, escape "
                                        "sequences) is atypical for model files and may indicate embedded scripts or "
                                        "injection attempts."
                                    ),
                                )

                            # Check for regex-based suspicious patterns (independent of above check)
                            for pattern in SUSPICIOUS_METADATA_PATTERNS:
                                if re.search(pattern, value):
                                    result.add_check(
                                        name="Metadata Pattern Check",
                                        passed=False,
                                        message=f"Suspicious metadata value for {key}",
                                        severity=IssueSeverity.INFO,
                                        location=path,
                                        details={"key": key, "pattern": pattern},
                                        why="Metadata matched known suspicious pattern",
                                    )
                                    break

                # Bytes scanned = file size
                result.bytes_scanned = file_size

        except Exception as e:
            result.add_check(
                name="SafeTensors File Scan",
                passed=False,
                message=f"Error scanning SafeTensors file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    @staticmethod
    def _expected_size(dtype: str | None, shape: list[int]) -> int | None:
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
