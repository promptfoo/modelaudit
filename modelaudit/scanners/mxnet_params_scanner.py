"""
MXNet Parameters Scanner

Security scanner for MXNet model parameter/weight files (binary NDArray format).
Detects vulnerabilities in MXNet parameter files including format spoofing,
oversized tensors, and binary content attacks.

Supported Formats:
- .params files: MXNet parameter files (serialized NDArray format)
- .nd files: MXNet NDArray files
- Binary files with MXNet NDArray structure

Security Focus:
- Insecure deserialization (pickle files disguised as .params)
- Oversized tensor attacks leading to memory exhaustion
- Binary format integrity validation
- Suspicious content in binary data
- Format spoofing and file masquerading attacks
"""

import math
import os
import struct
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult


class MXNetParamsScanner(BaseScanner):
    """Scanner for MXNet parameter/weight binary files."""

    name: ClassVar[str] = "mxnet_params"
    description: ClassVar[str] = "Scans MXNet parameter files for security vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".params", ".nd"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_tensor_elements = self.config.get("max_tensor_elements", 10**8)  # 100M elements
        self.max_total_size = self.config.get("max_total_size", 10 * 1024**3)  # 10GB
        self.max_param_name_length = self.config.get("max_param_name_length", 1000)
        self.max_num_arrays = self.config.get("max_num_arrays", 10000)

        # MXNet NDArray format constants
        self.MXNET_MAGIC = 0x112  # MXNet magic number (if exists)
        self.SUPPORTED_DTYPES = {
            0: ("float32", 4),
            1: ("float64", 8),
            2: ("float16", 2),
            3: ("uint8", 1),
            4: ("int32", 4),
            5: ("int8", 1),
            6: ("int64", 8),
            7: ("int16", 2),
            8: ("uint16", 2),
            9: ("uint32", 4),
            10: ("uint64", 8),
        }

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        if not os.path.isfile(path):
            return False

        # Check file extension
        file_ext = os.path.splitext(path)[1].lower()
        return file_ext in cls.supported_extensions

    def scan(self, path: str) -> ScanResult:
        """Scan MXNet parameter file for security vulnerabilities."""
        # Standard path checks
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path

        # Add file integrity check
        self.add_file_integrity_check(path, result)

        file_size = os.path.getsize(path)

        if file_size == 0:
            result.add_check(
                name="File Size Check",
                passed=False,
                message="MXNet parameter file is empty",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"file_size": 0},
                why="Empty parameter files are invalid and may indicate corruption or attack",
            )
            result.finish(success=False)
            return result

        try:
            # Check if file is actually a pickle (common attack)
            if self._is_pickle_file(path):
                result.add_check(
                    name="Format Validation",
                    passed=False,
                    message="File appears to be a Python pickle with MXNet parameter extension",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"detected_format": "pickle", "claimed_format": "mxnet_params"},
                    why="Pickle masquerading as MXNet params may execute malicious code on load",
                )
                # Don't continue with NDArray parsing if it's a pickle
                result.finish(success=True)
                return result

            # Parse MXNet NDArray format
            self._parse_ndarray_format(path, result)

            # Check for suspicious binary content
            self._check_suspicious_binary_content(path, result)

        except Exception as e:
            result.add_check(
                name="MXNet Params Analysis",
                passed=False,
                message=f"Error analyzing MXNet parameter file: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )

        result.finish(success=True)
        return result

    def _is_pickle_file(self, path: str) -> bool:
        """Check if file is actually a Python pickle file."""
        try:
            with open(path, "rb") as f:
                header = f.read(16)

            # Check for pickle protocol headers
            if len(header) >= 2:
                # Pickle protocol 2-5 headers
                if header.startswith(b"\x80"):
                    return True
                # Pickle protocol 0-1 patterns
                if header[0:1] in [b"c", b"(", b"]", b"}", b"q", b"Q"]:
                    return True
                # Look for common pickle opcodes in first bytes
                pickle_opcodes = {
                    0x63: "GLOBAL",
                    0x71: "BINGET",
                    0x4B: "BININT1",
                    0x58: "BINUNICODE",
                    0x80: "PROTO",
                }
                if header[0] in pickle_opcodes:
                    return True

        except (OSError, IndexError):
            pass
        return False

    def _parse_ndarray_format(self, path: str, result: ScanResult) -> None:
        """Parse MXNet NDArray binary format and validate structure."""
        try:
            with open(path, "rb") as f:
                file_size = os.path.getsize(path)

                # Check file header - MXNet NDArray files typically start with array count
                header = f.read(8)
                if len(header) < 4:
                    result.add_check(
                        name="Binary Format Validation",
                        passed=False,
                        message="File too small to contain valid MXNet NDArray header",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"header_size": len(header)},
                        why="Truncated files may indicate corruption or attack",
                    )
                    return

                # Try to read number of arrays (first 4 bytes, little-endian)
                f.seek(0)
                try:
                    num_arrays_bytes = f.read(4)
                    if len(num_arrays_bytes) != 4:
                        raise ValueError("Cannot read array count")

                    num_arrays = struct.unpack("<I", num_arrays_bytes)[0]
                except (struct.error, ValueError):
                    result.add_check(
                        name="NDArray Header Parsing",
                        passed=False,
                        message="Cannot parse NDArray header - possibly corrupted or not MXNet format",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"header_bytes": header.hex()},
                        why="Invalid header may indicate file corruption or format spoofing",
                    )
                    return

                # Validate array count
                if num_arrays == 0:
                    result.add_check(
                        name="Array Count Validation",
                        passed=False,
                        message="NDArray file claims to contain zero arrays",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"num_arrays": 0},
                        why="Empty parameter files are suspicious and may indicate corruption",
                    )
                    return

                if num_arrays > self.max_num_arrays:
                    result.add_check(
                        name="Array Count Validation",
                        passed=False,
                        message=f"Extremely large number of arrays: {num_arrays} (max: {self.max_num_arrays})",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"num_arrays": num_arrays, "max_arrays": self.max_num_arrays},
                        why="Excessive array count may cause memory exhaustion or indicate malformed file",
                    )

                # Parse array metadata
                self._parse_array_metadata(f, num_arrays, result, path, file_size)

                result.add_check(
                    name="NDArray Format Validation",
                    passed=True,
                    message=f"MXNet NDArray format validated ({num_arrays} arrays)",
                    location=path,
                    details={"num_arrays": num_arrays, "file_size": file_size},
                )

        except Exception as e:
            result.add_check(
                name="Binary Format Analysis",
                passed=False,
                message=f"Error parsing MXNet NDArray format: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )

    def _parse_array_metadata(self, f: Any, num_arrays: int, result: ScanResult, path: str, file_size: int) -> None:
        """Parse individual array metadata and validate."""
        total_elements = 0
        total_data_size = 0
        suspicious_arrays = []

        try:
            for i in range(min(num_arrays, 100)):  # Limit to first 100 arrays for performance
                # Save position
                pos = f.tell()

                try:
                    # Read array name length (4 bytes)
                    name_len_bytes = f.read(4)
                    if len(name_len_bytes) != 4:
                        break
                    name_len = struct.unpack("<I", name_len_bytes)[0]

                    # Validate name length
                    if name_len > self.max_param_name_length:
                        result.add_check(
                            name="Parameter Name Length Check",
                            passed=False,
                            message=f"Extremely long parameter name ({name_len} chars) in array {i}",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={
                                "array_index": i,
                                "name_length": name_len,
                                "max_length": self.max_param_name_length,
                            },
                            why="Excessively long parameter names may indicate malformed or malicious file",
                        )

                    if name_len == 0 or name_len > 10000:  # Sanity check
                        break

                    # Read array name
                    name_bytes = f.read(name_len)
                    if len(name_bytes) != name_len:
                        break
                    param_name = name_bytes.decode("utf-8", errors="ignore")

                    # Read shape info (4 bytes for ndim)
                    ndim_bytes = f.read(4)
                    if len(ndim_bytes) != 4:
                        break
                    ndim = struct.unpack("<I", ndim_bytes)[0]

                    if ndim > 10:  # Reasonable limit for tensor dimensions
                        suspicious_arrays.append(
                            {"index": i, "name": param_name, "issue": f"excessive_dimensions_{ndim}"}
                        )

                    # Read shape dimensions
                    shape = []
                    for _ in range(ndim):
                        dim_bytes = f.read(4)
                        if len(dim_bytes) != 4:
                            break
                        dim = struct.unpack("<I", dim_bytes)[0]

                        # Check for negative or extremely large dimensions
                        if dim > 10**6:  # 1M elements per dimension
                            suspicious_arrays.append(
                                {"index": i, "name": param_name, "issue": f"large_dimension_{dim}"}
                            )
                        shape.append(dim)

                    if len(shape) != ndim:
                        break

                    # Calculate total elements in this array
                    elements = 1
                    for dim in shape:
                        elements *= dim

                    if elements > self.max_tensor_elements:
                        result.add_check(
                            name="Tensor Size Validation",
                            passed=False,
                            message=f"Extremely large tensor '{param_name}' with {elements} elements",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={
                                "array_index": i,
                                "param_name": param_name,
                                "shape": shape,
                                "elements": elements,
                                "max_elements": self.max_tensor_elements,
                            },
                            why="Oversized tensors may cause memory exhaustion attacks",
                        )

                    total_elements += elements

                    # Read data type (4 bytes)
                    dtype_bytes = f.read(4)
                    if len(dtype_bytes) != 4:
                        break
                    dtype_id = struct.unpack("<I", dtype_bytes)[0]

                    # Validate data type
                    if dtype_id not in self.SUPPORTED_DTYPES:
                        suspicious_arrays.append({"index": i, "name": param_name, "issue": f"unknown_dtype_{dtype_id}"})
                        dtype_size = 4  # Default assumption
                    else:
                        dtype_name, dtype_size = self.SUPPORTED_DTYPES[dtype_id]

                    # Calculate expected data size for this array
                    expected_data_size = elements * dtype_size
                    total_data_size += expected_data_size

                    # Skip the actual data
                    f.seek(f.tell() + expected_data_size)

                except (struct.error, UnicodeDecodeError, ValueError) as e:
                    # Restore position and break on parsing error
                    f.seek(pos)
                    result.add_check(
                        name="Array Metadata Parsing",
                        passed=False,
                        message=f"Error parsing array {i} metadata: {e!s}",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"array_index": i, "exception": str(e)},
                        why="Metadata parsing errors may indicate file corruption or format attack",
                    )
                    break

            # Validate total file size vs expected data size
            expected_file_size = f.tell()  # Current position should be near end
            if abs(file_size - expected_file_size) > 1024:  # Allow 1KB tolerance
                result.add_check(
                    name="File Size Consistency Check",
                    passed=False,
                    message=f"File size ({file_size}) doesn't match expected size ({expected_file_size})",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "actual_size": file_size,
                        "expected_size": expected_file_size,
                        "difference": abs(file_size - expected_file_size),
                    },
                    why="Size mismatches may indicate file corruption, truncation, or hidden data",
                )

            # Report suspicious arrays
            if suspicious_arrays:
                result.add_check(
                    name="Suspicious Array Detection",
                    passed=False,
                    message=f"Found {len(suspicious_arrays)} arrays with suspicious characteristics",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "suspicious_arrays": suspicious_arrays[:10],  # Limit output
                        "total_count": len(suspicious_arrays),
                    },
                    why="Suspicious array characteristics may indicate malformed or malicious data",
                )

            # Check total data size
            if total_data_size > self.max_total_size:
                result.add_check(
                    name="Total Data Size Check",
                    passed=False,
                    message=f"Total parameter data size ({total_data_size} bytes) exceeds limit",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"total_data_size": total_data_size, "max_total_size": self.max_total_size},
                    why="Extremely large parameter files may cause memory exhaustion",
                )

        except Exception as e:
            result.add_check(
                name="Array Metadata Analysis",
                passed=False,
                message=f"Error analyzing array metadata: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )

    def _check_suspicious_binary_content(self, path: str, result: ScanResult) -> None:
        """Check for suspicious patterns in binary content."""
        try:
            with open(path, "rb") as f:
                # Read chunks to check for suspicious patterns
                chunk_size = 64 * 1024  # 64KB chunks
                suspicious_patterns = []

                # Patterns that shouldn't appear in legitimate NDArray files
                dangerous_strings = [
                    b"eval(",
                    b"exec(",
                    b"import os",
                    b"subprocess",
                    b"system(",
                    b"__import__",
                    b"/bin/sh",
                    b"/bin/bash",
                    b"rm -rf",
                    b"chmod +x",
                    b"wget http",
                    b"curl http",
                ]

                # Read first few chunks for pattern matching
                for chunk_num in range(min(10, (os.path.getsize(path) // chunk_size) + 1)):
                    f.seek(chunk_num * chunk_size)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Check for dangerous strings
                    for pattern in dangerous_strings:
                        if pattern in chunk:
                            suspicious_patterns.append(
                                {
                                    "pattern": pattern.decode("utf-8", errors="ignore"),
                                    "offset": chunk_num * chunk_size + chunk.find(pattern),
                                }
                            )

                    # Check for high entropy regions (possible encrypted/compressed payload)
                    if len(chunk) > 256:
                        entropy = self._calculate_entropy(chunk[:256])
                        if entropy > 7.5:  # High entropy threshold
                            suspicious_patterns.append(
                                {"pattern": "high_entropy_data", "offset": chunk_num * chunk_size, "entropy": entropy}
                            )

                if suspicious_patterns:
                    result.add_check(
                        name="Suspicious Binary Content Detection",
                        passed=False,
                        message=f"Found {len(suspicious_patterns)} suspicious patterns in binary data",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={
                            "suspicious_patterns": suspicious_patterns[:5],  # Limit output
                            "total_patterns": len(suspicious_patterns),
                        },
                        why="Suspicious patterns in parameter files may indicate embedded malicious content",
                    )

        except Exception as e:
            result.add_check(
                name="Binary Content Analysis",
                passed=False,
                message=f"Error analyzing binary content: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies:
            if freq > 0:
                p = freq / data_len
                entropy -= p * math.log2(p) if p > 0 else 0

        return entropy
