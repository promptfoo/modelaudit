from __future__ import annotations

import sys

import numpy.lib.format as fmt

from .base import BaseScanner, IssueSeverity, ScanResult


class NumPyScanner(BaseScanner):
    """Scanner for NumPy binary files (.npy)."""

    name = "numpy"
    description = "Scans NumPy .npy files for integrity issues"
    supported_extensions = [".npy"]

    def __init__(self, config=None):
        super().__init__(config)
        # Security limits
        self.max_array_bytes = self.config.get(
            "max_array_bytes", 1024 * 1024 * 1024
        )  # 1GB
        self.max_dimensions = self.config.get("max_dimensions", 32)
        self.max_dimension_size = self.config.get("max_dimension_size", 100_000_000)
        self.max_itemsize = self.config.get("max_itemsize", 1024)  # 1KB per element

    def _validate_array_dimensions(self, shape: tuple) -> None:
        """Validate array dimensions for security"""
        # Check number of dimensions
        if len(shape) > self.max_dimensions:
            raise ValueError(
                f"Too many dimensions: {len(shape)} (max: {self.max_dimensions})"
            )

        # Check individual dimension sizes
        for i, dim in enumerate(shape):
            if dim < 0:
                raise ValueError(f"Negative dimension at index {i}: {dim}")
            if dim > self.max_dimension_size:
                raise ValueError(
                    f"Dimension {i} too large: {dim} (max: {self.max_dimension_size})"
                )

    def _validate_dtype(self, dtype) -> None:
        """Validate numpy dtype for security"""
        # Check for problematic data types
        dangerous_names = ["object"]
        dangerous_kinds = ["O", "V"]  # Object and Void kinds

        if dtype.name in dangerous_names or dtype.kind in dangerous_kinds:
            raise ValueError(f"Dangerous dtype not allowed: {dtype.name} (kind: {dtype.kind})")

        # Check for extremely large item sizes
        if dtype.itemsize > self.max_itemsize:
            raise ValueError(
                f"Itemsize too large: {dtype.itemsize} bytes (max: {self.max_itemsize})"
            )

    def _calculate_safe_array_size(self, shape: tuple, dtype) -> int:
        """Calculate array size with overflow protection"""
        total_elements = 1
        max_elements = sys.maxsize // max(dtype.itemsize, 1)

        for dim in shape:
            # Check for overflow before multiplication
            if total_elements > max_elements // max(dim, 1):
                raise ValueError(
                    f"Array size would overflow: shape={shape}, dtype={dtype}"
                )

            total_elements *= dim

        total_bytes = total_elements * dtype.itemsize

        if total_bytes > self.max_array_bytes:
            raise ValueError(
                f"Array too large: {total_bytes} bytes "
                f"(max: {self.max_array_bytes}) for shape={shape}, dtype={dtype}"
            )

        return total_bytes

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                # Verify magic string
                magic = f.read(6)
                if magic != b"\x93NUMPY":
                    result.add_issue(
                        "Invalid NumPy file magic",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result
                f.seek(0)
                major, minor = fmt.read_magic(f)
                if (major, minor) == (1, 0):
                    shape, fortran, dtype = fmt.read_array_header_1_0(f)
                elif (major, minor) == (2, 0):
                    shape, fortran, dtype = fmt.read_array_header_2_0(f)
                else:
                    shape, fortran, dtype = fmt._read_array_header(  # type: ignore[attr-defined]
                        f, version=(major, minor)
                    )
                data_offset = f.tell()

                # Validate array dimensions and dtype for security
                try:
                    self._validate_array_dimensions(shape)
                    self._validate_dtype(dtype)
                    expected_data_size = self._calculate_safe_array_size(shape, dtype)
                    expected_size = data_offset + expected_data_size
                except ValueError as e:
                    result.add_issue(
                        f"Array validation failed: {e}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "security_check": "array_validation",
                            "shape": shape,
                            "dtype": str(dtype),
                        },
                    )
                    result.finish(success=False)
                    return result

                if file_size != expected_size:
                    result.add_issue(
                        "File size does not match header information",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "expected_size": expected_size,
                            "actual_size": file_size,
                            "shape": shape,
                            "dtype": str(dtype),
                        },
                    )

                # Note: Dimension validation is now handled in _validate_array_dimensions
                # which is called earlier and has configurable limits

                result.bytes_scanned = file_size
                result.metadata.update(
                    {"shape": shape, "dtype": str(dtype), "fortran_order": fortran}
                )
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_issue(
                f"Error scanning NumPy file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
