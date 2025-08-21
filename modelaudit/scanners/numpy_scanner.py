from __future__ import annotations

import sys
import warnings
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

# Import NumPy with compatibility handling
np: Any
fmt: Any
try:
    import numpy as np

    # Handle NumPy format module imports with version compatibility
    try:
        import numpy.lib.format as fmt

        NUMPY_FORMAT_AVAILABLE = True
    except (ImportError, AttributeError):
        # Fallback for potential import issues
        NUMPY_FORMAT_AVAILABLE = False
        fmt = None

    NUMPY_AVAILABLE = True
    NUMPY_VERSION = getattr(np, "__version__", "unknown")
    NUMPY_MAJOR_VERSION = int(NUMPY_VERSION.split(".")[0]) if NUMPY_VERSION != "unknown" else 1
except ImportError:
    NUMPY_AVAILABLE = False
    NUMPY_FORMAT_AVAILABLE = False
    NUMPY_VERSION = "not available"
    NUMPY_MAJOR_VERSION = 0
    np = None
    fmt = None


class NumPyScanner(BaseScanner):
    """Scanner for NumPy binary files (.npy) with cross-version compatibility."""

    name = "numpy"
    description = f"Scans NumPy .npy files for integrity issues (NumPy {NUMPY_VERSION})"
    supported_extensions: ClassVar[list[str]] = [".npy"]

    def __init__(self, config=None):
        super().__init__(config)
        # Security limits
        self.max_array_bytes = self.config.get(
            "max_array_bytes",
            100 * 1024 * 1024 * 1024,
        )  # 100GB for large numpy arrays
        self.max_dimensions = self.config.get("max_dimensions", 32)
        self.max_dimension_size = self.config.get("max_dimension_size", 100_000_000)
        self.max_itemsize = self.config.get("max_itemsize", 1024)  # 1KB per element

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not NUMPY_AVAILABLE or not NUMPY_FORMAT_AVAILABLE:
            return False
        return super().can_handle(path)

    def _validate_array_dimensions(self, shape: tuple) -> None:
        """Validate array dimensions for security"""
        # Check number of dimensions
        if len(shape) > self.max_dimensions:
            raise ValueError(
                f"Too many dimensions: {len(shape)} (max: {self.max_dimensions})",
            )

        # Check individual dimension sizes
        for i, dim in enumerate(shape):
            if dim < 0:
                raise ValueError(f"Negative dimension at index {i}: {dim}")
            if dim > self.max_dimension_size:
                raise ValueError(
                    f"Dimension {i} too large: {dim} (max: {self.max_dimension_size})",
                )

    def _validate_dtype(self, dtype) -> None:
        """Validate numpy dtype for security"""
        # Check for problematic data types
        dangerous_names = ["object"]
        dangerous_kinds = ["O", "V"]  # Object and Void kinds

        if dtype.name in dangerous_names or dtype.kind in dangerous_kinds:
            raise ValueError(
                f"Dangerous dtype not allowed: {dtype.name} (kind: {dtype.kind})",
            )

        # Check for extremely large item sizes
        if dtype.itemsize > self.max_itemsize:
            raise ValueError(
                f"Itemsize too large: {dtype.itemsize} bytes (max: {self.max_itemsize})",
            )

    def _calculate_safe_array_size(self, shape: tuple, dtype) -> int:
        """Calculate array size with overflow protection"""
        total_elements = 1
        max_elements = sys.maxsize // max(dtype.itemsize, 1)

        for dim in shape:
            # Check for overflow before multiplication
            if total_elements > max_elements // max(dim, 1):
                raise ValueError(
                    f"Array size would overflow: shape={shape}, dtype={dtype}",
                )

            total_elements *= dim

        total_bytes = total_elements * dtype.itemsize

        if total_bytes > self.max_array_bytes:
            raise ValueError(
                f"Array too large: {total_bytes} bytes (max: {self.max_array_bytes}) for shape={shape}, dtype={dtype}",
            )

        return total_bytes

    def scan(self, path: str) -> ScanResult:
        # Check if NumPy and format module are available
        if not NUMPY_AVAILABLE:
            result = self._create_result()
            result.add_check(
                name="NumPy Library Check",
                passed=False,
                message="NumPy not available for scanning .npy files",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"numpy_version": NUMPY_VERSION},
            )
            result.finish(success=False)
            return result

        if not NUMPY_FORMAT_AVAILABLE:
            result = self._create_result()
            result.add_check(
                name="NumPy Format Module Check",
                passed=False,
                message=f"NumPy format module not available (NumPy {NUMPY_VERSION}). May be a compatibility issue.",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"numpy_version": NUMPY_VERSION, "numpy_major": NUMPY_MAJOR_VERSION},
            )
            result.finish(success=False)
            return result

        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        result.metadata["numpy_version"] = NUMPY_VERSION
        result.metadata["numpy_major_version"] = NUMPY_MAJOR_VERSION

        try:
            self.current_file_path = path
            with warnings.catch_warnings():
                # Suppress NumPy warnings during scanning
                warnings.simplefilter("ignore")

                with open(path, "rb") as f:
                    # Verify magic string
                    magic = f.read(6)
                    if magic != b"\x93NUMPY":
                        result.add_check(
                            name="NumPy Magic String Validation",
                            passed=False,
                            message="Invalid NumPy file magic",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"expected": "\x93NUMPY", "found": magic.hex()},
                        )
                        result.finish(success=False)
                        return result
                    else:
                        result.add_check(
                            name="NumPy Magic String Validation",
                            passed=True,
                            message="Valid NumPy file magic string found",
                            location=path,
                            details={"magic": magic.hex()},
                        )
                    f.seek(0)

                    # Use format module with version compatibility
                    try:
                        major, minor = fmt.read_magic(f)
                        if (major, minor) == (1, 0):
                            shape, fortran, dtype = fmt.read_array_header_1_0(f)
                        elif (major, minor) == (2, 0):
                            shape, fortran, dtype = fmt.read_array_header_2_0(f)
                        else:
                            # For newer versions, try the private method with fallback
                            if hasattr(fmt, "_read_array_header"):
                                shape, fortran, dtype = fmt._read_array_header(f, version=(major, minor))
                            else:
                                # Fallback for newer NumPy versions
                                shape, fortran, dtype = fmt.read_array_header_2_0(f)
                    except Exception as header_error:
                        result.add_check(
                            name="NumPy Header Read",
                            passed=False,
                            message=f"Failed to read NumPy array header: {header_error}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"numpy_version": NUMPY_VERSION, "header_error": str(header_error)},
                        )
                        result.finish(success=False)
                        return result

                    data_offset = f.tell()

                    # Validate array dimensions and dtype for security
                    try:
                        self._validate_array_dimensions(shape)
                        result.add_check(
                            name="Array Dimension Validation",
                            passed=True,
                            message="Array dimensions are within safe limits",
                            location=path,
                            details={
                                "shape": shape,
                                "dimensions": len(shape),
                                "max_dimensions": self.max_dimensions,
                            },
                        )

                        self._validate_dtype(dtype)
                        result.add_check(
                            name="Data Type Safety Check",
                            passed=True,
                            message=f"Data type '{dtype}' is safe",
                            location=path,
                            details={
                                "dtype": str(dtype),
                                "dtype_kind": dtype.kind,
                                "itemsize": dtype.itemsize,
                            },
                        )

                        expected_data_size = self._calculate_safe_array_size(shape, dtype)
                        result.add_check(
                            name="Array Size Validation",
                            passed=True,
                            message="Array size is within safe limits",
                            location=path,
                            details={
                                "calculated_size": expected_data_size,
                                "max_size": self.max_array_bytes,
                                "shape": shape,
                                "dtype": str(dtype),
                            },
                        )
                        expected_size = data_offset + expected_data_size
                    except ValueError as e:
                        # Determine which validation failed based on error message
                        if "dimensions" in str(e).lower():
                            check_name = "Array Dimension Validation"
                        elif "dtype" in str(e).lower():
                            check_name = "Data Type Safety Check"
                        else:
                            check_name = "Array Size Validation"

                        result.add_check(
                            name=check_name,
                            passed=False,
                            message=f"Array validation failed: {e}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "security_check": "array_validation",
                                "shape": shape,
                                "dtype": str(dtype),
                                "error": str(e),
                            },
                        )
                        result.finish(success=False)
                        return result

                    if file_size != expected_size:
                        result.add_check(
                            name="File Integrity Check",
                            passed=False,
                            message="File size does not match header information",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "expected_size": expected_size,
                                "actual_size": file_size,
                                "shape": shape,
                                "dtype": str(dtype),
                            },
                        )
                    else:
                        result.add_check(
                            name="File Integrity Check",
                            passed=True,
                            message="File size matches header information",
                            location=path,
                            details={
                                "file_size": file_size,
                                "shape": shape,
                                "dtype": str(dtype),
                            },
                        )

                    result.bytes_scanned = file_size
                    result.metadata.update(
                        {"shape": shape, "dtype": str(dtype), "fortran_order": fortran},
                    )
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_check(
                name="NumPy File Scan",
                passed=False,
                message=f"Error scanning NumPy file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__, "numpy_version": NUMPY_VERSION},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
