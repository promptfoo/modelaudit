from __future__ import annotations

import numpy.lib.format as fmt

from .base import BaseScanner, IssueSeverity, ScanResult


class NumPyScanner(BaseScanner):
    """Scanner for NumPy binary files (.npy)."""

    name = "numpy"
    description = "Scans NumPy .npy files for integrity issues"
    supported_extensions = [".npy"]

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
                        severity=IssueSeverity.ERROR,
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

                expected_size = dtype.itemsize
                for dim in shape:
                    expected_size *= dim

                if file_size != data_offset + expected_size:
                    result.add_issue(
                        "File size does not match header information",
                        severity=IssueSeverity.ERROR,
                        location=path,
                        details={
                            "expected_size": data_offset + expected_size,
                            "actual_size": file_size,
                            "shape": shape,
                            "dtype": str(dtype),
                        },
                    )

                if any(dim > 1_000_000_000 for dim in shape):
                    result.add_issue(
                        "Declared array shape extremely large",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"shape": shape},
                    )

                result.bytes_scanned = file_size
                result.metadata.update(
                    {"shape": shape, "dtype": str(dtype), "fortran_order": fortran}
                )
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_issue(
                f"Error scanning NumPy file: {e}",
                severity=IssueSeverity.ERROR,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
