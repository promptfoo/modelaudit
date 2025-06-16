import io
import os
import zipfile
from typing import Any, Dict, Optional

import numpy as np

from .base import BaseScanner, IssueSeverity, ScanResult


class NumpyScanner(BaseScanner):
    """Scanner for NumPy .npy and .npz files."""

    name = "numpy"
    description = "Scans NumPy checkpoint files"
    supported_extensions = [".npy", ".npz"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.max_array_size = self.config.get("max_array_size", 1_073_741_824)  # 1GB

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext == ".npy":
            try:
                with open(path, "rb") as f:
                    return f.read(6) == b"\x93NUMPY"
            except Exception:
                return False
        if ext == ".npz":
            return zipfile.is_zipfile(path)
        return False

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)
        self.current_file_path = path
        ext = os.path.splitext(path)[1].lower()

        if ext == ".npy":
            with open(path, "rb") as f:
                magic = f.read(6)
                if magic != b"\x93NUMPY":
                    result.add_issue(
                        "Invalid NumPy magic header",
                        severity=IssueSeverity.ERROR,
                        location=path,
                    )
                    result.finish(success=False)
                    return result
                f.seek(0)
                try:
                    arr = np.load(f, allow_pickle=False)
                except Exception as e:  # pragma: no cover - rare
                    result.add_issue(
                        f"Error loading array: {e}",
                        severity=IssueSeverity.ERROR,
                        location=path,
                        details={"exception": str(e)},
                    )
                    result.finish(success=False)
                    return result
            result.metadata.update({"dtype": str(arr.dtype), "shape": arr.shape})
            result.bytes_scanned = arr.nbytes
            result.finish(success=True)
            return result

        # ext == ".npz"
        try:
            with zipfile.ZipFile(path, "r") as z:
                result.metadata["entries"] = {}
                for info in z.infolist():
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > 100:
                            result.add_issue(
                                f"Suspicious compression ratio ({ratio:.1f}x) in entry: {info.filename}",
                                severity=IssueSeverity.WARNING,
                                location=f"{path}:{info.filename}",
                                details={
                                    "entry": info.filename,
                                    "compressed_size": info.compress_size,
                                    "uncompressed_size": info.file_size,
                                    "ratio": ratio,
                                },
                            )
                    data = z.read(info.filename)
                    if not data.startswith(b"\x93NUMPY"):
                        result.add_issue(
                            f"Invalid NPY entry header: {info.filename}",
                            severity=IssueSeverity.ERROR,
                            location=f"{path}:{info.filename}",
                            details={"entry": info.filename},
                        )
                        continue
                    try:
                        arr = np.load(io.BytesIO(data), allow_pickle=False)
                    except Exception as e:  # pragma: no cover - rare
                        result.add_issue(
                            f"Error loading array {info.filename}: {e}",
                            severity=IssueSeverity.ERROR,
                            location=f"{path}:{info.filename}",
                            details={"exception": str(e)},
                        )
                        continue
                    result.metadata["entries"][info.filename] = {
                        "dtype": str(arr.dtype),
                        "shape": arr.shape,
                        "size": info.file_size,
                    }
                    result.bytes_scanned += arr.nbytes
        except zipfile.BadZipFile:
            result.add_issue(
                "Not a valid zip file",
                severity=IssueSeverity.ERROR,
                location=path,
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result
