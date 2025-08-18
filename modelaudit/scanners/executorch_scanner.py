import io
import os
import tempfile
import zipfile
from typing import Any, ClassVar, Optional

from ..utils import sanitize_archive_path
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner


class ExecuTorchScanner(BaseScanner):
    """Scanner for PyTorch Mobile/ExecuTorch archives (.ptl, .pte)."""

    name = "executorch"
    description = "Scans ExecuTorch mobile model files for suspicious content"
    supported_extensions: ClassVar[list[str]] = [".ptl", ".pte"]

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        super().__init__(config)
        self.pickle_scanner = PickleScanner(config)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        return ext in cls.supported_extensions

    @staticmethod
    def _read_header(path: str, length: int = 4) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read(length)
        except Exception:
            return b""

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

        header = self._read_header(path)
        if not header.startswith(b"PK"):
            result.add_check(
                name="ExecuTorch Archive Format Validation",
                passed=False,
                message=f"Not a valid ExecuTorch archive: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result

        try:
            self.current_file_path = path
            with zipfile.ZipFile(path, "r") as z:
                safe_entries: list[str] = []
                for name in z.namelist():
                    temp_base = os.path.join(tempfile.gettempdir(), "extract")
                    _, is_safe = sanitize_archive_path(name, temp_base)
                    if not is_safe:
                        result.add_check(
                            name="Path Traversal Protection",
                            passed=False,
                            message=f"Archive entry {name} attempted path traversal outside the archive",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"entry": name},
                        )
                        continue
                    safe_entries.append(name)

                pickle_files = [n for n in safe_entries if n.endswith(".pkl")]
                result.metadata["pickle_files"] = pickle_files
                bytes_scanned = 0

                for name in pickle_files:
                    data = z.read(name)
                    bytes_scanned += len(data)
                    with io.BytesIO(data) as file_like:
                        sub_result = self.pickle_scanner._scan_pickle_bytes(file_like, len(data))
                    for issue in sub_result.issues:
                        if issue.details:
                            issue.details["pickle_filename"] = name
                        else:
                            issue.details = {"pickle_filename": name}
                        if not issue.location:
                            issue.location = f"{path}:{name}"
                        elif "pos" in issue.location:
                            issue.location = f"{path}:{name} {issue.location}"
                    result.merge(sub_result)

                for name in safe_entries:
                    if name.endswith(".py"):
                        result.add_check(
                            name="Python File Detection",
                            passed=False,
                            message=f"Python code file found in ExecuTorch model: {name}",
                            severity=IssueSeverity.INFO,
                            location=f"{path}:{name}",
                            details={"file": name},
                        )
                    elif name.endswith((".sh", ".bash", ".cmd", ".exe")):
                        result.add_check(
                            name="Executable File Detection",
                            passed=False,
                            message=f"Executable file found in ExecuTorch model: {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"file": name},
                        )

                result.bytes_scanned = bytes_scanned
        except zipfile.BadZipFile:
            result.add_check(
                name="ZIP File Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_check(
                name="ExecuTorch File Scan",
                passed=False,
                message=f"Error scanning ExecuTorch file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
