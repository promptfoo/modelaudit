import io
import os
import zipfile
from typing import Any, Optional

from ..utils import sanitize_archive_path
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner


class PyTorchZipScanner(BaseScanner):
    """Scanner for PyTorch Zip-based model files (.pt, .pth)"""

    name = "pytorch_zip"
    description = "Scans PyTorch model files for suspicious code in embedded pickles"
    supported_extensions = [".pt", ".pth"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Initialize a pickle scanner for embedded pickles
        self.pickle_scanner = PickleScanner(config)

    @staticmethod
    def _read_header(path: str, length: int = 4) -> bytes:
        """Return the first few bytes of a file."""
        try:
            with open(path, "rb") as f:
                return f.read(length)
        except Exception:
            return b""

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Check file extension
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        return True

    def scan(self, path: str) -> ScanResult:
        """Scan a PyTorch model file for suspicious code"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        header = self._read_header(path)
        if not header.startswith(b"PK"):
            result.add_issue(
                f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            with zipfile.ZipFile(path, "r") as z:
                safe_entries: list[str] = []
                for name in z.namelist():
                    _, is_safe = sanitize_archive_path(name, "/tmp/extract")
                    if not is_safe:
                        result.add_issue(
                            f"Archive entry {name} attempted path traversal outside the archive",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"entry": name},
                        )
                        continue
                    safe_entries.append(name)
                pickle_files = [n for n in safe_entries if n.endswith(".pkl")]
                result.metadata["pickle_files"] = pickle_files

                # Track number of bytes scanned
                bytes_scanned = 0

                # Scan each pickle file
                for name in pickle_files:
                    data = z.read(name)
                    bytes_scanned += len(data)

                    file_like = io.BytesIO(data)
                    # Use the pickle scanner directly
                    sub_result = self.pickle_scanner._scan_pickle_bytes(
                        file_like,
                        len(data),
                    )

                    # Include the pickle filename in each issue
                    for issue in sub_result.issues:
                        if issue.details:
                            issue.details["pickle_filename"] = name
                        else:
                            issue.details = {"pickle_filename": name}

                        # Update location to include the main file path
                        if not issue.location:
                            issue.location = f"{path}:{name}"
                        elif "pos" in issue.location:
                            # If it's a position from the pickle scanner,
                            # prepend the file path
                            issue.location = f"{path}:{name} {issue.location}"

                    # Merge results
                    result.merge(sub_result)

                # Check for other suspicious files
                for name in safe_entries:
                    # Check for Python code files
                    if name.endswith(".py"):
                        result.add_issue(
                            f"Python code file found in PyTorch model: {name}",
                            severity=IssueSeverity.WARNING,
                            location=f"{path}:{name}",
                            details={"file": name},
                        )
                    # Check for shell scripts or other executable files
                    elif name.endswith((".sh", ".bash", ".cmd", ".exe")):
                        result.add_issue(
                            f"Executable file found in PyTorch model: {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"file": name},
                        )

                # Check for missing data.pkl (common in PyTorch models)
                if not pickle_files or "data.pkl" not in [
                    os.path.basename(f) for f in pickle_files
                ]:
                    result.add_issue(
                        "PyTorch model is missing 'data.pkl', which is "
                        "unusual for standard PyTorch models.",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"missing_file": "data.pkl"},
                    )

                # Check for blacklist patterns in all files
                if (
                    hasattr(self, "config")
                    and self.config
                    and "blacklist_patterns" in self.config
                ):
                    blacklist_patterns = self.config["blacklist_patterns"]
                    for name in safe_entries:
                        try:
                            file_data = z.read(name)

                            # For pickled files, check for patterns in the binary data
                            if name.endswith(".pkl"):
                                for pattern in blacklist_patterns:
                                    # Convert pattern to bytes for binary search
                                    pattern_bytes = pattern.encode("utf-8")
                                    if pattern_bytes in file_data:
                                        result.add_issue(
                                            f"Blacklisted pattern '{pattern}' "
                                            f"found in pickled file {name}",
                                            severity=IssueSeverity.WARNING,
                                            location=f"{self.current_file_path} "
                                            f"({name})",
                                            details={
                                                "pattern": pattern,
                                                "file": name,
                                                "file_type": "pickle",
                                            },
                                        )
                            else:
                                # For text files, decode and search as text
                                try:
                                    content = file_data.decode("utf-8")
                                    for pattern in blacklist_patterns:
                                        if pattern in content:
                                            result.add_issue(
                                                f"Blacklisted pattern '{pattern}' "
                                                f"found in file {name}",
                                                severity=IssueSeverity.WARNING,
                                                location=f"{self.current_file_path} "
                                                f"({name})",
                                                details={
                                                    "pattern": pattern,
                                                    "file": name,
                                                    "file_type": "text",
                                                },
                                            )
                                except UnicodeDecodeError:
                                    # Skip blacklist checking for binary files
                                    # that can't be decoded as text
                                    pass
                        except Exception:
                            # Skip files we can't read
                            pass

                result.bytes_scanned = bytes_scanned

        except zipfile.BadZipFile:
            result.add_issue(
                f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_issue(
                f"Error scanning PyTorch zip file: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
