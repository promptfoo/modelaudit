import io
import os
import tempfile
import zipfile
from typing import Any, ClassVar, Optional, cast

from ..utils import sanitize_archive_path
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner


class PyTorchZipScanner(BaseScanner):
    """Scanner for PyTorch Zip-based model files (.pt, .pth)"""

    name = "pytorch_zip"
    description = "Scans PyTorch model files for suspicious code in embedded pickles"
    supported_extensions: ClassVar[list[str]] = [".pt", ".pth", ".bin"]

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

        # For .bin files, only handle if they're ZIP format (torch.save() output)
        if ext == ".bin":
            try:
                from modelaudit.utils.filetype import detect_file_format

                return detect_file_format(path) == "zip"
            except Exception:
                return False

        # For .pt and .pth, always try to handle
        return True

    def scan(self, path: str) -> ScanResult:
        """Scan a PyTorch model file for suspicious code"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        # Handle large files with streaming
        # size_check = self._check_size_limit(path)
        # if size_check:
        #     return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        header = self._read_header(path)
        if not header.startswith(b"PK"):
            result.add_check(
                name="ZIP Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        else:
            result.add_check(
                name="ZIP Format Validation",
                passed=True,
                message="Valid ZIP format detected",
                location=path,
            )

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            with zipfile.ZipFile(path, "r") as z:
                safe_entries: list[str] = []
                path_traversal_found = False
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
                        path_traversal_found = True
                        continue
                    safe_entries.append(name)

                if not path_traversal_found and z.namelist():
                    result.add_check(
                        name="Path Traversal Protection",
                        passed=True,
                        message="All archive entries have safe paths",
                        location=path,
                        details={"entries_checked": len(z.namelist())},
                    )
                # Find pickle files - PyTorch models often use various names
                # Common patterns: data.pkl, archive/data.pkl, *.pkl, or any file with pickle magic bytes
                pickle_files = []
                for name in safe_entries:
                    # Check common pickle file patterns
                    if name.endswith(".pkl") or name == "data.pkl" or name.endswith("/data.pkl"):
                        pickle_files.append(name)

                # If no obvious pickle files found, check all files for pickle magic bytes
                if not pickle_files:
                    for name in safe_entries:
                        try:
                            # Read first few bytes to check for pickle magic
                            data_start = z.read(name)[:4]
                            pickle_magics = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
                            if any(data_start.startswith(m) for m in pickle_magics):
                                pickle_files.append(name)
                        except Exception:
                            pass

                result.metadata["pickle_files"] = pickle_files

                # Track number of bytes scanned
                bytes_scanned = 0

                # Scan each pickle file using streaming to handle large files
                for name in pickle_files:
                    # Get file info without loading it
                    info = z.getinfo(name)
                    file_size = info.file_size

                    # Set the current file path on the pickle scanner for proper error reporting
                    self.pickle_scanner.current_file_path = f"{path}:{name}"

                    # For small pickle files (< 10MB), read normally
                    if file_size < 10 * 1024 * 1024:
                        data = z.read(name)
                        bytes_scanned += len(data)

                        with io.BytesIO(data) as file_like:
                            sub_result = self.pickle_scanner._scan_pickle_bytes(
                                file_like,
                                len(data),
                            )
                    else:
                        # For large pickle files, use streaming extraction
                        with z.open(name, "r") as zf:
                            # Scan the pickle file in a memory-efficient way
                            # The pickle scanner will handle the streaming internally
                            # Type cast to satisfy mypy - z.open returns IO[bytes] which is compatible with BinaryIO
                            sub_result = self.pickle_scanner._scan_pickle_bytes(
                                cast(io.BufferedIOBase, zf),  # type: ignore[arg-type]
                                file_size,
                            )
                        bytes_scanned += file_size

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

                # Check for JIT/Script code execution risks
                # Stream through entries to check for TorchScript patterns without loading all into memory
                jit_patterns_found = False
                for name in safe_entries:
                    if jit_patterns_found:
                        break  # Already found patterns, no need to continue

                    try:
                        info = z.getinfo(name)
                        # Only check first 10MB of each file for JIT patterns
                        check_size = min(info.file_size, 10 * 1024 * 1024)

                        with z.open(name, "r") as zf:
                            chunk = zf.read(check_size)
                            bytes_scanned += len(chunk)

                            # Check this chunk for JIT/Script patterns
                            self.check_for_jit_script_code(
                                chunk,
                                result,
                                model_type="pytorch",
                                context=f"{path}:{name}",
                            )

                            # Check if we found any JIT issues
                            if any("JIT" in issue.message or "TorchScript" in issue.message for issue in result.issues):
                                jit_patterns_found = True

                    except Exception:
                        # Skip files that can't be read
                        pass

                # Network communication check is already done per-file in the loop above

                # Check for other suspicious files
                python_files_found = False
                executable_files_found = False
                for name in safe_entries:
                    # Check for Python code files
                    if name.endswith(".py"):
                        result.add_check(
                            name="Python Code File Detection",
                            passed=False,
                            message=f"Python code file found in PyTorch model: {name}",
                            severity=IssueSeverity.INFO,
                            location=f"{path}:{name}",
                            details={"file": name},
                        )
                        python_files_found = True
                    # Check for shell scripts or other executable files
                    elif name.endswith((".sh", ".bash", ".cmd", ".exe")):
                        result.add_check(
                            name="Executable File Detection",
                            passed=False,
                            message=f"Executable file found in PyTorch model: {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"file": name},
                        )
                        executable_files_found = True

                if not python_files_found and safe_entries:
                    result.add_check(
                        name="Python Code File Detection",
                        passed=True,
                        message="No Python code files found in model",
                        location=path,
                    )

                if not executable_files_found and safe_entries:
                    result.add_check(
                        name="Executable File Detection",
                        passed=True,
                        message="No executable files found in model",
                        location=path,
                    )

                # Check for missing data.pkl (common in PyTorch models)
                if not pickle_files or "data.pkl" not in [os.path.basename(f) for f in pickle_files]:
                    result.add_check(
                        name="PyTorch Structure Validation",
                        passed=False,
                        message="PyTorch model is missing 'data.pkl', which is unusual for standard PyTorch models.",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"missing_file": "data.pkl"},
                    )
                else:
                    result.add_check(
                        name="PyTorch Structure Validation",
                        passed=True,
                        message="PyTorch model has expected structure with data.pkl",
                        location=self.current_file_path,
                        details={"pickle_files": pickle_files},
                    )

                # Check for blacklist patterns in all files
                if hasattr(self, "config") and self.config and "blacklist_patterns" in self.config:
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
                                        result.add_check(
                                            name="Blacklist Pattern Check",
                                            passed=False,
                                            message=f"Blacklisted pattern '{pattern}' found in pickled file {name}",
                                            severity=IssueSeverity.CRITICAL,
                                            location=f"{self.current_file_path} ({name})",
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
                                            result.add_check(
                                                name="Blacklist Pattern Check",
                                                passed=False,
                                                message=f"Blacklisted pattern '{pattern}' found in file {name}",
                                                severity=IssueSeverity.CRITICAL,
                                                location=f"{self.current_file_path} ({name})",
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
                        except Exception as e:
                            result.add_check(
                                name="ZIP Entry Read",
                                passed=False,
                                message=f"Error reading file {name}: {e!s}",
                                severity=IssueSeverity.DEBUG,
                                location=f"{self.current_file_path} ({name})",
                                details={
                                    "zip_entry": name,
                                    "exception": str(e),
                                    "exception_type": type(e).__name__,
                                },
                            )

                result.bytes_scanned = bytes_scanned

        except zipfile.BadZipFile:
            result.add_check(
                name="PyTorch ZIP Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_check(
                name="PyTorch ZIP Scan",
                passed=False,
                message=f"Error scanning PyTorch zip file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
