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

                # Extract PyTorch version information for CVE-2025-32434 detection
                pytorch_version_info = self._extract_pytorch_version_info(z, safe_entries)
                result.metadata.update(pytorch_version_info)

                # Check for CVE-2025-32434 vulnerability based on version
                self._check_cve_2025_32434_vulnerability(pytorch_version_info, result, path)

                # Track number of bytes scanned
                bytes_scanned = 0

                # Scan each pickle file using streaming to handle large files
                for name in pickle_files:
                    # Get file info without loading it
                    info = z.getinfo(name)
                    file_size = info.file_size

                    # Set the current file path on the pickle scanner for proper error reporting
                    self.pickle_scanner.current_file_path = f"{path}:{name}"

                    # For small pickle files (< 10GB), read normally
                    if file_size < 10 * 1024 * 1024 * 1024:
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

                    # Add CVE-2025-32434 specific warnings for PyTorch models with dangerous opcodes
                    self._add_weights_only_safety_warnings(sub_result, result, path, name)

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
                        # Only check first 100GB of each file for JIT patterns
                        check_size = min(info.file_size, 100 * 1024 * 1024 * 1024)

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
                blacklist_patterns = None
                if (
                    hasattr(self, "config")
                    and self.config
                    and "blacklist_patterns" in self.config
                    and self.config["blacklist_patterns"] is not None
                ):
                    blacklist_patterns = self.config["blacklist_patterns"]

                if blacklist_patterns:
                    # Configure size limits for blacklist scanning to prevent memory issues
                    max_blacklist_scan_size = self.config.get(
                        "max_blacklist_scan_size",
                        100 * 1024 * 1024,  # 100MB default
                    )

                    for name in safe_entries:
                        try:
                            # Check file size before attempting to read
                            info = z.getinfo(name)
                            if info.file_size > max_blacklist_scan_size:
                                result.add_check(
                                    name="Blacklist Pattern Check",
                                    passed=True,
                                    message=(
                                        f"File {name} too large for blacklist scanning "
                                        f"(size: {info.file_size}, limit: {max_blacklist_scan_size})"
                                    ),
                                    severity=IssueSeverity.INFO,
                                    location=f"{self.current_file_path} ({name})",
                                    details={
                                        "file_size": info.file_size,
                                        "scan_limit": max_blacklist_scan_size,
                                        "zip_entry": name,
                                        "reason": "size_limit_exceeded",
                                    },
                                )
                                continue

                            # Use streaming read for large files to avoid memory issues
                            if info.file_size > 10 * 1024 * 1024:  # 10MB threshold for streaming
                                # Stream the file and check patterns in chunks
                                found_patterns = []
                                with z.open(name, "r") as zf:
                                    chunk_size = 1024 * 1024  # 1MB chunks
                                    overlap_buffer = b""
                                    max_pattern_len = (
                                        max(len(p.encode("utf-8")) for p in blacklist_patterns)
                                        if blacklist_patterns
                                        else 0
                                    )

                                    while True:
                                        chunk = zf.read(chunk_size)
                                        if not chunk:
                                            break

                                        # Combine with overlap buffer to catch patterns across chunk boundaries
                                        search_data = overlap_buffer + chunk

                                        # Check for patterns in this chunk
                                        if name.endswith(".pkl"):
                                            # Binary search for pickled files
                                            for pattern in blacklist_patterns:
                                                pattern_bytes = pattern.encode("utf-8")
                                                if pattern_bytes in search_data and pattern not in found_patterns:
                                                    found_patterns.append(pattern)
                                        else:
                                            # Text search for other files
                                            try:
                                                text_data = search_data.decode("utf-8", errors="ignore")
                                                for pattern in blacklist_patterns:
                                                    if pattern in text_data and pattern not in found_patterns:
                                                        found_patterns.append(pattern)
                                            except UnicodeDecodeError:
                                                # Fall back to binary search if text decode fails
                                                for pattern in blacklist_patterns:
                                                    pattern_bytes = pattern.encode("utf-8")
                                                    if pattern_bytes in search_data and pattern not in found_patterns:
                                                        found_patterns.append(pattern)

                                        # Keep overlap buffer for pattern matching across chunks
                                        overlap_buffer = (
                                            search_data[-max_pattern_len:]
                                            if len(search_data) >= max_pattern_len
                                            else search_data
                                        )

                                # Report found patterns
                                for pattern in found_patterns:
                                    result.add_check(
                                        name="Blacklist Pattern Check",
                                        passed=False,
                                        message=f"Blacklisted pattern '{pattern}' found in file {name}",
                                        severity=IssueSeverity.CRITICAL,
                                        location=f"{self.current_file_path} ({name})",
                                        details={
                                            "pattern": pattern,
                                            "file": name,
                                            "file_type": "pickle" if name.endswith(".pkl") else "text",
                                            "scan_method": "streaming",
                                        },
                                    )
                            else:
                                # Small file - read normally
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
                                                    "scan_method": "direct",
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
                                                        "scan_method": "direct",
                                                    },
                                                )
                                    except UnicodeDecodeError:
                                        # Fall back to binary search for files that can't be decoded as text
                                        for pattern in blacklist_patterns:
                                            pattern_bytes = pattern.encode("utf-8")
                                            if pattern_bytes in file_data:
                                                result.add_check(
                                                    name="Blacklist Pattern Check",
                                                    passed=False,
                                                    message=(
                                                        f"Blacklisted pattern '{pattern}' found in binary file {name}"
                                                    ),
                                                    severity=IssueSeverity.CRITICAL,
                                                    location=f"{self.current_file_path} ({name})",
                                                    details={
                                                        "pattern": pattern,
                                                        "file": name,
                                                        "file_type": "binary",
                                                        "scan_method": "direct",
                                                    },
                                                )
                        except zipfile.BadZipFile as e:
                            result.add_check(
                                name="ZIP Entry Read",
                                passed=False,
                                message=f"Bad ZIP file structure reading {name}: {e!s}",
                                severity=IssueSeverity.WARNING,
                                location=f"{self.current_file_path} ({name})",
                                details={
                                    "zip_entry": name,
                                    "exception": str(e),
                                    "exception_type": "BadZipFile",
                                    "scan_phase": "blacklist_check",
                                },
                            )
                        except MemoryError as e:
                            result.add_check(
                                name="ZIP Entry Read",
                                passed=False,
                                message=f"Memory limit exceeded reading {name}: {e!s}",
                                severity=IssueSeverity.WARNING,
                                location=f"{self.current_file_path} ({name})",
                                details={
                                    "zip_entry": name,
                                    "exception": str(e),
                                    "exception_type": "MemoryError",
                                    "scan_phase": "blacklist_check",
                                },
                            )
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
                                    "scan_phase": "blacklist_check",
                                },
                            )
                else:
                    # No blacklist patterns configured - add a pass check to indicate this was intentionally skipped
                    if safe_entries:  # Only add this check if there are entries to potentially scan
                        result.add_check(
                            name="Blacklist Pattern Check",
                            passed=True,
                            message="No blacklist patterns configured for scanning",
                            severity=IssueSeverity.INFO,
                            location=self.current_file_path,
                            details={"reason": "no_blacklist_configured", "entries_available": len(safe_entries)},
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

    def _extract_pytorch_version_info(self, zipfile_obj, safe_entries: list[str]) -> dict[str, Any]:
        """Extract PyTorch version information from model archive for CVE-2025-32434 detection"""
        version_info: dict[str, Any] = {
            "pytorch_archive_version": None,
            "pytorch_framework_version": None,
            "pytorch_version_source": None,
        }

        try:
            # Check for PyTorch archive version file
            if "version" in safe_entries:
                version_data = zipfile_obj.read("version").decode("utf-8", errors="ignore").strip()
                version_info["pytorch_archive_version"] = version_data
                version_info["pytorch_version_source"] = "archive/version"
            elif "archive/version" in safe_entries:
                version_data = zipfile_obj.read("archive/version").decode("utf-8", errors="ignore").strip()
                version_info["pytorch_archive_version"] = version_data
                version_info["pytorch_version_source"] = "archive/version"

            # Try to extract PyTorch framework version from pickle files
            # Look for torch.__version__ references in pickle GLOBAL opcodes
            for name in safe_entries:
                if name.endswith(".pkl"):
                    try:
                        pickle_data = zipfile_obj.read(name)
                        # Look for torch version patterns in pickle data
                        framework_version = self._extract_framework_version_from_pickle(pickle_data)
                        if framework_version:
                            version_info["pytorch_framework_version"] = framework_version
                            version_info["pytorch_version_source"] = f"pickle:{name}"
                            break
                    except Exception:
                        continue

            # Look for version information in other metadata files
            metadata_files = ["meta.json", "config.json", "pytorch_model.bin.index.json"]
            for meta_file in metadata_files:
                if meta_file in safe_entries:
                    try:
                        import json

                        meta_data = json.loads(zipfile_obj.read(meta_file).decode("utf-8"))
                        # Look for version fields in metadata
                        for key in ["pytorch_version", "torch_version", "framework_version", "version"]:
                            if key in meta_data and isinstance(meta_data[key], str):
                                version_info["pytorch_framework_version"] = meta_data[key]
                                version_info["pytorch_version_source"] = f"metadata:{meta_file}"
                                break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue

        except Exception:
            # Log but don't fail - version detection is best effort
            pass

        return version_info

    def _extract_framework_version_from_pickle(self, pickle_data: bytes) -> Optional[str]:
        """Extract PyTorch framework version from pickle data by examining opcodes"""
        try:
            import io
            import pickletools

            # Use pickletools to examine opcodes without executing the pickle
            opcodes = []
            with io.BytesIO(pickle_data) as f:
                for opcode, arg, pos in pickletools.genops(f):
                    opcodes.append((opcode, arg, pos))

            # Look for GLOBAL opcodes that reference torch.__version__
            for i, (opcode, arg, _pos) in enumerate(opcodes):
                if opcode.name == "GLOBAL" and arg and "torch" in arg and ("version" in arg or "__version__" in arg):
                    # Found a reference to torch version - try to get the value
                    # Look for subsequent opcodes that might contain the version string
                    for j in range(i + 1, min(i + 10, len(opcodes))):
                        next_opcode, next_arg, next_pos = opcodes[j]
                        if (
                            next_opcode.name in ["UNICODE", "STRING", "SHORT_BINSTRING", "BINUNICODE"]
                            and next_arg
                            and isinstance(next_arg, str)
                            and self._looks_like_version(next_arg)
                        ):
                            return next_arg

            # Look for any version-like strings in the pickle
            for opcode, arg, _pos in opcodes:
                if (
                    opcode.name in ["UNICODE", "STRING", "SHORT_BINSTRING", "BINUNICODE"]
                    and arg
                    and isinstance(arg, str)
                    and self._looks_like_pytorch_version(arg)
                ):
                    return arg

        except Exception:
            pass

        return None

    def _looks_like_version(self, text: str) -> bool:
        """Check if a string looks like a version number"""
        import re

        # Match patterns like 2.5.1, 1.13.0+cu117, 2.0.0.dev20230101
        version_pattern = r"^\d+\.\d+\.\d+(?:\+\w+)?(?:\.dev\d+)?$"
        return bool(re.match(version_pattern, text.strip()))

    def _looks_like_pytorch_version(self, text: str) -> bool:
        """Check if a string looks specifically like a PyTorch version"""
        if not self._looks_like_version(text):
            return False
        # PyTorch versions typically start with 1.x or 2.x
        return text.strip().startswith(("1.", "2."))

    def _check_cve_2025_32434_vulnerability(self, version_info: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2025-32434 vulnerability based on PyTorch version"""

        # Get the framework version to check
        framework_version = version_info.get("pytorch_framework_version")
        version_source = version_info.get("pytorch_version_source", "unknown")

        if framework_version:
            # Check if this is a vulnerable PyTorch version (≤2.5.1)
            is_vulnerable = self._is_vulnerable_pytorch_version(framework_version)

            if is_vulnerable:
                result.add_check(
                    name="CVE-2025-32434 PyTorch Version Check",
                    passed=False,
                    message=(
                        f"Model uses vulnerable PyTorch version {framework_version} susceptible to CVE-2025-32434 RCE"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "cve_id": "CVE-2025-32434",
                        "pytorch_version": framework_version,
                        "version_source": version_source,
                        "vulnerability_description": "RCE when loading models with torch.load(weights_only=True)",
                        "fixed_in": "PyTorch 2.6.0",
                        "recommendation": (
                            "Update to PyTorch 2.6.0 or later, "
                            "avoid torch.load(weights_only=True) with untrusted models"
                        ),
                    },
                )
            else:
                result.add_check(
                    name="CVE-2025-32434 PyTorch Version Check",
                    passed=True,
                    message=f"Model uses PyTorch version {framework_version} which is not affected by CVE-2025-32434",
                    location=path,
                    details={
                        "pytorch_version": framework_version,
                        "version_source": version_source,
                        "cve_status": "not_vulnerable",
                    },
                )
        else:
            # No version detected - add informational check
            result.add_check(
                name="CVE-2025-32434 PyTorch Version Check",
                passed=True,  # Pass by default if we can't determine version
                message="Could not determine PyTorch version from model file",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "cve_id": "CVE-2025-32434",
                    "version_detection": "failed",
                    "recommendation": (
                        "Verify PyTorch version manually - "
                        "avoid torch.load(weights_only=True) with untrusted models if using PyTorch ≤2.5.1"
                    ),
                },
            )

    def _is_vulnerable_pytorch_version(self, version: str) -> bool:
        """Check if a PyTorch version is vulnerable to CVE-2025-32434 (≤2.5.1)"""
        try:
            import re

            # Parse version string
            version_match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version.strip())
            if not version_match:
                # If we can't parse it, assume vulnerable for safety
                return True

            major, minor, patch = map(int, version_match.groups())

            # CVE-2025-32434 affects PyTorch ≤2.5.1
            if major < 2:
                return True  # All 1.x versions are vulnerable
            elif major == 2:
                if minor < 5:
                    return True  # 2.0.x through 2.4.x are vulnerable
                elif minor == 5:
                    return patch <= 1  # 2.5.0 and 2.5.1 are vulnerable
                else:
                    return False  # 2.6.0+ are fixed
            else:
                return False  # 3.x+ would not be vulnerable (future versions)

        except Exception:
            # If version parsing fails, assume vulnerable for safety
            return True

    def _add_weights_only_safety_warnings(
        self, pickle_result: ScanResult, pytorch_result: ScanResult, model_path: str, pickle_name: str
    ) -> None:
        """Add CVE-2025-32434 specific warnings when dangerous opcodes detected in PyTorch models"""

        # Check if the pickle scan found any dangerous opcodes that would make weights_only=True unsafe
        dangerous_opcodes_found = []
        code_execution_risks = []

        # Analyze the pickle scan results for dangerous patterns
        for issue in pickle_result.issues:
            issue_msg = issue.message.lower()
            issue_details = issue.details or {}

            # Look for specific dangerous opcodes
            if "reduce" in issue_msg or "REDUCE" in str(issue_details):
                dangerous_opcodes_found.append("REDUCE")
                code_execution_risks.append("__reduce__ method exploitation")
            if "inst" in issue_msg or "INST" in str(issue_details):
                dangerous_opcodes_found.append("INST")
                code_execution_risks.append("Class instantiation code execution")
            if "obj" in issue_msg or "OBJ" in str(issue_details):
                dangerous_opcodes_found.append("OBJ")
                code_execution_risks.append("Object creation code execution")
            if "newobj" in issue_msg or "NEWOBJ" in str(issue_details):
                dangerous_opcodes_found.append("NEWOBJ")
                code_execution_risks.append("New-style object creation")
            if "stack_global" in issue_msg or "STACK_GLOBAL" in str(issue_details):
                dangerous_opcodes_found.append("STACK_GLOBAL")
                code_execution_risks.append("Dynamic import and attribute access")
            if "global" in issue_msg or "GLOBAL" in str(issue_details):
                dangerous_opcodes_found.append("GLOBAL")
                code_execution_risks.append("Module import and attribute access")
            if "build" in issue_msg or "BUILD" in str(issue_details):
                dangerous_opcodes_found.append("BUILD")
                code_execution_risks.append("__setstate__ method exploitation")

            # Look for any code execution patterns
            if any(pattern in issue_msg for pattern in ["exec", "eval", "import", "subprocess", "__import__"]):
                code_execution_risks.append("Direct code execution patterns")

        # If dangerous opcodes were found, add specific CVE-2025-32434 warning
        if dangerous_opcodes_found or code_execution_risks:
            # Create detailed warning message
            opcode_list = ", ".join(set(dangerous_opcodes_found)) if dangerous_opcodes_found else "unknown"
            # risk_description = "; ".join(set(code_execution_risks)) if code_execution_risks else "code execution"

            pytorch_result.add_check(
                name="CVE-2025-32434 weights_only=True Safety Warning",
                passed=False,
                message=(
                    f"PyTorch model contains dangerous opcodes ({opcode_list}) that can execute code "
                    f"even when loaded with torch.load(weights_only=True). This contradicts the common "
                    f"assumption that weights_only=True provides safety against code execution."
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": "CVE-2025-32434",
                    "dangerous_opcodes": list(set(dangerous_opcodes_found)),
                    "code_execution_risks": list(set(code_execution_risks)),
                    "weights_only_false_security": True,
                    "vulnerability_description": (
                        "The weights_only=True parameter in torch.load() does not prevent code execution "
                        "from malicious pickle files, contrary to common security assumptions."
                    ),
                    "recommendation": (
                        "Do not rely on weights_only=True for security. Use PyTorch 2.6.0+ and consider "
                        "safer serialization formats like SafeTensors. Always validate model sources."
                    ),
                    "affected_pytorch_versions": "All versions ≤2.5.1",
                    "fixed_in": "PyTorch 2.6.0",
                },
            )
        else:
            # No dangerous opcodes found - add informational check
            pytorch_result.add_check(
                name="CVE-2025-32434 weights_only=True Safety Warning",
                passed=True,
                message=(
                    f"No dangerous pickle opcodes detected in {pickle_name}. However, weights_only=True "
                    f"should not be relied upon for security with untrusted models."
                ),
                severity=IssueSeverity.INFO,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": "CVE-2025-32434",
                    "dangerous_opcodes_found": False,
                    "weights_only_security_note": (
                        "Even when no dangerous opcodes are detected, weights_only=True in torch.load() "
                        "should not be considered a security boundary for untrusted models."
                    ),
                    "recommendation": (
                        "Use PyTorch 2.6.0+ and prefer SafeTensors format for better security. "
                        "Always validate model sources and avoid loading untrusted models."
                    ),
                },
            )
