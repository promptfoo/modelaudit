import io
import os
import tempfile
import zipfile
from typing import Any, ClassVar

from ..utils import sanitize_archive_path
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner


class PyTorchZipScanner(BaseScanner):
    """Scanner for PyTorch Zip-based model files (.pt, .pth)"""

    name = "pytorch_zip"
    description = "Scans PyTorch model files for suspicious code in embedded pickles"
    supported_extensions: ClassVar[list[str]] = [".pt", ".pth", ".bin"]

    # CVE-2025-32434 constants
    CVE_2025_32434_ID: ClassVar[str] = "CVE-2025-32434"
    CVE_2025_32434_FIX_VERSION: ClassVar[str] = "2.6.0"
    CVE_2025_32434_DESCRIPTION: ClassVar[str] = "RCE when loading models with torch.load(weights_only=True)"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Initialize a pickle scanner for embedded pickles
        self.pickle_scanner: PickleScanner = PickleScanner(config)
        self.current_file_path = ""  # Will be set when scanning files

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
                from modelaudit.utils.file.detection import detect_file_format

                return detect_file_format(path) == "zip"
            except Exception:
                return False

        # For .pt and .pth, always try to handle
        return True

    def scan(self, path: str, timeout: int | None = None) -> ScanResult:
        """Scan a PyTorch model file for suspicious code"""
        # Override timeout if provided
        if timeout is not None:
            self.timeout = timeout

        # Start timeout tracking
        self._start_scan_timer()

        # Initial validation and setup
        result = self._initialize_scan(path)
        if result.success is False:  # Early return for validation failures
            return result

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            with zipfile.ZipFile(path, "r") as zip_file:
                # Validate ZIP entries and check for path traversal
                safe_entries = self._validate_zip_entries(zip_file, result, path)
                self._check_timeout()  # Check timeout after entry validation

                # Discover pickle files in the archive
                pickle_files = self._discover_pickle_files(zip_file, safe_entries, result)

                # Extract version info and check for CVE vulnerabilities
                self._check_pytorch_vulnerabilities(zip_file, safe_entries, result, path)

                # Scan all discovered pickle files
                bytes_scanned = self._scan_pickle_files(zip_file, pickle_files, result, path)
                self._check_timeout()  # Check timeout after pickle scanning

                # Check for JIT/Script code execution risks
                bytes_scanned += self._scan_for_jit_patterns(zip_file, safe_entries, result, path)

                # Detect suspicious non-pickle files
                self._detect_suspicious_files(safe_entries, result, path)

                # Validate PyTorch model structure
                self._validate_pytorch_structure(pickle_files, result)

                # Check for blacklisted patterns across all files
                self._check_blacklist_patterns(zip_file, safe_entries, result)

                result.bytes_scanned += bytes_scanned

        except TimeoutError as e:
            # Handle timeout gracefully
            result.add_check(
                name="Scan Timeout",
                passed=False,
                message=f"Scan timed out: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"timeout_seconds": self.timeout},
            )
            result.finish(success=True)  # Partial results are still valid
            return result
        except zipfile.BadZipFile:
            return self._handle_bad_zip_error(path)
        except Exception as e:
            return self._handle_scan_error(path, e)

        result.finish(success=True)
        return result

    def _initialize_scan(self, path: str) -> ScanResult:
        """Initialize scan with basic validation and setup"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        # Validate ZIP format
        header = self._read_header(path)
        if not header.startswith(b"PK"):
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
        else:
            result.add_check(
                name="PyTorch ZIP Format Validation",
                passed=True,
                message="Valid ZIP format detected",
                location=path,
            )

        return result

    def _validate_zip_entries(self, zip_file: zipfile.ZipFile, result: ScanResult, path: str) -> list[str]:
        """Validate ZIP entries and check for path traversal attacks"""
        safe_entries: list[str] = []
        path_traversal_found = False
        temp_base = os.path.join(tempfile.gettempdir(), "extract")
        for name in zip_file.namelist():
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

        if not path_traversal_found and zip_file.namelist():
            result.add_check(
                name="Path Traversal Protection",
                passed=True,
                message="All archive entries have safe paths",
                location=path,
                details={"entries_checked": len(zip_file.namelist())},
            )

        return safe_entries

    def _discover_pickle_files(
        self, zip_file: zipfile.ZipFile, safe_entries: list[str], result: ScanResult
    ) -> list[str]:
        """Discover pickle files in the ZIP archive"""
        pickle_files = []

        # First pass: Look for common pickle file patterns
        for name in safe_entries:
            if name.endswith(".pkl") or name == "data.pkl" or name.endswith("/data.pkl"):
                pickle_files.append(name)

        # Second pass: If no obvious pickle files found, check for pickle magic bytes
        if not pickle_files:
            for name in safe_entries:
                try:
                    with zip_file.open(name, "r") as zef:
                        data_start = zef.read(8)  # header only
                    # Include protocol 1 and check for protocol 0 ASCII pickles
                    pickle_magics = [b"\x80\x01", b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
                    # Common Protocol 0 ASCII opcodes: MARK '(', PUT 'p', GLOBAL 'c',
                    # LIST 'l', DICT 'd', INT 'I'/'i', STRING 'S', UNICODE 'V', etc.
                    ascii_pickle_opcodes = [b"(", b"p", b"c", b"l", b"d", b"I", b"i", b"S", b"V", b"q", b"t", b"u"]
                    if any(data_start.startswith(m) for m in pickle_magics) or any(
                        data_start.startswith(op) for op in ascii_pickle_opcodes
                    ):
                        pickle_files.append(name)
                except Exception:
                    pass

        result.metadata["pickle_files"] = pickle_files
        return pickle_files

    def _check_pytorch_vulnerabilities(
        self, zip_file: zipfile.ZipFile, safe_entries: list[str], result: ScanResult, path: str
    ) -> None:
        """Extract PyTorch version info and check for CVE vulnerabilities"""
        pytorch_version_info = self._extract_pytorch_version_info(zip_file, safe_entries)
        result.metadata.update(pytorch_version_info)
        self._check_cve_2025_32434_vulnerability(pytorch_version_info, result, path)

    def _scan_pickle_files(
        self, zip_file: zipfile.ZipFile, pickle_files: list[str], result: ScanResult, path: str
    ) -> int:
        """Scan all discovered pickle files for malicious content"""
        bytes_scanned = 0

        # Get the original ZIP file size for proper density calculations
        # This is crucial for CVE-2025-32434 detection to avoid false positives
        original_file_size = int(result.metadata.get("file_size") or 0)
        if original_file_size <= 0:
            try:
                original_file_size = os.path.getsize(path)
            except OSError:
                original_file_size = 1  # Avoid divide-by-zero in density calculations

        for name in pickle_files:
            info = zip_file.getinfo(name)
            pickle_data_size = info.file_size

            # Set the current file path on the pickle scanner for proper error reporting
            self.pickle_scanner.current_file_path = f"{path}:{name}"

            # Choose scanning approach based on file size with spooling for seekability
            cfg = self.config or {}
            max_in_mem = int(cfg.get("pickle_max_memory_read", 32 * 1024 * 1024))  # 32MB default
            if pickle_data_size <= max_in_mem:
                data = zip_file.read(name)
                bytes_scanned += len(data)
                with io.BytesIO(data) as file_like:
                    # IMPORTANT: Pass original ZIP file size, not pickle data size
                    # This enables proper density-based CVE detection
                    sub_result = self.pickle_scanner._scan_pickle_bytes(file_like, original_file_size)
            else:
                # Stream to a spooled temp file to avoid OOM and provide seek()
                with zip_file.open(name, "r") as zf, tempfile.SpooledTemporaryFile(max_size=max_in_mem) as spool:
                    for chunk in iter(lambda: zf.read(1024 * 1024), b""):
                        spool.write(chunk)
                        bytes_scanned += len(chunk)
                    spool.seek(0)
                    # IMPORTANT: Pass original ZIP file size, not pickle data size
                    # This enables proper density-based CVE detection
                    sub_result = self.pickle_scanner._scan_pickle_bytes(
                        spool,  # type: ignore[arg-type]
                        original_file_size,
                    )

            # Update issue metadata and locations
            for issue in sub_result.issues:
                if issue.details:
                    issue.details["pickle_filename"] = name
                else:
                    issue.details = {"pickle_filename": name}

                # Update location to include the main file path
                if not issue.location:
                    issue.location = f"{path}:{name}"
                elif "pos" in issue.location:
                    issue.location = f"{path}:{name} {issue.location}"

            # Add CVE-2025-32434 specific warnings
            self._add_weights_only_safety_warnings(sub_result, result, path, name)
            result.merge(sub_result)

        return bytes_scanned

    def _scan_for_jit_patterns(
        self, zip_file: zipfile.ZipFile, safe_entries: list[str], result: ScanResult, path: str
    ) -> int:
        """Check for JIT/Script code execution risks and network communication patterns"""
        bytes_scanned = 0
        all_jit_findings = []
        all_network_findings = []

        for name in safe_entries:
            try:
                with zip_file.open(name, "r") as zf:
                    # Collect all data from this file for analysis
                    chunks: list[bytes] = []
                    for chunk in iter(lambda: zf.read(1024 * 1024), b""):
                        bytes_scanned += len(chunk)
                        chunks.append(chunk)
                    file_data = b"".join(chunks)

                    # Collect findings for this file without creating individual checks
                    if file_data:  # Only process if we have data
                        jit_findings = self.collect_jit_script_findings(
                            file_data,
                            model_type="pytorch",
                            context=f"{path}:{name}",
                        )
                        network_findings = self.collect_network_communication_findings(
                            file_data,
                            context=f"{path}:{name}",
                        )

                        all_jit_findings.extend(jit_findings)
                        all_network_findings.extend(network_findings)

            except Exception:
                # Skip files that can't be read
                pass

        # Create single aggregated checks for the entire ZIP file
        if safe_entries:  # Only create checks if we processed files
            check_jit = self._get_bool_config("check_jit_script", True)
            if check_jit:
                self.summarize_jit_script_findings(all_jit_findings, result, context=path)
            else:
                result.metadata.setdefault("disabled_checks", []).append("JIT/Script Code Execution Detection")

            check_net = self._get_bool_config("check_network_comm", True)
            if check_net:
                self.summarize_network_communication_findings(all_network_findings, result, context=path)
            else:
                result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")

        return bytes_scanned

    def _detect_suspicious_files(self, safe_entries: list[str], result: ScanResult, path: str) -> None:
        """Detect suspicious non-pickle files in the archive"""
        python_files_found = False
        executable_files_found = False

        for name in safe_entries:
            # Check for Python code files
            if name.endswith(".py"):
                result.add_check(
                    name="Python Code File Detection",
                    passed=False,
                    message=f"Python code file found in PyTorch model: {name}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{name}",
                    details={"file": name},
                )
                python_files_found = True
            # Check for shell scripts or other executable files
            elif name.endswith(
                (".sh", ".bash", ".cmd", ".exe", ".dll", ".so", ".dylib", ".scr", ".com", ".bat", ".ps1")
            ):
                result.add_check(
                    name="Executable File Detection",
                    passed=False,
                    message=f"Executable file found in PyTorch model: {name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path}:{name}",
                    details={"file": name},
                )
                executable_files_found = True

        # Add positive checks if no suspicious files found
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

    def _validate_pytorch_structure(self, pickle_files: list[str], result: ScanResult) -> None:
        """Validate that the PyTorch model has expected structure"""
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

    def _check_blacklist_patterns(self, zip_file: zipfile.ZipFile, safe_entries: list[str], result: ScanResult) -> None:
        """Check for blacklisted patterns in all files"""
        blacklist_patterns = None
        if not blacklist_patterns:
            blacklist_patterns = self.config.get("blacklist_patterns") if self.config else None

        if blacklist_patterns:
            self._scan_blacklist_patterns(zip_file, safe_entries, blacklist_patterns, result)
        else:
            # No blacklist patterns configured
            if safe_entries:
                result.add_check(
                    name="Blacklist Pattern Check",
                    passed=True,
                    message="No blacklist patterns configured for scanning",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"reason": "no_blacklist_configured", "entries_available": len(safe_entries)},
                )

    def _scan_blacklist_patterns(
        self, zip_file: zipfile.ZipFile, safe_entries: list[str], blacklist_patterns: list[str], result: ScanResult
    ) -> None:
        """Scan files for blacklisted patterns"""
        max_blacklist_scan_size = self.config.get("max_blacklist_scan_size", 100 * 1024 * 1024)  # 100MB default

        for name in safe_entries:
            try:
                info = zip_file.getinfo(name)

                # Skip files that are too large
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

                # Choose scanning method based on file size
                if info.file_size > 10 * 1024 * 1024:  # 10MB threshold for streaming
                    self._scan_large_file_for_patterns(zip_file, name, blacklist_patterns, result)
                else:
                    self._scan_small_file_for_patterns(zip_file, name, blacklist_patterns, result)

            except Exception as e:
                self._handle_blacklist_scan_error(name, e, result)

    def _scan_large_file_for_patterns(
        self, zip_file: zipfile.ZipFile, name: str, blacklist_patterns: list[str], result: ScanResult
    ) -> None:
        """Stream large files and check patterns in chunks"""
        found_patterns = []
        with zip_file.open(name, "r") as zf:
            chunk_size = 1024 * 1024  # 1MB chunks
            overlap_buffer = b""
            max_pattern_len = max(len(p.encode("utf-8")) for p in blacklist_patterns) if blacklist_patterns else 0

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
                overlap_buffer = search_data[-max_pattern_len:] if len(search_data) >= max_pattern_len else search_data

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

    def _scan_small_file_for_patterns(
        self, zip_file: zipfile.ZipFile, name: str, blacklist_patterns: list[str], result: ScanResult
    ) -> None:
        """Scan small files for blacklisted patterns"""
        file_data = zip_file.read(name)

        # For pickled files, check for patterns in the binary data
        if name.endswith(".pkl"):
            for pattern in blacklist_patterns:
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
                            message=f"Blacklisted pattern '{pattern}' found in binary file {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} ({name})",
                            details={
                                "pattern": pattern,
                                "file": name,
                                "file_type": "binary",
                                "scan_method": "direct",
                            },
                        )

    def _handle_blacklist_scan_error(self, name: str, error: Exception, result: ScanResult) -> None:
        """Handle errors during blacklist pattern scanning"""
        if isinstance(error, zipfile.BadZipFile):
            severity = IssueSeverity.WARNING
            error_type = "BadZipFile"
        elif isinstance(error, MemoryError):
            severity = IssueSeverity.WARNING
            error_type = "MemoryError"
        else:
            severity = IssueSeverity.DEBUG
            error_type = type(error).__name__

        result.add_check(
            name="ZIP Entry Read",
            passed=False,
            message=f"Error reading file {name}: {error!s}",
            severity=severity,
            location=f"{self.current_file_path} ({name})",
            details={
                "zip_entry": name,
                "exception": str(error),
                "exception_type": error_type,
                "scan_phase": "blacklist_check",
            },
        )

    def _handle_bad_zip_error(self, path: str) -> ScanResult:
        """Handle BadZipFile errors"""
        result = self._create_result()
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

    def _handle_scan_error(self, path: str, error: Exception) -> ScanResult:
        """Handle general scan errors"""
        result = self._create_result()
        result.add_check(
            name="PyTorch ZIP Scan",
            passed=False,
            message=f"Error scanning PyTorch zip file: {error!s}",
            severity=IssueSeverity.CRITICAL,
            location=path,
            details={"exception": str(error), "exception_type": type(error).__name__},
        )
        result.finish(success=False)
        return result

    def _extract_pytorch_version_info(self, zipfile_obj: zipfile.ZipFile, safe_entries: list[str]) -> dict[str, Any]:
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
                version_info["pytorch_version_source"] = "version"
            elif "archive/version" in safe_entries:
                version_data = zipfile_obj.read("archive/version").decode("utf-8", errors="ignore").strip()
                version_info["pytorch_archive_version"] = version_data
                version_info["pytorch_version_source"] = "archive/version"

            # Try to extract PyTorch framework version from pickle files
            # Look for torch.__version__ references in pickle GLOBAL opcodes
            for name in safe_entries:
                if name.endswith(".pkl"):
                    try:
                        # Cap read for version probing to 1MB; adjust via config if needed
                        with zipfile_obj.open(name, "r") as zf:
                            cfg = self.config or {}
                            probe_bytes = cfg.get("version_probe_bytes", 1024 * 1024)  # 1MB default
                            pickle_data = zf.read(probe_bytes)
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
                    except (json.JSONDecodeError, UnicodeDecodeError):  # type: ignore[possibly-unresolved-reference]
                        continue

        except Exception:
            # Log but don't fail - version detection is best effort
            pass

        return version_info

    def _extract_framework_version_from_pickle(self, pickle_data: bytes) -> str | None:
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
        """Check for CVE-2025-32434 vulnerability based on installed PyTorch version"""

        # Only check if PyTorch is actually installed
        try:
            import torch

            installed_version = torch.__version__
        except ImportError:
            # PyTorch not installed, skip the check entirely
            return

        # Check if the installed PyTorch version is vulnerable (< 2.6.0)
        is_vulnerable = self._is_vulnerable_pytorch_version(installed_version)

        if is_vulnerable:
            # Only warn if the installed version is vulnerable
            result.add_check(
                name="CVE-2025-32434 PyTorch Version Check",
                passed=False,
                message=(
                    f"PyTorch {installed_version} is installed and vulnerable to CVE-2025-32434 RCE. "
                    f"Upgrade to PyTorch 2.6.0 or later."
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "installed_pytorch_version": installed_version,
                    "vulnerability_description": "RCE when loading models with torch.load(weights_only=True)",
                    "fixed_in": f"PyTorch {self.CVE_2025_32434_FIX_VERSION}",
                    "recommendation": (
                        "Update to PyTorch 2.6.0 or later, avoid torch.load(weights_only=True) with untrusted models"
                    ),
                },
            )
        # If not vulnerable, don't show anything

    def _is_vulnerable_pytorch_version(self, version: str) -> bool:
        """Check if a PyTorch version is vulnerable to CVE-2025-32434 (≤2.5.1)"""
        try:
            import re

            # Parse version string
            vstr = version.strip()
            is_prerelease = bool(re.search(r"(dev|rc|alpha|beta)", vstr, re.IGNORECASE))
            version_match = re.match(r"^(\d+)\.(\d+)\.(\d+)", vstr)
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
                elif minor >= 6:
                    # For 2.6.0+, treat pre-releases conservatively as vulnerable
                    return is_prerelease
                else:
                    return False  # 2.6.0+ stable releases are fixed
            else:
                # For 3.x+, treat pre-releases conservatively as vulnerable
                return is_prerelease

        except Exception:
            # If version parsing fails, assume vulnerable for safety
            return True

    def _check_safetensors_available(self, model_path: str) -> bool:
        """Check if a SafeTensors alternative exists in the same directory"""
        try:
            import glob

            # Get the directory containing the PyTorch model
            model_dir = os.path.dirname(model_path)
            if not model_dir:
                # If no directory (relative path), use current directory
                model_dir = "."

            # Look for .safetensors files in the same directory
            safetensors_pattern = os.path.join(model_dir, "*.safetensors")
            safetensors_files = glob.glob(safetensors_pattern)

            return len(safetensors_files) > 0
        except Exception:
            return False

    def _analyze_pickle_imports(self, pickle_result: ScanResult) -> dict[str, Any]:
        """Analyze pickle imports to distinguish legitimate vs malicious patterns"""
        # Standard PyTorch imports that are expected in legitimate models
        legitimate_imports = {
            "torch._utils",
            "torch.LongStorage",
            "torch.FloatStorage",
            "torch.HalfStorage",
            "torch.IntStorage",
            "torch.Storage",
            "collections.OrderedDict",
            "collections",
            "numpy",
        }

        # Malicious imports that indicate actual attack
        malicious_imports = {
            "os.system",
            "subprocess",
            "eval",
            "exec",
            "compile",
            "__builtin__",
            "builtins.eval",
            "builtins.exec",
            "webbrowser",
            "socket",
            "urllib",
        }

        found_imports = set()
        found_malicious = set()

        # Extract GLOBAL opcodes from ALL checks (both passed and failed)
        # This is important because legitimate imports are recorded as passed checks
        all_checks = pickle_result.issues + getattr(pickle_result, "checks", [])
        for check in all_checks:
            check_details = check.details or {}
            if "import_reference" in check_details:
                imp = check_details["import_reference"]
                found_imports.add(imp)
                # Check if this is a malicious import
                if any(mal in imp for mal in malicious_imports):
                    found_malicious.add(imp)

        # Determine if all imports are legitimate
        all_legitimate = (
            all(any(legit in imp for legit in legitimate_imports) for imp in found_imports) if found_imports else True
        )

        return {
            "total_imports": len(found_imports),
            "all_legitimate": all_legitimate,
            "found_malicious": list(found_malicious),
            "found_imports": list(found_imports),
        }

    def _add_weights_only_safety_warnings(
        self, pickle_result: ScanResult, pytorch_result: ScanResult, model_path: str, pickle_name: str
    ) -> None:
        """Add CVE-2025-32434 specific warnings with context-aware severity"""

        # Check for SafeTensors availability
        has_safetensors = self._check_safetensors_available(model_path)

        # Analyze imports to distinguish legitimate vs malicious
        import_analysis = self._analyze_pickle_imports(pickle_result)

        # Check if the pickle scan found any dangerous opcodes
        dangerous_opcodes_found: list[str] = []
        code_execution_risks: list[str] = []
        opcode_counts: dict[str, int] = {}

        # Analyze the pickle scan results for dangerous patterns
        for issue in pickle_result.issues:
            issue_msg = issue.message.lower()
            issue_details = issue.details or {}

            # Look for specific dangerous opcodes
            if "reduce" in issue_msg or "REDUCE" in str(issue_details):
                dangerous_opcodes_found.append("REDUCE")
                opcode_counts["REDUCE"] = opcode_counts.get("REDUCE", 0) + 1
                code_execution_risks.append("__reduce__ method exploitation")
            if "inst" in issue_msg or "INST" in str(issue_details):
                dangerous_opcodes_found.append("INST")
                opcode_counts["INST"] = opcode_counts.get("INST", 0) + 1
                code_execution_risks.append("Class instantiation code execution")
            if "obj" in issue_msg or "OBJ" in str(issue_details):
                dangerous_opcodes_found.append("OBJ")
                opcode_counts["OBJ"] = opcode_counts.get("OBJ", 0) + 1
                code_execution_risks.append("Object creation code execution")
            if "newobj" in issue_msg or "NEWOBJ" in str(issue_details):
                dangerous_opcodes_found.append("NEWOBJ")
                opcode_counts["NEWOBJ"] = opcode_counts.get("NEWOBJ", 0) + 1
                code_execution_risks.append("New-style object creation")
            if "stack_global" in issue_msg or "STACK_GLOBAL" in str(issue_details):
                dangerous_opcodes_found.append("STACK_GLOBAL")
                opcode_counts["STACK_GLOBAL"] = opcode_counts.get("STACK_GLOBAL", 0) + 1
                code_execution_risks.append("Dynamic import and attribute access")
            if "global" in issue_msg or "GLOBAL" in str(issue_details):
                dangerous_opcodes_found.append("GLOBAL")
                opcode_counts["GLOBAL"] = opcode_counts.get("GLOBAL", 0) + 1
                code_execution_risks.append("Module import and attribute access")
            if "build" in issue_msg or "BUILD" in str(issue_details):
                dangerous_opcodes_found.append("BUILD")
                opcode_counts["BUILD"] = opcode_counts.get("BUILD", 0) + 1
                code_execution_risks.append("__setstate__ method exploitation")

            # Look for any code execution patterns
            if any(pattern in issue_msg for pattern in ["exec", "eval", "import", "subprocess", "__import__"]):
                code_execution_risks.append("Direct code execution patterns")

        # If dangerous opcodes were found, determine appropriate severity
        if dangerous_opcodes_found or code_execution_risks:
            # Determine severity based on context
            if import_analysis["found_malicious"]:
                # Malicious imports found - this is CRITICAL
                severity = IssueSeverity.CRITICAL
                message_prefix = "CRITICAL: Malicious code detected"
                recommendation = (
                    "DO NOT USE THIS MODEL - it contains malicious imports "
                    f"({', '.join(import_analysis['found_malicious'])}). "
                    "This is likely a supply chain attack."
                )
            elif has_safetensors and import_analysis["all_legitimate"]:
                # Legitimate opcodes using safe ML framework functions - this is INFO
                severity = IssueSeverity.INFO
                message_prefix = "Pickle serialization with safe ML framework operations (SafeTensors available)"
                # Handle all supported PyTorch extensions (.pt, .pth, .bin)
                base_name = os.path.splitext(os.path.basename(model_path))[0]
                safetensors_name = f"{base_name}.safetensors"
                recommendation = (
                    f"This model uses pickle format with legitimate ML framework operations. "
                    f"All REDUCE opcodes call safe functions from allowlisted ML frameworks. "
                    f"A safer SafeTensors version is available: {safetensors_name}. "
                    f"While current operations are safe, consider using SafeTensors for defense-in-depth "
                    f"(protects against environment tampering/supply chain attacks)."
                )
            elif import_analysis["all_legitimate"]:
                # Legitimate opcodes but no SafeTensors - this is INFO with recommendation
                severity = IssueSeverity.INFO
                message_prefix = "Pickle serialization format detected"
                recommendation = (
                    "This model uses pickle serialization format which allows code execution by design "
                    "(CVE-2025-32434). While the current opcodes appear legitimate, consider requesting "
                    "a SafeTensors version from the publisher for improved supply chain security."
                )
            else:
                # Suspicious but not definitively malicious - this is WARNING
                severity = IssueSeverity.WARNING
                message_prefix = "Suspicious patterns detected"
                recommendation = (
                    "Model contains unusual pickle patterns that require manual review. "
                    "Consider using SafeTensors format or verifying model source before deployment."
                )

            # Create opcode summary for evidence
            opcode_summary = ", ".join(f"{op}({count})" for op, count in opcode_counts.items())

            pytorch_result.add_check(
                name="CVE-2025-32434 Pickle Format Security Analysis",
                passed=False,
                message=f"{message_prefix}: {opcode_summary} opcodes detected",
                severity=severity,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "opcode_counts": opcode_counts,
                    "total_dangerous_opcodes": sum(opcode_counts.values()),
                    "unique_opcode_types": list(set(dangerous_opcodes_found)),
                    "code_execution_risks": list(set(code_execution_risks)),
                    "import_analysis": import_analysis,
                    "safetensors_available": has_safetensors,
                    "assessment": (
                        "malicious"
                        if import_analysis["found_malicious"]
                        else ("legitimate_but_risky_format" if import_analysis["all_legitimate"] else "suspicious")
                    ),
                    "vulnerability_description": (
                        "The weights_only=True parameter in torch.load() does not prevent code execution "
                        "from pickle files, contrary to common security assumptions."
                    ),
                    "recommendation": recommendation,
                    "affected_pytorch_versions": "All versions ≤2.5.1",
                    "fixed_in": f"PyTorch {self.CVE_2025_32434_FIX_VERSION}",
                },
            )
        else:
            # No dangerous opcodes found - add informational check
            pytorch_result.add_check(
                name="CVE-2025-32434 Pickle Format Security Analysis",
                passed=True,
                message=(
                    f"No dangerous pickle opcodes detected in {pickle_name}. However, pickle format "
                    f"should not be relied upon for security with untrusted models."
                ),
                severity=IssueSeverity.INFO,
                location=f"{model_path}:{pickle_name}",
                details={
                    "cve_id": self.CVE_2025_32434_ID,
                    "dangerous_opcodes_found": False,
                    "safetensors_available": has_safetensors,
                    "recommendation": (
                        "Use SafeTensors format for better security. "
                        + (
                            "A SafeTensors version is available in the same directory."
                            if has_safetensors
                            else "Consider requesting a SafeTensors version from the publisher."
                        )
                    ),
                },
            )
