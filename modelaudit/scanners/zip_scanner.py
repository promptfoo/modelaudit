import os
import re
import stat
import tempfile
import zipfile
from typing import Any, ClassVar

from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.helpers.assets import asset_from_scan_result
from .base import BaseScanner, IssueSeverity, ScanResult

CRITICAL_SYSTEM_PATHS = [
    "/etc",
    "/bin",
    "/usr",
    "/var",
    "/lib",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/sbin",
    "C:\\Windows",
]


class ZipScanner(BaseScanner):
    """Scanner for generic ZIP archive files"""

    name = "zip"
    description = "Scans ZIP archive files and their contents recursively"
    # Include .mar so non-TorchServe archives still receive generic ZIP scanning.
    supported_extensions: ClassVar[list[str]] = [".zip", ".npz", ".mar"]
    MAX_MAR_PYTHON_ANALYSIS_BYTES: ClassVar[int] = 10 * 1024 * 1024

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_depth = self.config.get("max_zip_depth", 5)  # Prevent zip bomb attacks
        self.max_entries = self.config.get(
            "max_zip_entries",
            10000,
        )  # Limit number of entries

    def _get_zip_depth(self) -> int:
        """Return the current nested ZIP depth from config."""
        raw_depth = self.config.get("_zip_depth", 0)
        try:
            depth = int(raw_depth)
        except (TypeError, ValueError):
            return 0
        return max(depth, 0)

    def _get_archive_depth(self) -> int:
        """Return the current shared archive depth from config."""
        raw_depth = self.config.get("_archive_depth", 0)
        try:
            depth = int(raw_depth)
        except (TypeError, ValueError):
            return 0
        return max(depth, 0)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Verify it's actually a zip file. Header-routed scans may reach this
        # scanner even when the outer filename uses a misleading suffix.
        try:
            with zipfile.ZipFile(path, "r") as _:
                pass
            return True
        except zipfile.BadZipFile:
            return False
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a ZIP file and its contents"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            # Scan the zip file recursively. Shared archive depth must survive
            # scanner handoffs, while nested ZIP recursion still needs its own
            # counter for extensionless ZIP members routed through core dispatch.
            scan_result = self._scan_zip_file(
                path,
                depth=max(self._get_archive_depth(), self._get_zip_depth()),
            )
            result.merge(scan_result)

        except zipfile.BadZipFile:
            result.add_check(
                name="ZIP File Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.INFO,
                rule_code="S902",  # Corrupted structure
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_check(
                name="ZIP File Scan",
                passed=False,
                message=f"Error scanning zip file: {e!s}",
                severity=IssueSeverity.INFO,
                rule_code="S902",  # Scan error
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        result.metadata["contents"] = scan_result.metadata.get("contents", [])
        result.metadata["file_size"] = os.path.getsize(path)
        return result

    def _rewrite_nested_result_context(
        self, scan_result: ScanResult, tmp_path: str, archive_path: str, entry_name: str
    ) -> None:
        """Rewrite nested result locations so archive members, not temp files, are reported."""
        archive_location = f"{archive_path}:{entry_name}"

        for issue in scan_result.issues:
            if issue.location:
                if issue.location.startswith(tmp_path):
                    issue.location = issue.location.replace(tmp_path, archive_location, 1)
                else:
                    issue.location = f"{archive_location} {issue.location}"
            else:
                issue.location = archive_location

            existing_issue_entry = issue.details.get("zip_entry")
            issue.details["zip_entry"] = (
                f"{entry_name}:{existing_issue_entry}"
                if isinstance(existing_issue_entry, str) and existing_issue_entry
                else entry_name
            )

        for check in scan_result.checks:
            if check.location:
                if check.location.startswith(tmp_path):
                    check.location = check.location.replace(tmp_path, archive_location, 1)
                else:
                    check.location = f"{archive_location} {check.location}"
            else:
                check.location = archive_location

            existing_check_entry = check.details.get("zip_entry")
            check.details["zip_entry"] = (
                f"{entry_name}:{existing_check_entry}"
                if isinstance(existing_check_entry, str) and existing_check_entry
                else entry_name
            )

    def _scan_zip_file(self, path: str, depth: int = 0) -> ScanResult:
        """Recursively scan a ZIP file and its contents"""
        result = ScanResult(scanner_name=self.name)
        contents: list[dict[str, Any]] = []
        archive_ext = os.path.splitext(path)[1].lower()

        # Check depth to prevent zip bomb attacks
        if depth >= self.max_depth:
            result.add_check(
                name="ZIP Depth Bomb Protection",
                passed=False,
                message=f"Maximum ZIP nesting depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
                rule_code="S410",  # Archive bomb
                location=path,
                details={"depth": depth, "max_depth": self.max_depth},
            )
            return result
        else:
            result.add_check(
                name="ZIP Depth Bomb Protection",
                passed=True,
                message="ZIP nesting depth is within safe limits",
                location=path,
                rule_code=None,  # Passing check
                details={"depth": depth, "max_depth": self.max_depth},
            )

        with zipfile.ZipFile(path, "r") as z:
            # Check number of entries
            entry_count = len(z.namelist())
            if entry_count > self.max_entries:
                result.add_check(
                    name="Entry Count Limit Check",
                    passed=False,
                    message=f"ZIP file contains too many entries ({entry_count} > {self.max_entries})",
                    severity=IssueSeverity.WARNING,
                    rule_code="S410",  # Archive bomb
                    location=path,
                    details={
                        "entries": entry_count,
                        "max_entries": self.max_entries,
                    },
                )
                return result
            else:
                result.add_check(
                    name="Entry Count Limit Check",
                    passed=True,
                    message=f"Entry count ({entry_count}) is within limits",
                    location=path,
                    details={
                        "entries": entry_count,
                        "max_entries": self.max_entries,
                    },
                    rule_code=None,  # Passing check
                )
            # Scan each file in the archive
            for name in z.namelist():
                info = z.getinfo(name)

                temp_base = os.path.join(tempfile.gettempdir(), "extract")
                resolved_name, is_safe = sanitize_archive_path(name, temp_base)
                if not is_safe:
                    result.add_check(
                        name="Path Traversal Protection",
                        passed=False,
                        message=f"Archive entry {name} attempted path traversal outside the archive",
                        severity=IssueSeverity.CRITICAL,
                        rule_code="S405",  # Path traversal
                        location=f"{path}:{name}",
                        details={"entry": name},
                    )
                    continue

                is_symlink = (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK
                if is_symlink:
                    try:
                        target = z.read(name).decode("utf-8", "replace")
                    except Exception:
                        target = ""
                    target_base = os.path.dirname(resolved_name)
                    _target_resolved, target_safe = sanitize_archive_path(
                        target,
                        target_base,
                    )
                    if not target_safe:
                        # Check if it's specifically a critical system path
                        if is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                            message = f"Symlink {name} points to critical system path: {target}"
                        else:
                            message = f"Symlink {name} resolves outside extraction directory"
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=message,
                            severity=IssueSeverity.CRITICAL,
                            rule_code="S406",  # Symlink external
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                        )
                    elif is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=f"Symlink {name} points to critical system path: {target}",
                            severity=IssueSeverity.CRITICAL,
                            rule_code="S408",  # System file access
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                        )
                    else:
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=True,
                            message=f"Symlink {name} is safe",
                            location=f"{path}:{name}",
                            rule_code=None,  # Passing check
                            details={"target": target, "entry": name},
                        )
                    # Do not scan symlink contents
                    continue

                # Skip directories
                if name.endswith("/"):
                    continue

                # Check compression ratio for zip bomb detection
                if info.compress_size > 0:
                    compression_ratio = info.file_size / info.compress_size
                    if compression_ratio > 100:
                        result.add_check(
                            name="Compression Ratio Check",
                            passed=False,
                            message=f"Suspicious compression ratio ({compression_ratio:.1f}x) in entry: {name}",
                            severity=IssueSeverity.WARNING,
                            rule_code="S410",  # Archive bomb
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "compressed_size": info.compress_size,
                                "uncompressed_size": info.file_size,
                                "ratio": compression_ratio,
                                "threshold": 100,
                            },
                        )
                    else:
                        # Record safe compression ratio
                        result.add_check(
                            name="Compression Ratio Check",
                            passed=True,
                            message=f"Compression ratio ({compression_ratio:.1f}x) is within safe limits: {name}",
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "compressed_size": info.compress_size,
                                "uncompressed_size": info.file_size,
                                "ratio": compression_ratio,
                                "threshold": 100,
                            },
                            rule_code=None,  # Passing check
                        )

                # Extract and scan the file
                try:
                    # Use max_file_size from CLI, fallback to max_entry_size, then default
                    max_entry_size = self.config.get(
                        "max_file_size", self.config.get("max_entry_size", 10 * 1024 * 1024 * 1024)
                    )  # Use CLI max_file_size, then max_entry_size, then 10GB default
                    # If max_file_size is 0 (unlimited), use a reasonable default for safety
                    if max_entry_size == 0:
                        max_entry_size = 1024 * 1024 * 1024 * 1024  # 1TB for unlimited case

                    if name.lower().endswith(".zip"):
                        suffix = ".zip"
                    else:
                        safe_name = re.sub(
                            r"[^a-zA-Z0-9_.-]",
                            "_",
                            os.path.basename(name),
                        )
                        suffix = f"_{safe_name}"

                    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                        tmp_path = tmp.name
                        total_size = 0
                        with z.open(name) as entry:
                            while True:
                                chunk = entry.read(4096)
                                if not chunk:
                                    break
                                total_size += len(chunk)
                                if total_size > max_entry_size:
                                    raise ValueError(
                                        f"ZIP entry {name} exceeds maximum size of {max_entry_size} bytes",
                                    )
                                tmp.write(chunk)

                    try:
                        if archive_ext == ".mar" and name.lower().endswith(".py"):
                            mar_python_result = self._scan_mar_python_entry(path, name, tmp_path, total_size)
                            if mar_python_result is not None:
                                result.merge(mar_python_result)

                        # Import core here to avoid circular import
                        from .. import core

                        nested_config = dict(self.config)
                        nested_config["_archive_depth"] = depth + 1
                        if zipfile.is_zipfile(tmp_path):
                            nested_config["_zip_depth"] = depth + 1

                        # Use core.scan_file so ZIP-based formats still reach their
                        # specialized scanners, while shared archive depth remains
                        # consistent across mixed ZIP/TAR/MAR recursion.
                        file_result = core.scan_file(tmp_path, nested_config)
                        self._rewrite_nested_result_context(file_result, tmp_path, path, name)

                        result.merge(file_result)

                        asset_entry = asset_from_scan_result(
                            f"{path}:{name}",
                            file_result,
                        )
                        asset_entry.setdefault("size", info.file_size)
                        contents.append(asset_entry)

                        # If no scanner handled the file, count the bytes ourselves
                        if file_result.scanner_name == "unknown":
                            result.bytes_scanned += total_size
                    finally:
                        os.unlink(tmp_path)

                except Exception as e:
                    result.add_check(
                        name="ZIP Entry Scan",
                        passed=False,
                        message=f"Error scanning ZIP entry {name}: {e!s}",
                        severity=IssueSeverity.WARNING,
                        rule_code="S902",  # Scan error
                        location=f"{path}:{name}",
                        details={"entry": name, "exception": str(e), "exception_type": type(e).__name__},
                    )

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(path)
        result.finish(success=not result.has_errors)
        return result

    def _scan_mar_python_entry(
        self,
        archive_path: str,
        entry_name: str,
        extracted_path: str,
        entry_size: int,
    ) -> ScanResult | None:
        """Apply TorchServe-style Python handler analysis for manifest-less `.mar` fallback."""
        max_analysis_bytes = self.config.get("max_mar_python_analysis_bytes", self.MAX_MAR_PYTHON_ANALYSIS_BYTES)
        if isinstance(max_analysis_bytes, bool) or not isinstance(max_analysis_bytes, int) or max_analysis_bytes <= 0:
            max_analysis_bytes = self.MAX_MAR_PYTHON_ANALYSIS_BYTES

        if entry_size > max_analysis_bytes:
            result = ScanResult(scanner_name=self.name)
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=(
                    f"Skipped Python handler static analysis for oversized entry ({entry_size} bytes); "
                    f"limit is {max_analysis_bytes} bytes"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{entry_name}",
                details={"entry": entry_name, "entry_size": entry_size, "size_limit": max_analysis_bytes},
            )
            result.finish(success=False)
            return result

        try:
            with open(extracted_path, "rb") as source_file:
                source_bytes = source_file.read()
        except OSError as exc:
            result = ScanResult(scanner_name=self.name)
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=f"Unable to read Python entry for static analysis: {exc}",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{entry_name}",
                details={"entry": entry_name, "exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result

        from .torchserve_mar_scanner import TorchServeMarScanner

        mar_scanner = TorchServeMarScanner(config=self.config)
        risky_calls, parse_error = mar_scanner._find_high_risk_calls(source_bytes)
        if parse_error is None and not risky_calls:
            return None

        result = ScanResult(scanner_name=self.name)
        if parse_error is not None:
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=f"Unable to parse Python entry for static analysis: {parse_error}",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{entry_name}",
                details={"entry": entry_name},
            )
        else:
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=f"Handler contains high-risk execution primitives: {', '.join(sorted(risky_calls))}",
                severity=IssueSeverity.CRITICAL,
                location=f"{archive_path}:{entry_name}",
                details={"entry": entry_name, "risky_calls": sorted(risky_calls)},
            )
        result.finish(success=False)
        return result

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract ZIP archive metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            with zipfile.ZipFile(file_path, "r") as zip_file:
                file_list = zip_file.namelist()

                # Basic ZIP info
                metadata.update(
                    {
                        "total_files": len(file_list),
                        "compressed_size": sum(info.compress_size for info in zip_file.filelist),
                        "uncompressed_size": sum(info.file_size for info in zip_file.filelist),
                    }
                )

                # Calculate compression ratio
                if metadata["uncompressed_size"] > 0:
                    metadata["compression_ratio"] = metadata["compressed_size"] / metadata["uncompressed_size"]

                # Analyze file types and structure
                file_extensions: dict[str, int] = {}
                directories = set()
                executable_files = []

                for name in file_list:
                    if name.endswith("/"):
                        directories.add(name)
                        continue

                    lower_name = name.lower()
                    # Track file extensions
                    if "." in name:
                        ext = name.split(".")[-1].lower()
                        file_extensions[ext] = file_extensions.get(ext, 0) + 1

                    # Check for executable files by extension or UNIX executable mode bits.
                    mode = zip_file.getinfo(name).external_attr >> 16
                    has_exec_mode = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    if has_exec_mode or any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".sh", ".py", ".js"]):
                        executable_files.append(name)

                metadata.update(
                    {
                        "file_extensions": file_extensions,
                        "directory_count": len(directories),
                        "executable_files": executable_files,
                        "has_executables": len(executable_files) > 0,
                    }
                )

                # Look for common model patterns
                model_indicators = {
                    "pytorch": any(name.endswith((".pt", ".pth")) for name in file_list),
                    "tensorflow": any("saved_model.pb" in name for name in file_list),
                    "onnx": any(name.endswith(".onnx") for name in file_list),
                    "pickle": any(name.endswith(".pkl") for name in file_list),
                    "keras": any(name.endswith(".h5") for name in file_list),
                    "safetensors": any(name.endswith(".safetensors") for name in file_list),
                }

                detected_formats = sorted(k for k, v in model_indicators.items() if v)
                if detected_formats:
                    metadata["detected_model_formats"] = detected_formats

                # Check for configuration files
                config_files = [
                    name
                    for name in file_list
                    if any(pattern in name.lower() for pattern in ["config", "manifest", "metadata", "readme"])
                ]
                if config_files:
                    metadata["config_files"] = sorted(set(config_files))

                # Security analysis
                metadata["security_notes"] = []
                if executable_files:
                    metadata["security_notes"].append(f"Contains {len(executable_files)} executable files")

                if any(".." in name for name in file_list):
                    metadata["security_notes"].append("Contains path traversal patterns")

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
