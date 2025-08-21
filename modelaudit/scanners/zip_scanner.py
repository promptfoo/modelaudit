import os
import re
import stat
import tempfile
import zipfile
from typing import Any, ClassVar, Optional

from ..utils import sanitize_archive_path
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
    supported_extensions: ClassVar[list[str]] = [".zip", ".npz"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        self.max_depth = self.config.get("max_zip_depth", 5)  # Prevent zip bomb attacks
        self.max_entries = self.config.get(
            "max_zip_entries",
            10000,
        )  # Limit number of entries

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Check file extension
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Verify it's actually a zip file
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

            # Scan the zip file recursively
            scan_result = self._scan_zip_file(path, depth=0)
            result.merge(scan_result)

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
        except Exception as e:
            result.add_check(
                name="ZIP File Scan",
                passed=False,
                message=f"Error scanning zip file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        result.metadata["contents"] = scan_result.metadata.get("contents", [])
        result.metadata["file_size"] = os.path.getsize(path)
        return result

    def _scan_zip_file(self, path: str, depth: int = 0) -> ScanResult:
        """Recursively scan a ZIP file and its contents"""
        result = ScanResult(scanner_name=self.name)
        contents: list[dict[str, Any]] = []

        # Check depth to prevent zip bomb attacks
        if depth >= self.max_depth:
            result.add_check(
                name="ZIP Depth Bomb Protection",
                passed=False,
                message=f"Maximum ZIP nesting depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
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
                    target_resolved, target_safe = sanitize_archive_path(
                        target,
                        target_base,
                    )
                    if not target_safe:
                        # Check if it's specifically a critical system path
                        if os.path.isabs(target) and any(target.startswith(p) for p in CRITICAL_SYSTEM_PATHS):
                            message = f"Symlink {name} points to critical system path: {target}"
                        else:
                            message = f"Symlink {name} resolves outside extraction directory"
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=message,
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                        )
                    elif os.path.isabs(target) and any(target.startswith(p) for p in CRITICAL_SYSTEM_PATHS):
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=False,
                            message=f"Symlink {name} points to critical system path: {target}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"target": target, "entry": name},
                        )
                    else:
                        result.add_check(
                            name="Symlink Safety Validation",
                            passed=True,
                            message=f"Symlink {name} is safe",
                            location=f"{path}:{name}",
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

                    # Check if it's another zip file
                    if name.lower().endswith(".zip"):
                        try:
                            nested_result = self._scan_zip_file(tmp_path, depth + 1)
                            # Update locations in nested results
                            for issue in nested_result.issues:
                                if issue.location and issue.location.startswith(
                                    tmp_path,
                                ):
                                    issue.location = issue.location.replace(
                                        tmp_path,
                                        f"{path}:{name}",
                                        1,
                                    )
                            result.merge(nested_result)
                            from ..utils.assets import asset_from_scan_result

                            asset_entry = asset_from_scan_result(
                                f"{path}:{name}",
                                nested_result,
                            )
                            asset_entry.setdefault("size", info.file_size)
                            contents.append(asset_entry)
                        finally:
                            os.unlink(tmp_path)
                    else:
                        # Try to scan the file with appropriate scanner
                        # Write to temporary file with proper extension and original filename
                        # This preserves the original filename for scanners that need it (like ManifestScanner)

                        try:
                            # Import core here to avoid circular import
                            from .. import core

                            # Use core.scan_file to scan with appropriate scanner
                            file_result = core.scan_file(tmp_path, self.config)

                            # Update locations in file results
                            for issue in file_result.issues:
                                if issue.location:
                                    if issue.location.startswith(tmp_path):
                                        issue.location = issue.location.replace(
                                            tmp_path,
                                            f"{path}:{name}",
                                            1,
                                        )
                                    else:
                                        issue.location = f"{path}:{name} {issue.location}"
                                else:
                                    issue.location = f"{path}:{name}"

                                # Add zip entry name to details
                                if issue.details:
                                    issue.details["zip_entry"] = name
                                else:
                                    issue.details = {"zip_entry": name}

                            result.merge(file_result)

                            from ..utils.assets import asset_from_scan_result

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
                        location=f"{path}:{name}",
                        details={"entry": name, "exception": str(e), "exception_type": type(e).__name__},
                    )

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(path)
        result.finish(success=not result.has_errors)
        return result
