import os
import zipfile
from typing import Any, Dict, Optional

from ..utils import sanitize_archive_path
from .base import BaseScanner, IssueSeverity, ScanResult


class ZipScanner(BaseScanner):
    """Scanner for generic ZIP archive files"""

    name = "zip"
    description = "Scans ZIP archive files and their contents recursively"
    supported_extensions = [".zip"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.max_depth = self.config.get("max_zip_depth", 5)  # Prevent zip bomb attacks
        self.max_entries = self.config.get(
            "max_zip_entries", 10000
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

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            # Scan the zip file recursively
            scan_result = self._scan_zip_file(path, depth=0)
            result.merge(scan_result)

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
                f"Error scanning zip file: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _scan_zip_file(self, path: str, depth: int = 0) -> ScanResult:
        """Recursively scan a ZIP file and its contents"""
        result = ScanResult(scanner_name=self.name)

        # Check depth to prevent zip bomb attacks
        if depth >= self.max_depth:
            result.add_issue(
                f"Maximum ZIP nesting depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"depth": depth, "max_depth": self.max_depth},
            )
            return result

        with zipfile.ZipFile(path, "r") as z:
            # Check number of entries
            if len(z.namelist()) > self.max_entries:
                result.add_issue(
                    f"ZIP file contains too many entries "
                    f"({len(z.namelist())} > {self.max_entries})",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "entries": len(z.namelist()),
                        "max_entries": self.max_entries,
                    },
                )
                return result

            # Scan each file in the archive
            for name in z.namelist():
                info = z.getinfo(name)

                _, is_safe = sanitize_archive_path(name, "/tmp/extract")
                if not is_safe:
                    result.add_issue(
                        f"Archive entry {name} attempted path traversal outside the archive",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{path}:{name}",
                        details={"entry": name},
                    )
                    continue

                # Skip directories
                if name.endswith("/"):
                    continue

                # Check compression ratio for zip bomb detection
                if info.compress_size > 0:
                    compression_ratio = info.file_size / info.compress_size
                    if compression_ratio > 100:
                        result.add_issue(
                            f"Suspicious compression ratio ({compression_ratio:.1f}x) "
                            f"in entry: {name}",
                            severity=IssueSeverity.WARNING,
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "compressed_size": info.compress_size,
                                "uncompressed_size": info.file_size,
                                "ratio": compression_ratio,
                            },
                        )

                # Extract and scan the file
                try:
                    max_entry_size = self.config.get(
                        "max_entry_size", 10485760
                    )  # 10 MB default
                    data = b""
                    with z.open(name) as entry:
                        while True:
                            chunk = entry.read(4096)  # Read in 4 KB chunks
                            if not chunk:
                                break
                            data += chunk
                            if len(data) > max_entry_size:
                                raise ValueError(
                                    f"ZIP entry {name} exceeds maximum size of "
                                    f"{max_entry_size} bytes"
                                )

                    # Check if it's another zip file
                    if name.lower().endswith(".zip"):
                        # Write to temporary file and scan recursively
                        import tempfile

                        with tempfile.NamedTemporaryFile(
                            suffix=".zip", delete=False
                        ) as tmp:
                            tmp.write(data)
                            tmp_path = tmp.name

                        try:
                            nested_result = self._scan_zip_file(tmp_path, depth + 1)
                            # Update locations in nested results
                            for issue in nested_result.issues:
                                if issue.location and issue.location.startswith(
                                    tmp_path
                                ):
                                    issue.location = issue.location.replace(
                                        tmp_path, f"{path}:{name}", 1
                                    )
                            result.merge(nested_result)
                        finally:
                            os.unlink(tmp_path)
                    else:
                        # Try to scan the file with appropriate scanner
                        # Write to temporary file with proper extension
                        import tempfile

                        _, ext = os.path.splitext(name)
                        with tempfile.NamedTemporaryFile(
                            suffix=ext, delete=False
                        ) as tmp:
                            tmp.write(data)
                            tmp_path = tmp.name

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
                                            tmp_path, f"{path}:{name}", 1
                                        )
                                    else:
                                        issue.location = (
                                            f"{path}:{name} {issue.location}"
                                        )
                                else:
                                    issue.location = f"{path}:{name}"

                                # Add zip entry name to details
                                if issue.details:
                                    issue.details["zip_entry"] = name
                                else:
                                    issue.details = {"zip_entry": name}

                            result.merge(file_result)

                            # If no scanner handled the file, count the bytes ourselves
                            if file_result.scanner_name == "unknown":
                                result.bytes_scanned += len(data)
                        finally:
                            os.unlink(tmp_path)

                except Exception as e:
                    result.add_issue(
                        f"Error scanning ZIP entry {name}: {str(e)}",
                        severity=IssueSeverity.WARNING,
                        location=f"{path}:{name}",
                        details={"entry": name, "exception": str(e)},
                    )

        return result
