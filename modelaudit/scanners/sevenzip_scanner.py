import os
import tempfile
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    import py7zr as _py7zr  # type: ignore[import-untyped]
else:
    _py7zr = None

from ..utils import sanitize_archive_path
from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import py7zr with graceful fallback
try:
    import py7zr  # type: ignore[import-untyped]

    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False
    py7zr = _py7zr


class SevenZipScanner(BaseScanner):
    """Scanner for 7-Zip archive files (.7z)

    This scanner extracts and scans model files contained within 7-Zip archives,
    looking for malicious content that could be hidden in compressed formats.
    """

    name = "sevenzip"
    description = "Scans 7-Zip archives for malicious model files"
    supported_extensions: ClassVar[list[str]] = [".7z"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_entries = self.config.get("max_7z_entries", 10000)
        self.max_extract_size = self.config.get("max_7z_extract_size", 1024 * 1024 * 1024)  # 1GB

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not HAS_PY7ZR:
            return False

        if not os.path.isfile(path):
            return False

        # Check extension
        if not path.lower().endswith(".7z"):
            return False

        # Check 7z magic bytes: "7z\xBC\xAF\x27\x1C"
        try:
            with open(path, "rb") as f:
                magic = f.read(6)
                return magic == b"7z\xbc\xaf\x27\x1c"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a 7-Zip archive file"""
        # Check if py7zr is available
        if not HAS_PY7ZR:
            result = self._create_result()
            result.add_issue(
                message=(
                    "py7zr library not installed. "
                    "Install with 'pip install py7zr' or 'pip install modelaudit[sevenzip]'"
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "error_type": "missing_dependency",
                    "required_package": "py7zr",
                    "install_command": "pip install py7zr",
                },
            )
            result.finish(success=False)
            return result

        # Standard path and size validation
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        result.metadata["archive_type"] = "7z"

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            with py7zr.SevenZipFile(path, mode="r") as archive:
                # Get file listing
                file_names = archive.getnames()
                result.metadata["total_files"] = len(file_names)

                # Check for zip bomb protection
                if len(file_names) > self.max_entries:
                    result.add_issue(
                        message=f"7z archive contains {len(file_names)} files, exceeding limit of {self.max_entries}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "file_count": len(file_names),
                            "limit": self.max_entries,
                            "potential_threat": "zip_bomb",
                        },
                    )
                    result.finish(success=False)
                    return result

                # Check for path traversal vulnerabilities
                self._check_path_traversal(file_names, path, result)

                # Filter for scannable model files
                scannable_files = self._identify_scannable_files(file_names)
                result.metadata["scannable_files"] = len(scannable_files)

                if not scannable_files:
                    result.add_check(
                        name="Archive Content Check",
                        passed=True,
                        message=f"No scannable model files found in 7z archive (found {len(file_names)} total files)",
                        location=path,
                    )
                    result.finish(success=True)
                    return result

                # Extract and scan scannable files
                self._extract_and_scan_files(archive, scannable_files, path, result)

        except py7zr.Bad7zFile as e:
            result.add_check(
                name="7z File Format Validation",
                passed=False,
                message=f"Invalid 7z file format: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e), "error_type": "invalid_format"},
            )
            result.finish(success=False)
            return result

        except Exception as e:
            result.add_check(
                name="7z Archive Scan",
                passed=False,
                message=f"Failed to scan 7z archive: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": "scan_failure"},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _identify_scannable_files(self, file_names: list[str]) -> list[str]:
        """Identify files that can be scanned for security issues"""
        scannable_extensions = {
            ".pkl",
            ".pickle",  # Pickle files
            ".pt",
            ".pth",  # PyTorch files
            ".bin",  # Binary model files
            ".h5",  # HDF5/Keras files
            ".onnx",  # ONNX files
            ".json",  # JSON configuration files
            ".yaml",
            ".yml",  # YAML configuration files
            ".pb",  # TensorFlow protobuf files
        }

        scannable_files = []
        for file_name in file_names:
            # Get file extension
            _, ext = os.path.splitext(file_name.lower())
            if ext in scannable_extensions:
                scannable_files.append(file_name)

        return scannable_files

    def _check_path_traversal(self, file_names: list[str], archive_path: str, result: ScanResult) -> None:
        """Check for path traversal vulnerabilities in archive entries"""
        for file_name in file_names:
            # Use temporary directory as base for sanitization check
            temp_base = "/tmp/modelaudit_7z"  # Placeholder base directory
            sanitized_path, is_safe = sanitize_archive_path(file_name, temp_base)
            if not is_safe:
                result.add_issue(
                    message=f"Potential path traversal attempt in archive entry: {file_name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}:{file_name}",
                    details={
                        "original_path": file_name,
                        "sanitized_path": sanitized_path,
                        "threat_type": "path_traversal",
                    },
                )

    def _extract_and_scan_files(
        self, archive: Any, scannable_files: list[str], archive_path: str, result: ScanResult
    ) -> None:
        """Extract scannable files and run appropriate scanners on them"""
        with tempfile.TemporaryDirectory(prefix="modelaudit_7z_") as tmp_dir:
            try:
                # Extract all scannable files at once to avoid py7zr state issues
                archive.extract(path=tmp_dir, targets=scannable_files)

                # Scan each extracted file
                for file_name in scannable_files:
                    try:
                        extracted_path = os.path.join(tmp_dir, file_name)
                        if os.path.isfile(extracted_path):
                            # Check extracted file size
                            extracted_size = os.path.getsize(extracted_path)
                            if extracted_size > self.max_extract_size:
                                result.add_issue(
                                    message=f"Extracted file {file_name} is too large ({extracted_size} bytes)",
                                    severity=IssueSeverity.WARNING,
                                    location=f"{archive_path}:{file_name}",
                                    details={"extracted_size": extracted_size, "size_limit": self.max_extract_size},
                                )
                                continue

                            # Get appropriate scanner for the extracted file
                            self._scan_extracted_file(extracted_path, file_name, archive_path, result)
                        else:
                            # File was not extracted - log as warning
                            result.add_check(
                                name=f"File Extraction: {file_name}",
                                passed=False,
                                message=f"File {file_name} was not extracted successfully",
                                severity=IssueSeverity.WARNING,
                                location=f"{archive_path}:{file_name}",
                                details={"error": "file_not_found_after_extraction"},
                            )

                    except Exception as e:
                        result.add_check(
                            name=f"File Extraction: {file_name}",
                            passed=False,
                            message=f"Failed to extract and scan {file_name}: {e}",
                            severity=IssueSeverity.WARNING,
                            location=f"{archive_path}:{file_name}",
                            details={"error": str(e)},
                        )

            except Exception as e:
                result.add_check(
                    name="Archive Extraction",
                    passed=False,
                    message=f"Failed during archive extraction: {e}",
                    severity=IssueSeverity.WARNING,
                    location=archive_path,
                    details={"error": str(e)},
                )

    def _scan_extracted_file(
        self, extracted_path: str, original_name: str, archive_path: str, result: ScanResult
    ) -> None:
        """Scan an individual extracted file using the appropriate scanner"""
        try:
            # Import scanner registry to find appropriate scanner
            from . import get_scanner_for_file

            file_scanner = get_scanner_for_file(extracted_path)

            if file_scanner:
                # Scan the extracted file
                file_result = file_scanner.scan(extracted_path)

                # Adjust issue locations to show archive context
                for issue in file_result.issues:
                    issue.location = f"{archive_path}:{original_name}"
                    # Add archive context to details
                    if not issue.details:
                        issue.details = {}
                    issue.details["archive_path"] = archive_path
                    issue.details["extracted_from"] = original_name

                # Adjust check locations
                for check in file_result.checks:
                    check.location = f"{archive_path}:{original_name}"

                # Merge results
                result.issues.extend(file_result.issues)
                result.checks.extend(file_result.checks)
                result.metadata.update(file_result.metadata)

            else:
                # No scanner available for this file type
                result.add_check(
                    name=f"File Type Support: {original_name}",
                    passed=True,
                    message=f"No scanner available for file type: {original_name}",
                    location=f"{archive_path}:{original_name}",
                    details={"file_type": "unsupported"},
                )

        except Exception as e:
            result.add_check(
                name=f"File Scan: {original_name}",
                passed=False,
                message=f"Error scanning extracted file {original_name}: {e}",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{original_name}",
                details={"error": str(e)},
            )
