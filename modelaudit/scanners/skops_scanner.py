"""Scanner for skops serialized files.

Skops is a secure serialization format for scikit-learn models, but versions < 0.12.0
contain critical vulnerabilities (CVE-2025-54412, CVE-2025-54413, CVE-2025-54886).
"""

from __future__ import annotations

import os
import zipfile
from typing import Any, ClassVar

from ..utils.file.detection import read_magic_bytes
from .base import BaseScanner, IssueSeverity, ScanResult


class SkopsScanner(BaseScanner):
    """Scanner for skops serialized files (.skops format)."""

    name = "skops"
    description = "Scans skops files for CVE-2025-54412, CVE-2025-54413, CVE-2025-54886 vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".skops"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Security limits for decompression bomb protection
        self.max_file_size = self.config.get("max_skops_file_size", 500 * 1024 * 1024)  # 500MB
        self.max_files_in_archive = self.config.get("max_files_in_archive", 10000)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the file."""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext == ".skops":
            return True

        # Also check magic bytes for ZIP signature (skops files are ZIP archives)
        try:
            magic = read_magic_bytes(path, 4)
            # Check if it's a ZIP file with .skops extension or contains skops metadata
            if magic.startswith(b"PK") and ext == ".skops":
                return True
        except Exception:
            pass

        return False

    def _detect_cve_2025_54412(self, result: ScanResult, zip_path: str, file_list: list[str]) -> None:
        """Detect CVE-2025-54412: OperatorFuncNode trusted-type confusion.

        This CVE allows arbitrary code execution through malicious OperatorFuncNode
        objects that bypass trusted type validation.
        """
        # Check for OperatorFuncNode patterns in file structure
        suspicious_patterns = [
            "OperatorFuncNode",
            "operator.func",
            "trusted_types",
            "__reduce__",
            "get_state",
        ]

        # Look for suspicious patterns in ZIP file names and metadata
        found_patterns = []
        for file_name in file_list:
            for pattern in suspicious_patterns:
                if pattern.lower() in file_name.lower():
                    found_patterns.append(f"{pattern} in {file_name}")

        if found_patterns:
            result.add_check(
                name="CVE-2025-54412 Detection",
                passed=False,
                message="Detected OperatorFuncNode patterns - potential CVE-2025-54412 exploitation",
                severity=IssueSeverity.CRITICAL,
                location=zip_path,
                details={
                    "cve_id": "CVE-2025-54412",
                    "cvss": "9.8 (Critical)",
                    "cwe": "CWE-502: Deserialization of Untrusted Data",
                    "affected_versions": "skops < 0.12.0",
                    "patterns_matched": found_patterns,
                    "vulnerability": "OperatorFuncNode trusted-type confusion",
                    "remediation": "Upgrade to skops >= 0.12.0",
                },
                why=(
                    "CVE-2025-54412 allows arbitrary code execution through malicious OperatorFuncNode "
                    "objects that bypass trusted type validation. Affected versions: skops < 0.12.0. "
                    "Remediation: Upgrade to skops >= 0.12.0"
                ),
            )

    def _detect_cve_2025_54413(self, result: ScanResult, zip_path: str, file_list: list[str]) -> None:
        """Detect CVE-2025-54413: MethodNode inconsistency → dangerous attribute access.

        This CVE allows dangerous attribute access through inconsistent MethodNode objects.
        """
        suspicious_patterns = [
            "MethodNode",
            "__getattr__",
            "__setattr__",
            "method_node",
            "getattr",
        ]

        found_patterns = []
        for file_name in file_list:
            for pattern in suspicious_patterns:
                if pattern.lower() in file_name.lower():
                    found_patterns.append(f"{pattern} in {file_name}")

        if found_patterns:
            result.add_check(
                name="CVE-2025-54413 Detection",
                passed=False,
                message="Detected MethodNode patterns - potential CVE-2025-54413 exploitation",
                severity=IssueSeverity.CRITICAL,
                location=zip_path,
                details={
                    "cve_id": "CVE-2025-54413",
                    "cvss": "9.8 (Critical)",
                    "cwe": "CWE-502: Deserialization of Untrusted Data",
                    "affected_versions": "skops < 0.12.0",
                    "patterns_matched": found_patterns,
                    "vulnerability": "MethodNode inconsistency allows dangerous attribute access",
                    "remediation": "Upgrade to skops >= 0.12.0",
                },
                why=(
                    "CVE-2025-54413 allows dangerous attribute access through inconsistent MethodNode "
                    "objects. Affected versions: skops < 0.12.0. "
                    "Remediation: Upgrade to skops >= 0.12.0"
                ),
            )

    def _detect_cve_2025_54886(self, zip_file: zipfile.ZipFile, result: ScanResult, zip_path: str) -> None:
        """Detect CVE-2025-54886: Card.get_model silent joblib fallback → code execution.

        This CVE allows code execution through Card.get_model's unsafe joblib fallback.
        """
        # Look for Card metadata and joblib patterns
        suspicious_files = []

        for file_info in zip_file.filelist:
            file_name = file_info.filename.lower()
            # Check for Card/model card files
            if "card" in file_name or "model_card" in file_name or "readme" in file_name:
                try:
                    content = zip_file.read(file_info).decode("utf-8", errors="ignore")
                    # Check for get_model or joblib references
                    if "get_model" in content or "joblib" in content or "load" in content:
                        suspicious_files.append(file_info.filename)
                except Exception:
                    pass

        if suspicious_files:
            result.add_check(
                name="CVE-2025-54886 Detection",
                passed=False,
                message="Detected Card.get_model with potential joblib fallback - CVE-2025-54886 risk",
                severity=IssueSeverity.CRITICAL,
                location=zip_path,
                details={
                    "cve_id": "CVE-2025-54886",
                    "cvss": "9.8 (Critical)",
                    "cwe": "CWE-502: Deserialization of Untrusted Data",
                    "affected_versions": "skops < 0.12.0",
                    "suspicious_files": suspicious_files,
                    "vulnerability": "Card.get_model silent joblib fallback",
                    "remediation": "Upgrade to skops >= 0.12.0",
                },
                why=(
                    "CVE-2025-54886: Card.get_model silently falls back to unsafe joblib deserialization "
                    "when skops parsing fails, enabling arbitrary code execution. "
                    "Affected versions: skops < 0.12.0. Remediation: Upgrade to skops >= 0.12.0"
                ),
            )

    def _check_protocol_version(self, zip_file: zipfile.ZipFile, result: ScanResult, zip_path: str) -> None:
        """Check skops protocol version and warn if using vulnerable version."""
        # Look for protocol version information
        try:
            # Check for schema or version files
            for file_name in zip_file.namelist():
                if "schema" in file_name.lower() or "version" in file_name.lower() or "protocol" in file_name.lower():
                    content = zip_file.read(file_name).decode("utf-8", errors="ignore")

                    # Check for protocol version indicators
                    if "PROTOCOL" in content or "version" in content.lower():
                        # Parse version if possible
                        import re

                        version_pattern = r"(?:PROTOCOL|version)\s*=\s*['\"]?([0-9.]+)"
                        match = re.search(version_pattern, content, re.IGNORECASE)

                        if match:
                            version = match.group(1)
                            result.add_check(
                                name="Skops Protocol Version Check",
                                passed=True,
                                message=f"Detected skops protocol version: {version}",
                                severity=IssueSeverity.INFO,
                                location=f"{zip_path}:{file_name}",
                                details={
                                    "protocol_version": version,
                                    "file": file_name,
                                },
                            )
        except Exception:
            pass

    def _check_unsafe_joblib_fallback(self, zip_file: zipfile.ZipFile, result: ScanResult, zip_path: str) -> None:
        """Check for unsafe joblib fallback patterns in skops files."""
        # Scan all files for joblib deserialization patterns
        joblib_patterns = [
            b"joblib.load",
            b"sklearn",
            b"pickle.load",
            b"_pickle",
        ]

        files_with_joblib = []

        for file_info in zip_file.filelist:
            try:
                content = zip_file.read(file_info)
                for pattern in joblib_patterns:
                    if pattern in content:
                        files_with_joblib.append(
                            {
                                "file": file_info.filename,
                                "pattern": pattern.decode("utf-8", errors="ignore"),
                            }
                        )
                        break
            except Exception:
                pass

        if files_with_joblib:
            result.add_check(
                name="Unsafe Joblib Fallback Detection",
                passed=False,
                message=f"Detected {len(files_with_joblib)} files with joblib/pickle patterns",
                severity=IssueSeverity.WARNING,
                location=zip_path,
                details={
                    "files_with_joblib": files_with_joblib[:10],  # Limit to first 10
                    "total_count": len(files_with_joblib),
                    "risk": "Unsafe deserialization through joblib fallback",
                },
                why=(
                    "Skops files should not contain joblib or pickle deserialization patterns. "
                    "This may indicate use of vulnerable Card.get_model with unsafe fallback."
                ),
            )

    def scan(self, path: str) -> ScanResult:
        """Scan a skops file for security vulnerabilities."""
        # Perform standard path checks
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path

            # Verify it's a ZIP file
            magic = read_magic_bytes(path, 4)
            if not magic.startswith(b"PK"):
                result.add_check(
                    name="Skops File Format Check",
                    passed=False,
                    message="File does not appear to be a valid skops file (not a ZIP archive)",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"magic_bytes": magic.hex()},
                )
                result.finish(success=False)
                return result

            # Open as ZIP archive
            with zipfile.ZipFile(path, "r") as zip_file:
                # Get file list
                file_list = zip_file.namelist()

                # Check for too many files (decompression bomb indicator)
                if len(file_list) > self.max_files_in_archive:
                    result.add_check(
                        name="Archive Bomb Detection",
                        passed=False,
                        message=(
                            f"Suspicious: Archive contains {len(file_list)} files (max: {self.max_files_in_archive})"
                        ),
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "file_count": len(file_list),
                            "max_files": self.max_files_in_archive,
                        },
                        why="Excessive number of files may indicate a decompression bomb attack",
                    )
                    result.finish(success=False)
                    return result

                result.metadata["file_count"] = len(file_list)
                result.metadata["files"] = file_list[:100]  # Store first 100 files

                # Run CVE detection checks
                self._detect_cve_2025_54412(result, path, file_list)
                self._detect_cve_2025_54413(result, path, file_list)
                self._detect_cve_2025_54886(zip_file, result, path)

                # Check protocol version
                self._check_protocol_version(zip_file, result, path)

                # Check for unsafe joblib fallback
                self._check_unsafe_joblib_fallback(zip_file, result, path)

                # Add file integrity check
                self.add_file_integrity_check(path, result)

                result.bytes_scanned = file_size

        except zipfile.BadZipFile:
            result.add_check(
                name="Skops File Format Check",
                passed=False,
                message="Invalid ZIP file - may be corrupted or malicious",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_check(
                name="Skops File Scan",
                passed=False,
                message=f"Error scanning skops file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
