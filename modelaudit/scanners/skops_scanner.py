"""Scanner for skops serialized files.

Skops is a secure serialization format for scikit-learn models, but versions < 0.12.0
contain critical vulnerabilities (CVE-2025-54412, CVE-2025-54413, CVE-2025-54886).
"""

from __future__ import annotations

import json
import os
import re
import zipfile
from contextlib import suppress
from typing import Any, ClassVar

from ..utils.file.detection import is_skops_archive, read_magic_bytes
from ._archive_outcomes import mark_archive_scan_incomplete
from .archive_dispatch import SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult


class SkopsScanner(BaseScanner):
    """Scanner for skops serialized files (.skops format)."""

    name = "skops"
    description = "Scans skops files for CVE-2025-54412, CVE-2025-54413, CVE-2025-54886 vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".skops"]
    _OVERSIZED_ENTRY_REASON: ClassVar[str] = "skops_zip_entry_size_limited"
    _OVERSIZED_ENTRY_METADATA_KEY: ClassVar[str] = "oversized_zip_entries"
    _UNREADABLE_ENTRY_REASON: ClassVar[str] = "skops_zip_entry_read_failed"
    _UNREADABLE_ENTRY_METADATA_KEY: ClassVar[str] = "unreadable_zip_entries"
    _NOT_ZIP_REASON: ClassVar[str] = "skops_not_zip_archive"
    _BAD_ZIP_REASON: ClassVar[str] = "skops_bad_zip_file"
    _SCAN_FAILURE_REASON: ClassVar[str] = "skops_scan_failed"
    _FILE_COUNT_LIMIT_REASON: ClassVar[str] = "skops_archive_file_count_limited"
    _UNCOMPRESSED_SIZE_LIMIT_REASON: ClassVar[str] = "skops_archive_uncompressed_size_limited"
    _STRUCTURED_JSON_PARSE_REASON: ClassVar[str] = "skops_structured_json_parse_failed"
    _CVE_54412_LOADER: ClassVar[str] = "OperatorFuncNode"
    _CVE_54413_LOADER: ClassVar[str] = "MethodNode"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Security limits for decompression bomb protection
        self.max_file_size = self.config.get("max_skops_file_size", 500 * 1024 * 1024)  # 500MB
        self.max_files_in_archive = self.config.get("max_files_in_archive", 10000)
        self.max_zip_entry_read_size = self.config.get("max_zip_entry_read_size", 10 * 1024 * 1024)

    @staticmethod
    def _is_nested_array_payload(filename: str) -> bool:
        """Return True for Skops numeric payloads covered by nested archive scans."""
        return os.path.splitext(filename.lower())[1] in {".npy", ".npz"}

    def _record_oversized_zip_entry(
        self,
        result: ScanResult,
        zip_path: str,
        file_info: zipfile.ZipInfo,
    ) -> None:
        oversized_entries = result.metadata.setdefault(self._OVERSIZED_ENTRY_METADATA_KEY, [])
        if not isinstance(oversized_entries, list):
            oversized_entries = []
            result.metadata[self._OVERSIZED_ENTRY_METADATA_KEY] = oversized_entries

        if file_info.filename in oversized_entries:
            return

        oversized_entries.append(file_info.filename)
        result.add_check(
            name="Skops Oversized ZIP Entry",
            passed=False,
            message=(
                f"Skipped oversized ZIP entry {file_info.filename} "
                f"({file_info.file_size} bytes > {self.max_zip_entry_read_size} byte read limit)"
            ),
            severity=IssueSeverity.INFO,
            location=f"{zip_path}:{file_info.filename}",
            details={
                "entry": file_info.filename,
                "entry_size": file_info.file_size,
                "max_zip_entry_read_size": self.max_zip_entry_read_size,
                "analysis_incomplete": True,
                "scan_outcome_reason": self._OVERSIZED_ENTRY_REASON,
            },
            why=(
                "The scanner did not inspect this archive member because reading it would exceed the configured "
                "per-entry limit, so Skops CVE coverage for the archive is incomplete."
            ),
        )
        mark_archive_scan_incomplete(result, self._OVERSIZED_ENTRY_REASON)

    def _record_unreadable_zip_entry(
        self,
        result: ScanResult,
        zip_path: str,
        file_info: zipfile.ZipInfo,
        exc: Exception,
    ) -> None:
        unreadable_entries = result.metadata.setdefault(self._UNREADABLE_ENTRY_METADATA_KEY, [])
        if not isinstance(unreadable_entries, list):
            unreadable_entries = []
            result.metadata[self._UNREADABLE_ENTRY_METADATA_KEY] = unreadable_entries

        if file_info.filename in unreadable_entries:
            return

        unreadable_entries.append(file_info.filename)
        result.add_check(
            name="Skops ZIP Entry Read",
            passed=False,
            message=f"Unable to read ZIP entry {file_info.filename} for Skops analysis: {exc}",
            severity=IssueSeverity.INFO,
            location=f"{zip_path}:{file_info.filename}",
            details={
                "entry": file_info.filename,
                "exception_type": type(exc).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": self._UNREADABLE_ENTRY_REASON,
            },
            why="Skops CVE coverage is incomplete because this archive member could not be read.",
        )
        mark_archive_scan_incomplete(result, self._UNREADABLE_ENTRY_REASON)

    def _read_zip_entry_safely(
        self,
        zip_file: zipfile.ZipFile,
        file_info: zipfile.ZipInfo,
        *,
        result: ScanResult | None = None,
        zip_path: str | None = None,
    ) -> bytes | None:
        """Read a ZIP entry with a bounded memory limit."""
        if file_info.file_size > self.max_zip_entry_read_size:
            if result is not None and zip_path is not None and not self._is_nested_array_payload(file_info.filename):
                self._record_oversized_zip_entry(result, zip_path, file_info)
            return None

        try:
            with zip_file.open(file_info, "r") as entry:
                content = entry.read(self.max_zip_entry_read_size + 1)
        except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            if result is not None and zip_path is not None and not self._is_nested_array_payload(file_info.filename):
                self._record_unreadable_zip_entry(result, zip_path, file_info, exc)
            return None

        if len(content) > self.max_zip_entry_read_size:
            if result is not None and zip_path is not None and not self._is_nested_array_payload(file_info.filename):
                self._record_oversized_zip_entry(result, zip_path, file_info)
            return None

        return content

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the file."""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext == ".skops":
            return True

        return is_skops_archive(path)

    def _detect_cve_2025_54412(self, zip_file: zipfile.ZipFile, result: ScanResult, zip_path: str) -> None:
        """Detect CVE-2025-54412: OperatorFuncNode trusted-type confusion.

        This CVE allows arbitrary code execution through malicious OperatorFuncNode
        objects that bypass trusted type validation.
        """
        found_patterns = self._find_structured_loader_references(
            zip_file,
            result,
            zip_path,
            loader_name=self._CVE_54412_LOADER,
        )

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

    def _detect_cve_2025_54413(self, zip_file: zipfile.ZipFile, result: ScanResult, zip_path: str) -> None:
        """Detect CVE-2025-54413: MethodNode inconsistency → dangerous attribute access.

        This CVE allows dangerous attribute access through inconsistent MethodNode objects.
        """
        found_patterns = self._find_structured_loader_references(
            zip_file,
            result,
            zip_path,
            loader_name=self._CVE_54413_LOADER,
        )

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
                with suppress(Exception):
                    raw_content = self._read_zip_entry_safely(zip_file, file_info, result=result, zip_path=zip_path)
                    if raw_content is None:
                        continue

                    content = raw_content.decode("utf-8", errors="ignore")
                    # Require explicit joblib/pickle fallback evidence; avoid generic
                    # substrings such as "download" in benign card/readme prose.
                    if self._contains_card_joblib_fallback_signal(content):
                        suspicious_files.append(file_info.filename)

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
        with suppress(Exception):
            # Check for schema or version files
            for file_name in zip_file.namelist():
                lowered_file_name = file_name.lower()
                if "schema" in lowered_file_name or "version" in lowered_file_name or "protocol" in lowered_file_name:
                    file_info = zip_file.getinfo(file_name)
                    raw_content = self._read_zip_entry_safely(zip_file, file_info, result=result, zip_path=zip_path)
                    if raw_content is None:
                        continue

                    content = raw_content.decode("utf-8", errors="ignore")

                    # Check for protocol version indicators
                    if "PROTOCOL" in content or "version" in content.lower():
                        # Parse version if possible
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

    # Metadata files that are part of the skops format and should be excluded
    # from joblib fallback pattern matching. These files legitimately contain
    # strings like "sklearn" as type references, not as pickle/joblib code.
    _SKOPS_METADATA_FILES: ClassVar[frozenset[str]] = frozenset(
        {
            "schema.json",
            "schema",
        }
    )
    _CARD_GET_MODEL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\bget_model\b", re.IGNORECASE)
    _CARD_JOBLIB_FALLBACK_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\bjoblib(?:\.load)?\b|\bpickle\.load\b",
        re.IGNORECASE,
    )
    _CARD_DIRECT_FALLBACK_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:joblib|pickle)\.load\b",
        re.IGNORECASE,
    )

    @classmethod
    def _is_skops_metadata(cls, filename: str) -> bool:
        """Return True if *filename* is a known skops metadata/schema file.

        Only the basename is checked so that nested paths like
        ``subdir/schema.json`` are also excluded.
        """
        basename = os.path.basename(filename).lower()
        return basename in cls._SKOPS_METADATA_FILES

    @classmethod
    def _contains_card_joblib_fallback_signal(cls, content: str) -> bool:
        """Return True when model-card text references an explicit joblib/pickle fallback."""
        if cls._CARD_DIRECT_FALLBACK_PATTERN.search(content):
            return True

        return bool(cls._CARD_GET_MODEL_PATTERN.search(content) and cls._CARD_JOBLIB_FALLBACK_PATTERN.search(content))

    @staticmethod
    def _contains_malicious_loader_state(value: Any, loader_name: str) -> bool:
        """Return whether decoded Skops JSON contains an exploit-shaped loader node."""
        if isinstance(value, dict):
            if value.get("__loader__") == loader_name:
                if loader_name == SkopsScanner._CVE_54412_LOADER:
                    return value.get("__module__") != "operator"
                if loader_name == SkopsScanner._CVE_54413_LOADER:
                    content = value.get("content")
                    obj = content.get("obj") if isinstance(content, dict) else None
                    if isinstance(obj, dict):
                        return value.get("__module__") != obj.get("__module__") or value.get("__class__") != obj.get(
                            "__class__"
                        )
            return any(SkopsScanner._contains_malicious_loader_state(child, loader_name) for child in value.values())
        elif isinstance(value, list):
            return any(SkopsScanner._contains_malicious_loader_state(child, loader_name) for child in value)
        return False

    def _find_structured_loader_references(
        self,
        zip_file: zipfile.ZipFile,
        result: ScanResult,
        zip_path: str,
        *,
        loader_name: str,
    ) -> list[str]:
        """Find exploit-shaped loader states inside authoritative Skops schema documents."""
        matches: list[str] = []
        for file_info in zip_file.filelist:
            raw_content = self._read_zip_entry_safely(zip_file, file_info, result=result, zip_path=zip_path)
            if raw_content is None or not self._is_skops_metadata(file_info.filename):
                continue
            try:
                decoded = json.loads(raw_content)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                if not any(
                    check.name == "Skops Structured JSON Parse Check"
                    and check.details.get("entry") == file_info.filename
                    for check in result.checks
                ):
                    result.add_check(
                        name="Skops Structured JSON Parse Check",
                        passed=False,
                        message=f"Unable to parse Skops JSON entry {file_info.filename}: {exc}",
                        severity=IssueSeverity.INFO,
                        location=f"{zip_path}:{file_info.filename}",
                        details={
                            "entry": file_info.filename,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": self._STRUCTURED_JSON_PARSE_REASON,
                        },
                        why="Structured Skops loader inspection was incomplete for this archive member.",
                    )
                mark_archive_scan_incomplete(result, self._STRUCTURED_JSON_PARSE_REASON)
                continue

            if self._contains_malicious_loader_state(decoded, loader_name):
                matches.append(f"loader: {loader_name} in {file_info.filename}")
        return matches

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
            is_metadata = self._is_skops_metadata(file_info.filename)

            with suppress(Exception):
                content = self._read_zip_entry_safely(zip_file, file_info, result=result, zip_path=zip_path)
                if content is None:
                    continue
                for pattern in joblib_patterns:
                    # Only suppress the broad `sklearn` heuristic for metadata
                    # files; explicit signals like `joblib.load` / `pickle.load`
                    # must still be reported even inside schema.json.
                    if is_metadata and pattern == b"sklearn":
                        continue
                    if pattern in content:
                        files_with_joblib.append(
                            {
                                "file": file_info.filename,
                                "pattern": pattern.decode("utf-8", errors="ignore"),
                            }
                        )
                        break

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

    def _scan_archive_members(self, path: str, result: ScanResult) -> None:
        """Recursively scan embedded archive members through the generic ZIP pipeline."""
        if self.config.get(SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY):
            return

        from .zip_scanner import ZipScanner

        zip_scanner = ZipScanner(config=self.config)
        result.merge(zip_scanner.scan_archive_members(path))

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
            if not magic.startswith(b"PK") and not zipfile.is_zipfile(path):
                result.add_check(
                    name="Skops File Format Check",
                    passed=False,
                    message="File does not appear to be a valid skops file (not a ZIP archive)",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"magic_bytes": magic.hex()},
                )
                mark_archive_scan_incomplete(result, self._NOT_ZIP_REASON)
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
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "file_count": len(file_list),
                            "max_files": self.max_files_in_archive,
                        },
                        why="Excessive number of files may indicate a decompression bomb attack",
                    )
                    mark_archive_scan_incomplete(result, self._FILE_COUNT_LIMIT_REASON)
                    result.finish(success=False)
                    return result

                result.metadata["file_count"] = len(file_list)
                result.metadata["files"] = file_list[:100]  # Store first 100 files

                total_uncompressed_size = sum(file_info.file_size for file_info in zip_file.filelist)
                result.metadata["archive_uncompressed_size"] = total_uncompressed_size

                if total_uncompressed_size > self.max_file_size:
                    result.add_check(
                        name="Archive Uncompressed Size Limit",
                        passed=False,
                        message=(
                            "Suspicious: Archive uncompressed content exceeds configured skops size limit "
                            f"({total_uncompressed_size} bytes > {self.max_file_size} bytes)"
                        ),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={
                            "archive_uncompressed_size": total_uncompressed_size,
                            "max_skops_file_size": self.max_file_size,
                        },
                        why=(
                            "Large uncompressed archive content may indicate a decompression bomb that can "
                            "exhaust memory during scanning."
                        ),
                    )
                    mark_archive_scan_incomplete(result, self._UNCOMPRESSED_SIZE_LIMIT_REASON)
                    result.finish(success=False)
                    return result

                # Run CVE detection checks (with content analysis)
                self._detect_cve_2025_54412(zip_file, result, path)
                self._detect_cve_2025_54413(zip_file, result, path)
                self._detect_cve_2025_54886(zip_file, result, path)

                # Check protocol version
                self._check_protocol_version(zip_file, result, path)

                # Check for unsafe joblib fallback
                self._check_unsafe_joblib_fallback(zip_file, result, path)

                # Recursively scan embedded members with the broader scanner suite.
                self._scan_archive_members(path, result)

                # Add file integrity check
                self.add_file_integrity_check(path, result)

                result.bytes_scanned += file_size

        except zipfile.BadZipFile:
            result.add_check(
                name="Skops File Format Check",
                passed=False,
                message="Invalid ZIP file - may be corrupted or malicious",
                severity=IssueSeverity.INFO,
                location=path,
            )
            mark_archive_scan_incomplete(result, self._BAD_ZIP_REASON)
            result.finish(success=False)
            return result
        except Exception as e:
            mark_archive_scan_incomplete(result, self._SCAN_FAILURE_REASON)
            result.add_check(
                name="Skops File Scan",
                passed=False,
                message=f"Error scanning skops file: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._SCAN_FAILURE_REASON,
                },
            )
            result.finish(success=False)
            return result

        result.finish(
            success=not result.has_errors and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        )
        return result
