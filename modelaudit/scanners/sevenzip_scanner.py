"""Scanner for 7-Zip compressed model archives (.7z)."""

import io
import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
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


class _HeaderProbeComplete(Exception):
    """Internal signal used to stop a header probe once enough bytes are captured."""


class _HeaderProbeBuffer:
    def __init__(self, limit: int, *, raise_on_limit: bool = True) -> None:
        self._limit = limit
        self._raise_on_limit = raise_on_limit
        self._buffer = io.BytesIO()

    def write(self, data: bytes | bytearray) -> int:
        if not data:
            return 0
        remaining = self._limit - self.size()
        if remaining > 0:
            self._buffer.write(data[:remaining])
        if self.size() >= self._limit and self._raise_on_limit:
            raise _HeaderProbeComplete
        return len(data)

    def read(self, size: int | None = None) -> bytes:
        return self._buffer.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._buffer.seek(offset, whence)

    def flush(self) -> None:
        self._buffer.flush()

    def size(self) -> int:
        return self._buffer.getbuffer().nbytes


class _HeaderProbeFactory:
    def __init__(self, limit: int, *, raise_on_limit: bool = True) -> None:
        self._limit = limit
        self._raise_on_limit = raise_on_limit
        self.products: dict[str, _HeaderProbeBuffer] = {}

    def create(self, filename: str) -> _HeaderProbeBuffer:
        probe = _HeaderProbeBuffer(self._limit, raise_on_limit=self._raise_on_limit)
        self.products[filename] = probe
        return probe

    def get(self, filename: str) -> _HeaderProbeBuffer | None:
        return self.products.get(filename)


@dataclass
class _RecursiveScanBudget:
    cumulative_entries: int = 0
    cumulative_extract_bytes: int = 0
    limit_exceeded: bool = False

    def record_entries(self, entry_count: int) -> int:
        self.cumulative_entries += entry_count
        return self.cumulative_entries

    def record_extract_bytes(self, extracted_size: int) -> int:
        self.cumulative_extract_bytes += extracted_size
        return self.cumulative_extract_bytes

    def abort_due_to_limit(self) -> None:
        self.limit_exceeded = True

    def should_stop(self) -> bool:
        return self.limit_exceeded


class SevenZipScanner(BaseScanner):
    """Scanner for 7-Zip archive files (.7z)

    This scanner extracts and scans model files contained within 7-Zip archives,
    looking for malicious content that could be hidden in compressed formats.
    """

    name = "sevenzip"
    description = "Scans 7-Zip archives for malicious model files"
    supported_extensions: ClassVar[list[str]] = [".7z"]
    _SEVENZIP_MAGIC: ClassVar[bytes] = b"7z\xbc\xaf\x27\x1c"

    _MAX_EXTENSIONLESS_PROBES: ClassVar[int] = 100
    _MAX_TOTAL_EXTRACT_SIZE: ClassVar[int] = 5 * 1024 * 1024 * 1024  # 5 GB
    _MAX_CUMULATIVE_ENTRIES: ClassVar[int] = 50000
    _NESTED_CORE_EXTENSION_EXCLUSIONS: ClassVar[frozenset[str]] = frozenset(
        {".txt", ".md", ".markdown", ".rst", ".j2", ".jinja", ".template"},
    )
    _LOW_VALUE_NESTED_PROBE_EXTENSIONS: ClassVar[frozenset[str]] = frozenset(
        {
            ".txt",
            ".md",
            ".markdown",
            ".rst",
            ".json",
            ".yaml",
            ".yml",
            ".xml",
            ".ini",
            ".cfg",
            ".conf",
            ".toml",
            ".csv",
            ".tsv",
            ".log",
            ".html",
            ".css",
            ".scss",
            ".sass",
            ".less",
            ".js",
            ".ts",
            ".py",
            ".java",
            ".c",
            ".cpp",
            ".h",
            ".go",
            ".rs",
            ".sh",
            ".bat",
            ".ps1",
        }
    )
    _COMMON_NESTED_DISGUISE_EXTENSIONS: ClassVar[frozenset[str]] = frozenset(
        {
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".svg",
            ".ico",
            ".webp",
            ".pdf",
            ".doc",
            ".docx",
            ".ppt",
            ".pptx",
            ".xls",
            ".xlsx",
            ".bin",
            ".dat",
        }
    )
    _SUSPICIOUS_NESTED_PROBE_TOKENS: ClassVar[frozenset[str]] = frozenset(
        {"model", "weight", "tensor", "checkpoint", "archive", "payload", "nested", "data"},
    )

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_depth = self._normalize_positive_int_config(
            self.config.get("max_7z_depth"),
            5,
        )
        self.max_entries = self._normalize_positive_int_config(
            self.config.get("max_7z_entries"),
            10000,
        )
        self.max_extract_size = self._normalize_positive_int_config(
            self.config.get("max_7z_extract_size"),
            1024 * 1024 * 1024,
        )
        self.max_extensionless_probes = self._normalize_positive_int_config(
            self.config.get("max_7z_extensionless_probes"),
            self._MAX_EXTENSIONLESS_PROBES,
        )
        self.max_total_extract_size = self._normalize_positive_int_config(
            self.config.get("max_7z_total_extract_size"),
            self._MAX_TOTAL_EXTRACT_SIZE,
        )
        self.max_cumulative_entries = self._normalize_positive_int_config(
            self.config.get("max_7z_cumulative_entries"),
            self._MAX_CUMULATIVE_ENTRIES,
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not HAS_PY7ZR:
            return False

        if not os.path.isfile(path):
            return False

        return cls._has_7z_magic(path)

    def _get_archive_depth(self) -> int:
        """Return the current shared archive depth from config."""
        raw_depth = self.config.get("_archive_depth", 0)
        try:
            depth = int(raw_depth)
        except (TypeError, ValueError):
            return 0
        return max(depth, 0)

    @classmethod
    def _supported_nested_core_extensions(cls) -> frozenset[str]:
        """Return supported nested member suffixes routed through shared core scanning."""
        from . import _registry

        extensions: set[str] = set()
        for scanner_id in _registry.get_available_scanners():
            scanner_info = _registry.get_scanner_info(scanner_id)
            if scanner_info is None:
                continue

            for extension in scanner_info.get("extensions", []):
                extension_lower = extension.lower()
                if not extension_lower or extension_lower in cls._NESTED_CORE_EXTENSION_EXCLUSIONS:
                    continue
                extensions.add(extension_lower)

        return frozenset(extensions)

    @staticmethod
    def _candidate_archive_extensions(file_name: str) -> list[str]:
        """Return candidate suffixes for an archive member, longest-first."""
        suffixes = [suffix.lower() for suffix in Path(file_name).suffixes]
        candidates: list[str] = []
        for i in range(len(suffixes), 0, -1):
            candidate = "".join(suffixes[-i:])
            if candidate and candidate not in candidates:
                candidates.append(candidate)
        return candidates

    @classmethod
    def _has_7z_magic(cls, path: str) -> bool:
        """Check whether a file starts with the 7z magic bytes."""
        try:
            with open(path, "rb") as f:
                magic = f.read(6)
                return magic == cls._SEVENZIP_MAGIC
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a 7-Zip archive file"""
        # Check if py7zr is available
        if not HAS_PY7ZR:
            result = self._create_result()
            result.add_check(
                name="Missing Dependency",
                passed=False,
                message=(
                    "py7zr library not installed. "
                    "Install with 'pip install py7zr' or 'pip install modelaudit[sevenzip]'"
                ),
                severity=IssueSeverity.WARNING,
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
            scan_result = self._scan_7z_file(path, depth=self._get_archive_depth())
            result.merge(scan_result)

        except py7zr.Bad7zFile as e:
            result.add_check(
                name="7z File Format Validation",
                passed=False,
                message=f"Invalid 7z file format: {e}",
                severity=IssueSeverity.INFO,
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

        result.metadata["file_size"] = file_size
        result.metadata["archive_type"] = "7z"
        result.finish(success=scan_result.success and not result.has_errors)
        return result

    def _scan_7z_file(
        self,
        path: str,
        depth: int = 0,
        budget: _RecursiveScanBudget | None = None,
    ) -> ScanResult:
        """Recursively scan a 7-Zip archive and its contents."""
        if budget is None:
            budget = _RecursiveScanBudget()

        result = ScanResult(scanner_name=self.name, scanner=self)
        scan_complete = True

        if budget.should_stop():
            result.finish(success=False)
            return result

        if depth >= self.max_depth:
            result.add_check(
                name="7z Depth Bomb Protection",
                passed=False,
                message=f"Maximum 7z nesting depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"depth": depth, "max_depth": self.max_depth},
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="7z Depth Bomb Protection",
            passed=True,
            message="7z nesting depth is within safe limits",
            location=path,
            details={"depth": depth, "max_depth": self.max_depth},
        )

        with py7zr.SevenZipFile(path, mode="r") as archive:
            # Get file listing
            file_names = archive.getnames()

            # Check per-archive entry limit
            if len(file_names) > self.max_entries:
                budget.abort_due_to_limit()
                result.add_check(
                    name="Archive Entry Limit",
                    passed=False,
                    message=f"7z archive contains {len(file_names)} files, exceeding limit of {self.max_entries}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "file_count": len(file_names),
                        "limit": self.max_entries,
                        "potential_threat": "zip_bomb",
                    },
                )
                result.metadata["total_files"] = len(file_names)
                result.metadata["scannable_files"] = 0
                result.metadata["unsafe_entries"] = 0
                result.metadata["file_size"] = os.path.getsize(path)
                result.finish(success=False)
                return result

            # Check cumulative entry count across nesting depths
            cumulative_entries = budget.record_entries(len(file_names))
            if cumulative_entries > self.max_cumulative_entries:
                budget.abort_due_to_limit()
                result.add_check(
                    name="Cumulative Entry Limit",
                    passed=False,
                    message=(
                        f"Cumulative entry count ({cumulative_entries}) across nested "
                        f"archives exceeds limit of {self.max_cumulative_entries}"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "cumulative_entries": cumulative_entries,
                        "limit": self.max_cumulative_entries,
                        "potential_threat": "nested_zip_bomb",
                    },
                )
                result.metadata["total_files"] = len(file_names)
                result.metadata["scannable_files"] = 0
                result.metadata["unsafe_entries"] = 0
                result.metadata["file_size"] = os.path.getsize(path)
                result.finish(success=False)
                return result

            # Check for path traversal vulnerabilities and only keep safe entries
            safe_file_names = self._check_path_traversal(file_names, path, result)
            if len(safe_file_names) < len(file_names):
                scan_complete = False

            # Filter for scannable model files from safe entries only
            scannable_files = self._identify_scannable_files(safe_file_names)
            nested_archive_files, probes_complete = self._identify_extensionless_nested_7z_files(
                archive,
                safe_file_names,
                path,
                result,
            )
            scannable_files.extend(nested_archive_files)
            if not probes_complete:
                scan_complete = False

            if not scannable_files:
                result.add_check(
                    name="Archive Content Check",
                    passed=True,
                    message=f"No scannable model files found in 7z archive (found {len(file_names)} total files)",
                    location=path,
                )
            else:
                # Extract and scan scannable files
                scan_complete = (
                    self._extract_and_scan_files(
                        archive,
                        scannable_files,
                        path,
                        result,
                        depth,
                        budget=budget,
                    )
                    and scan_complete
                )

            result.metadata["total_files"] = len(file_names)
            result.metadata["scannable_files"] = len(scannable_files)
            result.metadata["unsafe_entries"] = len(file_names) - len(safe_file_names)
            result.metadata["file_size"] = os.path.getsize(path)

        result.finish(success=scan_complete and not budget.should_stop() and not result.has_errors)
        return result

    def _identify_scannable_files(self, file_names: list[str]) -> list[str]:
        """Identify files that can be scanned for security issues"""
        supported_extensions = self._supported_nested_core_extensions()
        scannable_files: list[str] = []
        for file_name in file_names:
            candidate_extensions = self._candidate_archive_extensions(file_name)
            if any(extension in supported_extensions for extension in candidate_extensions):
                scannable_files.append(file_name)

        return scannable_files

    def _identify_extensionless_nested_7z_files(
        self, archive: Any, file_names: list[str], archive_path: str, result: ScanResult
    ) -> tuple[list[str], bool]:
        """Inspect likely disguised nested members and keep only confirmed 7z archives."""
        nested_archives: list[str] = []
        probes_complete = True
        probe_candidates: list[tuple[int, int, str]] = []
        supported_extensions = self._supported_nested_core_extensions()
        for index, file_name in enumerate(file_names):
            candidate_extensions = self._candidate_archive_extensions(file_name)
            if any(extension in supported_extensions for extension in candidate_extensions):
                continue

            member_info = None
            with suppress(Exception):
                member_info = archive.getinfo(file_name)

            if getattr(member_info, "is_directory", False) is True:
                continue

            priority = self._nested_probe_priority(file_name)
            if priority <= 0:
                continue

            probe_candidates.append((priority, index, file_name))

        if len(probe_candidates) > self.max_extensionless_probes:
            probes_complete = False
            result.add_check(
                name="Nested Member Probe Limit",
                passed=False,
                message=(
                    f"Nested member probe limit ({self.max_extensionless_probes}) "
                    f"reached; remaining unsupported members were not inspected"
                ),
                severity=IssueSeverity.WARNING,
                location=archive_path,
                details={"limit": self.max_extensionless_probes},
            )

        probe_candidates.sort(key=lambda item: (-item[0], item[1]))
        probe_targets = [file_name for _, _, file_name in probe_candidates[: self.max_extensionless_probes]]
        if not probe_targets:
            return nested_archives, probes_complete

        try:
            probe_results = self._probe_extensionless_members(archive, probe_targets)
            for file_name in probe_targets:
                if probe_results.get(file_name, False):
                    nested_archives.append(file_name)
            return nested_archives, probes_complete
        except Exception:
            # Fall back to per-member probing if the fast path fails against a
            # particular archive layout or py7zr behavior.
            pass

        for file_name in probe_targets:
            try:
                if self._member_has_7z_magic(archive, file_name):
                    nested_archives.append(file_name)
            except Exception as e:
                probes_complete = False
                result.add_check(
                    name=f"Nested 7z Probe: {file_name}",
                    passed=False,
                    message=f"Failed to inspect nested archive candidate {file_name}: {e}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{file_name}",
                    details={"error": str(e)},
                )

        return nested_archives, probes_complete

    @classmethod
    def _nested_probe_priority(cls, file_name: str) -> int:
        """Score unsupported members so likely nested-archive disguises consume probe budget first."""
        candidate_extensions = cls._candidate_archive_extensions(file_name)
        if not candidate_extensions:
            return 5

        leaf_extension = Path(file_name).suffix.lower()
        if not leaf_extension:
            leaf_extension = candidate_extensions[-1]
        if leaf_extension in cls._LOW_VALUE_NESTED_PROBE_EXTENSIONS:
            return 1

        priority = 2
        if leaf_extension in cls._COMMON_NESTED_DISGUISE_EXTENSIONS:
            priority = 4

        basename = Path(file_name).name.lower()
        if any(token in basename for token in cls._SUSPICIOUS_NESTED_PROBE_TOKENS):
            priority += 1

        return priority

    def _probe_extensionless_members(self, archive: Any, file_names: list[str]) -> dict[str, bool]:
        """Batch probe extensionless members in one pass to avoid repeated archive resets."""
        probe_factory = _HeaderProbeFactory(
            limit=len(self._SEVENZIP_MAGIC),
            raise_on_limit=False,
        )

        try:
            archive.extract(targets=file_names, factory=probe_factory)
        finally:
            with suppress(Exception):
                archive.reset()

        return {file_name: self._probe_has_7z_magic(probe_factory.get(file_name)) for file_name in file_names}

    @classmethod
    def _probe_has_7z_magic(cls, probe: _HeaderProbeBuffer | None) -> bool:
        """Return True when a probe buffer captured the 7z magic header."""
        if probe is None:
            return False

        probe.seek(0)
        return probe.read(len(cls._SEVENZIP_MAGIC)) == cls._SEVENZIP_MAGIC

    def _member_has_7z_magic(self, archive: Any, file_name: str) -> bool:
        """Read only enough bytes to confirm whether an extensionless member is a nested 7z archive."""
        probe_factory = _HeaderProbeFactory(limit=len(self._SEVENZIP_MAGIC))

        try:
            archive.extract(targets=[file_name], factory=probe_factory)
        except _HeaderProbeComplete:
            pass
        finally:
            with suppress(Exception):
                archive.reset()

        probe = probe_factory.get(file_name)
        if probe is None:
            probe = next(iter(probe_factory.products.values()), None)
        return self._probe_has_7z_magic(probe)

    def _check_path_traversal(self, file_names: list[str], archive_path: str, result: ScanResult) -> list[str]:
        """Check for path traversal vulnerabilities and return only safe entries."""
        safe_entries: list[str] = []
        canonical_entries: dict[str, str] = {}
        temp_base = os.path.join(tempfile.gettempdir(), "modelaudit_7z")

        for file_name in file_names:
            sanitized_path, is_safe = sanitize_archive_path(file_name, temp_base)
            if not is_safe:
                result.add_check(
                    name="7z Path Traversal Protection",
                    passed=False,
                    message=f"Potential path traversal attempt in archive entry: {file_name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}:{file_name}",
                    details={
                        "original_path": file_name,
                        "sanitized_path": sanitized_path,
                        "threat_type": "path_traversal",
                    },
                )
                continue

            canonical_entry = os.path.normcase(os.path.normpath(sanitized_path))
            if canonical_entry in canonical_entries:
                result.add_check(
                    name="7z Duplicate Entry Protection",
                    passed=False,
                    message=(
                        "Archive contains duplicate entries that resolve to the same extraction path: "
                        f"{canonical_entries[canonical_entry]} and {file_name}"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{file_name}",
                    details={
                        "entry": file_name,
                        "first_entry": canonical_entries[canonical_entry],
                        "canonical_path": sanitized_path,
                        "threat_type": "duplicate_entry_shadowing",
                    },
                )
                continue

            canonical_entries[canonical_entry] = file_name
            safe_entries.append(file_name)

        return safe_entries

    def _extract_and_scan_files(
        self,
        archive: Any,
        scannable_files: list[str],
        archive_path: str,
        result: ScanResult,
        depth: int,
        budget: _RecursiveScanBudget,
    ) -> bool:
        """Extract scannable files and run appropriate scanners on them"""
        scan_complete = not budget.should_stop()
        extractable_files = []
        for file_name in scannable_files:
            member_info = None
            with suppress(Exception):
                member_info = archive.getinfo(file_name)

            if getattr(member_info, "is_directory", False) is True:
                continue

            member_size = self._get_archive_member_size(archive, file_name)
            if member_size is not None and member_size > self.max_extract_size:
                scan_complete = False
                result.add_check(
                    name="Extracted File Size",
                    passed=False,
                    message=f"Extracted file {file_name} is too large ({member_size} bytes)",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{file_name}",
                    details={"extracted_size": member_size, "size_limit": self.max_extract_size},
                )
                continue

            extractable_files.append(file_name)

        if not extractable_files or budget.should_stop():
            return scan_complete and not budget.should_stop()

        with tempfile.TemporaryDirectory(prefix="modelaudit_7z_") as tmp_dir:
            try:
                # Extract all scannable files at once to avoid py7zr state issues
                archive.extract(path=tmp_dir, targets=extractable_files)

                for file_name in extractable_files:
                    if budget.should_stop():
                        return False
                    try:
                        extracted_path = os.path.join(tmp_dir, file_name)

                        # Block symlinks — matches zip_scanner / pytorch_zip_scanner
                        if os.path.islink(extracted_path):
                            scan_complete = False
                            result.add_check(
                                name="7z Symlink Protection",
                                passed=False,
                                message=f"Symlink detected in 7z archive: {file_name}",
                                severity=IssueSeverity.CRITICAL,
                                location=f"{archive_path}:{file_name}",
                                details={
                                    "threat_type": "symlink_traversal",
                                    "symlink_target": os.readlink(extracted_path),
                                },
                            )
                            continue

                        if os.path.isfile(extracted_path):
                            # Check extracted file size
                            extracted_size = os.path.getsize(extracted_path)
                            if extracted_size > self.max_extract_size:
                                scan_complete = False
                                result.add_check(
                                    name="Extracted File Size",
                                    passed=False,
                                    message=f"Extracted file {file_name} is too large ({extracted_size} bytes)",
                                    severity=IssueSeverity.WARNING,
                                    location=f"{archive_path}:{file_name}",
                                    details={"extracted_size": extracted_size, "size_limit": self.max_extract_size},
                                )
                                continue

                            # Check cumulative extraction size
                            cumulative_extract_bytes = budget.record_extract_bytes(extracted_size)
                            if cumulative_extract_bytes > self.max_total_extract_size:
                                budget.abort_due_to_limit()
                                scan_complete = False
                                result.add_check(
                                    name="Cumulative Extraction Size",
                                    passed=False,
                                    message=(
                                        f"Cumulative extracted bytes ({cumulative_extract_bytes}) "
                                        f"exceed limit of {self.max_total_extract_size}"
                                    ),
                                    severity=IssueSeverity.CRITICAL,
                                    location=archive_path,
                                    details={
                                        "cumulative_bytes": cumulative_extract_bytes,
                                        "limit": self.max_total_extract_size,
                                        "potential_threat": "zip_bomb",
                                    },
                                )
                                return False

                            # Get appropriate scanner for the extracted file
                            nested_scan_success = self._scan_extracted_file(
                                extracted_path,
                                file_name,
                                archive_path,
                                result,
                                depth,
                                budget=budget,
                            )
                            if not nested_scan_success:
                                scan_complete = False
                            if budget.should_stop():
                                return False
                        else:
                            # File was not extracted - log as warning
                            scan_complete = False
                            result.add_check(
                                name=f"File Extraction: {file_name}",
                                passed=False,
                                message=f"File {file_name} was not extracted successfully",
                                severity=IssueSeverity.WARNING,
                                location=f"{archive_path}:{file_name}",
                                details={"error": "file_not_found_after_extraction"},
                            )

                    except Exception as e:
                        scan_complete = False
                        result.add_check(
                            name=f"File Extraction: {file_name}",
                            passed=False,
                            message=f"Failed to extract and scan {file_name}: {e}",
                            severity=IssueSeverity.WARNING,
                            location=f"{archive_path}:{file_name}",
                            details={"error": str(e)},
                        )

            except Exception as e:
                scan_complete = False
                result.add_check(
                    name="Archive Extraction",
                    passed=False,
                    message=f"Failed during archive extraction: {e}",
                    severity=IssueSeverity.WARNING,
                    location=archive_path,
                    details={"error": str(e)},
                )

        return scan_complete and not budget.should_stop()

    @staticmethod
    def _get_archive_member_size(archive: Any, file_name: str) -> int | None:
        """Return the uncompressed size for an archive member when available."""
        try:
            member_info = archive.getinfo(file_name)
        except Exception:
            return None

        member_size = getattr(member_info, "uncompressed", None)
        if isinstance(member_size, int):
            return member_size
        return None

    def _rewrite_nested_result_context(
        self, file_result: ScanResult, extracted_path: str, archive_path: str, original_name: str
    ) -> None:
        """Rewrite nested scan locations to preserve archive member context."""
        archive_location = f"{archive_path}:{original_name}"

        for issue in file_result.issues:
            if issue.location:
                if issue.location.startswith(extracted_path):
                    issue.location = issue.location.replace(extracted_path, archive_location, 1)
                else:
                    issue.location = f"{archive_location} {issue.location}"
            else:
                issue.location = archive_location

            issue.details["archive_path"] = archive_path
            issue.details["extracted_from"] = original_name

        for check in file_result.checks:
            if check.location:
                if check.location.startswith(extracted_path):
                    check.location = check.location.replace(extracted_path, archive_location, 1)
                else:
                    check.location = f"{archive_location} {check.location}"
            else:
                check.location = archive_location

    def _scan_extracted_file(
        self,
        extracted_path: str,
        original_name: str,
        archive_path: str,
        result: ScanResult,
        depth: int,
        budget: _RecursiveScanBudget,
    ) -> bool:
        """Scan an individual extracted file using the appropriate scanner"""
        try:
            if original_name.lower().endswith(".7z") or self._has_7z_magic(extracted_path):
                file_result = self._scan_7z_file(
                    extracted_path,
                    depth + 1,
                    budget=budget,
                )
            else:
                from .. import core

                nested_config = dict(self.config)
                nested_config["_archive_depth"] = depth + 1
                file_result = core.scan_file(extracted_path, nested_config)

            self._rewrite_nested_result_context(file_result, extracted_path, archive_path, original_name)
            result.merge(file_result)
            return file_result.success and not file_result.has_errors

        except Exception as e:
            result.add_check(
                name=f"File Scan: {original_name}",
                passed=False,
                message=f"Error scanning extracted file {original_name}: {e}",
                severity=IssueSeverity.WARNING,
                location=f"{archive_path}:{original_name}",
                details={"error": str(e)},
            )
            return False
