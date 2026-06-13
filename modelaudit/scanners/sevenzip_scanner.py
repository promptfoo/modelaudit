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
from ..utils.file.detection import _looks_like_proto0_or_1_pickle, detect_format_from_magic_bytes
from ._archive_config import get_archive_depth
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import mark_archive_scan_incomplete, member_scan_incomplete
from .archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from .archive_member_security import (
    is_executable_archive_member_name,
    is_python_archive_member_name,
    probe_executable_archive_member_signature,
    scan_archive_member_for_known_risks,
)
from .base import BaseScanner, IssueSeverity, ScanResult
from .xgboost_scanner import XGBoostScanner

# Try to import py7zr with graceful fallback
try:
    import py7zr  # type: ignore[import-untyped]

    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False
    py7zr = _py7zr


class _HeaderProbeComplete(Exception):
    """Internal signal used to stop a header probe once enough bytes are captured."""


class _ExtractionBudgetExceeded(Exception):
    """Internal signal used to abort extraction before a configured byte budget is exceeded."""

    def __init__(
        self,
        file_name: str,
        *,
        cumulative_bytes: int,
        total_limit: int,
        file_bytes: int,
        file_limit: int,
    ) -> None:
        super().__init__(f"Extraction budget exceeded while extracting {file_name}")
        self.file_name = file_name
        self.cumulative_bytes = cumulative_bytes
        self.total_limit = total_limit
        self.file_bytes = file_bytes
        self.file_limit = file_limit


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


class _BudgetedExtractionFile:
    def __init__(
        self,
        path: Path,
        file_name: str,
        *,
        budget: "_RecursiveScanBudget",
        max_file_size: int,
        max_total_size: int,
    ) -> None:
        self._file = path.open("wb")
        self._file_name = file_name
        self._budget = budget
        self._max_file_size = max_file_size
        self._max_total_size = max_total_size
        self._written = 0

    def write(self, data: bytes | bytearray) -> int:
        chunk_size = len(data)
        projected_file_size = self._written + chunk_size
        projected_total_size = self._budget.cumulative_extract_bytes + chunk_size
        if projected_file_size > self._max_file_size or projected_total_size > self._max_total_size:
            raise _ExtractionBudgetExceeded(
                self._file_name,
                cumulative_bytes=projected_total_size,
                total_limit=self._max_total_size,
                file_bytes=projected_file_size,
                file_limit=self._max_file_size,
            )

        self._file.write(data)
        self._written = projected_file_size
        self._budget.record_extract_bytes(chunk_size)
        return chunk_size

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class _BudgetedExtractionFactory:
    def __init__(
        self,
        target_dir: Path,
        *,
        budget: "_RecursiveScanBudget",
        max_file_size: int,
        max_total_size: int,
    ) -> None:
        self._target_dir = target_dir.resolve()
        self._budget = budget
        self._max_file_size = max_file_size
        self._max_total_size = max_total_size
        self.products: dict[str, _BudgetedExtractionFile] = {}
        self.paths: dict[str, Path] = {}

    def create(self, filename: str) -> _BudgetedExtractionFile:
        target_path = (self._target_dir / filename).resolve()
        try:
            target_path.relative_to(self._target_dir)
        except ValueError as exc:
            raise ValueError(f"Refusing to extract 7z member outside target directory: {filename}") from exc

        target_path.parent.mkdir(parents=True, exist_ok=True)
        writer = _BudgetedExtractionFile(
            target_path,
            filename,
            budget=self._budget,
            max_file_size=self._max_file_size,
            max_total_size=self._max_total_size,
        )
        self.products[filename] = writer
        self.paths[filename] = target_path
        return writer

    def get_path(self, filename: str) -> Path:
        return self.paths.get(filename, self._target_dir / filename)

    def close(self) -> None:
        for writer in self.products.values():
            with suppress(Exception):
                writer.close()


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


@dataclass(frozen=True)
class _NestedMemberProbeResult:
    detected_format: str | None
    executable_content: bool = False
    executable_probe_incomplete: bool = False


class SevenZipScanner(BaseScanner):
    """Scanner for 7-Zip archive files (.7z)

    This scanner extracts and scans model files contained within 7-Zip archives,
    looking for malicious content that could be hidden in compressed formats.
    """

    name = "sevenzip"
    description = "Scans 7-Zip archives for malicious model files"
    supported_extensions: ClassVar[list[str]] = [".7z"]
    _SEVENZIP_MAGIC: ClassVar[bytes] = b"7z\xbc\xaf\x27\x1c"
    _NESTED_MEMBER_PROBE_BYTES: ClassVar[int] = 1024
    _MAX_PYTHON_MEMBER_ANALYSIS_BYTES: ClassVar[int] = 10 * 1024 * 1024
    _XGBOOST_NESTED_MEMBER_PROBE_BYTES: ClassVar[int] = XGBoostScanner._UBJSON_PROBE_READ_BYTES
    _XGBOOST_PROBE_FORMATS: ClassVar[frozenset[str]] = frozenset({"xgboost", "structural_candidate"})

    _MAX_EXTENSIONLESS_PROBES: ClassVar[int] = 100
    _MAX_TOTAL_EXTRACT_SIZE: ClassVar[int] = 5 * 1024 * 1024 * 1024  # 5 GB
    _MAX_CUMULATIVE_ENTRIES: ClassVar[int] = 50000
    _NESTED_CORE_EXTENSION_EXCLUSIONS: ClassVar[frozenset[str]] = frozenset(
        {".txt", ".md", ".markdown", ".rst", ".j2", ".jinja", ".template"},
    )
    _EXECUTABLE_MODEL_EXTENSIONS: ClassVar[frozenset[str]] = frozenset({".llamafile"})
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
        self._archive_member_info_cache: dict[int, tuple[Any, dict[str, list[Any]]]] = {}
        self._reported_member_metadata_gaps: set[tuple[str, str]] = set()
        self._reported_preextraction_links: set[tuple[str, str]] = set()

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
        return get_archive_depth(self.config)

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

    @classmethod
    def _archive_member_name(cls, member_info: Any) -> str:
        if isinstance(member_info, str):
            return member_info
        member_name = getattr(member_info, "filename", None)
        if not isinstance(member_name, str) or not member_name:
            raise ValueError("7z member metadata did not include a filename")
        return member_name

    @staticmethod
    def _archive_member_name_source(archive: Any) -> Any | None:
        archive_state = getattr(archive, "__dict__", None)
        return archive_state.get("files") if isinstance(archive_state, dict) else None

    def _bounded_archive_file_names(self, archive: Any) -> tuple[list[str], int, bool]:
        """Return archive member names without building a second unbounded name table when possible."""
        member_source = self._archive_member_name_source(archive)
        if member_source is None:
            if type(archive).__module__.startswith("py7zr"):
                raise ValueError("7z archive metadata did not expose a bounded member source")
            fallback_file_names = list(archive.getnames())
            return fallback_file_names, len(fallback_file_names), len(fallback_file_names) > self.max_entries

        try:
            observed_entry_count = len(member_source)
        except TypeError:
            pass
        else:
            if observed_entry_count > self.max_entries:
                return [], observed_entry_count, True

        file_names: list[str] = []
        for member_info in member_source:
            file_names.append(self._archive_member_name(member_info))
            if len(file_names) > self.max_entries:
                return file_names, len(file_names), True
        return file_names, len(file_names), False

    def scan(self, path: str) -> ScanResult:
        """Scan a 7-Zip archive file"""
        self._archive_member_info_cache.clear()
        self._reported_member_metadata_gaps.clear()
        self._reported_preextraction_links.clear()

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
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error_type": "missing_dependency",
                    "required_package": "py7zr",
                    "install_command": "pip install py7zr",
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "sevenzip_analysis_incomplete",
                },
            )
            mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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
            mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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
            mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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
            mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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
            mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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
            file_names, observed_entry_count, entry_limit_exceeded = self._bounded_archive_file_names(archive)

            # Check per-archive entry limit
            if entry_limit_exceeded:
                budget.abort_due_to_limit()
                result.add_check(
                    name="Archive Entry Limit",
                    passed=False,
                    message=(
                        f"7z archive contains at least {observed_entry_count} files, "
                        f"exceeding limit of {self.max_entries}"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "file_count": observed_entry_count,
                        "limit": self.max_entries,
                        "potential_threat": "zip_bomb",
                    },
                )
                result.metadata["total_files"] = observed_entry_count
                result.metadata["scannable_files"] = 0
                result.metadata["unsafe_entries"] = 0
                result.metadata["file_size"] = os.path.getsize(path)
                mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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
                mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
                result.finish(success=False)
                return result

            # Check for path traversal vulnerabilities and only keep safe entries
            safe_file_names = self._check_path_traversal(file_names, path, result)
            if len(safe_file_names) < len(file_names):
                scan_complete = False

            # Filter for scannable model files from safe entries only
            scannable_files = self._identify_scannable_files(safe_file_names)
            named_security_files = self._identify_named_member_security_files(safe_file_names)
            # Nested model targets still need generic executable-content inspection.
            member_security_files = [
                file_name
                for file_name in dict.fromkeys([*scannable_files, *named_security_files])
                if not self._is_explicit_executable_model_member(file_name)
            ]
            nested_archive_files, probed_executable_files, nested_probe_formats, probes_complete = (
                self._identify_probed_nested_and_security_files(
                    archive,
                    safe_file_names,
                    path,
                    result,
                    named_security_files=frozenset(named_security_files),
                )
            )
            nested_scan_targets = list(dict.fromkeys([*scannable_files, *nested_archive_files]))
            extraction_targets = list(dict.fromkeys([*nested_scan_targets, *member_security_files]))
            if not probes_complete:
                scan_complete = False

            if not extraction_targets:
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
                        extraction_targets,
                        path,
                        result,
                        depth,
                        budget=budget,
                        member_security_files=frozenset(member_security_files),
                        prechecked_executable_files=frozenset(probed_executable_files),
                        nested_scan_files=frozenset(nested_scan_targets),
                        nested_probe_formats=nested_probe_formats,
                    )
                    and scan_complete
                )

            result.metadata["total_files"] = len(file_names)
            result.metadata["scannable_files"] = len(nested_scan_targets)
            result.metadata["security_files"] = len({*member_security_files, *probed_executable_files})
            result.metadata["unsafe_entries"] = len(file_names) - len(safe_file_names)
            result.metadata["file_size"] = os.path.getsize(path)

        if not scan_complete or budget.should_stop():
            mark_archive_scan_incomplete(result, "sevenzip_analysis_incomplete")
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

    @staticmethod
    def _identify_named_member_security_files(file_names: list[str]) -> list[str]:
        """Return archive members whose names require generic security inspection."""
        return [
            file_name
            for file_name in file_names
            if is_python_archive_member_name(file_name) or is_executable_archive_member_name(file_name)
        ]

    @classmethod
    def _is_explicit_executable_model_member(cls, file_name: str) -> bool:
        """Return True for unambiguous nested formats that are intentionally executable."""
        return any(
            extension in cls._EXECUTABLE_MODEL_EXTENSIONS for extension in cls._candidate_archive_extensions(file_name)
        )

    @staticmethod
    def _add_probed_executable_member_check(result: ScanResult, archive_path: str, file_name: str) -> None:
        result.add_check(
            name="Executable Archive Member Detection",
            passed=False,
            message=f"Executable file found in 7z archive: {file_name}",
            severity=IssueSeverity.WARNING,
            location=f"{archive_path}:{file_name}",
            details={"entry": file_name},
        )

    def _identify_probed_nested_and_security_files(
        self,
        archive: Any,
        file_names: list[str],
        archive_path: str,
        result: ScanResult,
        *,
        named_security_files: frozenset[str] = frozenset(),
    ) -> tuple[list[str], list[str], dict[str, str], bool]:
        """Probe unsupported members for nested formats and hidden executables."""
        nested_archives: list[str] = []
        executable_members: list[str] = []
        incomplete_executable_members: list[str] = []
        nested_probe_formats: dict[str, str] = {}
        probes_complete = True
        probe_candidates: list[tuple[int, int, str]] = []
        supported_extensions = self._supported_nested_core_extensions()
        for index, file_name in enumerate(file_names):
            candidate_extensions = self._candidate_archive_extensions(file_name)
            if (
                any(extension in supported_extensions for extension in candidate_extensions)
                and file_name not in named_security_files
            ):
                continue

            member_info = self._get_archive_member_info(archive, file_name)
            symlink_state = self._preflight_member_symlink_state(member_info)
            if symlink_state == "unknown":
                probes_complete = False
                self._add_member_metadata_incomplete_check(result, archive_path, file_name)
                continue
            if symlink_state == "symlink":
                probes_complete = False
                self._add_preextraction_symlink_check(result, archive_path, file_name, member_info)
                continue

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
                severity=IssueSeverity.INFO,
                location=archive_path,
                details={
                    "limit": self.max_extensionless_probes,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "sevenzip_analysis_incomplete",
                },
            )

        probe_candidates.sort(key=lambda item: (-item[0], item[1]))
        probe_targets = [file_name for _, _, file_name in probe_candidates[: self.max_extensionless_probes]]
        if not probe_targets:
            return nested_archives, executable_members, nested_probe_formats, probes_complete

        try:
            probe_results = self._probe_extensionless_members(archive, probe_targets)
            for file_name in probe_targets:
                probe_result = probe_results.get(file_name)
                if probe_result is None:
                    continue
                if probe_result.detected_format is not None:
                    nested_archives.append(file_name)
                    nested_probe_formats[file_name] = probe_result.detected_format
                if probe_result.executable_content:
                    executable_members.append(file_name)
                    self._add_probed_executable_member_check(result, archive_path, file_name)
                if probe_result.executable_probe_incomplete:
                    incomplete_executable_members.append(file_name)
                    probes_complete = False
            self._add_incomplete_executable_probe_checks(result, archive_path, incomplete_executable_members)
            return nested_archives, executable_members, nested_probe_formats, probes_complete
        except Exception:
            # Fall back to per-member probing if the fast path fails against a
            # particular archive layout or py7zr behavior.
            pass

        for file_name in probe_targets:
            try:
                probe_result = self._member_probe_result(archive, file_name)
                if probe_result.detected_format is not None:
                    nested_archives.append(file_name)
                    nested_probe_formats[file_name] = probe_result.detected_format
                if probe_result.executable_content:
                    executable_members.append(file_name)
                    self._add_probed_executable_member_check(result, archive_path, file_name)
                if probe_result.executable_probe_incomplete:
                    incomplete_executable_members.append(file_name)
                    probes_complete = False
            except Exception as e:
                probes_complete = False
                result.add_check(
                    name=f"Nested 7z Probe: {file_name}",
                    passed=False,
                    message=f"Failed to inspect nested archive candidate {file_name}: {e}",
                    severity=IssueSeverity.INFO,
                    location=f"{archive_path}:{file_name}",
                    details={
                        "error": str(e),
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "sevenzip_analysis_incomplete",
                    },
                )

        self._add_incomplete_executable_probe_checks(result, archive_path, incomplete_executable_members)
        return nested_archives, executable_members, nested_probe_formats, probes_complete

    @staticmethod
    def _add_incomplete_executable_probe_checks(
        result: ScanResult,
        archive_path: str,
        member_names: list[str],
    ) -> None:
        for member_name in member_names:
            result.add_check(
                name=f"Executable 7z Probe: {member_name}",
                passed=False,
                message=f"Executable content probe was inconclusive for 7z member {member_name}",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:{member_name}",
                details={"analysis_incomplete": True},
            )

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

    def _probe_extensionless_members(self, archive: Any, file_names: list[str]) -> dict[str, _NestedMemberProbeResult]:
        """Probe disguised members while stopping each extraction at bounded prefixes."""
        return {file_name: self._member_probe_result(archive, file_name) for file_name in file_names}

    @classmethod
    def _probe_has_7z_magic(cls, probe: Any | None) -> bool:
        """Return True when a probe buffer captured the 7z magic header."""
        if probe is None:
            return False

        probe.seek(0)
        return probe.read(len(cls._SEVENZIP_MAGIC)) == cls._SEVENZIP_MAGIC

    @classmethod
    def _probe_has_tar_magic(cls, probe: Any | None) -> bool:
        """Return True when a probe buffer captured a TAR header marker."""
        if probe is None:
            return False

        probe.seek(0)
        tar_header = probe.read(cls._NESTED_MEMBER_PROBE_BYTES)
        return len(tar_header) >= 262 and tar_header[257:262] == b"ustar"

    def _probe_detected_format(self, probe: Any | None) -> str | None:
        """Return a directly routable header format captured by a bounded member probe."""
        if probe is None:
            return None

        if self._probe_has_7z_magic(probe):
            return "sevenzip"
        if self._probe_has_tar_magic(probe):
            return "tar"

        probe.seek(0)
        prefix = probe.read(self._NESTED_MEMBER_PROBE_BYTES)
        if len(prefix) < 4:
            return None

        if XGBoostScanner._is_ubjson_probe(prefix):
            return "xgboost"

        if _looks_like_proto0_or_1_pickle(prefix, sample_is_prefix=len(prefix) == self._NESTED_MEMBER_PROBE_BYTES):
            return "pickle"

        detected_format = detect_format_from_magic_bytes(
            prefix[:4],
            prefix[:8],
            prefix[:16],
            len(prefix),
            pickle_probe_sample=prefix,
            pickle_probe_is_prefix=len(prefix) == self._NESTED_MEMBER_PROBE_BYTES,
        )
        if detected_format == "unknown":
            return None
        return detected_format

    def _read_member_probe_prefix(self, archive: Any, file_name: str, limit: int) -> bytes:
        """Extract a bounded prefix from one member without writing to disk."""
        probe_factory = _HeaderProbeFactory(limit=limit)

        try:
            with suppress(_HeaderProbeComplete):
                archive.extract(targets=[file_name], factory=probe_factory)
        finally:
            with suppress(Exception):
                archive.reset()

        probe = probe_factory.get(file_name)
        if probe is None:
            probe = next(iter(probe_factory.products.values()), None)
        if probe is None:
            return b""
        probe.seek(0)
        return probe.read(limit)

    def _get_archive_member_infos(self, archive: Any, file_name: str) -> list[Any]:
        """Return every metadata record for a member across py7zr API variants."""
        archive_key = id(archive)
        cached_archive = self._archive_member_info_cache.get(archive_key)
        member_index = cached_archive[1] if cached_archive is not None and cached_archive[0] is archive else None
        if member_index is None:
            member_index = {}
            metadata_records: list[Any] = []

            files = getattr(archive, "files", None)
            if files is not None:
                try:
                    metadata_records = list(files)
                except Exception:
                    metadata_records = []

            if not metadata_records:
                list_members = getattr(archive, "list", None)
                if callable(list_members):
                    try:
                        metadata_records = list(list_members())
                    except Exception:
                        metadata_records = []

            for member_info in metadata_records:
                member_name = getattr(member_info, "filename", None)
                if isinstance(member_name, str):
                    member_index.setdefault(member_name, []).append(member_info)
            self._archive_member_info_cache[archive_key] = (archive, member_index)

        member_infos = member_index.get(file_name)
        if member_infos is not None:
            return member_infos

        # Older or mocked py7zr variants may expose only per-name lookup.
        member_info = None
        getinfo = getattr(archive, "getinfo", None)
        if callable(getinfo):
            with suppress(Exception):
                member_info = getinfo(file_name)
        member_infos = [] if member_info is None else [member_info]
        member_index[file_name] = member_infos
        return member_infos

    def _get_archive_member_info(self, archive: Any, file_name: str) -> Any | None:
        """Return unambiguous metadata for a member without extracting it."""
        member_infos = self._get_archive_member_infos(archive, file_name)
        if len(member_infos) == 1:
            return member_infos[0]
        return None

    @staticmethod
    def _preflight_member_symlink_state(member_info: Any | None) -> str:
        if member_info is None:
            return "unknown"
        try:
            is_symlink = getattr(member_info, "is_symlink", None)
            is_junction = getattr(member_info, "is_junction", False)
        except Exception:
            return "unknown"
        if isinstance(is_symlink, bool):
            if is_symlink or is_junction is True:
                return "symlink"
            return "regular"
        return "unknown"

    def _add_member_metadata_incomplete_check(self, result: ScanResult, archive_path: str, file_name: str) -> None:
        finding_key = (archive_path, file_name)
        if finding_key in self._reported_member_metadata_gaps:
            return
        self._reported_member_metadata_gaps.add(finding_key)
        result.add_check(
            name="7z Member Metadata",
            passed=False,
            message=f"Unable to verify 7z member metadata before extraction: {file_name}",
            severity=IssueSeverity.INFO,
            location=f"{archive_path}:{file_name}",
            details={
                "entry": file_name,
                "metadata_field": "is_symlink",
                "analysis_incomplete": True,
                "scan_outcome_reason": "sevenzip_analysis_incomplete",
            },
        )

    def _add_preextraction_symlink_check(
        self,
        result: ScanResult,
        archive_path: str,
        file_name: str,
        member_info: Any | None,
    ) -> None:
        finding_key = (archive_path, file_name)
        if finding_key in self._reported_preextraction_links:
            return
        self._reported_preextraction_links.add(finding_key)
        details: dict[str, Any] = {
            "threat_type": "symlink_traversal",
            "checked_before_extraction": True,
        }
        symlink_target = getattr(member_info, "linkname", None)
        if isinstance(symlink_target, str):
            details["symlink_target"] = symlink_target
        result.add_check(
            name="7z Symlink Protection",
            passed=False,
            message=f"Symlink detected in 7z archive before extraction: {file_name}",
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{file_name}",
            details=details,
        )

    def _member_probe_result(self, archive: Any, file_name: str) -> _NestedMemberProbeResult:
        """Classify a member through bounded format and executable-content probes."""
        prefix = self._read_member_probe_prefix(archive, file_name, self._NESTED_MEMBER_PROBE_BYTES)
        detected_format = self._probe_detected_format(io.BytesIO(prefix))
        if detected_format is None and XGBoostScanner._classify_extensionless_ubjson_probe(prefix) == "inconclusive":
            expanded_prefix = self._read_member_probe_prefix(
                archive,
                file_name,
                self._XGBOOST_NESTED_MEMBER_PROBE_BYTES,
            )
            route = XGBoostScanner._classify_extensionless_ubjson_probe(expanded_prefix)
            if route == "xgboost":
                detected_format = "xgboost"
            elif route == "inconclusive":
                detected_format = "structural_candidate"

        if detected_format is not None:
            return _NestedMemberProbeResult(detected_format=detected_format)

        prefix_cache = prefix

        def read_prefix(limit: int) -> bytes:
            nonlocal prefix_cache
            if limit <= len(prefix_cache) or not prefix_cache.startswith(b"MZ"):
                return prefix_cache[:limit]
            expanded_prefix = self._read_member_probe_prefix(archive, file_name, limit)
            if len(expanded_prefix) > len(prefix_cache):
                prefix_cache = expanded_prefix
            return prefix_cache[:limit]

        executable_probe_outcome = probe_executable_archive_member_signature(read_prefix)
        return _NestedMemberProbeResult(
            detected_format=None,
            executable_content=executable_probe_outcome == "detected",
            executable_probe_incomplete=executable_probe_outcome == "incomplete",
        )

    def _member_probe_detected_format(self, archive: Any, file_name: str) -> str | None:
        """Read only enough bytes to confirm whether a member has a scannable nested format."""
        return self._member_probe_result(archive, file_name).detected_format

    def _check_path_traversal(self, file_names: list[str], archive_path: str, result: ScanResult) -> list[str]:
        """Check for path traversal vulnerabilities and return only safe entries."""
        safe_entries: list[str] = []
        canonical_entries: dict[str, str] = {}
        ambiguous_entries: set[str] = set()
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
                first_entry = canonical_entries[canonical_entry]
                if canonical_entry not in ambiguous_entries:
                    ambiguous_entries.add(canonical_entry)
                    safe_entries.remove(first_entry)
                result.add_check(
                    name="7z Duplicate Entry Protection",
                    passed=False,
                    message=(
                        "Archive contains duplicate entries that resolve to the same extraction path: "
                        f"{first_entry} and {file_name}"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}:{file_name}",
                    details={
                        "entry": file_name,
                        "first_entry": first_entry,
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
        member_security_files: frozenset[str] = frozenset(),
        prechecked_executable_files: frozenset[str] = frozenset(),
        nested_scan_files: frozenset[str] | None = None,
        nested_probe_formats: dict[str, str] | None = None,
    ) -> bool:
        """Extract scannable files and run appropriate scanners on them"""
        scan_complete = not budget.should_stop()
        if nested_scan_files is None:
            nested_scan_files = frozenset(scannable_files)
        extractable_files: list[str] = []
        member_sizes: dict[str, int | None] = {}
        known_extract_bytes = 0
        for file_name in scannable_files:
            member_info = self._get_archive_member_info(archive, file_name)
            symlink_state = self._preflight_member_symlink_state(member_info)
            if symlink_state == "unknown":
                scan_complete = False
                self._add_member_metadata_incomplete_check(result, archive_path, file_name)
                continue
            if symlink_state == "symlink":
                scan_complete = False
                self._add_preextraction_symlink_check(result, archive_path, file_name, member_info)
                continue

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
            member_sizes[file_name] = member_size
            if member_size is not None:
                known_extract_bytes += member_size

        if not extractable_files or budget.should_stop():
            return scan_complete and not budget.should_stop()

        projected_cumulative_bytes = budget.cumulative_extract_bytes + known_extract_bytes
        if known_extract_bytes > 0 and projected_cumulative_bytes > self.max_total_extract_size:
            budget.abort_due_to_limit()
            self._add_cumulative_extraction_size_check(
                result,
                archive_path,
                cumulative_bytes=projected_cumulative_bytes,
            )
            return False

        use_budgeted_factory = any(member_sizes[file_name] is None for file_name in extractable_files)

        with tempfile.TemporaryDirectory(prefix="modelaudit_7z_") as tmp_dir:
            extraction_factory: _BudgetedExtractionFactory | None = None
            try:
                if use_budgeted_factory:
                    extraction_factory = _BudgetedExtractionFactory(
                        Path(tmp_dir),
                        budget=budget,
                        max_file_size=self.max_extract_size,
                        max_total_size=self.max_total_extract_size,
                    )
                    archive.extract(targets=extractable_files, factory=extraction_factory)
                else:
                    # Extract all scannable files at once to avoid py7zr state issues
                    archive.extract(path=tmp_dir, targets=extractable_files)

                for file_name in extractable_files:
                    if budget.should_stop():
                        return False
                    try:
                        extracted_path = (
                            str(extraction_factory.get_path(file_name))
                            if extraction_factory is not None
                            else os.path.join(tmp_dir, file_name)
                        )

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
                            if extraction_factory is None:
                                cumulative_extract_bytes = budget.record_extract_bytes(extracted_size)
                                if cumulative_extract_bytes > self.max_total_extract_size:
                                    budget.abort_due_to_limit()
                                    scan_complete = False
                                    self._add_cumulative_extraction_size_check(
                                        result,
                                        archive_path,
                                        cumulative_bytes=cumulative_extract_bytes,
                                    )
                                    return False

                            if file_name in member_security_files and file_name not in prechecked_executable_files:
                                scan_archive_member_for_known_risks(
                                    archive_kind="7z",
                                    archive_path=archive_path,
                                    member_name=file_name,
                                    tmp_path=extracted_path,
                                    total_size=extracted_size,
                                    result=result,
                                    max_python_analysis_bytes=self._MAX_PYTHON_MEMBER_ANALYSIS_BYTES,
                                    python_analysis_incomplete_reason="sevenzip_python_member_analysis_incomplete",
                                    executable_analysis_incomplete_reason="sevenzip_executable_member_analysis_incomplete",
                                    analyze_python_source=file_name not in nested_scan_files,
                                )
                                if member_scan_incomplete(result):
                                    scan_complete = False

                            if file_name not in nested_scan_files:
                                continue

                            # Get appropriate scanner for the extracted file
                            nested_scan_success = self._scan_extracted_file(
                                extracted_path,
                                file_name,
                                archive_path,
                                result,
                                depth,
                                budget=budget,
                                probed_format=(nested_probe_formats or {}).get(file_name),
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

            except _ExtractionBudgetExceeded as e:
                budget.abort_due_to_limit()
                scan_complete = False
                if e.file_bytes > e.file_limit:
                    result.add_check(
                        name="Extracted File Size",
                        passed=False,
                        message=f"Extracted file {e.file_name} is too large ({e.file_bytes} bytes)",
                        severity=IssueSeverity.WARNING,
                        location=f"{archive_path}:{e.file_name}",
                        details={"extracted_size": e.file_bytes, "size_limit": e.file_limit},
                    )
                else:
                    self._add_cumulative_extraction_size_check(
                        result,
                        archive_path,
                        cumulative_bytes=e.cumulative_bytes,
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
            finally:
                if extraction_factory is not None:
                    extraction_factory.close()

        return scan_complete and not budget.should_stop()

    def _add_cumulative_extraction_size_check(
        self,
        result: ScanResult,
        archive_path: str,
        *,
        cumulative_bytes: int,
    ) -> None:
        result.add_check(
            name="Cumulative Extraction Size",
            passed=False,
            message=(f"Cumulative extracted bytes ({cumulative_bytes}) exceed limit of {self.max_total_extract_size}"),
            severity=IssueSeverity.CRITICAL,
            location=archive_path,
            details={
                "cumulative_bytes": cumulative_bytes,
                "limit": self.max_total_extract_size,
                "potential_threat": "zip_bomb",
            },
        )

    def _get_archive_member_size(self, archive: Any, file_name: str) -> int | None:
        """Return the uncompressed size for an archive member when available."""
        member_info = self._get_archive_member_info(archive, file_name)
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
            issue.location = rewrite_extracted_member_location(
                issue.location,
                extracted_path,
                archive_location,
                preserve_non_delimited_suffix=True,
            )

            issue.details["archive_path"] = archive_path
            issue.details["extracted_from"] = original_name

        for check in file_result.checks:
            check.location = rewrite_extracted_member_location(
                check.location,
                extracted_path,
                archive_location,
                preserve_non_delimited_suffix=True,
            )

    def _scan_nested_archive_entry(self, path: str, nested_config: dict[str, Any]) -> ScanResult:
        """Dispatch a nested archive member through an injected callback or registry fallback."""
        nested_scan_callback = self.config.get(NESTED_SCAN_CALLBACK_CONFIG_KEY)
        if callable(nested_scan_callback):
            return nested_scan_callback(path, nested_config)
        from .. import core

        return core.scan_file(path, nested_config)

    @staticmethod
    def _retarget_probe_confirmed_xgboost_member(extracted_path: str) -> str:
        """Move a disguised XGBoost member to an extensionless private routing path."""
        routed_dir = os.path.join(os.path.dirname(extracted_path), ".modelaudit_routed")
        os.makedirs(routed_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="member_", dir=routed_dir, delete=False) as routed_file:
            routed_path = routed_file.name
        os.replace(extracted_path, routed_path)
        return routed_path

    @classmethod
    def _probe_extracted_xgboost_format(cls, extracted_path: str) -> str | None:
        """Classify an extracted member that may hide UBJSON behind another suffix."""
        try:
            with open(extracted_path, "rb") as extracted_file:
                prefix = extracted_file.read(cls._XGBOOST_NESTED_MEMBER_PROBE_BYTES)
        except OSError:
            return None

        route = XGBoostScanner._classify_extensionless_ubjson_probe(prefix)
        if route == "inconclusive":
            return "structural_candidate"
        return route

    def _scan_extracted_file(
        self,
        extracted_path: str,
        original_name: str,
        archive_path: str,
        result: ScanResult,
        depth: int,
        budget: _RecursiveScanBudget,
        probed_format: str | None = None,
    ) -> bool:
        """Scan an individual extracted file using the appropriate scanner"""
        try:
            scan_path = extracted_path
            original_suffix = Path(original_name).suffix.lower()
            if probed_format is None and original_suffix not in {".bst", ".model", ".ubj"}:
                probed_format = self._probe_extracted_xgboost_format(extracted_path)
            if probed_format in self._XGBOOST_PROBE_FORMATS:
                scan_path = self._retarget_probe_confirmed_xgboost_member(extracted_path)

            if original_name.lower().endswith(".7z") or self._has_7z_magic(scan_path):
                file_result = self._scan_7z_file(
                    scan_path,
                    depth + 1,
                    budget=budget,
                )
            else:
                nested_config = dict(self.config)
                nested_config["_archive_depth"] = depth + 1
                # Extracted members are deleted below, so their temporary paths cannot be reused as cache keys.
                nested_config["cache_enabled"] = False
                file_result = self._scan_nested_archive_entry(scan_path, nested_config)

            self._rewrite_nested_result_context(file_result, scan_path, archive_path, original_name)
            result.merge_member_result(file_result, original_name)
            return not member_scan_incomplete(file_result)

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
