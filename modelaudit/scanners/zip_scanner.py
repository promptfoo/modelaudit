import contextlib
import os
import re
import stat
import tempfile
import zipfile
from typing import Any, ClassVar

from ..core_results import mark_operational_scan_error
from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.helpers.assets import asset_from_scan_result
from ._archive_config import get_archive_depth
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import mark_archive_scan_incomplete, member_scan_incomplete
from .archive_dispatch import (
    KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY,
    NESTED_SCAN_CALLBACK_CONFIG_KEY,
    scan_nested_file,
)
from .archive_member_security import is_executable_archive_member_name, scan_archive_member_for_known_risks
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
ARCHIVE_MEMBER_COPY_CHUNK_BYTES = 64 * 1024
ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY = "_zip_security_only_member_entries"


class ZipScanner(BaseScanner):
    """Scanner for generic ZIP archive files"""

    name = "zip"
    description = "Scans ZIP archive files and their contents recursively"
    # Include .mar so non-TorchServe archives still receive generic ZIP scanning.
    supported_extensions: ClassVar[list[str]] = [".zip", ".npz", ".mar"]
    MAX_MAR_PYTHON_ANALYSIS_BYTES: ClassVar[int] = 10 * 1024 * 1024
    MAX_SYMLINK_TARGET_BYTES: ClassVar[int] = 64 * 1024
    MAX_COMPRESSION_RATIO: ClassVar[int] = 100
    MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE: ClassVar[int] = 1024 * 1024
    DEFAULT_MAX_ENTRY_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    UNLIMITED_ARCHIVE_SIZE: ClassVar[int] = 1024 * 1024 * 1024 * 1024

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_depth = self.config.get("max_zip_depth", 5)  # Prevent zip bomb attacks
        self.max_entries = self.config.get(
            "max_zip_entries",
            10000,
        )  # Limit number of entries
        self.max_compression_ratio = self.MAX_COMPRESSION_RATIO
        self.min_compression_bomb_uncompressed_size = self._normalize_positive_int_config(
            self.config.get("zip_min_compression_bomb_uncompressed_size"),
            self.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE,
        )
        self.skip_archive_entries = self._normalize_archive_entry_names(self.config.get("skip_archive_entries", ()))
        self.known_unreadable_archive_entry_offsets = self._normalize_archive_entry_offsets(
            self.config.get(KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY, ())
        )
        raw_security_only_entries = self.config.get(ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY, ())
        if isinstance(raw_security_only_entries, str):
            raw_security_only_entries = (raw_security_only_entries,)
        if not isinstance(raw_security_only_entries, (list, tuple, set, frozenset)):
            raw_security_only_entries = ()
        self.security_only_member_entries = {
            self._normalize_skip_entry_name(entry) for entry in raw_security_only_entries if isinstance(entry, str)
        }

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
        return get_archive_depth(self.config)

    def _get_max_entry_size(self) -> int:
        """Return the configured per-entry extraction limit with a safe unlimited fallback."""
        default_limit = self.DEFAULT_MAX_ENTRY_SIZE
        configured_file_limit = self.config.get("max_file_size")
        configured_entry_limit = self.config.get("max_entry_size")

        if configured_file_limit is not None and configured_file_limit != 0:
            return self._normalize_positive_int_config(configured_file_limit, default_limit)

        if configured_entry_limit is not None:
            if configured_entry_limit == 0:
                return self.UNLIMITED_ARCHIVE_SIZE
            return self._normalize_positive_int_config(configured_entry_limit, default_limit)

        return default_limit

    def _get_max_total_uncompressed_size(self) -> int:
        """Return the configured aggregate uncompressed ZIP budget."""
        positive_limits: list[int] = []
        configured_limit = self.config.get("max_zip_total_uncompressed_size")
        if configured_limit is not None:
            if configured_limit != 0:
                positive_limits.append(
                    self._normalize_positive_int_config(configured_limit, self.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)
                )
        else:
            positive_limits.append(self.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)

        for config_key in ("max_total_size", "max_file_size"):
            configured_public_limit = self.config.get(config_key)
            if configured_public_limit is None or configured_public_limit == 0:
                continue
            positive_limits.append(
                self._normalize_positive_int_config(configured_public_limit, self.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)
            )

        return min(positive_limits) if positive_limits else self.UNLIMITED_ARCHIVE_SIZE

    @staticmethod
    def _normalize_skip_entry_name(name: str) -> str:
        normalized = name.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized.lstrip("/")

    @classmethod
    def _normalize_archive_entry_names(cls, entries: Any) -> set[str]:
        if isinstance(entries, str):
            entries = (entries,)
        if not isinstance(entries, (list, tuple, set, frozenset)):
            return set()
        return {cls._normalize_skip_entry_name(entry) for entry in entries if isinstance(entry, str)}

    @staticmethod
    def _normalize_archive_entry_offsets(offsets: Any) -> set[int]:
        if isinstance(offsets, int) and not isinstance(offsets, bool):
            offsets = (offsets,)
        if not isinstance(offsets, (list, tuple, set, frozenset)):
            return set()
        return {offset for offset in offsets if isinstance(offset, int) and not isinstance(offset, bool)}

    def _should_skip_archive_entry(self, name: str) -> bool:
        return self._normalize_skip_entry_name(name) in self.skip_archive_entries

    def _is_security_only_member_entry(self, name: str) -> bool:
        return self._normalize_skip_entry_name(name) in self.security_only_member_entries

    def _is_known_unreadable_archive_entry(self, info: zipfile.ZipInfo) -> bool:
        return info.header_offset in self.known_unreadable_archive_entry_offsets

    def _read_symlink_target(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
        """Read a symlink target with a hard cap to avoid materializing large archive members."""
        target_bytes = bytearray()
        with archive.open(info) as entry:
            while True:
                chunk = entry.read(4096)
                if not chunk:
                    break

                target_bytes.extend(chunk)
                if len(target_bytes) > self.MAX_SYMLINK_TARGET_BYTES:
                    raise ValueError(f"symlink target exceeds maximum size of {self.MAX_SYMLINK_TARGET_BYTES} bytes")

        return target_bytes.decode("utf-8", "replace")

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
        except OSError:
            return os.path.splitext(path)[1].lower() in cls.supported_extensions
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a ZIP file and its contents"""
        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result

        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            scan_result = self.scan_archive_members(path)
            result.merge(scan_result)

        except OSError as e:
            result.add_check(
                name="ZIP File Scan",
                passed=False,
                message=f"Error scanning zip file: {e!s}",
                severity=IssueSeverity.INFO,
                rule_code="S902",  # Scan error
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
            mark_operational_scan_error(result, "zip_analysis_incomplete")
            result.finish(success=False)
            return result
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
            mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
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
            mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
            result.finish(success=False)
            return result

        result.finish(success=scan_result.success and not result.has_errors)
        result.metadata["contents"] = scan_result.metadata.get("contents", [])
        result.metadata["file_size"] = os.path.getsize(path)
        return result

    def scan_archive_members(self, path: str) -> ScanResult:
        """Recursively scan entries of an already validated ZIP container."""
        # Shared archive depth must survive scanner handoffs, while nested ZIP
        # recursion still needs its own counter for extensionless ZIP members
        # routed through core dispatch.
        return self._scan_zip_file(
            path,
            depth=max(self._get_archive_depth(), self._get_zip_depth()),
        )

    def _rewrite_nested_result_context(
        self, scan_result: ScanResult, tmp_path: str, archive_path: str, entry_name: str
    ) -> None:
        """Rewrite nested result locations so archive members, not temp files, are reported."""
        archive_location = f"{archive_path}:{entry_name}"

        for issue in scan_result.issues:
            issue.location = rewrite_extracted_member_location(
                issue.location,
                tmp_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )

            existing_issue_entry = issue.details.get("zip_entry")
            issue.details["zip_entry"] = (
                f"{entry_name}:{existing_issue_entry}"
                if isinstance(existing_issue_entry, str) and existing_issue_entry
                else entry_name
            )

        for check in scan_result.checks:
            check.location = rewrite_extracted_member_location(
                check.location,
                tmp_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )

            existing_check_entry = check.details.get("zip_entry")
            check.details["zip_entry"] = (
                f"{entry_name}:{existing_check_entry}"
                if isinstance(existing_check_entry, str) and existing_check_entry
                else entry_name
            )

    def _scan_nested_archive_entry(self, path: str, nested_config: dict[str, Any]) -> ScanResult:
        """Dispatch a nested archive member through an injected callback or registry fallback."""
        nested_scan_callback = self.config.get(NESTED_SCAN_CALLBACK_CONFIG_KEY)
        if callable(nested_scan_callback):
            return nested_scan_callback(path, nested_config)
        return scan_nested_file(path, nested_config)

    def _validate_entry_metadata(
        self,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        archive_path: str,
        temp_base: str,
        result: ScanResult,
    ) -> tuple[bool, bool]:
        """Validate ZIP entry metadata that does not require full extraction."""
        name = info.filename
        if not name:
            return False, True

        resolved_name, is_safe = sanitize_archive_path(name, temp_base)
        if not is_safe:
            result.add_check(
                name="Path Traversal Protection",
                passed=False,
                message=f"Archive entry {name} attempted path traversal outside the archive",
                severity=IssueSeverity.CRITICAL,
                rule_code="S405",  # Path traversal
                location=f"{archive_path}:{name}",
                details={"entry": name},
            )
            return False, True

        is_symlink = (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK
        if is_symlink:
            if self._is_known_unreadable_archive_entry(info):
                result.add_check(
                    name="ZIP Member Analysis Coverage",
                    passed=False,
                    message=f"Skipped ZIP symlink target validation for known unreadable member: {name}",
                    severity=IssueSeverity.INFO,
                    rule_code="S902",
                    location=f"{archive_path}:{name}",
                    details={"entry": name, "reason": "known_unreadable_archive_member_skip"},
                )
                return False, False

            try:
                target = self._read_symlink_target(archive, info)
            except Exception as exc:
                mark_archive_scan_incomplete(result, "zip_symlink_target_read_incomplete")
                result.add_check(
                    name="Symlink Safety Validation",
                    passed=False,
                    message=f"Unable to read symlink target for {name}: {exc!s}",
                    severity=IssueSeverity.INFO,
                    rule_code="S902",
                    location=f"{archive_path}:{name}",
                    details={
                        "entry": name,
                        "exception": str(exc),
                        "exception_type": type(exc).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "zip_symlink_target_read_incomplete",
                    },
                )
                return False, False

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
                    location=f"{archive_path}:{name}",
                    details={"target": target, "entry": name},
                )
            elif is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                result.add_check(
                    name="Symlink Safety Validation",
                    passed=False,
                    message=f"Symlink {name} points to critical system path: {target}",
                    severity=IssueSeverity.CRITICAL,
                    rule_code="S408",  # System file access
                    location=f"{archive_path}:{name}",
                    details={"target": target, "entry": name},
                )
            else:
                result.add_check(
                    name="Symlink Safety Validation",
                    passed=True,
                    message=f"Symlink {name} is safe",
                    location=f"{archive_path}:{name}",
                    rule_code=None,  # Passing check
                    details={"target": target, "entry": name},
                )
            return False, True

        if info.is_dir():
            return False, True

        return True, True

    def _scan_zip_file(self, path: str, depth: int = 0) -> ScanResult:
        """Recursively scan a ZIP file and its contents"""
        result = ScanResult(scanner_name=self.name)
        contents: list[dict[str, Any]] = []
        archive_ext = os.path.splitext(path)[1].lower()
        scan_complete = True

        # Check depth to prevent zip bomb attacks
        if depth >= self.max_depth:
            mark_archive_scan_incomplete(result, "zip_depth_limit")
            result.add_check(
                name="ZIP Depth Bomb Protection",
                passed=False,
                message=f"Maximum ZIP nesting depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
                rule_code="S410",  # Archive bomb
                location=path,
                details={
                    "depth": depth,
                    "max_depth": self.max_depth,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "zip_depth_limit",
                },
            )
            result.finish(success=False)
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
            max_total_uncompressed_size = self._get_max_total_uncompressed_size()
            entries = z.infolist()

            # Check number of entries
            entry_count = len(entries)
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
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
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

            temp_base = os.path.join(tempfile.gettempdir(), "extract")
            extractable_entries: list[zipfile.ZipInfo] = []
            for info in entries:
                should_extract, entry_metadata_complete = self._validate_entry_metadata(
                    z, info, path, temp_base, result
                )
                if not entry_metadata_complete:
                    scan_complete = False
                if should_extract:
                    extractable_entries.append(info)

            archive_declared_uncompressed_size = sum(info.file_size for info in entries if not info.is_dir())
            archive_uncompressed_size = sum(info.file_size for info in extractable_entries)
            result.metadata["archive_declared_uncompressed_size"] = archive_declared_uncompressed_size
            result.metadata["archive_uncompressed_size"] = archive_uncompressed_size
            result.metadata["max_zip_total_uncompressed_size"] = max_total_uncompressed_size
            if archive_uncompressed_size > max_total_uncompressed_size:
                result.add_check(
                    name="ZIP Aggregate Size Limit Check",
                    passed=False,
                    message=(
                        f"ZIP total uncompressed size exceeds limit "
                        f"({archive_uncompressed_size} > {max_total_uncompressed_size} bytes); skipping extraction"
                    ),
                    severity=IssueSeverity.WARNING,
                    rule_code="S410",  # Archive bomb
                    location=path,
                    details={
                        "archive_uncompressed_size": archive_uncompressed_size,
                        "archive_declared_uncompressed_size": archive_declared_uncompressed_size,
                        "max_zip_total_uncompressed_size": max_total_uncompressed_size,
                    },
                )
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
                return result

            result.add_check(
                name="ZIP Aggregate Size Limit Check",
                passed=True,
                message=(
                    f"ZIP total uncompressed size ({archive_uncompressed_size}) is within "
                    f"limit ({max_total_uncompressed_size})"
                ),
                location=path,
                details={
                    "archive_uncompressed_size": archive_uncompressed_size,
                    "archive_declared_uncompressed_size": archive_declared_uncompressed_size,
                    "max_zip_total_uncompressed_size": max_total_uncompressed_size,
                },
                rule_code=None,
            )

            # Scan each file in the archive
            extracted_uncompressed_size = 0
            for info in extractable_entries:
                name = info.filename

                # Check compression ratio for zip bomb detection
                if info.compress_size > 0:
                    compression_ratio = info.file_size / info.compress_size
                    if (
                        compression_ratio > self.max_compression_ratio
                        and info.file_size >= self.min_compression_bomb_uncompressed_size
                    ):
                        result.add_check(
                            name="Compression Ratio Check",
                            passed=False,
                            message=(
                                f"Suspicious compression ratio ({compression_ratio:.1f}x) and "
                                f"uncompressed size ({info.file_size} bytes) in entry: {name}; skipping extraction"
                            ),
                            severity=IssueSeverity.WARNING,
                            rule_code="S410",  # Archive bomb
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "compressed_size": info.compress_size,
                                "uncompressed_size": info.file_size,
                                "ratio": compression_ratio,
                                "threshold": self.max_compression_ratio,
                                "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                            },
                        )
                        scan_complete = False
                        continue
                    else:
                        # Record safe compression ratio
                        if compression_ratio > self.max_compression_ratio:
                            message = (
                                f"Compression ratio ({compression_ratio:.1f}x) is below actionable size floor: {name}"
                            )
                        else:
                            message = f"Compression ratio ({compression_ratio:.1f}x) is within safe limits: {name}"
                        result.add_check(
                            name="Compression Ratio Check",
                            passed=True,
                            message=message,
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "compressed_size": info.compress_size,
                                "uncompressed_size": info.file_size,
                                "ratio": compression_ratio,
                                "threshold": self.max_compression_ratio,
                                "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                            },
                            rule_code=None,  # Passing check
                        )

                is_known_unreadable = self._is_known_unreadable_archive_entry(info)
                is_configured_skip = self._should_skip_archive_entry(name)
                if is_known_unreadable or is_configured_skip:
                    scan_complete = False
                    if is_executable_archive_member_name(name):
                        scan_archive_member_for_known_risks(
                            archive_kind="ZIP",
                            archive_path=path,
                            member_name=name,
                            tmp_path=None,
                            total_size=info.file_size,
                            result=result,
                            max_python_analysis_bytes=self._max_python_member_analysis_bytes(),
                            python_analysis_incomplete_reason="zip_python_member_analysis_incomplete",
                            executable_analysis_incomplete_reason="zip_executable_member_analysis_incomplete",
                        )
                    if is_known_unreadable:
                        skip_message = f"Skipped ZIP member analysis for known unreadable member: {name}"
                        skip_reason = "known_unreadable_archive_member_skip"
                    else:
                        skip_message = f"Skipped ZIP member analysis by configured request: {name}"
                        skip_reason = "configured_archive_member_skip"
                    result.add_check(
                        name="ZIP Member Analysis Coverage",
                        passed=False,
                        message=skip_message,
                        severity=IssueSeverity.INFO,
                        rule_code="S902",
                        location=f"{path}:{name}",
                        details={"entry": name, "reason": skip_reason},
                    )
                    continue

                if self._is_security_only_member_entry(name):
                    continue

                # Extract and scan the file
                tmp_path: str | None = None
                try:
                    max_entry_size = self._get_max_entry_size()

                    if name.lower().endswith(".zip"):
                        suffix = ".zip"
                    else:
                        safe_name = re.sub(
                            r"[^a-zA-Z0-9_.-]",
                            "_",
                            os.path.basename(name),
                        )
                        suffix = f"_{safe_name}"

                    try:
                        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                            tmp_path = tmp.name
                            total_size = 0
                            with z.open(info) as entry:
                                while True:
                                    chunk = entry.read(ARCHIVE_MEMBER_COPY_CHUNK_BYTES)
                                    if not chunk:
                                        break
                                    total_size += len(chunk)
                                    if total_size > max_entry_size:
                                        raise ValueError(
                                            f"ZIP entry {name} exceeds maximum size of {max_entry_size} bytes",
                                        )
                                    if extracted_uncompressed_size + total_size > max_total_uncompressed_size:
                                        raise ValueError(
                                            "ZIP archive exceeds maximum total uncompressed size of "
                                            f"{max_total_uncompressed_size} bytes",
                                        )
                                    tmp.write(chunk)
                            extracted_uncompressed_size += total_size

                        if archive_ext == ".mar" and name.lower().endswith(".py"):
                            mar_python_result = self._scan_mar_python_entry(path, name, tmp_path, total_size)
                            if mar_python_result is not None:
                                result.merge(mar_python_result)
                                if not mar_python_result.success:
                                    scan_complete = False
                        else:
                            scan_archive_member_for_known_risks(
                                archive_kind="ZIP",
                                archive_path=path,
                                member_name=name,
                                tmp_path=tmp_path,
                                total_size=total_size,
                                result=result,
                                max_python_analysis_bytes=self._max_python_member_analysis_bytes(),
                                python_analysis_incomplete_reason="zip_python_member_analysis_incomplete",
                                executable_analysis_incomplete_reason="zip_executable_member_analysis_incomplete",
                            )

                        nested_config = dict(self.config)
                        nested_config.pop("skip_archive_entries", None)
                        nested_config.pop(ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY, None)
                        nested_config.pop(KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY, None)
                        # Extracted members are deleted below and cannot provide
                        # stable cache keys for a subsequent scan.
                        nested_config["cache_enabled"] = False
                        nested_config["_archive_depth"] = depth + 1
                        if zipfile.is_zipfile(tmp_path):
                            nested_config["_zip_depth"] = depth + 1

                        # Dispatch nested members through the injected callback
                        # so production scans preserve core routing while direct
                        # ZipScanner usage still falls back to registry routing.
                        file_result = self._scan_nested_archive_entry(tmp_path, nested_config)
                        if member_scan_incomplete(file_result):
                            scan_complete = False

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
                        if tmp_path is not None:
                            with contextlib.suppress(FileNotFoundError):
                                os.unlink(tmp_path)

                except Exception as e:
                    scan_complete = False
                    mark_archive_scan_incomplete(result, "zip_entry_scan_incomplete")
                    result.add_check(
                        name="ZIP Entry Scan",
                        passed=False,
                        message=f"Error scanning ZIP entry {name}: {e!s}",
                        severity=IssueSeverity.INFO,
                        rule_code="S902",
                        location=f"{path}:{name}",
                        details={
                            "entry": name,
                            "exception": str(e),
                            "exception_type": type(e).__name__,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "zip_entry_scan_incomplete",
                        },
                    )

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(path)
        if not scan_complete:
            mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
        result.finish(success=scan_complete and not member_scan_incomplete(result) and not result.has_errors)
        return result

    def _max_python_member_analysis_bytes(self) -> int:
        """Resolve the bounded-AST-analysis cap, honoring the config override."""
        configured = self.config.get("max_mar_python_analysis_bytes", self.MAX_MAR_PYTHON_ANALYSIS_BYTES)
        if isinstance(configured, bool) or not isinstance(configured, int) or configured <= 0:
            return self.MAX_MAR_PYTHON_ANALYSIS_BYTES
        return configured

    def _scan_mar_python_entry(
        self,
        archive_path: str,
        entry_name: str,
        extracted_path: str,
        entry_size: int,
    ) -> ScanResult | None:
        """Apply TorchServe-style Python handler analysis for manifest-less `.mar` fallback."""
        max_analysis_bytes = self._max_python_member_analysis_bytes()

        if entry_size > max_analysis_bytes:
            result = ScanResult(scanner_name=self.name)
            mark_archive_scan_incomplete(result, "torchserve_handler_size_limit")
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=(
                    f"Skipped Python handler static analysis for oversized entry ({entry_size} bytes); "
                    f"limit is {max_analysis_bytes} bytes"
                ),
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:{entry_name}",
                details={
                    "entry": entry_name,
                    "entry_size": entry_size,
                    "size_limit": max_analysis_bytes,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_handler_size_limit",
                },
            )
            result.finish(success=False)
            return result

        try:
            with open(extracted_path, "rb") as source_file:
                source_bytes = source_file.read()
        except OSError as exc:
            result = ScanResult(scanner_name=self.name)
            mark_archive_scan_incomplete(result, "torchserve_handler_read_failed")
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=f"Unable to read Python entry for static analysis: {exc}",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:{entry_name}",
                details={
                    "entry": entry_name,
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_handler_read_failed",
                },
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
            mark_archive_scan_incomplete(result, "torchserve_handler_parse_failed")
            result.add_check(
                name="TorchServe Handler Static Analysis",
                passed=False,
                message=f"Unable to parse Python entry for static analysis: {parse_error}",
                severity=IssueSeverity.INFO,
                location=f"{archive_path}:{entry_name}",
                details={
                    "entry": entry_name,
                    "analysis_kind": "syntax",
                    "parse_error": parse_error,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "torchserve_handler_parse_failed",
                },
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
