"""Scanner for ExecuTorch model files (.pte)."""

import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, Final, cast

from ..scanner_results import mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, embedded_pickle_scanner
from ..utils import sanitize_archive_path
from ..utils.file.detection import (
    _is_executorch_binary_signature,
    _is_valid_executorch_binary,
    is_executorch_archive,
)
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner
from .picklescan_adapter import (
    apply_pickle_member_context,
)
from .pytorch_binary_scanner import PyTorchBinaryScanner

CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset({".bin", ".meta", ".pb"})
_ZIP_EOCD_SIGNATURE: Final[bytes] = b"PK\x05\x06"
_ZIP_EOCD_MIN_SIZE: Final[int] = 22
_ZIP_MAX_COMMENT_SIZE: Final[int] = 0xFFFF
_ZIP64_EOCD_LOCATOR_SIGNATURE: Final[bytes] = b"PK\x06\x07"
_ZIP64_EOCD_LOCATOR_SIZE: Final[int] = 20
_ZIP64_EOCD_SIGNATURE: Final[bytes] = b"PK\x06\x06"
_ZIP64_EOCD_MIN_SIZE: Final[int] = 56
_ZIP64_SENTINEL_ENTRY_COUNT: Final[int] = 0xFFFF
_ZIP_CENTRAL_DIRECTORY_SIGNATURE: Final[bytes] = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE: Final[int] = 46
_ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE: Final[bytes] = b"PK\x05\x05"
_ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE_HEADER_SIZE: Final[int] = 6
PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY = "_pytorch_binary_primary_scanned"


class ExecuTorchScanner(BaseScanner):
    """Scanner for PyTorch Mobile/ExecuTorch archives (.ptl, .pte)."""

    name = "executorch"
    description = "Scans ExecuTorch mobile model files for suspicious content"
    supported_extensions: ClassVar[list[str]] = [".ptl", ".pte"]
    DEFAULT_MAX_ARCHIVE_ENTRIES: ClassVar[int] = 10000
    DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE: ClassVar[int] = 64 * 1024 * 1024
    DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    MAX_COMPRESSION_RATIO: ClassVar[int] = 100
    MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE: ClassVar[int] = 1024 * 1024
    UNLIMITED_ARCHIVE_SIZE: ClassVar[int] = 1024 * 1024 * 1024 * 1024
    ZIP_ENTRY_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_entry_limit"
    ZIP_CENTRAL_DIRECTORY_INVALID_REASON: ClassVar[str] = "executorch_zip_central_directory_invalid"
    ZIP_CENTRAL_DIRECTORY_SIZE_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_central_directory_size_limit"
    ZIP_AGGREGATE_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_total_uncompressed_size_limit"
    ZIP_PICKLE_MEMBER_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_pickle_member_size_limit"
    ZIP_COMPRESSION_RATIO_INCONCLUSIVE_REASON: ClassVar[str] = "executorch_zip_compression_ratio_limit"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.pickle_scanner, self.scanner_selection = embedded_pickle_scanner(self.config, PickleScanner)
        self.max_archive_entries = self._normalize_positive_int_config(
            self.config.get(
                "max_executorch_zip_entries",
                self.config.get("max_archive_entries", self.config.get("max_zip_entries")),
            ),
            self.DEFAULT_MAX_ARCHIVE_ENTRIES,
        )
        self.max_central_directory_size = self._normalize_positive_int_config(
            self.config.get("max_executorch_zip_central_directory_size"),
            self.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE,
        )
        self.max_total_uncompressed_size = self._get_max_total_uncompressed_size()
        self.min_compression_bomb_uncompressed_size = self._normalize_positive_int_config(
            self.config.get("zip_min_compression_bomb_uncompressed_size"),
            self.MIN_COMPRESSION_BOMB_UNCOMPRESSED_SIZE,
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True
        if ext in CONTENT_ROUTE_BLOCKED_EXTENSIONS:
            return False
        try:
            header = cls._read_header(path, length=8)
        except OSError:
            return False
        return (_is_executorch_binary_signature(header) and _is_valid_executorch_binary(path)) or is_executorch_archive(
            path
        )

    @staticmethod
    def _read_header(path: str, length: int = 4) -> bytes:
        with open(path, "rb") as f:
            return f.read(length)

    @classmethod
    def _get_max_total_uncompressed_size_from_config(cls, config: dict[str, Any]) -> int:
        """Return the configured aggregate ExecuTorch ZIP budget."""
        positive_limits: list[int] = []
        configured_limit = config.get("max_executorch_zip_total_uncompressed_size")
        if configured_limit is None:
            configured_limit = config.get("max_zip_total_uncompressed_size")

        if configured_limit is not None:
            is_unlimited = (
                isinstance(configured_limit, int) and not isinstance(configured_limit, bool) and configured_limit == 0
            )
            if not is_unlimited:
                positive_limits.append(
                    cls._normalize_positive_int_config(configured_limit, cls.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)
                )
        else:
            positive_limits.append(cls.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)

        for config_key in ("max_total_size", "max_file_size"):
            configured_public_limit = config.get(config_key)
            if configured_public_limit is None or (
                isinstance(configured_public_limit, int)
                and not isinstance(configured_public_limit, bool)
                and configured_public_limit == 0
            ):
                continue
            positive_limits.append(
                cls._normalize_positive_int_config(configured_public_limit, cls.DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE)
            )

        return min(positive_limits) if positive_limits else cls.UNLIMITED_ARCHIVE_SIZE

    def _get_max_total_uncompressed_size(self) -> int:
        return self._get_max_total_uncompressed_size_from_config(self.config)

    @staticmethod
    def _find_zip_eocd_index(tail: bytes) -> tuple[int, bool, tuple[int, ...]] | None:
        candidate_indexes: list[int] = []
        search_start = 0
        while True:
            candidate_index = tail.find(_ZIP_EOCD_SIGNATURE, search_start)
            if candidate_index < 0:
                break
            if candidate_index + _ZIP_EOCD_MIN_SIZE <= len(tail):
                candidate_indexes.append(candidate_index)
            search_start = candidate_index + 1

        if not candidate_indexes:
            return None

        exact_candidates = []
        for candidate_index in candidate_indexes:
            comment_length = int.from_bytes(tail[candidate_index + 20 : candidate_index + 22], "little")
            if candidate_index + _ZIP_EOCD_MIN_SIZE + comment_length == len(tail):
                exact_candidates.append(candidate_index)

        selected_index = candidate_indexes[-1]
        ambiguous = len(exact_candidates) > 1 or (len(exact_candidates) == 1 and exact_candidates[0] != selected_index)
        return selected_index, ambiguous, tuple(candidate_indexes)

    @staticmethod
    def _count_central_directory_entries(
        handle: BinaryIO,
        *,
        directory_start: int,
        directory_size: int,
        entry_limit: int,
    ) -> tuple[int, bool]:
        """Count bounded central-directory records without constructing ZipInfo objects."""
        if directory_start < 0 or directory_size < 0:
            return 0, False

        handle.seek(directory_start)
        remaining = directory_size
        entry_count = 0
        while remaining > 0:
            signature = handle.read(4)
            if len(signature) != 4:
                return entry_count, False

            if signature == _ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE:
                signature_size_bytes = handle.read(2)
                if len(signature_size_bytes) != 2:
                    return entry_count, False
                signature_size = int.from_bytes(signature_size_bytes, "little")
                record_size = _ZIP_CENTRAL_DIRECTORY_DIGITAL_SIGNATURE_HEADER_SIZE + signature_size
                if record_size != remaining:
                    return entry_count, False
                handle.seek(signature_size, os.SEEK_CUR)
                remaining -= record_size
                continue

            if signature != _ZIP_CENTRAL_DIRECTORY_SIGNATURE or remaining < _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                return entry_count, False

            header_tail = handle.read(_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE - 4)
            if len(header_tail) != _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE - 4:
                return entry_count, False
            header = signature + header_tail

            filename_length = int.from_bytes(header[28:30], "little")
            extra_length = int.from_bytes(header[30:32], "little")
            comment_length = int.from_bytes(header[32:34], "little")
            record_size = _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + filename_length + extra_length + comment_length
            if record_size > remaining:
                return entry_count, False

            entry_count += 1
            if entry_count > entry_limit:
                return entry_count, True
            handle.seek(record_size - _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE, os.SEEK_CUR)
            remaining -= record_size

        return entry_count, True

    @classmethod
    def _has_prior_valid_eocd_overlay(
        cls,
        handle: BinaryIO,
        *,
        tail: bytes,
        tail_start: int,
        selected_index: int,
        candidate_indexes: tuple[int, ...],
        entry_limit: int,
        central_directory_size_limit: int,
    ) -> bool:
        """Detect a complete ZIP archive hidden before a trailing EOCD overlay."""
        for candidate_index in candidate_indexes:
            if candidate_index >= selected_index:
                continue
            comment_length = int.from_bytes(tail[candidate_index + 20 : candidate_index + 22], "little")
            if candidate_index + _ZIP_EOCD_MIN_SIZE + comment_length > selected_index:
                continue

            entry_count = int.from_bytes(tail[candidate_index + 10 : candidate_index + 12], "little")
            directory_size = int.from_bytes(tail[candidate_index + 12 : candidate_index + 16], "little")
            if entry_count == 0 and directory_size == 0:
                continue

            candidate_absolute_index = tail_start + candidate_index
            if entry_count == _ZIP64_SENTINEL_ENTRY_COUNT:
                locator_offset = candidate_absolute_index - _ZIP64_EOCD_LOCATOR_SIZE
                if locator_offset >= 0:
                    handle.seek(locator_offset)
                    if handle.read(4) == _ZIP64_EOCD_LOCATOR_SIGNATURE:
                        return True
                continue

            directory_start = candidate_absolute_index - directory_size
            if directory_size == 0 or directory_start < 0:
                continue
            if directory_size > central_directory_size_limit:
                handle.seek(directory_start)
                if handle.read(4) == _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                    return True
                continue

            parsed_count, parsed_completely = cls._count_central_directory_entries(
                handle,
                directory_start=directory_start,
                directory_size=directory_size,
                entry_limit=entry_limit,
            )
            if parsed_count > entry_limit or (parsed_completely and parsed_count > 0):
                return True
        return False

    @classmethod
    def _read_zip_entry_count(
        cls,
        handle: BinaryIO,
        file_size: int,
        entry_limit: int,
        central_directory_size_limit: int,
    ) -> tuple[int, int, bool] | None:
        """Read and validate bounded central-directory metadata without ZipInfo allocation."""
        if file_size < _ZIP_EOCD_MIN_SIZE:
            return None

        tail_size = min(file_size, _ZIP_EOCD_MIN_SIZE + _ZIP_MAX_COMMENT_SIZE)
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
        eocd_match = cls._find_zip_eocd_index(tail)
        if eocd_match is None:
            return None
        eocd_index, eocd_ambiguous, candidate_indexes = eocd_match

        entry_count = int.from_bytes(tail[eocd_index + 10 : eocd_index + 12], "little")
        central_directory_size = int.from_bytes(tail[eocd_index + 12 : eocd_index + 16], "little")
        tail_start = file_size - tail_size
        if eocd_ambiguous or cls._has_prior_valid_eocd_overlay(
            handle,
            tail=tail,
            tail_start=tail_start,
            selected_index=eocd_index,
            candidate_indexes=candidate_indexes,
            entry_limit=entry_limit,
            central_directory_size_limit=central_directory_size_limit,
        ):
            return entry_count, central_directory_size, False

        central_directory_end = tail_start + eocd_index
        locator_offset = central_directory_end - _ZIP64_EOCD_LOCATOR_SIZE
        zip64_locator_found = False
        if locator_offset >= 0:
            handle.seek(locator_offset)
            locator = handle.read(_ZIP64_EOCD_LOCATOR_SIZE)
            if locator.startswith(_ZIP64_EOCD_LOCATOR_SIGNATURE):
                zip64_locator_found = True
                stored_zip64_eocd_offset = int.from_bytes(locator[8:16], "little")
                candidate_offsets = [stored_zip64_eocd_offset]
                physical_zip64_eocd_offset = locator_offset - _ZIP64_EOCD_MIN_SIZE
                if physical_zip64_eocd_offset != stored_zip64_eocd_offset:
                    candidate_offsets.append(physical_zip64_eocd_offset)

                zip64_eocd = b""
                for candidate_offset in candidate_offsets:
                    if candidate_offset < 0:
                        continue
                    handle.seek(candidate_offset)
                    candidate = handle.read(_ZIP64_EOCD_MIN_SIZE)
                    if len(candidate) >= _ZIP64_EOCD_MIN_SIZE and candidate.startswith(_ZIP64_EOCD_SIGNATURE):
                        zip64_eocd = candidate
                        central_directory_end = candidate_offset
                        break
                if not zip64_eocd:
                    return entry_count, central_directory_size, False

                entry_count = int.from_bytes(zip64_eocd[32:40], "little")
                central_directory_size = int.from_bytes(zip64_eocd[40:48], "little")

        if entry_count == _ZIP64_SENTINEL_ENTRY_COUNT and not zip64_locator_found:
            return entry_count, central_directory_size, False
        if entry_count > entry_limit or central_directory_size > central_directory_size_limit:
            return entry_count, central_directory_size, True

        parsed_entry_count, parsed_completely = cls._count_central_directory_entries(
            handle,
            directory_start=central_directory_end - central_directory_size,
            directory_size=central_directory_size,
            entry_limit=entry_limit,
        )
        return (
            max(entry_count, parsed_entry_count),
            central_directory_size,
            parsed_completely and parsed_entry_count == entry_count,
        )

    @staticmethod
    def _finish_read_failure(result: ScanResult, path: str, exc: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, "executorch_read_failed")
        result.add_check(
            name="ExecuTorch File Read",
            passed=False,
            message=f"Unable to read ExecuTorch content: {exc!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(exc),
                "exception_type": type(exc).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "executorch_read_failed",
            },
            rule_code="S902",
        )
        result.finish(success=False)
        return result

    @classmethod
    def _add_zip_budget_failure(
        cls,
        result: ScanResult,
        path: str,
        *,
        check_name: str,
        message: str,
        details: dict[str, Any],
        reason: str,
        rule_code: str = "S410",
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name=check_name,
            passed=False,
            message=message,
            severity=IssueSeverity.WARNING,
            location=path,
            details={
                **details,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            rule_code=rule_code,
        )

    @classmethod
    def _finish_zip_budget_failure(
        cls,
        result: ScanResult,
        path: str,
        *,
        check_name: str,
        message: str,
        details: dict[str, Any],
        reason: str,
        rule_code: str = "S410",
    ) -> ScanResult:
        cls._add_zip_budget_failure(
            result,
            path,
            check_name=check_name,
            message=message,
            details=details,
            reason=reason,
            rule_code=rule_code,
        )
        result.finish(success=False)
        return result

    def _check_zip_entry_count_preflight(
        self,
        result: ScanResult,
        path: str,
        archive_handle: BinaryIO,
        file_size: int,
    ) -> ScanResult | None:
        preflight = self._read_zip_entry_count(
            archive_handle,
            file_size,
            self.max_archive_entries,
            self.max_central_directory_size,
        )
        if preflight is None:
            return None
        entry_count, central_directory_size, central_directory_valid = preflight

        result.metadata["executorch_zip_entry_count"] = entry_count
        result.metadata["max_executorch_zip_entries"] = self.max_archive_entries
        result.metadata["executorch_zip_central_directory_size"] = central_directory_size
        result.metadata["max_executorch_zip_central_directory_size"] = self.max_central_directory_size

        if entry_count > self.max_archive_entries:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Entry Count Preflight",
                message=(
                    f"ExecuTorch ZIP contains too many entries before archive open "
                    f"({entry_count} > {self.max_archive_entries})"
                ),
                details={
                    "entry_count": entry_count,
                    "max_entries": self.max_archive_entries,
                    "phase": "pre_open",
                },
                reason=self.ZIP_ENTRY_LIMIT_INCONCLUSIVE_REASON,
            )

        if central_directory_size > self.max_central_directory_size:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Central Directory Size Preflight",
                message=(
                    f"ExecuTorch ZIP central directory exceeds the pre-open allocation limit "
                    f"({central_directory_size} > {self.max_central_directory_size} bytes)"
                ),
                details={
                    "central_directory_size": central_directory_size,
                    "max_central_directory_size": self.max_central_directory_size,
                    "phase": "pre_open",
                },
                reason=self.ZIP_CENTRAL_DIRECTORY_SIZE_LIMIT_INCONCLUSIVE_REASON,
            )

        if central_directory_valid:
            return None
        return self._finish_zip_budget_failure(
            result,
            path,
            check_name="ExecuTorch ZIP Central Directory Preflight",
            message="ExecuTorch ZIP central-directory metadata is inconsistent; refusing incomplete analysis",
            details={
                "entry_count": entry_count,
                "central_directory_size": central_directory_size,
                "phase": "pre_open",
            },
            reason=self.ZIP_CENTRAL_DIRECTORY_INVALID_REASON,
            rule_code="S902",
        )

    def _check_zip_entry_count(
        self, result: ScanResult, path: str, entries: list[zipfile.ZipInfo]
    ) -> ScanResult | None:
        entry_count = len(entries)
        result.metadata["executorch_zip_entry_count"] = entry_count
        result.metadata["max_executorch_zip_entries"] = self.max_archive_entries
        if entry_count > self.max_archive_entries:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Entry Count Limit",
                message=f"ExecuTorch ZIP contains too many entries ({entry_count} > {self.max_archive_entries})",
                details={
                    "entry_count": entry_count,
                    "max_entries": self.max_archive_entries,
                    "phase": "post_open",
                },
                reason=self.ZIP_ENTRY_LIMIT_INCONCLUSIVE_REASON,
            )

        result.add_check(
            name="ExecuTorch ZIP Entry Count Limit",
            passed=True,
            message=f"ExecuTorch ZIP entry count ({entry_count}) is within limits",
            location=path,
            details={
                "entry_count": entry_count,
                "max_entries": self.max_archive_entries,
            },
        )
        return None

    def _check_pickle_member_budgets(
        self,
        result: ScanResult,
        path: str,
        pickle_entries: list[zipfile.ZipInfo],
    ) -> tuple[list[zipfile.ZipInfo], bool]:
        small_high_ratio_uncompressed_size = 0
        small_high_ratio_compressed_size = 0
        small_high_ratio_entries: list[zipfile.ZipInfo] = []
        oversized_entries: list[zipfile.ZipInfo] = []
        large_high_ratio_entries: list[tuple[zipfile.ZipInfo, float | None]] = []
        blocked_entry_ids: set[int] = set()
        analysis_incomplete = False
        pickle_member_limit = self.pickle_scanner.max_file_read_size if self.pickle_scanner is not None else 0
        for entry in pickle_entries:
            if pickle_member_limit > 0 and entry.file_size > pickle_member_limit:
                oversized_entries.append(entry)
                blocked_entry_ids.add(id(entry))
                analysis_incomplete = True
                continue

            compression_ratio = entry.file_size / entry.compress_size if entry.compress_size > 0 else None
            exceeds_ratio = compression_ratio is None or compression_ratio > self.MAX_COMPRESSION_RATIO
            if not exceeds_ratio:
                continue

            if entry.file_size < self.min_compression_bomb_uncompressed_size:
                small_high_ratio_uncompressed_size += entry.file_size
                small_high_ratio_compressed_size += entry.compress_size
                small_high_ratio_entries.append(entry)
                continue

            large_high_ratio_entries.append((entry, compression_ratio))
            blocked_entry_ids.add(id(entry))
            analysis_incomplete = True

        if oversized_entries:
            first_entry = oversized_entries[0]
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Pickle Member Size Limit",
                message=(
                    f"ExecuTorch pickle member {first_entry.filename} exceeds the pickle scan limit "
                    f"({first_entry.file_size} > {pickle_member_limit} bytes); skipping "
                    f"{len(oversized_entries)} oversized member content scan(s)"
                ),
                details={
                    "member": first_entry.filename,
                    "member_count": len(oversized_entries),
                    "uncompressed_size": first_entry.file_size,
                    "max_pickle_member_size": pickle_member_limit,
                },
                reason=self.ZIP_PICKLE_MEMBER_LIMIT_INCONCLUSIVE_REASON,
            )

        if large_high_ratio_entries:
            first_entry, first_ratio = large_high_ratio_entries[0]
            ratio_text = "infinite" if first_ratio is None else f"{first_ratio:.1f}x"
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Pickle Compression Ratio Limit",
                message=(
                    f"ExecuTorch pickle member {first_entry.filename} has a suspicious compression ratio "
                    f"({ratio_text}); skipping {len(large_high_ratio_entries)} suspicious member content scan(s)"
                ),
                details={
                    "member": first_entry.filename,
                    "member_count": len(large_high_ratio_entries),
                    "compressed_size": first_entry.compress_size,
                    "uncompressed_size": first_entry.file_size,
                    "compression_ratio": first_ratio,
                    "max_compression_ratio": self.MAX_COMPRESSION_RATIO,
                    "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                },
                reason=self.ZIP_COMPRESSION_RATIO_INCONCLUSIVE_REASON,
            )

        if small_high_ratio_uncompressed_size >= self.min_compression_bomb_uncompressed_size:
            aggregate_ratio = (
                small_high_ratio_uncompressed_size / small_high_ratio_compressed_size
                if small_high_ratio_compressed_size > 0
                else None
            )
            ratio_text = "infinite" if aggregate_ratio is None else f"{aggregate_ratio:.1f}x"
            self._add_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Pickle Compression Ratio Limit",
                message=(
                    "ExecuTorch ZIP contains multiple small pickle members with a suspicious aggregate "
                    f"compression ratio ({ratio_text}); skipping those member content scans"
                ),
                details={
                    "aggregate_small_member_check": True,
                    "member_count": len(small_high_ratio_entries),
                    "compressed_size": small_high_ratio_compressed_size,
                    "uncompressed_size": small_high_ratio_uncompressed_size,
                    "compression_ratio": aggregate_ratio,
                    "max_compression_ratio": self.MAX_COMPRESSION_RATIO,
                    "min_uncompressed_size": self.min_compression_bomb_uncompressed_size,
                },
                reason=self.ZIP_COMPRESSION_RATIO_INCONCLUSIVE_REASON,
            )
            blocked_entry_ids.update(id(entry) for entry in small_high_ratio_entries)
            analysis_incomplete = True

        scannable_entries = [entry for entry in pickle_entries if id(entry) not in blocked_entry_ids]
        return scannable_entries, analysis_incomplete

    def _check_zip_aggregate_size(
        self,
        result: ScanResult,
        path: str,
        *,
        all_entries: list[zipfile.ZipInfo],
        safe_entries: list[zipfile.ZipInfo],
    ) -> ScanResult | None:
        declared_uncompressed_size = sum(entry.file_size for entry in all_entries if not entry.is_dir())
        safe_uncompressed_size = sum(entry.file_size for entry in safe_entries if not entry.is_dir())
        result.metadata["executorch_zip_declared_uncompressed_size"] = declared_uncompressed_size
        result.metadata["executorch_zip_uncompressed_size"] = safe_uncompressed_size
        result.metadata["max_executorch_zip_total_uncompressed_size"] = self.max_total_uncompressed_size
        if safe_uncompressed_size > self.max_total_uncompressed_size:
            return self._finish_zip_budget_failure(
                result,
                path,
                check_name="ExecuTorch ZIP Aggregate Size Limit",
                message=(
                    f"ExecuTorch ZIP total uncompressed size exceeds limit "
                    f"({safe_uncompressed_size} > {self.max_total_uncompressed_size} bytes); "
                    "skipping member content scan"
                ),
                details={
                    "archive_uncompressed_size": safe_uncompressed_size,
                    "archive_declared_uncompressed_size": declared_uncompressed_size,
                    "max_total_uncompressed_size": self.max_total_uncompressed_size,
                },
                reason=self.ZIP_AGGREGATE_LIMIT_INCONCLUSIVE_REASON,
            )

        result.add_check(
            name="ExecuTorch ZIP Aggregate Size Limit",
            passed=True,
            message=(
                f"ExecuTorch ZIP total uncompressed size ({safe_uncompressed_size}) is within "
                f"limit ({self.max_total_uncompressed_size})"
            ),
            location=path,
            details={
                "archive_uncompressed_size": safe_uncompressed_size,
                "archive_declared_uncompressed_size": declared_uncompressed_size,
                "max_total_uncompressed_size": self.max_total_uncompressed_size,
            },
        )
        return None

    @staticmethod
    def _add_python_entry_checks(result: ScanResult, path: str, safe_entries: list[zipfile.ZipInfo]) -> None:
        for entry in safe_entries:
            name = entry.filename
            if name.casefold().endswith(".py"):
                result.add_check(
                    name="Python File Detection",
                    passed=False,
                    message=f"Python code file found in ExecuTorch model: {name}",
                    severity=IssueSeverity.INFO,
                    location=f"{path}:{name}",
                    details={"file": name},
                    rule_code="S507",  # Python embedded code
                )
                result.add_check(
                    name="Executable File Detection",
                    passed=False,
                    message=f"Executable file found in ExecuTorch model: {name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path}:{name}",
                    details={"file": name},
                    rule_code="S104",
                )

    @staticmethod
    def _supplemental_raw_binary_config(config: dict[str, Any]) -> dict[str, Any]:
        raw_config = dict(config)
        try:
            archive_depth = int(raw_config.get("_archive_depth", 0))
        except (TypeError, ValueError):
            archive_depth = 0
        raw_config["_archive_depth"] = max(archive_depth, 1)
        return raw_config

    def _merge_raw_binary_analysis(self, path: str, result: ScanResult, file_size: int) -> None:
        if self.config.get(PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY) is True:
            result.bytes_scanned = max(result.bytes_scanned, file_size)
            return

        if not self.scanner_selection.allows("pytorch_binary"):
            add_scanner_selection_skip_check(
                result,
                path,
                "pytorch_binary",
                self.scanner_selection,
                context="supplemental ExecuTorch binary raw payload analysis",
            )
            result.bytes_scanned = max(result.bytes_scanned, file_size)
            return

        primary_bytes_scanned = result.bytes_scanned
        raw_result = PyTorchBinaryScanner(config=self._supplemental_raw_binary_config(self.config)).scan(path)
        result.merge(raw_result)
        result.bytes_scanned = max(primary_bytes_scanned, raw_result.bytes_scanned, file_size)
        supplemental_scanners = result.metadata.setdefault("supplemental_scanners", [])
        if isinstance(supplemental_scanners, list):
            supplemental_scanners.append("pytorch_binary")

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        pickle_coverage_incomplete = False

        try:
            header = self._read_header(path, length=8)
            valid_binary_program = _is_executorch_binary_signature(header) and _is_valid_executorch_binary(
                path,
                propagate_io_errors=True,
            )
        except OSError as exc:
            return self._finish_read_failure(result, path, exc)
        if valid_binary_program:
            result.add_check(
                name="ExecuTorch Binary Format Validation",
                passed=True,
                message="Valid ExecuTorch binary program format detected",
                location=path,
                details={"path": path, "format": "executorch_binary"},
            )

        should_scan_archive = header.startswith(b"PK")
        if not should_scan_archive:
            try:
                should_scan_archive = zipfile.is_zipfile(path)
            except OSError as exc:
                return self._finish_read_failure(result, path, exc)

        if valid_binary_program and not should_scan_archive:
            result.bytes_scanned = file_size
            self._merge_raw_binary_analysis(path, result, file_size)
            result.finish(success=not result.has_errors)
            return result

        if not should_scan_archive:
            result.add_check(
                name="ExecuTorch Archive Format Validation",
                passed=False,
                message=f"Not a valid ExecuTorch archive: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S104",
            )
            result.finish(success=False)
            return result

        archive_handle: BinaryIO | None = None
        try:
            # Kept open across preflight and ZipFile to prevent path-reopen races.
            archive_handle = Path(path).open("rb")  # noqa: SIM115
            preflight_result = self._check_zip_entry_count_preflight(result, path, archive_handle, file_size)
            if preflight_result:
                return preflight_result

            archive_handle.seek(0)
            self.current_file_path = path
            with zipfile.ZipFile(archive_handle, "r") as z:
                archive_entries = z.infolist()
                entry_limit_result = self._check_zip_entry_count(result, path, archive_entries)
                if entry_limit_result:
                    return entry_limit_result

                safe_entries: list[zipfile.ZipInfo] = []
                for entry in archive_entries:
                    name = entry.filename
                    temp_base = os.path.join(tempfile.gettempdir(), "extract")
                    _, is_safe = sanitize_archive_path(name, temp_base)
                    if not is_safe:
                        result.add_check(
                            name="Path Traversal Protection",
                            passed=False,
                            message=f"Archive entry {name} attempted path traversal outside the archive",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"entry": name},
                            rule_code="S405",
                        )
                        continue
                    safe_entries.append(entry)

                self._add_python_entry_checks(result, path, safe_entries)
                aggregate_limit_result = self._check_zip_aggregate_size(
                    result,
                    path,
                    all_entries=archive_entries,
                    safe_entries=safe_entries,
                )
                if aggregate_limit_result:
                    return aggregate_limit_result

                pickle_entries = [entry for entry in safe_entries if entry.filename.casefold().endswith(".pkl")]
                pickle_files = [entry.filename for entry in pickle_entries]
                result.metadata["pickle_files"] = pickle_files
                pickle_entries, pickle_coverage_incomplete = self._check_pickle_member_budgets(
                    result,
                    path,
                    pickle_entries,
                )
                bytes_scanned = 0

                for member_info in pickle_entries:
                    name = member_info.filename
                    bytes_scanned += member_info.file_size
                    if self.pickle_scanner is None:
                        add_scanner_selection_skip_check(
                            result,
                            f"{path}:{name}",
                            "pickle",
                            self.scanner_selection,
                            context="embedded ExecuTorch pickle analysis",
                        )
                        continue

                    with z.open(member_info, "r") as file_like:
                        sub_result = self.pickle_scanner.scan_stream(
                            cast(BinaryIO, file_like),
                            member_info.file_size,
                            source=f"{path}:{name}",
                        )
                    apply_pickle_member_context(sub_result, archive_path=path, member_name=name)
                    result.merge(sub_result)

                result.bytes_scanned = bytes_scanned
        except zipfile.BadZipFile:
            result.add_check(
                name="ZIP File Format Validation",
                passed=False,
                message=f"Not a valid zip file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S902",
            )
            result.finish(success=False)
            return result
        except OSError as exc:
            return self._finish_read_failure(result, path, exc)
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_check(
                name="ExecuTorch File Scan",
                passed=False,
                message=f"Error scanning ExecuTorch file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result
        finally:
            if archive_handle is not None:
                archive_handle.close()

        if valid_binary_program or not header.startswith(b"PK"):
            self._merge_raw_binary_analysis(path, result, file_size)
        result.finish(success=not pickle_coverage_incomplete)
        return result
