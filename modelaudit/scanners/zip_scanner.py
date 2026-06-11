import bz2
import contextlib
import os
import re
import stat
import tempfile
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, BinaryIO, ClassVar, cast

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
ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY = "_zip_content_only_member_entries"
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_MIN_SIZE = 22
_ZIP_MAX_COMMENT_SIZE = 0xFFFF
_ZIP_MAX_EOCD_CANDIDATES = 16
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_ZIP_MAX_CENTRAL_DIRECTORY_RECORD_SIZE = _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + (3 * 0xFFFF)
_ZIP_LOCAL_FILE_HEADER_SIGNATURE = b"PK\x03\x04"
_ZIP_LOCAL_FILE_HEADER_SIZE = 30
_ZIP_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_ZIP_ARCHIVE_EXTRA_DATA_SIGNATURE = b"PK\x06\x08"
_ZIP_MAX_ARCHIVE_EXTRA_DATA_RECORDS = 1024
_ZIP_MAX_LOCAL_PREFIX_SCAN_SIZE = 64 * 1024 * 1024
_ZIP_MAX_LOCAL_PAYLOAD_VALIDATION_SIZE = 64 * 1024 * 1024
_ZIP_MAX_LOCAL_PAYLOAD_VALIDATION_TOTAL = 64 * 1024 * 1024
_ZIP_MAX_LOCAL_DESCRIPTOR_SEARCH_WORK = 1_000_000
_ZIP_MAX_LOCAL_ENTRY_PADDING = 64 * 1024
_ZIP_MAX_LOCAL_HEADER_CANDIDATES = 10000
_ZIP64_EOCD_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_EOCD_LOCATOR_SIZE = 20
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_EOCD_MIN_SIZE = 56
_ZIP64_SENTINEL_ENTRY_COUNT = 0xFFFF
_ZIP64_SENTINEL_OFFSET = 0xFFFFFFFF
_UNIX_MODE_ZIP_CREATOR_SYSTEMS = frozenset({3, 19})


@dataclass(frozen=True)
class _ZipDirectoryMetadata:
    entry_count: int
    directory_start: int
    directory_size: int
    archive_prefix_size: int


@dataclass(frozen=True)
class _ZipCentralDirectoryEntry:
    filename: bytes
    flags: int
    creator_system: int
    external_attr: int
    compression_method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    relative_local_offset: int
    uses_zip64_sizes: bool

    @property
    def is_symlink(self) -> bool:
        """Return whether Unix mode metadata declares this entry as a symlink."""
        return self.creator_system in _UNIX_MODE_ZIP_CREATOR_SYSTEMS and stat.S_ISLNK(self.external_attr >> 16)


@dataclass(frozen=True)
class _ZipLocalEntryLayout:
    offset: int
    end_candidates: frozenset[int]


class _InvalidZipDirectory(ValueError):
    def __init__(self, message: str, *, routing_evidence: bool = False):
        super().__init__(message)
        self.routing_evidence = routing_evidence


class _ZipLocalEntryMismatch(_InvalidZipDirectory):
    """Raised when a central-directory entry does not match its local record."""

    def __init__(self, message: str, entry: _ZipCentralDirectoryEntry):
        super().__init__(message, routing_evidence=True)
        self.entry = entry


class _ZipCentralDirectorySizeExceeded(_InvalidZipDirectory):
    def __init__(self, directory_size: int, max_directory_size: int):
        super().__init__(
            f"ZIP central directory is too large ({directory_size} > {max_directory_size} bytes)",
            routing_evidence=True,
        )
        self.directory_size = directory_size
        self.max_directory_size = max_directory_size


class ZipPreflightRejected(Exception):
    """Raised when a same-handle ZIP preflight produces a terminal scan result."""

    def __init__(self, result: ScanResult):
        super().__init__("ZIP central-directory preflight rejected the archive")
        self.result = result


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
    DEFAULT_MAX_ENTRIES: ClassVar[int] = 10000
    DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE: ClassVar[int] = 64 * 1024 * 1024
    DEFAULT_MAX_ENTRY_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    DEFAULT_MAX_TOTAL_UNCOMPRESSED_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    UNLIMITED_ARCHIVE_SIZE: ClassVar[int] = 1024 * 1024 * 1024 * 1024

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_depth = self.config.get("max_zip_depth", 5)  # Prevent zip bomb attacks
        self.max_entries = self.config.get(
            "max_zip_entries",
            self.DEFAULT_MAX_ENTRIES,
        )  # Limit number of entries
        self.max_central_directory_size = self.central_directory_size_limit(self.config)
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
        self.content_only_member_entries = self._normalize_archive_entry_names(
            self.config.get(ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY, ())
        )

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

    @classmethod
    def central_directory_size_limit(cls, config: dict[str, Any] | None = None) -> int:
        """Return the byte cap applied before ``zipfile`` materializes directory metadata."""
        raw_limit = (config or {}).get("max_zip_central_directory_size")
        configured_limit = cls._normalize_positive_int_config(raw_limit, cls.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE)
        return min(configured_limit, cls.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE)

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

    def _is_content_only_member_entry(self, name: str) -> bool:
        return self._normalize_skip_entry_name(name) in self.content_only_member_entries

    @staticmethod
    def _preserve_nested_routing_basename(name: str) -> bool:
        """Return True when nested scanner routing depends on the exact basename."""
        basename = os.path.basename(name).lower()
        ext = os.path.splitext(basename)[1]
        if ext in {".zip", ".npz", ".mar"}:
            return True
        return (
            basename == ".env"
            or basename == "readme"
            or (basename.startswith("readme.") and ext in {".txt", ".md", ".markdown", ".rst"})
            or basename == "model_card"
            or (basename.startswith(("model_card.", "modelcard.")) and ext in {".txt", ".md", ".markdown", ".rst"})
        )

    def _is_known_unreadable_archive_entry(self, info: zipfile.ZipInfo) -> bool:
        return info.header_offset in self.known_unreadable_archive_entry_offsets

    @staticmethod
    def _find_zip_eocd_indices(tail: bytes) -> tuple[int, ...]:
        primary_index = tail.rfind(_ZIP_EOCD_SIGNATURE)
        if primary_index < 0 or primary_index + _ZIP_EOCD_MIN_SIZE > len(tail):
            return ()

        earlier_indices: list[int] = []
        primary_record_end = primary_index + _ZIP_EOCD_MIN_SIZE
        primary_is_empty = not any(tail[primary_index + 8 : primary_index + 16])
        search_start = 0
        while True:
            eocd_index = tail.find(_ZIP_EOCD_SIGNATURE, search_start, primary_index)
            if eocd_index < 0 or eocd_index + _ZIP_EOCD_MIN_SIZE > len(tail):
                return (primary_index, *reversed(earlier_indices))
            comment_length = int.from_bytes(tail[eocd_index + 20 : eocd_index + 22], "little")
            record_fields = tail[eocd_index + 8 : eocd_index + 20]
            if eocd_index + _ZIP_EOCD_MIN_SIZE + comment_length >= primary_record_end or (
                primary_is_empty and any(record_fields)
            ):
                earlier_indices.append(eocd_index)
                if len(earlier_indices) + 1 >= _ZIP_MAX_EOCD_CANDIDATES:
                    return (primary_index, *reversed(earlier_indices))
            search_start = eocd_index + 1

    @staticmethod
    def _zip_directory_metadata(
        *,
        entry_count: int,
        directory_size: int,
        directory_offset: int,
        directory_end: int,
    ) -> _ZipDirectoryMetadata:
        directory_start = directory_end - directory_size
        if directory_start < 0 or directory_offset > directory_start:
            raise _InvalidZipDirectory("ZIP central-directory offsets are inconsistent")
        return _ZipDirectoryMetadata(
            entry_count=entry_count,
            directory_start=directory_start,
            directory_size=directory_size,
            archive_prefix_size=directory_start - directory_offset,
        )

    @classmethod
    def _read_zip64_directory_metadata(
        cls,
        handle: BinaryIO,
        *,
        locator_offset: int,
    ) -> _ZipDirectoryMetadata:
        if locator_offset < 0:
            raise _InvalidZipDirectory("ZIP64 locator is missing")

        handle.seek(locator_offset)
        locator = handle.read(_ZIP64_EOCD_LOCATOR_SIZE)
        if len(locator) != _ZIP64_EOCD_LOCATOR_SIZE or not locator.startswith(_ZIP64_EOCD_LOCATOR_SIGNATURE):
            raise _InvalidZipDirectory("ZIP64 locator is missing")
        if int.from_bytes(locator[4:8], "little") != 0 or int.from_bytes(locator[16:20], "little") != 1:
            raise _InvalidZipDirectory("multi-disk ZIP64 archives are unsupported")

        relative_record_offset = int.from_bytes(locator[8:16], "little")
        candidate_offsets = (relative_record_offset, locator_offset - _ZIP64_EOCD_MIN_SIZE)
        record_offset: int | None = None
        record = b""
        for candidate_offset in candidate_offsets:
            if candidate_offset < 0 or candidate_offset > locator_offset - _ZIP64_EOCD_MIN_SIZE:
                continue
            try:
                handle.seek(candidate_offset)
                candidate = handle.read(_ZIP64_EOCD_MIN_SIZE)
            except (OSError, OverflowError, ValueError):
                continue
            if len(candidate) == _ZIP64_EOCD_MIN_SIZE and candidate.startswith(_ZIP64_EOCD_SIGNATURE):
                record_offset = candidate_offset
                record = candidate
                break
        if record_offset is None:
            raise _InvalidZipDirectory("ZIP64 end-of-directory record is missing")

        record_size = int.from_bytes(record[4:12], "little")
        if record_size < _ZIP64_EOCD_MIN_SIZE - 12 or record_offset + 12 + record_size != locator_offset:
            raise _InvalidZipDirectory("ZIP64 end-of-directory size is inconsistent")
        if int.from_bytes(record[16:20], "little") != 0 or int.from_bytes(record[20:24], "little") != 0:
            raise _InvalidZipDirectory("multi-disk ZIP64 archives are unsupported")

        entries_on_disk = int.from_bytes(record[24:32], "little")
        entry_count = int.from_bytes(record[32:40], "little")
        directory_size = int.from_bytes(record[40:48], "little")
        directory_offset = int.from_bytes(record[48:56], "little")
        if entries_on_disk != entry_count or directory_offset + directory_size != relative_record_offset:
            raise _InvalidZipDirectory("ZIP64 central-directory metadata is inconsistent", routing_evidence=True)
        return cls._zip_directory_metadata(
            entry_count=entry_count,
            directory_size=directory_size,
            directory_offset=directory_offset,
            directory_end=record_offset,
        )

    @classmethod
    def _read_zip_directory_metadata_at(
        cls,
        handle: BinaryIO,
        *,
        file_size: int,
        tail_size: int,
        tail: bytes,
        eocd_index: int,
    ) -> _ZipDirectoryMetadata:
        eocd = tail[eocd_index : eocd_index + _ZIP_EOCD_MIN_SIZE]
        disk_number = int.from_bytes(eocd[4:6], "little")
        directory_disk = int.from_bytes(eocd[6:8], "little")
        entries_on_disk = int.from_bytes(eocd[8:10], "little")
        entry_count = int.from_bytes(eocd[10:12], "little")
        eocd_offset = file_size - tail_size + eocd_index
        directory_size = int.from_bytes(eocd[12:16], "little")
        directory_offset = int.from_bytes(eocd[16:20], "little")
        locator_offset = eocd_offset - _ZIP64_EOCD_LOCATOR_SIZE
        if locator_offset >= 0:
            handle.seek(locator_offset)
            if handle.read(len(_ZIP64_EOCD_LOCATOR_SIGNATURE)) == _ZIP64_EOCD_LOCATOR_SIGNATURE:
                return cls._read_zip64_directory_metadata(handle, locator_offset=locator_offset)
        if (
            entry_count == _ZIP64_SENTINEL_ENTRY_COUNT
            or entries_on_disk == _ZIP64_SENTINEL_ENTRY_COUNT
            or directory_size == _ZIP64_SENTINEL_OFFSET
            or directory_offset == _ZIP64_SENTINEL_OFFSET
        ):
            return cls._read_zip64_directory_metadata(
                handle,
                locator_offset=eocd_offset - _ZIP64_EOCD_LOCATOR_SIZE,
            )
        if disk_number != 0 or directory_disk != 0:
            raise _InvalidZipDirectory("multi-disk ZIP archives are unsupported")
        if entries_on_disk != entry_count:
            raise _InvalidZipDirectory("ZIP entry counts are inconsistent")
        return cls._zip_directory_metadata(
            entry_count=entry_count,
            directory_size=directory_size,
            directory_offset=directory_offset,
            directory_end=eocd_offset,
        )

    @classmethod
    def _read_zip_tail(cls, handle: BinaryIO) -> tuple[int, int, bytes, tuple[int, ...]] | None:
        handle.seek(0, os.SEEK_END)
        file_size = handle.tell()
        if file_size < _ZIP_EOCD_MIN_SIZE:
            return None
        tail_size = min(file_size, _ZIP_EOCD_MIN_SIZE + _ZIP_MAX_COMMENT_SIZE)
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
        return file_size, tail_size, tail, cls._find_zip_eocd_indices(tail)

    @classmethod
    def _has_zip_routing_evidence(cls, path: str) -> bool:
        return os.path.splitext(path)[1].lower() in cls.supported_extensions

    @classmethod
    def _count_bounded_central_directory_entries(
        cls,
        handle: BinaryIO,
        metadata: _ZipDirectoryMetadata,
        max_entries: int,
    ) -> tuple[int, bool]:
        """Count fixed central-directory records, stopping once the configured cap is exceeded."""
        consumed = 0
        entry_count = 0
        entries: list[_ZipCentralDirectoryEntry] = []
        try:
            handle.seek(metadata.directory_start)
            while consumed < metadata.directory_size:
                remaining = metadata.directory_size - consumed
                if remaining < _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                    raise _InvalidZipDirectory(
                        "ZIP central directory is truncated",
                        routing_evidence=entry_count > 0,
                    )
                header = handle.read(_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE)
                if len(header) != _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                    raise _InvalidZipDirectory(
                        "ZIP central directory is truncated",
                        routing_evidence=entry_count > 0,
                    )
                if not header.startswith(_ZIP_CENTRAL_DIRECTORY_SIGNATURE):
                    raise _InvalidZipDirectory("ZIP central-directory signature is invalid")

                variable_size = (
                    int.from_bytes(header[28:30], "little")
                    + int.from_bytes(header[30:32], "little")
                    + int.from_bytes(header[32:34], "little")
                )
                record_size = _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + variable_size
                if record_size > remaining:
                    raise _InvalidZipDirectory(
                        "ZIP central-directory record exceeds its declared size",
                        routing_evidence=True,
                    )

                entry_count += 1
                if entry_count > max_entries:
                    return entry_count, True
                variable_data = handle.read(variable_size)
                if len(variable_data) != variable_size:
                    raise _InvalidZipDirectory(
                        "ZIP central directory is truncated",
                        routing_evidence=True,
                    )
                filename_size = int.from_bytes(header[28:30], "little")
                extra_size = int.from_bytes(header[30:32], "little")
                filename = variable_data[:filename_size]
                extra = variable_data[filename_size : filename_size + extra_size]
                entries.append(cls._central_directory_entry(header, filename, extra))
                consumed += record_size
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP central directory could not be read: {exc}") from exc

        if entry_count != metadata.entry_count:
            raise _InvalidZipDirectory(
                f"ZIP entry count mismatch ({metadata.entry_count} declared, {entry_count} observed)",
                routing_evidence=True,
            )
        cls._validate_declared_local_entry_layout(handle, metadata, entries)
        return entry_count, False

    @staticmethod
    def _zip64_extra_field(extra: bytes) -> bytes | None:
        field_offset = 0
        while field_offset + 4 <= len(extra):
            field_id = int.from_bytes(extra[field_offset : field_offset + 2], "little")
            field_size = int.from_bytes(extra[field_offset + 2 : field_offset + 4], "little")
            field_data = extra[field_offset + 4 : field_offset + 4 + field_size]
            if len(field_data) != field_size:
                return None
            field_offset += 4 + field_size
            if field_id == 0x0001:
                return field_data
        return None

    @classmethod
    def _central_directory_entry(
        cls,
        header: bytes,
        filename: bytes,
        extra: bytes,
    ) -> _ZipCentralDirectoryEntry:
        if not filename or b"\x00" in filename:
            raise _InvalidZipDirectory("ZIP central-directory filename is invalid", routing_evidence=True)

        raw_uncompressed_size = int.from_bytes(header[24:28], "little")
        raw_compressed_size = int.from_bytes(header[20:24], "little")
        raw_local_offset = int.from_bytes(header[42:46], "little")
        raw_disk_start = int.from_bytes(header[34:36], "little")
        requires_zip64 = (
            raw_uncompressed_size == _ZIP64_SENTINEL_OFFSET
            or raw_compressed_size == _ZIP64_SENTINEL_OFFSET
            or raw_local_offset == _ZIP64_SENTINEL_OFFSET
            or raw_disk_start == _ZIP64_SENTINEL_ENTRY_COUNT
        )
        zip64_data = cls._zip64_extra_field(extra) if requires_zip64 else b""
        if zip64_data is None:
            raise _InvalidZipDirectory("ZIP64 central-directory metadata is incomplete", routing_evidence=True)

        value_offset = 0

        def zip64_value(raw_value: int, sentinel: int, width: int) -> int:
            nonlocal value_offset
            if raw_value != sentinel:
                return raw_value
            if value_offset + width > len(zip64_data):
                raise _InvalidZipDirectory("ZIP64 central-directory metadata is incomplete", routing_evidence=True)
            value = int.from_bytes(zip64_data[value_offset : value_offset + width], "little")
            value_offset += width
            return value

        uncompressed_size = zip64_value(raw_uncompressed_size, _ZIP64_SENTINEL_OFFSET, 8)
        compressed_size = zip64_value(raw_compressed_size, _ZIP64_SENTINEL_OFFSET, 8)
        relative_local_offset = zip64_value(raw_local_offset, _ZIP64_SENTINEL_OFFSET, 8)
        disk_start = zip64_value(raw_disk_start, _ZIP64_SENTINEL_ENTRY_COUNT, 4)
        if disk_start != 0:
            raise _InvalidZipDirectory("multi-disk ZIP archives are unsupported", routing_evidence=True)

        return _ZipCentralDirectoryEntry(
            filename=filename,
            flags=int.from_bytes(header[8:10], "little"),
            creator_system=header[5],
            external_attr=int.from_bytes(header[38:42], "little"),
            compression_method=int.from_bytes(header[10:12], "little"),
            crc32=int.from_bytes(header[16:20], "little"),
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            relative_local_offset=relative_local_offset,
            uses_zip64_sizes=(
                raw_uncompressed_size == _ZIP64_SENTINEL_OFFSET or raw_compressed_size == _ZIP64_SENTINEL_OFFSET
            ),
        )

    @classmethod
    def _local_sizes(cls, header: bytes, extra: bytes) -> tuple[int, int] | None:
        raw_uncompressed_size = int.from_bytes(header[22:26], "little")
        raw_compressed_size = int.from_bytes(header[18:22], "little")
        if raw_uncompressed_size != _ZIP64_SENTINEL_OFFSET and raw_compressed_size != _ZIP64_SENTINEL_OFFSET:
            return raw_compressed_size, raw_uncompressed_size
        zip64_data = cls._zip64_extra_field(extra)
        if zip64_data is None:
            return None
        value_offset = 0

        def zip64_value(raw_value: int) -> int | None:
            nonlocal value_offset
            if raw_value != _ZIP64_SENTINEL_OFFSET:
                return raw_value
            if value_offset + 8 > len(zip64_data):
                return None
            value = int.from_bytes(zip64_data[value_offset : value_offset + 8], "little")
            value_offset += 8
            return value

        uncompressed_size = zip64_value(raw_uncompressed_size)
        compressed_size = zip64_value(raw_compressed_size)
        if uncompressed_size is None or compressed_size is None:
            return None
        return compressed_size, uncompressed_size

    @staticmethod
    def _data_descriptor_end_candidates(
        descriptor: bytes,
        descriptor_offset: int,
        entry: _ZipCentralDirectoryEntry,
        *,
        uses_zip64_sizes: bool,
    ) -> frozenset[int]:
        size_width = 8 if uses_zip64_sizes else 4
        payload_size = 4 + (2 * size_width)
        end_candidates: set[int] = set()
        for signature_size in (0, len(_ZIP_DATA_DESCRIPTOR_SIGNATURE)):
            if signature_size and not descriptor.startswith(_ZIP_DATA_DESCRIPTOR_SIGNATURE):
                continue
            end = signature_size + payload_size
            if len(descriptor) < end:
                continue
            payload = descriptor[signature_size:end]
            crc32 = int.from_bytes(payload[:4], "little")
            compressed_size = int.from_bytes(payload[4 : 4 + size_width], "little")
            uncompressed_size = int.from_bytes(payload[4 + size_width :], "little")
            if (
                crc32 == entry.crc32
                and compressed_size == entry.compressed_size
                and uncompressed_size == entry.uncompressed_size
            ):
                end_candidates.add(descriptor_offset + end)
        return frozenset(end_candidates)

    @classmethod
    def _local_entry_layout(
        cls,
        handle: BinaryIO,
        metadata: _ZipDirectoryMetadata,
        entry: _ZipCentralDirectoryEntry,
        local_header_offset: int,
    ) -> _ZipLocalEntryLayout | None:
        if local_header_offset < 0 or local_header_offset + _ZIP_LOCAL_FILE_HEADER_SIZE > metadata.directory_start:
            return None
        try:
            handle.seek(local_header_offset)
            header = handle.read(_ZIP_LOCAL_FILE_HEADER_SIZE)
            if len(header) != _ZIP_LOCAL_FILE_HEADER_SIZE or not header.startswith(_ZIP_LOCAL_FILE_HEADER_SIGNATURE):
                return None
            filename_size = int.from_bytes(header[26:28], "little")
            extra_size = int.from_bytes(header[28:30], "little")
            variable_data = handle.read(filename_size + extra_size)
            if len(variable_data) != filename_size + extra_size:
                return None
            filename = variable_data[:filename_size]
            extra = variable_data[filename_size:]
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP local header could not be read: {exc}") from exc

        local_flags = int.from_bytes(header[6:8], "little")
        if (
            filename != entry.filename
            or local_flags != entry.flags
            or int.from_bytes(header[8:10], "little") != entry.compression_method
        ):
            return None

        uses_data_descriptor = bool(local_flags & 0x0008)
        local_crc32 = int.from_bytes(header[14:18], "little")
        local_uses_zip64_sizes = (
            int.from_bytes(header[18:22], "little") == _ZIP64_SENTINEL_OFFSET
            or int.from_bytes(header[22:26], "little") == _ZIP64_SENTINEL_OFFSET
        )
        local_sizes = cls._local_sizes(header, extra)
        if local_sizes is None:
            return None
        local_compressed_size, local_uncompressed_size = local_sizes
        if uses_data_descriptor:
            if local_crc32 not in {0, entry.crc32}:
                return None
            if local_compressed_size not in {0, entry.compressed_size}:
                return None
            if local_uncompressed_size not in {0, entry.uncompressed_size}:
                return None
        elif (
            local_crc32 != entry.crc32
            or local_compressed_size != entry.compressed_size
            or local_uncompressed_size != entry.uncompressed_size
        ):
            return None

        data_offset = local_header_offset + _ZIP_LOCAL_FILE_HEADER_SIZE + filename_size + extra_size
        data_end = data_offset + entry.compressed_size
        if data_end > metadata.directory_start:
            return None
        if not uses_data_descriptor:
            return _ZipLocalEntryLayout(offset=local_header_offset, end_candidates=frozenset({data_end}))

        descriptor_widths = {entry.uses_zip64_sizes or local_uses_zip64_sizes}
        local_zip64_data = cls._zip64_extra_field(extra)
        if local_zip64_data is not None and len(local_zip64_data) >= 16:
            # Python 3.10 can write zero local sizes with a ZIP64 extra field and
            # still emit the 64-bit descriptor selected by force_zip64=True.
            descriptor_widths.add(True)
        descriptor_size = 24 if True in descriptor_widths else 16
        try:
            handle.seek(data_end)
            descriptor = handle.read(descriptor_size)
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP data descriptor could not be read: {exc}") from exc
        end_candidates: set[int] = set()
        for uses_zip64_sizes in descriptor_widths:
            end_candidates.update(
                cls._data_descriptor_end_candidates(
                    descriptor,
                    data_end,
                    entry,
                    uses_zip64_sizes=uses_zip64_sizes,
                )
            )
        if not end_candidates:
            return None
        return _ZipLocalEntryLayout(offset=local_header_offset, end_candidates=frozenset(end_candidates))

    @classmethod
    def _validate_declared_local_entry_layout(
        cls,
        handle: BinaryIO,
        metadata: _ZipDirectoryMetadata,
        entries: list[_ZipCentralDirectoryEntry],
    ) -> None:
        if not entries:
            if cls._has_preceding_central_directory_entry(
                handle, metadata
            ) or cls._has_unreferenced_local_entry_ending_at(handle, metadata.directory_start):
                raise _InvalidZipDirectory(
                    "ZIP central directory omits a preceding record",
                    routing_evidence=True,
                )
            return
        layouts: list[_ZipLocalEntryLayout] = []
        for entry in entries:
            candidates = {
                entry.relative_local_offset,
                metadata.archive_prefix_size + entry.relative_local_offset,
            }
            matching_layouts = [
                layout
                for candidate in candidates
                if (layout := cls._local_entry_layout(handle, metadata, entry, candidate)) is not None
            ]
            if not matching_layouts:
                raise _ZipLocalEntryMismatch(
                    "ZIP central directory does not uniquely identify its local entry",
                    entry,
                )
            if len(matching_layouts) != 1:
                raise _InvalidZipDirectory(
                    "ZIP central directory does not uniquely identify its local entry",
                    routing_evidence=True,
                )
            layouts.append(matching_layouts[0])

        layouts.sort(key=lambda layout: layout.offset)
        if cls._has_unreferenced_local_entry_ending_at(handle, layouts[0].offset):
            raise _InvalidZipDirectory(
                "ZIP central directory omits a preceding record",
                routing_evidence=True,
            )
        for layout, next_layout in pairwise(layouts):
            if next_layout.offset not in layout.end_candidates:
                raise _InvalidZipDirectory(
                    "ZIP central directory omits a preceding record",
                    routing_evidence=True,
                )
        if metadata.directory_start not in layouts[-1].end_candidates and not any(
            cls._archive_extra_data_records_cover(handle, end, metadata.directory_start)
            for end in layouts[-1].end_candidates
        ):
            raise _InvalidZipDirectory("ZIP central directory omits a preceding record", routing_evidence=True)

    @staticmethod
    def _archive_extra_data_records_cover(handle: BinaryIO, start: int, end: int) -> bool:
        if start >= end:
            return False
        offset = start
        record_count = 0
        try:
            while offset < end:
                record_count += 1
                if record_count > _ZIP_MAX_ARCHIVE_EXTRA_DATA_RECORDS:
                    raise _InvalidZipDirectory(
                        "too many ZIP archive extra data records",
                        routing_evidence=True,
                    )
                if end - offset < 8:
                    return False
                handle.seek(offset)
                header = handle.read(8)
                if len(header) != 8 or not header.startswith(_ZIP_ARCHIVE_EXTRA_DATA_SIGNATURE):
                    return False
                record_size = int.from_bytes(header[4:8], "little")
                offset += 8 + record_size
                if offset > end:
                    return False
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP archive extra data could not be read: {exc}") from exc
        return offset == end

    @classmethod
    def _has_preceding_central_directory_entry(
        cls,
        handle: BinaryIO,
        metadata: _ZipDirectoryMetadata,
    ) -> bool:
        window_size = min(metadata.directory_start, _ZIP_MAX_CENTRAL_DIRECTORY_RECORD_SIZE)
        if window_size < _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
            return False
        window_start = metadata.directory_start - window_size
        try:
            handle.seek(window_start)
            prefix = handle.read(window_size)
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP central-directory prefix could not be read: {exc}") from exc

        candidate_index = prefix.find(_ZIP_CENTRAL_DIRECTORY_SIGNATURE)
        while candidate_index >= 0:
            header_end = candidate_index + _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE
            if header_end <= len(prefix):
                header = prefix[candidate_index:header_end]
                filename_size = int.from_bytes(header[28:30], "little")
                extra_size = int.from_bytes(header[30:32], "little")
                comment_size = int.from_bytes(header[32:34], "little")
                record_end = header_end + filename_size + extra_size + comment_size
                if record_end <= len(prefix):
                    filename = prefix[header_end : header_end + filename_size]
                    extra = prefix[header_end + filename_size : header_end + filename_size + extra_size]
                    try:
                        entry = cls._central_directory_entry(header, filename, extra)
                    except _InvalidZipDirectory:
                        pass
                    else:
                        for local_offset in {
                            entry.relative_local_offset,
                            metadata.archive_prefix_size + entry.relative_local_offset,
                        }:
                            if cls._local_entry_layout(handle, metadata, entry, local_offset) is not None:
                                return True
            candidate_index = prefix.find(_ZIP_CENTRAL_DIRECTORY_SIGNATURE, candidate_index + 1)
        return False

    @classmethod
    def _has_unreferenced_local_entry_ending_at(
        cls,
        handle: BinaryIO,
        boundary: int,
        *,
        start: int = 0,
    ) -> bool:
        if start < 0 or start > boundary or boundary - start < _ZIP_LOCAL_FILE_HEADER_SIZE:
            return False
        if boundary - start > _ZIP_MAX_LOCAL_PREFIX_SCAN_SIZE:
            raise _InvalidZipDirectory(
                "ZIP local-entry search region is too large to validate safely",
                routing_evidence=True,
            )

        overlap = len(_ZIP_LOCAL_FILE_HEADER_SIGNATURE) - 1
        search_offset = start
        trailing = b""
        candidate_count = 0
        payload_validation_budget = [_ZIP_MAX_LOCAL_PAYLOAD_VALIDATION_TOTAL]
        descriptor_search_budget = [_ZIP_MAX_LOCAL_DESCRIPTOR_SEARCH_WORK]
        while search_offset < boundary:
            read_size = min(64 * 1024, boundary - search_offset)
            try:
                handle.seek(search_offset)
                chunk = handle.read(read_size)
            except OSError as exc:
                raise _InvalidZipDirectory(f"ZIP local-entry prefix could not be read: {exc}") from exc
            if not chunk:
                break
            search_data = trailing + chunk
            data_offset = search_offset - len(trailing)
            candidate_index = search_data.find(_ZIP_LOCAL_FILE_HEADER_SIGNATURE)
            while candidate_index >= 0:
                candidate_count += 1
                if candidate_count > _ZIP_MAX_LOCAL_HEADER_CANDIDATES:
                    raise _InvalidZipDirectory(
                        "too many plausible ZIP local headers before the declared entries",
                        routing_evidence=True,
                    )
                candidate_offset = data_offset + candidate_index
                if cls._unreferenced_local_entry_ends_at(
                    handle,
                    candidate_offset,
                    boundary,
                    payload_validation_budget,
                    descriptor_search_budget,
                ):
                    return True
                candidate_index = search_data.find(_ZIP_LOCAL_FILE_HEADER_SIGNATURE, candidate_index + 1)
            trailing = search_data[-overlap:]
            search_offset += len(chunk)
        return False

    @staticmethod
    def _local_entry_payload_matches_header(
        handle: BinaryIO,
        *,
        data_offset: int,
        compressed_size: int,
        uncompressed_size: int,
        compression_method: int,
        expected_crc32: int,
        flags: int,
        payload_validation_budget: list[int],
    ) -> bool:
        """Validate a bounded local-entry payload when its central record is absent."""
        if flags & 0x0001:
            return True
        if (
            compressed_size > _ZIP_MAX_LOCAL_PAYLOAD_VALIDATION_SIZE
            or uncompressed_size > _ZIP_MAX_LOCAL_PAYLOAD_VALIDATION_SIZE
        ):
            return True
        if compression_method == zipfile.ZIP_LZMA:
            # ZIP's LZMA wrapper cannot bound output per call. A structurally
            # valid hidden entry must fail closed rather than risk decompression.
            return True
        if compression_method not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2}:
            return True

        validation_cost = compressed_size + uncompressed_size
        if validation_cost > payload_validation_budget[0]:
            raise _InvalidZipDirectory(
                "ZIP local-entry payload validation exceeded its bounded work budget",
                routing_evidence=True,
            )
        payload_validation_budget[0] -= validation_cost

        try:
            handle.seek(data_offset)
            compressed_data = handle.read(compressed_size)
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP local-entry data could not be read: {exc}") from exc
        if len(compressed_data) != compressed_size:
            return False

        crc32 = 0
        output_size = 0

        def consume_output(output: bytes) -> bool:
            nonlocal crc32, output_size
            output_size += len(output)
            if output_size > uncompressed_size:
                return False
            crc32 = zlib.crc32(output, crc32)
            return True

        if compression_method == zipfile.ZIP_STORED:
            return compressed_size == uncompressed_size and consume_output(compressed_data) and crc32 == expected_crc32

        if compression_method == zipfile.ZIP_DEFLATED:
            decompressor: Any = zlib.decompressobj(-15)
            pending = compressed_data
            try:
                while pending:
                    output = decompressor.decompress(
                        pending,
                        min(64 * 1024, uncompressed_size - output_size + 1),
                    )
                    pending = decompressor.unconsumed_tail
                    if not consume_output(output):
                        return False
                    if pending and not output:
                        return False
            except zlib.error:
                return False
            if not decompressor.eof or decompressor.unused_data:
                return False
        else:
            decompressor = bz2.BZ2Decompressor()
            pending = compressed_data
            try:
                while pending or not decompressor.needs_input:
                    output = decompressor.decompress(
                        pending,
                        max_length=min(64 * 1024, uncompressed_size - output_size + 1),
                    )
                    pending = b""
                    if not consume_output(output):
                        return False
                    if decompressor.eof:
                        break
                    if decompressor.needs_input and not pending:
                        break
            except (OSError, EOFError):
                return False
            if not decompressor.eof or decompressor.unused_data:
                return False

        return output_size == uncompressed_size and crc32 == expected_crc32

    @classmethod
    def _unreferenced_local_entry_ends_at(
        cls,
        handle: BinaryIO,
        offset: int,
        boundary: int,
        payload_validation_budget: list[int],
        descriptor_search_budget: list[int],
    ) -> bool:
        try:
            handle.seek(offset)
            header = handle.read(_ZIP_LOCAL_FILE_HEADER_SIZE)
            if len(header) != _ZIP_LOCAL_FILE_HEADER_SIZE or not header.startswith(_ZIP_LOCAL_FILE_HEADER_SIGNATURE):
                return False
            version_needed = int.from_bytes(header[4:6], "little")
            flags = int.from_bytes(header[6:8], "little")
            filename_size = int.from_bytes(header[26:28], "little")
            extra_size = int.from_bytes(header[28:30], "little")
            if not (10 <= version_needed <= 100) or filename_size == 0:
                return False
            variable_data = handle.read(filename_size + extra_size)
            if len(variable_data) != filename_size + extra_size:
                return False
            filename = variable_data[:filename_size]
            if b"\x00" in filename:
                return False
            extra = variable_data[filename_size:]
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP local-entry prefix could not be read: {exc}") from exc

        data_offset = offset + _ZIP_LOCAL_FILE_HEADER_SIZE + filename_size + extra_size
        local_sizes = cls._local_sizes(header, extra)
        if local_sizes is None:
            return False
        compressed_size, uncompressed_size = local_sizes
        if not flags & 0x0008:
            entry_end = data_offset + compressed_size
            if entry_end <= boundary:
                return cls._local_entry_payload_matches_header(
                    handle,
                    data_offset=data_offset,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    compression_method=int.from_bytes(header[8:10], "little"),
                    expected_crc32=int.from_bytes(header[14:18], "little"),
                    flags=flags,
                    payload_validation_budget=payload_validation_budget,
                )
            return False

        raw_compressed_size = int.from_bytes(header[18:22], "little")
        raw_uncompressed_size = int.from_bytes(header[22:26], "little")
        if data_offset >= boundary:
            return False
        descriptor_window_start = max(
            data_offset,
            boundary - (_ZIP_MAX_LOCAL_ENTRY_PADDING + 24),
        )
        try:
            handle.seek(descriptor_window_start)
            descriptor_window = handle.read(boundary - descriptor_window_start)
        except OSError as exc:
            raise _InvalidZipDirectory(f"ZIP data descriptor could not be read: {exc}") from exc
        descriptor_search_work = sum(
            max(0, len(descriptor_window) - descriptor_size + 1) for descriptor_size in (12, 16, 20, 24)
        )
        if descriptor_search_work > descriptor_search_budget[0]:
            raise _InvalidZipDirectory(
                "ZIP local-entry data descriptor search exceeded its bounded work budget",
                routing_evidence=True,
            )
        descriptor_search_budget[0] -= descriptor_search_work
        for size_width in (4, 8):
            for signature_size in (0, len(_ZIP_DATA_DESCRIPTOR_SIGNATURE)):
                descriptor_size = signature_size + 4 + (2 * size_width)
                for descriptor_end in range(boundary, descriptor_window_start + descriptor_size - 1, -1):
                    descriptor_offset = descriptor_end - descriptor_size
                    relative_offset = descriptor_offset - descriptor_window_start
                    descriptor = descriptor_window[relative_offset : relative_offset + descriptor_size]
                    if len(descriptor) != descriptor_size:
                        continue
                    if signature_size and not descriptor.startswith(_ZIP_DATA_DESCRIPTOR_SIGNATURE):
                        continue
                    payload = descriptor[signature_size:]
                    descriptor_crc32 = int.from_bytes(payload[:4], "little")
                    descriptor_compressed_size = int.from_bytes(payload[4 : 4 + size_width], "little")
                    descriptor_uncompressed_size = int.from_bytes(payload[4 + size_width :], "little")
                    if data_offset + descriptor_compressed_size != descriptor_offset:
                        continue
                    if raw_compressed_size not in {0, _ZIP64_SENTINEL_OFFSET, descriptor_compressed_size}:
                        continue
                    if raw_uncompressed_size not in {0, _ZIP64_SENTINEL_OFFSET, descriptor_uncompressed_size}:
                        continue
                    if compressed_size not in {0, descriptor_compressed_size}:
                        continue
                    if uncompressed_size not in {0, descriptor_uncompressed_size}:
                        continue
                    if cls._local_entry_payload_matches_header(
                        handle,
                        data_offset=data_offset,
                        compressed_size=descriptor_compressed_size,
                        uncompressed_size=descriptor_uncompressed_size,
                        compression_method=int.from_bytes(header[8:10], "little"),
                        expected_crc32=descriptor_crc32,
                        flags=flags,
                        payload_validation_budget=payload_validation_budget,
                    ):
                        return True
        if boundary - data_offset > _ZIP_MAX_LOCAL_ENTRY_PADDING + 24:
            raise _InvalidZipDirectory(
                "ZIP streamed local entry cannot be bounded within the preflight window",
                routing_evidence=True,
            )
        return False

    @classmethod
    def _trailing_data_contains_local_entry_marker(cls, handle: BinaryIO, start: int, end: int) -> bool:
        return cls._has_unreferenced_local_entry_ending_at(handle, end, start=start)

    @staticmethod
    def _candidate_has_directory_signature(
        handle: BinaryIO,
        *,
        file_size: int,
        tail_size: int,
        tail: bytes,
        eocd_index: int,
    ) -> bool:
        directory_size = int.from_bytes(tail[eocd_index + 12 : eocd_index + 16], "little")
        if directory_size in {0, _ZIP64_SENTINEL_OFFSET}:
            return False
        eocd_offset = file_size - tail_size + eocd_index
        directory_start = eocd_offset - directory_size
        if directory_start < 0:
            return False
        try:
            handle.seek(directory_start)
            return handle.read(len(_ZIP_CENTRAL_DIRECTORY_SIGNATURE)) == _ZIP_CENTRAL_DIRECTORY_SIGNATURE
        except OSError:
            return False

    @classmethod
    def _preflight_zip_directory(
        cls,
        handle: BinaryIO,
        max_entries: int,
        max_directory_size: int,
    ) -> tuple[int, bool] | None:
        tail_data = cls._read_zip_tail(handle)
        if tail_data is None:
            return None
        file_size, tail_size, tail, eocd_indices = tail_data
        if not eocd_indices:
            return None
        if len(eocd_indices) >= _ZIP_MAX_EOCD_CANDIDATES:
            raise _InvalidZipDirectory(
                "too many plausible ZIP end-of-directory records",
                routing_evidence=True,
            )

        last_error: _InvalidZipDirectory | None = None
        size_limit_error: _ZipCentralDirectorySizeExceeded | None = None
        candidate_errors: list[tuple[int, bool]] = []
        valid_preflight: tuple[int, bool] | None = None
        valid_eocd_index: int | None = None
        for eocd_index in eocd_indices:
            try:
                metadata = cls._read_zip_directory_metadata_at(
                    handle,
                    file_size=file_size,
                    tail_size=tail_size,
                    tail=tail,
                    eocd_index=eocd_index,
                )
                if metadata.directory_size > max_directory_size:
                    raise _ZipCentralDirectorySizeExceeded(metadata.directory_size, max_directory_size)
                candidate_preflight = cls._count_bounded_central_directory_entries(handle, metadata, max_entries)
            except _ZipCentralDirectorySizeExceeded as exc:
                size_limit_error = exc
                candidate_errors.append((eocd_index, True))
                continue
            except _InvalidZipDirectory as exc:
                candidate_errors.append(
                    (
                        eocd_index,
                        exc.routing_evidence
                        or cls._candidate_has_directory_signature(
                            handle,
                            file_size=file_size,
                            tail_size=tail_size,
                            tail=tail,
                            eocd_index=eocd_index,
                        ),
                    )
                )
                if last_error is None or (exc.routing_evidence and not last_error.routing_evidence):
                    last_error = exc
                continue
            if valid_preflight is not None:
                raise _InvalidZipDirectory(
                    "multiple valid ZIP end-of-directory records are ambiguous",
                    routing_evidence=True,
                )
            valid_preflight = candidate_preflight
            valid_eocd_index = eocd_index
        if valid_preflight is not None:
            assert valid_eocd_index is not None
            valid_comment_length = int.from_bytes(tail[valid_eocd_index + 20 : valid_eocd_index + 22], "little")
            valid_comment_start = valid_eocd_index + _ZIP_EOCD_MIN_SIZE
            valid_record_end = valid_eocd_index + _ZIP_EOCD_MIN_SIZE + valid_comment_length
            valid_comment_start_offset = file_size - tail_size + valid_comment_start
            if cls._trailing_data_contains_local_entry_marker(handle, valid_comment_start_offset, file_size):
                raise _InvalidZipDirectory(
                    "ZIP trailing data contains an unreferenced local entry",
                    routing_evidence=True,
                )
            if any(
                strong_evidence
                and not (
                    valid_eocd_index < error_index
                    and error_index
                    + _ZIP_EOCD_MIN_SIZE
                    + int.from_bytes(tail[error_index + 20 : error_index + 22], "little")
                    <= valid_record_end
                )
                for error_index, strong_evidence in candidate_errors
            ):
                raise _InvalidZipDirectory(
                    "multiple plausible ZIP end-of-directory records are ambiguous",
                    routing_evidence=True,
                )
            return valid_preflight
        if size_limit_error is not None:
            raise size_limit_error
        if last_error is not None:
            raise last_error
        return None

    @classmethod
    def requires_preflight_result(cls, path: str, max_entries: int, max_directory_size: int | None = None) -> bool:
        """Return whether ZIP routing must defer to this scanner before materializing entries."""
        directory_size_limit = max_directory_size or cls.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE
        try:
            with open(path, "rb") as handle:
                preflight = cls._preflight_zip_directory(handle, max_entries, directory_size_limit)
        except _InvalidZipDirectory as exc:
            if exc.routing_evidence:
                return True
            try:
                return cls._has_zip_routing_evidence(path)
            except OSError:
                return False
        except OSError:
            return False
        return preflight is not None and preflight[1]

    def _add_entry_count_limit_check(
        self,
        result: ScanResult,
        path: str,
        entry_count: int,
        *,
        passed: bool,
        source: str,
    ) -> None:
        details: dict[str, Any] = {
            "entries": entry_count,
            "max_entries": self.max_entries,
            "entry_count_source": source,
        }
        if not passed:
            details["analysis_incomplete"] = True
            details["scan_outcome_reason"] = "zip_analysis_incomplete"

        result.add_check(
            name="Entry Count Limit Check",
            passed=passed,
            message=(
                f"Entry count ({entry_count}) is within limits"
                if passed
                else f"ZIP file contains too many entries ({entry_count} > {self.max_entries})"
            ),
            severity=None if passed else IssueSeverity.WARNING,
            rule_code=None if passed else "S410",
            location=path,
            details=details,
        )

    def _preflight_rejection_result(
        self,
        path: str,
        *,
        entry_count: int | None = None,
        error: _InvalidZipDirectory | None = None,
    ) -> ScanResult:
        result = self._create_result()
        with contextlib.suppress(OSError):
            result.metadata["file_size"] = os.path.getsize(path)
        if entry_count is not None:
            result.metadata["zip_entry_count_preflight"] = entry_count
            self._add_entry_count_limit_check(
                result,
                path,
                entry_count,
                passed=False,
                source="central_directory_preflight",
            )
        elif isinstance(error, _ZipCentralDirectorySizeExceeded):
            self._add_central_directory_size_limit_check(result, path, error)
        else:
            assert error is not None
            self._add_invalid_directory_checks(result, path, error)
        mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
        result.finish(success=False)
        return result

    @staticmethod
    def _add_invalid_directory_checks(
        result: ScanResult,
        path: str,
        error: _InvalidZipDirectory,
    ) -> None:
        result.add_check(
            name="ZIP Central Directory Preflight",
            passed=False,
            message=f"ZIP central-directory validation failed: {error}",
            severity=IssueSeverity.INFO,
            rule_code="S902",
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "zip_analysis_incomplete",
            },
        )
        if not isinstance(error, _ZipLocalEntryMismatch) or not error.entry.is_symlink:
            return

        encoding = "utf-8" if error.entry.flags & 0x0800 else "cp437"
        entry_name = error.entry.filename.decode(encoding, errors="replace")
        if len(entry_name) > 1024:
            entry_name = f"{entry_name[:1021]}..."
        result.add_check(
            name="Symlink Safety Validation",
            passed=False,
            message=f"Symlink {entry_name} has inconsistent ZIP local metadata",
            severity=IssueSeverity.CRITICAL,
            rule_code="S406",
            location=f"{path}:{entry_name}",
            details={
                "entry": entry_name,
                "target": "<inconsistent-zip-metadata>",
                "target_class": "invalid",
                "compressed_size": error.entry.compressed_size,
                "uncompressed_size": error.entry.uncompressed_size,
                "analysis_incomplete": True,
            },
        )

    @staticmethod
    def _add_central_directory_size_limit_check(
        result: ScanResult,
        path: str,
        exc: _ZipCentralDirectorySizeExceeded,
    ) -> None:
        result.add_check(
            name="Central Directory Size Limit Check",
            passed=False,
            message=str(exc),
            severity=IssueSeverity.WARNING,
            rule_code="S410",
            location=path,
            details={
                "central_directory_size": exc.directory_size,
                "max_central_directory_size": exc.max_directory_size,
                "analysis_incomplete": True,
                "scan_outcome_reason": "zip_analysis_incomplete",
            },
        )

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

    @staticmethod
    def _resolve_symlink_target(
        target: str,
        *,
        resolved_name: str,
        extraction_root: str,
    ) -> tuple[str, bool]:
        """Resolve a relative symlink target while enforcing the archive extraction root."""
        if is_absolute_archive_path(target):
            return target, False

        normalized_target = target.replace("\\", os.sep).replace("/", os.sep)
        target_base = os.path.dirname(resolved_name)
        target_resolved = os.path.normpath(os.path.join(target_base, normalized_target))
        try:
            target_from_root = os.path.relpath(target_resolved, extraction_root)
        except ValueError:
            return target_resolved, False
        return sanitize_archive_path(target_from_root, extraction_root)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        try:
            with open(path, "rb") as handle:
                preflight = cls._preflight_zip_directory(
                    handle,
                    cls.DEFAULT_MAX_ENTRIES,
                    cls.DEFAULT_MAX_CENTRAL_DIRECTORY_SIZE,
                )
            return preflight is not None or cls._has_zip_routing_evidence(path)
        except _InvalidZipDirectory as exc:
            if exc.routing_evidence:
                return True
            return cls._has_zip_routing_evidence(path)
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

    def scan_archive_members(self, path: str, archive: zipfile.ZipFile | None = None) -> ScanResult:
        """Recursively scan entries of an already validated ZIP container."""
        # Shared archive depth must survive scanner handoffs, while nested ZIP
        # recursion still needs its own counter for extensionless ZIP members
        # routed through core dispatch.
        return self._scan_zip_file(
            path,
            depth=max(self._get_archive_depth(), self._get_zip_depth()),
            archive=archive,
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

    @staticmethod
    @contextlib.contextmanager
    def _open_archive_handle(path: str, archive: zipfile.ZipFile | None) -> Iterator[BinaryIO]:
        """Yield an owned path handle or borrow the handle from an existing archive."""
        if archive is None:
            with open(path, "rb") as handle:
                yield handle
            return

        archive_fp = archive.fp
        if archive_fp is None:
            raise zipfile.BadZipFile("ZIP archive is already closed")
        yield cast(BinaryIO, archive_fp)

    @staticmethod
    @contextlib.contextmanager
    def _open_member_temp_file(
        suffix: str,
        safe_name: str | None,
        preserve_nested_routing_basename: bool,
    ) -> Iterator[tuple[str, BinaryIO, str | None]]:
        """Yield a writable temporary member path plus its optional parent directory."""
        if preserve_nested_routing_basename:
            tmp_dir = tempfile.mkdtemp()
            tmp_path = os.path.join(tmp_dir, safe_name or "archive-member")
            with open(tmp_path, "wb") as tmp:
                yield tmp_path, tmp, tmp_dir
            return

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as named_tmp:
            yield named_tmp.name, cast(BinaryIO, named_tmp), None

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

        is_symlink = info.create_system in _UNIX_MODE_ZIP_CREATOR_SYSTEMS and stat.S_ISLNK(info.external_attr >> 16)
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

            _target_resolved, target_safe = self._resolve_symlink_target(
                target,
                resolved_name=resolved_name,
                extraction_root=temp_base,
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

    def _scan_zip_file(
        self,
        path: str,
        depth: int = 0,
        archive: zipfile.ZipFile | None = None,
    ) -> ScanResult:
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

        with self._open_archive_handle(path, archive) as opened_archive_handle, contextlib.ExitStack() as archive_stack:
            try:
                archive_file_size = os.fstat(opened_archive_handle.fileno()).st_size
            except (AttributeError, OSError):
                archive_file_size = os.path.getsize(path)
            try:
                preflight = self._preflight_zip_directory(
                    opened_archive_handle,
                    self.max_entries,
                    self.max_central_directory_size,
                )
                if preflight is not None:
                    preflight_entry_count, exceeds_limit = preflight
                    result.metadata["zip_entry_count_preflight"] = preflight_entry_count
                else:
                    preflight_entry_count = None
            except _ZipCentralDirectorySizeExceeded as exc:
                self._add_central_directory_size_limit_check(result, path, exc)
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
                return result
            except _InvalidZipDirectory as exc:
                self._add_invalid_directory_checks(result, path, exc)
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
                return result

            if preflight_entry_count is not None and exceeds_limit:
                self._add_entry_count_limit_check(
                    result,
                    path,
                    preflight_entry_count,
                    passed=False,
                    source="central_directory_preflight",
                )
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
                return result

            opened_archive_handle.seek(0)
            z = (
                archive
                if archive is not None
                else archive_stack.enter_context(zipfile.ZipFile(opened_archive_handle, "r"))
            )
            max_total_uncompressed_size = self._get_max_total_uncompressed_size()
            entries = z.infolist()

            # Check number of entries
            entry_count = len(entries)
            if preflight_entry_count is not None and entry_count != preflight_entry_count:
                result.add_check(
                    name="ZIP Central Directory Preflight",
                    passed=False,
                    message=(
                        "ZIP central directory changed between preflight and parsing "
                        f"({preflight_entry_count} != {entry_count})"
                    ),
                    severity=IssueSeverity.INFO,
                    rule_code="S902",
                    location=path,
                    details={
                        "preflight_entries": preflight_entry_count,
                        "parsed_entries": entry_count,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "zip_analysis_incomplete",
                    },
                )
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
                return result
            if entry_count > self.max_entries:
                self._add_entry_count_limit_check(
                    result,
                    path,
                    entry_count,
                    passed=False,
                    source="post_open_fallback",
                )
                mark_archive_scan_incomplete(result, "zip_analysis_incomplete")
                result.finish(success=False)
                return result
            else:
                self._add_entry_count_limit_check(
                    result,
                    path,
                    entry_count,
                    passed=True,
                    source=("post_open_fallback" if preflight_entry_count is None else "central_directory_preflight"),
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

                # Extract and scan the file
                tmp_dir: str | None = None
                tmp_path: str | None = None
                try:
                    max_entry_size = self._get_max_entry_size()
                    is_security_only_member = self._is_security_only_member_entry(name)
                    is_content_only_member = self._is_content_only_member_entry(name)
                    preserve_nested_routing_basename = self._preserve_nested_routing_basename(name)
                    safe_name: str | None = None

                    if is_content_only_member:
                        suffix = ""
                    else:
                        raw_safe_name = re.sub(
                            r"[^a-zA-Z0-9_.-]",
                            "_",
                            os.path.basename(name),
                        )
                        safe_name = raw_safe_name if preserve_nested_routing_basename else raw_safe_name.strip("._")
                        if not safe_name:
                            safe_name = "archive-member"
                        suffix = f"_{safe_name}"

                    try:
                        with self._open_member_temp_file(
                            suffix,
                            safe_name,
                            preserve_nested_routing_basename and not is_content_only_member,
                        ) as (tmp_path, tmp, tmp_dir):
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

                        if archive_ext == ".mar" and name.lower().endswith(".py") and not is_security_only_member:
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

                        if is_security_only_member:
                            contents.append(
                                {
                                    "path": f"{path}:{name}",
                                    "type": "security_only",
                                    "size": info.file_size,
                                }
                            )
                            result.bytes_scanned += total_size
                            continue

                        nested_config = dict(self.config)
                        nested_config.pop("skip_archive_entries", None)
                        nested_config.pop(ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY, None)
                        nested_config.pop(ZIP_CONTENT_ONLY_MEMBER_ENTRIES_CONFIG_KEY, None)
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
                        if tmp_dir is not None:
                            with contextlib.suppress(OSError):
                                os.rmdir(tmp_dir)

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
        result.metadata["file_size"] = archive_file_size
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
            with open_preflighted_zip(file_path, self.config) as zip_file:
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


@contextlib.contextmanager
def _open_preflighted_zip_handle(
    path: str | os.PathLike[str],
    config: dict[str, Any] | None = None,
    *,
    require_zip: bool = True,
) -> Iterator[tuple[BinaryIO, bool]]:
    """Open once, preflight that descriptor, and yield it with its ZIP routing state."""
    scanner = ZipScanner(config=config)
    path_text = os.fspath(path)
    with open(path, "rb") as handle:
        try:
            preflight = scanner._preflight_zip_directory(
                handle,
                scanner.max_entries,
                scanner.max_central_directory_size,
            )
        except _InvalidZipDirectory as exc:
            if not require_zip:
                handle.seek(0)
                try:
                    leading_signature = handle.read(4)
                except OSError:
                    leading_signature = b""
                if not exc.routing_evidence and leading_signature not in {
                    _ZIP_LOCAL_FILE_HEADER_SIGNATURE,
                    _ZIP_EOCD_SIGNATURE,
                    _ZIP64_EOCD_SIGNATURE,
                }:
                    handle.seek(0)
                    yield handle, False
                    return
            raise ZipPreflightRejected(scanner._preflight_rejection_result(path_text, error=exc)) from exc
        if preflight is None:
            if require_zip:
                raise zipfile.BadZipFile("File is not a valid ZIP archive")
        else:
            entry_count, exceeds_limit = preflight
            if exceeds_limit:
                raise ZipPreflightRejected(scanner._preflight_rejection_result(path_text, entry_count=entry_count))
        preflight_is_zip = preflight is not None
        if not require_zip and preflight is not None and preflight[0] == 0:
            handle.seek(0)
            leading_signature = handle.read(4)
            preflight_is_zip = leading_signature in {
                _ZIP_LOCAL_FILE_HEADER_SIGNATURE,
                _ZIP_EOCD_SIGNATURE,
                _ZIP64_EOCD_SIGNATURE,
            }
        handle.seek(0)
        yield handle, preflight_is_zip


@contextlib.contextmanager
def open_preflighted_zip_handle(
    path: str | os.PathLike[str],
    config: dict[str, Any] | None = None,
    *,
    require_zip: bool = True,
) -> Iterator[BinaryIO]:
    """Open once, preflight that descriptor, and yield it without a pathname race."""
    with _open_preflighted_zip_handle(path, config, require_zip=require_zip) as (handle, _is_zip):
        yield handle


@contextlib.contextmanager
def open_preflighted_zip(
    path: str | os.PathLike[str],
    config: dict[str, Any] | None = None,
) -> Iterator[zipfile.ZipFile]:
    """Construct ``ZipFile`` only after preflighting the same open descriptor."""
    with open_preflighted_zip_handle(path, config) as handle, zipfile.ZipFile(handle, "r") as archive:
        yield archive
