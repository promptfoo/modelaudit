"""Scanner for tar-archived model files (.tar, .tar.gz, .tgz)."""

from __future__ import annotations

import bz2
import contextlib
import errno
import gzip
import lzma
import math
import os
import re
import tarfile
import tempfile
import zlib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any, BinaryIO, ClassVar, Literal, cast

from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.file.detection import (
    _NEMO_ROUTE_MAX_LINK_RESOLUTION_VISITS,
    _looks_like_uncompressed_tar_header,
    _NemoRouteResolutionLimitExceeded,
    _resolve_safe_tar_link_target_name,
    _resolve_safe_tar_path_through_symlinks,
    _resolve_safe_tar_symlink_target_at_destination,
    bounded_tar_info_class,
    is_declared_text_content_filename,
)
from ..utils.helpers.assets import asset_from_scan_result
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import mark_archive_scan_incomplete, member_scan_incomplete
from .archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY, scan_nested_file
from .archive_member_security import scan_archive_member_for_known_risks
from .base import DEFAULT_MAX_FILE_READ_SIZE, BaseScanner, Check, CheckStatus, IssueSeverity, ScanResult

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

DEFAULT_MAX_TAR_ENTRY_SIZE = 1024 * 1024 * 1024
DEFAULT_MAX_TAR_TOTAL_UNCOMPRESSED_SIZE = 10 * 1024 * 1024 * 1024
DEFAULT_MAX_TAR_METADATA_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSION_RATIO = 250.0
DEFAULT_MAX_XZ_STREAM_PADDING_BYTES = 10 * 1024 * 1024
ARCHIVE_MEMBER_COPY_CHUNK_BYTES = 64 * 1024
MAX_TAR_PYTHON_ANALYSIS_BYTES = 10 * 1024 * 1024
TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY = "_tar_security_only_nested_member_entries"
TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY = "_tar_skip_reachable_nemo_config_scan"
TAR_SHARED_SCAN_BUDGET_CONFIG_KEY = "_tar_shared_scan_budget"
TAR_SOURCE_SIZE_LIMIT_CONFIG_KEY = "_tar_source_size_limit"
TAR_ENTRY_EXTRACTION_INCOMPLETE_REASON = "tar_entry_extraction_incomplete"
TAR_TOTAL_SIZE_INCOMPLETE_REASON = "tar_total_size_limit_exceeded"
TAR_ENTRY_COUNT_INCOMPLETE_REASON = "tar_entry_count_limit_exceeded"
TAR_SPECIAL_MEMBER_INCOMPLETE_REASON = "tar_special_member_unsupported"
TAR_SPARSE_MEMBER_INCOMPLETE_REASON = "tar_sparse_member_unsupported"
TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON = "tar_compressed_trailing_data"
TAR_COMPRESSED_PADDING_LIMIT_INCOMPLETE_REASON = "tar_compressed_padding_limit_exceeded"
TAR_DECOMPRESSED_SIZE_LIMIT_INCOMPLETE_REASON = "tar_decompressed_size_limit_exceeded"
TAR_DECOMPRESSION_RATIO_LIMIT_INCOMPLETE_REASON = "tar_decompression_ratio_limit_exceeded"
TarPrefixOwnership = Literal["complete", "embedded_member", "scan_limit", "incomplete", "inconclusive"]
_TAR_OWNERSHIP_SCAN_LIMIT_REASONS = frozenset(
    {
        TAR_TOTAL_SIZE_INCOMPLETE_REASON,
        TAR_ENTRY_COUNT_INCOMPLETE_REASON,
        TAR_DECOMPRESSED_SIZE_LIMIT_INCOMPLETE_REASON,
        TAR_DECOMPRESSION_RATIO_LIMIT_INCOMPLETE_REASON,
        "tar_metadata_read_limit_exceeded",
    }
)
TAR_SPARSE_PAX_SIZE_FIELDS = frozenset({"GNU.sparse.size", "GNU.sparse.realsize"})
_POST_TAR_EOF_CONTINUABLE_INCOMPLETE_REASONS = frozenset(
    {
        TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON,
        TAR_COMPRESSED_PADDING_LIMIT_INCOMPLETE_REASON,
    }
)

_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_TAR_HEADER_PROBE_BYTES = 2 * tarfile.BLOCKSIZE


class _TarEntryExtractionIncomplete(ValueError):
    """Raised when a TAR member cannot be inspected within extraction policy."""


class _TarStreamBudgetExceeded(ValueError):
    """Raised when TAR stream traversal exceeds bounded work limits."""

    def __init__(
        self,
        message: str,
        *,
        bytes_read: int,
        max_bytes: int,
        reason: str,
    ) -> None:
        super().__init__(message)
        self.bytes_read = bytes_read
        self.max_bytes = max_bytes
        self.reason = reason


class _TarCompressedPhysicalTrailingData(ValueError):
    """Raised when bytes after a complete compressed stream are not a valid stream."""


@dataclass
class _TarSharedScanBudget:
    max_total_uncompressed_size: int
    member_bytes_consumed: int = 0
    exhausted: bool = False


def _tar_shared_scan_budget_exhausted(config: dict[str, Any]) -> bool:
    budget = config.get(TAR_SHARED_SCAN_BUDGET_CONFIG_KEY)
    return isinstance(budget, _TarSharedScanBudget) and budget.exhausted


@contextmanager
def _tar_shared_scan_budget_scope(
    config: dict[str, Any],
    *,
    max_total_uncompressed_size: int,
) -> Iterator[_TarSharedScanBudget]:
    """Reuse one aggregate TAR budget across every scanner in an archive tree."""
    existing_budget = config.get(TAR_SHARED_SCAN_BUDGET_CONFIG_KEY)
    if isinstance(existing_budget, _TarSharedScanBudget):
        yield existing_budget
        return

    budget = _TarSharedScanBudget(max_total_uncompressed_size=max_total_uncompressed_size)
    config[TAR_SHARED_SCAN_BUDGET_CONFIG_KEY] = budget
    try:
        yield budget
    finally:
        if config.get(TAR_SHARED_SCAN_BUDGET_CONFIG_KEY) is budget:
            config.pop(TAR_SHARED_SCAN_BUDGET_CONFIG_KEY, None)


class _TarBoundedStream:
    """Read wrapper that bounds TAR stream work before tarfile materializes metadata."""

    def __init__(self, fileobj: Any, *, max_bytes: int, max_read_size: int) -> None:
        self._fileobj = fileobj
        self.max_bytes = max_bytes
        self.max_read_size = max_read_size
        self.bytes_read = 0

    @property
    def ratio_excluded_compressed_bytes(self) -> int:
        """Physical bytes accepted by framing but unrelated to payload output."""
        zero_output = getattr(self._fileobj, "zero_output_stream_bytes", 0)
        inter_stream_padding = getattr(self._fileobj, "inter_stream_padding_bytes", 0)
        terminal_padding = getattr(self._fileobj, "terminal_padding_bytes", 0)
        return sum(
            value if isinstance(value, int) and value > 0 else 0
            for value in (zero_output, inter_stream_padding, terminal_padding)
        )

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = ARCHIVE_MEMBER_COPY_CHUNK_BYTES
        if self.max_read_size > 0 and size > self.max_read_size:
            raise _TarStreamBudgetExceeded(
                f"TAR stream read request exceeds bounded metadata limit ({size} > {self.max_read_size} bytes)",
                bytes_read=self.bytes_read,
                max_bytes=self.max_read_size,
                reason="tar_metadata_read_limit_exceeded",
            )
        read_size = size
        if self.max_bytes > 0:
            read_size = min(size, self.max_bytes - self.bytes_read + 1)

        data = self._fileobj.read(read_size)
        self.bytes_read += len(data)
        if self.max_bytes > 0 and self.bytes_read > self.max_bytes:
            raise _TarStreamBudgetExceeded(
                f"TAR stream exceeded decompressed read limit ({self.bytes_read} > {self.max_bytes} bytes)",
                bytes_read=self.bytes_read,
                max_bytes=self.max_bytes,
                reason=TAR_DECOMPRESSED_SIZE_LIMIT_INCOMPLETE_REASON,
            )
        return data


class _TarSourcePrefixFile:
    """Expose only the physical source prefix owned by a supplemental TAR scan."""

    def __init__(self, fileobj: BinaryIO, limit: int) -> None:
        self._fileobj = fileobj
        self.limit = limit

    def read(self, size: int = -1) -> bytes:
        remaining = max(self.limit - self.tell(), 0)
        if size is None or size < 0 or size > remaining:
            size = remaining
        return self._fileobj.read(size)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        elif whence == os.SEEK_END:
            target = self.limit + offset
        else:
            raise ValueError(f"Unsupported seek mode: {whence}")
        if target < 0 or target > self.limit:
            raise OSError("TAR source prefix seek exceeds owner boundary")
        return self._fileobj.seek(target, os.SEEK_SET)

    def tell(self) -> int:
        return self._fileobj.tell()

    def fileno(self) -> int:
        return self._fileobj.fileno()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fileobj, name)


class _StrictConcatenatedDecompressionReader:
    """Stream gzip/bzip2/xz members and reject unbounded physical tails."""

    _RAW_READ_SIZE = 8 * 1024

    def __init__(
        self,
        fileobj: BinaryIO,
        *,
        compression_codec: str,
        max_xz_padding_bytes: int,
    ) -> None:
        self._fileobj = fileobj
        self._compression_codec = compression_codec
        self._max_xz_padding_bytes = max_xz_padding_bytes
        self._xz_padding_bytes_read = 0
        self._decompressor = self._new_decompressor()
        self._completed_streams = 0
        self._eof = False
        self._current_stream_input_bytes = 0
        self._current_stream_output_bytes = 0
        self.zero_output_stream_bytes = 0
        self.inter_stream_padding_bytes = 0
        self.terminal_padding_bytes = 0

    def _new_decompressor(self) -> Any:
        if self._compression_codec == "gzip":
            return zlib.decompressobj(wbits=31)
        if self._compression_codec == "bzip2":
            return bz2.BZ2Decompressor()
        if self._compression_codec == "xz":
            return lzma.LZMADecompressor()
        raise ValueError(f"Unsupported strict decompression codec: {self._compression_codec}")

    def _read_after_padding(self, initial: bytes) -> bytes | None:
        """Bound permitted zero padding before a possible next compressed stream."""
        block = initial
        stream_padding_size = 0
        while True:
            nonzero_offset = len(block) - len(block.lstrip(b"\0"))
            stream_padding_size += nonzero_offset
            self._xz_padding_bytes_read += nonzero_offset
            block = block[nonzero_offset:]
            if self._xz_padding_bytes_read > self._max_xz_padding_bytes:
                raise _TarStreamBudgetExceeded(
                    "XZ stream padding exceeded bounded read limit "
                    f"({self._xz_padding_bytes_read} > {self._max_xz_padding_bytes} bytes)",
                    bytes_read=self._xz_padding_bytes_read,
                    max_bytes=self._max_xz_padding_bytes,
                    reason=TAR_COMPRESSED_PADDING_LIMIT_INCOMPLETE_REASON,
                )
            if block:
                if self._compression_codec == "xz" and stream_padding_size % 4 != 0:
                    raise _TarCompressedPhysicalTrailingData("Invalid XZ stream padding")
                self.inter_stream_padding_bytes += stream_padding_size
                return block

            padding_remaining = self._max_xz_padding_bytes - self._xz_padding_bytes_read
            block = self._fileobj.read(min(self._RAW_READ_SIZE, padding_remaining + 1))
            if not block:
                if self._compression_codec == "xz" and stream_padding_size % 4 != 0:
                    raise _TarCompressedPhysicalTrailingData("Invalid XZ stream padding")
                self.terminal_padding_bytes += stream_padding_size
                return None

    def _next_stream_input(self) -> bytes | None:
        block = cast(bytes, self._decompressor.unused_data)
        if self._compression_codec in {"gzip", "xz"}:
            return self._read_after_padding(block)
        if not block:
            block = self._fileobj.read(self._RAW_READ_SIZE)
        return block or None

    def _decompress(self, block: bytes, max_length: int) -> bytes:
        try:
            output = cast(bytes, self._decompressor.decompress(block, max_length))
            self._current_stream_output_bytes += len(output)
            return output
        except (OSError, lzma.LZMAError, zlib.error) as exc:
            if self._completed_streams > 0:
                raise _TarCompressedPhysicalTrailingData(
                    "Compressed wrapper contains invalid physical trailing data"
                ) from exc
            raise

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = ARCHIVE_MEMBER_COPY_CHUNK_BYTES
        if size == 0 or self._eof:
            return b""

        output = bytearray()
        while len(output) < size and not self._eof:
            if self._decompressor.eof:
                consumed_stream_bytes = self._current_stream_input_bytes - len(
                    cast(bytes, self._decompressor.unused_data)
                )
                if self._current_stream_output_bytes == 0:
                    self.zero_output_stream_bytes += max(consumed_stream_bytes, 0)
                self._completed_streams += 1
                block = self._next_stream_input()
                if block is None:
                    self._eof = True
                    break
                self._decompressor = self._new_decompressor()
                self._current_stream_input_bytes = len(block)
                self._current_stream_output_bytes = 0
            elif getattr(self._decompressor, "needs_input", not getattr(self._decompressor, "unconsumed_tail", b"")):
                block = self._fileobj.read(self._RAW_READ_SIZE)
                if not block:
                    if self._completed_streams > 0:
                        raise _TarCompressedPhysicalTrailingData(
                            "Compressed wrapper contains truncated physical trailing data"
                        )
                    raise EOFError("Compressed file ended before the end-of-stream marker")
                self._current_stream_input_bytes += len(block)
            else:
                block = cast(bytes, self._decompressor.unconsumed_tail) if self._compression_codec == "gzip" else b""

            output.extend(self._decompress(block, size - len(output)))

        return bytes(output)


def _tar_padded_size(size: int) -> int:
    return ((max(size, 0) + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE


class TarScanner(BaseScanner):
    """Scanner for TAR archive files."""

    name = "tar"
    description = "Scans TAR archive files and their contents recursively"
    default_max_file_read_size: ClassVar[int] = 0
    supported_extensions: ClassVar[list[str]] = [
        ".tar",
        ".tar.gz",
        ".tgz",
        ".tar.bz2",
        ".tbz2",
        ".tar.xz",
        ".txz",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_depth = self.config.get("max_tar_depth", 5)
        self.max_entries = self.config.get("max_tar_entries", 10000)
        self.max_decompressed_bytes = self._normalize_positive_int_config(
            self.config.get("compressed_max_decompressed_bytes"),
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        self.max_decompression_ratio = self._normalize_positive_float_config(
            self.config.get("compressed_max_decompression_ratio"),
            DEFAULT_MAX_DECOMPRESSION_RATIO,
        )
        self.max_xz_padding_bytes = self._normalize_positive_int_config(
            self.config.get("compressed_max_xz_padding_bytes"),
            DEFAULT_MAX_XZ_STREAM_PADDING_BYTES,
        )
        self.max_metadata_bytes = self._normalize_positive_int_config(
            self.config.get("max_tar_metadata_bytes"),
            DEFAULT_MAX_TAR_METADATA_BYTES,
        )
        self._raw_tar_end_marker_scan_limit_exceeded = False
        configured_source_limit = self.config.get(TAR_SOURCE_SIZE_LIMIT_CONFIG_KEY)
        self.source_size_limit = (
            configured_source_limit
            if isinstance(configured_source_limit, int)
            and not isinstance(configured_source_limit, bool)
            and configured_source_limit > 0
            else None
        )

    def _effective_source_size(self, path: str, raw_file: BinaryIO | None = None) -> int:
        size = os.fstat(raw_file.fileno()).st_size if raw_file is not None else os.path.getsize(path)
        return min(size, self.source_size_limit) if self.source_size_limit is not None else size

    def _effective_compressed_source_size(self, path: str, raw_file: BinaryIO | None = None) -> int:
        """Return the exact physical compressed source size."""
        return self._effective_source_size(path, raw_file)

    def _projected_compressed_source_size(self, path: str, raw_file: BinaryIO | None = None) -> int:
        """Conservatively exclude provable padding before payload extraction.

        Exact terminal padding is reported by the strict reader after wrapper
        EOF/CRC validation. This estimate preserves the largest possible
        codec trailer so zero-valued trailer bytes are never misclassified.
        """
        source_size = self._effective_source_size(path, raw_file)
        if source_size <= 0:
            return source_size

        with contextlib.nullcontext(raw_file) if raw_file is not None else open(path, "rb") as source:
            assert source is not None
            original_offset = source.tell()
            try:
                source.seek(0)
                prefix = source.read(len(_XZ_MAGIC))
                if prefix.startswith(_GZIP_MAGIC):
                    protected_trailer_bytes = 8
                elif prefix.startswith(_XZ_MAGIC):
                    protected_trailer_bytes = 12
                else:
                    return source_size

                trailing_padding = 0
                cursor = source_size
                while cursor > 0:
                    read_start = max(cursor - ARCHIVE_MEMBER_COPY_CHUNK_BYTES, 0)
                    source.seek(read_start)
                    block = source.read(cursor - read_start)
                    trailing_padding += len(block) - len(block.rstrip(b"\0"))
                    if trailing_padding > self.max_xz_padding_bytes:
                        return max(source_size - max(trailing_padding - protected_trailer_bytes, 0), 1)
                    if any(block):
                        return max(source_size - max(trailing_padding - protected_trailer_bytes, 0), 1)
                    cursor = read_start
                return max(source_size - max(trailing_padding - protected_trailer_bytes, 0), 1)
            finally:
                source.seek(original_offset)

    @staticmethod
    def _normalize_positive_float_config(value: Any, default: float) -> float:
        """Return a positive float config value, or default for invalid input."""
        if isinstance(value, bool):
            return default
        try:
            normalized_value = float(value)
        except (TypeError, ValueError):
            return default
        return normalized_value if math.isfinite(normalized_value) and normalized_value > 0 else default

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        try:
            compression_codec = cls._detect_compressed_tar_wrapper(path)
            if compression_codec is not None:
                return cls._compressed_tar_has_valid_header(path, compression_codec)
            with open(path, "rb") as file_obj:
                prefix = file_obj.read(_TAR_HEADER_PROBE_BYTES)
            if cls._looks_like_empty_tar_prefix(prefix):
                return cls._is_empty_tar_archive(path)
            return cls._tar_header_probe_is_valid(prefix)
        except (EOFError, OSError, lzma.LZMAError):
            return False

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)

        self._add_streaming_safe_integrity_check(path, result)

        try:
            self.current_file_path = path
            try:
                archive_depth = int(self.config.get("_archive_depth", 0))
            except (TypeError, ValueError):
                archive_depth = 0

            with _tar_shared_scan_budget_scope(
                self.config,
                max_total_uncompressed_size=self._get_max_total_uncompressed_size(),
            ):
                scan_result = self._scan_tar_file(path, depth=max(archive_depth, 0))
            result.merge(scan_result)
        except tarfile.TarError:
            result.add_check(
                name="TAR File Format Validation",
                passed=False,
                message=f"Not a valid tar file: {path}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
                rule_code="S902",
            )
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
            result.finish(success=False)
            return result
        except Exception as e:
            self._record_incomplete_tar_scan(result, path, e)
            result.finish(success=False)
            return result

        result.finish(success=scan_result.success and not result.has_errors)
        result.metadata["contents"] = scan_result.metadata.get("contents", [])
        return result

    def _add_streaming_safe_integrity_check(self, path: str, result: ScanResult) -> None:
        file_size = self.get_file_size(path)
        hash_read_limit = self.max_file_read_size if self.max_file_read_size > 0 else DEFAULT_MAX_FILE_READ_SIZE
        if file_size > hash_read_limit:
            result.checks.append(
                Check(
                    name="File Integrity Hash",
                    status=CheckStatus.SKIPPED,
                    message="File integrity hashes skipped for streaming TAR archive",
                    location=path,
                    details={
                        "file_size": file_size,
                        "max_file_read_size": hash_read_limit,
                        "hash_skipped": True,
                        "skip_reason": "tar_file_integrity_hash_skipped",
                    },
                )
            )
            result.metadata["file_size"] = file_size
            result.metadata["file_hashes_skipped"] = True
            result.metadata["file_hashes_skip_reason"] = "tar_file_integrity_hash_skipped"
            return

        self.add_file_integrity_check(path, result)

    def _get_max_entry_size(self) -> int:
        """Return the per-entry extraction limit used for TAR members."""
        configured_file_limit = self.config.get("max_file_size")
        configured_entry_limit = self.config.get("max_entry_size")

        if configured_entry_limit is not None:
            if configured_entry_limit == 0:
                entry_limit = 1024 * 1024 * 1024 * 1024
            else:
                entry_limit = self._normalize_positive_int_config(
                    configured_entry_limit,
                    DEFAULT_MAX_TAR_ENTRY_SIZE,
                )
        else:
            entry_limit = DEFAULT_MAX_TAR_ENTRY_SIZE

        # Core enforces max_file_size for the top-level archive. For members it
        # can only make extraction stricter; it must not raise the bounded TAR
        # default just because a large container was allowed.
        if configured_file_limit is not None and configured_file_limit != 0:
            file_limit = self._normalize_positive_int_config(
                configured_file_limit,
                DEFAULT_MAX_TAR_ENTRY_SIZE,
            )
            return min(entry_limit, file_limit)

        return entry_limit

    def _get_max_total_uncompressed_size(self) -> int:
        """Return the aggregate TAR member byte budget."""
        positive_limits: list[int] = []
        configured_total_limit = self.config.get("max_tar_total_uncompressed_size")
        if configured_total_limit is not None:
            if configured_total_limit != 0:
                positive_limits.append(
                    self._normalize_positive_int_config(
                        configured_total_limit,
                        DEFAULT_MAX_TAR_TOTAL_UNCOMPRESSED_SIZE,
                    )
                )
        else:
            positive_limits.append(DEFAULT_MAX_TAR_TOTAL_UNCOMPRESSED_SIZE)

        configured_public_limit = self.config.get("max_total_size")
        if configured_public_limit is not None and configured_public_limit != 0:
            positive_limits.append(
                self._normalize_positive_int_config(
                    configured_public_limit,
                    DEFAULT_MAX_TAR_TOTAL_UNCOMPRESSED_SIZE,
                )
            )

        return min(positive_limits) if positive_limits else 1024 * 1024 * 1024 * 1024

    def _get_or_create_shared_budget(self) -> _TarSharedScanBudget:
        raw_budget = self.config.get(TAR_SHARED_SCAN_BUDGET_CONFIG_KEY)
        if isinstance(raw_budget, _TarSharedScanBudget):
            return raw_budget
        budget = _TarSharedScanBudget(max_total_uncompressed_size=self._get_max_total_uncompressed_size())
        self.config[TAR_SHARED_SCAN_BUDGET_CONFIG_KEY] = budget
        return budget

    def _tar_stream_read_limit(self) -> int:
        return max(tarfile.BLOCKSIZE, self.max_metadata_bytes)

    def _tar_metadata_limit(self) -> int:
        return max(1, self.max_metadata_bytes)

    @staticmethod
    def _metadata_budget_exception(message: str, bytes_read: int, max_bytes: int) -> Exception:
        return _TarStreamBudgetExceeded(
            message,
            bytes_read=bytes_read,
            max_bytes=max_bytes,
            reason="tar_metadata_read_limit_exceeded",
        )

    @contextmanager
    def _open_tar_stream(
        self,
        path: str,
        *,
        raw_file: BinaryIO | None = None,
    ) -> Iterator[tuple[tarfile.TarFile, _TarBoundedStream | None, str | None]]:
        """Open raw TAR seekably or compressed TAR through bounded r| traversal."""
        with ExitStack() as stack:
            raw = raw_file if raw_file is not None else stack.enter_context(open(path, "rb"))
            if self.source_size_limit is not None:
                raw = cast(BinaryIO, _TarSourcePrefixFile(raw, self._effective_source_size(path, raw)))
            raw.seek(0)
            prefix = raw.read(tarfile.BLOCKSIZE)
            if prefix == b"\0" * tarfile.BLOCKSIZE:
                prefix += raw.read(tarfile.BLOCKSIZE)
            raw.seek(0)
            compression_codec = None
            if not (self._looks_like_empty_tar_prefix(prefix) or _looks_like_uncompressed_tar_header(prefix)):
                if prefix.startswith(_GZIP_MAGIC):
                    compression_codec = "gzip"
                elif prefix.startswith(_BZIP2_MAGIC):
                    compression_codec = "bzip2"
                elif prefix.startswith(_XZ_MAGIC):
                    compression_codec = "xz"

            if compression_codec is None:
                archive = stack.enter_context(
                    tarfile.open(
                        fileobj=raw,
                        mode="r:",
                        tarinfo=cast(
                            type[tarfile.TarInfo],
                            bounded_tar_info_class(
                                self._tar_metadata_limit(),
                                exception_factory=self._metadata_budget_exception,
                            ),
                        ),
                    )
                )
                yield archive, None, None
                return

            if compression_codec in {"gzip", "bzip2", "xz"}:
                decompressed: Any = _StrictConcatenatedDecompressionReader(
                    raw,
                    compression_codec=compression_codec,
                    max_xz_padding_bytes=self.max_xz_padding_bytes,
                )
            else:  # pragma: no cover - _detect_compressed_tar_wrapper returns only supported codecs.
                return

            bounded_stream = _TarBoundedStream(
                decompressed,
                max_bytes=self.max_decompressed_bytes,
                max_read_size=self._tar_stream_read_limit(),
            )
            archive = stack.enter_context(
                tarfile.open(
                    fileobj=cast(Any, bounded_stream),
                    mode="r|",
                    bufsize=tarfile.BLOCKSIZE,
                    tarinfo=cast(
                        type[tarfile.TarInfo],
                        bounded_tar_info_class(
                            self._tar_metadata_limit(),
                            exception_factory=self._metadata_budget_exception,
                        ),
                    ),
                )
            )
            yield archive, bounded_stream, compression_codec

    def _rewrite_nested_result_context(
        self,
        scan_result: ScanResult,
        tmp_path: str,
        archive_path: str,
        entry_name: str,
    ) -> None:
        """Rewrite nested result locations so archive members, not temp files, are reported."""
        archive_location = f"{archive_path}:{entry_name}"

        for issue in scan_result.issues:
            issue.location = self._rewrite_archive_location(issue.location, tmp_path, archive_location)

            existing_issue_entry = issue.details.get("tar_entry")
            issue.details["tar_entry"] = (
                f"{entry_name}:{existing_issue_entry}"
                if isinstance(existing_issue_entry, str) and existing_issue_entry
                else entry_name
            )

        for check in scan_result.checks:
            check.location = self._rewrite_archive_location(check.location, tmp_path, archive_location)

            existing_check_entry = check.details.get("tar_entry")
            check.details["tar_entry"] = (
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

    def _is_reachable_nemo_root_config(self, member_name: str) -> bool:
        """Return whether a streamed TAR member is a root NeMo config path."""
        if self.config.get(TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY) is True:
            return False
        from .nemo_scanner import NemoScanner

        return NemoScanner._is_root_config_member_name(member_name)

    def _scan_reachable_nemo_config_member(
        self,
        *,
        archive_path: str,
        member_name: str,
        member_size: int,
        tmp_path: str,
        result: ScanResult,
    ) -> bool:
        """Apply NeMo root-config checks to a member reached by generic TAR streaming."""
        if not self._is_reachable_nemo_root_config(member_name):
            return True

        from .nemo_scanner import NemoScanner

        nemo_scanner = NemoScanner(config=dict(self.config))
        with open(tmp_path, "rb") as config_file:
            raw_config = config_file.read(nemo_scanner.MAX_CONFIG_SIZE + 1)
        return nemo_scanner.scan_reachable_root_config_bytes(
            raw_config,
            config_file=member_name,
            archive_path=archive_path,
            result=result,
            declared_size=member_size,
        )

    def _record_reachable_nemo_link_incomplete(
        self,
        result: ScanResult,
        *,
        archive_path: str,
        member: tarfile.TarInfo,
        effective_name: str | None = None,
    ) -> bool:
        """Fail closed when generic TAR streaming reaches a linked root NeMo config."""
        config_name = effective_name or member.name
        if not self._is_reachable_nemo_root_config(config_name):
            return False

        mark_archive_scan_incomplete(result, "nemo_link_semantics_incomplete")
        result.add_check(
            name="NeMo Link Semantics",
            passed=False,
            message="Root NeMo config is link-mediated; generic TAR analysis is conservative",
            severity=IssueSeverity.INFO,
            location=f"{archive_path}:{config_name}",
            details={
                "entry": member.name,
                "effective_entry": config_name,
                "target": member.linkname,
                "analysis_incomplete": True,
                "scan_outcome_reason": "nemo_link_semantics_incomplete",
            },
        )
        return True

    @staticmethod
    def _record_nemo_link_resolution_incomplete(
        result: ScanResult,
        *,
        archive_path: str,
        entry_name: str,
        message: str,
    ) -> None:
        mark_archive_scan_incomplete(result, "nemo_link_semantics_incomplete")
        result.add_check(
            name="NeMo Link Semantics",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=f"{archive_path}:{entry_name}",
            details={
                "entry": entry_name,
                "analysis_incomplete": True,
                "scan_outcome_reason": "nemo_link_semantics_incomplete",
            },
        )

    @staticmethod
    def _rewrite_archive_location(location: str | None, tmp_path: str, archive_location: str) -> str:
        return rewrite_extracted_member_location(
            location,
            tmp_path,
            archive_location,
            preserve_non_delimited_suffix=False,
        )

    @staticmethod
    def _member_declares_sparse_data(member: tarfile.TarInfo) -> bool:
        try:
            if member.issparse():
                return True
        except AttributeError:
            # Older TarInfo-compatible objects may not expose issparse();
            # continue with PAX sparse header detection below.
            pass
        return any(field in member.pax_headers for field in TAR_SPARSE_PAX_SIZE_FIELDS)

    @classmethod
    def _tar_member_kind(cls, member: tarfile.TarInfo) -> str:
        """Return a stable inventory type for a TAR member."""
        if cls._member_declares_sparse_data(member):
            return "tar_sparse"
        if member.isfile():
            return "tar_file"
        if member.isdir():
            return "tar_directory"
        if member.issym():
            return "tar_symlink"
        if member.islnk():
            return "tar_hardlink"
        if member.isfifo():
            return "tar_fifo"
        if member.isdev():
            return "tar_device"
        return "tar_special"

    @classmethod
    def _member_inventory_entry(
        cls,
        archive_path: str,
        member: tarfile.TarInfo,
        *,
        scan_status: str,
        scan_outcome_reason: str | None = None,
    ) -> dict[str, Any]:
        """Build a bounded metadata entry for a TAR member without reading its content."""
        entry: dict[str, Any] = {
            "path": f"{archive_path}:{member.name}",
            "type": cls._tar_member_kind(member),
            "size": member.size,
            "scan_status": scan_status,
        }
        if scan_outcome_reason is not None:
            entry["scan_outcome_reason"] = scan_outcome_reason
        return entry

    @staticmethod
    def _resolve_link_target(
        target: str,
        *,
        resolved_member_name: str,
        extraction_root: str,
        is_symlink: bool,
    ) -> tuple[str, bool]:
        """Resolve TAR symlinks from their parent and hardlinks from the archive root."""
        if not is_symlink:
            return sanitize_archive_path(target, extraction_root)
        if is_absolute_archive_path(target):
            return sanitize_archive_path(target, extraction_root)

        normalized_target = target.replace("\\", os.sep).replace("/", os.sep)
        target_base = os.path.dirname(resolved_member_name)
        target_resolved = os.path.normpath(os.path.join(target_base, normalized_target))
        try:
            target_from_root = os.path.relpath(target_resolved, extraction_root)
        except ValueError:
            return target_resolved, False
        return sanitize_archive_path(target_from_root, extraction_root)

    def _extract_member_to_tempfile(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        *,
        suffix: str,
        basename: str | None = None,
    ) -> tuple[str, int]:
        """Stream a TAR member to disk while enforcing the configured size limit."""
        max_entry_size = self._get_max_entry_size()
        if member.size > max_entry_size:
            raise _TarEntryExtractionIncomplete(
                f"TAR entry {member.name} exceeds maximum size of {max_entry_size} bytes"
            )
        fileobj = tar.extractfile(member)
        if fileobj is None:
            raise _TarEntryExtractionIncomplete(f"Unable to extract TAR entry: {member.name}")

        total_size = 0
        tmp_path: str | None = None
        tmp_dir: str | None = None
        try:

            def copy_member_to(tmp_file: BinaryIO) -> int:
                copied_size = 0
                while True:
                    chunk = fileobj.read(ARCHIVE_MEMBER_COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    copied_size += len(chunk)
                    if copied_size > max_entry_size:
                        raise _TarEntryExtractionIncomplete(
                            f"TAR entry {member.name} exceeds maximum size of {max_entry_size} bytes"
                        )
                    tmp_file.write(chunk)
                return copied_size

            if basename is None:
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as named_tmp:
                    tmp_path = named_tmp.name
                    total_size = copy_member_to(cast(BinaryIO, named_tmp))
            else:
                tmp_dir = tempfile.mkdtemp(prefix="modelaudit_tar_")
                tmp_path = os.path.join(tmp_dir, basename)
                with open(tmp_path, "wb") as tmp_file:
                    total_size = copy_member_to(tmp_file)
        except Exception:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
            if tmp_dir and os.path.isdir(tmp_dir):
                os.rmdir(tmp_dir)
            raise
        finally:
            fileobj.close()

        assert tmp_path is not None
        return tmp_path, total_size

    @staticmethod
    def _raw_tar_has_valid_header(path: str) -> bool:
        with open(path, "rb") as file_obj:
            prefix = file_obj.read(tarfile.BLOCKSIZE)
            if prefix == b"\0" * tarfile.BLOCKSIZE:
                prefix += file_obj.read(tarfile.BLOCKSIZE)
        return TarScanner._looks_like_empty_tar_prefix(prefix) or _looks_like_uncompressed_tar_header(prefix)

    @staticmethod
    def _detect_compressed_tar_wrapper(path: str) -> str | None:
        """Detect compressed TAR wrappers by content, not by filename suffix."""
        with open(path, "rb") as file_obj:
            header = file_obj.read(6)

        if header.startswith(_GZIP_MAGIC):
            return "gzip"
        if header.startswith(_BZIP2_MAGIC):
            return "bzip2"
        if header.startswith(_XZ_MAGIC):
            return "xz"
        return None

    @staticmethod
    def _looks_like_empty_tar_prefix(prefix: bytes) -> bool:
        return len(prefix) >= _TAR_HEADER_PROBE_BYTES and prefix[:_TAR_HEADER_PROBE_BYTES] == (
            b"\0" * _TAR_HEADER_PROBE_BYTES
        )

    @staticmethod
    def _tar_header_probe_is_valid(prefix: bytes) -> bool:
        if TarScanner._looks_like_empty_tar_prefix(prefix):
            return True
        if len(prefix) < tarfile.BLOCKSIZE:
            return False
        try:
            tarfile.TarInfo.frombuf(prefix[: tarfile.BLOCKSIZE], encoding="utf-8", errors="surrogateescape")
        except tarfile.HeaderError:
            return False
        return True

    @staticmethod
    def _read_compressed_tar_header_probe(path: str, compression_codec: str) -> bytes | None:
        try:
            with open(path, "rb") as raw:
                if compression_codec == "gzip":
                    with gzip.GzipFile(fileobj=raw, mode="rb") as stream:
                        return stream.read(_TAR_HEADER_PROBE_BYTES)
                if compression_codec == "bzip2":
                    with bz2.BZ2File(raw, mode="rb") as stream:
                        return stream.read(_TAR_HEADER_PROBE_BYTES)
                if compression_codec == "xz":
                    with lzma.LZMAFile(raw, mode="rb") as stream:
                        return stream.read(_TAR_HEADER_PROBE_BYTES)
        except (EOFError, OSError, lzma.LZMAError, zlib.error):
            return None
        return None

    @classmethod
    def _compressed_tar_has_valid_header(cls, path: str, compression_codec: str) -> bool:
        if cls._detect_compressed_tar_wrapper(path) != compression_codec:
            return False
        prefix = cls._read_compressed_tar_header_probe(path, compression_codec)
        return prefix is not None and cls._tar_header_probe_is_valid(prefix)

    @staticmethod
    def _finalize_tar_stream_size(consumed_size: int) -> int:
        """Return the minimum TAR stream size after EOF blocks and record padding."""
        total_size = max(consumed_size + (2 * tarfile.BLOCKSIZE), tarfile.RECORDSIZE)
        return ((total_size + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE

    @staticmethod
    def _is_empty_tar_archive(path: str, *, raw_file: BinaryIO | None = None) -> bool:
        """Detect standard empty TAR archives that some Python 3.10 builds reject on ``next()``."""
        max_read_size = 10 * 1024 * 1024
        try:
            file_size = os.fstat(raw_file.fileno()).st_size if raw_file is not None else os.path.getsize(path)
            if file_size < 2 * tarfile.BLOCKSIZE or file_size % tarfile.BLOCKSIZE != 0:
                return False
            if file_size > max_read_size:
                return False

            with ExitStack() as stack:
                file_obj = raw_file if raw_file is not None else stack.enter_context(open(path, "rb"))
                original_offset = file_obj.tell()
                try:
                    file_obj.seek(0)
                    first_block = file_obj.read(tarfile.BLOCKSIZE)
                    if first_block != b"\0" * tarfile.BLOCKSIZE:
                        return False
                    return all(not any(chunk) for chunk in iter(lambda: file_obj.read(64 * 1024), b""))
                finally:
                    file_obj.seek(original_offset)
        except OSError:
            return False

    def _windows_sparse_tail_is_zero(self, file_obj: BinaryIO, *, tail_start: int, tail_end: int) -> bool | None:
        """Check only allocated Windows sparse-tail ranges; return ``None`` if unavailable."""
        if os.name != "nt":
            return None

        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes
        except ImportError:  # pragma: no cover - Windows stdlib provides these modules.
            return None

        class _FileAllocatedRangeBuffer(ctypes.Structure):
            _fields_ = [("file_offset", ctypes.c_longlong), ("length", ctypes.c_longlong)]

        fsctl_query_allocated_ranges = 0x000940CF
        error_more_data = 234
        output_range_count = 64
        windows_ctypes = cast(Any, ctypes)
        windows_msvcrt = cast(Any, msvcrt)
        kernel32 = windows_ctypes.WinDLL("kernel32", use_last_error=True)
        device_io_control = kernel32.DeviceIoControl
        device_io_control.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        device_io_control.restype = wintypes.BOOL

        try:
            handle = wintypes.HANDLE(windows_msvcrt.get_osfhandle(file_obj.fileno()))
        except OSError:
            return None

        checked_bytes = 0
        query_offset = tail_start
        while query_offset < tail_end:
            query = _FileAllocatedRangeBuffer(query_offset, tail_end - query_offset)
            ranges = (_FileAllocatedRangeBuffer * output_range_count)()
            bytes_returned = wintypes.DWORD()
            succeeded = bool(
                device_io_control(
                    handle,
                    fsctl_query_allocated_ranges,
                    ctypes.byref(query),
                    ctypes.sizeof(query),
                    ctypes.byref(ranges),
                    ctypes.sizeof(ranges),
                    ctypes.byref(bytes_returned),
                    None,
                )
            )
            error = windows_ctypes.get_last_error()
            if not succeeded and error != error_more_data:
                return None

            range_count = bytes_returned.value // ctypes.sizeof(_FileAllocatedRangeBuffer)
            if range_count == 0:
                return True if succeeded else None

            furthest_offset = query_offset
            for allocated_range in ranges[:range_count]:
                range_start = max(allocated_range.file_offset, tail_start)
                range_end = min(allocated_range.file_offset + allocated_range.length, tail_end)
                if range_end <= range_start:
                    continue

                checked_bytes += range_end - range_start
                if checked_bytes > self.max_xz_padding_bytes:
                    self._raw_tar_end_marker_scan_limit_exceeded = True
                    return False

                file_obj.seek(range_start)
                remaining = range_end - range_start
                while remaining > 0:
                    chunk = file_obj.read(min(ARCHIVE_MEMBER_COPY_CHUNK_BYTES, remaining))
                    if not chunk or any(chunk):
                        return False
                    remaining -= len(chunk)
                furthest_offset = max(furthest_offset, range_end)

            if succeeded:
                return True
            if furthest_offset <= query_offset:
                return None
            query_offset = furthest_offset

        return True

    def _raw_tar_has_complete_end_marker(self, tar: tarfile.TarFile) -> bool:
        """Validate raw TAR EOF and bounded zero-only record padding."""
        self._raw_tar_end_marker_scan_limit_exceeded = False
        file_obj = cast(BinaryIO, tar.fileobj)
        file_obj.seek(tar.offset)
        if file_obj.read(2 * tarfile.BLOCKSIZE) != b"\0" * (2 * tarfile.BLOCKSIZE):
            return False
        tail_start = file_obj.tell()
        tail_end = os.fstat(file_obj.fileno()).st_size
        if self.source_size_limit is not None:
            tail_end = min(tail_end, self.source_size_limit)
        tail_size = tail_end - tail_start
        if tail_size <= self.max_xz_padding_bytes:
            return not any(file_obj.read())
        if hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE"):
            offset = tail_start
            checked_bytes = 0
            while True:
                try:
                    data_offset = os.lseek(file_obj.fileno(), offset, os.SEEK_DATA)
                except OSError as exc:
                    return exc.errno == errno.ENXIO
                if data_offset >= tail_end:
                    return True
                hole_offset = min(os.lseek(file_obj.fileno(), data_offset, os.SEEK_HOLE), tail_end)
                if hole_offset <= offset:
                    return False
                checked_bytes += hole_offset - data_offset
                if checked_bytes > self.max_xz_padding_bytes:
                    self._raw_tar_end_marker_scan_limit_exceeded = True
                    return False
                file_obj.seek(data_offset)
                remaining = hole_offset - data_offset
                while remaining > 0:
                    chunk = file_obj.read(min(ARCHIVE_MEMBER_COPY_CHUNK_BYTES, remaining))
                    if not chunk:
                        return True
                    if any(chunk):
                        return False
                    remaining -= len(chunk)
                offset = hole_offset
        windows_tail_is_zero = self._windows_sparse_tail_is_zero(
            file_obj,
            tail_start=tail_start,
            tail_end=tail_end,
        )
        if windows_tail_is_zero is not None:
            return windows_tail_is_zero
        tail_size = 0
        while chunk := file_obj.read(min(ARCHIVE_MEMBER_COPY_CHUNK_BYTES, self.max_xz_padding_bytes - tail_size + 1)):
            tail_size += len(chunk)
            if any(chunk):
                return False
            if tail_size > self.max_xz_padding_bytes:
                self._raw_tar_end_marker_scan_limit_exceeded = True
                return False
        return True

    def _add_compressed_wrapper_limit_check(
        self,
        result: ScanResult,
        *,
        passed: bool,
        path: str,
        message: str,
        decompressed_size: int,
        compressed_size: int,
        compression_codec: str,
        actual_ratio: float | None = None,
        incomplete_reason: str | None = None,
    ) -> None:
        """Record compressed-wrapper policy checks with consistent details."""
        details: dict[str, Any] = {
            "decompressed_size": decompressed_size,
            "compressed_size": compressed_size,
            "max_decompressed_size": self.max_decompressed_bytes,
            "max_ratio": self.max_decompression_ratio,
            "compression": compression_codec,
        }
        if actual_ratio is not None:
            details["actual_ratio"] = actual_ratio
        if not passed and incomplete_reason is not None:
            details["analysis_incomplete"] = True
            details["scan_outcome_reason"] = incomplete_reason

        result.add_check(
            name="Compressed Wrapper Decompression Limits",
            passed=passed,
            message=message,
            severity=None if passed else IssueSeverity.WARNING,
            location=path,
            details=details,
            rule_code=None if passed else "S902",
        )

    def _add_tar_aggregate_size_check(
        self,
        result: ScanResult,
        path: str,
        *,
        passed: bool,
        archive_uncompressed_size: int,
        member_name: str | None = None,
    ) -> None:
        details: dict[str, Any] = {
            "archive_uncompressed_size": archive_uncompressed_size,
            "max_tar_total_uncompressed_size": self._get_max_total_uncompressed_size(),
        }
        if member_name is not None:
            details["entry"] = member_name
            details["analysis_incomplete"] = True
            details["scan_outcome_reason"] = TAR_TOTAL_SIZE_INCOMPLETE_REASON

        result.add_check(
            name="TAR Aggregate Size Limit Check",
            passed=passed,
            message=(
                f"TAR total uncompressed size ({archive_uncompressed_size}) is within limit "
                f"({self._get_max_total_uncompressed_size()})"
                if passed
                else (
                    "TAR total uncompressed size exceeds limit "
                    f"({archive_uncompressed_size} > {self._get_max_total_uncompressed_size()} bytes); "
                    "member coverage is incomplete"
                )
            ),
            severity=None if passed else IssueSeverity.WARNING,
            rule_code=None if passed else "S410",
            location=path if member_name is None else f"{path}:{member_name}",
            details=details,
        )

    def _reserve_member_work(
        self,
        result: ScanResult,
        path: str,
        member: tarfile.TarInfo,
        shared_budget: _TarSharedScanBudget,
        archive_uncompressed_size: int,
        *,
        work_size: int | None = None,
    ) -> tuple[int, bool]:
        """Reserve declared member work before traversal can consume its body."""
        member_size = max(member.size if work_size is None else work_size, 0)
        archive_uncompressed_size += member_size
        if shared_budget.exhausted:
            return archive_uncompressed_size, False

        projected_total = shared_budget.member_bytes_consumed + member_size
        if (
            shared_budget.max_total_uncompressed_size > 0
            and projected_total > shared_budget.max_total_uncompressed_size
        ):
            shared_budget.exhausted = True
            mark_archive_scan_incomplete(result, TAR_TOTAL_SIZE_INCOMPLETE_REASON)
            self._add_tar_aggregate_size_check(
                result,
                path,
                passed=False,
                archive_uncompressed_size=projected_total,
                member_name=member.name,
            )
            return archive_uncompressed_size, False

        shared_budget.member_bytes_consumed = projected_total
        return archive_uncompressed_size, True

    def _project_compressed_stream_size(self, bounded_stream: _TarBoundedStream, member: tarfile.TarInfo) -> int:
        return self._finalize_tar_stream_size(bounded_stream.bytes_read + _tar_padded_size(member.size))

    @staticmethod
    def _payload_compressed_size(bounded_stream: _TarBoundedStream, compressed_size: int) -> int:
        """Exclude framing bytes that produce no payload from the ratio denominator."""
        return max(compressed_size - bounded_stream.ratio_excluded_compressed_bytes, 1)

    def _record_projected_compressed_member_limit(
        self,
        result: ScanResult,
        path: str,
        member: tarfile.TarInfo,
        bounded_stream: _TarBoundedStream | None,
        *,
        compression_codec: str | None,
        compressed_size: int,
    ) -> bool:
        if compression_codec is None or bounded_stream is None or compressed_size <= 0:
            return False

        projected_stream_size = self._project_compressed_stream_size(bounded_stream, member)
        return self._record_compressed_stream_limit(
            result,
            path,
            stream_size=projected_stream_size,
            compressed_size=self._payload_compressed_size(bounded_stream, compressed_size),
            compression_codec=compression_codec,
        )

    def _record_compressed_stream_limit(
        self,
        result: ScanResult,
        path: str,
        *,
        stream_size: int,
        compressed_size: int,
        compression_codec: str,
        emit_pass: bool = False,
    ) -> bool:
        actual_ratio = (stream_size / compressed_size) if compressed_size > 0 else 0.0
        if stream_size > self.max_decompressed_bytes:
            passed = False
            incomplete_reason = TAR_DECOMPRESSED_SIZE_LIMIT_INCOMPLETE_REASON
            message = f"Decompressed size exceeded limit ({stream_size} > {self.max_decompressed_bytes})"
        elif compressed_size > 0 and actual_ratio > self.max_decompression_ratio:
            passed = False
            incomplete_reason = TAR_DECOMPRESSION_RATIO_LIMIT_INCOMPLETE_REASON
            message = f"Decompression ratio exceeded limit ({actual_ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
        elif emit_pass:
            passed = True
            incomplete_reason = None
            message = f"Decompressed size/ratio are within limits ({stream_size} bytes, {actual_ratio:.1f}x)"
        else:
            return False

        self._add_compressed_wrapper_limit_check(
            result,
            passed=passed,
            path=path,
            message=message,
            decompressed_size=stream_size,
            compressed_size=compressed_size,
            compression_codec=compression_codec,
            actual_ratio=actual_ratio,
            incomplete_reason=incomplete_reason,
        )
        if not passed:
            assert incomplete_reason is not None
            mark_archive_scan_incomplete(result, incomplete_reason)
        return not passed

    def _record_tar_stream_budget_exceeded(
        self,
        result: ScanResult,
        path: str,
        exc: _TarStreamBudgetExceeded,
        *,
        compression_codec: str | None,
        compressed_size: int,
    ) -> None:
        if compression_codec is not None and exc.reason == TAR_DECOMPRESSED_SIZE_LIMIT_INCOMPLETE_REASON:
            actual_ratio = (exc.bytes_read / compressed_size) if compressed_size > 0 else 0.0
            self._add_compressed_wrapper_limit_check(
                result,
                passed=False,
                path=path,
                message=f"Decompressed size exceeded limit ({exc.bytes_read} > {exc.max_bytes})",
                decompressed_size=exc.bytes_read,
                compressed_size=compressed_size,
                compression_codec=compression_codec,
                actual_ratio=actual_ratio,
                incomplete_reason=exc.reason,
            )
        else:
            result.add_check(
                name="TAR Stream Budget",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.INFO,
                rule_code="S902",
                location=path,
                details={
                    "bytes_read": exc.bytes_read,
                    "max_bytes": exc.max_bytes,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": exc.reason,
                },
            )
        mark_archive_scan_incomplete(result, exc.reason)

    @staticmethod
    def _record_compressed_tar_trailing_data(result: ScanResult, path: str) -> None:
        """Record physical compressed-wrapper data that cannot belong to the TAR."""
        mark_archive_scan_incomplete(result, TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON)
        result.add_check(
            name="Compressed TAR Trailing Data",
            passed=False,
            message="Compressed wrapper contains data after the TAR end marker",
            severity=IssueSeverity.WARNING,
            rule_code="S902",
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON,
            },
        )

    def _drain_compressed_tar_tail(
        self,
        tar: tarfile.TarFile,
        bounded_stream: _TarBoundedStream,
        result: ScanResult,
        path: str,
        *,
        compressed_size: int,
        compression_codec: str,
    ) -> bool:
        """Consume the complete wrapper stream and reject data after the TAR end marker."""
        has_trailing_data = False
        read_size = min(ARCHIVE_MEMBER_COPY_CHUNK_BYTES, bounded_stream.max_read_size)
        # Header traversal uses one-block buffering to avoid prefetching member bodies
        # before policy checks. Once TAR EOF is proven, larger reads are safe.
        cast(Any, tar.fileobj).bufsize = read_size
        try:
            while True:
                payload_compressed_size = self._payload_compressed_size(bounded_stream, compressed_size)
                ratio_remaining = (payload_compressed_size * self.max_decompression_ratio) - bounded_stream.bytes_read
                tail_read_size = read_size
                if ratio_remaining < read_size:
                    tail_read_size = max(int(ratio_remaining) + 1, 1)
                cast(Any, tar.fileobj).bufsize = tail_read_size
                chunk = tar.fileobj.read(tail_read_size)
                if not chunk:
                    break
                if self._record_compressed_stream_limit(
                    result,
                    path,
                    stream_size=bounded_stream.bytes_read,
                    compressed_size=self._payload_compressed_size(bounded_stream, compressed_size),
                    compression_codec=compression_codec,
                ):
                    return False
                has_trailing_data = any(chunk)
                if has_trailing_data:
                    break
        except _TarStreamBudgetExceeded as exc:
            if exc.reason != TAR_COMPRESSED_PADDING_LIMIT_INCOMPLETE_REASON:
                raise
            self._record_tar_stream_budget_exceeded(
                result,
                path,
                exc,
                compression_codec=compression_codec,
                compressed_size=compressed_size,
            )
            return False
        except _TarCompressedPhysicalTrailingData:
            has_trailing_data = True
        except Exception as exc:
            TarScanner._record_incomplete_tar_scan(result, path, exc)
            return False

        if not has_trailing_data:
            return True

        self._record_compressed_tar_trailing_data(result, path)
        return False

    def _preflight_tar_archive(
        self,
        path: str,
        result: ScanResult,
        *,
        retain_member_budget: bool = True,
        raw_file: BinaryIO | None = None,
    ) -> bool:
        """Stream TAR headers once to enforce wrapper and optional aggregate limits."""
        entry_count = 0
        compressed_size = self._effective_source_size(path, raw_file)
        projected_compressed_size = compressed_size
        compression_codec: str | None = None
        consumed_size = 0
        archive_uncompressed_size = 0
        shared_budget = self._get_or_create_shared_budget()
        initial_member_bytes = shared_budget.member_bytes_consumed

        try:
            compressed_size = self._effective_compressed_source_size(path, raw_file)
            projected_compressed_size = self._projected_compressed_source_size(path, raw_file)
            with self._open_tar_stream(path, raw_file=raw_file) as (tar, bounded_stream, compression_codec):
                while True:
                    try:
                        member = tar.next()
                    except OSError as exc:
                        if entry_count == 0 and exc.errno == errno.EINVAL and self._is_empty_tar_archive(path):
                            break
                        raise

                    if member is None:
                        if compression_codec is None and not self._raw_tar_has_complete_end_marker(tar):
                            self._record_incomplete_tar_scan(
                                result,
                                path,
                                tarfile.ReadError(
                                    f"Raw TAR traversal stopped without a two-block end marker at offset {tar.offset}"
                                ),
                            )
                            return False
                        if compression_codec is not None and bounded_stream is not None:
                            tail_complete = self._drain_compressed_tar_tail(
                                tar,
                                bounded_stream,
                                result,
                                path,
                                compressed_size=compressed_size,
                                compression_codec=compression_codec,
                            )
                            if not tail_complete:
                                reasons = set(result.metadata.get("scan_outcome_reasons", []))
                                if reasons and reasons <= _POST_TAR_EOF_CONTINUABLE_INCOMPLETE_REASONS:
                                    break
                                return False
                        break

                    entry_count += 1
                    if entry_count > self.max_entries:
                        mark_archive_scan_incomplete(result, TAR_ENTRY_COUNT_INCOMPLETE_REASON)
                        result.add_check(
                            name="Entry Count Limit Check",
                            passed=False,
                            message=f"TAR file contains too many entries ({entry_count} > {self.max_entries})",
                            rule_code="S902",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "entries": entry_count,
                                "max_entries": self.max_entries,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": TAR_ENTRY_COUNT_INCOMPLETE_REASON,
                            },
                        )
                        return False

                    if member.size > 0:
                        work_size = member.size
                        if self._member_declares_sparse_data(member):
                            work_size = max(work_size, tar.offset - member.offset_data)
                        archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                            result,
                            path,
                            member,
                            shared_budget,
                            archive_uncompressed_size,
                            work_size=work_size,
                        )
                        if not budget_reserved:
                            return False

                    if compression_codec is not None and bounded_stream is not None:
                        if self._record_projected_compressed_member_limit(
                            result,
                            path,
                            member,
                            bounded_stream,
                            compression_codec=compression_codec,
                            compressed_size=projected_compressed_size,
                        ):
                            return False
                        consumed_size = max(consumed_size, bounded_stream.bytes_read)
                        estimated_stream_size = self._finalize_tar_stream_size(consumed_size)
                        if self._record_compressed_stream_limit(
                            result,
                            path,
                            stream_size=estimated_stream_size,
                            compressed_size=self._payload_compressed_size(
                                bounded_stream,
                                projected_compressed_size,
                            ),
                            compression_codec=compression_codec,
                        ):
                            return False

                if bounded_stream is not None:
                    consumed_size = max(consumed_size, bounded_stream.bytes_read)

            result.add_check(
                name="Entry Count Limit Check",
                passed=True,
                message=f"Entry count ({entry_count}) is within limits",
                location=path,
                details={"entries": entry_count, "max_entries": self.max_entries},
                rule_code=None,
            )
            self._add_tar_aggregate_size_check(
                result,
                path,
                passed=True,
                archive_uncompressed_size=archive_uncompressed_size,
            )

            if compression_codec is not None and bounded_stream is not None:
                final_stream_size = consumed_size
                if self._record_compressed_stream_limit(
                    result,
                    path=path,
                    stream_size=final_stream_size,
                    compressed_size=self._payload_compressed_size(bounded_stream, compressed_size),
                    compression_codec=compression_codec,
                    emit_pass=True,
                ):
                    return False

        except _TarStreamBudgetExceeded as exc:
            self._record_tar_stream_budget_exceeded(
                result,
                path,
                exc,
                compression_codec=compression_codec,
                compressed_size=projected_compressed_size,
            )
            return False
        except _TarCompressedPhysicalTrailingData:
            self._record_compressed_tar_trailing_data(result, path)
            return False
        except (EOFError, OSError, tarfile.TarError, lzma.LZMAError) as exc:
            self._record_incomplete_tar_scan(result, path, exc)
            return False

        if not retain_member_budget:
            shared_budget.member_bytes_consumed = initial_member_bytes
        return True

    @staticmethod
    def _record_incomplete_tar_scan(result: ScanResult, path: str, exc: Exception) -> None:
        """Record unavailable TAR traversal without discarding findings already collected."""
        mark_archive_scan_incomplete(result, "tar_scan_incomplete")
        result.add_check(
            name="TAR File Scan",
            passed=False,
            message=f"Error scanning tar file: {exc!s}",
            severity=IssueSeverity.INFO,
            rule_code="S902",
            location=path,
            details={
                "exception": str(exc),
                "exception_type": type(exc).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "tar_scan_incomplete",
            },
        )

    def _record_unscannable_member(
        self,
        result: ScanResult,
        contents: list[dict[str, Any]],
        path: str,
        member: tarfile.TarInfo,
        *,
        reason: str,
        message: str,
    ) -> None:
        """Record a TAR member that is intentionally not extracted or scanned."""
        mark_archive_scan_incomplete(result, reason)
        result.add_check(
            name="TAR Member Coverage",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            rule_code="S902",
            location=f"{path}:{member.name}",
            details={
                "entry": member.name,
                "member_type": self._tar_member_kind(member),
                "size": member.size,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )
        contents.append(
            self._member_inventory_entry(
                path,
                member,
                scan_status="incomplete",
                scan_outcome_reason=reason,
            )
        )

    @staticmethod
    def _record_unsupported_member_body(
        result: ScanResult,
        path: str,
        member: tarfile.TarInfo,
    ) -> None:
        mark_archive_scan_incomplete(result, TAR_SPECIAL_MEMBER_INCOMPLETE_REASON)
        result.add_check(
            name="TAR Member Coverage",
            passed=False,
            message=f"TAR metadata entry {member.name} declares an unsupported body",
            severity=IssueSeverity.INFO,
            rule_code="S902",
            location=f"{path}:{member.name}",
            details={
                "entry": member.name,
                "size": member.size,
                "analysis_incomplete": True,
                "scan_outcome_reason": TAR_SPECIAL_MEMBER_INCOMPLETE_REASON,
            },
        )

    def _scan_tar_file(self, path: str, depth: int = 0, *, raw_file: BinaryIO | None = None) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        contents: list[dict[str, Any]] = []
        scan_complete = True

        if depth >= self.max_depth:
            mark_archive_scan_incomplete(result, "tar_depth_limit")
            result.add_check(
                name="TAR Depth Bomb Protection",
                passed=False,
                message=f"Maximum TAR nesting depth ({self.max_depth}) exceeded",
                rule_code="S902",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "depth": depth,
                    "max_depth": self.max_depth,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "tar_depth_limit",
                },
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="TAR Depth Bomb Protection",
            passed=True,
            message="TAR nesting depth is within safe limits",
            location=path,
            details={"depth": depth, "max_depth": self.max_depth},
            rule_code=None,
        )

        if self._is_empty_tar_archive(path, raw_file=raw_file):
            result.add_check(
                name="Entry Count Limit Check",
                passed=True,
                message="Entry count (0) is within limits",
                location=path,
                details={"entries": 0, "max_entries": self.max_entries},
                rule_code=None,
            )
            self._add_tar_aggregate_size_check(
                result,
                path,
                passed=True,
                archive_uncompressed_size=0,
            )
            result.metadata["contents"] = contents
            result.finish(success=True)
            return result

        entry_count = 0
        archive_uncompressed_size = 0
        entry_count_check_recorded = False
        aggregate_size_check_recorded = False
        compressed_size = self._effective_source_size(path, raw_file)
        projected_compressed_size = compressed_size
        compression_codec: str | None = None
        bounded_stream: _TarBoundedStream | None = None
        shared_budget = self._get_or_create_shared_budget()
        stream_budget_failed = False
        reached_eof = False
        wrapper_integrity_failed = False
        symlink_targets: dict[str, str] = {}
        materialized_symlinks: dict[str, tarfile.TarInfo] = {}
        link_resolution_budget = [_NEMO_ROUTE_MAX_LINK_RESOLUTION_VISITS]

        try:
            compressed_size = self._effective_compressed_source_size(path, raw_file)
            projected_compressed_size = self._projected_compressed_source_size(path, raw_file)
            with self._open_tar_stream(path, raw_file=raw_file) as (tar, bounded_stream, compression_codec):
                security_only_nested_entries = self.config.get(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY)
                if not isinstance(security_only_nested_entries, set):
                    security_only_nested_entries = set()

                while True:
                    try:
                        member = tar.next()
                    except OSError as exc:
                        if (
                            not contents
                            and exc.errno == errno.EINVAL
                            and self._is_empty_tar_archive(
                                path,
                                raw_file=raw_file,
                            )
                        ):
                            break
                        scan_complete = False
                        self._record_incomplete_tar_scan(result, path, exc)
                        break
                    except _TarStreamBudgetExceeded as exc:
                        scan_complete = False
                        stream_budget_failed = True
                        self._record_tar_stream_budget_exceeded(
                            result,
                            path,
                            exc,
                            compression_codec=compression_codec,
                            compressed_size=projected_compressed_size,
                        )
                        break
                    except _TarCompressedPhysicalTrailingData:
                        scan_complete = False
                        wrapper_integrity_failed = True
                        self._record_compressed_tar_trailing_data(result, path)
                        break
                    except tarfile.TarError:
                        raise
                    except Exception as exc:
                        scan_complete = False
                        self._record_incomplete_tar_scan(result, path, exc)
                        break

                    if member is None:
                        if compression_codec is None:
                            try:
                                raw_end_marker_valid = self._raw_tar_has_complete_end_marker(tar)
                            except OSError as exc:
                                scan_complete = False
                                self._record_incomplete_tar_scan(result, path, exc)
                                break
                            if not raw_end_marker_valid:
                                scan_complete = False
                                self._record_incomplete_tar_scan(
                                    result,
                                    path,
                                    tarfile.ReadError(
                                        "Raw TAR traversal stopped without a two-block end marker "
                                        f"at offset {tar.offset}"
                                    ),
                                )
                                break
                        reached_eof = True
                        if (
                            compression_codec is not None
                            and bounded_stream is not None
                            and not self._drain_compressed_tar_tail(
                                tar,
                                bounded_stream,
                                result,
                                path,
                                compressed_size=compressed_size,
                                compression_codec=compression_codec,
                            )
                        ):
                            scan_complete = False
                            wrapper_integrity_failed = True
                        break

                    entry_count += 1
                    if entry_count > self.max_entries:
                        scan_complete = False
                        entry_count_check_recorded = True
                        result.add_check(
                            name="Entry Count Limit Check",
                            passed=False,
                            message=f"TAR file contains too many entries ({entry_count} > {self.max_entries})",
                            rule_code="S902",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "entries": entry_count,
                                "max_entries": self.max_entries,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": TAR_ENTRY_COUNT_INCOMPLETE_REASON,
                            },
                        )
                        mark_archive_scan_incomplete(result, TAR_ENTRY_COUNT_INCOMPLETE_REASON)
                        break

                    name = member.name
                    temp_base = os.path.join(tempfile.gettempdir(), "extract_tar")
                    resolved_name, is_safe = sanitize_archive_path(name, temp_base)
                    if not is_safe:
                        contents.append(self._member_inventory_entry(path, member, scan_status="rejected"))
                        result.add_check(
                            name="Path Traversal Protection",
                            passed=False,
                            message=f"Archive entry {name} attempted path traversal outside the archive",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}:{name}",
                            details={"entry": name},
                            rule_code="S405",
                        )
                        if member.size > 0:
                            archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                                result,
                                path,
                                member,
                                shared_budget,
                                archive_uncompressed_size,
                                work_size=max(member.size, tar.offset - member.offset_data),
                            )
                            if not budget_reserved:
                                scan_complete = False
                                aggregate_size_check_recorded = True
                                break

                            if self._record_projected_compressed_member_limit(
                                result,
                                path,
                                member,
                                bounded_stream,
                                compression_codec=compression_codec,
                                compressed_size=projected_compressed_size,
                            ):
                                scan_complete = False
                                stream_budget_failed = True
                                break
                        continue

                    if member.issym() or member.islnk():
                        target = member.linkname
                        link_kind = "Symlink" if member.issym() else "Hard link"
                        if target:
                            _target_resolved, target_safe = self._resolve_link_target(
                                target,
                                resolved_member_name=resolved_name,
                                extraction_root=temp_base,
                                is_symlink=member.issym(),
                            )
                        else:
                            target_safe = False
                        link_rejected = False
                        if not target_safe:
                            link_rejected = True
                            if is_absolute_archive_path(target) and is_critical_system_path(
                                target, CRITICAL_SYSTEM_PATHS
                            ):
                                message = f"{link_kind} {name} points to critical system path: {target}"
                            elif not target:
                                message = f"{link_kind} {name} has an empty target"
                            else:
                                message = f"{link_kind} {name} resolves outside extraction directory"
                            result.add_check(
                                name="Symlink Safety Validation",
                                passed=False,
                                message=message,
                                severity=IssueSeverity.CRITICAL,
                                location=f"{path}:{name}",
                                details={"target": target, "entry": name},
                                rule_code="S406",
                            )
                        elif is_absolute_archive_path(target) and is_critical_system_path(
                            target, CRITICAL_SYSTEM_PATHS
                        ):
                            link_rejected = True
                            result.add_check(
                                name="Symlink Safety Validation",
                                passed=False,
                                message=f"{link_kind} {name} points to critical system path: {target}",
                                severity=IssueSeverity.CRITICAL,
                                location=f"{path}:{name}",
                                details={"target": target, "entry": name},
                                rule_code="S406",
                            )
                        contents.append(
                            self._member_inventory_entry(
                                path,
                                member,
                                scan_status="rejected" if link_rejected else "link_validated",
                            )
                        )
                        if not link_rejected and member.issym():
                            try:
                                destination_name = _resolve_safe_tar_path_through_symlinks(
                                    member.name,
                                    symlink_targets,
                                    link_resolution_budget,
                                    follow_final_symlink=False,
                                )
                                target_name = (
                                    _resolve_safe_tar_symlink_target_at_destination(member, destination_name)
                                    if destination_name is not None
                                    else None
                                )
                            except _NemoRouteResolutionLimitExceeded:
                                destination_name = None
                                target_name = None
                            if destination_name is None or target_name is None:
                                scan_complete = False
                                self._record_nemo_link_resolution_incomplete(
                                    result,
                                    archive_path=path,
                                    entry_name=member.name,
                                    message="TAR symlink destinations exceeded bounded NeMo resolution",
                                )
                            else:
                                symlink_targets[destination_name] = target_name
                                materialized_symlinks[destination_name] = member
                        elif not link_rejected:
                            try:
                                destination_name = _resolve_safe_tar_path_through_symlinks(
                                    member.name,
                                    symlink_targets,
                                    link_resolution_budget,
                                    follow_final_symlink=False,
                                )
                                target_name = _resolve_safe_tar_link_target_name(member)
                                resolved_target_name = (
                                    _resolve_safe_tar_path_through_symlinks(
                                        target_name,
                                        symlink_targets,
                                        link_resolution_budget,
                                        follow_final_symlink=False,
                                    )
                                    if target_name is not None
                                    else None
                                )
                                target_symlink = (
                                    materialized_symlinks.get(resolved_target_name)
                                    if resolved_target_name is not None
                                    else None
                                )
                                redirected_target = (
                                    _resolve_safe_tar_symlink_target_at_destination(target_symlink, destination_name)
                                    if target_symlink is not None and destination_name is not None
                                    else None
                                )
                            except _NemoRouteResolutionLimitExceeded:
                                destination_name = None
                                resolved_target_name = None
                                target_symlink = None
                                redirected_target = None
                            if destination_name is None or resolved_target_name is None:
                                scan_complete = False
                                self._record_nemo_link_resolution_incomplete(
                                    result,
                                    archive_path=path,
                                    entry_name=member.name,
                                    message="TAR hardlink destinations exceeded bounded NeMo resolution",
                                )
                            elif target_symlink is not None:
                                if redirected_target is None:
                                    scan_complete = False
                                    self._record_nemo_link_resolution_incomplete(
                                        result,
                                        archive_path=path,
                                        entry_name=member.name,
                                        message="TAR hardlink destinations exceeded bounded NeMo resolution",
                                    )
                                else:
                                    symlink_targets[destination_name] = redirected_target
                                    materialized_symlinks[destination_name] = target_symlink
                        if not link_rejected and self._record_reachable_nemo_link_incomplete(
                            result,
                            archive_path=path,
                            member=member,
                            effective_name=destination_name,
                        ):
                            scan_complete = False
                        if member.size > 0:
                            scan_complete = False
                            self._record_unsupported_member_body(result, path, member)
                            archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                                result,
                                path,
                                member,
                                shared_budget,
                                archive_uncompressed_size,
                            )
                            if not budget_reserved:
                                aggregate_size_check_recorded = True
                            break
                        continue

                    if member.isdir():
                        contents.append(self._member_inventory_entry(path, member, scan_status="directory"))
                        if member.size > 0:
                            scan_complete = False
                            self._record_unsupported_member_body(result, path, member)
                            archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                                result,
                                path,
                                member,
                                shared_budget,
                                archive_uncompressed_size,
                            )
                            if not budget_reserved:
                                aggregate_size_check_recorded = True
                            break
                        continue

                    if self._member_declares_sparse_data(member):
                        scan_complete = False
                        self._record_unscannable_member(
                            result,
                            contents,
                            path,
                            member,
                            reason=TAR_SPARSE_MEMBER_INCOMPLETE_REASON,
                            message=f"TAR sparse entry {name} was not extracted; sparse member coverage is incomplete",
                        )
                        sparse_work_size = max(member.size, tar.offset - member.offset_data)
                        archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                            result,
                            path,
                            member,
                            shared_budget,
                            archive_uncompressed_size,
                            work_size=sparse_work_size,
                        )
                        if not budget_reserved:
                            aggregate_size_check_recorded = True
                            break
                        if self._record_projected_compressed_member_limit(
                            result,
                            path,
                            member,
                            bounded_stream,
                            compression_codec=compression_codec,
                            compressed_size=projected_compressed_size,
                        ):
                            stream_budget_failed = True
                            break
                        if compression_codec is not None:
                            break
                        continue

                    if not member.isfile():
                        scan_complete = False
                        self._record_unscannable_member(
                            result,
                            contents,
                            path,
                            member,
                            reason=TAR_SPECIAL_MEMBER_INCOMPLETE_REASON,
                            message=(
                                f"TAR special entry {name} has unsupported type {member.type!r}; "
                                "member coverage is incomplete"
                            ),
                        )
                        if member.size > 0:
                            archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                                result,
                                path,
                                member,
                                shared_budget,
                                archive_uncompressed_size,
                            )
                            if not budget_reserved:
                                aggregate_size_check_recorded = True

                            stream_budget_exceeded = self._record_projected_compressed_member_limit(
                                result,
                                path,
                                member,
                                bounded_stream,
                                compression_codec=compression_codec,
                                compressed_size=projected_compressed_size,
                            )
                            if stream_budget_exceeded:
                                stream_budget_failed = True
                            if aggregate_size_check_recorded or stream_budget_exceeded:
                                break
                        continue

                    archive_uncompressed_size, budget_reserved = self._reserve_member_work(
                        result,
                        path,
                        member,
                        shared_budget,
                        archive_uncompressed_size,
                    )
                    if not budget_reserved:
                        scan_complete = False
                        aggregate_size_check_recorded = True
                        contents.append(
                            self._member_inventory_entry(
                                path,
                                member,
                                scan_status="incomplete",
                                scan_outcome_reason=TAR_TOTAL_SIZE_INCOMPLETE_REASON,
                            )
                        )
                        break

                    if self._record_projected_compressed_member_limit(
                        result,
                        path,
                        member,
                        bounded_stream,
                        compression_codec=compression_codec,
                        compressed_size=projected_compressed_size,
                    ):
                        scan_complete = False
                        stream_budget_failed = True
                        contents.append(
                            self._member_inventory_entry(
                                path,
                                member,
                                scan_status="incomplete",
                                scan_outcome_reason="tar_analysis_incomplete",
                            )
                        )
                        break

                    try:
                        effective_member_name = _resolve_safe_tar_path_through_symlinks(
                            name,
                            symlink_targets,
                            link_resolution_budget,
                        )
                    except _NemoRouteResolutionLimitExceeded:
                        effective_member_name = None
                    if effective_member_name is None:
                        scan_complete = False
                        self._record_nemo_link_resolution_incomplete(
                            result,
                            archive_path=path,
                            entry_name=name,
                            message="TAR member destination exceeded bounded NeMo symlink resolution",
                        )

                    try:
                        name_lower = name.lower()
                        member_basename = os.path.basename(name.replace("\\", "/"))
                        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", member_basename) or "member"
                        tar_suffix = next(
                            (extension for extension in self.supported_extensions if name_lower.endswith(extension)),
                            None,
                        )
                        is_tar_extension = tar_suffix is not None
                        suffix = tar_suffix if tar_suffix is not None else f"_{safe_name}"
                        basename = safe_name if is_declared_text_content_filename(member_basename) else None

                        tmp_path, total_size = self._extract_member_to_tempfile(
                            tar,
                            member,
                            suffix=suffix,
                            basename=basename,
                        )
                        tmp_dir = os.path.dirname(tmp_path) if basename is not None else None
                        try:
                            if is_tar_extension and TarScanner.can_handle(tmp_path):
                                nested_config = dict(self.config)
                                nested_config.pop(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY, None)
                                nested_config.pop(TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY, None)
                                nested_config.pop(TAR_SOURCE_SIZE_LIMIT_CONFIG_KEY, None)
                                nested_config["cache_enabled"] = False
                                nested_config["_archive_depth"] = depth + 1
                                nested_result = self._scan_nested_archive_entry(tmp_path, nested_config)
                                if member_scan_incomplete(nested_result):
                                    scan_complete = False

                                self._rewrite_nested_result_context(nested_result, tmp_path, path, name)
                                result.merge_member_result(nested_result, name)
                                asset_entry = asset_from_scan_result(f"{path}:{name}", nested_result)
                            else:
                                scan_archive_member_for_known_risks(
                                    archive_kind="TAR",
                                    archive_path=path,
                                    member_name=name,
                                    tmp_path=tmp_path,
                                    total_size=total_size,
                                    result=result,
                                    max_python_analysis_bytes=MAX_TAR_PYTHON_ANALYSIS_BYTES,
                                    python_analysis_incomplete_reason="tar_python_member_analysis_incomplete",
                                    executable_analysis_incomplete_reason="tar_executable_member_analysis_incomplete",
                                )

                                if name in security_only_nested_entries:
                                    result.bytes_scanned += total_size
                                    asset_entry = {"path": f"{path}:{name}", "type": "nemo_managed"}
                                else:
                                    if not self._scan_reachable_nemo_config_member(
                                        archive_path=path,
                                        member_name=effective_member_name or name,
                                        member_size=member.size,
                                        tmp_path=tmp_path,
                                        result=result,
                                    ):
                                        scan_complete = False

                                    nested_config = dict(self.config)
                                    nested_config.pop(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY, None)
                                    nested_config.pop(TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY, None)
                                    nested_config.pop(TAR_SOURCE_SIZE_LIMIT_CONFIG_KEY, None)
                                    nested_config["cache_enabled"] = False
                                    nested_config["_archive_depth"] = depth + 1
                                    file_result = self._scan_nested_archive_entry(tmp_path, nested_config)
                                    self._rewrite_nested_result_context(file_result, tmp_path, path, name)
                                    if member_scan_incomplete(file_result):
                                        scan_complete = False

                                    result.merge_member_result(file_result, name)
                                    asset_entry = asset_from_scan_result(f"{path}:{name}", file_result)

                                    if file_result.scanner_name == "unknown":
                                        result.bytes_scanned += total_size

                            asset_entry.setdefault("size", member.size)
                            contents.append(asset_entry)
                        finally:
                            os.unlink(tmp_path)
                            if tmp_dir is not None:
                                with contextlib.suppress(OSError):
                                    os.rmdir(tmp_dir)
                    except _TarStreamBudgetExceeded as exc:
                        scan_complete = False
                        stream_budget_failed = True
                        self._record_tar_stream_budget_exceeded(
                            result,
                            path,
                            exc,
                            compression_codec=compression_codec,
                            compressed_size=projected_compressed_size,
                        )
                        break
                    except _TarEntryExtractionIncomplete as exc:
                        scan_complete = False
                        mark_archive_scan_incomplete(result, TAR_ENTRY_EXTRACTION_INCOMPLETE_REASON)
                        contents.append(
                            self._member_inventory_entry(
                                path,
                                member,
                                scan_status="incomplete",
                                scan_outcome_reason=TAR_ENTRY_EXTRACTION_INCOMPLETE_REASON,
                            )
                        )
                        result.add_check(
                            name="TAR Entry Scan",
                            passed=False,
                            message=f"Unable to fully inspect TAR entry {name}: {exc!s}",
                            severity=IssueSeverity.INFO,
                            rule_code="S902",
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "exception": str(exc),
                                "exception_type": type(exc).__name__,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": TAR_ENTRY_EXTRACTION_INCOMPLETE_REASON,
                            },
                        )
                        if compression_codec is not None:
                            break
                    except Exception as exc:
                        scan_complete = False
                        mark_archive_scan_incomplete(result, "tar_entry_scan_incomplete")
                        result.add_check(
                            name="TAR Entry Scan",
                            passed=False,
                            message=f"Error scanning TAR entry {name}: {exc!s}",
                            severity=IssueSeverity.INFO,
                            rule_code="S902",
                            location=f"{path}:{name}",
                            details={
                                "entry": name,
                                "exception": str(exc),
                                "exception_type": type(exc).__name__,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": "tar_entry_scan_incomplete",
                            },
                        )
        except _TarStreamBudgetExceeded as exc:
            scan_complete = False
            stream_budget_failed = True
            self._record_tar_stream_budget_exceeded(
                result,
                path,
                exc,
                compression_codec=compression_codec,
                compressed_size=projected_compressed_size,
            )
        except Exception as exc:
            if raw_file is None:
                raise
            scan_complete = False
            self._record_incomplete_tar_scan(result, path, exc)

        if reached_eof and not entry_count_check_recorded:
            result.add_check(
                name="Entry Count Limit Check",
                passed=True,
                message=f"Entry count ({entry_count}) is within limits",
                location=path,
                details={"entries": entry_count, "max_entries": self.max_entries},
                rule_code=None,
            )

        if reached_eof and not aggregate_size_check_recorded:
            self._add_tar_aggregate_size_check(
                result,
                path,
                passed=True,
                archive_uncompressed_size=archive_uncompressed_size,
            )

        if (
            reached_eof
            and compression_codec is not None
            and bounded_stream is not None
            and not stream_budget_failed
            and not wrapper_integrity_failed
        ):
            final_stream_size = bounded_stream.bytes_read
            if self._record_compressed_stream_limit(
                result,
                path,
                stream_size=final_stream_size,
                compressed_size=self._payload_compressed_size(bounded_stream, compressed_size),
                compression_codec=compression_codec,
                emit_pass=True,
            ):
                scan_complete = False

        result.metadata["contents"] = contents
        result.metadata["file_size"] = self._effective_source_size(path, raw_file)
        result.metadata["archive_uncompressed_size"] = archive_uncompressed_size
        result.metadata["max_tar_total_uncompressed_size"] = self._get_max_total_uncompressed_size()
        if not scan_complete:
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
        result.finish(success=scan_complete and not member_scan_incomplete(result) and not result.has_errors)
        return result


def classify_raw_tar_prefix_ownership(
    path: str,
    boundary: int,
    *,
    config: dict[str, Any] | None = None,
) -> TarPrefixOwnership:
    """Classify whether a bounded raw source prefix owns a complete TAR archive."""
    if boundary < 2 * tarfile.BLOCKSIZE or boundary % tarfile.BLOCKSIZE:
        return "incomplete"

    scanner_config = dict(config or {})
    scanner_config[TAR_SOURCE_SIZE_LIMIT_CONFIG_KEY] = boundary
    scanner = TarScanner(config=scanner_config)
    try:
        with (
            open(path, "rb") as raw_file,
            scanner._open_tar_stream(path, raw_file=raw_file) as (
                archive,
                bounded_stream,
                compression_codec,
            ),
        ):
            if compression_codec is not None or bounded_stream is not None:
                return "incomplete"
            entry_count = 0
            while True:
                member = archive.next()
                if member is None:
                    if scanner._raw_tar_has_complete_end_marker(archive):
                        return "complete"
                    return "scan_limit" if scanner._raw_tar_end_marker_scan_limit_exceeded else "incomplete"
                entry_count += 1
                if entry_count > scanner.max_entries:
                    return "scan_limit"
                padded_member_end = (
                    member.offset_data
                    + ((max(member.size, 0) + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
                )
                if padded_member_end > boundary:
                    return "embedded_member"
    except _TarStreamBudgetExceeded:
        return "scan_limit"
    except (EOFError, OSError, tarfile.TarError, ValueError):
        return "inconclusive"


def classify_compressed_tar_prefix_ownership(
    path: str,
    boundary: int,
    *,
    config: dict[str, Any] | None = None,
) -> TarPrefixOwnership:
    """Prove a compressed TAR wrapper completes within its physical owner prefix."""
    if boundary <= 0:
        return "incomplete"

    scanner_config = dict(config or {})
    scanner_config[TAR_SOURCE_SIZE_LIMIT_CONFIG_KEY] = boundary
    # Ownership proof is structural; the actual supplemental scan enforces the
    # caller's ratio policy after ownership is established.
    scanner_config["compressed_max_decompression_ratio"] = 1e300
    scanner = TarScanner(config=scanner_config)
    result = ScanResult(scanner_name="tar")
    try:
        with open(path, "rb") as raw_file:
            if scanner._preflight_tar_archive(path, result, retain_member_budget=False, raw_file=raw_file):
                return "complete"
            reasons = set(result.metadata.get("scan_outcome_reasons", []))
            return "scan_limit" if reasons & _TAR_OWNERSHIP_SCAN_LIMIT_REASONS else "incomplete"
    except (EOFError, OSError, tarfile.TarError, ValueError):
        return "inconclusive"
