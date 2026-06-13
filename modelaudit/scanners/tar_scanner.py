"""Scanner for tar-archived model files (.tar, .tar.gz, .tgz)."""

from __future__ import annotations

import bz2
import contextlib
import errno
import gzip
import lzma
import os
import re
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any, BinaryIO, ClassVar, cast

from ..utils import is_absolute_archive_path, is_critical_system_path, sanitize_archive_path
from ..utils.file.detection import (
    _NEMO_ROUTE_MAX_LINK_RESOLUTION_VISITS,
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
ARCHIVE_MEMBER_COPY_CHUNK_BYTES = 64 * 1024
MAX_TAR_PYTHON_ANALYSIS_BYTES = 10 * 1024 * 1024
TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY = "_tar_security_only_nested_member_entries"
TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY = "_tar_skip_reachable_nemo_config_scan"
TAR_SHARED_SCAN_BUDGET_CONFIG_KEY = "_tar_shared_scan_budget"
TAR_ENTRY_EXTRACTION_INCOMPLETE_REASON = "tar_entry_extraction_incomplete"
TAR_TOTAL_SIZE_INCOMPLETE_REASON = "tar_total_size_limit_exceeded"
TAR_SPECIAL_MEMBER_INCOMPLETE_REASON = "tar_special_member_unsupported"
TAR_SPARSE_MEMBER_INCOMPLETE_REASON = "tar_sparse_member_unsupported"
TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON = "tar_compressed_trailing_data"
TAR_SPARSE_PAX_SIZE_FIELDS = frozenset({"GNU.sparse.size", "GNU.sparse.realsize"})

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


@dataclass
class _TarSharedScanBudget:
    max_total_uncompressed_size: int
    member_bytes_consumed: int = 0


class _TarBoundedStream:
    """Read wrapper that bounds TAR stream work before tarfile materializes metadata."""

    def __init__(self, fileobj: Any, *, max_bytes: int, max_read_size: int) -> None:
        self._fileobj = fileobj
        self.max_bytes = max_bytes
        self.max_read_size = max_read_size
        self.bytes_read = 0

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
                reason="tar_decompressed_size_limit_exceeded",
            )
        return data


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
        self.max_metadata_bytes = self._normalize_positive_int_config(
            self.config.get("max_tar_metadata_bytes"),
            DEFAULT_MAX_TAR_METADATA_BYTES,
        )

    @staticmethod
    def _normalize_positive_float_config(value: Any, default: float) -> float:
        """Return a positive float config value, or default for invalid input."""
        if isinstance(value, bool):
            return default
        try:
            normalized_value = float(value)
        except (TypeError, ValueError):
            return default
        return normalized_value if normalized_value > 0 else default

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

            owns_shared_budget = TAR_SHARED_SCAN_BUDGET_CONFIG_KEY not in self.config
            if owns_shared_budget:
                self.config[TAR_SHARED_SCAN_BUDGET_CONFIG_KEY] = _TarSharedScanBudget(
                    max_total_uncompressed_size=self._get_max_total_uncompressed_size()
                )
            try:
                scan_result = self._scan_tar_file(path, depth=max(archive_depth, 0))
            finally:
                if owns_shared_budget:
                    self.config.pop(TAR_SHARED_SCAN_BUDGET_CONFIG_KEY, None)
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
    def _open_tar_stream(self, path: str) -> Iterator[tuple[tarfile.TarFile, _TarBoundedStream | None, str | None]]:
        """Open a TAR stream through a bounded decompressed-byte reader."""
        compression_codec = self._detect_compressed_tar_wrapper(path)
        with open(path, "rb") as raw, ExitStack() as stack:
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

            if compression_codec == "gzip":
                decompressed: Any = stack.enter_context(gzip.GzipFile(fileobj=raw, mode="rb"))
            elif compression_codec == "bzip2":
                decompressed = stack.enter_context(bz2.BZ2File(raw, mode="rb"))
            elif compression_codec == "xz":
                decompressed = stack.enter_context(lzma.LZMAFile(raw, mode="rb"))
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
        except (EOFError, OSError, lzma.LZMAError):
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
    def _is_empty_tar_archive(path: str) -> bool:
        """Detect standard empty TAR archives that some Python 3.10 builds reject on ``next()``."""
        max_read_size = 10 * 1024 * 1024
        try:
            file_size = os.path.getsize(path)
            if file_size < 2 * tarfile.BLOCKSIZE or file_size % tarfile.BLOCKSIZE != 0:
                return False
            if file_size > max_read_size:
                return False

            with open(path, "rb") as file_obj:
                first_block = file_obj.read(tarfile.BLOCKSIZE)
                if first_block != b"\0" * tarfile.BLOCKSIZE:
                    return False
                return all(not any(chunk) for chunk in iter(lambda: file_obj.read(64 * 1024), b""))
        except OSError:
            return False

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
        projected_total = shared_budget.member_bytes_consumed + member_size
        if (
            shared_budget.max_total_uncompressed_size > 0
            and projected_total > shared_budget.max_total_uncompressed_size
        ):
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
            compressed_size=compressed_size,
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
            message = f"Decompressed size exceeded limit ({stream_size} > {self.max_decompressed_bytes})"
        elif compressed_size > 0 and actual_ratio > self.max_decompression_ratio:
            passed = False
            message = f"Decompression ratio exceeded limit ({actual_ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
        elif emit_pass:
            passed = True
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
        )
        if not passed:
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
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
        if compression_codec is not None and exc.reason == "tar_decompressed_size_limit_exceeded":
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
    def _drain_compressed_tar_tail(
        tar: tarfile.TarFile,
        bounded_stream: _TarBoundedStream,
        result: ScanResult,
        path: str,
    ) -> bool:
        """Consume the complete wrapper stream and reject data after the TAR end marker."""
        has_nonzero_trailing_data = False
        read_size = min(ARCHIVE_MEMBER_COPY_CHUNK_BYTES, bounded_stream.max_read_size)
        # Header traversal uses one-block buffering to avoid prefetching member bodies
        # before policy checks. Once TAR EOF is proven, larger reads are safe.
        cast(Any, tar.fileobj).bufsize = read_size
        try:
            while chunk := tar.fileobj.read(read_size):
                has_nonzero_trailing_data = has_nonzero_trailing_data or any(chunk)
        except _TarStreamBudgetExceeded:
            raise
        except Exception as exc:
            TarScanner._record_incomplete_tar_scan(result, path, exc)
            return False

        if not has_nonzero_trailing_data:
            return True

        mark_archive_scan_incomplete(result, TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON)
        result.add_check(
            name="Compressed TAR Trailing Data",
            passed=False,
            message="Compressed wrapper contains non-zero data after the TAR end marker",
            severity=IssueSeverity.WARNING,
            rule_code="S902",
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": TAR_COMPRESSED_TRAILING_DATA_INCOMPLETE_REASON,
            },
        )
        return False

    def _preflight_tar_archive(
        self,
        path: str,
        result: ScanResult,
        *,
        reserve_member_budget: bool = False,
    ) -> bool:
        """Stream TAR headers once to enforce wrapper and optional aggregate limits."""
        entry_count = 0
        compressed_size = os.path.getsize(path)
        compression_codec: str | None = None
        consumed_size = 0
        archive_uncompressed_size = 0
        shared_budget = self._get_or_create_shared_budget() if reserve_member_budget else None

        try:
            with self._open_tar_stream(path) as (tar, bounded_stream, compression_codec):
                while True:
                    try:
                        member = tar.next()
                    except OSError as exc:
                        if entry_count == 0 and exc.errno == errno.EINVAL and self._is_empty_tar_archive(path):
                            break
                        raise

                    if member is None:
                        if (
                            compression_codec is not None
                            and bounded_stream is not None
                            and not self._drain_compressed_tar_tail(tar, bounded_stream, result, path)
                        ):
                            return False
                        break

                    entry_count += 1
                    if entry_count > self.max_entries:
                        result.add_check(
                            name="Entry Count Limit Check",
                            passed=False,
                            message=f"TAR file contains too many entries ({entry_count} > {self.max_entries})",
                            rule_code="S902",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"entries": entry_count, "max_entries": self.max_entries},
                        )
                        return False

                    if shared_budget is not None and member.size > 0:
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
                            compressed_size=compressed_size,
                        ):
                            return False
                        consumed_size = max(consumed_size, bounded_stream.bytes_read)
                        estimated_stream_size = self._finalize_tar_stream_size(consumed_size)
                        if self._record_compressed_stream_limit(
                            result,
                            path,
                            stream_size=estimated_stream_size,
                            compressed_size=compressed_size,
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
            if shared_budget is not None:
                self._add_tar_aggregate_size_check(
                    result,
                    path,
                    passed=True,
                    archive_uncompressed_size=archive_uncompressed_size,
                )

            if compression_codec is not None:
                final_stream_size = consumed_size
                if self._record_compressed_stream_limit(
                    result,
                    path=path,
                    stream_size=final_stream_size,
                    compressed_size=compressed_size,
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
                compressed_size=compressed_size,
            )
            return False
        except (EOFError, OSError, tarfile.TarError, lzma.LZMAError) as exc:
            self._record_incomplete_tar_scan(result, path, exc)
            return False

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

    def _scan_tar_file(self, path: str, depth: int = 0) -> ScanResult:
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

        if self._is_empty_tar_archive(path):
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
        compressed_size = os.path.getsize(path)
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
            with self._open_tar_stream(path) as (tar, bounded_stream, compression_codec):
                security_only_nested_entries = self.config.get(TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY)
                if not isinstance(security_only_nested_entries, set):
                    security_only_nested_entries = set()

                while True:
                    try:
                        member = tar.next()
                    except OSError as exc:
                        if not contents and exc.errno == errno.EINVAL and self._is_empty_tar_archive(path):
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
                            compressed_size=compressed_size,
                        )
                        break
                    except tarfile.TarError:
                        raise
                    except Exception as exc:
                        scan_complete = False
                        self._record_incomplete_tar_scan(result, path, exc)
                        break

                    if member is None:
                        reached_eof = True
                        if (
                            compression_codec is not None
                            and bounded_stream is not None
                            and not self._drain_compressed_tar_tail(tar, bounded_stream, result, path)
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
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"entries": entry_count, "max_entries": self.max_entries},
                        )
                        mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
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
                                compressed_size=compressed_size,
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
                            compressed_size=compressed_size,
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
                                compressed_size=compressed_size,
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
                        compressed_size=compressed_size,
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
                            compressed_size=compressed_size,
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
                compressed_size=compressed_size,
            )

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
                compressed_size=compressed_size,
                compression_codec=compression_codec,
                emit_pass=True,
            ):
                scan_complete = False

        result.metadata["contents"] = contents
        result.metadata["file_size"] = os.path.getsize(path)
        result.metadata["archive_uncompressed_size"] = archive_uncompressed_size
        result.metadata["max_tar_total_uncompressed_size"] = self._get_max_total_uncompressed_size()
        if not scan_complete:
            mark_archive_scan_incomplete(result, "tar_analysis_incomplete")
        result.finish(success=scan_complete and not member_scan_incomplete(result) and not result.has_errors)
        return result
