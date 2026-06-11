"""Scanner for standalone compressed wrapper artifacts (.gz, .bz2, .xz, .lz4, .zlib)."""

from __future__ import annotations

import bz2
import importlib
import lzma
import os
import tempfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from .. import core
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..utils.file._compression import is_zlib_header
from ._archive_config import get_archive_depth
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import member_scan_incomplete
from .archive_member_security import scan_archive_member_for_known_risks
from .base import BaseScanner, IssueSeverity, ScanResult

ALLOW_SAFETENSORS_NONMEMBER_TRAILING_CONFIG_KEY = "_compressed_allow_safetensors_nonmember_trailing"


class _DecompressionLimitExceeded(ValueError):
    """Raised when decompression policies are exceeded."""


class _CompressedMemberLimitExceeded(_DecompressionLimitExceeded):
    """Raised when concatenated-member fan-out exceeds the scan budget."""


class _CorruptStreamError(ValueError):
    """Raised when compressed streams cannot be decoded safely."""


class _MissingOptionalDependencyError(ImportError):
    """Raised when an optional dependency is unavailable."""


class _DecompressedOutputSink:
    """Write aggregate and per-member decompressed payloads to temp files."""

    def __init__(self, suffix: str, max_members: int):
        aggregate_fd, self.aggregate_path = tempfile.mkstemp(suffix=suffix)
        self.aggregate_file = os.fdopen(aggregate_fd, "w+b")
        self.member_paths: list[str] = []
        self.max_members = max_members
        self.current_member_file = self._open_member_file(suffix)

    def _open_member_file(self, suffix: str) -> Any:
        next_member_count = len(self.member_paths) + 1
        if next_member_count > self.max_members:
            raise _CompressedMemberLimitExceeded(
                f"Compressed member count exceeded limit ({next_member_count} > {self.max_members})",
            )
        member_fd, member_path = tempfile.mkstemp(suffix=suffix)
        self.member_paths.append(member_path)
        return os.fdopen(member_fd, "w+b")

    def write(self, output: bytes) -> int:
        self.aggregate_file.write(output)
        return self.current_member_file.write(output)

    def start_new_member(self, suffix: str) -> None:
        self.current_member_file.close()
        self.current_member_file = self._open_member_file(suffix)

    def close(self) -> None:
        self.current_member_file.close()
        self.aggregate_file.close()

    def cleanup(self) -> None:
        self.close()
        for temp_path in [self.aggregate_path, *self.member_paths]:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class CompressedScanner(BaseScanner):
    """Safely decompress standalone wrappers and scan the resulting payload."""

    name = "compressed"
    description = "Scans standalone compressed wrappers and routes inner payloads to existing scanners"
    supported_extensions: ClassVar[list[str]] = [".gz", ".bz2", ".xz", ".lz4", ".zlib"]

    _EXTENSION_TO_CODEC: ClassVar[dict[str, str]] = {
        ".gz": "gzip",
        ".bz2": "bzip2",
        ".xz": "xz",
        ".lz4": "lz4",
        ".zlib": "zlib",
    }

    _CODEC_MAGIC_PREFIXES: ClassVar[dict[str, bytes]] = {
        "gzip": b"\x1f\x8b",
        "bzip2": b"BZh",
        "xz": b"\xfd7zXZ\x00",
        "lz4": b"\x04\x22\x4d\x18",
    }

    DEFAULT_MAX_DECOMPRESSED_BYTES: ClassVar[int] = 512 * 1024 * 1024
    DEFAULT_MAX_DECOMPRESSION_RATIO: ClassVar[float] = 250.0
    DEFAULT_MAX_DEPTH: ClassVar[int] = 3
    DEFAULT_MAX_MEMBERS: ClassVar[int] = 1000
    DEFAULT_CHUNK_SIZE: ClassVar[int] = 64 * 1024
    MAX_PYTHON_PAYLOAD_ANALYSIS_BYTES: ClassVar[int] = 10 * 1024 * 1024
    _DEPTH_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_depth_limit_exceeded"
    _MEMBER_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_member_limit_exceeded"
    _DECOMPRESSION_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_decompression_limit_exceeded"
    _OPTIONAL_DEPENDENCY_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_optional_dependency_unavailable"
    _STREAM_DECODE_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_stream_decode_failed"
    _PYTHON_PAYLOAD_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_python_payload_analysis_incomplete"
    _EXECUTABLE_PAYLOAD_INCONCLUSIVE_REASON: ClassVar[str] = "compressed_executable_payload_analysis_incomplete"
    _LOGICAL_WRAPPER_NAME_CONFIG: ClassVar[str] = "_compressed_logical_wrapper_name"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_decompressed_bytes = int(
            self.config.get("compressed_max_decompressed_bytes", self.DEFAULT_MAX_DECOMPRESSED_BYTES),
        )
        self.max_decompression_ratio = float(
            self.config.get("compressed_max_decompression_ratio", self.DEFAULT_MAX_DECOMPRESSION_RATIO),
        )
        self.max_depth = int(self.config.get("compressed_max_depth", self.DEFAULT_MAX_DEPTH))
        self.max_members = self._normalize_positive_int_config(
            self.config.get("compressed_max_members"),
            self.DEFAULT_MAX_MEMBERS,
        )
        self.chunk_size = int(self.config.get("compressed_chunk_size", self.DEFAULT_CHUNK_SIZE))

    @classmethod
    def _expected_codec_for_path(cls, path: str) -> str | None:
        extension = Path(path).suffix.lower()
        return cls._EXTENSION_TO_CODEC.get(extension)

    @classmethod
    def _has_declared_wrapper_extension(cls, path: str) -> bool:
        return Path(path).suffix.lower() in cls._EXTENSION_TO_CODEC

    @classmethod
    def _detect_codec_from_header(cls, header: bytes) -> str | None:
        if header.startswith(cls._CODEC_MAGIC_PREFIXES["gzip"]):
            return "gzip"
        if header.startswith(cls._CODEC_MAGIC_PREFIXES["bzip2"]):
            return "bzip2"
        if header.startswith(cls._CODEC_MAGIC_PREFIXES["xz"]):
            return "xz"
        if header.startswith(cls._CODEC_MAGIC_PREFIXES["lz4"]):
            return "lz4"
        if is_zlib_header(header[:2]):
            return "zlib"
        return None

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        try:
            with open(path, "rb") as handle:
                header = handle.read(8)
        except OSError:
            return False

        detected_codec = cls._detect_codec_from_header(header)
        expected_codec = cls._expected_codec_for_path(path)
        if expected_codec is None:
            return detected_codec is not None
        return detected_codec == expected_codec

    @staticmethod
    def _derive_inner_suffix(path: str) -> str:
        wrapper_path = Path(path)
        if not CompressedScanner._has_declared_wrapper_extension(path):
            return wrapper_path.suffix or ".bin"

        stem_without_wrapper = (
            wrapper_path.name[: -len(wrapper_path.suffix)] if wrapper_path.suffix else wrapper_path.name
        )
        inferred_suffix = Path(stem_without_wrapper).suffix
        return inferred_suffix or ".bin"

    @staticmethod
    def _derive_inner_display_name(path: str) -> str:
        wrapper_path = Path(path)
        if wrapper_path.suffix and CompressedScanner._has_declared_wrapper_extension(path):
            return wrapper_path.name[: -len(wrapper_path.suffix)]
        return f"{wrapper_path.name}.inner"

    @staticmethod
    def _derive_inner_security_name(path: str) -> str:
        wrapper_path = Path(path)
        if wrapper_path.suffix and CompressedScanner._has_declared_wrapper_extension(path):
            return wrapper_path.name[: -len(wrapper_path.suffix)]
        return wrapper_path.name

    @staticmethod
    def _copy_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
    ) -> int:
        total_out = 0
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break

            total_out += len(chunk)
            if total_out > max_decompressed_bytes:
                raise _DecompressionLimitExceeded(
                    f"Decompressed size exceeded limit ({total_out} > {max_decompressed_bytes})",
                )

            if compressed_size > 0 and (total_out / compressed_size) > max_ratio:
                raise _DecompressionLimitExceeded(
                    f"Decompression ratio exceeded limit ({total_out / compressed_size:.1f}x > {max_ratio:.1f}x)",
                )

            destination.write(chunk)

        return total_out

    @staticmethod
    def _write_decompressed_output_with_limits(
        output: bytes,
        destination: Any,
        total_out: int,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
    ) -> int:
        if not output:
            return total_out

        total_out += len(output)
        if total_out > max_decompressed_bytes:
            raise _DecompressionLimitExceeded(
                f"Decompressed size exceeded limit ({total_out} > {max_decompressed_bytes})",
            )
        if compressed_size > 0 and (total_out / compressed_size) > max_ratio:
            raise _DecompressionLimitExceeded(
                f"Decompression ratio exceeded limit ({total_out / compressed_size:.1f}x > {max_ratio:.1f}x)",
            )

        destination.write(output)
        return total_out

    @staticmethod
    def _remaining_decompressed_budget(total_out: int, max_decompressed_bytes: int) -> int:
        return max(max_decompressed_bytes - total_out, 0)

    @staticmethod
    def _probe_limit(total_out: int, max_decompressed_bytes: int, chunk_size: int) -> int:
        remaining_budget = CompressedScanner._remaining_decompressed_budget(total_out, max_decompressed_bytes)
        budget_probe = remaining_budget + 1 if remaining_budget > 0 else 1
        return min(budget_probe, max(chunk_size, 1))

    @staticmethod
    def _read_concatenated_stream_with_limits(
        source: Any,
        destination: Any,
        decompressor_factory: Callable[[], Any],
        error_types: tuple[type[BaseException], ...],
        codec: str,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
        allow_nonmember_trailing: bool = False,
    ) -> int:
        decompressor = decompressor_factory()
        total_out = 0
        ignored_nonmember_trailing = False

        def should_ignore_proven_nonmember_trailing(pending: bytes) -> bool:
            return bool(pending) and allow_nonmember_trailing and codec == "gzip"

        def _consume_pending(pending: bytes) -> None:
            nonlocal decompressor, ignored_nonmember_trailing, total_out
            while pending or not getattr(decompressor, "needs_input", True):
                if getattr(decompressor, "eof", False):
                    if not pending:
                        break
                    if should_ignore_proven_nonmember_trailing(pending):
                        ignored_nonmember_trailing = True
                        return
                    if on_new_member is not None:
                        on_new_member()
                    decompressor = decompressor_factory()

                try:
                    output = decompressor.decompress(
                        pending,
                        max_length=CompressedScanner._probe_limit(total_out, max_decompressed_bytes, chunk_size),
                    )
                except error_types as exc:
                    raise _CorruptStreamError(f"Invalid {codec} stream: {exc}") from exc

                pending = b""
                total_out = CompressedScanner._write_decompressed_output_with_limits(
                    output=output,
                    destination=destination,
                    total_out=total_out,
                    max_decompressed_bytes=max_decompressed_bytes,
                    max_ratio=max_ratio,
                    compressed_size=compressed_size,
                )

                unconsumed_tail = getattr(decompressor, "unconsumed_tail", b"")
                if unconsumed_tail:
                    pending = unconsumed_tail
                    continue

                unused_data = getattr(decompressor, "unused_data", b"")
                if unused_data:
                    if should_ignore_proven_nonmember_trailing(unused_data):
                        ignored_nonmember_trailing = True
                        return
                    pending = unused_data
                    if on_new_member is not None:
                        on_new_member()
                    decompressor = decompressor_factory()

        while True:
            pending = source.read(chunk_size)
            if not pending:
                break
            _consume_pending(pending)
            if ignored_nonmember_trailing:
                break

        _consume_pending(b"")

        if ignored_nonmember_trailing:
            return total_out

        if not getattr(decompressor, "eof", False):
            raise _CorruptStreamError(f"Invalid {codec} stream: missing end-of-stream marker")

        return total_out

    @staticmethod
    def _read_bzip2_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
    ) -> int:
        return CompressedScanner._read_concatenated_stream_with_limits(
            source=source,
            destination=destination,
            decompressor_factory=bz2.BZ2Decompressor,
            error_types=(OSError, EOFError),
            codec="bzip2",
            max_decompressed_bytes=max_decompressed_bytes,
            max_ratio=max_ratio,
            compressed_size=compressed_size,
            chunk_size=chunk_size,
            on_new_member=on_new_member,
        )

    @staticmethod
    def _read_xz_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
    ) -> int:
        return CompressedScanner._read_concatenated_stream_with_limits(
            source=source,
            destination=destination,
            decompressor_factory=lambda: lzma.LZMADecompressor(format=lzma.FORMAT_AUTO),
            error_types=(lzma.LZMAError, EOFError),
            codec="xz",
            max_decompressed_bytes=max_decompressed_bytes,
            max_ratio=max_ratio,
            compressed_size=compressed_size,
            chunk_size=chunk_size,
            on_new_member=on_new_member,
        )

    @staticmethod
    def _read_gzip_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
        allow_nonmember_trailing: bool = False,
    ) -> int:
        return CompressedScanner._read_concatenated_stream_with_limits(
            source=source,
            destination=destination,
            decompressor_factory=lambda: zlib.decompressobj(16 + zlib.MAX_WBITS),
            error_types=(zlib.error,),
            codec="gzip",
            max_decompressed_bytes=max_decompressed_bytes,
            max_ratio=max_ratio,
            compressed_size=compressed_size,
            chunk_size=chunk_size,
            on_new_member=on_new_member,
            allow_nonmember_trailing=allow_nonmember_trailing,
        )

    @staticmethod
    def _read_zlib_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
    ) -> int:
        decompressor = zlib.decompressobj()
        total_out = 0

        def _write_decompressed_output(output: bytes) -> None:
            nonlocal total_out
            total_out = CompressedScanner._write_decompressed_output_with_limits(
                output=output,
                destination=destination,
                total_out=total_out,
                max_decompressed_bytes=max_decompressed_bytes,
                max_ratio=max_ratio,
                compressed_size=compressed_size,
            )

        def _probe_limit() -> int:
            return CompressedScanner._probe_limit(total_out, max_decompressed_bytes, chunk_size)

        while True:
            pending = source.read(chunk_size)
            if not pending:
                break

            while pending:
                try:
                    out = decompressor.decompress(pending, max_length=_probe_limit())
                except zlib.error as exc:
                    raise _CorruptStreamError(f"Invalid zlib stream: {exc}") from exc

                _write_decompressed_output(out)

                if decompressor.unconsumed_tail:
                    pending = decompressor.unconsumed_tail
                    continue

                if decompressor.eof and decompressor.unused_data:
                    # Support concatenated zlib members while rejecting raw
                    # trailer bytes that could hide an unscanned payload.
                    pending = decompressor.unused_data
                    if on_new_member is not None:
                        on_new_member()
                    decompressor = zlib.decompressobj()
                    continue

                pending = b""

        try:
            final = decompressor.flush(_probe_limit())
        except zlib.error as exc:
            raise _CorruptStreamError(f"Invalid zlib stream flush: {exc}") from exc

        _write_decompressed_output(final)

        if not decompressor.eof:
            raise _CorruptStreamError("Invalid zlib stream: missing end-of-stream marker")

        if decompressor.unused_data:
            raise _CorruptStreamError("Invalid zlib stream: unexpected trailing bytes after compressed payload")

        return total_out

    @staticmethod
    def _get_lz4_frame_module() -> Any:
        try:
            return importlib.import_module("lz4.frame")
        except Exception as exc:
            raise _MissingOptionalDependencyError("Optional dependency 'lz4' is not installed") from exc

    @staticmethod
    def _lz4_error_types(lz4_frame: Any) -> tuple[type[BaseException], ...]:
        error_types: list[type[BaseException]] = [OSError, EOFError, RuntimeError]
        frame_error = getattr(lz4_frame, "LZ4FrameError", None)
        if isinstance(frame_error, type) and issubclass(frame_error, BaseException):
            error_types.append(frame_error)
        return tuple(error_types)

    @staticmethod
    def _read_lz4_stream_with_limits(
        source: Any,
        destination: Any,
        lz4_frame: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
    ) -> int:
        try:
            decompressor_factory = lz4_frame.LZ4FrameDecompressor
        except AttributeError:
            return CompressedScanner._read_lz4_chunk_stream_with_limits(
                source=source,
                destination=destination,
                lz4_frame=lz4_frame,
                max_decompressed_bytes=max_decompressed_bytes,
                max_ratio=max_ratio,
                compressed_size=compressed_size,
                chunk_size=chunk_size,
                on_new_member=on_new_member,
            )

        return CompressedScanner._read_concatenated_stream_with_limits(
            source=source,
            destination=destination,
            decompressor_factory=decompressor_factory,
            error_types=CompressedScanner._lz4_error_types(lz4_frame),
            codec="lz4",
            max_decompressed_bytes=max_decompressed_bytes,
            max_ratio=max_ratio,
            compressed_size=compressed_size,
            chunk_size=chunk_size,
            on_new_member=on_new_member,
        )

    @staticmethod
    def _read_lz4_chunk_stream_with_limits(
        source: Any,
        destination: Any,
        lz4_frame: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
        on_new_member: Callable[[], None] | None = None,
    ) -> int:
        create_context = getattr(lz4_frame, "create_decompression_context", None)
        decompress_chunk = getattr(lz4_frame, "decompress_chunk", None)
        if not callable(create_context) or not callable(decompress_chunk):
            raise _CorruptStreamError("Invalid lz4 stream: lz4.frame lacks supported incremental decompression APIs")

        context = create_context()
        error_types = CompressedScanner._lz4_error_types(lz4_frame)
        total_out = 0
        frame_eof = False
        pending = b""
        probe_buffered_output = False

        while True:
            if not pending and not probe_buffered_output:
                pending = source.read(chunk_size)
                if not pending:
                    break

                if frame_eof:
                    if on_new_member is not None:
                        on_new_member()
                    context = create_context()
                    frame_eof = False

            max_length = CompressedScanner._probe_limit(total_out, max_decompressed_bytes, chunk_size)
            try:
                output, bytes_read, frame_eof = decompress_chunk(
                    context,
                    pending,
                    max_length=max_length,
                )
            except error_types as exc:
                raise _CorruptStreamError(f"Invalid lz4 stream: {exc}") from exc

            if not isinstance(bytes_read, int) or bytes_read < 0 or bytes_read > len(pending):
                raise _CorruptStreamError("Invalid lz4 stream: decompressor reported invalid consumed byte count")

            total_out = CompressedScanner._write_decompressed_output_with_limits(
                output=output,
                destination=destination,
                total_out=total_out,
                max_decompressed_bytes=max_decompressed_bytes,
                max_ratio=max_ratio,
                compressed_size=compressed_size,
            )

            pending = pending[bytes_read:]
            if frame_eof:
                if pending:
                    if on_new_member is not None:
                        on_new_member()
                    context = create_context()
                    frame_eof = False
                probe_buffered_output = False
                continue

            if pending and bytes_read == 0 and not output:
                next_chunk = source.read(chunk_size)
                if not next_chunk:
                    break
                pending += next_chunk
                continue

            probe_buffered_output = not pending and bool(output) and len(output) >= max_length
            if pending or probe_buffered_output:
                continue

        if not frame_eof:
            raise _CorruptStreamError("Invalid lz4 stream: missing end-of-stream marker")

        return total_out

    def _decompress_to_tempfiles(self, path: str, codec: str) -> tuple[str, list[str], int]:
        compressed_size = self.get_file_size(path)
        suffix = self._derive_inner_suffix(path)
        outputs = _DecompressedOutputSink(suffix, self.max_members)
        try:
            with open(path, "rb") as source:
                if codec == "gzip":
                    total_out = self._read_gzip_stream_with_limits(
                        source=source,
                        destination=outputs,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                        on_new_member=lambda: outputs.start_new_member(suffix),
                        allow_nonmember_trailing=bool(self.config.get(ALLOW_SAFETENSORS_NONMEMBER_TRAILING_CONFIG_KEY)),
                    )
                elif codec == "bzip2":
                    total_out = self._read_bzip2_stream_with_limits(
                        source=source,
                        destination=outputs,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                        on_new_member=lambda: outputs.start_new_member(suffix),
                    )
                elif codec == "xz":
                    total_out = self._read_xz_stream_with_limits(
                        source=source,
                        destination=outputs,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                        on_new_member=lambda: outputs.start_new_member(suffix),
                    )
                elif codec == "lz4":
                    lz4_frame = self._get_lz4_frame_module()
                    total_out = self._read_lz4_stream_with_limits(
                        source=source,
                        destination=outputs,
                        lz4_frame=lz4_frame,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                        on_new_member=lambda: outputs.start_new_member(suffix),
                    )
                elif codec == "zlib":
                    total_out = self._read_zlib_stream_with_limits(
                        source=source,
                        destination=outputs,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                        on_new_member=lambda: outputs.start_new_member(suffix),
                    )
                else:
                    raise _CorruptStreamError(f"Unsupported compression codec: {codec}")
        except Exception:
            outputs.cleanup()
            raise

        outputs.close()
        return outputs.aggregate_path, outputs.member_paths, total_out

    @staticmethod
    def _rewrite_wrapper_location(location: str | None, temp_path: str, provenance: str) -> str:
        return rewrite_extracted_member_location(
            location,
            temp_path,
            provenance,
            preserve_non_delimited_suffix=False,
        )

    @staticmethod
    def _rewrite_inner_locations(inner_result: ScanResult, temp_path: str, provenance: str) -> None:
        for issue in inner_result.issues:
            issue.location = CompressedScanner._rewrite_wrapper_location(issue.location, temp_path, provenance)

            if issue.details:
                issue.details["compressed_wrapper"] = provenance
            else:
                issue.details = {"compressed_wrapper": provenance}

        for check in inner_result.checks:
            check.location = CompressedScanner._rewrite_wrapper_location(check.location, temp_path, provenance)

            if check.details:
                check.details["compressed_wrapper"] = provenance
            else:
                check.details = {"compressed_wrapper": provenance}

    @staticmethod
    def _is_transport_fragment_member(inner_result: ScanResult, member_result: ScanResult) -> bool:
        """Return whether a member rescan only proves transport fragmentation."""
        return (
            inner_result.success is True
            and member_result.success is False
            and member_result.scanner_name == inner_result.scanner_name
            and member_result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            and not any(issue.severity == IssueSeverity.CRITICAL for issue in member_result.issues)
        )

    @staticmethod
    def _set_compressed_provenance(
        result: ScanResult,
        *,
        first_issue: int,
        first_check: int,
        provenance: str,
    ) -> None:
        for issue in result.issues[first_issue:]:
            issue.location = provenance
            issue.details["compressed_wrapper"] = provenance
        for check in result.checks[first_check:]:
            check.location = provenance
            check.details["compressed_wrapper"] = provenance

    def _scan_decompressed_payload_security(
        self,
        *,
        path: str,
        security_name: str,
        provenance: str,
        temp_path: str,
        member_temp_paths: list[str],
        decompressed_bytes: int,
        inner_owns_executable_content: bool,
        sniff_python_source: bool,
        result: ScanResult,
    ) -> None:
        first_issue = len(result.issues)
        first_check = len(result.checks)
        scan_archive_member_for_known_risks(
            archive_kind="compressed",
            archive_path=path,
            member_name=security_name,
            tmp_path=temp_path,
            total_size=decompressed_bytes,
            result=result,
            max_python_analysis_bytes=self.MAX_PYTHON_PAYLOAD_ANALYSIS_BYTES,
            python_analysis_incomplete_reason=self._PYTHON_PAYLOAD_INCONCLUSIVE_REASON,
            executable_analysis_incomplete_reason=self._EXECUTABLE_PAYLOAD_INCONCLUSIVE_REASON,
            analyze_executable_content=not inner_owns_executable_content,
            sniff_python_source=sniff_python_source,
        )
        self._set_compressed_provenance(
            result,
            first_issue=first_issue,
            first_check=first_check,
            provenance=provenance,
        )

        scan_outcome_reasons = result.metadata.get("scan_outcome_reasons")
        aggregate_python_incomplete = (
            isinstance(scan_outcome_reasons, list) and self._PYTHON_PAYLOAD_INCONCLUSIVE_REASON in scan_outcome_reasons
        )
        aggregate_executable_detected = any(
            check.name == "Executable Archive Member Detection" for check in result.checks[first_check:]
        )
        if len(member_temp_paths) <= 1 or (aggregate_executable_detected and not aggregate_python_incomplete):
            return

        for member_index, member_temp_path in enumerate(member_temp_paths, start=1):
            member_provenance = f"{provenance}#member-{member_index}"
            member_first_issue = len(result.issues)
            member_first_check = len(result.checks)
            scan_archive_member_for_known_risks(
                archive_kind="compressed",
                archive_path=path,
                member_name=security_name,
                tmp_path=member_temp_path,
                total_size=self.get_file_size(member_temp_path),
                result=result,
                max_python_analysis_bytes=self.MAX_PYTHON_PAYLOAD_ANALYSIS_BYTES,
                python_analysis_incomplete_reason=self._PYTHON_PAYLOAD_INCONCLUSIVE_REASON,
                executable_analysis_incomplete_reason=self._EXECUTABLE_PAYLOAD_INCONCLUSIVE_REASON,
                analyze_python_source=aggregate_python_incomplete,
                sniff_python_source=sniff_python_source,
            )
            self._set_compressed_provenance(
                result,
                first_issue=member_first_issue,
                first_check=member_first_check,
                provenance=member_provenance,
            )
            if not aggregate_python_incomplete and any(
                check.name == "Executable Archive Member Detection" for check in result.checks[member_first_check:]
            ):
                return

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check_result = self._check_size_limit(path)
        if size_check_result:
            return size_check_result

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)
        self.add_file_integrity_check(path, result)

        archive_depth = get_archive_depth(self.config)
        depth = max(int(self.config.get("_compressed_depth", 0)), archive_depth)
        if depth >= self.max_depth:
            mark_inconclusive_scan_result(result, self._DEPTH_LIMIT_INCONCLUSIVE_REASON)
            result.add_check(
                name="Compressed Wrapper Depth Limit",
                passed=False,
                message=f"Maximum compressed-wrapper nesting depth ({self.max_depth}) exceeded; analysis incomplete",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "depth": depth,
                    "max_depth": self.max_depth,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._DEPTH_LIMIT_INCONCLUSIVE_REASON,
                },
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="Compressed Wrapper Depth Limit",
            passed=True,
            message="Compressed-wrapper nesting depth is within safe limits",
            location=path,
            details={"depth": depth, "max_depth": self.max_depth},
        )

        try:
            with open(path, "rb") as handle:
                header = handle.read(8)
        except OSError as exc:
            result.add_check(
                name="Compressed Wrapper Signature Validation",
                passed=False,
                message=f"Unable to read compressed wrapper header: {exc}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result

        expected_codec = self._expected_codec_for_path(path)
        detected_codec = self._detect_codec_from_header(header)
        if expected_codec is None:
            if detected_codec is None:
                result.add_check(
                    name="Compressed Wrapper Signature Validation",
                    passed=False,
                    message="Unsupported compressed wrapper extension and no compressed magic bytes detected",
                    severity=IssueSeverity.INFO,
                    location=path,
                )
                result.finish(success=False)
                return result
            expected_codec = detected_codec
        elif detected_codec != expected_codec:
            result.add_check(
                name="Compressed Wrapper Signature Validation",
                passed=False,
                message=(
                    "Compressed wrapper signature mismatch: "
                    f"extension expects {expected_codec}, detected {detected_codec or 'unknown'}"
                ),
                severity=IssueSeverity.WARNING,
                location=path,
                details={"expected_codec": expected_codec, "detected_codec": detected_codec},
            )
            result.finish(success=False)
            return result

        result.metadata["compression_codec"] = expected_codec
        result.add_check(
            name="Compressed Wrapper Signature Validation",
            passed=True,
            message=f"Compressed wrapper signature validated for codec: {expected_codec}",
            location=path,
            details={"codec": expected_codec},
        )

        temp_paths: list[str] = []
        decompressed_bytes = 0
        try:
            temp_path, member_temp_paths, decompressed_bytes = self._decompress_to_tempfiles(path, expected_codec)
            temp_paths = [temp_path, *member_temp_paths]
            result.metadata["decompressed_bytes"] = decompressed_bytes
            result.metadata["compressed_member_count"] = len(member_temp_paths)
            compressed_size = max(1, self.get_file_size(path))
            ratio = decompressed_bytes / compressed_size
            result.add_check(
                name="Compressed Wrapper Decompression Limits",
                passed=True,
                message="Compressed payload decompressed within configured limits",
                location=path,
                details={
                    "compressed_bytes": compressed_size,
                    "decompressed_bytes": decompressed_bytes,
                    "decompression_ratio": ratio,
                    "max_decompressed_bytes": self.max_decompressed_bytes,
                    "max_decompression_ratio": self.max_decompression_ratio,
                },
            )

            nested_config = dict(self.config)
            nested_config.pop(ALLOW_SAFETENSORS_NONMEMBER_TRAILING_CONFIG_KEY, None)
            nested_config["_compressed_depth"] = depth + 1
            nested_config["_archive_depth"] = depth + 1
            # Extracted temp paths are removed after this scan and cannot yield reusable cache entries.
            nested_config["cache_enabled"] = False
            logical_wrapper_name = self.config.get(self._LOGICAL_WRAPPER_NAME_CONFIG, path)
            if not isinstance(logical_wrapper_name, str) or not logical_wrapper_name:
                logical_wrapper_name = path
            security_name = self._derive_inner_security_name(logical_wrapper_name)
            nested_config[self._LOGICAL_WRAPPER_NAME_CONFIG] = security_name
            inner_result = core.scan_file(temp_path, nested_config)

            inner_display = self._derive_inner_display_name(path)
            provenance = f"{path} -> {inner_display}"
            self._rewrite_inner_locations(inner_result, temp_path, provenance)
            self._scan_decompressed_payload_security(
                path=path,
                security_name=security_name,
                provenance=provenance,
                temp_path=temp_path,
                member_temp_paths=member_temp_paths,
                decompressed_bytes=decompressed_bytes,
                inner_owns_executable_content=(
                    len(member_temp_paths) == 1 and inner_result.scanner_name == "llamafile" and inner_result.success
                ),
                sniff_python_source=bool(self.config.get(ALLOW_SAFETENSORS_NONMEMBER_TRAILING_CONFIG_KEY)),
                result=result,
            )

            result.add_check(
                name="Compressed Wrapper Inner Scanner Routing",
                passed=True,
                message=f"Routed decompressed payload to scanner: {inner_result.scanner_name}",
                location=path,
                details={"inner_scanner": inner_result.scanner_name, "provenance": provenance},
            )

            result.merge_member_result(inner_result, inner_display)
            if len(member_temp_paths) > 1:
                for member_index, member_temp_path in enumerate(member_temp_paths, start=1):
                    member_result = core.scan_file(member_temp_path, nested_config)
                    if self._is_transport_fragment_member(inner_result, member_result):
                        continue
                    member_provenance = f"{provenance}#member-{member_index}"
                    self._rewrite_inner_locations(member_result, member_temp_path, member_provenance)
                    result.add_check(
                        name="Compressed Wrapper Member Scanner Routing",
                        passed=True,
                        message=(f"Routed decompressed member {member_index} to scanner: {member_result.scanner_name}"),
                        location=path,
                        details={
                            "inner_scanner": member_result.scanner_name,
                            "member_index": member_index,
                            "provenance": member_provenance,
                        },
                    )
                    result.merge_member_result(member_result, member_provenance)
            result.bytes_scanned += self.get_file_size(path)
        except _MissingOptionalDependencyError as exc:
            mark_inconclusive_scan_result(result, self._OPTIONAL_DEPENDENCY_INCONCLUSIVE_REASON)
            result.add_check(
                name="Compressed Wrapper Optional Dependency",
                passed=False,
                message=f"{exc}; analysis incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "codec": expected_codec,
                    "missing_dependency": "lz4",
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._OPTIONAL_DEPENDENCY_INCONCLUSIVE_REASON,
                },
            )
            result.finish(success=False)
            return result
        except _CompressedMemberLimitExceeded as exc:
            mark_inconclusive_scan_result(result, self._MEMBER_LIMIT_INCONCLUSIVE_REASON)
            result.add_check(
                name="Compressed Wrapper Decompression Limits",
                passed=False,
                message=f"{exc}; analysis incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "codec": expected_codec,
                    "max_decompressed_bytes": self.max_decompressed_bytes,
                    "max_decompression_ratio": self.max_decompression_ratio,
                    "max_compressed_members": self.max_members,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._MEMBER_LIMIT_INCONCLUSIVE_REASON,
                },
            )
            result.finish(success=False)
            return result
        except _DecompressionLimitExceeded as exc:
            mark_inconclusive_scan_result(result, self._DECOMPRESSION_LIMIT_INCONCLUSIVE_REASON)
            result.add_check(
                name="Compressed Wrapper Decompression Limits",
                passed=False,
                message=f"{exc}; analysis incomplete",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "codec": expected_codec,
                    "max_decompressed_bytes": self.max_decompressed_bytes,
                    "max_decompression_ratio": self.max_decompression_ratio,
                    "max_compressed_members": self.max_members,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._DECOMPRESSION_LIMIT_INCONCLUSIVE_REASON,
                },
            )
            result.finish(success=False)
            return result
        except _CorruptStreamError as exc:
            mark_inconclusive_scan_result(result, self._STREAM_DECODE_INCONCLUSIVE_REASON)
            result.add_check(
                name="Compressed Wrapper Stream Decode",
                passed=False,
                message=f"{exc}; analysis incomplete",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "codec": expected_codec,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._STREAM_DECODE_INCONCLUSIVE_REASON,
                },
            )
            result.finish(success=False)
            return result
        except Exception as exc:
            result.add_check(
                name="Compressed Wrapper Scan",
                passed=False,
                message=f"Error scanning compressed wrapper: {exc}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"codec": expected_codec, "exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result
        finally:
            for temp_path in temp_paths:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

        result.finish(success=not member_scan_incomplete(result) and not result.has_errors)
        return result
