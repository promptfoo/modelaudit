"""Scanner for standalone compressed wrapper artifacts (.gz, .bz2, .xz, .lz4, .zlib)."""

from __future__ import annotations

import bz2
import gzip
import importlib
import lzma
import os
import tempfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from .. import core
from ..utils.file._compression import is_zlib_header
from ._archive_config import get_archive_depth
from ._archive_locations import rewrite_extracted_member_location
from .base import BaseScanner, IssueSeverity, ScanResult


class _DecompressionLimitExceeded(ValueError):
    """Raised when decompression policies are exceeded."""


class _CorruptStreamError(ValueError):
    """Raised when compressed streams cannot be decoded safely."""


class _MissingOptionalDependencyError(ImportError):
    """Raised when an optional dependency is unavailable."""


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
    DEFAULT_CHUNK_SIZE: ClassVar[int] = 64 * 1024

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_decompressed_bytes = int(
            self.config.get("compressed_max_decompressed_bytes", self.DEFAULT_MAX_DECOMPRESSED_BYTES),
        )
        self.max_decompression_ratio = float(
            self.config.get("compressed_max_decompression_ratio", self.DEFAULT_MAX_DECOMPRESSION_RATIO),
        )
        self.max_depth = int(self.config.get("compressed_max_depth", self.DEFAULT_MAX_DEPTH))
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
    ) -> int:
        decompressor = decompressor_factory()
        total_out = 0

        def _consume_pending(pending: bytes) -> None:
            nonlocal decompressor, total_out
            while pending or not getattr(decompressor, "needs_input", True):
                if getattr(decompressor, "eof", False):
                    if not pending:
                        break
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

                unused_data = getattr(decompressor, "unused_data", b"")
                if unused_data:
                    pending = unused_data
                    decompressor = decompressor_factory()

        while True:
            pending = source.read(chunk_size)
            if not pending:
                break
            _consume_pending(pending)

        _consume_pending(b"")

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
        )

    @staticmethod
    def _read_xz_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
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
        )

    @staticmethod
    def _read_zlib_stream_with_limits(
        source: Any,
        destination: Any,
        max_decompressed_bytes: int,
        max_ratio: float,
        compressed_size: int,
        chunk_size: int,
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

        def _remaining_decompressed_budget() -> int:
            return max(max_decompressed_bytes - total_out, 0)

        def _probe_limit() -> int:
            remaining_budget = _remaining_decompressed_budget()
            return remaining_budget + 1 if remaining_budget > 0 else 1

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

    def _decompress_to_tempfile(self, path: str, codec: str) -> tuple[str, int]:
        compressed_size = self.get_file_size(path)
        suffix = self._derive_inner_suffix(path)

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            temp_path = temp_file.name

            with open(path, "rb") as source:
                if codec == "gzip":
                    try:
                        with gzip.GzipFile(fileobj=source, mode="rb") as reader:
                            total_out = self._copy_stream_with_limits(
                                source=reader,
                                destination=temp_file,
                                max_decompressed_bytes=self.max_decompressed_bytes,
                                max_ratio=self.max_decompression_ratio,
                                compressed_size=compressed_size,
                                chunk_size=self.chunk_size,
                            )
                    except (OSError, EOFError, gzip.BadGzipFile) as exc:
                        raise _CorruptStreamError(f"Invalid gzip stream: {exc}") from exc
                elif codec == "bzip2":
                    total_out = self._read_bzip2_stream_with_limits(
                        source=source,
                        destination=temp_file,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                    )
                elif codec == "xz":
                    total_out = self._read_xz_stream_with_limits(
                        source=source,
                        destination=temp_file,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                    )
                elif codec == "lz4":
                    lz4_frame = self._get_lz4_frame_module()
                    try:
                        with lz4_frame.open(source, "rb") as reader:
                            total_out = self._copy_stream_with_limits(
                                source=reader,
                                destination=temp_file,
                                max_decompressed_bytes=self.max_decompressed_bytes,
                                max_ratio=self.max_decompression_ratio,
                                compressed_size=compressed_size,
                                chunk_size=self.chunk_size,
                            )
                    except (OSError, EOFError, RuntimeError) as exc:
                        raise _CorruptStreamError(f"Invalid lz4 stream: {exc}") from exc
                elif codec == "zlib":
                    total_out = self._read_zlib_stream_with_limits(
                        source=source,
                        destination=temp_file,
                        max_decompressed_bytes=self.max_decompressed_bytes,
                        max_ratio=self.max_decompression_ratio,
                        compressed_size=compressed_size,
                        chunk_size=self.chunk_size,
                    )
                else:
                    raise _CorruptStreamError(f"Unsupported compression codec: {codec}")

        return temp_path, total_out

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
            result.add_check(
                name="Compressed Wrapper Depth Limit",
                passed=False,
                message=f"Maximum compressed-wrapper nesting depth ({self.max_depth}) exceeded",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"depth": depth, "max_depth": self.max_depth},
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

        temp_path: str | None = None
        decompressed_bytes = 0
        try:
            temp_path, decompressed_bytes = self._decompress_to_tempfile(path, expected_codec)
            result.metadata["decompressed_bytes"] = decompressed_bytes
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
            nested_config["_compressed_depth"] = depth + 1
            nested_config["_archive_depth"] = depth + 1
            inner_result = core.scan_file(temp_path, nested_config)

            inner_display = self._derive_inner_display_name(path)
            provenance = f"{path} -> {inner_display}"
            self._rewrite_inner_locations(inner_result, temp_path, provenance)

            result.add_check(
                name="Compressed Wrapper Inner Scanner Routing",
                passed=True,
                message=f"Routed decompressed payload to scanner: {inner_result.scanner_name}",
                location=path,
                details={"inner_scanner": inner_result.scanner_name, "provenance": provenance},
            )

            result.merge(inner_result)
            result.bytes_scanned += self.get_file_size(path)
        except _MissingOptionalDependencyError as exc:
            result.add_check(
                name="Compressed Wrapper Optional Dependency",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.INFO,
                location=path,
                details={"codec": expected_codec, "missing_dependency": "lz4"},
            )
            result.finish(success=False)
            return result
        except _DecompressionLimitExceeded as exc:
            result.add_check(
                name="Compressed Wrapper Decompression Limits",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "codec": expected_codec,
                    "max_decompressed_bytes": self.max_decompressed_bytes,
                    "max_decompression_ratio": self.max_decompression_ratio,
                },
            )
            result.finish(success=False)
            return result
        except _CorruptStreamError as exc:
            result.add_check(
                name="Compressed Wrapper Stream Decode",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.WARNING,
                location=path,
                details={"codec": expected_codec},
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
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

        result.finish(success=not result.has_errors)
        return result
