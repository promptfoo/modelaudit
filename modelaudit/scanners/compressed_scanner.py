"""Scanner for standalone compressed wrapper artifacts (.gz, .bz2, .xz, .lz4, .zlib)."""

from __future__ import annotations

import bz2
import gzip
import importlib
import lzma
import os
import tempfile
import zlib
from pathlib import Path
from typing import Any, ClassVar

from .. import core
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

    @staticmethod
    def _is_zlib_header(data: bytes) -> bool:
        if len(data) < 2:
            return False
        cmf = data[0]
        flg = data[1]
        if (cmf & 0x0F) != 8:
            return False
        if (cmf >> 4) > 7:
            return False
        return ((cmf << 8) + flg) % 31 == 0

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
        if cls._is_zlib_header(header[:2]):
            return "zlib"
        return None

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        expected_codec = cls._expected_codec_for_path(path)
        if expected_codec is None:
            return False

        try:
            with open(path, "rb") as handle:
                header = handle.read(8)
        except OSError:
            return False

        detected_codec = cls._detect_codec_from_header(header)
        return detected_codec == expected_codec

    @staticmethod
    def _derive_inner_suffix(path: str) -> str:
        wrapper_path = Path(path)
        stem_without_wrapper = (
            wrapper_path.name[: -len(wrapper_path.suffix)] if wrapper_path.suffix else wrapper_path.name
        )
        inferred_suffix = Path(stem_without_wrapper).suffix
        return inferred_suffix or ".bin"

    @staticmethod
    def _derive_inner_display_name(path: str) -> str:
        wrapper_path = Path(path)
        if wrapper_path.suffix:
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

        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break

            try:
                out = decompressor.decompress(chunk)
            except zlib.error as exc:
                raise _CorruptStreamError(f"Invalid zlib stream: {exc}") from exc

            if out:
                total_out += len(out)
                if total_out > max_decompressed_bytes:
                    raise _DecompressionLimitExceeded(
                        f"Decompressed size exceeded limit ({total_out} > {max_decompressed_bytes})",
                    )
                if compressed_size > 0 and (total_out / compressed_size) > max_ratio:
                    raise _DecompressionLimitExceeded(
                        f"Decompression ratio exceeded limit ({total_out / compressed_size:.1f}x > {max_ratio:.1f}x)",
                    )
                destination.write(out)

        try:
            final = decompressor.flush()
        except zlib.error as exc:
            raise _CorruptStreamError(f"Invalid zlib stream flush: {exc}") from exc

        if final:
            total_out += len(final)
            if total_out > max_decompressed_bytes:
                raise _DecompressionLimitExceeded(
                    f"Decompressed size exceeded limit ({total_out} > {max_decompressed_bytes})",
                )
            if compressed_size > 0 and (total_out / compressed_size) > max_ratio:
                raise _DecompressionLimitExceeded(
                    f"Decompression ratio exceeded limit ({total_out / compressed_size:.1f}x > {max_ratio:.1f}x)",
                )
            destination.write(final)

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
                    try:
                        with bz2.BZ2File(source, "rb") as reader:
                            total_out = self._copy_stream_with_limits(
                                source=reader,
                                destination=temp_file,
                                max_decompressed_bytes=self.max_decompressed_bytes,
                                max_ratio=self.max_decompression_ratio,
                                compressed_size=compressed_size,
                                chunk_size=self.chunk_size,
                            )
                    except (OSError, EOFError) as exc:
                        raise _CorruptStreamError(f"Invalid bzip2 stream: {exc}") from exc
                elif codec == "xz":
                    try:
                        with lzma.LZMAFile(source, "rb") as reader:
                            total_out = self._copy_stream_with_limits(
                                source=reader,
                                destination=temp_file,
                                max_decompressed_bytes=self.max_decompressed_bytes,
                                max_ratio=self.max_decompression_ratio,
                                compressed_size=compressed_size,
                                chunk_size=self.chunk_size,
                            )
                    except (OSError, EOFError, lzma.LZMAError) as exc:
                        raise _CorruptStreamError(f"Invalid xz stream: {exc}") from exc
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
    def _rewrite_inner_locations(inner_result: ScanResult, temp_path: str, provenance: str) -> None:
        for issue in inner_result.issues:
            if issue.location:
                if issue.location.startswith(temp_path):
                    issue.location = issue.location.replace(temp_path, provenance, 1)
                else:
                    issue.location = f"{provenance} {issue.location}"
            else:
                issue.location = provenance

            if issue.details:
                issue.details["compressed_wrapper"] = provenance
            else:
                issue.details = {"compressed_wrapper": provenance}

        for check in inner_result.checks:
            if check.location:
                if check.location.startswith(temp_path):
                    check.location = check.location.replace(temp_path, provenance, 1)
                else:
                    check.location = f"{provenance} {check.location}"
            else:
                check.location = provenance

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

        depth = int(self.config.get("_compressed_depth", 0))
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

        expected_codec = self._expected_codec_for_path(path)
        if expected_codec is None:
            result.add_check(
                name="Compressed Wrapper Signature Validation",
                passed=False,
                message="Unsupported compressed wrapper extension",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

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

        detected_codec = self._detect_codec_from_header(header)
        if detected_codec != expected_codec:
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
