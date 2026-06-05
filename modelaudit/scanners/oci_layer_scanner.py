"""Scanner for OCI container image layers containing model artifacts."""

import json
import math
import os
import posixpath
import shutil
import tarfile
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from ..scanner_results import mark_inconclusive_scan_result
from ..utils import is_absolute_archive_path, is_critical_system_path, is_within_directory, sanitize_archive_path
from ..utils.file.detection import (
    MARKED_PROTOCOL0_GLOBAL_RE,
    PROTOCOL0_GLOBAL_RE,
    detect_file_format,
)
from ..utils.model_extensions import get_model_extensions
from ._archive_locations import rewrite_extracted_member_location
from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import yaml for YAML manifests
try:
    import yaml

    HAS_YAML = True
except Exception:
    HAS_YAML = False

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


@dataclass
class _TarStreamMetrics:
    """Bounded structural metrics collected without materializing TAR metadata bodies."""

    max_metadata_bytes: int
    max_entries: int
    raw_entries: int = 0
    hidden_entries: int = 0
    metadata_bytes: int = 0
    metadata_limit_exceeded: bool = False
    visible_entries_completed: int = 0
    visible_entries_within_limit: int = 0
    _header: bytearray = field(default_factory=bytearray)
    _payload_bytes_remaining: int = 0
    _payload_is_visible: bool = False
    _sparse_extension_pending: bool = False
    _sparse_payload_bytes: int = 0
    _payload_is_within_entry_limit: bool = False
    _ended: bool = False
    _invalid: bool = False

    _HIDDEN_TYPES: ClassVar[frozenset[bytes]] = frozenset(
        {
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.SOLARIS_XHDTYPE,
        }
    )

    def feed(self, data: bytes) -> None:
        offset = 0
        while offset < len(data) and not self._ended and not self._invalid:
            if self._sparse_extension_pending:
                needed = tarfile.BLOCKSIZE - len(self._header)
                consumed = min(needed, len(data) - offset)
                self._header.extend(data[offset : offset + consumed])
                offset += consumed
                if len(self._header) < tarfile.BLOCKSIZE:
                    continue

                extension = bytes(self._header)
                self._header.clear()
                self.metadata_bytes += tarfile.BLOCKSIZE
                if self.metadata_bytes > self.max_metadata_bytes:
                    self.metadata_limit_exceeded = True
                self._sparse_extension_pending = bool(extension[504])
                if not self._sparse_extension_pending:
                    self._payload_bytes_remaining = self._sparse_payload_bytes
                    self._sparse_payload_bytes = 0
                    if self._payload_bytes_remaining == 0 and self._payload_is_visible:
                        self.visible_entries_completed += 1
                        self._payload_is_visible = False
                continue

            if self._payload_bytes_remaining:
                consumed = min(self._payload_bytes_remaining, len(data) - offset)
                self._payload_bytes_remaining -= consumed
                offset += consumed
                if self._payload_bytes_remaining == 0 and self._payload_is_visible:
                    self.visible_entries_completed += 1
                    if self._payload_is_within_entry_limit:
                        self.visible_entries_within_limit += 1
                    self._payload_is_visible = False
                    self._payload_is_within_entry_limit = False
                continue

            needed = tarfile.BLOCKSIZE - len(self._header)
            consumed = min(needed, len(data) - offset)
            self._header.extend(data[offset : offset + consumed])
            offset += consumed
            if len(self._header) < tarfile.BLOCKSIZE:
                continue

            header = bytes(self._header)
            self._header.clear()
            if header == b"\x00" * tarfile.BLOCKSIZE:
                self._ended = True
                continue

            try:
                info = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            except tarfile.HeaderError:
                self._invalid = True
                continue

            self.raw_entries += 1
            is_hidden = info.type in self._HIDDEN_TYPES
            if is_hidden:
                self.hidden_entries += 1
                self.metadata_bytes += max(0, info.size)
                if self.metadata_bytes > self.max_metadata_bytes:
                    self.metadata_limit_exceeded = True

            payload_size = max(0, info.size)
            self._payload_is_visible = not is_hidden
            self._payload_is_within_entry_limit = self.raw_entries <= self.max_entries
            self._payload_bytes_remaining = (
                (payload_size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
            ) * tarfile.BLOCKSIZE
            sparse_structs: Any = getattr(info, "_sparse_structs", ())
            if (
                info.type == tarfile.GNUTYPE_SPARSE
                and isinstance(sparse_structs, tuple)
                and len(sparse_structs) > 1
                and bool(sparse_structs[1])
            ):
                self._sparse_extension_pending = True
                self._sparse_payload_bytes = self._payload_bytes_remaining
                self._payload_bytes_remaining = 0
            if self._payload_bytes_remaining == 0 and self._payload_is_visible:
                self.visible_entries_completed += 1
                if self._payload_is_within_entry_limit:
                    self.visible_entries_within_limit += 1
                self._payload_is_visible = False
                self._payload_is_within_entry_limit = False


@dataclass
class _GzipStreamMetrics:
    """Security-relevant metrics for a validated gzip stream."""

    compressed_size: int = 0
    decompressed_size: int = 0
    size_exceeded: bool = False
    ratio_exceeded: bool = False
    ratio_compressed_size: int = 0
    ratio_decompressed_size: int = 0
    member_count: int = 0
    safe_tar_entries: int = 0
    failure: str | None = None
    tar: _TarStreamMetrics | None = None


@dataclass
class _LayerMetadataState:
    """Bounded per-layer state for metadata ambiguity checks."""

    seen_paths: set[str] = field(default_factory=set)
    duplicate_reported: bool = False
    invalid_whiteout_reported: bool = False


class OciLayerScanner(BaseScanner):
    """Scanner for OCI/Artifactory manifest files with .tar.gz layers."""

    name = "oci_layer"
    description = "Scans container manifests and embedded layers for model files"
    supported_extensions: ClassVar[list[str]] = [".manifest"]
    _DETECTED_FORMAT_SUFFIXES: ClassVar[dict[str, str]] = {
        "pickle": ".pkl",
        "onnx": ".onnx",
        "hdf5": ".h5",
        "safetensors": ".safetensors",
        "numpy": ".npy",
        "protobuf": ".pb",
        "zip": ".zip",
        "gguf": ".gguf",
        "ggml": ".gguf",
    }
    _LAYER_ARCHIVE_SUFFIX: ClassVar[str] = ".tar.gz"
    _MANIFEST_PROBE_CHUNK_BYTES: ClassVar[int] = 8192
    _MEMBER_HEADER_PROBE_BYTES: ClassVar[int] = 64
    _GZIP_CHUNK_BYTES: ClassVar[int] = 1024 * 1024
    _GZIP_OUTPUT_CHUNK_BYTES: ClassVar[int] = 64 * 1024
    _GZIP_TRAILER_BYTES: ClassVar[int] = 8
    _GZIP_HEADER_BYTES: ClassVar[int] = 10
    _MAX_GZIP_HEADER_BYTES: ClassVar[int] = 64 * 1024
    _MAX_GZIP_METADATA_BYTES: ClassVar[int] = 1024 * 1024
    _MAX_GZIP_MEMBERS: ClassVar[int] = 1024
    _MAX_GZIP_PADDING_BYTES: ClassVar[int] = 1024 * 1024
    _MAX_TAR_METADATA_BYTES: ClassVar[int] = 8 * 1024 * 1024
    _MIN_MAX_HIDDEN_TAR_ENTRIES: ClassVar[int] = 1024
    _MIN_PREFIX_RATIO_BYTES: ClassVar[int] = 64 * 1024
    _DEFAULT_MAX_LAYER_FILE_SIZE: ClassVar[int] = 10 * 1024 * 1024 * 1024
    _DEFAULT_MAX_LAYER_ENTRIES: ClassVar[int] = 10000
    _DEFAULT_MAX_DECOMPRESSED_BYTES: ClassVar[int] = 512 * 1024 * 1024
    _DEFAULT_MAX_DECOMPRESSION_RATIO: ClassVar[float] = 250.0
    _REMOTE_LAYER_REF_SCHEMES: ClassVar[frozenset[str]] = frozenset({"http", "https", "s3", "gs", "oci"})
    _PARENT_IDENTITY_METADATA_KEYS: ClassVar[frozenset[str]] = frozenset({"file_size", "file_hashes"})

    @staticmethod
    def _mark_incomplete_coverage(result: ScanResult, reason: str) -> None:
        """Record OCI content that could not be inspected without reporting a security finding."""
        mark_inconclusive_scan_result(result, reason)

    @classmethod
    def _merge_nested_result(cls, result: ScanResult, nested_result: ScanResult) -> None:
        """Merge embedded analysis without replacing manifest identity or incomplete coverage."""
        parent_identity = {
            key: result.metadata[key] for key in cls._PARENT_IDENTITY_METADATA_KEYS if key in result.metadata
        }
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        result.merge(nested_result)
        for key in cls._PARENT_IDENTITY_METADATA_KEYS:
            if key in parent_identity:
                result.metadata[key] = parent_identity[key]
            else:
                result.metadata.pop(key, None)
        for reason in existing_reasons:
            cls._mark_incomplete_coverage(result, reason)

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        configured_max_file_size = self.config.get("max_file_size")
        if configured_max_file_size == 0:
            self.max_layer_file_size = 0
        else:
            self.max_layer_file_size = self._normalize_positive_int_config(
                configured_max_file_size,
                self._DEFAULT_MAX_LAYER_FILE_SIZE,
            )
        self.max_layer_entries = self._normalize_positive_int_config(
            self.config.get("max_oci_layer_entries", self.config.get("max_tar_entries")),
            self._DEFAULT_MAX_LAYER_ENTRIES,
        )
        self.max_decompressed_bytes = self._normalize_positive_int_config(
            self.config.get("compressed_max_decompressed_bytes"),
            self._DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        self.max_decompression_ratio = self._normalize_positive_float_config(
            self.config.get("compressed_max_decompression_ratio"),
            self._DEFAULT_MAX_DECOMPRESSION_RATIO,
        )

    @staticmethod
    def _normalize_positive_float_config(value: Any, default: float) -> float:
        """Return a positive float config value, or default for invalid input."""
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            return default
        try:
            normalized_value = float(value)
        except (OverflowError, TypeError, ValueError):
            return default
        return normalized_value if math.isfinite(normalized_value) else default

    def _add_layer_budget_check(
        self,
        result: ScanResult,
        *,
        manifest_path: str,
        layer_ref: str,
        reason: str,
        message: str,
        details: dict[str, Any],
    ) -> None:
        self._mark_incomplete_coverage(result, reason)
        result.add_check(
            name="Layer Decompression Budget Check",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=f"{manifest_path}:{layer_ref}",
            details={
                "layer": layer_ref,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
                **details,
            },
            rule_code="S902",
        )

    def _gzip_stream_metrics(
        self,
        layer_path: str,
    ) -> _GzipStreamMetrics:
        metrics = _GzipStreamMetrics(
            tar=_TarStreamMetrics(
                max_metadata_bytes=self._MAX_TAR_METADATA_BYTES,
                max_entries=self.max_layer_entries,
            )
        )
        pending = bytearray()
        gzip_metadata_bytes = 0

        with open(layer_path, "rb") as layer_file:

            def _fill(size: int) -> bool:
                while len(pending) < size:
                    chunk = layer_file.read(max(self._GZIP_CHUNK_BYTES, size - len(pending)))
                    if not chunk:
                        return False
                    pending.extend(chunk)
                return True

            def _take(size: int) -> bytes | None:
                if not _fill(size):
                    return None
                value = bytes(pending[:size])
                del pending[:size]
                return value

            def _take_terminated(header: bytearray) -> bool:
                while len(header) < self._MAX_GZIP_HEADER_BYTES:
                    if not _fill(1):
                        metrics.failure = "truncated_header"
                        return False
                    remaining = self._MAX_GZIP_HEADER_BYTES - len(header)
                    search_size = min(len(pending), remaining)
                    terminator = pending.find(0, 0, search_size)
                    consumed = terminator + 1 if terminator >= 0 else search_size
                    header.extend(pending[:consumed])
                    del pending[:consumed]
                    if terminator >= 0:
                        return True
                metrics.failure = "header_limit_exceeded"
                return False

            def _parse_header() -> bool:
                nonlocal gzip_metadata_bytes
                fixed = _take(self._GZIP_HEADER_BYTES)
                if fixed is None:
                    metrics.failure = "truncated_header"
                    return False
                if fixed[:3] != b"\x1f\x8b\x08" or fixed[3] & 0xE0:
                    metrics.failure = "invalid_header"
                    return False

                flags = fixed[3]
                header = bytearray(fixed)
                if flags & 0x04:
                    extra_size_bytes = _take(2)
                    if extra_size_bytes is None:
                        metrics.failure = "truncated_header"
                        return False
                    header.extend(extra_size_bytes)
                    extra_size = int.from_bytes(extra_size_bytes, "little")
                    if len(header) + extra_size > self._MAX_GZIP_HEADER_BYTES:
                        metrics.failure = "header_limit_exceeded"
                        return False
                    extra = _take(extra_size)
                    if extra is None:
                        metrics.failure = "truncated_header"
                        return False
                    header.extend(extra)
                if flags & 0x08 and not _take_terminated(header):
                    return False
                if flags & 0x10 and not _take_terminated(header):
                    return False
                if flags & 0x02:
                    expected_crc = _take(2)
                    if expected_crc is None:
                        metrics.failure = "truncated_header"
                        return False
                    if int.from_bytes(expected_crc, "little") != zlib.crc32(header) & 0xFFFF:
                        metrics.failure = "header_checksum_mismatch"
                        return False
                    header.extend(expected_crc)
                gzip_metadata_bytes += len(header) + self._GZIP_TRAILER_BYTES
                if gzip_metadata_bytes > self._MAX_GZIP_METADATA_BYTES:
                    metrics.failure = "metadata_limit_exceeded"
                    return False
                return True

            padding_bytes = 0
            while True:
                if metrics.member_count:
                    while True:
                        if not pending:
                            chunk = layer_file.read(self._GZIP_CHUNK_BYTES)
                            if not chunk:
                                return metrics
                            pending.extend(chunk)
                        first_nonzero = next((index for index, value in enumerate(pending) if value), len(pending))
                        padding_bytes += first_nonzero
                        del pending[:first_nonzero]
                        if padding_bytes > self._MAX_GZIP_PADDING_BYTES:
                            metrics.failure = "padding_limit_exceeded"
                            return metrics
                        if pending:
                            break
                    if not _fill(2) or pending[:2] != b"\x1f\x8b":
                        metrics.failure = "trailing_data"
                        return metrics

                metrics.member_count += 1
                if metrics.member_count > self._MAX_GZIP_MEMBERS:
                    metrics.failure = "member_count_exceeded"
                    return metrics
                if not _parse_header():
                    return metrics

                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                member_compressed = 0
                member_decompressed = 0
                member_crc = 0
                while not decompressor.eof:
                    if pending:
                        data = bytes(pending)
                        pending.clear()
                    else:
                        data = layer_file.read(self._GZIP_CHUNK_BYTES)
                    if not data:
                        metrics.failure = "truncated_deflate_stream"
                        return metrics

                    while data and not decompressor.eof:
                        try:
                            output = decompressor.decompress(data, self._GZIP_OUTPUT_CHUNK_BYTES)
                        except zlib.error:
                            metrics.failure = "invalid_deflate_stream"
                            return metrics

                        remaining = max(
                            len(decompressor.unconsumed_tail),
                            len(decompressor.unused_data),
                        )
                        consumed = len(data) - remaining
                        member_compressed += consumed
                        member_decompressed += len(output)
                        decompressed_before = metrics.decompressed_size
                        metrics.decompressed_size += len(output)
                        member_crc = zlib.crc32(output, member_crc)

                        ratio_compressed_size = metrics.compressed_size + member_compressed
                        if metrics.decompressed_size > self.max_decompressed_bytes:
                            if metrics.tar is not None:
                                safe_output_size = max(0, self.max_decompressed_bytes - decompressed_before)
                                metrics.tar.feed(output[:safe_output_size])
                                metrics.safe_tar_entries = metrics.tar.visible_entries_completed
                            metrics.compressed_size = ratio_compressed_size
                            metrics.size_exceeded = True
                            return metrics

                        if metrics.tar is not None:
                            metrics.tar.feed(output)
                        if ratio_compressed_size > 0:
                            ratio = metrics.decompressed_size / ratio_compressed_size
                            if (
                                metrics.decompressed_size >= self._MIN_PREFIX_RATIO_BYTES
                                and ratio > self.max_decompression_ratio
                            ):
                                metrics.ratio_exceeded = True
                                metrics.ratio_compressed_size = ratio_compressed_size
                                metrics.ratio_decompressed_size = metrics.decompressed_size
                                if metrics.tar is not None:
                                    metrics.safe_tar_entries = metrics.tar.visible_entries_completed
                                return metrics

                        if decompressor.eof:
                            pending.extend(decompressor.unused_data)
                            break
                        if consumed == 0 and not output:
                            metrics.failure = "stalled_deflate_stream"
                            return metrics
                        data = decompressor.unconsumed_tail

                trailer = _take(self._GZIP_TRAILER_BYTES)
                if trailer is None:
                    metrics.failure = "truncated_trailer"
                    return metrics
                expected_crc = int.from_bytes(trailer[:4], "little")
                expected_size = int.from_bytes(trailer[4:], "little")
                if expected_crc != member_crc & 0xFFFFFFFF:
                    metrics.failure = "checksum_mismatch"
                    return metrics
                if expected_size != member_decompressed & 0xFFFFFFFF:
                    metrics.failure = "size_mismatch"
                    return metrics

                if member_decompressed:
                    metrics.compressed_size += member_compressed
                    ratio = metrics.decompressed_size / metrics.compressed_size
                    if ratio > self.max_decompression_ratio:
                        metrics.ratio_exceeded = True
                        metrics.ratio_compressed_size = metrics.compressed_size
                        metrics.ratio_decompressed_size = metrics.decompressed_size
                        if metrics.tar is not None:
                            metrics.safe_tar_entries = metrics.tar.visible_entries_completed
                        return metrics

    @staticmethod
    def _get_scannable_extension(member_name: str) -> str | None:
        suffixes = [suffix.lower() for suffix in Path(member_name.rstrip(" .")).suffixes]
        if not suffixes:
            return None

        scannable_extensions = get_model_extensions()
        best_candidate: tuple[int, int, str] | None = None

        for start in range(len(suffixes)):
            for end in range(len(suffixes), start, -1):
                candidate = "".join(suffixes[start:end])
                if candidate not in scannable_extensions:
                    continue
                candidate_width = end - start
                if (
                    best_candidate is None
                    or candidate_width > best_candidate[0]
                    or (candidate_width == best_candidate[0] and start < best_candidate[1])
                ):
                    best_candidate = (candidate_width, start, candidate)

        return best_candidate[2] if best_candidate is not None else None

    def _validate_layer_member_metadata(
        self,
        result: ScanResult,
        *,
        manifest_path: str,
        layer_ref: str,
        member: tarfile.TarInfo,
        state: _LayerMetadataState,
    ) -> tuple[bool, bool]:
        """Return whether metadata is valid and whether member bytes should be scanned."""
        name = member.name
        temp_base = os.path.join(tempfile.gettempdir(), "extract_oci_layer")
        resolved_name, is_safe = sanitize_archive_path(name, temp_base)
        if not is_safe:
            result.add_check(
                name="Path Traversal Protection",
                passed=False,
                message=f"Layer member {name} attempted path traversal outside the layer",
                severity=IssueSeverity.CRITICAL,
                location=f"{manifest_path}:{layer_ref}:{name}",
                details={"layer": layer_ref, "member": name},
                rule_code="S405",
            )
            return False, False

        metadata_valid = True
        normalized_name = posixpath.normpath(name.replace("\\", "/"))
        if normalized_name in state.seen_paths:
            metadata_valid = False
            if not state.duplicate_reported:
                result.add_check(
                    name="OCI Layer Metadata Validation",
                    passed=False,
                    message=f"Layer member {name} duplicates normalized path {normalized_name}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{manifest_path}:{layer_ref}:{name}",
                    details={"layer": layer_ref, "member": name, "normalized_path": normalized_name},
                    rule_code="S902",
                )
                state.duplicate_reported = True
        else:
            state.seen_paths.add(normalized_name)

        raw_path_components = [component for component in name.replace("\\", "/").split("/") if component]
        reserved_whiteout_parent = next(
            (component for component in raw_path_components[:-1] if component.startswith(".wh.")),
            None,
        )
        if reserved_whiteout_parent is not None:
            metadata_valid = False
            if not state.invalid_whiteout_reported:
                result.add_check(
                    name="OCI Layer Metadata Validation",
                    passed=False,
                    message=(
                        f"Layer member {name} uses reserved OCI whiteout path component {reserved_whiteout_parent}"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=f"{manifest_path}:{layer_ref}:{name}",
                    details={
                        "layer": layer_ref,
                        "member": name,
                        "reserved_component": reserved_whiteout_parent,
                    },
                    rule_code="S902",
                )
                state.invalid_whiteout_reported = True

        basename = posixpath.basename(normalized_name)
        if basename.startswith(".wh."):
            whiteout_target = basename.removeprefix(".wh.")
            valid_whiteout_target = basename == ".wh..wh..opq" or (
                whiteout_target not in {"", ".", ".."} and not whiteout_target.startswith(".wh.")
            )
            valid_whiteout = valid_whiteout_target and member.isfile() and member.size == 0
            if not valid_whiteout:
                metadata_valid = False
                if not state.invalid_whiteout_reported:
                    result.add_check(
                        name="OCI Layer Metadata Validation",
                        passed=False,
                        message=f"Layer member {name} is not a valid empty OCI whiteout file",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{manifest_path}:{layer_ref}:{name}",
                        details={
                            "layer": layer_ref,
                            "member": name,
                            "member_type": member.type.decode("ascii", errors="replace"),
                            "size": member.size,
                        },
                        rule_code="S902",
                    )
                    state.invalid_whiteout_reported = True
            return metadata_valid, not valid_whiteout and member.isfile() and member.size > 0

        if member.issym() or member.islnk():
            target = member.linkname
            details = {"layer": layer_ref, "member": name, "target": target}
            if not target:
                result.add_check(
                    name="Symlink Safety Validation",
                    passed=False,
                    message=f"Layer link {name} has an empty target",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{manifest_path}:{layer_ref}:{name}",
                    details=details,
                    rule_code="S406",
                )
                return False, False
            _target_resolved, target_safe = self._resolve_link_target(
                target,
                resolved_member_name=resolved_name,
                extraction_root=temp_base,
                is_symlink=member.issym(),
            )
            if not target_safe:
                if is_absolute_archive_path(target) and is_critical_system_path(target, CRITICAL_SYSTEM_PATHS):
                    message = f"Layer link {name} points to critical system path: {target}"
                else:
                    message = f"Layer link {name} resolves outside extraction directory"
                result.add_check(
                    name="Symlink Safety Validation",
                    passed=False,
                    message=message,
                    severity=IssueSeverity.CRITICAL,
                    location=f"{manifest_path}:{layer_ref}:{name}",
                    details=details,
                    rule_code="S406",
                )
                return False, False
            return metadata_valid, False

        return metadata_valid, member.isfile()

    @staticmethod
    def _resolve_link_target(
        target: str,
        *,
        resolved_member_name: str,
        extraction_root: str,
        is_symlink: bool,
    ) -> tuple[str, bool]:
        if not is_symlink:
            return sanitize_archive_path(target, extraction_root)
        normalized_archive_target = target.replace("\\", "/")
        if target.startswith("/") and not normalized_archive_target.startswith("//"):
            # OCI layers describe a container root filesystem. A POSIX-absolute
            # symlink therefore targets that root, not the extraction host.
            container_relative_target = posixpath.normpath(normalized_archive_target).lstrip("/")
            return posixpath.join(extraction_root.replace("\\", "/"), container_relative_target), True
        if is_absolute_archive_path(normalized_archive_target):
            return target, False

        normalized_target = target.replace("\\", os.sep).replace("/", os.sep)
        target_base = os.path.dirname(resolved_member_name)
        target_resolved = os.path.normpath(os.path.join(target_base, normalized_target))
        try:
            target_from_root = os.path.relpath(target_resolved, extraction_root)
        except ValueError:
            return target_resolved, False
        return sanitize_archive_path(target_from_root, extraction_root)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Check for .tar.gz references case-insensitively without reading the
        # whole file into memory at once.
        try:
            probe_tail = ""
            with open(path, encoding="utf-8", errors="ignore") as f:
                while chunk := f.read(cls._MANIFEST_PROBE_CHUNK_BYTES):
                    haystack = f"{probe_tail}{chunk}".lower()
                    if cls._LAYER_ARCHIVE_SUFFIX in haystack:
                        return True
                    probe_tail = haystack[-(len(cls._LAYER_ARCHIVE_SUFFIX) - 1) :]
            return False
        except Exception:
            return False

    @staticmethod
    def _normalize_layer_ref(layer_ref: str) -> str:
        """Trim manifest layer refs so cosmetic suffix whitespace cannot hide .tar.gz layers."""
        return layer_ref.strip().rstrip(" .")

    @staticmethod
    def _is_remote_layer_ref(layer_ref: str) -> bool:
        """Return True when a layer reference points to a remote URL-like location."""
        parsed = urlparse(layer_ref.strip())
        return parsed.scheme.lower() in OciLayerScanner._REMOTE_LAYER_REF_SCHEMES and bool(parsed.netloc)

    @classmethod
    def _collect_layer_paths(cls, manifest_data: Any) -> list[str]:
        """Collect layer refs from manifest layer fields without treating arbitrary strings as layers."""
        layer_paths: list[str] = []

        def _append_layer_ref(value: Any) -> None:
            if isinstance(value, str) and cls._normalize_layer_ref(value).lower().endswith(cls._LAYER_ARCHIVE_SUFFIX):
                layer_paths.append(value)

        def _collect_layer_value(value: Any) -> None:
            if isinstance(value, str):
                _append_layer_ref(value)
            elif isinstance(value, list):
                for item in value:
                    _collect_layer_value(item)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if str(key).lower() in {"layers", "urls"}:
                        _collect_layer_value(item)

        def _walk_manifest(obj: Any) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if str(key).lower() == "layers":
                        _collect_layer_value(value)
                    elif isinstance(value, (dict, list)):
                        _walk_manifest(value)
            elif isinstance(obj, list):
                for item in obj:
                    _walk_manifest(item)

        _walk_manifest(manifest_data)
        return layer_paths

    @staticmethod
    def _rewrite_embedded_location(
        location: str | None,
        *,
        manifest_path: str,
        layer_ref: str,
        member_name: str,
        extracted_path: str,
    ) -> str:
        """Replace temporary extraction paths with the original OCI member location."""
        member_location = f"{manifest_path}:{layer_ref}:{member_name}"
        return rewrite_extracted_member_location(
            location,
            extracted_path,
            member_location,
            preserve_non_delimited_suffix=True,
        )

    @classmethod
    def _get_detected_format_suffix(cls, extracted_path: str) -> str | None:
        """Return a canonical suffix for detected content-based formats."""
        detected_format = detect_file_format(extracted_path)
        return cls._DETECTED_FORMAT_SUFFIXES.get(detected_format)

    @staticmethod
    def _looks_like_model_member_prefix(data: bytes) -> bool:
        """Return True when an extensionless or misnamed member has model-like magic bytes."""
        if len(data) >= 8 and data[4:8] == b"TFL3":
            return True
        if data.startswith(
            (
                b"\x80\x02",
                b"\x80\x03",
                b"\x80\x04",
                b"\x80\x05",
                b"\x89HDF\r\n\x1a\n",
                b"\x93NUMPY",
                b"GGUF",
                b"GGML",
                b"GGMF",
                b"GGJT",
                b"GGLA",
                b"GGSA",
                b"PK\x03\x04",
                b"PK\x05\x06",
                b"PK\x07\x08",
                b"\x08\x01\x12\x00",
                b"ONNX",
                b"onnx",
                b"<?xml",
            )
        ):
            return True
        if PROTOCOL0_GLOBAL_RE.match(data) or MARKED_PROTOCOL0_GLOBAL_RE.match(data):
            return True

        for offset in range(1, len(data)):
            shifted_prefix = data[offset:]
            if shifted_prefix.startswith(
                (
                    b"\x80\x02",
                    b"\x80\x03",
                    b"\x80\x04",
                    b"\x80\x05",
                    b"\x89HDF\r\n\x1a\n",
                    b"\x93NUMPY",
                    b"GGUF",
                    b"GGML",
                    b"GGMF",
                    b"GGJT",
                    b"GGLA",
                    b"GGSA",
                    b"PK\x03\x04",
                    b"PK\x05\x06",
                    b"PK\x07\x08",
                    b"\x08\x01\x12\x00",
                    b"ONNX",
                    b"onnx",
                    b"<?xml",
                )
            ):
                return True
            if PROTOCOL0_GLOBAL_RE.match(shifted_prefix) or MARKED_PROTOCOL0_GLOBAL_RE.match(shifted_prefix):
                return True

        return False

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        manifest_data: Any = None

        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            try:
                manifest_data = json.loads(text)
            except Exception:
                if HAS_YAML:
                    manifest_data = yaml.safe_load(text)
                else:
                    raise
        except Exception as e:
            self._mark_incomplete_coverage(result, "oci_manifest_parse_failed")
            result.add_check(
                name="OCI Manifest Parse",
                passed=False,
                message=f"Error parsing manifest: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "oci_manifest_parse_failed",
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        layer_paths = self._collect_layer_paths(manifest_data)

        manifest_dir = os.path.dirname(path)
        scan_complete = True

        for layer_ref in layer_paths:
            normalized_layer_ref = self._normalize_layer_ref(layer_ref)
            layer_path, is_safe = sanitize_archive_path(layer_ref, manifest_dir)

            if not is_safe or not is_within_directory(manifest_dir, layer_path):
                scan_complete = False
                result.add_check(
                    name="Layer Path Traversal Protection",
                    passed=False,
                    message=f"Layer reference {layer_ref} attempted path traversal outside manifest directory",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path}:{layer_ref}",
                    details={"layer": layer_ref, "resolved_path": layer_path},
                    rule_code="S405",
                )
                continue

            if not os.path.exists(layer_path):
                if self._is_remote_layer_ref(layer_ref):
                    scan_complete = False
                    self._mark_incomplete_coverage(result, "oci_remote_layer_unavailable")
                    result.add_check(
                        name="Remote Layer Resolution Check",
                        passed=False,
                        message=f"Remote layer was not scanned because it is not available locally: {layer_ref}",
                        severity=IssueSeverity.INFO,
                        location=f"{path}:{layer_ref}",
                        details={
                            "layer": layer_ref,
                            "resolved_path": layer_path,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "oci_remote_layer_unavailable",
                        },
                        rule_code="S902",
                    )
                    continue
                scan_complete = False
                self._mark_incomplete_coverage(result, "oci_layer_missing")
                result.add_check(
                    name="Layer File Existence Check",
                    passed=False,
                    message=f"Layer not found: {layer_ref}",
                    severity=IssueSeverity.INFO,
                    location=f"{path}:{layer_ref}",
                    details={
                        "layer": layer_ref,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "oci_layer_missing",
                    },
                    rule_code="S902",
                )
                continue
            try:
                if not os.path.isfile(layer_path):
                    raise OSError("layer path is not a regular file")
                layer_size = os.path.getsize(layer_path)
                if self.max_layer_file_size > 0 and layer_size > self.max_layer_file_size:
                    scan_complete = False
                    self._mark_incomplete_coverage(result, "oci_layer_size_limit_exceeded")
                    result.add_check(
                        name="Layer File Size Check",
                        passed=False,
                        message=(
                            f"Layer {normalized_layer_ref} is too large to scan: "
                            f"{layer_size} bytes (max: {self.max_layer_file_size})"
                        ),
                        severity=IssueSeverity.INFO,
                        location=f"{path}:{layer_ref}",
                        details={
                            "layer": layer_ref,
                            "normalized_layer": normalized_layer_ref,
                            "size": layer_size,
                            "max_file_size": self.max_layer_file_size,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "oci_layer_size_limit_exceeded",
                        },
                        rule_code="S902",
                    )
                    continue

                gzip_metrics = self._gzip_stream_metrics(layer_path)
                gzip_structure_budget_failures = {
                    "header_limit_exceeded",
                    "member_count_exceeded",
                    "metadata_limit_exceeded",
                    "padding_limit_exceeded",
                }
                if gzip_metrics.failure in gzip_structure_budget_failures:
                    scan_complete = False
                    self._add_layer_budget_check(
                        result,
                        manifest_path=path,
                        layer_ref=layer_ref,
                        reason="oci_layer_gzip_structure_limit_exceeded",
                        message=(
                            f"Layer {normalized_layer_ref} gzip structure exceeded safety limits: "
                            f"{gzip_metrics.failure.replace('_', ' ')}"
                        ),
                        details={
                            "gzip_members": gzip_metrics.member_count,
                            "failure": gzip_metrics.failure,
                        },
                    )
                    continue
                if gzip_metrics.failure is not None:
                    raise tarfile.ReadError(f"gzip preflight failed: {gzip_metrics.failure.replace('_', ' ')}")

                tar_metrics = gzip_metrics.tar
                if tar_metrics is not None and tar_metrics.metadata_limit_exceeded:
                    scan_complete = False
                    self._add_layer_budget_check(
                        result,
                        manifest_path=path,
                        layer_ref=layer_ref,
                        reason="oci_layer_tar_metadata_limit_exceeded",
                        message=(
                            f"Layer {normalized_layer_ref} TAR metadata exceeded limit "
                            f"({tar_metrics.metadata_bytes} > {tar_metrics.max_metadata_bytes})"
                        ),
                        details={
                            "metadata_bytes": tar_metrics.metadata_bytes,
                            "max_metadata_bytes": tar_metrics.max_metadata_bytes,
                            "raw_entries": tar_metrics.raw_entries,
                            "hidden_entries": tar_metrics.hidden_entries,
                        },
                    )
                    continue

                compressed_budget_size = gzip_metrics.compressed_size or layer_size
                preflight_member_limit: int | None = None
                if gzip_metrics.size_exceeded:
                    scan_complete = False
                    self._add_layer_budget_check(
                        result,
                        manifest_path=path,
                        layer_ref=layer_ref,
                        reason="oci_layer_decompressed_size_exceeded",
                        message=(
                            f"Layer {normalized_layer_ref} decompressed size exceeded limit "
                            f"({gzip_metrics.decompressed_size} > {self.max_decompressed_bytes})"
                        ),
                        details={
                            "decompressed_size": gzip_metrics.decompressed_size,
                            "compressed_size": compressed_budget_size,
                            "max_decompressed_size": self.max_decompressed_bytes,
                        },
                    )
                    preflight_member_limit = gzip_metrics.safe_tar_entries
                    if preflight_member_limit == 0:
                        continue

                if gzip_metrics.ratio_exceeded:
                    scan_complete = False
                    ratio = gzip_metrics.ratio_decompressed_size / gzip_metrics.ratio_compressed_size
                    self._add_layer_budget_check(
                        result,
                        manifest_path=path,
                        layer_ref=layer_ref,
                        reason="oci_layer_decompression_ratio_exceeded",
                        message=(
                            f"Layer {normalized_layer_ref} decompression ratio exceeded limit "
                            f"({ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
                        ),
                        details={
                            "decompressed_size": gzip_metrics.ratio_decompressed_size,
                            "compressed_size": gzip_metrics.ratio_compressed_size,
                            "max_ratio": self.max_decompression_ratio,
                            "actual_ratio": ratio,
                        },
                    )
                    preflight_member_limit = gzip_metrics.safe_tar_entries
                    if preflight_member_limit == 0:
                        continue

                hidden_entries_exceeded_limit = (
                    tar_metrics is not None
                    and tar_metrics.hidden_entries > 0
                    and tar_metrics.raw_entries > self.max_layer_entries
                )
                hidden_entry_hard_limit = max(self.max_layer_entries, self._MIN_MAX_HIDDEN_TAR_ENTRIES)
                hidden_entry_hard_limit_exceeded = (
                    tar_metrics is not None and tar_metrics.hidden_entries > hidden_entry_hard_limit
                )
                if hidden_entries_exceeded_limit or hidden_entry_hard_limit_exceeded:
                    assert tar_metrics is not None
                    scan_complete = False
                    self._add_layer_budget_check(
                        result,
                        manifest_path=path,
                        layer_ref=layer_ref,
                        reason="oci_layer_entry_count_exceeded",
                        message=(
                            f"Layer {normalized_layer_ref} contains too many raw TAR entries "
                            f"({tar_metrics.raw_entries} > {self.max_layer_entries})"
                        ),
                        details={
                            "entries": tar_metrics.raw_entries,
                            "hidden_entries": tar_metrics.hidden_entries,
                            "max_entries": self.max_layer_entries,
                        },
                    )
                    if hidden_entry_hard_limit_exceeded:
                        continue
                    hidden_entry_member_limit = tar_metrics.visible_entries_within_limit
                    if hidden_entry_member_limit == 0:
                        continue
                    if preflight_member_limit is None:
                        preflight_member_limit = hidden_entry_member_limit
                    else:
                        preflight_member_limit = min(preflight_member_limit, hidden_entry_member_limit)

                layer_entry_count = 0
                metadata_state = _LayerMetadataState()
                with tarfile.open(layer_path, "r:gz") as tar:
                    while preflight_member_limit is None or layer_entry_count < preflight_member_limit:
                        member = tar.next()
                        if member is None:
                            break
                        layer_entry_count += 1
                        if layer_entry_count > self.max_layer_entries:
                            scan_complete = False
                            self._add_layer_budget_check(
                                result,
                                manifest_path=path,
                                layer_ref=layer_ref,
                                reason="oci_layer_entry_count_exceeded",
                                message=(
                                    f"Layer {self._normalize_layer_ref(layer_ref)} contains too many entries "
                                    f"({layer_entry_count} > {self.max_layer_entries})"
                                ),
                                details={"entries": layer_entry_count, "max_entries": self.max_layer_entries},
                            )
                            break

                        metadata_valid, should_scan_member = self._validate_layer_member_metadata(
                            result,
                            manifest_path=path,
                            layer_ref=layer_ref,
                            member=member,
                            state=metadata_state,
                        )
                        if not metadata_valid:
                            scan_complete = False
                        if not should_scan_member:
                            continue
                        name = member.name
                        matched_ext = self._get_scannable_extension(name)
                        if self.max_layer_file_size > 0 and member.size > self.max_layer_file_size:
                            scan_complete = False
                            self._mark_incomplete_coverage(result, "oci_member_size_limit_exceeded")
                            result.add_check(
                                name="Layer Member Size Check",
                                passed=False,
                                message=(
                                    f"Layer member {name} is too large to scan: "
                                    f"{member.size} bytes (max: {self.max_layer_file_size})"
                                ),
                                severity=IssueSeverity.INFO,
                                location=f"{path}:{layer_ref}:{name}",
                                details={
                                    "layer": layer_ref,
                                    "member": name,
                                    "size": member.size,
                                    "max_file_size": self.max_layer_file_size,
                                    "analysis_incomplete": True,
                                    "scan_outcome_reason": "oci_member_size_limit_exceeded",
                                },
                                rule_code="S902",
                            )
                            continue

                        fileobj = tar.extractfile(member)
                        if fileobj is None:
                            scan_complete = False
                            self._mark_incomplete_coverage(result, "oci_member_extraction_failed")
                            result.add_check(
                                name="Layer Member Extraction",
                                passed=False,
                                message=f"Layer member {name} was not extracted from {layer_ref}",
                                severity=IssueSeverity.INFO,
                                location=f"{path}:{layer_ref}:{name}",
                                details={
                                    "layer": layer_ref,
                                    "member": name,
                                    "analysis_incomplete": True,
                                    "scan_outcome_reason": "oci_member_extraction_failed",
                                },
                                rule_code="S902",
                            )
                            continue
                        header_prefix = b""
                        tmp_path: str | None = None
                        try:
                            if matched_ext is None:
                                header_prefix = fileobj.read(self._MEMBER_HEADER_PROBE_BYTES)

                            with tempfile.NamedTemporaryFile(
                                suffix=matched_ext or "",
                                delete=False,
                            ) as tmp:
                                tmp_path = tmp.name
                                if header_prefix:
                                    tmp.write(header_prefix)
                                shutil.copyfileobj(fileobj, tmp)

                            from .. import core

                            nested_config = dict(self.config)
                            # Extracted members are deleted below, so their temporary paths are not reusable cache keys.
                            nested_config["cache_enabled"] = False
                            try:
                                _oci_depth = int(nested_config.get("_archive_depth", 0))
                            except (TypeError, ValueError):
                                _oci_depth = 0
                            nested_config["_archive_depth"] = max(_oci_depth, 0) + 1

                            file_result = core.scan_file(tmp_path, nested_config)
                            detected_suffix = self._get_detected_format_suffix(tmp_path)
                            if (
                                file_result.scanner_name == "unknown"
                                and detected_suffix
                                and not tmp_path.endswith(detected_suffix)
                            ):
                                retargeted_path = f"{tmp_path}{detected_suffix}"
                                os.replace(tmp_path, retargeted_path)
                                tmp_path = retargeted_path
                                file_result = core.scan_file(tmp_path, nested_config)
                            for check in file_result.checks:
                                check.location = self._rewrite_embedded_location(
                                    check.location,
                                    manifest_path=path,
                                    layer_ref=layer_ref,
                                    member_name=name,
                                    extracted_path=tmp_path,
                                )
                            for issue in file_result.issues:
                                issue.location = self._rewrite_embedded_location(
                                    issue.location,
                                    manifest_path=path,
                                    layer_ref=layer_ref,
                                    member_name=name,
                                    extracted_path=tmp_path,
                                )
                                if issue.details is None:
                                    issue.details = {}
                                issue.details["layer"] = layer_ref
                            self._merge_nested_result(result, file_result)
                            if not file_result.success or file_result.has_errors:
                                scan_complete = False
                        finally:
                            fileobj.close()
                            if tmp_path and os.path.exists(tmp_path):
                                os.unlink(tmp_path)
            except Exception as e:
                scan_complete = False
                self._mark_incomplete_coverage(result, "oci_layer_processing_failed")
                result.add_check(
                    name="Layer Processing",
                    passed=False,
                    message=f"Error processing layer {layer_ref}: {e}",
                    severity=IssueSeverity.INFO,
                    location=f"{path}:{layer_ref}",
                    details={
                        "exception_type": type(e).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "oci_layer_processing_failed",
                    },
                    rule_code="S902",
                )

        result.finish(success=scan_complete and not result.has_errors)
        return result
