"""Scanner for OCI container image layers containing model artifacts."""

import json
import math
import os
import shutil
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from ..scanner_results import mark_inconclusive_scan_result
from ..utils import is_within_directory, sanitize_archive_path
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
    _GZIP_OUTPUT_CHUNK_BYTES: ClassVar[int] = 1024 * 1024
    _GZIP_TRAILER_BYTES: ClassVar[int] = 8
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
        normalized_value = float(value)
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
        *,
        stop_after_decompressed: int | None = None,
    ) -> tuple[int | None, int, bool]:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        completed_compressed = 0
        completed_decompressed = 0
        member_compressed = 0
        member_decompressed = 0
        with open(layer_path, "rb") as layer_file:
            data = b""
            while True:
                if not data:
                    data = layer_file.read(self._GZIP_CHUNK_BYTES)
                    if not data:
                        break

                while data:
                    decompressed_before = completed_decompressed + member_decompressed
                    if stop_after_decompressed is not None and decompressed_before >= stop_after_decompressed:
                        return completed_compressed + member_compressed or None, decompressed_before, False

                    try:
                        compressed_input = data
                        withheld = b""
                        if len(data) > self._GZIP_TRAILER_BYTES:
                            compressed_input = data[: -self._GZIP_TRAILER_BYTES]
                            withheld = data[-self._GZIP_TRAILER_BYTES :]
                        before_len = len(compressed_input)
                        output_limit = self._GZIP_OUTPUT_CHUNK_BYTES
                        if stop_after_decompressed is not None:
                            output_limit = min(output_limit, stop_after_decompressed - decompressed_before)
                        output = decompressor.decompress(compressed_input, output_limit)
                    except zlib.error:
                        return (
                            completed_compressed + member_compressed or None,
                            completed_decompressed + member_decompressed,
                            False,
                        )
                    member_compressed += before_len - len(decompressor.unconsumed_tail) - len(decompressor.unused_data)
                    member_decompressed += len(output)
                    compressed_consumed = completed_compressed + member_compressed
                    decompressed_seen = completed_decompressed + member_decompressed
                    if stop_after_decompressed is not None and decompressed_seen >= stop_after_decompressed:
                        return compressed_consumed, decompressed_seen, False
                    if decompressed_seen > self.max_decompressed_bytes:
                        return compressed_consumed, decompressed_seen, True
                    if decompressor.eof:
                        completed_compressed = compressed_consumed
                        completed_decompressed = decompressed_seen
                        data = decompressor.unused_data + withheld
                        while len(data) < 2:
                            chunk = layer_file.read(self._GZIP_CHUNK_BYTES)
                            if not chunk:
                                return completed_compressed, completed_decompressed, False
                            data += chunk
                        if not data.startswith(b"\x1f\x8b"):
                            return completed_compressed, completed_decompressed, False
                        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        member_compressed = 0
                        member_decompressed = 0
                        continue
                    data = decompressor.unconsumed_tail + withheld
        if decompressor.eof:
            return completed_compressed, completed_decompressed, False
        return (
            completed_compressed + member_compressed or None,
            completed_decompressed + member_decompressed,
            False,
        )

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

                gzip_compressed_size, gzip_decompressed_size, gzip_decompressed_size_exceeded = (
                    self._gzip_stream_metrics(layer_path)
                )
                compressed_budget_size = gzip_compressed_size or layer_size
                layer_entry_count = 0
                layer_payload_size = 0
                layer_budget_exhausted = False
                tar_stream_end = 0
                with tarfile.open(layer_path, "r:gz") as tar:
                    for member in tar:
                        layer_entry_count += 1
                        if layer_entry_count > self.max_layer_entries:
                            scan_complete = False
                            layer_budget_exhausted = True
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

                        layer_payload_size += max(0, member.size)
                        decompressed_size = max(layer_payload_size, tar.offset)
                        ratio = (decompressed_size / compressed_budget_size) if compressed_budget_size > 0 else 0.0
                        if decompressed_size > self.max_decompressed_bytes:
                            scan_complete = False
                            layer_budget_exhausted = True
                            self._add_layer_budget_check(
                                result,
                                manifest_path=path,
                                layer_ref=layer_ref,
                                reason="oci_layer_decompressed_size_exceeded",
                                message=(
                                    f"Layer {self._normalize_layer_ref(layer_ref)} decompressed size exceeded limit "
                                    f"({decompressed_size} > {self.max_decompressed_bytes})"
                                ),
                                details={
                                    "decompressed_size": decompressed_size,
                                    "compressed_size": compressed_budget_size,
                                    "max_decompressed_size": self.max_decompressed_bytes,
                                    "entries": layer_entry_count,
                                },
                            )
                            break

                        if compressed_budget_size > 0 and ratio > self.max_decompression_ratio:
                            scan_complete = False
                            layer_budget_exhausted = True
                            self._add_layer_budget_check(
                                result,
                                manifest_path=path,
                                layer_ref=layer_ref,
                                reason="oci_layer_decompression_ratio_exceeded",
                                message=(
                                    f"Layer {self._normalize_layer_ref(layer_ref)} decompression ratio exceeded limit "
                                    f"({ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
                                ),
                                details={
                                    "decompressed_size": decompressed_size,
                                    "compressed_size": compressed_budget_size,
                                    "max_ratio": self.max_decompression_ratio,
                                    "actual_ratio": ratio,
                                    "entries": layer_entry_count,
                                },
                            )
                            break

                        if not member.isfile():
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
                    tar_stream_end = tar.offset
                if not layer_budget_exhausted:
                    if gzip_decompressed_size_exceeded or gzip_decompressed_size > self.max_decompressed_bytes:
                        scan_complete = False
                        self._add_layer_budget_check(
                            result,
                            manifest_path=path,
                            layer_ref=layer_ref,
                            reason="oci_layer_decompressed_size_exceeded",
                            message=(
                                f"Layer {self._normalize_layer_ref(layer_ref)} decompressed size exceeded limit "
                                f"({gzip_decompressed_size} > {self.max_decompressed_bytes})"
                            ),
                            details={
                                "decompressed_size": gzip_decompressed_size,
                                "compressed_size": compressed_budget_size,
                                "max_decompressed_size": self.max_decompressed_bytes,
                                "entries": layer_entry_count,
                            },
                        )
                    elif compressed_budget_size > 0:
                        ratio_decompressed_size = gzip_decompressed_size
                        ratio_compressed_size = compressed_budget_size
                        final_ratio = ratio_decompressed_size / ratio_compressed_size
                        expected_tar_stream_size = (
                            (max(tar_stream_end, layer_payload_size) + (2 * tarfile.BLOCKSIZE) + tarfile.RECORDSIZE - 1)
                            // tarfile.RECORDSIZE
                        ) * tarfile.RECORDSIZE
                        if gzip_decompressed_size > expected_tar_stream_size:
                            tar_compressed_size, _, _ = self._gzip_stream_metrics(
                                layer_path,
                                stop_after_decompressed=expected_tar_stream_size,
                            )
                            if tar_compressed_size is not None:
                                tar_ratio = expected_tar_stream_size / tar_compressed_size
                                if tar_ratio > final_ratio:
                                    final_ratio = tar_ratio
                                    ratio_compressed_size = tar_compressed_size
                                    ratio_decompressed_size = expected_tar_stream_size
                        if final_ratio > self.max_decompression_ratio:
                            scan_complete = False
                            self._add_layer_budget_check(
                                result,
                                manifest_path=path,
                                layer_ref=layer_ref,
                                reason="oci_layer_decompression_ratio_exceeded",
                                message=(
                                    f"Layer {self._normalize_layer_ref(layer_ref)} decompression ratio exceeded limit "
                                    f"({final_ratio:.1f}x > {self.max_decompression_ratio:.1f}x)"
                                ),
                                details={
                                    "decompressed_size": ratio_decompressed_size,
                                    "compressed_size": ratio_compressed_size,
                                    "max_ratio": self.max_decompression_ratio,
                                    "actual_ratio": final_ratio,
                                    "entries": layer_entry_count,
                                },
                            )
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
