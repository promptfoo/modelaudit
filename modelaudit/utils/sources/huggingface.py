"""Utilities for handling HuggingFace model downloads."""

import hashlib
import json
import logging
import ntpath
import os
import posixpath
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Collection, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from functools import cache
from glob import escape as escape_glob
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast, overload
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from ..file.detection import detect_file_format_for_skip_filter
from ..helpers.disk_space import check_disk_space
from .huggingface_paths import (
    extract_model_id_from_path,
    is_huggingface_cache_path,
    is_huggingface_file_url,
    is_huggingface_url,
    parse_huggingface_file_url,
    parse_huggingface_url,
    parse_huggingface_url_with_revision,
    redact_huggingface_url_for_display,
    redact_huggingface_urls_in_text,
)

logger = logging.getLogger(__name__)

_HF_CONTENT_SNIFF_BYTES = 8 * 1024
_HF_CONTENT_SNIFF_MAX_FILES = 256
_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_BYTES = b"TFL3"
_MAX_HF_STREAMING_EXTENSIONLESS_FILES = 128
_HF_SAFETENSORS_STRICT_RANGE_REDIRECTS = 5
_HF_SAFETENSORS_RANGE_ATTEMPTS = 3
_HF_SAFETENSORS_OVERLAP_PROBE_BYTES = 64 * 1024
_HF_SAFETENSORS_OVERLAP_TAIL_PROBE_BYTES = 128 * 1024
_HF_SAFETENSORS_TORCH7_PROBE_BYTES = 4 * 1024
_MAX_HF_SAFETENSORS_INDEX_BYTES = 32 * 1024 * 1024
_MAX_HF_SAFETENSORS_INDEX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_HF_SAFETENSORS_INDEX_TENSORS = 250_000
_MAX_HF_SAFETENSORS_INDEX_JSON_TOKENS = (2 * _MAX_HF_SAFETENSORS_INDEX_TENSORS) + 4096
_MAX_HF_SAFETENSORS_INDEX_DETAIL_ITEMS = 20
_HF_SAFETENSORS_REMOTE_OVERLAP_REASON = "remote_safetensors_overlap_coverage_incomplete"
_MAX_HF_STREAMING_ONNX_EXTERNAL_DATA_FILES = 256
_MAX_HF_STREAMING_UNBOUNDED_INCLUDE_ALL_EXTRA_FILES = 128
_MAX_HF_REPOSITORY_INVENTORY_FILES = 8192
_MAX_HF_REPOSITORY_INVENTORY_PAGES = 128
_MAX_HF_REPOSITORY_TREE_PAGE_RESPONSE_BYTES = 10 * 1024 * 1024
_MAX_HF_REPOSITORY_PATH_CHARS = 4096
_HF_REPOSITORY_TREE_RESPONSE_CHUNK_BYTES = 64 * 1024
_HF_PATH_INFO_BATCH_SIZE = 512
_HF_DOWNLOAD_WORKER_RESULT_PREFIX = "MODELAUDIT_HF_DOWNLOAD_RESULT="
_POSIX_TERMINATE_SIGNAL = getattr(signal, "SIGTERM", 15)
_POSIX_KILL_SIGNAL = getattr(signal, "SIGKILL", 9)
_HF_SAFETENSORS_SHARD_PATTERN = re.compile(
    r"(?P<stem>.+)-(?P<index>\d{5})-of-(?P<total>\d{5})\.safetensors",
    re.IGNORECASE,
)
_HF_SAFETENSORS_SHARD_SHAPE_PATTERN = re.compile(
    r".+-\d+-of-\d+\.safetensors",
    re.IGNORECASE,
)
_HF_REPO_BOOKKEEPING_FILENAMES = frozenset({".gitattributes"})

__all__ = [
    "download_file_from_hf",
    "download_model",
    "extract_model_id_from_path",
    "get_model_info",
    "get_model_size",
    "is_huggingface_cache_path",
    "is_huggingface_file_url",
    "is_huggingface_url",
    "parse_huggingface_file_url",
    "parse_huggingface_url",
    "parse_huggingface_url_with_revision",
    "plan_huggingface_model_download",
    "plan_huggingface_streaming_download",
    "redact_huggingface_url_for_display",
    "redact_huggingface_urls_in_text",
]


@dataclass
class _HuggingFaceProbeBudget:
    remaining_bytes: int
    deadline: float | None = None
    file_sizes: dict[str, int] = field(default_factory=dict)
    prefixes: dict[str, bytes] = field(default_factory=dict)
    transferred_bytes: int = 0

    def reserve(self, repo_id: str, max_bytes: int) -> None:
        """Reserve a bounded remote read or fail closed before issuing it."""
        if max_bytes <= 0 or max_bytes > self.remaining_bytes:
            raise ValueError(
                "Hugging Face selective filtering incomplete: skipped file inspection byte limit exceeded "
                f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES} bytes)"
            )
        self.remaining_bytes -= max_bytes

    def refund(self, byte_count: int) -> None:
        """Return unused reserved bytes after a response proves an earlier EOF."""
        self.remaining_bytes += max(byte_count, 0)

    def request_timeout(self, repo_id: str) -> float:
        """Return a per-request timeout bounded by the overall acquisition deadline."""
        if self.deadline is None:
            return 30.0
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
        return min(30.0, remaining)

    def check_deadline(self, repo_id: str) -> None:
        """Fail when the end-to-end acquisition deadline has expired."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

    def record_file_size(self, repo_id: str, filename: str, file_size: int) -> None:
        """Record immutable remote size evidence and reject inconsistent responses."""
        previous_size = self.file_sizes.get(filename)
        if previous_size is not None and previous_size != file_size:
            raise ValueError(
                f"Hugging Face selective filtering incomplete: inconsistent skipped file size for {repo_id}/{filename}"
            )
        self.file_sizes[filename] = file_size


class _SparseRangeReader:
    """Seekable bounded view over known remote ranges without allocating gaps."""

    def __init__(self, size: int, ranges: Collection[tuple[int, bytes]]) -> None:
        self._size = size
        self._ranges = tuple(ranges)
        self._position = 0

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError(f"invalid seek mode: {whence}")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        if self._position >= self._size:
            return b""
        read_size = self._size - self._position if size < 0 else min(size, self._size - self._position)
        start = self._position
        end = start + read_size
        output = bytearray(read_size)
        for range_start, range_bytes in self._ranges:
            range_end = range_start + len(range_bytes)
            overlap_start = max(start, range_start)
            overlap_end = min(end, range_end)
            if overlap_start < overlap_end:
                output[overlap_start - start : overlap_end - start] = range_bytes[
                    overlap_start - range_start : overlap_end - range_start
                ]
        self._position = end
        return bytes(output)


@dataclass(frozen=True)
class _HuggingFaceStrictRangeRead:
    data: bytes
    total_size: int
    validator: str
    final_url: str
    bytes_transferred: int


class _HuggingFaceRangeBudgetExceeded(ValueError):
    """Raised when a bounded range read would exceed the caller's byte budget."""


class _HuggingFaceStrictRangeError(RuntimeError):
    """Preserve bytes consumed before a strict range read failed."""

    def __init__(self, error: BaseException, bytes_transferred: int) -> None:
        super().__init__(str(error))
        self.error = error
        self.bytes_transferred = bytes_transferred


class _DuplicateAwareJsonObject(dict[str, Any]):
    """JSON object retaining values hidden by duplicate keys."""

    def __init__(self, values: dict[str, Any], overwritten_items: list[tuple[str, Any]]) -> None:
        super().__init__(values)
        self.overwritten_items = overwritten_items


def _remote_safetensors_source_path(repo_id: str, revision: str, filename: str) -> str:
    return f"hf://{repo_id}@{revision}/{filename}"


def _replace_remote_temp_path(value: Any, temp_path: str, source_path: str) -> Any:
    """Rewrite source-local temporary paths before records leave remote scanning."""
    if isinstance(value, str):
        return value.replace(temp_path, source_path)
    if isinstance(value, list):
        return [_replace_remote_temp_path(item, temp_path, source_path) for item in value]
    if isinstance(value, dict):
        return {key: _replace_remote_temp_path(item, temp_path, source_path) for key, item in value.items()}
    return value


def _is_trusted_huggingface_range_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    host = hostname.rstrip(".").lower()
    return (
        host in {"huggingface.co", "hf.co"}
        or host.endswith(".huggingface.co")
        or host.endswith(".hf.co")
        or host.endswith(".cloudfront.net")
    )


def _validate_huggingface_range_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Hugging Face range redirect used an untrusted scheme")
    if parsed.username or parsed.password:
        raise ValueError("Hugging Face range redirect used userinfo credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Hugging Face range redirect used an invalid port") from exc
    if port not in {None, 443}:
        raise ValueError("Hugging Face range redirect used an untrusted port")
    if not _is_trusted_huggingface_range_host(parsed.hostname):
        raise ValueError("Hugging Face range redirect used an untrusted final host")


def _range_response_validator(headers: Any) -> str:
    validator_parts: list[str] = []
    for key in ("ETag", "X-Linked-ETag", "X-Xet-Hash"):
        value = headers.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = value.strip()
        if normalized.lower().startswith("w/"):
            raise ValueError("Hugging Face range response used a weak object validator")
        validator_value = normalized.strip('"')
        if not validator_value:
            raise ValueError("Hugging Face range response used an empty object validator")
        validator_parts.append(f"{key.lower()}={validator_value}")
    if not validator_parts:
        raise ValueError("Hugging Face range response omitted a stable object validator")
    return ";".join(validator_parts)


def _parse_strict_content_range(
    response: Any,
    expected_size: int | None,
    max_bytes: int,
    start_offset: int,
) -> tuple[int, int]:
    content_range = response.headers.get("Content-Range", "")
    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range.strip(), flags=re.IGNORECASE)
    if match is None:
        raise ValueError("Hugging Face range response omitted a valid Content-Range")
    reported_start, end_offset, total_size = (int(value) for value in match.groups())
    if reported_start != start_offset:
        raise ValueError("Hugging Face range response returned an unexpected start offset")
    if expected_size is not None and total_size != expected_size:
        raise ValueError("Hugging Face range response size changed during header scan")
    expected_bytes = min(max(total_size - start_offset, 0), max_bytes)
    if end_offset - start_offset + 1 != expected_bytes:
        raise ValueError("Hugging Face range response returned an unexpected byte range")
    return expected_bytes, total_size


def _interrupt_huggingface_range_response(response: Any) -> None:
    """Interrupt a blocking Requests body read at the hard acquisition deadline."""
    import socket

    raw_response = getattr(response, "raw", None)
    connection = getattr(raw_response, "_connection", None)
    sock = getattr(connection, "sock", None)
    if sock is None:
        response_fp = getattr(getattr(raw_response, "_fp", None), "fp", None)
        sock = getattr(getattr(response_fp, "raw", None), "_sock", None)
    if sock is not None:
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            sock.close()
    if raw_response is not None:
        with suppress(Exception):
            raw_response.close()
    with suppress(Exception):
        response.close()


def _is_retryable_huggingface_range_error(error: BaseException) -> bool:
    """Return whether a remote range failure is likely transport-side, not evidence-side."""
    if isinstance(error, _HuggingFaceStrictRangeError):
        return _is_retryable_huggingface_range_error(error.error)
    try:
        import requests
    except Exception:
        return False

    if isinstance(
        error,
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ContentDecodingError,
            requests.exceptions.SSLError,
        ),
    ):
        return True
    if isinstance(error, requests.exceptions.HTTPError):
        status_code = getattr(getattr(error, "response", None), "status_code", None)
        return status_code in {408, 425, 429, 500, 502, 503, 504}
    return False


def _read_huggingface_strict_range(
    repo_id: str,
    filename: str,
    revision: str,
    max_bytes: int,
    *,
    expected_size: int | None,
    deadline: float | None,
    start_offset: int = 0,
) -> _HuggingFaceStrictRangeRead:
    """Read a trusted prefix range and reject ambiguous range or object identity semantics."""
    if max_bytes <= 0 or start_offset < 0:
        raise ValueError("Hugging Face range read size must be positive")

    import requests
    from huggingface_hub import hf_hub_url
    from huggingface_hub.utils import build_hf_headers

    request_deadline = _HuggingFaceProbeBudget(remaining_bytes=max_bytes, deadline=deadline)
    current_url = hf_hub_url(repo_id=repo_id, filename=filename, revision=revision)
    _validate_huggingface_range_url(current_url)
    headers = build_hf_headers(
        token=None,
        headers={
            "Range": f"bytes={start_offset}-{start_offset + max_bytes - 1}",
            "Accept-Encoding": "identity",
        },
    )
    current_headers = dict(headers)
    original_url = urlparse(current_url)
    original_origin = (original_url.scheme, original_url.hostname, original_url.port or 443)

    response = None
    for _redirect_count in range(_HF_SAFETENSORS_STRICT_RANGE_REDIRECTS + 1):
        request_deadline.check_deadline(repo_id)
        response = requests.get(
            current_url,
            headers=dict(current_headers),
            stream=True,
            timeout=request_deadline.request_timeout(repo_id),
            allow_redirects=False,
        )
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("Location")
            response.close()
            if not isinstance(location, str) or not location:
                raise ValueError("Hugging Face range redirect omitted a Location header")
            next_url = urljoin(current_url, location)
            _validate_huggingface_range_url(next_url)
            parsed_next_url = urlparse(next_url)
            next_origin = (parsed_next_url.scheme, parsed_next_url.hostname, parsed_next_url.port or 443)
            if next_origin != original_origin:
                current_headers = {
                    key: value
                    for key, value in current_headers.items()
                    if key.lower() not in {"authorization", "cookie"}
                }
            current_url = next_url
            continue
        break
    else:
        raise ValueError("Hugging Face range redirect limit exceeded")

    assert response is not None
    with response:
        response.raise_for_status()
        if response.status_code != 206:
            raise ValueError("Hugging Face server did not honor required range semantics")
        content_encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise ValueError("Hugging Face range response used encoded content")
        expected_bytes, total_size = _parse_strict_content_range(response, expected_size, max_bytes, start_offset)
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                parsed_content_length = int(content_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("Hugging Face range response used invalid Content-Length") from exc
            if parsed_content_length != expected_bytes:
                raise ValueError("Hugging Face range response Content-Length did not match Content-Range")
        validator = _range_response_validator(response.headers)

        chunks: list[bytes] = []
        total = 0
        chunk_size = min(64 * 1024, max(1, expected_bytes))
        deadline_timer = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
            import threading

            deadline_timer = threading.Timer(remaining, _interrupt_huggingface_range_response, args=(response,))
            deadline_timer.daemon = True
            deadline_timer.start()
        try:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue
                total += len(chunk)
                if total > expected_bytes:
                    raise ValueError("Hugging Face range response body exceeded declared range")
                chunks.append(chunk)
                request_deadline.check_deadline(repo_id)
                if total == expected_bytes:
                    break
            data = b"".join(chunks)
            if len(data) != expected_bytes:
                raise ValueError("Hugging Face range response ended before declared range")
        except Exception as exc:
            raise _HuggingFaceStrictRangeError(exc, total) from exc
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
        return _HuggingFaceStrictRangeRead(
            data=data,
            total_size=total_size,
            validator=validator,
            final_url=response.url,
            bytes_transferred=len(data),
        )


def _remote_safetensors_failure_result(
    repo_id: str,
    filename: str,
    revision: str,
    *,
    declared_size: int | None,
    bytes_transferred: int,
    reason: str,
    error: BaseException,
) -> Any:
    from ...core_results import mark_operational_scan_error
    from ...scanner_results import ScanResult, mark_inconclusive_scan_result
    from ...scanners.base import IssueSeverity

    source_path = _remote_safetensors_source_path(repo_id, revision, filename)
    result = ScanResult(scanner_name="safetensors")
    result.metadata.update(
        {
            "source_path": source_path,
            "remote_source_path": source_path,
            "hf_repo_id": repo_id,
            "hf_revision": revision,
            "hf_filename": filename,
            "file_size": declared_size,
            "remote_declared_size": declared_size,
            "remote_bytes_transferred": bytes_transferred,
            "remote_header_only": True,
            "analysis_scope": "safetensors_header_and_metadata",
        }
    )
    mark_inconclusive_scan_result(result, reason)
    mark_operational_scan_error(result, reason)
    result.add_check(
        name="Hugging Face SafeTensors Header Range Read",
        passed=False,
        message=f"Unable to inspect remote SafeTensors header: {type(error).__name__}",
        severity=IssueSeverity.INFO,
        location=source_path,
        details={
            "exception_type": type(error).__name__,
            "exception": redact_huggingface_urls_in_text(str(error)),
            "analysis_incomplete": True,
            "scan_outcome_reason": reason,
            "remote_bytes_transferred": bytes_transferred,
        },
    )
    result.bytes_scanned = bytes_transferred
    result.finish(success=False)
    return result


def _remote_safetensors_gzip_overlap_state(prefix: bytes, *, sample_is_prefix: bool) -> bool | None:
    """Classify a bounded gzip candidate without accepting magic alone."""
    if len(prefix) < 4 or prefix[:3] != b"\x1f\x8b\x08" or prefix[3] & 0xE0:
        return False

    import zlib

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decompressed = decompressor.decompress(prefix, _HF_SAFETENSORS_OVERLAP_PROBE_BYTES + 1)
    except zlib.error:
        return False
    if decompressor.eof or decompressor.unconsumed_tail or len(decompressed) > _HF_SAFETENSORS_OVERLAP_PROBE_BYTES:
        return True
    return None if sample_is_prefix else False


def _remote_safetensors_structural_overlap_scanner_ids(
    prefix: bytes,
    active_scanner_ids: Collection[str],
    *,
    file_size: int,
    include_pickle: bool,
) -> list[str]:
    from ..file.detection import classify_safetensors_pickle_overlap_sample, find_structural_torch7_offset

    active = {str(scanner_id).lower() for scanner_id in active_scanner_ids}
    matched: set[str] = set()
    if (
        "compressed" in active
        and _remote_safetensors_gzip_overlap_state(
            prefix,
            sample_is_prefix=len(prefix) < file_size,
        )
        is not False
    ):
        matched.add("compressed")
    if "torch7" in active and find_structural_torch7_offset(prefix[:_HF_SAFETENSORS_TORCH7_PROBE_BYTES]) == 0:
        matched.add("torch7")
    if include_pickle and "pickle" in active:
        pickle_state = classify_safetensors_pickle_overlap_sample(prefix, file_size=file_size)
        if pickle_state is not False:
            matched.add("pickle")
    return sorted(matched)


def _active_safetensors_overlap_scanner_ids(active_scanner_ids: Collection[str] | None) -> set[str]:
    overlap_ids = set(_hf_safetensors_route_scanner_ids()) - {"safetensors"}
    if active_scanner_ids is None:
        return overlap_ids
    active = {str(scanner_id).lower() for scanner_id in active_scanner_ids}
    return overlap_ids.intersection(active)


def _mark_remote_safetensors_overlap_incomplete(
    result: Any,
    *,
    source_path: str,
    overlap_scanner_ids: list[str],
    payload_bytes_downloaded: int,
) -> None:
    from ...core_results import mark_operational_scan_error
    from ...scanner_results import mark_inconclusive_scan_result
    from ...scanners.base import IssueSeverity

    result.add_check(
        name="Remote SafeTensors Overlap Coverage",
        passed=False,
        message="Remote SafeTensors header-only scan could not cover overlapping payload scanner evidence",
        severity=IssueSeverity.INFO,
        location=source_path,
        details={
            "remote_overlap_scanner_ids": overlap_scanner_ids,
            "analysis_incomplete": True,
            "scan_outcome_reason": _HF_SAFETENSORS_REMOTE_OVERLAP_REASON,
            "tensor_payload_bytes_downloaded": payload_bytes_downloaded,
        },
    )
    mark_inconclusive_scan_result(result, _HF_SAFETENSORS_REMOTE_OVERLAP_REASON)
    mark_operational_scan_error(result, _HF_SAFETENSORS_REMOTE_OVERLAP_REASON)
    result.finish(success=False)


def _scan_remote_huggingface_safetensors_header(
    repo_id: str,
    filename: str,
    revision: str,
    *,
    declared_size: int,
    deadline: float | None,
    shard_details: dict[str, Any] | None = None,
    max_transferred_bytes: int | None = None,
    scanner_config: dict[str, Any] | None = None,
    active_scanner_ids: Collection[str] | None = None,
) -> Any:
    """Inspect one remote SafeTensors header without downloading tensor payload bytes."""
    from ...scanners.base import FORMAT_VALIDATION_CONFIG_KEY
    from ...scanners.safetensors_scanner import (
        _REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY,
        _REMOTE_HEADER_INTEGRITY_CONFIG_KEY,
        _REMOTE_HEADER_ONLY_CONFIG_KEY,
        MAX_HEADER_BYTES,
        SafeTensorsScanner,
    )

    source_path = _remote_safetensors_source_path(repo_id, revision, filename)
    caller_scanner_config = dict(scanner_config or {})
    max_header_bytes = int(caller_scanner_config.get("max_safetensors_header_bytes", MAX_HEADER_BYTES))
    total_bytes_transferred = 0
    for attempt in range(_HF_SAFETENSORS_RANGE_ATTEMPTS):
        attempt_bytes_transferred = 0
        payload_probe = b""
        tail_probe = b""
        tail_probe_start = declared_size
        sparse_overlap_probes: list[tuple[int, bytes]] = []
        temp_path: str | None = None
        try:
            if max_transferred_bytes is not None and total_bytes_transferred + 8 > max_transferred_bytes:
                raise _HuggingFaceRangeBudgetExceeded("remote SafeTensors header length read exceeds max-size budget")
            first_range = _read_huggingface_strict_range(
                repo_id,
                filename,
                revision,
                8,
                expected_size=declared_size,
                deadline=deadline,
            )
            attempt_bytes_transferred += first_range.bytes_transferred
            if len(first_range.data) != 8:
                raise ValueError("SafeTensors header length range returned a short body")

            header_len = struct.unpack("<Q", first_range.data)[0]
            header_payload = first_range.data
            final_url = first_range.final_url
            validator = first_range.validator
            active_overlap_scanner_ids = _active_safetensors_overlap_scanner_ids(active_scanner_ids)
            overlap_scanner_ids: list[str] = []
            if 0 < header_len <= max_header_bytes and header_len <= declared_size - 8:
                projected_bytes = total_bytes_transferred + attempt_bytes_transferred + 8 + header_len
                if max_transferred_bytes is not None and projected_bytes > max_transferred_bytes:
                    raise _HuggingFaceRangeBudgetExceeded("remote SafeTensors header range exceeds max-size budget")
                header_range = _read_huggingface_strict_range(
                    repo_id,
                    filename,
                    revision,
                    8 + header_len,
                    expected_size=declared_size,
                    deadline=deadline,
                )
                attempt_bytes_transferred += header_range.bytes_transferred
                if header_range.data[:8] != first_range.data:
                    raise ValueError("Hugging Face SafeTensors header prefix changed between range reads")
                if header_range.validator != first_range.validator:
                    raise ValueError("Hugging Face SafeTensors object validator changed during header scan")
                if header_range.total_size != first_range.total_size:
                    raise ValueError("Hugging Face SafeTensors declared size changed during header scan")
                header_payload = header_range.data
                final_url = header_range.final_url
                validator = header_range.validator

                payload_size = declared_size - (8 + header_len)
                if payload_size > 0 and active_overlap_scanner_ids:
                    payload_probe_size = min(payload_size, _HF_SAFETENSORS_OVERLAP_PROBE_BYTES)
                    projected_bytes = total_bytes_transferred + attempt_bytes_transferred + payload_probe_size
                    if max_transferred_bytes is not None and projected_bytes > max_transferred_bytes:
                        raise _HuggingFaceRangeBudgetExceeded(
                            "remote SafeTensors overlap probe exceeds max-size budget"
                        )
                    payload_range = _read_huggingface_strict_range(
                        repo_id,
                        filename,
                        revision,
                        payload_probe_size,
                        expected_size=declared_size,
                        deadline=deadline,
                        start_offset=8 + header_len,
                    )
                    attempt_bytes_transferred += payload_range.bytes_transferred
                    if payload_range.validator != first_range.validator:
                        raise ValueError("Hugging Face SafeTensors object validator changed during overlap probe")
                    payload_probe = payload_range.data

                    if "keras_h5" in active_overlap_scanner_ids:
                        from ..file.hdf5 import (
                            HDF5_SUPERBLOCK_PROBE_BYTES,
                            has_plausible_hdf5_superblock,
                            hdf5_signature_offsets,
                        )

                        covered_prefix_end = 8 + header_len + len(payload_probe)
                        covered_prefix = header_payload + payload_probe
                        for signature_offset in hdf5_signature_offsets(
                            declared_size,
                            max_signature_scan_bytes=None,
                        ):
                            probe_size = min(HDF5_SUPERBLOCK_PROBE_BYTES, declared_size - signature_offset)
                            if signature_offset + probe_size <= covered_prefix_end:
                                if has_plausible_hdf5_superblock(
                                    covered_prefix[signature_offset : signature_offset + probe_size],
                                    signature_offset,
                                    declared_size,
                                ):
                                    overlap_scanner_ids = sorted({*overlap_scanner_ids, "keras_h5"})
                                    break
                                continue
                            projected_bytes = total_bytes_transferred + attempt_bytes_transferred + probe_size
                            if max_transferred_bytes is not None and projected_bytes > max_transferred_bytes:
                                raise _HuggingFaceRangeBudgetExceeded(
                                    "remote SafeTensors HDF5 overlap probes exceed max-size budget"
                                )
                            hdf5_range = _read_huggingface_strict_range(
                                repo_id,
                                filename,
                                revision,
                                probe_size,
                                expected_size=declared_size,
                                deadline=deadline,
                                start_offset=signature_offset,
                            )
                            attempt_bytes_transferred += hdf5_range.bytes_transferred
                            if hdf5_range.validator != first_range.validator:
                                raise ValueError(
                                    "Hugging Face SafeTensors object validator changed during HDF5 overlap probe"
                                )
                            sparse_overlap_probes.append((signature_offset, hdf5_range.data))
                            if has_plausible_hdf5_superblock(
                                hdf5_range.data,
                                signature_offset,
                                declared_size,
                            ):
                                overlap_scanner_ids = sorted({*overlap_scanner_ids, "keras_h5"})
                                break

                    zip_overlap_scanner_ids = active_overlap_scanner_ids.intersection(
                        _hf_route_scanner_ids_for_formats(frozenset({"zip"}))
                    )
                    payload_probe_end = 8 + header_len + len(payload_probe)
                    if zip_overlap_scanner_ids and declared_size > payload_probe_end:
                        tail_probe_size = min(
                            declared_size - payload_probe_end,
                            _HF_SAFETENSORS_OVERLAP_TAIL_PROBE_BYTES,
                        )
                        tail_probe_start = declared_size - tail_probe_size
                        projected_bytes = total_bytes_transferred + attempt_bytes_transferred + tail_probe_size
                        if max_transferred_bytes is not None and projected_bytes > max_transferred_bytes:
                            raise _HuggingFaceRangeBudgetExceeded(
                                "remote SafeTensors overlap tail probe exceeds max-size budget"
                            )
                        tail_range = _read_huggingface_strict_range(
                            repo_id,
                            filename,
                            revision,
                            tail_probe_size,
                            expected_size=declared_size,
                            deadline=deadline,
                            start_offset=tail_probe_start,
                        )
                        attempt_bytes_transferred += tail_range.bytes_transferred
                        if tail_range.validator != first_range.validator:
                            raise ValueError(
                                "Hugging Face SafeTensors object validator changed during overlap tail probe"
                            )
                        tail_probe = tail_range.data

                if active_overlap_scanner_ids:
                    frame_probe = header_payload + payload_probe
                    structural_overlap_scanner_ids = _remote_safetensors_structural_overlap_scanner_ids(
                        frame_probe,
                        active_overlap_scanner_ids,
                        file_size=declared_size,
                        include_pickle=True,
                    )
                    overlap_scanner_ids = sorted({*overlap_scanner_ids, *structural_overlap_scanner_ids})

            bytes_transferred = total_bytes_transferred + attempt_bytes_transferred
            suffix = ".safetensors" if not Path(filename).suffix else Path(filename).suffix
            with tempfile.NamedTemporaryFile(
                prefix="modelaudit_hf_safetensors_",
                suffix=suffix,
                delete=False,
            ) as temp_file:
                temp_path = temp_file.name
                temp_file.write(header_payload)
                temp_file.write(payload_probe)

            if active_overlap_scanner_ids:
                import zipfile

                sparse_ranges = [
                    (0, header_payload),
                    (len(header_payload), payload_probe),
                    (tail_probe_start, tail_probe),
                    *sparse_overlap_probes,
                ]
                if zipfile.is_zipfile(_SparseRangeReader(declared_size, sparse_ranges)):
                    overlap_scanner_ids = sorted(
                        set(overlap_scanner_ids).union(
                            active_overlap_scanner_ids.intersection(
                                _hf_route_scanner_ids_for_formats(frozenset({"zip"}))
                            )
                        )
                    )

            integrity_details: dict[str, Any] = {
                "hf_repo_id": repo_id,
                "hf_revision": revision,
                "hf_filename": filename,
                "remote_source_path": source_path,
                "remote_declared_size": declared_size,
                "remote_header_len": header_len,
                "remote_bytes_transferred": bytes_transferred,
                "remote_object_validator": validator,
                "remote_final_host": urlparse(final_url).hostname,
                "range_semantics": "strict_206_content_range",
                "range_attempts": attempt + 1,
                "tensor_payload_bytes_downloaded": (
                    len(payload_probe)
                    + len(tail_probe)
                    + sum(len(probe_bytes) for _, probe_bytes in sparse_overlap_probes)
                ),
            }
            remote_scanner_config = dict(caller_scanner_config)
            remote_scanner_config.update(
                {
                    FORMAT_VALIDATION_CONFIG_KEY: {
                        "path": os.path.abspath(temp_path),
                        "file_type_valid": True,
                        "header_format": "safetensors",
                        "extension_format": "safetensors",
                    },
                    _REMOTE_HEADER_ONLY_CONFIG_KEY: True,
                    _REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY: bytes_transferred,
                    _REMOTE_HEADER_INTEGRITY_CONFIG_KEY: integrity_details,
                }
            )
            scanner = SafeTensorsScanner(
                config=remote_scanner_config,
            )
            result = scanner.scan(temp_path)
            for record in [*result.checks, *result.issues]:
                record_value = cast(Any, record)
                if getattr(record_value, "location", None) == temp_path:
                    record_value.location = source_path
                record_value.details = _replace_remote_temp_path(record_value.details, temp_path, source_path)
            result.metadata.update(integrity_details)
            result.metadata.update(
                {
                    "source_path": source_path,
                    "remote_source_path": source_path,
                    "file_size": declared_size,
                    "remote_header_only": True,
                    "analysis_scope": "safetensors_header_and_metadata",
                    "content_hash_unavailable_reason": "remote_safetensors_header_only",
                    "tensor_payload_bytes_downloaded": integrity_details["tensor_payload_bytes_downloaded"],
                }
            )
            if shard_details is not None:
                from ...scanners.base import IssueSeverity

                evaluated_shard_details = dict(shard_details)
                expected_tensor_digest = evaluated_shard_details.get("index_tensor_names_digest")
                actual_tensor_digest = result.metadata.get("tensor_names_digest")
                if (
                    evaluated_shard_details.get("index_referenced_by_manifest")
                    and isinstance(expected_tensor_digest, str)
                    and expected_tensor_digest != actual_tensor_digest
                ):
                    evaluated_shard_details.update(
                        {
                            "complete": False,
                            "index_complete": False,
                            "index_incomplete_reason": "index_tensor_assignment_mismatch",
                            "message": "Remote SafeTensors index tensor assignments do not match the shard header.",
                        }
                    )
                result.metadata["remote_shard_family"] = evaluated_shard_details
                result.add_check(
                    name="Hugging Face SafeTensors Shard Coverage",
                    passed=bool(evaluated_shard_details.get("complete")),
                    message=str(evaluated_shard_details.get("message", "Remote SafeTensors shard coverage evaluated")),
                    severity=None if evaluated_shard_details.get("complete") else IssueSeverity.INFO,
                    location=source_path,
                    details=evaluated_shard_details,
                )
                if not evaluated_shard_details.get("complete"):
                    from ...scanner_results import mark_inconclusive_scan_result

                    mark_inconclusive_scan_result(result, "remote_safetensors_shard_coverage_incomplete")
                    result.finish(success=False)
            if overlap_scanner_ids:
                result.metadata["remote_overlap_scanner_ids"] = overlap_scanner_ids
                _mark_remote_safetensors_overlap_incomplete(
                    result,
                    source_path=source_path,
                    overlap_scanner_ids=overlap_scanner_ids,
                    payload_bytes_downloaded=int(integrity_details["tensor_payload_bytes_downloaded"]),
                )
            result.bytes_scanned = bytes_transferred
            return result
        except Exception as exc:
            if isinstance(exc, _HuggingFaceStrictRangeError):
                attempt_bytes_transferred += exc.bytes_transferred
            total_bytes_transferred += attempt_bytes_transferred
            if not _is_retryable_huggingface_range_error(exc) or attempt + 1 >= _HF_SAFETENSORS_RANGE_ATTEMPTS:
                reason = (
                    "remote_safetensors_header_max_size_exceeded"
                    if isinstance(exc, _HuggingFaceRangeBudgetExceeded)
                    else "remote_safetensors_header_range_failed"
                )
                return _remote_safetensors_failure_result(
                    repo_id,
                    filename,
                    revision,
                    declared_size=declared_size,
                    bytes_transferred=total_bytes_transferred,
                    reason=reason,
                    error=exc,
                )
            retry_delay = 0.25 * (attempt + 1)
            if deadline is not None:
                retry_delay = min(retry_delay, max(0.0, deadline - time.monotonic()))
            if retry_delay > 0:
                time.sleep(retry_delay)
        finally:
            if temp_path is not None:
                with suppress(OSError):
                    Path(temp_path).unlink()

    raise AssertionError("unreachable SafeTensors range retry state")


def _remote_safetensors_filename_shard_details_by_file(
    model_files: list[str], repo_files: list[str]
) -> dict[str, dict[str, Any]]:
    """Return per-shard filename coverage details derived from the immutable repository listing."""
    from modelaudit.utils.file.handlers import ShardedModelDetector, _summarize_missing_shard_indices

    grouped: dict[tuple[str, str, int], dict[int, list[str]]] = {}
    selected = set(model_files)
    for filename in repo_files:
        match = ShardedModelDetector.match_shard_filename(PurePosixPath(filename).name)
        if match is None:
            continue
        expected_total = match.get("expected_total_shards")
        shard_index = match.get("current_shard_index")
        pattern = match.get("pattern")
        if (
            not isinstance(expected_total, int)
            or not isinstance(shard_index, int)
            or not isinstance(pattern, str)
            or expected_total <= 0
        ):
            continue
        parent = PurePosixPath(filename).parent.as_posix()
        key = (parent, pattern, expected_total)
        grouped.setdefault(key, {}).setdefault(shard_index, []).append(filename)

    details_by_file: dict[str, dict[str, Any]] = {}
    for (_parent, pattern, expected_total), by_index in grouped.items():
        missing_indices, missing_count, missing_truncated = _summarize_missing_shard_indices(
            set(by_index), expected_total
        )
        duplicate_indices = {index: names for index, names in by_index.items() if len(names) > 1}
        present_filenames = [name for names in by_index.values() for name in names]
        unselected = sorted(name for name in present_filenames if name not in selected)
        filename_pattern_authoritative = all(1 <= index <= expected_total for index in by_index)
        complete = (
            filename_pattern_authoritative
            and missing_count == 0
            and not duplicate_indices
            and not unselected
            and len(present_filenames) == expected_total
        )
        message = (
            f"All {expected_total} remote SafeTensors shard headers are selected for inspection."
            if complete
            else "Remote SafeTensors shard coverage is incomplete."
        )
        group_details: dict[str, Any] = {
            "complete": complete,
            "filename_pattern_complete": complete,
            "filename_pattern_authoritative": filename_pattern_authoritative,
            "message": message,
            "pattern": pattern,
            "expected_total_shards": expected_total,
            "present_total_shards": len(present_filenames),
            "missing_shard_count": missing_count,
            "missing_shard_indices": missing_indices[:20],
            "missing_shard_indices_truncated": missing_truncated or missing_count > 20,
            "duplicate_shard_count": len(duplicate_indices),
            "duplicate_shard_indices": sorted(duplicate_indices)[:20],
            "unselected_shard_count": len(unselected),
            "unselected_shards": unselected[:20],
            "unselected_shards_truncated": len(unselected) > 20,
        }
        for filename in present_filenames:
            if filename in selected:
                details_by_file[filename] = dict(group_details)
    return details_by_file


def _is_safetensors_index_file(filename: str) -> bool:
    return PurePosixPath(filename).name.lower().endswith(".safetensors.index.json")


def _remote_index_parent_prefix(index_filename: str) -> str:
    parent = PurePosixPath(index_filename).parent
    return "" if parent.as_posix() == "." else f"{parent.as_posix().rstrip('/')}/"


def _remote_safetensors_index_filename_family(
    index_filename: str,
    selected_safetensors: Collection[str],
) -> set[str]:
    """Return selected shards that the index filename can identify without parsing it."""
    index_family = index_filename[: -len(".safetensors.index.json")]
    standalone_name = f"{index_family}.safetensors".casefold()
    shard_prefix = f"{index_family}-".casefold()
    return {
        filename
        for filename in selected_safetensors
        if filename.casefold() == standalone_name
        or (filename.casefold().startswith(shard_prefix) and _has_hf_safetensors_shard_shape(filename))
    }


def _normalize_safetensors_index_shard_path(index_filename: str, shard_name: object) -> tuple[str | None, str | None]:
    if not isinstance(shard_name, str) or not shard_name:
        return None, "non-string or empty shard reference"
    if "\x00" in shard_name or "\\" in shard_name:
        return None, "invalid character in shard reference"
    if re.match(r"^[A-Za-z]:", shard_name):
        return None, "Windows-absolute shard reference"
    if (
        shard_name.startswith("/")
        or "//" in shard_name
        or any(part in {"", ".", ".."} for part in shard_name.split("/"))
    ):
        return None, "unsafe shard reference path"
    shard_path = PurePosixPath(shard_name)
    if shard_path.is_absolute() or any(part in {"", ".", ".."} for part in shard_path.parts):
        return None, "unsafe shard reference path"
    parent_prefix = _remote_index_parent_prefix(index_filename)
    return f"{parent_prefix}{shard_path.as_posix()}" if parent_prefix else shard_path.as_posix(), None


def _loads_json_without_duplicate_keys(raw: bytes) -> tuple[Any | None, list[str], int, str | None]:
    from ...scanners.safetensors_scanner import _validate_json_structural_token_limit

    duplicate_keys: list[str] = []
    duplicate_key_count = 0

    try:
        _validate_json_structural_token_limit(raw, _MAX_HF_SAFETENSORS_INDEX_JSON_TOKENS, "SafeTensors index")
    except ValueError as exc:
        return None, [], 0, str(exc)

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate_key_count
        obj: dict[str, Any] = {}
        seen: set[str] = set()
        overwritten_items: list[tuple[str, Any]] = []
        for key, value in pairs:
            if key in seen:
                duplicate_key_count += 1
                overwritten_items.append((key, obj[key]))
                if key not in duplicate_keys and len(duplicate_keys) < _MAX_HF_SAFETENSORS_INDEX_DETAIL_ITEMS:
                    duplicate_keys.append(key)
            seen.add(key)
            obj[key] = value
        return _DuplicateAwareJsonObject(obj, overwritten_items)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, [], 0, f"invalid UTF-8: {exc}"
    try:
        parsed = json.loads(text, object_pairs_hook=object_pairs_hook)
    except json.JSONDecodeError as exc:
        return None, [], duplicate_key_count, f"invalid JSON: {exc}"
    return parsed, sorted(duplicate_keys), duplicate_key_count, None


def _index_failure_details(
    index_filename: str,
    reason: str,
    *,
    bytes_transferred: int = 0,
    index_size: int | None = None,
    error: BaseException | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "complete": False,
        "index_complete": False,
        "index_manifest": index_filename,
        "index_bytes_transferred": bytes_transferred,
        "index_declared_size": index_size,
        "index_incomplete_reason": reason,
        "message": "Remote SafeTensors index coverage is incomplete.",
    }
    if error is not None:
        details["index_error_type"] = type(error).__name__
        details["index_error"] = redact_huggingface_urls_in_text(str(error))
    return details


def _tensor_name_digest(tensor_names: Collection[str], *, deadline: float | None = None) -> str:
    """Return an order-independent digest without retaining an unbounded name list."""
    digest = hashlib.sha256()
    sorted_names = sorted(tensor_names)
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("SafeTensors index reconciliation timed out")
    for index, name in enumerate(sorted_names):
        if index % 1024 == 0 and deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("SafeTensors index reconciliation timed out")
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("SafeTensors index reconciliation timed out")
    return digest.hexdigest()


def _merge_remote_index_details(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """Merge manifest evidence conservatively so a later manifest cannot erase failure."""
    if existing is None:
        merged = dict(incoming)
        merged["index_manifest_count"] = 1
        merged["index_manifests"] = [incoming.get("index_manifest")]
        return merged

    existing_complete = bool(existing.get("index_complete"))
    incoming_complete = bool(incoming.get("index_complete"))
    conflicting_tensors = (
        existing_complete
        and incoming_complete
        and existing.get("index_tensor_names_digest") != incoming.get("index_tensor_names_digest")
    )
    merged = dict(incoming if not incoming_complete else existing)
    manifests = [
        manifest
        for manifest in [*existing.get("index_manifests", []), incoming.get("index_manifest")]
        if isinstance(manifest, str)
    ]
    merged["index_manifest_count"] = int(existing.get("index_manifest_count", 1)) + 1
    merged["index_manifests"] = list(dict.fromkeys(manifests))[:_MAX_HF_SAFETENSORS_INDEX_DETAIL_ITEMS]
    merged["index_manifests_truncated"] = len(set(manifests)) > _MAX_HF_SAFETENSORS_INDEX_DETAIL_ITEMS
    merged["index_complete"] = existing_complete and incoming_complete and not conflicting_tensors
    merged["complete"] = merged["index_complete"]
    if conflicting_tensors:
        merged["index_incomplete_reason"] = "conflicting_index_tensor_assignments"
    if not merged["index_complete"]:
        merged["message"] = "Remote SafeTensors index coverage is incomplete."
    return merged


def _remote_safetensors_index_details_by_file(
    repo_id: str,
    model_files: list[str],
    repo_files: list[str],
    revision: str,
    path_sizes: dict[str, int | None],
    *,
    deadline: float | None,
    max_transferred_bytes: int | None,
) -> tuple[dict[str, dict[str, Any]], int, dict[str, bytes]]:
    """Return per-shard details from bounded SafeTensors index manifests."""
    selected_files = set(model_files)
    repo_file_set = set(repo_files)
    if not selected_files:
        return {}, 0, {}

    details_by_file: dict[str, dict[str, Any]] = {}

    def attach_details(filename: str, details: dict[str, Any]) -> None:
        details_by_file[filename] = _merge_remote_index_details(details_by_file.get(filename), details)

    total_index_bytes = 0
    acquired_index_bytes: dict[str, bytes] = {}
    for index_filename in sorted(filename for filename in repo_files if _is_safetensors_index_file(filename)):
        filename_family = _remote_safetensors_index_filename_family(index_filename, selected_files)
        if deadline is not None and time.monotonic() >= deadline:
            failure = _index_failure_details(index_filename, "index_reconciliation_timed_out")
            for filename in filename_family:
                attach_details(filename, failure)
            break
        parent_prefix = _remote_index_parent_prefix(index_filename)
        if not any(not parent_prefix or filename.startswith(parent_prefix) for filename in selected_files):
            continue

        index_size = path_sizes.get(index_filename)
        if index_size is None:
            failure = _index_failure_details(index_filename, "missing_index_size")
            for filename in filename_family:
                attach_details(filename, failure)
            continue
        if index_size > _MAX_HF_SAFETENSORS_INDEX_BYTES:
            failure = _index_failure_details(index_filename, "index_exceeds_limit", index_size=index_size)
            for filename in filename_family:
                attach_details(filename, failure)
            continue
        if total_index_bytes + index_size > _MAX_HF_SAFETENSORS_INDEX_TOTAL_BYTES:
            failure = _index_failure_details(
                index_filename, "aggregate_index_bytes_exceed_limit", index_size=index_size
            )
            for filename in filename_family:
                attach_details(filename, failure)
            continue
        if max_transferred_bytes is not None and total_index_bytes + index_size > max_transferred_bytes:
            failure = _index_failure_details(index_filename, "index_exceeds_max_size_budget", index_size=index_size)
            for filename in filename_family:
                attach_details(filename, failure)
            continue

        index_bytes_transferred = 0
        try:
            index_range = _read_huggingface_strict_range(
                repo_id,
                index_filename,
                revision,
                index_size,
                expected_size=index_size,
                deadline=deadline,
            )
            index_bytes_transferred = index_range.bytes_transferred
            total_index_bytes += index_range.bytes_transferred
            acquired_index_bytes[index_filename] = index_range.data
            parsed, duplicate_keys, duplicate_key_count, parse_error = _loads_json_without_duplicate_keys(
                index_range.data
            )
            if parse_error is not None:
                raise ValueError(parse_error)
            if not isinstance(parsed, dict):
                raise ValueError("SafeTensors index root is not a JSON object")
            metadata = parsed.get("metadata")
            if metadata is not None and not isinstance(metadata, dict):
                raise ValueError("SafeTensors index metadata is not a JSON object")
            weight_map_values = [parsed.get("weight_map")]
            if isinstance(parsed, _DuplicateAwareJsonObject):
                weight_map_values.extend(value for key, value in parsed.overwritten_items if key == "weight_map")
            weight_maps = [value for value in weight_map_values if isinstance(value, dict)]
            if not weight_maps:
                raise ValueError("SafeTensors index weight_map is not a JSON object")
            invalid_weight_map_count = len(weight_map_values) - len(weight_maps)
            weight_map_items: list[tuple[str, Any]] = []
            for weight_map in weight_maps:
                weight_map_items.extend(weight_map.items())
                if isinstance(weight_map, _DuplicateAwareJsonObject):
                    weight_map_items.extend(weight_map.overwritten_items)
            if len(weight_map_items) > _MAX_HF_SAFETENSORS_INDEX_TENSORS:
                raise ValueError("SafeTensors index weight_map exceeds tensor entry limit")
        except Exception as exc:
            if isinstance(exc, _HuggingFaceStrictRangeError):
                index_bytes_transferred += exc.bytes_transferred
                total_index_bytes += exc.bytes_transferred
            failure = _index_failure_details(
                index_filename,
                "index_read_or_parse_failed",
                bytes_transferred=index_bytes_transferred,
                index_size=index_size,
                error=exc,
            )
            for filename in filename_family:
                attach_details(filename, failure)
            continue

        referenced_by_file: dict[str, list[str]] = {}
        invalid_entries = ["weight_map occurrence is not a JSON object"] * invalid_weight_map_count
        reconciliation_timed_out = False
        for entry_index, (tensor_name, shard_name) in enumerate(weight_map_items):
            if entry_index % 1024 == 0 and deadline is not None and time.monotonic() >= deadline:
                reconciliation_timed_out = True
                break
            if not isinstance(tensor_name, str) or not tensor_name:
                invalid_entries.append("<invalid tensor key>")
                continue
            normalized_path, invalid_reason = _normalize_safetensors_index_shard_path(index_filename, shard_name)
            if normalized_path is None:
                invalid_entries.append(f"{tensor_name}: {invalid_reason}")
                continue
            referenced_by_file.setdefault(normalized_path, []).append(tensor_name)

        if reconciliation_timed_out:
            failure = _index_failure_details(
                index_filename,
                "index_reconciliation_timed_out",
                bytes_transferred=index_range.bytes_transferred,
                index_size=index_size,
            )
            scoped_files = filename_family.union(referenced_by_file).intersection(selected_files)
            for filename in scoped_files:
                attach_details(filename, failure)
            continue

        referenced_files = set(referenced_by_file)
        missing_files = sorted(referenced_files - repo_file_set)
        unselected_files = sorted((referenced_files & repo_file_set) - selected_files)
        selected_referenced = sorted(referenced_files & selected_files)
        metadata_total_size = metadata.get("total_size") if isinstance(metadata, dict) else None
        invalid_total_size = False
        if metadata_total_size is not None:
            if (
                not isinstance(metadata_total_size, int)
                or isinstance(metadata_total_size, bool)
                or metadata_total_size < 0
            ):
                invalid_total_size = True
            else:
                known_capacity = 0
                for filename in referenced_files:
                    file_size = path_sizes.get(filename)
                    if isinstance(file_size, int) and not isinstance(file_size, bool):
                        known_capacity += max(0, file_size - 8)
                if known_capacity > 0 and metadata_total_size > known_capacity:
                    invalid_total_size = True

        try:
            tensor_digests_by_file = {
                filename: _tensor_name_digest(tensors, deadline=deadline)
                for filename, tensors in referenced_by_file.items()
            }
        except TimeoutError:
            failure = _index_failure_details(
                index_filename,
                "index_reconciliation_timed_out",
                bytes_transferred=index_range.bytes_transferred,
                index_size=index_size,
            )
            for filename in filename_family.union(selected_referenced):
                attach_details(filename, failure)
            continue

        if deadline is not None and time.monotonic() >= deadline:
            failure = _index_failure_details(
                index_filename,
                "index_reconciliation_timed_out",
                bytes_transferred=index_range.bytes_transferred,
                index_size=index_size,
            )
            for filename in filename_family.union(selected_referenced):
                attach_details(filename, failure)
            continue

        index_complete = (
            not duplicate_keys
            and not invalid_entries
            and not missing_files
            and not unselected_files
            and not invalid_total_size
            and bool(selected_referenced)
        )
        common_details: dict[str, Any] = {
            "complete": index_complete,
            "index_complete": index_complete,
            "index_manifest": index_filename,
            "index_declared_size": index_size,
            "index_bytes_transferred": index_range.bytes_transferred,
            "index_object_validator": index_range.validator,
            "index_final_host": urlparse(index_range.final_url).hostname,
            "index_weight_map_tensor_count": len(weight_map_items),
            "index_referenced_shard_count": len(referenced_files),
            "index_missing_shard_count": len(missing_files),
            "index_missing_shards": missing_files[:20],
            "index_missing_shards_truncated": len(missing_files) > 20,
            "index_unselected_shard_count": len(unselected_files),
            "index_unselected_shards": unselected_files[:20],
            "index_unselected_shards_truncated": len(unselected_files) > 20,
            "index_invalid_entry_count": len(invalid_entries),
            "index_invalid_entries": invalid_entries[:20],
            "index_invalid_entries_truncated": len(invalid_entries) > 20,
            "index_duplicate_json_key_count": duplicate_key_count,
            "index_duplicate_json_keys": duplicate_keys[:20],
            "index_duplicate_json_keys_truncated": duplicate_key_count > len(duplicate_keys),
            "index_metadata_total_size": metadata_total_size,
            "index_metadata_total_size_plausible": not invalid_total_size,
            "index_metadata_total_size_verified": None if metadata_total_size is None else False,
            "index_relationships_complete": index_complete,
            "message": (
                (
                    "SafeTensors index file and tensor relationships are complete for this shard; "
                    "metadata.total_size was not independently verified."
                )
                if index_complete and metadata_total_size is not None
                else "SafeTensors index file and tensor relationships are complete for this shard."
                if index_complete
                else "Remote SafeTensors index coverage is incomplete."
            ),
        }
        attach_filenames = (
            sorted(filename_family.union(selected_referenced))
            if duplicate_keys or invalid_entries or invalid_total_size or not selected_referenced
            else selected_referenced
        )
        for filename in attach_filenames:
            details = dict(common_details)
            tensors = referenced_by_file.get(filename, [])
            details["index_referenced_by_manifest"] = filename in referenced_by_file
            details["index_tensor_count_for_shard"] = len(tensors)
            details["index_tensor_names_for_shard"] = tensors[:20]
            details["index_tensor_names_for_shard_truncated"] = len(tensors) > 20
            details["index_tensor_names_digest"] = tensor_digests_by_file.get(filename, _tensor_name_digest(()))
            attach_details(filename, details)

    return details_by_file, total_index_bytes, acquired_index_bytes


def _combine_remote_safetensors_shard_details(
    filename_details: dict[str, dict[str, Any]],
    index_details: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    details_by_file: dict[str, dict[str, Any]] = {}
    for filename in sorted(set(filename_details) | set(index_details)):
        filename_detail = filename_details.get(filename)
        index_detail = index_details.get(filename)
        if filename_detail is None:
            details_by_file[filename] = dict(index_detail or {})
            continue
        if index_detail is None:
            details_by_file[filename] = dict(filename_detail)
            continue

        combined = dict(filename_detail)
        combined.update(index_detail)
        filename_complete = bool(filename_detail.get("complete"))
        filename_pattern_authoritative = bool(filename_detail.get("filename_pattern_authoritative", True))
        index_complete = bool(index_detail.get("complete"))
        combined["filename_pattern_complete"] = filename_complete
        combined["index_complete"] = index_complete
        combined["complete"] = index_complete and (filename_complete or not filename_pattern_authoritative)
        combined["message"] = (
            "Remote SafeTensors shard filename and index coverage are complete."
            if combined["complete"]
            else "Remote SafeTensors shard coverage is incomplete."
        )
        details_by_file[filename] = combined
    return details_by_file


def _remote_safetensors_shard_details_by_file(
    repo_id: str,
    model_files: list[str],
    repo_files: list[str],
    revision: str,
    path_sizes: dict[str, int | None],
    *,
    deadline: float | None,
    max_transferred_bytes: int | None,
) -> tuple[dict[str, dict[str, Any]], int, dict[str, bytes]]:
    """Return per-shard remote coverage details from filenames and index manifests."""
    filename_details = _remote_safetensors_filename_shard_details_by_file(model_files, repo_files)
    index_details, index_bytes, acquired_index_bytes = _remote_safetensors_index_details_by_file(
        repo_id,
        model_files,
        repo_files,
        revision,
        path_sizes,
        deadline=deadline,
        max_transferred_bytes=max_transferred_bytes,
    )
    return (
        _combine_remote_safetensors_shard_details(filename_details, index_details),
        index_bytes,
        acquired_index_bytes,
    )


@dataclass
class _HuggingFaceStreamingSelection:
    filenames: list[str]
    content_route_formats: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HuggingFaceDownloadPlan:
    namespace: str
    repo_name: str
    repo_id: str
    deadline: float | None
    size_limit: int | None
    repo_files: list[str]
    repo_revision: str
    selected_files: list[str]
    selected_sizes: dict[str, int]
    download_revision: str
    content_route_formats: dict[str, str] = field(default_factory=dict)


def _parse_huggingface_response_file_size(response: Any, bytes_read: int, max_bytes: int) -> int | None:
    """Return the total remote file size when the bounded response proves it."""
    headers = getattr(response, "headers", {})
    content_range = headers.get("Content-Range", "")
    if getattr(response, "status_code", None) == 206:
        import re

        match = re.fullmatch(r"bytes 0-(\d+)/(\d+)", content_range.strip(), flags=re.IGNORECASE)
        if match is None:
            raise ValueError("partial Hugging Face response omitted a valid Content-Range")
        end_offset, total_size = (int(value) for value in match.groups())
        expected_bytes = min(total_size, max_bytes)
        if end_offset + 1 != bytes_read or total_size < end_offset + 1 or bytes_read != expected_bytes:
            raise ValueError("partial Hugging Face response reported an inconsistent Content-Range")
        return total_size

    if getattr(response, "status_code", None) == 200:
        content_length = headers.get("Content-Length")
        if content_length is not None:
            try:
                total_size = int(content_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("Hugging Face response reported an invalid Content-Length") from exc
            if total_size >= bytes_read and bytes_read == min(total_size, max_bytes):
                return total_size
            raise ValueError("Hugging Face response reported an inconsistent Content-Length")

    return None


def _huggingface_sample_is_prefix(
    budget: _HuggingFaceProbeBudget,
    filename: str,
    probe: bytes,
    fallback_limit: int,
) -> bool:
    """Return whether a bounded probe is known or conservatively assumed to be partial."""
    file_size = budget.file_sizes.get(filename)
    if file_size is not None:
        return file_size > len(probe)
    return len(probe) >= fallback_limit


def _format_huggingface_exception_label(exc: Exception) -> str:
    """Return a compact, redacted exception label that preserves HTTP status."""
    status_code = getattr(getattr(exc, "response", None), "status_code", None)
    if isinstance(status_code, int):
        return f"{type(exc).__name__}: HTTP {status_code}"
    return type(exc).__name__


def _get_model_extensions() -> set[str]:
    """
    Lazy-load model extensions to avoid circular imports.

    Returns all file extensions that ModelAudit can scan - dynamically loaded from scanner registry.
    This ensures we download and scan everything we have scanners for.
    """
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _read_huggingface_prefix(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    max_bytes: int,
) -> bytes:
    """Read a bounded remote prefix for selective content routing."""
    cached_prefix = budget.prefixes.get(filename, b"")
    known_size = budget.file_sizes.get(filename)
    if len(cached_prefix) >= max_bytes or (known_size is not None and len(cached_prefix) >= known_size):
        return cached_prefix[:max_bytes]

    reserved_bytes = min(max_bytes, known_size) if known_size is not None else max_bytes
    budget.reserve(repo_id, reserved_bytes)
    try:
        import requests
        from huggingface_hub import hf_hub_url
        from huggingface_hub.utils import build_hf_headers

        file_url = hf_hub_url(repo_id=repo_id, filename=filename, revision=revision)
        headers = build_hf_headers(
            token=None,
            headers={
                "Range": f"bytes=0-{max_bytes - 1}",
                "Accept-Encoding": "identity",
            },
        )
        with requests.get(
            file_url,
            headers=headers,
            stream=True,
            timeout=budget.request_timeout(repo_id),
            allow_redirects=True,
        ) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=max_bytes):
                budget.check_deadline(repo_id)
                if not chunk:
                    continue
                budget.transferred_bytes += len(chunk)
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            prefix = b"".join(chunks)[:max_bytes]
            file_size = _parse_huggingface_response_file_size(response, len(prefix), max_bytes)
            if file_size is not None:
                budget.record_file_size(repo_id, filename, file_size)
                if file_size <= len(prefix):
                    budget.refund(reserved_bytes - len(prefix))
            if len(prefix) > len(cached_prefix):
                budget.prefixes[filename] = prefix
        return prefix
    except Exception as exc:
        raise ValueError(
            "Hugging Face selective filtering incomplete: unable to inspect skipped file "
            f"{repo_id}/{filename} ({_format_huggingface_exception_label(exc)})"
        ) from exc


def _read_huggingface_probe(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
    max_bytes: int,
) -> bytes:
    """Return an existing or freshly expanded bounded remote prefix."""
    if len(prefix) >= max_bytes:
        return prefix[:max_bytes]
    return _read_huggingface_prefix(repo_id, filename, revision, budget, max_bytes)


def _read_huggingface_tail(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
    max_bytes: int,
) -> bytes:
    """Read a bounded remote tail when the earlier prefix proved the file size."""
    file_size = budget.file_sizes.get(filename)
    if file_size is None or max_bytes <= 0:
        return b""
    if file_size <= len(prefix):
        return prefix[-max_bytes:]

    read_size = min(file_size, max_bytes)
    start_offset = file_size - read_size
    if start_offset == 0:
        return _read_huggingface_probe(repo_id, filename, revision, budget, prefix, read_size)[-read_size:]

    budget.reserve(repo_id, read_size)
    try:
        import re

        import requests
        from huggingface_hub import hf_hub_url
        from huggingface_hub.utils import build_hf_headers

        file_url = hf_hub_url(repo_id=repo_id, filename=filename, revision=revision)
        headers = build_hf_headers(
            token=None,
            headers={
                "Range": f"bytes={start_offset}-{file_size - 1}",
                "Accept-Encoding": "identity",
            },
        )
        with requests.get(
            file_url,
            headers=headers,
            stream=True,
            timeout=budget.request_timeout(repo_id),
            allow_redirects=True,
        ) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=read_size):
                budget.check_deadline(repo_id)
                if not chunk:
                    continue
                budget.transferred_bytes += len(chunk)
                chunks.append(chunk)
                total += len(chunk)
                if total >= read_size:
                    break
            tail = b"".join(chunks)[:read_size]
            content_range = getattr(response, "headers", {}).get("Content-Range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range.strip(), flags=re.IGNORECASE)
            if getattr(response, "status_code", None) != 206 or match is None:
                raise ValueError("tail Hugging Face response omitted a valid Content-Range")
            reported_start, reported_end, reported_size = (int(value) for value in match.groups())
            if (
                reported_start != start_offset
                or reported_end != file_size - 1
                or reported_size != file_size
                or len(tail) != read_size
            ):
                raise ValueError("tail Hugging Face response reported an inconsistent Content-Range")
        return tail
    except Exception as exc:
        raise ValueError(
            "Hugging Face selective filtering incomplete: unable to inspect skipped file "
            f"{repo_id}/{filename} ({type(exc).__name__})"
        ) from exc


def _read_huggingface_range(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
    start_offset: int,
    max_bytes: int,
) -> bytes:
    """Read a bounded remote byte range, reusing the cached prefix when possible."""
    file_size = budget.file_sizes.get(filename)
    if file_size is None or max_bytes <= 0 or start_offset < 0 or start_offset >= file_size:
        return b""

    read_size = min(max_bytes, file_size - start_offset)
    end_offset = start_offset + read_size
    if end_offset <= len(prefix):
        return prefix[start_offset:end_offset]

    chunks: list[bytes] = []
    remote_start = start_offset
    if start_offset < len(prefix):
        chunks.append(prefix[start_offset:])
        remote_start = len(prefix)

    remote_size = read_size - sum(len(chunk) for chunk in chunks)
    if remote_size <= 0:
        return b"".join(chunks)[:read_size]

    remote_end = remote_start + remote_size - 1
    budget.reserve(repo_id, remote_size)
    try:
        import re

        import requests
        from huggingface_hub import hf_hub_url
        from huggingface_hub.utils import build_hf_headers

        file_url = hf_hub_url(repo_id=repo_id, filename=filename, revision=revision)
        headers = build_hf_headers(
            token=None,
            headers={
                "Range": f"bytes={remote_start}-{remote_end}",
                "Accept-Encoding": "identity",
            },
        )
        with requests.get(
            file_url,
            headers=headers,
            stream=True,
            timeout=budget.request_timeout(repo_id),
            allow_redirects=True,
        ) as response:
            response.raise_for_status()
            remote_chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=remote_size):
                budget.check_deadline(repo_id)
                if not chunk:
                    continue
                budget.transferred_bytes += len(chunk)
                remote_chunks.append(chunk)
                total += len(chunk)
                if total >= remote_size:
                    break
            remote_payload = b"".join(remote_chunks)[:remote_size]
            content_range = getattr(response, "headers", {}).get("Content-Range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range.strip(), flags=re.IGNORECASE)
            if getattr(response, "status_code", None) != 206 or match is None:
                raise ValueError("range Hugging Face response omitted a valid Content-Range")
            reported_start, reported_end, reported_size = (int(value) for value in match.groups())
            if (
                reported_start != remote_start
                or reported_end != remote_end
                or reported_size != file_size
                or len(remote_payload) != remote_size
            ):
                raise ValueError("range Hugging Face response reported an inconsistent Content-Range")
            chunks.append(remote_payload)
        return b"".join(chunks)[:read_size]
    except Exception as exc:
        raise ValueError(
            "Hugging Face selective filtering incomplete: unable to inspect skipped file "
            f"{repo_id}/{filename} ({type(exc).__name__})"
        ) from exc


def _detect_huggingface_png_media_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a PNG media route by walking chunk framing with sparse range reads."""
    from modelaudit.utils.file.detection import (
        _PNG_SIGNATURE,
        MEDIA_ROUTE_READ_BYTES,
        MEDIA_ROUTE_TAIL_READ_BYTES,
        PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        VALID_MEDIA_ROUTING_FORMAT,
        _detect_complete_media_route_from_trailing,
        _find_png_end_with_reader,
    )

    if not prefix.startswith(_PNG_SIGNATURE):
        return None
    file_size = budget.file_sizes.get(filename)
    if file_size is None:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    tail: bytes | None = None
    tail_start = file_size
    range_windows: list[tuple[int, bytes]] = []

    def read_at(offset: int, size: int) -> bytes:
        nonlocal tail, tail_start
        end_offset = offset + size
        if end_offset <= len(prefix):
            return prefix[offset:end_offset]
        if tail is None:
            tail = _read_huggingface_tail(
                repo_id,
                filename,
                revision,
                budget,
                prefix,
                MEDIA_ROUTE_TAIL_READ_BYTES,
            )
            tail_start = file_size - len(tail)
        if tail_start <= offset and end_offset <= tail_start + len(tail):
            return tail[offset - tail_start : end_offset - tail_start]
        if offset < len(prefix) and len(prefix) >= tail_start and end_offset <= tail_start + len(tail):
            prefix_part = prefix[offset : min(end_offset, len(prefix))]
            tail_part_start = max(len(prefix), tail_start)
            tail_part = tail[tail_part_start - tail_start : end_offset - tail_start]
            return prefix_part + tail_part
        for window_start, window in range_windows:
            if window_start <= offset and end_offset <= window_start + len(window):
                return window[offset - window_start : end_offset - window_start]
        window_size = min(MEDIA_ROUTE_TAIL_READ_BYTES, file_size - offset)
        window = _read_huggingface_range(repo_id, filename, revision, budget, prefix, offset, window_size)
        range_windows.append((offset, window))
        return window[:size]

    try:
        media_end = _find_png_end_with_reader(
            file_size,
            read_at,
        )
    except ValueError:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    if media_end is None:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    trailing_size = file_size - media_end
    if trailing_size <= 0:
        return VALID_MEDIA_ROUTING_FORMAT
    read_size = min(trailing_size, MEDIA_ROUTE_READ_BYTES + 1)
    try:
        trailing = read_at(media_end, read_size)
    except ValueError:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    return _detect_complete_media_route_from_trailing(trailing, sample_is_prefix=trailing_size > len(trailing))


def _detect_huggingface_jpeg_media_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a JPEG media route by walking marker structure with sparse range reads."""
    from modelaudit.utils.file.detection import (
        MEDIA_ROUTE_READ_BYTES,
        MEDIA_ROUTE_TAIL_READ_BYTES,
        PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        VALID_MEDIA_ROUTING_FORMAT,
        _detect_complete_media_route_from_trailing,
        _find_jpeg_end_with_reader,
    )

    if not prefix.startswith(b"\xff\xd8"):
        return None
    file_size = budget.file_sizes.get(filename)
    if file_size is None:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    tail: bytes | None = None
    tail_start = file_size
    range_windows: list[tuple[int, bytes]] = []

    def read_at(offset: int, size: int) -> bytes:
        nonlocal tail, tail_start
        end_offset = offset + size
        if end_offset <= len(prefix):
            return prefix[offset:end_offset]
        if tail is None:
            tail = _read_huggingface_tail(
                repo_id,
                filename,
                revision,
                budget,
                prefix,
                MEDIA_ROUTE_TAIL_READ_BYTES,
            )
            tail_start = file_size - len(tail)
        if tail_start <= offset and end_offset <= tail_start + len(tail):
            return tail[offset - tail_start : end_offset - tail_start]
        if offset < len(prefix) and len(prefix) >= tail_start and end_offset <= tail_start + len(tail):
            prefix_part = prefix[offset : min(end_offset, len(prefix))]
            tail_part_start = max(len(prefix), tail_start)
            tail_part = tail[tail_part_start - tail_start : end_offset - tail_start]
            return prefix_part + tail_part
        for window_start, window in range_windows:
            if window_start <= offset and end_offset <= window_start + len(window):
                return window[offset - window_start : end_offset - window_start]
        window_size = min(MEDIA_ROUTE_TAIL_READ_BYTES, file_size - offset)
        window = _read_huggingface_range(repo_id, filename, revision, budget, prefix, offset, window_size)
        range_windows.append((offset, window))
        return window[:size]

    try:
        media_end = _find_jpeg_end_with_reader(file_size, read_at)
    except ValueError:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    if media_end is None:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    trailing_size = file_size - media_end
    if trailing_size <= 0:
        return VALID_MEDIA_ROUTING_FORMAT
    read_size = min(trailing_size, MEDIA_ROUTE_READ_BYTES + 1)
    try:
        trailing = read_at(media_end, read_size)
    except ValueError:
        return PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    return _detect_complete_media_route_from_trailing(trailing, sample_is_prefix=trailing_size > len(trailing))


def _looks_like_safetensors_prefix(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> bool:
    """Recognize bounded SafeTensors framing without requiring a local path."""
    if len(prefix) <= 8:
        return False

    header_len = struct.unpack("<Q", prefix[:8])[0]
    header_prefix = prefix[8:]
    if header_len <= 0 or not header_prefix.startswith(b"{"):
        return False

    file_size = budget.file_sizes.get(filename)
    if file_size is not None and header_len > file_size - 8:
        return False

    from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES

    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        return (file_size is None and len(prefix) >= _HF_CONTENT_SNIFF_BYTES) or header_len <= (
            file_size if file_size is not None else len(prefix)
        ) - 8

    header_probe = _read_huggingface_prefix(repo_id, filename, revision, budget, 8 + header_len)
    if len(header_probe) != 8 + header_len or header_probe[8:9] != b"{":
        return False
    try:
        parsed_header = json.loads(header_probe[8:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed_header, dict)


def _detect_huggingface_mxnet_symbol_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded MXNet JSON route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import MXNET_SYMBOL_SIGNATURE_READ_BYTES, _detect_mxnet_symbol_prefix_route

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    if not normalized_prefix.lstrip().startswith(b"{"):
        return None

    max_probe_size = MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1
    mxnet_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size)
    mxnet_probe = mxnet_probe[3:] if mxnet_probe.startswith(b"\xef\xbb\xbf") else mxnet_probe
    if len(mxnet_probe) > MXNET_SYMBOL_SIGNATURE_READ_BYTES:
        return _detect_mxnet_symbol_prefix_route(
            mxnet_probe[:MXNET_SYMBOL_SIGNATURE_READ_BYTES],
            fail_closed_without_hint=True,
        )
    return _detect_mxnet_symbol_prefix_route(
        mxnet_probe,
        sample_is_prefix=len(mxnet_probe) >= max_probe_size,
        fail_closed_without_hint=True,
    )


def _detect_huggingface_xml_model_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded XML model route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _XML_MODEL_SIGNATURE_READ_BYTES,
        _could_be_xml_prefix,
        _detect_xml_model_format,
    )

    if not _could_be_xml_prefix(prefix):
        return None

    xml_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, _XML_MODEL_SIGNATURE_READ_BYTES)
    detected_format = _detect_xml_model_format(
        xml_probe,
        sample_is_prefix=_huggingface_sample_is_prefix(
            budget,
            filename,
            xml_probe,
            _XML_MODEL_SIGNATURE_READ_BYTES,
        ),
    )
    return None if detected_format == "unknown" else detected_format


def _detect_huggingface_jax_json_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded JAX JSON checkpoint route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _JAX_JSON_CHECKPOINT_CONTENT_ROUTE_EXCLUDED_SUFFIXES,
        JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
        _could_start_json_object,
        has_jax_json_checkpoint_structure,
    )

    if Path(filename).suffix.lower() in _JAX_JSON_CHECKPOINT_CONTENT_ROUTE_EXCLUDED_SUFFIXES:
        return None

    jax_probe = prefix
    normalized_prefix = jax_probe.lstrip()
    if normalized_prefix.startswith(b"\xef\xbb\xbf"):
        normalized_prefix = normalized_prefix[3:].lstrip()

    if not normalized_prefix:
        max_probe_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1
        jax_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size)
        normalized_prefix = jax_probe.lstrip()
        if normalized_prefix.startswith(b"\xef\xbb\xbf"):
            normalized_prefix = normalized_prefix[3:].lstrip()
        if not normalized_prefix and len(jax_probe) > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            return "jax_checkpoint"

    if not _could_start_json_object(jax_probe):
        return None

    max_probe_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1
    jax_probe = _read_huggingface_probe(repo_id, filename, revision, budget, jax_probe, max_probe_size)
    try:
        payload = json.loads(jax_probe.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        if len(jax_probe) > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            return "jax_checkpoint"
        return None
    return "jax_checkpoint" if has_jax_json_checkpoint_structure(payload) else None


def _detect_huggingface_xgboost_ubjson_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded XGBoost UBJSON route for a suffix-skipped remote file."""
    if Path(filename).suffix and not _has_hf_safetensors_shard_shape(filename):
        return None

    from modelaudit.utils.file.detection import (
        _XGBOOST_UBJSON_ROUTE_READ_BYTES,
        _detect_extensionless_xgboost_ubjson_route,
    )

    xgboost_route = _detect_extensionless_xgboost_ubjson_route(prefix)
    if xgboost_route is not None:
        return xgboost_route

    normalized_prefix = prefix.lstrip(b"N")
    if not normalized_prefix.startswith(b"{"):
        return None

    xgboost_probe = _read_huggingface_probe(
        repo_id,
        filename,
        revision,
        budget,
        prefix,
        _XGBOOST_UBJSON_ROUTE_READ_BYTES,
    )
    return _detect_extensionless_xgboost_ubjson_route(xgboost_probe)


def _detect_huggingface_llamafile_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded Llamafile route for a suffix-skipped remote executable."""
    import zipfile

    from modelaudit.utils.file.detection import (
        EXECUTABLE_ZIP_POLYGLOT_FORMAT,
        LLAMAFILE_MARKER,
        LLAMAFILE_ROUTE_SCAN_BYTES,
        LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
        _is_supported_llamafile_executable_header,
    )

    if not _is_supported_llamafile_executable_header(prefix[:4]):
        return None

    max_probe_size = LLAMAFILE_ROUTE_SCAN_BYTES + 1
    probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size)
    if LLAMAFILE_MARKER in probe[:LLAMAFILE_ROUTE_SCAN_BYTES].lower():
        return "llamafile"
    if zipfile.is_zipfile(BytesIO(probe)):
        return EXECUTABLE_ZIP_POLYGLOT_FORMAT
    if len(probe) > LLAMAFILE_ROUTE_SCAN_BYTES:
        return LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT
    return None


def _detect_huggingface_torch7_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded Torch7 route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _TORCH7_SIGNATURE_READ_BYTES,
        _allows_renamed_binary_content_route,
        _is_torch7_signature,
    )

    if not _allows_renamed_binary_content_route(Path(filename)):
        return None
    probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, _TORCH7_SIGNATURE_READ_BYTES)
    return "torch7" if _is_torch7_signature(probe) else None


def _detect_huggingface_rknn_route(filename: str, prefix: bytes) -> str | None:
    """Return the RKNN route when renamed binary routing permits the remote filename."""
    from modelaudit.utils.file.detection import _allows_renamed_binary_content_route

    if prefix[:4] != b"RKNN" or not _allows_renamed_binary_content_route(Path(filename)):
        return None
    return "rknn"


def _probe_huggingface_executorch_prefix(prefix: bytes, *, sample_is_prefix: bool) -> bool | None:
    """Validate bounded ExecuTorch FlatBuffers structure without a local file."""
    from modelaudit.utils.file.detection import _is_executorch_binary_signature

    if not _is_executorch_binary_signature(prefix):
        return False
    if len(prefix) < 16:
        return None if sample_is_prefix else False

    root_table_offset = struct.unpack("<I", prefix[:4])[0]
    if root_table_offset < 12:
        return False
    if root_table_offset + 4 > len(prefix):
        return None if sample_is_prefix else False

    vtable_back_offset = struct.unpack("<i", prefix[root_table_offset : root_table_offset + 4])[0]
    if vtable_back_offset <= 0 or vtable_back_offset > root_table_offset:
        return False

    vtable_offset = root_table_offset - vtable_back_offset
    if vtable_offset < 8:
        return False
    if vtable_offset + 4 > len(prefix):
        return None if sample_is_prefix else False

    vtable_size, object_size = struct.unpack("<HH", prefix[vtable_offset : vtable_offset + 4])
    if vtable_size < 4 or object_size < 4:
        return False
    return sample_is_prefix or not (
        vtable_offset + vtable_size > len(prefix) or root_table_offset + object_size > len(prefix)
    )


def _is_complete_huggingface_text_or_json(
    filename: str,
    probe: bytes,
    *,
    sample_is_prefix: bool,
    preserve_protobuf_model_candidates: bool = False,
) -> bool:
    """Return whether a complete bounded probe is owned by benign text or JSON."""
    if sample_is_prefix:
        return False

    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES,
        _has_bounded_protobuf_model_text_candidate_signal_bytes,
        _is_complete_bounded_ascii_printable_text_content_owner_bytes,
        _is_complete_bounded_printable_text_content_owner_bytes,
    )

    remote_path = Path(filename)
    if (
        preserve_protobuf_model_candidates
        and remote_path.suffix.lower() in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES
        and _has_bounded_protobuf_model_text_candidate_signal_bytes(probe)
        and not _is_complete_bounded_ascii_printable_text_content_owner_bytes(remote_path, len(probe), probe)
    ):
        return False

    if _is_complete_bounded_printable_text_content_owner_bytes(remote_path, len(probe), probe):
        return True

    normalized = probe.lstrip()
    if normalized.startswith(b"\xef\xbb\xbf"):
        normalized = normalized[3:].lstrip()
    if not normalized.startswith((b"{", b"[")):
        return False
    try:
        return isinstance(json.loads(normalized.decode("utf-8")), (dict, list))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False


def _starts_with_non_ascii_length_delimited_proto_prefix(probe: bytes) -> bool:
    """Return whether a text-like prefix starts with a non-ASCII length-delimited proto field."""
    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES,
        _read_length_delimited_proto_value,
        _read_proto_varint,
    )

    tag_result = _read_proto_varint(probe, 0)
    if tag_result is None:
        return False
    tag, value_offset = tag_result
    if tag >> 3 == 0 or tag & 0x07 != 2:
        return False
    bounds = _read_length_delimited_proto_value(probe, value_offset)
    if bounds is None:
        return False
    length, value_start, value_end, actual_value_end = bounds
    if length <= 0 or actual_value_end > len(probe):
        return False
    return bool(probe[value_start:value_end].translate(None, _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES))


def _is_huggingface_text_owner_prefix(
    filename: str,
    probe: bytes,
    *,
    preserve_protobuf_model_candidates: bool = False,
) -> bool:
    """Return whether an already-read remote prefix has ordinary text-owner structure."""
    if not probe:
        return False

    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES,
        _CONTENT_ROUTE_TEXT_WHITESPACE_CHARS,
        _has_content_route_text_owner_structure,
        _is_complete_bounded_ascii_printable_text_content_owner_bytes,
        is_declared_text_content_filename,
    )

    remote_path = Path(filename)
    if remote_path.suffix.lower() not in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES and not is_declared_text_content_filename(
        filename
    ):
        return False
    if (
        preserve_protobuf_model_candidates
        and _starts_with_non_ascii_length_delimited_proto_prefix(probe)
        and not _is_complete_bounded_ascii_printable_text_content_owner_bytes(remote_path, len(probe), probe)
    ):
        return False
    try:
        text = probe.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    return _has_content_route_text_owner_structure(text) and all(
        char in _CONTENT_ROUTE_TEXT_WHITESPACE_CHARS or char.isprintable() for char in text
    )


def _is_printable_non_ascii_huggingface_text_prefix(probe: bytes) -> bool:
    """Return whether a prefix is printable UTF-8 text with non-ASCII bytes."""
    if not probe:
        return False
    return any(byte >= 0x80 for byte in probe) and not any(
        (byte < 0x20 and byte not in {0x09, 0x0A, 0x0C, 0x0D}) or byte == 0x7F for byte in probe
    )


def _detect_huggingface_text_owner_embedded_binary_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded route for binary/model bytes embedded after a text-owned prefix."""
    known_size = budget.file_sizes.get(filename)
    if known_size is None or known_size <= len(prefix):
        return None

    from modelaudit.utils.file.detection import (
        FLAX_MSGPACK_STRUCTURE_READ_BYTES,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        _has_bounded_protobuf_model_text_candidate_signal_bytes,
        _looks_like_proto0_or_1_pickle,
        _probe_flax_msgpack_checkpoint_stream,
        detect_format_from_magic_bytes,
    )

    def detect_sample_route(sample: bytes) -> str | None:
        if not sample:
            return None
        flax_state = _probe_flax_msgpack_checkpoint_stream(
            BytesIO(sample),
            len(sample),
            sample_is_prefix=True,
            incomplete_prefix_is_inconclusive=True,
        )
        if flax_state is True:
            return "flax_msgpack"
        if _starts_with_non_ascii_length_delimited_proto_prefix(
            sample
        ) or _has_bounded_protobuf_model_text_candidate_signal_bytes(sample):
            return PROTOBUF_MODEL_CANDIDATE_FORMAT
        if _looks_like_proto0_or_1_pickle(sample, sample_is_prefix=True):
            return "pickle"
        detected_format = detect_format_from_magic_bytes(
            sample[:4],
            sample[:8],
            sample[:16],
            max(len(sample), 1),
            None,
            pickle_probe_sample=sample,
            pickle_probe_is_prefix=True,
        )
        return None if detected_format == "unknown" else detected_format

    sample_size = FLAX_MSGPACK_STRUCTURE_READ_BYTES
    post_prefix = _read_huggingface_range(repo_id, filename, revision, budget, prefix, len(prefix), sample_size)
    post_prefix_route = detect_sample_route(post_prefix)
    if post_prefix_route is not None:
        return post_prefix_route

    tail_start = max(0, known_size - min(known_size, sample_size))
    if tail_start <= len(prefix) + len(post_prefix):
        return None
    tail = _read_huggingface_tail(repo_id, filename, revision, budget, prefix, sample_size)
    return detect_sample_route(tail)


def _is_complete_huggingface_text_owner_or_json_probe(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    raw_probe: bytes,
    max_probe_size: int,
    *,
    preserve_protobuf_model_candidates: bool = False,
) -> bool:
    """Return whether a bounded remote probe proves text or JSON ownership."""
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_or_json(
        filename,
        probe,
        sample_is_prefix=_huggingface_sample_is_prefix(budget, filename, probe, max_probe_size),
        preserve_protobuf_model_candidates=preserve_protobuf_model_candidates,
    ):
        return True

    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_TEXT_OWNER_COMPLETE_BYTES,
        _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES,
        is_declared_text_content_filename,
    )

    if Path(
        filename
    ).suffix.lower() not in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES and not is_declared_text_content_filename(filename):
        return False
    known_size = budget.file_sizes.get(filename)
    if known_size is not None and known_size > _CONTENT_ROUTE_TEXT_OWNER_COMPLETE_BYTES:
        return False
    if known_size is None or known_size > len(probe):
        return False

    return _is_huggingface_text_owner_prefix(
        filename,
        probe,
        preserve_protobuf_model_candidates=preserve_protobuf_model_candidates,
    )


def _detect_huggingface_protobuf_model_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded TensorFlow, CoreML, ONNX, or unresolved protobuf model route."""
    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES,
        _COREML_PROTO_SIGNATURE_READ_BYTES,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        _classify_bounded_tensorflow_protobuf_stream,
        _could_start_coreml_model_proto,
        _looks_like_coreml_model_proto_prefix,
        _looks_like_onnx_model_proto_stream,
    )

    if Path(filename).suffix.lower() in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES and prefix.startswith(b":"):
        return None
    if not _could_start_coreml_model_proto(prefix):
        return None

    max_probe_size = _COREML_PROTO_SIGNATURE_READ_BYTES
    raw_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size + 1)
    sample_is_prefix = len(raw_probe) > max_probe_size
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_owner_or_json_probe(
        repo_id,
        filename,
        revision,
        budget,
        raw_probe,
        max_probe_size,
        preserve_protobuf_model_candidates=True,
    ):
        return None

    coreml_status = _looks_like_coreml_model_proto_prefix(probe, sample_is_prefix=sample_is_prefix)
    if coreml_status is True:
        return "coreml"

    onnx_status = _looks_like_onnx_model_proto_stream(BytesIO(probe), len(probe))
    if onnx_status is True:
        return "onnx"

    tensorflow_route = _classify_bounded_tensorflow_protobuf_stream(BytesIO(probe), len(probe))
    if tensorflow_route in {"tf_metagraph", "tf_savedmodel"}:
        return tensorflow_route
    if tensorflow_route == "oversized":
        return "tf_metagraph"
    if tensorflow_route in {"oversized_candidate", "inconclusive"}:
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    if Path(
        filename
    ).suffix.lower() in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES and _starts_with_non_ascii_length_delimited_proto_prefix(
        prefix
    ):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    if sample_is_prefix or coreml_status is None or onnx_status is None:
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    return None


def _detect_huggingface_flax_msgpack_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
    *,
    require_confirmed: bool = False,
) -> str | None:
    """Return a bounded Flax MessagePack route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_TEXT_OWNER_COMPLETE_BYTES,
        _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES,
        FLAX_MSGPACK_STRUCTURE_READ_BYTES,
        _probe_flax_msgpack_checkpoint_stream,
        is_declared_text_content_filename,
    )

    remote_path = Path(filename)
    suffix = remote_path.suffix.lower()
    text_owner_filename = suffix in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES or is_declared_text_content_filename(filename)
    if suffix in {".py", ".pyw"}:
        return None

    initial_probe_state = _probe_flax_msgpack_checkpoint_stream(
        BytesIO(prefix),
        len(prefix),
        sample_is_prefix=_huggingface_sample_is_prefix(
            budget,
            filename,
            prefix,
            _HF_CONTENT_SNIFF_BYTES,
        ),
        incomplete_prefix_is_inconclusive=True,
    )
    if initial_probe_state is True:
        return "flax_msgpack"
    if len(prefix) < _HF_CONTENT_SNIFF_BYTES:
        return None
    if initial_probe_state is False and not text_owner_filename:
        return None
    if initial_probe_state is False and _is_huggingface_text_owner_prefix(filename, prefix):
        known_size = budget.file_sizes.get(filename)
        if known_size is not None and known_size <= _CONTENT_ROUTE_TEXT_OWNER_COMPLETE_BYTES:
            raw_text_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, known_size)
            if len(raw_text_probe) >= known_size and _is_complete_huggingface_text_or_json(
                filename,
                raw_text_probe[:known_size],
                sample_is_prefix=False,
            ):
                return None
        return _detect_huggingface_text_owner_embedded_binary_route(repo_id, filename, revision, budget, prefix)
    if _is_complete_huggingface_text_owner_or_json_probe(
        repo_id,
        filename,
        revision,
        budget,
        prefix,
        _HF_CONTENT_SNIFF_BYTES,
    ):
        return None

    max_probe_size = FLAX_MSGPACK_STRUCTURE_READ_BYTES
    raw_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size + 1)
    sample_is_prefix = len(raw_probe) > max_probe_size
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_owner_or_json_probe(
        repo_id,
        filename,
        revision,
        budget,
        raw_probe,
        max_probe_size,
    ):
        return None
    probe_state = _probe_flax_msgpack_checkpoint_stream(
        BytesIO(probe),
        len(probe),
        sample_is_prefix=sample_is_prefix,
        incomplete_prefix_is_inconclusive=True,
    )
    if (
        probe_state is False
        and not require_confirmed
        and text_owner_filename
        and _is_printable_non_ascii_huggingface_text_prefix(probe)
    ):
        return "flax_msgpack"
    if probe_state is True or (probe_state is not False and not require_confirmed):
        return "flax_msgpack"
    return None


def _detect_huggingface_content_route_format(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
) -> str | None:
    """Return a content-routed model format for a remote file, if cheaply identifiable."""
    remote_path = Path(filename)
    prefix = _read_huggingface_prefix(repo_id, filename, revision, budget, _HF_CONTENT_SNIFF_BYTES)
    if not prefix:
        return None

    from modelaudit.utils.file.detection import (
        _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES,
        _MEDIA_ROUTING_SUFFIXES,
        _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS,
        MEDIA_ROUTE_TAIL_READ_BYTES,
        PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        PROTO0_1_MAX_PROBE_BYTES,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        VALID_MEDIA_ROUTING_FORMAT,
        _allows_renamed_binary_content_route,
        _could_start_bounded_media_route,
        _could_start_proto0_or_1_pickle,
        _detect_bounded_media_route_from_edges,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _looks_like_proto0_or_1_pickle,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )

    llamafile_route = _detect_huggingface_llamafile_route(repo_id, filename, revision, budget, prefix)
    if llamafile_route is not None:
        return llamafile_route

    from modelaudit.utils.file._compression import is_zlib_header

    if is_zlib_header(prefix[:2]) and prefix[1] & 0x20:
        return "zlib"

    if _looks_like_safetensors_prefix(repo_id, filename, revision, budget, prefix):
        if remote_path.suffix.lower() in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES:
            flax_route = _detect_huggingface_flax_msgpack_route(
                repo_id,
                filename,
                revision,
                budget,
                prefix,
                require_confirmed=True,
            )
            if flax_route is not None:
                return flax_route
        return "safetensors"
    if _looks_like_uncompressed_tar_header(prefix):
        return "tar"
    if remote_path.suffix.lower() != ".model" and _is_cntk_signature(prefix):
        return "cntk"
    if _is_content_routed_lightgbm_signature(prefix):
        return "lightgbm"

    xml_route = _detect_huggingface_xml_model_route(repo_id, filename, revision, budget, prefix)
    if xml_route is not None:
        return xml_route

    xgboost_ubjson_route = _detect_huggingface_xgboost_ubjson_route(repo_id, filename, revision, budget, prefix)
    if xgboost_ubjson_route is not None:
        return xgboost_ubjson_route

    jax_json_route = _detect_huggingface_jax_json_route(repo_id, filename, revision, budget, prefix)
    if jax_json_route is not None:
        return jax_json_route

    mxnet_route = _detect_huggingface_mxnet_symbol_route(repo_id, filename, revision, budget, prefix)
    if mxnet_route is not None:
        return mxnet_route

    if remote_path.suffix.lower() in _MEDIA_ROUTING_SUFFIXES:
        media_route = _detect_huggingface_png_media_route(repo_id, filename, revision, budget, prefix)
        if media_route is None:
            media_route = _detect_huggingface_jpeg_media_route(repo_id, filename, revision, budget, prefix)
        if media_route is None:
            media_tail = _read_huggingface_tail(
                repo_id,
                filename,
                revision,
                budget,
                prefix,
                MEDIA_ROUTE_TAIL_READ_BYTES,
            )
            media_route = _detect_bounded_media_route_from_edges(remote_path, prefix, media_tail)
        if media_route == VALID_MEDIA_ROUTING_FORMAT:
            return None
        if media_route is not None:
            return media_route
        if _could_start_bounded_media_route(remote_path, prefix):
            return PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    if _could_start_proto0_or_1_pickle(prefix):
        pickle_probe = _read_huggingface_probe(
            repo_id,
            filename,
            revision,
            budget,
            prefix,
            PROTO0_1_MAX_PROBE_BYTES,
        )
        if _looks_like_proto0_or_1_pickle(
            pickle_probe,
            sample_is_prefix=len(pickle_probe) >= PROTO0_1_MAX_PROBE_BYTES,
        ):
            flax_route = _detect_huggingface_flax_msgpack_route(repo_id, filename, revision, budget, prefix)
            if flax_route is not None:
                return flax_route
            return "pickle"
    if _allows_renamed_binary_content_route(remote_path):
        executorch_state = _probe_huggingface_executorch_prefix(
            prefix,
            sample_is_prefix=_huggingface_sample_is_prefix(
                budget,
                filename,
                prefix,
                _HF_CONTENT_SNIFF_BYTES,
            ),
        )
        if executorch_state is not False:
            return "executorch"

    torch7_route = _detect_huggingface_torch7_route(repo_id, filename, revision, budget, prefix)
    if torch7_route is not None:
        return torch7_route

    rknn_route = _detect_huggingface_rknn_route(filename, prefix)
    if prefix[:4] == b"RKNN":
        return rknn_route

    detected_format = detect_format_from_magic_bytes(
        prefix[:4],
        prefix[:8],
        prefix[:16],
        max(len(prefix), 1),
        None,
        pickle_probe_sample=prefix,
        pickle_probe_is_prefix=_huggingface_sample_is_prefix(
            budget,
            filename,
            prefix,
            _HF_CONTENT_SNIFF_BYTES,
        ),
    )
    if detected_format in {"rknn", "torch7"} and not _allows_renamed_binary_content_route(remote_path):
        detected_format = "unknown"
    if detected_format == "cntk" and remote_path.suffix.lower() == ".model":
        detected_format = "unknown"
    if detected_format == "pickle":
        flax_route = _detect_huggingface_flax_msgpack_route(repo_id, filename, revision, budget, prefix)
        if flax_route is not None:
            return flax_route
    tflite_route_blocked = remote_path.suffix.lower() in _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS
    if detected_format == "tflite" and tflite_route_blocked:
        detected_format = "unknown"
    if (
        detected_format == "unknown"
        and not tflite_route_blocked
        and prefix[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + len(_TFLITE_MAGIC_BYTES)] == _TFLITE_MAGIC_BYTES
    ):
        return "tflite"
    if detected_format != "unknown":
        return detected_format

    if _is_complete_huggingface_text_owner_or_json_probe(
        repo_id,
        filename,
        revision,
        budget,
        prefix,
        _HF_CONTENT_SNIFF_BYTES,
        preserve_protobuf_model_candidates=True,
    ):
        return None
    if _is_huggingface_text_owner_prefix(
        filename,
        prefix,
        preserve_protobuf_model_candidates=True,
    ):
        return _detect_huggingface_text_owner_embedded_binary_route(repo_id, filename, revision, budget, prefix)

    if (
        remote_path.suffix.lower() in _CONTENT_ROUTE_TEXT_OWNER_SUFFIXES
        and not prefix.startswith(b":")
        and _starts_with_non_ascii_length_delimited_proto_prefix(prefix)
    ):
        return PROTOBUF_MODEL_CANDIDATE_FORMAT

    protobuf_route = _detect_huggingface_protobuf_model_route(repo_id, filename, revision, budget, prefix)
    if protobuf_route is not None:
        return protobuf_route

    return _detect_huggingface_flax_msgpack_route(repo_id, filename, revision, budget, prefix)


def _select_huggingface_model_files(
    repo_id: str,
    repo_files: list[str],
    revision: str,
    model_extensions: Collection[str],
    *,
    allow_content_probes: bool = True,
    allow_inaccessible_probe_errors: bool = False,
    inaccessible_probe_files: list[str] | None = None,
    deadline: float | None = None,
) -> list[str]:
    """Select extension-matching files plus bounded content-routed renamed model files."""
    model_files = list(
        dict.fromkeys(filename for filename in repo_files if _is_scannable_hf_file(filename, model_extensions))
    )
    if not allow_content_probes:
        candidate_files = _metadata_only_hf_content_probe_candidates(repo_files, model_files)
        if candidate_files:
            _raise_metadata_only_hf_selection_incomplete(repo_id, candidate_files)
        return model_files

    selected_files = set(model_files)
    inspected_files = 0
    probe_budget = _HuggingFaceProbeBudget(
        remaining_bytes=_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES,
        deadline=deadline,
    )

    for filename in repo_files:
        if filename in selected_files:
            continue
        if _is_huggingface_repo_bookkeeping_file(filename):
            continue
        if inspected_files >= _HF_CONTENT_SNIFF_MAX_FILES:
            raise ValueError(
                "Hugging Face selective filtering incomplete: skipped file inspection limit exceeded "
                f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_FILES} files)"
            )
        inspected_files += 1
        try:
            detected_format = _detect_huggingface_content_route_format(repo_id, filename, revision, probe_budget)
        except Exception as exc:
            if allow_inaccessible_probe_errors and _is_huggingface_gated_or_auth_error(exc):
                logger.debug(
                    "Skipping inaccessible gated Hugging Face content probe for %s/%s: %s",
                    repo_id,
                    filename,
                    redact_huggingface_urls_in_text(str(exc)),
                )
                if inaccessible_probe_files is not None and filename not in inaccessible_probe_files:
                    inaccessible_probe_files.append(filename)
                continue
            raise
        if detected_format is None:
            continue
        model_files.append(filename)
        selected_files.add(filename)

    return model_files


def _metadata_only_hf_content_probe_candidates(repo_files: list[str], selected_files: Collection[str]) -> list[str]:
    """Return unselected repo files whose inclusion cannot be proven without content probes."""
    selected_file_set = set(selected_files)
    return list(
        dict.fromkeys(
            filename
            for filename in repo_files
            if filename not in selected_file_set and not _is_huggingface_repo_bookkeeping_file(filename)
        )
    )


def _raise_metadata_only_hf_selection_incomplete(repo_id: str, candidate_files: Collection[str]) -> None:
    """Fail closed when metadata-only dry-runs cannot prove content-routed selection."""
    candidates = list(candidate_files)
    preview = ", ".join(candidates[:3])
    if len(candidates) > 3:
        preview = f"{preview}, ..."
    candidate_label = "file" if len(candidates) == 1 else "files"
    raise ValueError(
        "Hugging Face metadata-only dry-run selection incomplete: "
        f"dry-run refuses for {repo_id} because it cannot prove selection without content probes; "
        f"{len(candidates)} unselected non-bookkeeping repository {candidate_label} would require "
        f"artifact content probing: {preview}"
    )


def _build_literal_allow_patterns(filenames: list[str]) -> list[str]:
    """Escape repository filenames before passing them to the Hub glob filter."""
    return [escape_glob(filename) for filename in filenames]


def _remote_companion_path_key(filename: str) -> str:
    return unicodedata.normalize("NFC", filename).casefold()


def _openvino_bin_companion_name(filename: str, repo_files: Collection[str] | None = None) -> str | None:
    """Return the exact same-stem OpenVINO weights filename for a repo XML path."""
    remote_path = PurePosixPath(filename)
    if remote_path.suffix.lower() != ".xml":
        return None
    expected_companion = remote_path.with_suffix(".bin").as_posix()
    if repo_files is None or expected_companion in repo_files:
        return expected_companion

    expected_key = _remote_companion_path_key(expected_companion)
    candidates = [repo_file for repo_file in repo_files if _remote_companion_path_key(repo_file) == expected_key]
    if len(candidates) == 1:
        return candidates[0]
    return expected_companion


def _include_huggingface_openvino_companions(
    repo_id: str,
    repo_files: list[str],
    revision: str,
    model_files: list[str],
    *,
    allow_content_probes: bool = True,
    include_openvino_companions: bool = True,
    deadline: float | None = None,
) -> list[str]:
    """Include exact OpenVINO XML/BIN companions before size checks and downloads."""
    if not include_openvino_companions:
        return model_files

    from modelaudit.utils.file.detection import XML_MODEL_INCONCLUSIVE_FORMAT

    repo_file_set = set(repo_files)
    selected_files = set(model_files)
    expanded_files = list(model_files)
    probe_budget = _HuggingFaceProbeBudget(
        remaining_bytes=_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES,
        deadline=deadline,
    )

    for filename in model_files:
        companion = _openvino_bin_companion_name(filename, repo_files)
        if companion is None or companion not in repo_file_set or companion in selected_files:
            continue

        if not allow_content_probes:
            _raise_metadata_only_hf_selection_incomplete(repo_id, [companion])

        detected_format = _detect_huggingface_content_route_format(repo_id, filename, revision, probe_budget)
        if detected_format not in {"openvino", XML_MODEL_INCONCLUSIVE_FORMAT}:
            continue

        expanded_files.append(companion)
        selected_files.add(companion)

    return expanded_files


def _extract_huggingface_repo_files(repo_info: Any) -> list[str] | None:
    """Extract repository filenames from a Hugging Face repository response."""
    siblings = getattr(repo_info, "siblings", None)
    if siblings is None:
        return None

    files: list[str] = []
    for sibling in siblings:
        if isinstance(sibling, dict):
            file_name = sibling.get("rfilename") or sibling.get("path")
        else:
            file_name = getattr(sibling, "rfilename", None) or getattr(sibling, "path", None)

        if isinstance(file_name, str) and file_name:
            files.append(file_name)
    return files


def _validate_huggingface_repo_filename(repo_id: str, filename: str) -> str:
    """Return a safe POSIX repository filename or fail closed."""
    if len(filename) > _MAX_HF_REPOSITORY_PATH_CHARS:
        raise ValueError(
            "Hugging Face repository inventory incomplete: repository filename exceeds "
            f"the bounded path length ({_MAX_HF_REPOSITORY_PATH_CHARS}) for {repo_id}"
        )
    if not filename or filename.startswith("/") or "\x00" in filename or "\\" in filename:
        raise ValueError(f"Hugging Face repository inventory incomplete: unsafe repository filename for {repo_id}")
    if any(ord(character) < 32 or ord(character) == 127 for character in filename):
        raise ValueError(f"Hugging Face repository inventory incomplete: unsafe repository filename for {repo_id}")

    parts = filename.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"Hugging Face repository inventory incomplete: unsafe repository filename for {repo_id}")
    return filename


def _normalize_huggingface_repo_files(repo_id: str, filenames: Collection[str]) -> list[str]:
    """Validate, deduplicate, bound, and deterministically order repository filenames."""
    normalized: set[str] = set()
    for filename in filenames:
        safe_filename = _validate_huggingface_repo_filename(repo_id, filename)
        normalized.add(safe_filename)
        if len(normalized) > _MAX_HF_REPOSITORY_INVENTORY_FILES:
            raise ValueError(
                "Hugging Face repository inventory incomplete: repository file count exceeds "
                f"the bounded inventory limit ({_MAX_HF_REPOSITORY_INVENTORY_FILES}) for {repo_id}"
            )
    return sorted(normalized)


def _is_scannable_hf_file(filename: str, extensions: Collection[str]) -> bool:
    """Return whether a listed Hugging Face file has a supported suffix."""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext.lower()) for ext in extensions if ext)


def _is_huggingface_repo_bookkeeping_file(filename: str) -> bool:
    """Return whether a Hub repo entry is fixed metadata, not model payload."""
    return PurePosixPath(filename).name.lower() in _HF_REPO_BOOKKEEPING_FILENAMES


def _raise_no_scannable_hf_files(repo_id: str) -> None:
    raise Exception(
        f"Refusing to download full snapshot for {repo_id}: "
        "repository listing contains no recognized ModelAudit-scannable files"
    )


def _get_default_hf_streaming_extensions() -> set[str]:
    """Return remotely scannable suffixes, including safe extensionless routes."""
    from ...scanner_registry_metadata import get_scanner_registry_metadata

    extensions = set(_get_model_extensions())
    for scanner_info in get_scanner_registry_metadata().values():
        scanner_extensions = {str(extension).lower() for extension in scanner_info.get("extensions", [])}
        remote_excluded_extensions = {
            str(extension).lower() for extension in scanner_info.get("remote_excluded_extensions", [])
        }
        if "" in scanner_extensions and "" not in remote_excluded_extensions:
            extensions.add("")
            break
    return extensions


def _get_default_hf_streaming_filenames() -> set[str]:
    """Return exact remotely scannable basenames without widening them to suffix routes."""
    from ...scanner_registry_metadata import get_scanner_registry_metadata

    filenames: set[str] = set()
    for scanner_info in get_scanner_registry_metadata().values():
        remote_excluded_extensions = {
            str(extension).lower() for extension in scanner_info.get("remote_excluded_extensions", [])
        }
        for filename in scanner_info.get("content_routed_filenames", []):
            filename_text = str(filename).lower()
            if PurePosixPath(filename_text).suffix.lower() not in remote_excluded_extensions:
                filenames.add(filename_text)
    return filenames


def _get_hf_content_route_formats() -> set[str]:
    """Return every format the bounded Hugging Face content probe may emit."""
    from modelaudit.utils.file.detection import (
        EXECUTABLE_ZIP_POLYGLOT_FORMAT,
        LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
        MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
        PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
        XML_MODEL_INCONCLUSIVE_FORMAT,
    )

    from ...scanner_registry_metadata import EXTENSION_FORMAT_MAP

    content_route_formats = set(EXTENSION_FORMAT_MAP.values())
    content_route_formats.update(
        {
            EXECUTABLE_ZIP_POLYGLOT_FORMAT,
            LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
            MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
            PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
            PROTOBUF_MODEL_CANDIDATE_FORMAT,
            TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
            XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
            XML_MODEL_INCONCLUSIVE_FORMAT,
            "coreml",
            "flax_msgpack",
            "jax_checkpoint",
            "mxnet",
            "onnx",
            "openvino",
            "pmml",
            "tf_metagraph",
            "tf_savedmodel",
            "xgboost",
        }
    )
    return content_route_formats


def _get_hf_content_route_scanner_ids() -> set[str]:
    """Return scanners that can consume a bounded Hugging Face content route."""
    from ...scanner_selection import scanner_ids_for_detected_format

    scanner_ids: set[str] = set()
    for format_name in _get_hf_content_route_formats():
        scanner_ids.update(scanner_ids_for_detected_format(format_name))
    return scanner_ids


@cache
def _hf_safetensors_route_scanner_ids() -> frozenset[str]:
    from ...scanner_selection import scanner_ids_for_detected_format

    return scanner_ids_for_detected_format("safetensors")


@cache
def _hf_route_scanner_ids_for_formats(format_names: frozenset[str]) -> frozenset[str]:
    from ...scanner_selection import scanner_ids_for_detected_format

    scanner_ids: set[str] = set()
    for format_name in format_names:
        scanner_ids.update(scanner_ids_for_detected_format(format_name))
    return frozenset(scanner_ids)


def _hf_safetensors_shard_excluded_by_selection(
    filename: str,
    selected_route_scanner_ids: set[str] | None,
    selected_route_formats: set[str] | None,
    *,
    complete_safetensors_shard_files: Collection[str] | None = None,
) -> bool:
    """Return whether no selected scanner can claim a declared SafeTensors shard."""
    if _parse_hf_safetensors_shard(filename) is None:
        return False
    if complete_safetensors_shard_files is not None and filename not in complete_safetensors_shard_files:
        return False

    # SafeTensors content routes intentionally include overlap-capable scanners
    # such as pickle and compressed, not only the SafeTensors scanner itself.
    safetensors_route_scanner_ids = _hf_safetensors_route_scanner_ids()
    if selected_route_scanner_ids is not None:
        selected_safetensors_routes = selected_route_scanner_ids.intersection(safetensors_route_scanner_ids)
        return not selected_safetensors_routes
    if selected_route_formats is None:
        return False

    selected_format_route_scanner_ids = _hf_route_scanner_ids_for_formats(frozenset(selected_route_formats))
    return not selected_format_route_scanner_ids.intersection(safetensors_route_scanner_ids)


def _parse_hf_safetensors_shard(filename: str) -> tuple[str, int, int] | None:
    match = _HF_SAFETENSORS_SHARD_PATTERN.fullmatch(filename)
    if match is None:
        return None
    index = int(match.group("index"))
    total = int(match.group("total"))
    if index < 1 or total < 2 or index > total:
        return None
    return match.group("stem"), index, total


def _has_hf_safetensors_shard_shape(filename: str) -> bool:
    return _HF_SAFETENSORS_SHARD_SHAPE_PATTERN.fullmatch(filename) is not None


def _complete_hf_safetensors_shard_files(repo_files: Collection[str]) -> frozenset[str]:
    """Return canonical SafeTensors shards whose directory-scoped family is complete."""
    families: dict[tuple[str, int], dict[int, set[str]]] = {}
    for filename in repo_files:
        parsed = _parse_hf_safetensors_shard(filename)
        if parsed is None:
            continue
        stem, index, total = parsed
        families.setdefault((stem, total), {}).setdefault(index, set()).add(filename)

    complete_files: set[str] = set()
    for (_stem, total), indexed_files in families.items():
        if len(indexed_files) != total:
            continue
        if any(index not in indexed_files or len(indexed_files[index]) != 1 for index in range(1, total + 1)):
            continue
        for filenames in indexed_files.values():
            complete_files.update(filenames)
    return frozenset(complete_files)


def _hf_detected_format_excluded_by_selected_route_formats(
    detected_format: str,
    selected_route_formats: set[str],
) -> bool:
    """Return whether inferred route formats cannot claim a detected route."""
    normalized_detected_format = str(detected_format).lower()
    if normalized_detected_format in selected_route_formats:
        return False

    from ...scanner_selection import scanner_ids_for_detected_format

    selected_route_scanner_ids = _hf_route_scanner_ids_for_formats(frozenset(selected_route_formats))
    detected_route_scanner_ids = scanner_ids_for_detected_format(normalized_detected_format)
    return not selected_route_scanner_ids.intersection(detected_route_scanner_ids)


def _get_selected_hf_content_route_formats(
    scannable_extensions: Collection[str] | None,
    scannable_filenames: Collection[str] | None,
) -> set[str] | None:
    """Infer content formats when callers do not provide exact scanner policy."""
    if scannable_extensions is None and scannable_filenames is None:
        return None

    from ...scanner_registry_metadata import EXTENSION_FORMAT_MAP, get_scanner_registry_metadata

    content_route_formats = _get_hf_content_route_formats()
    selected_extensions: set[str] = (
        set() if scannable_extensions is None else {str(extension).lower() for extension in scannable_extensions}
    )
    selected_filenames = (
        set() if scannable_filenames is None else {str(filename).lower() for filename in scannable_filenames}
    )
    for filename in selected_filenames:
        suffix = PurePosixPath(filename).suffix.lower()
        if suffix:
            selected_extensions.add(suffix)

    scanner_metadata = get_scanner_registry_metadata()
    extension_claimants: dict[str, set[str]] = {extension: set() for extension in selected_extensions if extension}
    for scanner_id, scanner_info in scanner_metadata.items():
        remote_excluded_extensions = {
            str(extension).lower() for extension in scanner_info.get("remote_excluded_extensions", [])
        }
        for key in ("extensions", "content_routed_extensions", "scanner_only_extensions"):
            for extension in scanner_info.get(key, []):
                extension_text = str(extension).lower()
                if extension_text in extension_claimants and extension_text not in remote_excluded_extensions:
                    extension_claimants[extension_text].add(scanner_id)

    selected_extensions = {
        extension
        for extension in selected_extensions
        if extension in EXTENSION_FORMAT_MAP
        or (
            len(extension_claimants.get(extension, set())) == 1
            and bool(extension_claimants.get(extension, set()).intersection(content_route_formats))
        )
    }
    selected_formats: set[str] = set()
    for scanner_id, scanner_info in scanner_metadata.items():
        remote_excluded_extensions = {
            str(extension).lower() for extension in scanner_info.get("remote_excluded_extensions", [])
        }
        scanner_extensions = {
            str(extension).lower()
            for key in ("extensions", "content_routed_extensions", "scanner_only_extensions")
            for extension in scanner_info.get(key, [])
            if str(extension).lower() not in remote_excluded_extensions
        }
        scanner_filenames = {str(filename).lower() for filename in scanner_info.get("content_routed_filenames", [])}
        matched_extensions = scanner_extensions.intersection(selected_extensions)
        if not matched_extensions and not scanner_filenames.intersection(selected_filenames):
            continue

        if scanner_id in content_route_formats:
            selected_formats.add(scanner_id)
        selected_formats.update(
            format_name
            for value in scanner_info.get("header_formats", [])
            if (format_name := str(value).lower()) in content_route_formats
        )
        selected_formats.update(
            mapped_format
            for extension in matched_extensions
            if (mapped_format := EXTENSION_FORMAT_MAP.get(extension)) is not None
        )
    return selected_formats


def _streamable_hf_content_probe_candidates(
    repo_files: list[str],
    selected_files: Collection[str],
    selected_route_scanner_ids: set[str] | None,
    selected_route_formats: set[str] | None,
    exact_openvino_companion_candidates: Collection[str],
) -> list[str]:
    """Return streaming files that the renamed-file sniff loop would inspect."""
    processed_files = set(selected_files)
    exact_openvino_companion_candidate_set = set(exact_openvino_companion_candidates)
    complete_safetensors_shard_files = _complete_hf_safetensors_shard_files(repo_files)
    candidates: list[str] = []
    for file_name in repo_files:
        if file_name in processed_files:
            continue
        processed_files.add(file_name)
        if _is_huggingface_repo_bookkeeping_file(file_name):
            continue
        if file_name in exact_openvino_companion_candidate_set:
            continue
        if _hf_safetensors_shard_excluded_by_selection(
            file_name,
            selected_route_scanner_ids,
            selected_route_formats,
            complete_safetensors_shard_files=complete_safetensors_shard_files,
        ):
            continue
        candidates.append(file_name)
    return candidates


def _select_streamable_hf_files(
    repo_id: str,
    repo_files: list[str],
    revision: str,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    *,
    allow_content_probes: bool = True,
    include_all_files: bool = False,
    include_all_files_unbounded_extra_limit: int | None = None,
    deadline: float | None = None,
) -> _HuggingFaceStreamingSelection:
    """Select bounded remotely scannable files without treating ``""`` as a wildcard."""
    selected_route_formats: set[str] | None = None
    selected_route_scanner_ids: set[str] | None = None
    if scannable_scanner_ids is not None:
        selected_route_scanner_ids = {str(scanner_id).lower() for scanner_id in scannable_scanner_ids}.intersection(
            _get_hf_content_route_scanner_ids()
        )
    else:
        selected_route_formats = _get_selected_hf_content_route_formats(scannable_extensions, scannable_filenames)
    sniff_renamed_files_would_be_active = not include_all_files and (
        bool(selected_route_scanner_ids)
        if selected_route_scanner_ids is not None
        else selected_route_formats is None or bool(selected_route_formats)
    )
    sniff_renamed_files = allow_content_probes and sniff_renamed_files_would_be_active
    if scannable_extensions is None:
        extensions = _get_default_hf_streaming_extensions()
        filenames = (
            _get_default_hf_streaming_filenames()
            if scannable_filenames is None
            else {str(filename).lower() for filename in scannable_filenames}
        )
    else:
        extensions = {str(extension).lower() for extension in scannable_extensions}
        filenames = (
            set() if scannable_filenames is None else {str(filename).lower() for filename in scannable_filenames}
        )
    model_files: list[str] = []
    content_route_formats: dict[str, str] = {}
    extensionless_count = 0
    include_all_extra_count = 0
    seen_files: set[str] = set()

    for file_name in repo_files:
        if file_name in seen_files:
            continue
        seen_files.add(file_name)

        if _is_scannable_hf_file(file_name, extensions):
            model_files.append(file_name)
            continue

        remote_path = PurePosixPath(file_name)
        is_extensionless = not remote_path.suffixes
        if remote_path.name.lower() in filenames:
            model_files.append(file_name)
            continue

        if _is_huggingface_repo_bookkeeping_file(file_name):
            continue

        if include_all_files:
            if include_all_files_unbounded_extra_limit is not None:
                include_all_extra_count += 1
                if include_all_extra_count > include_all_files_unbounded_extra_limit:
                    raise ValueError(
                        "Refusing to stream-download all files from "
                        f"{repo_id}: include_all_files=True without max_size selected more than "
                        f"{include_all_files_unbounded_extra_limit} otherwise-unrecognized file(s); "
                        "set max_size to bound aggregate transfer size"
                    )
            model_files.append(file_name)
            continue

        if "" in extensions and is_extensionless:
            extensionless_count += 1
            if extensionless_count > _MAX_HF_STREAMING_EXTENSIONLESS_FILES:
                raise Exception(
                    f"Refusing to stream-download extensionless files from {repo_id}: "
                    f"repository listing exceeds the bounded extensionless candidate limit "
                    f"({_MAX_HF_STREAMING_EXTENSIONLESS_FILES}); streaming coverage is incomplete"
                )
            model_files.append(file_name)

    exact_openvino_companion_candidates = (
        {
            companion
            for selected_file in model_files
            if (companion := _openvino_bin_companion_name(selected_file, repo_files)) is not None
        }
        if selected_route_scanner_ids == {"openvino"}
        else set()
    )

    if not allow_content_probes and sniff_renamed_files_would_be_active:
        candidate_files = _streamable_hf_content_probe_candidates(
            repo_files,
            model_files,
            selected_route_scanner_ids,
            selected_route_formats,
            exact_openvino_companion_candidates,
        )
        if candidate_files:
            _raise_metadata_only_hf_selection_incomplete(repo_id, candidate_files)

    if sniff_renamed_files:
        inspected_files = 0
        probe_budget = _HuggingFaceProbeBudget(
            remaining_bytes=_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES,
            deadline=deadline,
        )
        unskippable_detected_safetensors_shards: list[str] = []
        for file_name in _streamable_hf_content_probe_candidates(
            repo_files,
            model_files,
            selected_route_scanner_ids,
            selected_route_formats,
            exact_openvino_companion_candidates,
        ):
            if _is_safetensors_index_file(file_name):
                continue
            if inspected_files >= _HF_CONTENT_SNIFF_MAX_FILES:
                raise ValueError(
                    "Hugging Face selective filtering incomplete: skipped file inspection limit exceeded "
                    f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_FILES} files)"
                )
            inspected_files += 1
            detected_format = _detect_huggingface_content_route_format(repo_id, file_name, revision, probe_budget)
            if detected_format is None:
                continue
            if selected_route_scanner_ids is not None:
                from ...scanner_selection import scanner_ids_for_detected_format

                if not selected_route_scanner_ids.intersection(scanner_ids_for_detected_format(detected_format)):
                    if detected_format == "safetensors" and _has_hf_safetensors_shard_shape(file_name):
                        unskippable_detected_safetensors_shards.append(file_name)
                    continue
            elif selected_route_formats is not None and _hf_detected_format_excluded_by_selected_route_formats(
                detected_format,
                selected_route_formats,
            ):
                if detected_format == "safetensors" and _has_hf_safetensors_shard_shape(file_name):
                    unskippable_detected_safetensors_shards.append(file_name)
                continue
            model_files.append(file_name)
            content_route_formats[file_name] = detected_format
        if unskippable_detected_safetensors_shards:
            preview = ", ".join(unskippable_detected_safetensors_shards[:3])
            if len(unskippable_detected_safetensors_shards) > 3:
                preview = f"{preview}, ..."
            raise ValueError(
                "Hugging Face selective filtering incomplete: detected SafeTensors shard candidates "
                f"that do not form a complete canonical shard family for {repo_id}: {preview}; "
                "streaming coverage is incomplete"
            )

    if not model_files:
        _raise_no_scannable_hf_files(repo_id)

    return _HuggingFaceStreamingSelection(model_files, content_route_formats)


def _is_hf_streaming_onnx_candidate(filename: str, *, content_route_format: str | None = None) -> bool:
    """Return whether a selected remote file should be checked for ONNX sidecars."""
    return PurePosixPath(filename).suffix.lower() == ".onnx" or content_route_format == "onnx"


def _resolve_hf_onnx_external_data_path(onnx_filename: str, location: str) -> str | None:
    """Resolve a declared ONNX external_data location to a safe repo-relative path."""
    if (
        not location
        or "\x00" in location
        or "\\" in location
        or location.startswith("/")
        or ntpath.isabs(location.replace("/", "\\"))
    ):
        return None

    normalized_location = posixpath.normpath(location)
    if normalized_location in {"", "."} or normalized_location == ".." or normalized_location.startswith("../"):
        return None

    onnx_parent = PurePosixPath(onnx_filename).parent
    candidate = onnx_parent / PurePosixPath(normalized_location)
    parent_parts = () if str(onnx_parent) == "." else onnx_parent.parts
    if candidate.parts[: len(parent_parts)] != parent_parts:
        return None
    return candidate.as_posix()


def _discover_hf_onnx_external_data_files(
    onnx_path: Path,
    onnx_filename: str,
    repo_files: set[str],
) -> list[str]:
    """Return safe declared ONNX external_data companions present in the repo listing."""
    try:
        import onnx

        from ...scanners.onnx_scanner import _iter_model_external_data_tensor_groups
    except Exception:
        return []

    try:
        model = onnx.load(str(onnx_path), load_external_data=False)
    except Exception:
        return []

    companions: list[str] = []
    seen: set[str] = set()
    for tensors in _iter_model_external_data_tensor_groups(model):
        for tensor in tensors:
            if tensor.data_location != onnx.TensorProto.EXTERNAL:
                continue
            info = {entry.key: entry.value for entry in tensor.external_data}
            location = info.get("location")
            if not isinstance(location, str):
                continue
            companion = _resolve_hf_onnx_external_data_path(onnx_filename, location)
            if companion is None or companion == onnx_filename or companion not in repo_files or companion in seen:
                continue
            seen.add(companion)
            companions.append(companion)
            if len(companions) > _MAX_HF_STREAMING_ONNX_EXTERNAL_DATA_FILES:
                raise ValueError(
                    "Hugging Face ONNX external_data coverage incomplete: "
                    f"{onnx_filename} declares more than "
                    f"{_MAX_HF_STREAMING_ONNX_EXTERNAL_DATA_FILES} external data files"
                )
    return companions


def _get_hf_onnx_external_data_sizes(
    repo_id: str,
    filenames: list[str],
    *,
    revision: str,
    deadline: float | None,
) -> dict[str, int]:
    """Return exact sizes for ONNX sidecars, failing closed on missing metadata."""
    sizes, _revision = _get_huggingface_path_sizes(
        repo_id,
        filenames,
        resolved_revision=revision,
        deadline=deadline,
    )
    exact_sizes: dict[str, int] = {}
    for filename in filenames:
        size = sizes.get(filename)
        if size is None:
            raise ValueError(f"Cannot download {repo_id}: unknown size for ONNX external_data file {filename}")
        exact_sizes[filename] = size
    return exact_sizes


def _get_hf_cache_root() -> Path:
    """Return the HuggingFace hub cache root."""
    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        return Path(HF_HUB_CACHE)
    except Exception:
        return Path.home() / ".cache" / "huggingface" / "hub"


def _format_size(size_bytes: int) -> str:
    """Format a byte count for user-facing download budget errors."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _normalize_download_size_limit(max_size: int | None) -> int | None:
    """Normalize ModelAudit's zero-is-unlimited download size semantics."""
    if max_size is not None and max_size < 0:
        raise ValueError("Maximum download size must be non-negative")
    return max_size or None


def _is_huggingface_commit_sha(revision: object) -> bool:
    """Return whether revision is a full immutable Git commit SHA."""
    if not isinstance(revision, str) or len(revision) not in {40, 64}:
        return False
    try:
        int(revision, 16)
    except ValueError:
        return False
    return True


def _is_within_directory(base_dir: Path, target: Path) -> bool:
    """Return True when target resolves inside base_dir."""
    base_path = base_dir.resolve()
    target_path = target.resolve()
    if os.name == "nt":
        base_norm = os.path.normcase(os.path.normpath(str(base_path)))
        target_norm = os.path.normcase(os.path.normpath(str(target_path)))
        try:
            return os.path.commonpath([target_norm, base_norm]) == base_norm
        except ValueError:
            return False
    return target_path.is_relative_to(base_path)


def _is_huggingface_cache_blob_target(downloaded_path: Path, target: Path) -> bool:
    """Return True when target is a Hub cache blob for the snapshot path."""
    target_path = target.resolve()
    current_path = downloaded_path.resolve()
    for candidate in [current_path, *current_path.parents]:
        if candidate.parent.name == "snapshots":
            blob_dir = candidate.parent.parent / "blobs"
            return _is_within_directory(blob_dir, target_path)
    return False


def _build_huggingface_download_path(cache_dir: Path, namespace: str, repo_name: str) -> Path:
    """Build and containment-check the local HuggingFace download path."""
    cache_root = (cache_dir / "huggingface").resolve()
    download_path = cache_root / namespace
    if repo_name:
        download_path = download_path / repo_name
    resolved_download_path = download_path.resolve()
    if not _is_within_directory(cache_root, resolved_download_path):
        raise ValueError(f"HuggingFace cache path escaped cache directory: {resolved_download_path}")
    return resolved_download_path


def _list_repo_files_with_timeout(
    repo_id: str,
    timeout_seconds: float = 30,
    *,
    requested_revision: str | None = None,
    deadline: float | None = None,
    revision: str | None = None,
) -> tuple[list[str] | None, str | None, str | None]:
    """Return repository files, their immutable revision, or a failure reason."""
    effective_revision = revision if revision is not None else requested_revision
    if deadline is not None:
        operation_kwargs: dict[str, Any] = {"repo_id": repo_id, "request_timeout": timeout_seconds}
        if effective_revision is not None:
            operation_kwargs["revision"] = effective_revision
        try:
            worker_result = _run_huggingface_worker_with_deadline(
                "list_repo_files",
                operation_kwargs,
                deadline,
                repo_id,
            )
        except Exception as exc:
            return None, None, str(exc)
        value = worker_result.get("value")
        if not isinstance(value, dict):
            return None, None, "repository listing returned an invalid response"
        raw_files = value.get("files")
        if raw_files is None:
            return None, None, "repository listing unavailable"
        if not isinstance(raw_files, list) or not all(isinstance(file_name, str) for file_name in raw_files):
            return None, None, "repository listing returned invalid filenames"
        worker_revision = value.get("revision")
        if not _is_huggingface_commit_sha(worker_revision):
            return None, None, "repository listing did not include an immutable commit SHA"
        assert isinstance(worker_revision, str)
        try:
            worker_files = _normalize_huggingface_repo_files(repo_id, cast(list[str], raw_files))
        except ValueError as exc:
            return None, None, str(exc)
        return worker_files, worker_revision, None

    try:
        files, resolved_revision = _list_huggingface_repo_files_at_revision(
            repo_id,
            requested_revision=effective_revision,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        return None, None, str(exc)
    return files, resolved_revision, None


def _run_huggingface_worker_with_deadline(
    operation: str,
    operation_kwargs: dict[str, Any],
    deadline: float,
    repo_id: str,
) -> dict[str, Any]:
    """Run one serializable Hugging Face operation in a terminable subprocess."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

    payload = json.dumps({"operation": operation, "operation_kwargs": operation_kwargs})
    process = subprocess.Popen(
        [sys.executable, "-m", "modelaudit.utils.sources._huggingface_download_worker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=os.name != "nt",
    )
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout=0)
        stdout, _stderr = process.communicate(payload, timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        _terminate_huggingface_download_process(process)
        raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}") from exc
    except BaseException:
        _terminate_huggingface_download_process(process)
        raise

    result_line = next(
        (line for line in reversed(stdout.splitlines()) if line.startswith(_HF_DOWNLOAD_WORKER_RESULT_PREFIX)),
        None,
    )
    if result_line is None:
        raise RuntimeError(f"Hugging Face download worker failed for {repo_id}")

    raw_result: object = json.loads(result_line.removeprefix(_HF_DOWNLOAD_WORKER_RESULT_PREFIX))
    if not isinstance(raw_result, dict):
        raise RuntimeError(f"Hugging Face download worker returned an invalid result for {repo_id}")
    result = cast(dict[str, Any], raw_result)
    if not result.get("ok"):
        error_type = result.get("error_type", "Exception")
        error_message = redact_huggingface_urls_in_text(str(result.get("error", "download failed")))
        raise RuntimeError(f"{error_type}: {error_message}")

    return result


def _run_huggingface_download_with_deadline(
    operation: str,
    download_kwargs: dict[str, Any],
    deadline: float | None,
    repo_id: str,
    *,
    direct_download: Callable[..., Any] | None = None,
) -> str:
    """Run an SDK download directly or in a terminable subprocess when bounded."""
    if operation not in {"snapshot_download", "hf_hub_download"}:
        raise ValueError(f"Unsupported Hugging Face download operation: {operation}")

    if deadline is None:
        if direct_download is None:
            if operation == "snapshot_download":
                from huggingface_hub import snapshot_download

                direct_download = snapshot_download
            else:
                from huggingface_hub import hf_hub_download

                direct_download = hf_hub_download
        return str(direct_download(**download_kwargs))

    result = _run_huggingface_worker_with_deadline(operation, download_kwargs, deadline, repo_id)

    local_path = result.get("path")
    if not isinstance(local_path, str):
        raise RuntimeError(f"Hugging Face download worker returned an invalid path for {repo_id}")
    return local_path


def _terminate_huggingface_download_process(process: subprocess.Popen[str]) -> None:
    """Stop a timed-out download worker without waiting indefinitely for cleanup."""
    if os.name == "nt":
        with suppress(ProcessLookupError):
            process.terminate()
    else:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, _POSIX_TERMINATE_SIGNAL)
    try:
        process.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            with suppress(ProcessLookupError):
                process.kill()
        else:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, _POSIX_KILL_SIGNAL)
        process.communicate()


def _extract_huggingface_tree_page_files(repo_id: str, page_items: object) -> list[str]:
    """Extract file paths from one Hugging Face tree API page."""
    if not isinstance(page_items, list):
        raise ValueError(f"Hugging Face repository inventory incomplete: invalid tree page for {repo_id}")

    files: list[str] = []
    for item in page_items:
        if not isinstance(item, dict):
            raise ValueError(f"Hugging Face repository inventory incomplete: invalid tree item for {repo_id}")
        item_type = item.get("type")
        if item_type not in {"file", "directory"}:
            raise ValueError(f"Hugging Face repository inventory incomplete: unknown tree item type for {repo_id}")
        path = item.get("path")
        if not isinstance(path, str):
            raise ValueError(f"Hugging Face repository inventory incomplete: invalid repository filename for {repo_id}")
        safe_path = _validate_huggingface_repo_filename(repo_id, path)
        if item_type == "directory":
            continue
        files.append(safe_path)
    return files


def _read_bounded_huggingface_tree_response(response: Any, repo_id: str) -> object:
    """Read and decode one bounded Hugging Face tree API page."""
    headers = getattr(response, "headers", {})
    content_length = headers.get("Content-Length") if hasattr(headers, "get") else None
    if content_length is not None:
        try:
            response_size = int(content_length)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Hugging Face repository inventory incomplete: invalid tree page size for {repo_id}"
            ) from exc
        if response_size < 0 or response_size > _MAX_HF_REPOSITORY_TREE_PAGE_RESPONSE_BYTES:
            raise ValueError(
                "Hugging Face repository inventory incomplete: tree page response exceeds "
                f"the bounded response limit ({_MAX_HF_REPOSITORY_TREE_PAGE_RESPONSE_BYTES} bytes) for {repo_id}"
            )

    payload = bytearray()
    iter_bytes = getattr(response, "iter_bytes", None)
    iter_content = getattr(response, "iter_content", None)
    if callable(iter_bytes):
        chunks = iter_bytes(chunk_size=_HF_REPOSITORY_TREE_RESPONSE_CHUNK_BYTES)
    elif callable(iter_content):
        chunks = iter_content(chunk_size=_HF_REPOSITORY_TREE_RESPONSE_CHUNK_BYTES)
    else:
        raise ValueError(f"Hugging Face repository inventory incomplete: invalid tree page response for {repo_id}")
    for chunk in chunks:
        if not chunk:
            continue
        payload.extend(chunk)
        if len(payload) > _MAX_HF_REPOSITORY_TREE_PAGE_RESPONSE_BYTES:
            raise ValueError(
                "Hugging Face repository inventory incomplete: tree page response exceeds "
                f"the bounded response limit ({_MAX_HF_REPOSITORY_TREE_PAGE_RESPONSE_BYTES} bytes) for {repo_id}"
            )

    try:
        return json.loads(bytes(payload))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Hugging Face repository inventory incomplete: invalid tree page JSON for {repo_id}") from exc


def _canonical_huggingface_tree_page_url(url: str) -> str:
    """Normalize tree page URLs enough to detect equivalent pagination loops."""
    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), doseq=True)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, query, ""))


def _validate_huggingface_tree_next_url(repo_id: str, current_url: str, next_url: str) -> str:
    """Return a safe same-origin tree pagination URL or fail closed."""
    if next_url.strip() != next_url or any(ord(char) < 32 or ord(char) == 127 for char in next_url):
        raise ValueError(f"Hugging Face repository inventory incomplete: invalid pagination link for {repo_id}")

    try:
        current_parts = urlsplit(current_url)
        next_parts = urlsplit(next_url)
        _ = (current_parts.port, next_parts.port)
    except ValueError as exc:
        raise ValueError(
            f"Hugging Face repository inventory incomplete: invalid pagination link for {repo_id}"
        ) from exc

    if (
        not next_parts.scheme
        or not next_parts.netloc
        or next_parts.username is not None
        or next_parts.password is not None
    ):
        raise ValueError(f"Hugging Face repository inventory incomplete: invalid pagination link for {repo_id}")

    if (
        next_parts.scheme.lower() != current_parts.scheme.lower()
        or next_parts.netloc.lower() != current_parts.netloc.lower()
    ):
        raise ValueError(f"Hugging Face repository inventory incomplete: pagination link changed origin for {repo_id}")

    return next_url


def _list_huggingface_repo_files_paginated(
    repo_id: str,
    revision: str,
    timeout_seconds: float = 30,
) -> list[str]:
    """Return a complete bounded repository file inventory at an immutable revision."""
    from huggingface_hub import HfApi
    from huggingface_hub.utils import build_hf_headers, get_session

    api = HfApi()
    next_url: str | None = f"{api.endpoint}/api/models/{repo_id}/tree/{quote(revision, safe='')}"
    params: dict[str, bool] | None = {"recursive": True, "expand": False}
    headers = build_hf_headers(token=None)
    session = get_session()
    seen_page_urls: set[str] = set()
    files: set[str] = set()
    page_count = 0

    while next_url is not None:
        canonical_next_url = _canonical_huggingface_tree_page_url(next_url)
        if canonical_next_url in seen_page_urls:
            raise ValueError(f"Hugging Face repository inventory incomplete: pagination cursor repeated for {repo_id}")
        seen_page_urls.add(canonical_next_url)
        page_count += 1
        if page_count > _MAX_HF_REPOSITORY_INVENTORY_PAGES:
            raise ValueError(
                "Hugging Face repository inventory incomplete: repository tree page count exceeds "
                f"the bounded pagination limit ({_MAX_HF_REPOSITORY_INVENTORY_PAGES}) for {repo_id}"
            )

        stream_response = getattr(session, "stream", None)
        if callable(stream_response):
            response_context = stream_response(
                "GET",
                next_url,
                headers=headers,
                params=params,
                timeout=timeout_seconds,
            )
        else:
            response_context = cast(Any, session).get(
                next_url, headers=headers, params=params, timeout=timeout_seconds, stream=True
            )
        with response_context as response:
            response.raise_for_status()
            page_items = _read_bounded_huggingface_tree_response(response, repo_id)

        for filename in _extract_huggingface_tree_page_files(repo_id, page_items):
            files.add(_validate_huggingface_repo_filename(repo_id, filename))
            if len(files) > _MAX_HF_REPOSITORY_INVENTORY_FILES:
                raise ValueError(
                    "Hugging Face repository inventory incomplete: repository file count exceeds "
                    f"the bounded inventory limit ({_MAX_HF_REPOSITORY_INVENTORY_FILES}) for {repo_id}"
                )

        links = getattr(response, "links", {})
        next_link = links.get("next") if isinstance(links, dict) else None
        next_candidate = next_link.get("url") if isinstance(next_link, dict) else None
        next_url = (
            _validate_huggingface_tree_next_url(repo_id, next_url, next_candidate)
            if isinstance(next_candidate, str) and next_candidate
            else None
        )
        params = None

    return sorted(files)


def _list_huggingface_repo_files_at_revision(
    repo_id: str,
    *,
    requested_revision: str | None = None,
    timeout_seconds: float = 30,
) -> tuple[list[str], str]:
    """Return repository filenames and the revision that produced the listing."""
    from huggingface_hub import HfApi

    repo_info_kwargs: dict[str, Any] = {"timeout": timeout_seconds, "files_metadata": False}
    if requested_revision is not None:
        repo_info_kwargs["revision"] = requested_revision
    repo_info = HfApi().repo_info(repo_id, **repo_info_kwargs)
    raw_revision = getattr(repo_info, "sha", None)
    if not _is_huggingface_commit_sha(raw_revision):
        raise Exception("repository listing did not include an immutable commit SHA")
    assert isinstance(raw_revision, str)

    files = _list_huggingface_repo_files_paginated(repo_id, raw_revision, timeout_seconds=timeout_seconds)
    return files, raw_revision


def _get_huggingface_path_sizes(
    repo_id: str,
    filenames: list[str],
    *,
    requested_revision: str | None = None,
    resolved_revision: str | None = None,
    deadline: float | None = None,
) -> tuple[dict[str, int | None], str]:
    """Return exact Hugging Face sizes for selected files and the checked revision."""
    if not filenames:
        return {}, ""

    if deadline is not None:
        worker_result = _run_huggingface_worker_with_deadline(
            "get_path_sizes",
            {
                "repo_id": repo_id,
                "filenames": filenames,
                "requested_revision": requested_revision,
                "resolved_revision": resolved_revision,
            },
            deadline,
            repo_id,
        )
        value = worker_result.get("value")
        if not isinstance(value, dict):
            raise Exception(f"Cannot enforce max-size for {repo_id}: invalid metadata response")
        raw_revision = value.get("revision")
        if not _is_huggingface_commit_sha(raw_revision):
            raise Exception(f"Cannot enforce max-size for {repo_id}: repository revision unavailable")
        assert isinstance(raw_revision, str)
        raw_sizes = value.get("sizes")
        if not isinstance(raw_sizes, list):
            raise Exception(f"Cannot enforce max-size for {repo_id}: file metadata unavailable")
        worker_sizes: dict[str, int | None] = {}
        for item in raw_sizes:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                continue
            raw_size = item.get("size")
            size = raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) and raw_size >= 0 else None
            path = item["path"]
            previous_size = worker_sizes.get(path)
            if path in worker_sizes and previous_size != size:
                raise Exception(
                    f"Cannot enforce max-size for {repo_id}: inconsistent size metadata for selected file {path}"
                )
            worker_sizes[path] = size
        return worker_sizes, raw_revision

    from huggingface_hub import HfApi

    api = HfApi()
    if resolved_revision is None:
        repo_info_kwargs: dict[str, Any] = {"files_metadata": False}
        if requested_revision is not None:
            repo_info_kwargs["revision"] = requested_revision
        repo_info = api.repo_info(repo_id, **repo_info_kwargs)
        raw_revision = getattr(repo_info, "sha", None)
        if not _is_huggingface_commit_sha(raw_revision):
            raise Exception(f"Cannot enforce max-size for {repo_id}: repository revision unavailable")
        assert isinstance(raw_revision, str)
        resolved_revision = raw_revision
    assert resolved_revision is not None
    path_info = []
    for start in range(0, len(filenames), _HF_PATH_INFO_BATCH_SIZE):
        path_info.extend(
            api.get_paths_info(
                repo_id,
                filenames[start : start + _HF_PATH_INFO_BATCH_SIZE],
                revision=resolved_revision,
            )
        )
    sizes: dict[str, int | None] = {}
    for item in path_info:
        path = getattr(item, "path", None)
        if not isinstance(path, str):
            continue
        raw_size = getattr(item, "size", None)
        size = raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) and raw_size >= 0 else None
        previous_size = sizes.get(path)
        if path in sizes and previous_size != size:
            raise Exception(
                f"Cannot enforce max-size for {repo_id}: inconsistent size metadata for selected file {path}"
            )
        sizes[path] = size
    return sizes, resolved_revision


def _ensure_huggingface_selection_within_max_size(
    repo_id: str,
    filenames: list[str],
    max_size: int | None,
    *,
    requested_revision: str | None = None,
    resolved_revision: str | None = None,
    deadline: float | None = None,
) -> tuple[str | None, dict[str, int]]:
    """Preflight selected files and return their pinned revision and verified sizes."""
    size_limit = _normalize_download_size_limit(max_size)
    if size_limit is None or not filenames:
        return None, {}

    filenames = list(dict.fromkeys(filenames))
    sizes, revision = _get_huggingface_path_sizes(
        repo_id,
        filenames,
        requested_revision=requested_revision,
        resolved_revision=resolved_revision,
        deadline=deadline,
    )
    total_size = 0
    for filename in filenames:
        size = sizes.get(filename)
        if size is None:
            raise Exception(f"Cannot download {repo_id}: unknown size for selected file {filename}")
        total_size += size
        if total_size > size_limit:
            raise Exception(
                f"Cannot download {repo_id}: selected Hugging Face files total {total_size} bytes "
                f"exceeds max size {size_limit} bytes"
            )
    return revision, {filename: size for filename, size in sizes.items() if size is not None}


def _verify_huggingface_selection_within_max_size(
    repo_id: str,
    downloaded_path: Path,
    filenames: list[str],
    max_size: int | None,
    *,
    initial_size: int = 0,
) -> int:
    """Fail closed when downloaded selected files cannot be verified within the cap."""
    size_limit = _normalize_download_size_limit(max_size)
    if size_limit is None:
        return initial_size

    total_size = initial_size
    for filename in dict.fromkeys(filenames):
        _validate_huggingface_repo_filename(repo_id, filename)
        file_path = downloaded_path / filename
        parent_path = file_path.parent.resolve()
        if not _is_within_directory(downloaded_path, parent_path):
            raise ValueError(f"Cannot verify max-size for {repo_id}: downloaded selected file path escaped: {filename}")
        if file_path.is_symlink():
            try:
                symlink_target = file_path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise ValueError(
                    f"Cannot verify max-size for {repo_id}: downloaded selected file missing: {filename}"
                ) from exc
            if not _is_within_directory(downloaded_path, symlink_target) and not _is_huggingface_cache_blob_target(
                downloaded_path, symlink_target
            ):
                raise ValueError(
                    f"Cannot verify max-size for {repo_id}: downloaded selected file symlink target escaped: {filename}"
                )
        if not file_path.is_file():
            raise ValueError(f"Cannot verify max-size for {repo_id}: downloaded selected file missing: {filename}")
        try:
            file_size = file_path.stat().st_size
        except OSError as exc:
            raise ValueError(
                f"Cannot verify max-size for {repo_id}: downloaded selected file unreadable: {filename}"
            ) from exc
        total_size += file_size
        if total_size > size_limit:
            raise ValueError(
                f"Cannot download {repo_id}: downloaded selected Hugging Face files total {total_size} bytes "
                f"exceeds max size {size_limit} bytes"
            )
    return total_size


def _get_downloaded_huggingface_file_size(repo_id: str, file_path: Path, filename: str) -> int:
    """Return a downloaded file's exact size or fail closed with remote filename context."""
    if not file_path.is_file():
        raise ValueError(f"Cannot verify max-size for {repo_id}: downloaded selected file missing: {filename}")
    try:
        return file_path.stat().st_size
    except OSError as exc:
        raise ValueError(
            f"Cannot verify max-size for {repo_id}: downloaded selected file unreadable: {filename}"
        ) from exc


def _should_cleanup_hf_streaming_context_file(
    cache_dir: Path | None,
    download_path: Path | None,
    file_path: Path,
) -> bool:
    """Return whether a context-only sidecar is in ModelAudit's disposable HF staging tree."""
    if cache_dir is None or download_path is None:
        return False
    try:
        resolved_cache_dir = cache_dir.resolve()
    except OSError:
        return False
    if not resolved_cache_dir.name.startswith("modelaudit_hf_"):
        return False
    return _is_within_directory(download_path, file_path)


def _huggingface_metadata_size(item: Any) -> int | None:
    """Extract a non-negative Hub-disclosed size from sibling/tree metadata."""
    if isinstance(item, dict):
        raw_size = item.get("size")
        raw_lfs = item.get("lfs")
    else:
        raw_size = getattr(item, "size", None)
        raw_lfs = getattr(item, "lfs", None)

    if isinstance(raw_size, int) and not isinstance(raw_size, bool) and raw_size >= 0:
        return raw_size

    raw_lfs_size = raw_lfs.get("size") if isinstance(raw_lfs, dict) else getattr(raw_lfs, "size", None)
    if isinstance(raw_lfs_size, int) and not isinstance(raw_lfs_size, bool) and raw_lfs_size >= 0:
        return raw_lfs_size

    return None


def _extract_huggingface_repo_file_sizes(repo_info: Any) -> dict[str, int]:
    """Return recursive file sizes disclosed by Hugging Face repo metadata."""
    siblings = getattr(repo_info, "siblings", None) or ()
    sizes: dict[str, int] = {}
    for sibling in siblings:
        if isinstance(sibling, dict):
            file_name = sibling.get("rfilename") or sibling.get("path")
        else:
            file_name = getattr(sibling, "rfilename", None) or getattr(sibling, "path", None)
        if not isinstance(file_name, str) or not file_name:
            continue
        file_size = _huggingface_metadata_size(sibling)
        if file_size is not None:
            sizes[file_name] = file_size
    return sizes


def _is_huggingface_gated_or_auth_error(error: BaseException) -> bool:
    """Return whether a Hub metadata error means selected bytes are inaccessible."""
    markers = (
        "gated",
        "unauthorized",
        "authorization",
        "forbidden",
        "restricted",
        "401",
        "403",
    )
    seen: set[int] = set()
    pending: list[BaseException] = [error]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        error_type = type(current).__name__.lower()
        error_text = str(current).lower()
        if any(marker in error_type or marker in error_text for marker in markers):
            return True
        response = getattr(current, "response", None)
        status_code = getattr(response, "status_code", None)
        if status_code in {401, 403}:
            return True
        cause = current.__cause__
        if cause is not None:
            pending.append(cause)
        context = current.__context__
        if context is not None:
            pending.append(context)
    return False


def _is_huggingface_gated_repo(repo_info: Any) -> bool:
    gated = getattr(repo_info, "gated", None)
    return bool(gated and gated not in {False, "false", "False", "none", "None"})


def _build_huggingface_model_info(
    repo_id: str,
    repo_info: Any,
    repo_files: list[str],
    repo_revision: str,
    *,
    deadline: float | None = None,
    streaming_selection: bool = False,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    allow_content_probes: bool = True,
    include_all_files: bool = False,
) -> dict[str, Any]:
    """Build selected recursive inventory metadata using the downloader's selection policy."""
    inaccessible_probe_files: list[str] = []
    allow_inaccessible_probe_errors = _is_huggingface_gated_repo(repo_info)
    if streaming_selection:
        selection = _select_streamable_hf_files(
            repo_id,
            repo_files,
            repo_revision,
            scannable_extensions,
            scannable_filenames,
            scannable_scanner_ids,
            allow_content_probes=allow_content_probes,
            include_all_files=include_all_files,
            deadline=deadline,
        )
        model_files = selection.filenames
        include_openvino_companions = scannable_scanner_ids is None or "openvino" in {
            str(scanner_id).lower() for scanner_id in scannable_scanner_ids
        }
        model_files = _include_huggingface_openvino_companions(
            repo_id,
            repo_files,
            repo_revision,
            model_files,
            allow_content_probes=allow_content_probes,
            include_openvino_companions=include_openvino_companions,
            deadline=deadline,
        )
    else:
        model_extensions = _get_model_extensions()
        model_files = _select_huggingface_model_files(
            repo_id,
            repo_files,
            repo_revision,
            model_extensions,
            allow_content_probes=allow_content_probes,
            allow_inaccessible_probe_errors=allow_inaccessible_probe_errors,
            inaccessible_probe_files=inaccessible_probe_files if allow_inaccessible_probe_errors else None,
            deadline=deadline,
        )
    inventory_files = list(dict.fromkeys([*model_files, *inaccessible_probe_files]))
    inaccessible_probe_file_set = set(inaccessible_probe_files)
    repo_metadata_sizes = _extract_huggingface_repo_file_sizes(repo_info)
    repo_is_gated = _is_huggingface_gated_repo(repo_info)

    path_size_error: str | None = None
    path_size_gated = False
    try:
        selected_sizes, size_revision = _get_huggingface_path_sizes(
            repo_id,
            inventory_files,
            resolved_revision=repo_revision,
            deadline=deadline,
        )
    except Exception as exc:
        selected_sizes = {}
        size_revision = repo_revision
        path_size_gated = _is_huggingface_gated_or_auth_error(exc) or repo_is_gated
        path_size_error = redact_huggingface_urls_in_text(str(exc))

    files: list[dict[str, Any]] = []
    accessible_bytes = 0
    inaccessible_gated_bytes = 0
    inaccessible_gated_count = 0
    unknown_size_count = 0
    unknown_size_files: list[str] = []
    inaccessible_gated_files: list[str] = []

    for filename in inventory_files:
        path_size = selected_sizes.get(filename)
        size = path_size if isinstance(path_size, int) and not isinstance(path_size, bool) else None
        inaccessible_gated = filename in inaccessible_probe_file_set
        gated_missing_path_size = repo_is_gated and (filename not in selected_sizes or path_size is None)
        if size is None and (path_size_gated or inaccessible_gated or gated_missing_path_size):
            metadata_size = repo_metadata_sizes.get(filename)
            if metadata_size is not None:
                size = metadata_size
            inaccessible_gated = True

        file_info: dict[str, Any] = {"name": filename, "size": size}
        if inaccessible_gated:
            inaccessible_gated_count += 1
            inaccessible_gated_bytes += size or 0
            inaccessible_gated_files.append(filename)
            file_info["access"] = "gated"
            if size is None:
                unknown_size_count += 1
                unknown_size_files.append(filename)
        elif size is None:
            unknown_size_count += 1
            unknown_size_files.append(filename)
            file_info["access"] = "unknown"
        else:
            accessible_bytes += size
            file_info["access"] = "available"
        files.append(file_info)

    total_size = accessible_bytes + inaccessible_gated_bytes
    inventory_status = "complete"
    if inaccessible_gated_count:
        inventory_status = "gated_inaccessible"
    elif unknown_size_count:
        inventory_status = "partial_unknown_size"

    return {
        "repo_id": repo_id,
        "revision": size_revision,
        "total_size": total_size,
        "accessible_size": accessible_bytes,
        "inaccessible_gated_bytes": inaccessible_gated_bytes,
        "inaccessible_gated_file_count": inaccessible_gated_count,
        "inaccessible_gated_files": inaccessible_gated_files[:20],
        "unknown_size_count": unknown_size_count,
        "unknown_size_files": unknown_size_files[:20],
        "file_count": len(inventory_files),
        "repo_file_count": len(repo_files),
        "files": files,
        "inventory_status": inventory_status,
        "inventory_error": path_size_error,
        "gated": repo_is_gated,
        "model_id": getattr(repo_info, "modelId", repo_id),
        "author": getattr(repo_info, "author", ""),
    }


def get_model_info(
    url: str,
    *,
    timeout_seconds: float | None = None,
    streaming_selection: bool = False,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    allow_content_probes: bool = True,
    include_all_files: bool = False,
) -> dict[str, Any]:
    """Get information about a HuggingFace model without downloading it.

    Args:
        url: HuggingFace model URL
        timeout_seconds: Optional end-to-end preview deadline in seconds
        streaming_selection: Match streaming acquisition selection instead of snapshot selection
        scannable_extensions: Optional remote prefilter extensions from scanner selection policy
        scannable_filenames: Optional exact remote prefilter basenames from scanner selection policy
        scannable_scanner_ids: Optional exact scanner IDs from scanner selection policy
        allow_content_probes: Allow bounded artifact range reads for renamed-format routing
        include_all_files: Include otherwise-unrecognized files under streaming selection bounds

    Returns:
        Dictionary with model information including size
    """
    try:
        from huggingface_hub import HfApi
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name, requested_revision = parse_huggingface_url_with_revision(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)
    deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None

    api = HfApi()
    try:
        repo_info_kwargs: dict[str, Any] = {"files_metadata": True}
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
            repo_info_kwargs["timeout"] = min(30.0, remaining)
        if requested_revision is not None:
            repo_info_kwargs["revision"] = requested_revision
        model_info = api.repo_info(repo_id, **repo_info_kwargs)
        repo_files = _extract_huggingface_repo_files(model_info)
        if repo_files is None:
            raise Exception("repository listing unavailable")
        repo_revision = getattr(model_info, "sha", None)
        if not _is_huggingface_commit_sha(repo_revision):
            raise Exception("repository listing did not include an immutable commit SHA")
        assert isinstance(repo_revision, str)

        return _build_huggingface_model_info(
            repo_id,
            model_info,
            repo_files,
            repo_revision,
            deadline=deadline,
            streaming_selection=streaming_selection,
            scannable_extensions=scannable_extensions,
            scannable_filenames=scannable_filenames,
            scannable_scanner_ids=scannable_scanner_ids,
            allow_content_probes=allow_content_probes,
            include_all_files=include_all_files,
        )
    except Exception as e:
        raise Exception(f"Failed to get model info for {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e


def get_model_size(
    repo_id: str,
    timeout_seconds: float | None = None,
    *,
    revision: str | None = None,
) -> int | None:
    """Get the total size of a HuggingFace model repository.

    Args:
        repo_id: Repository ID (e.g., "namespace/model-name")
        timeout_seconds: Optional request timeout
        revision: Optional branch, tag, or commit to size

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        from huggingface_hub import HfApi

        api = HfApi()
        model_info_kwargs: dict[str, Any] = {}
        if timeout_seconds is not None:
            model_info_kwargs["timeout"] = timeout_seconds
        if revision is not None:
            model_info_kwargs["revision"] = revision
        model_info = api.model_info(repo_id, **model_info_kwargs)

        # Calculate total size from all files
        total_size = 0
        if hasattr(model_info, "siblings") and model_info.siblings:
            for file_info in model_info.siblings:
                if hasattr(file_info, "size") and file_info.size:
                    total_size += file_info.size

        return total_size if total_size > 0 else None
    except Exception:
        # If we can't get the size, return None and proceed with download
        return None


def _get_model_size_with_deadline(
    repo_id: str,
    deadline: float | None,
    *,
    revision: str | None = None,
) -> int | None:
    """Return model size without allowing the optional lookup to outlive acquisition."""
    if deadline is None:
        return get_model_size(repo_id, revision=revision)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
    try:
        operation_kwargs: dict[str, Any] = {"repo_id": repo_id, "request_timeout": min(30.0, remaining)}
        if revision is not None:
            operation_kwargs["revision"] = revision
        worker_result = _run_huggingface_worker_with_deadline(
            "get_model_size",
            operation_kwargs,
            deadline,
            repo_id,
        )
    except TimeoutError:
        raise
    except Exception:
        return None
    value = worker_result.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def download_model(
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    max_size: int | None = None,
    *,
    timeout_seconds: float | None = None,
    repository_file_inventory: list[str] | None = None,
) -> Path:
    """Download a model from HuggingFace.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress
        max_size: Optional maximum total selected download size in bytes
        timeout_seconds: Optional end-to-end acquisition deadline in seconds
        repository_file_inventory: Optional list filled with repository member names from metadata

    Returns:
        Path to the downloaded model directory

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name, requested_revision = parse_huggingface_url_with_revision(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)
    deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None

    # Disk space check and path setup
    model_size = _get_model_size_with_deadline(repo_id, deadline, revision=requested_revision)
    download_path = None  # Will be set only if cache_dir is provided
    disk_check_path = None
    download_path_preexisting = False

    if cache_dir is not None:
        # Create a structured, containment-checked cache directory.
        download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
        download_path_preexisting = download_path.exists()
        download_path.mkdir(parents=True, exist_ok=True)
        disk_check_path = download_path

    else:
        disk_check_path = _get_hf_cache_root()
        disk_check_path.mkdir(parents=True, exist_ok=True)

    if model_size and disk_check_path is not None:
        has_space, message = check_disk_space(disk_check_path, model_size)
        if not has_space:
            raise Exception(f"Cannot download model from {display_url}: {redact_huggingface_urls_in_text(message)}")

    try:
        # Configure progress display based on environment
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Enable/disable progress bars based on parameter
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            # Force progress bar to show even in non-TTY environments
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        plan = plan_huggingface_model_download(url, max_size, deadline=deadline)
        deadline = plan.deadline
        size_limit = plan.size_limit
        model_files = plan.selected_files
        if repository_file_inventory is not None:
            repository_file_inventory[:] = plan.repo_files

        # Download strategy:
        # - When cache_dir is provided: Use local_dir to place files directly there (safer)
        # - When cache_dir is None: Use HF's default caching mechanism (avoid interfering)

        download_kwargs: dict[str, Any] = {
            "repo_id": repo_id,
            "tqdm_class": None,  # Use default tqdm
        }
        download_kwargs["revision"] = plan.download_revision

        if cache_dir is not None:
            # User provided cache directory - use local_dir for direct placement
            download_kwargs["local_dir"] = str(download_path)
        else:
            # No cache directory provided - let HF use its default cache
            # This is safer as it doesn't risk deleting user's global cache
            pass

        download_kwargs["allow_patterns"] = _build_literal_allow_patterns(model_files)

        local_path = _run_huggingface_download_with_deadline(
            "snapshot_download",
            download_kwargs,
            deadline,
            repo_id,
            direct_download=snapshot_download,
        )

        # Verify we actually got model files
        downloaded_path = Path(local_path)
        _verify_huggingface_selection_within_max_size(repo_id, downloaded_path, model_files, size_limit)
        downloaded_files = {
            path.relative_to(downloaded_path).as_posix() for path in downloaded_path.rglob("*") if path.is_file()
        }
        missing_model_files = set(model_files).difference(downloaded_files)
        if missing_model_files:
            raise ValueError(
                "Hugging Face selective filtering incomplete: "
                f"snapshot missing {len(missing_model_files)} selected file(s) for {repo_id}"
            )

        return Path(local_path)
    except Exception as e:
        # Clean up directory on failure only if we created a custom cache directory
        # When cache_dir is None, we use HF's default cache and shouldn't clean it up
        if (
            cache_dir is not None
            and download_path is not None
            and not download_path_preexisting
            and download_path.exists()
            and _is_within_directory(cache_dir / "huggingface", download_path)
        ):
            import shutil

            shutil.rmtree(download_path)
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def plan_huggingface_model_download(
    url: str,
    max_size: int | None = None,
    *,
    timeout_seconds: float | None = None,
    deadline: float | None = None,
    allow_content_probes: bool = True,
) -> HuggingFaceDownloadPlan:
    """Plan the bounded Hugging Face files a standard acquisition would download."""
    namespace, repo_name, requested_revision = parse_huggingface_url_with_revision(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    size_limit = _normalize_download_size_limit(max_size)
    if deadline is None and timeout_seconds is not None:
        deadline = time.monotonic() + timeout_seconds

    listing_timeout = 30.0
    if deadline is not None:
        listing_timeout = min(listing_timeout, max(deadline - time.monotonic(), 0.0))
        if listing_timeout <= 0:
            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
    repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(
        repo_id,
        listing_timeout,
        deadline=deadline,
        revision=requested_revision,
    )
    if repo_files is None:
        raise ValueError(
            "Hugging Face selective filtering incomplete: "
            f"failed listing files in repository {repo_id}: {repo_listing_error}"
        )
    if repo_revision is None:
        raise ValueError(
            "Hugging Face selective filtering incomplete: "
            f"{repo_listing_error or 'repository listing did not include an immutable commit SHA'}"
        )

    model_files = _select_huggingface_model_files(
        repo_id,
        repo_files,
        repo_revision,
        _get_model_extensions(),
        allow_content_probes=allow_content_probes,
        deadline=deadline,
    )
    model_files = _include_huggingface_openvino_companions(
        repo_id,
        repo_files,
        repo_revision,
        model_files,
        allow_content_probes=allow_content_probes,
        deadline=deadline,
    )
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
    if not model_files:
        _raise_no_scannable_hf_files(repo_id)
    revision, selected_sizes = _ensure_huggingface_selection_within_max_size(
        repo_id,
        model_files,
        size_limit,
        resolved_revision=repo_revision,
        deadline=deadline,
    )
    return HuggingFaceDownloadPlan(
        namespace=namespace,
        repo_name=repo_name,
        repo_id=repo_id,
        deadline=deadline,
        size_limit=size_limit,
        repo_files=repo_files,
        repo_revision=repo_revision,
        selected_files=model_files,
        selected_sizes=selected_sizes,
        download_revision=revision or repo_revision,
    )


def plan_huggingface_streaming_download(
    url: str,
    max_size: int | None = None,
    *,
    timeout_seconds: float | None = None,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    allow_content_probes: bool = True,
    include_all_files: bool = False,
    _stream_safetensors_headers: bool = False,
) -> HuggingFaceDownloadPlan:
    """Plan the bounded Hugging Face files a streaming acquisition would download."""
    namespace, repo_name, requested_revision = parse_huggingface_url_with_revision(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    size_limit = _normalize_download_size_limit(max_size)
    deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None

    listing_timeout = 30.0
    if deadline is not None:
        listing_timeout = min(listing_timeout, max(deadline - time.monotonic(), 0.0))
        if listing_timeout <= 0:
            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
    repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(
        repo_id,
        listing_timeout,
        deadline=deadline,
        revision=requested_revision,
    )
    if repo_files is None:
        if repo_listing_error and repo_listing_error.startswith("timed out after"):
            raise Exception(f"Timeout listing files in repository {repo_id}")
        raise Exception(f"Failed listing files in repository {repo_id}: {repo_listing_error}")
    if repo_revision is None:
        raise Exception(
            f"Failed listing files in repository {repo_id}: "
            f"{repo_listing_error or 'repository listing did not include an immutable commit SHA'}"
        )

    selection = _select_streamable_hf_files(
        repo_id,
        repo_files,
        repo_revision,
        scannable_extensions,
        scannable_filenames,
        scannable_scanner_ids,
        allow_content_probes=allow_content_probes,
        include_all_files=include_all_files,
        include_all_files_unbounded_extra_limit=(
            _MAX_HF_STREAMING_UNBOUNDED_INCLUDE_ALL_EXTRA_FILES if include_all_files and size_limit is None else None
        ),
        deadline=deadline,
    )
    model_files = selection.filenames
    openvino_companion_suppression_enabled = scannable_scanner_ids is None or "openvino" in {
        str(scanner_id).lower() for scanner_id in scannable_scanner_ids
    }
    model_files = _include_huggingface_openvino_companions(
        repo_id,
        repo_files,
        repo_revision,
        model_files,
        allow_content_probes=allow_content_probes,
        include_openvino_companions=openvino_companion_suppression_enabled,
        deadline=deadline,
    )
    size_preflight_files = model_files
    minimum_safetensors_read_bytes = 0
    safetensors_header_files: set[str] = set()
    if _stream_safetensors_headers:
        safetensors_selection_enabled = scannable_scanner_ids is None or "safetensors" in {
            str(scanner_id).lower() for scanner_id in scannable_scanner_ids
        }
        if safetensors_selection_enabled:
            safetensors_header_files = {
                filename
                for filename in model_files
                if selection.content_route_formats.get(filename) == "safetensors"
                or (
                    PurePosixPath(filename).suffix.lower() == ".safetensors"
                    and selection.content_route_formats.get(filename) is None
                )
            }
            minimum_safetensors_read_bytes = 8 * len(safetensors_header_files)
            size_preflight_files = [filename for filename in model_files if filename not in safetensors_header_files]
    revision, selected_sizes = _ensure_huggingface_selection_within_max_size(
        repo_id,
        size_preflight_files,
        size_limit,
        resolved_revision=repo_revision,
        deadline=deadline,
    )
    declared_safetensors_probe_files = [
        filename
        for filename in safetensors_header_files
        if PurePosixPath(filename).suffix.lower() == ".safetensors"
        and selection.content_route_formats.get(filename) is None
    ]
    if (
        size_limit is not None
        and declared_safetensors_probe_files
        and _active_safetensors_overlap_scanner_ids(scannable_scanner_ids)
    ):
        probe_sizes, probe_revision = _get_huggingface_path_sizes(
            repo_id,
            declared_safetensors_probe_files,
            resolved_revision=repo_revision,
            deadline=deadline,
        )
        if probe_revision != repo_revision:
            raise ValueError(
                f"Cannot stream {repo_id}: file metadata revision {probe_revision} "
                f"did not match listing revision {repo_revision}"
            )
        for filename in declared_safetensors_probe_files:
            file_size = probe_sizes.get(filename)
            if file_size is None:
                raise ValueError(f"Cannot stream {repo_id}: unknown size for selected file {filename}")
            selected_sizes[filename] = file_size
            minimum_safetensors_read_bytes += min(file_size, _HF_CONTENT_SNIFF_BYTES)
            if not allow_content_probes or file_size <= _HF_CONTENT_SNIFF_BYTES:
                minimum_safetensors_read_bytes += file_size
    minimum_selected_bytes = minimum_safetensors_read_bytes + sum(
        selected_sizes.get(filename, 0) for filename in size_preflight_files
    )
    if size_limit is not None and minimum_selected_bytes > size_limit:
        raise ValueError(
            f"Cannot stream {repo_id}: selected files plus minimum remote SafeTensors routing reads "
            f"require at least {minimum_selected_bytes} bytes, "
            f"exceeding max size {size_limit} bytes"
        )
    return HuggingFaceDownloadPlan(
        namespace=namespace,
        repo_name=repo_name,
        repo_id=repo_id,
        deadline=deadline,
        size_limit=size_limit,
        repo_files=repo_files,
        repo_revision=repo_revision,
        selected_files=model_files,
        selected_sizes=selected_sizes,
        download_revision=revision or repo_revision,
        content_route_formats=selection.content_route_formats,
    )


@overload
def download_model_streaming(
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    max_size: int | None = None,
    *,
    timeout_seconds: float | None = None,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    include_all_files: bool = False,
    repository_file_inventory: list[str] | None = None,
    scanner_config: dict[str, Any] | None = None,
    _include_scan_results: Literal[False] = False,
) -> Iterator[tuple[Path, bool]]:
    pass


@overload
def download_model_streaming(
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    max_size: int | None = None,
    *,
    timeout_seconds: float | None = None,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    include_all_files: bool = False,
    repository_file_inventory: list[str] | None = None,
    scanner_config: dict[str, Any] | None = None,
    _include_scan_results: Literal[True],
) -> Iterator[tuple[Path, bool] | tuple[Path, bool, Any]]:
    pass


def download_model_streaming(
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    max_size: int | None = None,
    *,
    timeout_seconds: float | None = None,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    include_all_files: bool = False,
    repository_file_inventory: list[str] | None = None,
    scanner_config: dict[str, Any] | None = None,
    _include_scan_results: bool = False,
) -> Iterator[tuple[Path, bool] | tuple[Path, bool, Any]]:
    """Download a model from HuggingFace one file at a time (streaming mode).

    This generator yields (file_path, is_last_file) tuples as each file is downloaded.
    Designed for streaming workflows to minimize disk usage.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress
        max_size: Optional maximum total selected download size in bytes
        timeout_seconds: Optional end-to-end acquisition deadline in seconds
        scannable_extensions: Optional remote prefilter extensions from scanner selection policy
        scannable_filenames: Optional exact remote prefilter basenames from scanner selection policy
        scannable_scanner_ids: Optional exact scanner IDs from scanner selection policy
        include_all_files: Include otherwise-unrecognized files under a bounded fail-closed limit
        repository_file_inventory: Optional list filled with repository member names from metadata
        scanner_config: Optional scanner configuration to preserve in remote native scans
        _include_scan_results: Internal opt-in for precomputed trusted source-native scan results

    Yields:
        Tuple of (Path, bool) for downloaded files. Internal scan callers that pass
        _include_scan_results may receive (Path, bool, ScanResult) for trusted
        source-native header scans.

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    display_url = redact_huggingface_url_for_display(url)

    try:
        # List all files in the repository
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Configure progress display
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        plan = plan_huggingface_streaming_download(
            url,
            max_size,
            timeout_seconds=timeout_seconds,
            scannable_extensions=scannable_extensions,
            scannable_filenames=scannable_filenames,
            scannable_scanner_ids=scannable_scanner_ids,
            include_all_files=include_all_files,
            _stream_safetensors_headers=_include_scan_results,
        )
        namespace = plan.namespace
        repo_name = plan.repo_name
        repo_id = plan.repo_id
        deadline = plan.deadline
        size_limit = plan.size_limit
        repo_files = plan.repo_files
        repo_revision = plan.repo_revision
        model_files = plan.selected_files
        selection = _HuggingFaceStreamingSelection(model_files, dict(plan.content_route_formats))
        if repository_file_inventory is not None:
            repository_file_inventory[:] = repo_files

        safetensors_header_streaming_allowed = _include_scan_results and (
            scannable_scanner_ids is None
            or "safetensors" in {str(scanner_id).lower() for scanner_id in scannable_scanner_ids}
        )
        safetensors_header_candidates = (
            {
                filename
                for filename in model_files
                if selection.content_route_formats.get(filename) == "safetensors"
                or (
                    PurePosixPath(filename).suffix.lower() == ".safetensors"
                    and selection.content_route_formats.get(filename) is None
                )
            }
            if safetensors_header_streaming_allowed
            else set()
        )
        safetensors_index_files = (
            {
                filename
                for filename in repo_files
                if _is_safetensors_index_file(filename)
                and any(
                    not _remote_index_parent_prefix(filename)
                    or selected_file.startswith(_remote_index_parent_prefix(filename))
                    for selected_file in safetensors_header_candidates
                )
            }
            if safetensors_header_candidates
            else set()
        )
        selected_sizes: dict[str, int] = dict(plan.selected_sizes)
        path_sizes: dict[str, int | None] = {}
        if _include_scan_results and (size_limit is not None or safetensors_header_candidates):
            size_lookup_files = sorted(set(model_files).union(safetensors_index_files))
            path_sizes, metadata_revision = _get_huggingface_path_sizes(
                repo_id,
                size_lookup_files,
                resolved_revision=repo_revision,
                deadline=deadline,
            )
            if metadata_revision != repo_revision:
                raise Exception(
                    f"Cannot stream {repo_id}: file metadata revision {metadata_revision} "
                    f"did not match listing revision {repo_revision}"
                )
            for filename in model_files:
                if size_limit is None and filename not in safetensors_header_candidates:
                    continue
                file_size = path_sizes.get(filename)
                if file_size is None:
                    raise Exception(f"Cannot stream {repo_id}: unknown size for selected file {filename}")
                selected_sizes[filename] = file_size
        download_revision = plan.download_revision if not _include_scan_results else repo_revision
        safetensors_header_files: set[str] = set()
        content_probe_budget = (
            _HuggingFaceProbeBudget(
                remaining_bytes=min(_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES, size_limit)
                if size_limit is not None
                else _HF_CONTENT_SNIFF_MAX_TOTAL_BYTES,
                deadline=deadline,
                file_sizes={filename: selected_sizes[filename] for filename in safetensors_header_candidates},
            )
            if _active_safetensors_overlap_scanner_ids(scannable_scanner_ids)
            else None
        )
        for filename in model_files:
            if filename not in safetensors_header_candidates:
                continue
            detected_format = selection.content_route_formats.get(filename)
            if detected_format == "safetensors" or content_probe_budget is None:
                safetensors_header_files.add(filename)
                continue
            detected_format = _detect_huggingface_content_route_format(
                repo_id,
                filename,
                repo_revision,
                content_probe_budget,
            )
            if detected_format == "safetensors":
                safetensors_header_files.add(filename)
            elif detected_format is not None:
                selection.content_route_formats[filename] = detected_format
        content_probe_bytes_transferred = content_probe_budget.transferred_bytes if content_probe_budget else 0
        (
            shard_details_by_file,
            remote_index_bytes_transferred,
            acquired_index_bytes,
        ) = _remote_safetensors_shard_details_by_file(
            repo_id,
            sorted(safetensors_header_files),
            repo_files,
            repo_revision,
            path_sizes,
            deadline=deadline,
            max_transferred_bytes=(size_limit - content_probe_bytes_transferred if size_limit is not None else None),
        )
        openvino_companion_suppression_enabled = scannable_scanner_ids is None or "openvino" in {
            str(scanner_id).lower() for scanner_id in scannable_scanner_ids
        }
        repo_file_set = set(repo_files)
        selected_file_set = set(model_files)
        onnx_external_data_enabled = scannable_scanner_ids is None or "onnx" in {
            str(scanner_id).lower() for scanner_id in scannable_scanner_ids
        }

        # Setup cache directory
        download_path = None
        if cache_dir is not None:
            download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
            download_path.mkdir(parents=True, exist_ok=True)

        openvino_companion_by_xml = (
            {
                filename: companion
                for filename in model_files
                if (companion := _openvino_bin_companion_name(filename, model_files)) in selected_file_set
            }
            if openvino_companion_suppression_enabled
            else {}
        )
        openvino_xml_by_companion = {companion: xml for xml, companion in openvino_companion_by_xml.items()}

        # Download each file one at a time. OpenVINO XML/BIN pairs are staged
        # together, then only the XML is yielded so the scanner owns the logical
        # model and the weights sidecar is not routed as standalone PyTorch.
        downloaded_total_size = content_probe_bytes_transferred + remote_index_bytes_transferred
        prefetched_selected_paths: dict[str, Path] = {}
        downloaded_selected_paths: dict[str, Path] = {}
        downloaded_context_paths: dict[str, Path] = {}
        context_cleanup_paths: set[Path] = set()
        acquired_index_temp_dirs: list[tempfile.TemporaryDirectory[str]] = []
        accounted_selected_filenames = acquired_index_bytes.keys() & selected_file_set
        consumed_filenames: set[str] = set()

        def emit_file(path: Path, cleanup_paths: list[Path], is_last: bool) -> Iterator[tuple[Path, bool]]:
            try:
                yield (path, is_last)
            finally:
                for external_path in cleanup_paths:
                    with suppress(OSError):
                        external_path.unlink()

        def has_future_yield(current_index: int) -> bool:
            for future_filename in model_files[current_index + 1 :]:
                if future_filename in consumed_filenames:
                    continue
                if future_filename in openvino_xml_by_companion:
                    continue
                return True
            return False

        def scan_remote_safetensors(filename: str) -> Any:
            nonlocal downloaded_total_size
            declared_size = selected_sizes[filename]
            scan_result = _scan_remote_huggingface_safetensors_header(
                repo_id,
                filename,
                download_revision,
                declared_size=declared_size,
                deadline=deadline,
                shard_details=shard_details_by_file.get(filename),
                max_transferred_bytes=(size_limit - downloaded_total_size if size_limit is not None else None),
                scanner_config=scanner_config,
                active_scanner_ids=scannable_scanner_ids,
            )
            transferred_bytes = scan_result.bytes_scanned
            if size_limit is not None and downloaded_total_size + transferred_bytes > size_limit:
                raise ValueError(
                    f"Cannot stream {repo_id}: remote SafeTensors header bytes plus prior downloads "
                    f"would total {downloaded_total_size + transferred_bytes} bytes, "
                    f"exceeding max size {size_limit} bytes"
                )
            downloaded_total_size += transferred_bytes
            return scan_result

        def download_stream_file(filename: str) -> Path:
            download_kwargs: dict[str, Any] = {
                "repo_id": repo_id,
                "filename": filename,
                "revision": download_revision,
            }
            if cache_dir is not None and download_path is not None:
                # Use specific cache dir for local placement
                download_kwargs["cache_dir"] = str(cache_dir / "huggingface")
                download_kwargs["local_dir"] = str(download_path)
                local_path = _run_huggingface_download_with_deadline(
                    "hf_hub_download",
                    download_kwargs,
                    deadline,
                    repo_id,
                    direct_download=hf_hub_download,
                )
            else:
                # Use HF default cache
                local_path = _run_huggingface_download_with_deadline(
                    "hf_hub_download",
                    download_kwargs,
                    deadline,
                    repo_id,
                    direct_download=hf_hub_download,
                )
            return Path(local_path)

        def materialize_acquired_index(filename: str) -> Path | None:
            payload = acquired_index_bytes.get(filename)
            if payload is None:
                return None
            validated_filename = _validate_huggingface_repo_filename(repo_id, filename)
            temp_dir = tempfile.TemporaryDirectory(prefix="modelaudit_hf_index_")
            try:
                temp_path = Path(temp_dir.name).joinpath(*PurePosixPath(validated_filename).parts)
                temp_path.parent.mkdir(parents=True, exist_ok=True)
                temp_path.write_bytes(payload)
            except Exception:
                temp_dir.cleanup()
                raise
            acquired_index_temp_dirs.append(temp_dir)
            return temp_path

        def download_selected_file(filename: str) -> Path:
            nonlocal downloaded_total_size
            downloaded_file = downloaded_selected_paths.get(filename)
            if downloaded_file is not None and downloaded_file.is_file():
                return downloaded_file

            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

            already_accounted = filename in accounted_selected_filenames
            if size_limit is not None and not already_accounted:
                advertised_size = selected_sizes[filename]
                projected_total = downloaded_total_size + advertised_size
                if projected_total > size_limit:
                    raise ValueError(
                        f"Cannot download {repo_id}: downloaded bytes plus selected file {filename} "
                        f"would total {projected_total} bytes, exceeding max size {size_limit} bytes"
                    )

            # Download single file
            downloaded_file = prefetched_selected_paths.pop(filename, None)
            if downloaded_file is None or not downloaded_file.is_file():
                downloaded_file = materialize_acquired_index(filename)
            if downloaded_file is None or not downloaded_file.is_file():
                downloaded_file = download_stream_file(filename)
            if size_limit is not None and not already_accounted:
                downloaded_file_size = _get_downloaded_huggingface_file_size(repo_id, downloaded_file, filename)
                downloaded_total_size += downloaded_file_size
                accounted_selected_filenames.add(filename)
                if downloaded_total_size > size_limit:
                    raise ValueError(
                        f"Cannot download {repo_id}: downloaded selected Hugging Face files total "
                        f"{downloaded_total_size} bytes exceeds max size {size_limit} bytes"
                    )
            downloaded_selected_paths[filename] = downloaded_file
            return downloaded_file

        def prepare_stream_yield(filename: str) -> tuple[Path, list[Path]]:
            nonlocal downloaded_total_size
            downloaded_file = download_selected_file(filename)

            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

            onnx_external_data_cleanup_paths: list[Path] = []
            content_route_format = selection.content_route_formats.get(filename)
            if (
                onnx_external_data_enabled
                and content_route_format is None
                and PurePosixPath(filename).suffix.lower() != ".onnx"
            ):
                try:
                    detected_format = detect_file_format_for_skip_filter(str(downloaded_file))
                except Exception:
                    logger.debug(
                        "Unable to sniff selected Hugging Face file %s for ONNX sidecars", filename, exc_info=True
                    )
                else:
                    if detected_format == "onnx":
                        content_route_format = detected_format
                        selection.content_route_formats[filename] = detected_format
            if onnx_external_data_enabled and _is_hf_streaming_onnx_candidate(
                filename,
                content_route_format=content_route_format,
            ):
                external_data_files = _discover_hf_onnx_external_data_files(
                    downloaded_file,
                    filename,
                    repo_file_set,
                )
                if external_data_files:
                    external_context_files = [
                        external_filename
                        for external_filename in external_data_files
                        if external_filename not in selected_file_set
                        and not (
                            (downloaded_context_path := downloaded_context_paths.get(external_filename)) is not None
                            and downloaded_context_path.is_file()
                        )
                    ]
                    external_data_sizes: dict[str, int] = {}
                    if size_limit is not None and external_context_files:
                        external_data_sizes = _get_hf_onnx_external_data_sizes(
                            repo_id,
                            external_context_files,
                            revision=download_revision,
                            deadline=deadline,
                        )
                    for external_filename in external_data_files:
                        if deadline is not None and time.monotonic() >= deadline:
                            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
                        if external_filename in selected_file_set:
                            downloaded_selected_path = downloaded_selected_paths.get(external_filename)
                            if downloaded_selected_path is not None and downloaded_selected_path.is_file():
                                continue
                            external_path = prefetched_selected_paths.get(external_filename)
                            if external_path is None or not external_path.is_file():
                                external_path = download_stream_file(external_filename)
                                if downloaded_selected_path is None:
                                    prefetched_selected_paths[external_filename] = external_path
                            if downloaded_selected_path is not None:
                                downloaded_selected_paths[external_filename] = external_path
                                if _should_cleanup_hf_streaming_context_file(cache_dir, download_path, external_path):
                                    onnx_external_data_cleanup_paths.append(external_path)
                                continue
                            if size_limit is not None and external_filename not in accounted_selected_filenames:
                                external_file_size = _get_downloaded_huggingface_file_size(
                                    repo_id,
                                    external_path,
                                    external_filename,
                                )
                                projected_total = downloaded_total_size + external_file_size
                                if projected_total > size_limit:
                                    raise ValueError(
                                        f"Cannot download {repo_id}: downloaded bytes plus selected ONNX "
                                        f"external_data file {external_filename} would total {projected_total} "
                                        f"bytes, exceeding max size {size_limit} bytes"
                                    )
                                downloaded_total_size = projected_total
                                accounted_selected_filenames.add(external_filename)
                            continue
                        external_path = downloaded_context_paths.get(external_filename)
                        if external_path is not None and external_path.is_file():
                            continue
                        if size_limit is not None:
                            advertised_size = external_data_sizes[external_filename]
                            projected_total = downloaded_total_size + advertised_size
                            if projected_total > size_limit:
                                raise ValueError(
                                    f"Cannot download {repo_id}: downloaded bytes plus ONNX external_data file "
                                    f"{external_filename} would total {projected_total} bytes, exceeding max size "
                                    f"{size_limit} bytes"
                                )
                        external_path = download_stream_file(external_filename)
                        if size_limit is not None:
                            external_file_size = _get_downloaded_huggingface_file_size(
                                repo_id,
                                external_path,
                                external_filename,
                            )
                            projected_total = downloaded_total_size + external_file_size
                            if projected_total > size_limit:
                                raise ValueError(
                                    f"Cannot download {repo_id}: downloaded bytes plus ONNX external_data file "
                                    f"{external_filename} would total {projected_total} bytes, exceeding max size "
                                    f"{size_limit} bytes"
                                )
                            downloaded_total_size = projected_total
                        downloaded_context_paths[external_filename] = external_path
                        if _should_cleanup_hf_streaming_context_file(cache_dir, download_path, external_path):
                            context_cleanup_paths.add(external_path)

            return downloaded_file, onnx_external_data_cleanup_paths

        try:
            for idx, filename in enumerate(model_files):
                if filename in consumed_filenames:
                    continue

                if filename in safetensors_header_files:
                    scan_result = scan_remote_safetensors(filename)
                    yield (Path(filename), not has_future_yield(idx), scan_result)
                    continue

                if filename in openvino_xml_by_companion:
                    # Wait for the XML so we can prove it is an OpenVINO model
                    # before suppressing standalone analysis of the same-stem .bin.
                    continue

                downloaded_file, cleanup_paths = prepare_stream_yield(filename)
                companion = openvino_companion_by_xml.get(filename)
                if companion is not None:
                    from modelaudit.scanners.openvino_scanner import OpenVinoScanner

                    if OpenVinoScanner.can_handle(str(downloaded_file)):
                        download_selected_file(companion)
                        consumed_filenames.add(companion)
                    else:
                        companion_path, companion_cleanup_paths = prepare_stream_yield(companion)
                        consumed_filenames.add(companion)
                        yield from emit_file(downloaded_file, cleanup_paths, False)
                        yield from emit_file(companion_path, companion_cleanup_paths, not has_future_yield(idx))
                        continue

                yield from emit_file(downloaded_file, cleanup_paths, not has_future_yield(idx))
        finally:
            for external_path in context_cleanup_paths:
                with suppress(OSError):
                    external_path.unlink()
            for temp_dir in acquired_index_temp_dirs:
                with suppress(OSError):
                    temp_dir.cleanup()

    except Exception as e:
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_file_from_hf(
    url: str,
    cache_dir: Path | None = None,
    max_size: int | None = None,
    *,
    repository_file_inventory: list[str] | None = None,
    timeout_seconds: float | None = None,
) -> Path:
    """Download a single file from HuggingFace using direct file URL.

    Args:
        url: Direct HuggingFace file URL (e.g., https://huggingface.co/user/repo/resolve/main/file.bin)
        cache_dir: Optional cache directory for downloads
        max_size: Optional maximum file size to download; 0 disables the limit
        repository_file_inventory: Optional list filled with repository member names from metadata
        timeout_seconds: Optional end-to-end acquisition deadline in seconds

    Returns:
        Path to the downloaded file

    Raises:
        ValueError: If URL is invalid
        ValueError: If max_size is set and file size is unknown or exceeds it
        Exception: If download fails
    """
    repo_id, branch, filename = parse_huggingface_file_url(url)
    display_url = redact_huggingface_url_for_display(url)

    try:
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    try:
        if max_size is not None and max_size < 0:
            raise ValueError("Maximum file size must be non-negative")

        size_limit = max_size or None
        download_revision = branch
        deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None
        repo_files: list[str] | None = None
        repo_revision: str | None = None
        repo_listing_error: str | None = None
        if repository_file_inventory is not None:
            listing_timeout = 30.0
            if deadline is not None:
                listing_timeout = min(listing_timeout, max(deadline - time.monotonic(), 0.0))
                if listing_timeout <= 0:
                    raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
            repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(
                repo_id,
                listing_timeout,
                revision=branch,
                deadline=deadline,
            )
            inventory_revision: str | None = None
            if _is_huggingface_commit_sha(repo_revision):
                assert isinstance(repo_revision, str)
                inventory_revision = repo_revision
            elif _is_huggingface_commit_sha(branch):
                inventory_revision = branch
            if repository_file_inventory is not None and repo_files is not None and inventory_revision is not None:
                repository_file_inventory[:] = repo_files
                download_revision = inventory_revision

        if size_limit is not None:
            if repository_file_inventory is not None and not _is_huggingface_commit_sha(repo_revision):
                error_suffix = f": {repo_listing_error}" if repo_listing_error else ""
                raise ValueError(
                    f"Unable to determine immutable revision for {display_url}; refusing capped download{error_suffix}"
                )
            pinned_revision = repo_revision if repository_file_inventory is not None else None

            try:
                path_sizes, resolved_revision = _get_huggingface_path_sizes(
                    repo_id,
                    [filename],
                    requested_revision=branch,
                    resolved_revision=pinned_revision,
                    deadline=deadline,
                )
            except Exception as exc:
                if "repository revision unavailable" in str(exc):
                    raise ValueError(
                        f"Unable to determine immutable revision for {display_url}; refusing capped download"
                    ) from exc
                raise
            if not _is_huggingface_commit_sha(resolved_revision):
                raise ValueError(f"Unable to determine immutable revision for {display_url}; refusing capped download")
            file_size = path_sizes.get(filename)
            if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
                raise ValueError(f"Unable to determine file size for {display_url}; refusing capped download")
            if file_size > size_limit:
                raise ValueError(
                    f"File size ({_format_size(file_size)}) exceeds maximum allowed size ({_format_size(size_limit)})"
                )
            download_revision = resolved_revision

        download_kwargs: dict[str, Any] = {
            "repo_id": repo_id,
            "filename": filename,
            "revision": download_revision,
            "cache_dir": str(cache_dir) if cache_dir else None,
        }
        local_path = _run_huggingface_download_with_deadline(
            "hf_hub_download",
            download_kwargs,
            deadline,
            repo_id,
            direct_download=hf_hub_download,
        )
        downloaded_path = Path(local_path)
        if size_limit is not None:
            try:
                downloaded_size = downloaded_path.stat().st_size
            except OSError as exc:
                raise ValueError(
                    f"Unable to verify downloaded file size for {display_url}; refusing capped download"
                ) from exc
            if downloaded_size > size_limit:
                raise ValueError(
                    f"Downloaded file size ({_format_size(downloaded_size)}) "
                    f"exceeds maximum allowed size ({_format_size(size_limit)})"
                )
        return downloaded_path
    except Exception as e:
        raise Exception(f"Failed to download file from {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e
