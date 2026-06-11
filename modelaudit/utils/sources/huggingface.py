"""Utilities for handling HuggingFace model downloads."""

import json
import logging
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Collection, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from glob import escape as escape_glob
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, cast
from urllib.parse import parse_qs, urljoin, urlparse

from ..helpers.disk_space import check_disk_space
from .huggingface_paths import (
    extract_model_id_from_path,
    is_huggingface_cache_path,
    is_huggingface_file_url,
    is_huggingface_url,
    parse_huggingface_file_url,
    parse_huggingface_url,
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
_MAX_HF_STREAMING_UNFILTERED_FILES = 128
_HF_SAFETENSORS_STRICT_RANGE_REDIRECTS = 5
_HF_SAFETENSORS_RANGE_ATTEMPTS = 3
_MAX_HF_SAFETENSORS_INDEX_BYTES = 32 * 1024 * 1024
_MAX_HF_SAFETENSORS_INDEX_TOTAL_BYTES = 64 * 1024 * 1024
_HF_DOWNLOAD_WORKER_RESULT_PREFIX = "MODELAUDIT_HF_DOWNLOAD_RESULT="
_POSIX_TERMINATE_SIGNAL = getattr(signal, "SIGTERM", 15)
_POSIX_KILL_SIGNAL = getattr(signal, "SIGKILL", 9)

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
    "redact_huggingface_url_for_display",
    "redact_huggingface_urls_in_text",
]


@dataclass
class _HuggingFaceProbeBudget:
    remaining_bytes: int
    deadline: float | None = None
    file_sizes: dict[str, int] = field(default_factory=dict)
    prefixes: dict[str, bytes] = field(default_factory=dict)

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


@dataclass(frozen=True)
class _HuggingFaceStrictRangeRead:
    data: bytes
    total_size: int
    validator: str
    final_url: str
    bytes_transferred: int


class _HuggingFaceRangeBudgetExceeded(ValueError):
    """Raised when a bounded range read would exceed the caller's byte budget."""


def _remote_safetensors_source_path(repo_id: str, revision: str, filename: str) -> str:
    return f"hf://{repo_id}@{revision}/{filename}"


def _requested_huggingface_revision(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    query = parse_qs(parsed.query, keep_blank_values=False)
    raw_values = query.get("revision") or query.get("rev")
    if not raw_values:
        return None
    if len(raw_values) != 1 or not _is_huggingface_commit_sha(raw_values[0]):
        raise ValueError("Hugging Face revision query must be a full immutable commit SHA")
    return raw_values[0]


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
        validator_parts.append(f"{key.lower()}={validator_value}")
    if not validator_parts:
        raise ValueError("Hugging Face range response omitted a stable object validator")
    return ";".join(validator_parts)


def _parse_strict_content_range(response: Any, expected_size: int | None, max_bytes: int) -> tuple[int, int]:
    content_range = response.headers.get("Content-Range", "")
    match = re.fullmatch(r"bytes 0-(\d+)/(\d+)", content_range.strip(), flags=re.IGNORECASE)
    if match is None:
        raise ValueError("Hugging Face range response omitted a valid Content-Range")
    end_offset, total_size = (int(value) for value in match.groups())
    if expected_size is not None and total_size != expected_size:
        raise ValueError("Hugging Face range response size changed during header scan")
    expected_bytes = min(total_size, max_bytes)
    if end_offset + 1 != expected_bytes:
        raise ValueError("Hugging Face range response returned an unexpected byte range")
    return expected_bytes, total_size


def _is_retryable_huggingface_range_error(error: BaseException) -> bool:
    """Return whether a remote range failure is likely transport-side, not evidence-side."""
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
) -> _HuggingFaceStrictRangeRead:
    """Read a trusted prefix range and reject ambiguous range or object identity semantics."""
    if max_bytes <= 0:
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
            "Range": f"bytes=0-{max_bytes - 1}",
            "Accept-Encoding": "identity",
        },
    )
    current_headers = dict(headers)
    original_host = urlparse(current_url).hostname

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
            next_host = urlparse(next_url).hostname
            if next_host != original_host:
                current_headers.pop("authorization", None)
                current_headers.pop("Authorization", None)
                current_headers.pop("cookie", None)
                current_headers.pop("Cookie", None)
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
        expected_bytes, total_size = _parse_strict_content_range(response, expected_size, max_bytes)
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
        chunk_size = min(1024 * 1024, max(1, expected_bytes))
        for chunk in response.iter_content(chunk_size=chunk_size):
            request_deadline.check_deadline(repo_id)
            if not chunk:
                continue
            total += len(chunk)
            if total > expected_bytes:
                raise ValueError("Hugging Face range response body exceeded declared range")
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != expected_bytes:
            raise ValueError("Hugging Face range response ended before declared range")
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


def _scan_remote_huggingface_safetensors_header(
    repo_id: str,
    filename: str,
    revision: str,
    *,
    declared_size: int,
    deadline: float | None,
    shard_details: dict[str, Any] | None = None,
    max_transferred_bytes: int | None = None,
) -> Any:
    """Inspect one remote SafeTensors header without downloading tensor payload bytes."""
    from ...scanners.safetensors_scanner import (
        _REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY,
        _REMOTE_HEADER_INTEGRITY_CONFIG_KEY,
        _REMOTE_HEADER_ONLY_CONFIG_KEY,
        MAX_HEADER_BYTES,
        SafeTensorsScanner,
    )

    source_path = _remote_safetensors_source_path(repo_id, revision, filename)
    total_bytes_transferred = 0
    for attempt in range(_HF_SAFETENSORS_RANGE_ATTEMPTS):
        attempt_bytes_transferred = 0
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
            if 0 < header_len <= MAX_HEADER_BYTES and header_len <= declared_size - 8:
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
                if header_range.validator != first_range.validator:
                    raise ValueError("Hugging Face SafeTensors object validator changed during header scan")
                if header_range.total_size != first_range.total_size:
                    raise ValueError("Hugging Face SafeTensors declared size changed during header scan")
                header_payload = header_range.data
                final_url = header_range.final_url
                validator = header_range.validator

            bytes_transferred = total_bytes_transferred + attempt_bytes_transferred
            suffix = ".safetensors" if not Path(filename).suffix else Path(filename).suffix
            with tempfile.NamedTemporaryFile(
                prefix="modelaudit_hf_safetensors_",
                suffix=suffix,
                delete=False,
            ) as temp_file:
                temp_path = temp_file.name
                temp_file.write(header_payload)
                temp_file.truncate(declared_size)

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
            }
            scanner = SafeTensorsScanner(
                config={
                    _REMOTE_HEADER_ONLY_CONFIG_KEY: True,
                    _REMOTE_HEADER_BYTES_SCANNED_CONFIG_KEY: bytes_transferred,
                    _REMOTE_HEADER_INTEGRITY_CONFIG_KEY: integrity_details,
                }
            )
            result = scanner.scan(temp_path)
            for record in [*result.checks, *result.issues]:
                if getattr(record, "location", None) == temp_path:
                    cast(Any, record).location = source_path
            result.metadata.update(integrity_details)
            result.metadata.update(
                {
                    "source_path": source_path,
                    "remote_source_path": source_path,
                    "file_size": declared_size,
                    "remote_header_only": True,
                    "analysis_scope": "safetensors_header_and_metadata",
                    "content_hash_unavailable_reason": "remote_safetensors_header_only",
                    "tensor_payload_bytes_downloaded": 0,
                }
            )
            if shard_details is not None:
                from ...scanners.base import IssueSeverity

                result.metadata["remote_shard_family"] = dict(shard_details)
                result.add_check(
                    name="Hugging Face SafeTensors Shard Coverage",
                    passed=bool(shard_details.get("complete")),
                    message=str(shard_details.get("message", "Remote SafeTensors shard coverage evaluated")),
                    severity=None if shard_details.get("complete") else IssueSeverity.INFO,
                    location=source_path,
                    details=shard_details,
                )
                if not shard_details.get("complete"):
                    from ...scanner_results import mark_inconclusive_scan_result

                    mark_inconclusive_scan_result(result, "remote_safetensors_shard_coverage_incomplete")
                    result.finish(success=False)
            result.bytes_scanned = bytes_transferred
            return result
        except Exception as exc:
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
            time.sleep(0.25 * (attempt + 1))
        finally:
            if temp_path is not None:
                with suppress(OSError):
                    Path(temp_path).unlink()

    raise AssertionError("unreachable SafeTensors range retry state")


def _remote_safetensors_filename_shard_details_by_file(
    model_files: list[str], repo_files: list[str]
) -> dict[str, dict[str, Any]]:
    """Return per-shard filename coverage details derived from the immutable repository listing."""
    from modelaudit.utils.file.handlers import ShardedModelDetector

    grouped: dict[tuple[str, str, int], dict[str, Any]] = {}
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
        entry = grouped.setdefault(key, {"expected_total_shards": expected_total, "by_index": {}, "filenames": []})
        entry["filenames"].append(filename)
        entry["by_index"].setdefault(shard_index, []).append(filename)

    details_by_file: dict[str, dict[str, Any]] = {}
    for (_parent, pattern, expected_total), entry in grouped.items():
        by_index = cast(dict[int, list[str]], entry["by_index"])
        missing_indices = [index for index in range(1, expected_total + 1) if index not in by_index]
        duplicate_indices = {index: names for index, names in by_index.items() if len(names) > 1}
        present_filenames = [name for names in by_index.values() for name in names]
        unselected = sorted(name for name in present_filenames if name not in selected)
        complete = (
            not missing_indices
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
            "message": message,
            "pattern": pattern,
            "expected_total_shards": expected_total,
            "present_total_shards": len(present_filenames),
            "missing_shard_count": len(missing_indices),
            "missing_shard_indices": missing_indices[:20],
            "missing_shard_indices_truncated": len(missing_indices) > 20,
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


def _normalize_safetensors_index_shard_path(index_filename: str, shard_name: object) -> tuple[str | None, str | None]:
    if not isinstance(shard_name, str) or not shard_name:
        return None, "non-string or empty shard reference"
    if "\\" in shard_name:
        return None, "backslash in shard reference"
    shard_path = PurePosixPath(shard_name)
    if shard_path.is_absolute() or any(part in {"", ".", ".."} for part in shard_path.parts):
        return None, "unsafe shard reference path"
    parent_prefix = _remote_index_parent_prefix(index_filename)
    return f"{parent_prefix}{shard_path.as_posix()}" if parent_prefix else shard_path.as_posix(), None


def _loads_json_without_duplicate_keys(raw: bytes) -> tuple[Any | None, list[str], str | None]:
    duplicate_keys: list[str] = []

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        seen: set[str] = set()
        for key, value in pairs:
            if key in seen:
                duplicate_keys.append(key)
            seen.add(key)
            obj[key] = value
        return obj

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, [], f"invalid UTF-8: {exc}"
    try:
        parsed = json.loads(text, object_pairs_hook=object_pairs_hook)
    except json.JSONDecodeError as exc:
        return None, [], f"invalid JSON: {exc}"
    return parsed, sorted(set(duplicate_keys)), None


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


def _remote_safetensors_index_details_by_file(
    repo_id: str,
    model_files: list[str],
    repo_files: list[str],
    revision: str,
    path_sizes: dict[str, int | None],
    *,
    deadline: float | None,
    max_transferred_bytes: int | None,
) -> tuple[dict[str, dict[str, Any]], int]:
    """Return per-shard details from bounded SafeTensors index manifests."""
    selected_files = set(model_files)
    repo_file_set = set(repo_files)
    selected_safetensors = {
        filename for filename in selected_files if PurePosixPath(filename).suffix.lower() == ".safetensors"
    }
    if not selected_safetensors:
        return {}, 0

    details_by_file: dict[str, dict[str, Any]] = {}
    total_index_bytes = 0
    for index_filename in sorted(filename for filename in repo_files if _is_safetensors_index_file(filename)):
        parent_prefix = _remote_index_parent_prefix(index_filename)
        selected_under_index = sorted(
            filename for filename in selected_safetensors if not parent_prefix or filename.startswith(parent_prefix)
        )
        if not selected_under_index:
            continue

        index_size = path_sizes.get(index_filename)
        if index_size is None:
            failure = _index_failure_details(index_filename, "missing_index_size")
            for filename in selected_under_index:
                details_by_file[filename] = dict(failure)
            continue
        if index_size > _MAX_HF_SAFETENSORS_INDEX_BYTES:
            failure = _index_failure_details(index_filename, "index_exceeds_limit", index_size=index_size)
            for filename in selected_under_index:
                details_by_file[filename] = dict(failure)
            continue
        if total_index_bytes + index_size > _MAX_HF_SAFETENSORS_INDEX_TOTAL_BYTES:
            failure = _index_failure_details(
                index_filename, "aggregate_index_bytes_exceed_limit", index_size=index_size
            )
            for filename in selected_under_index:
                details_by_file[filename] = dict(failure)
            continue
        if max_transferred_bytes is not None and total_index_bytes + index_size > max_transferred_bytes:
            failure = _index_failure_details(index_filename, "index_exceeds_max_size_budget", index_size=index_size)
            for filename in selected_under_index:
                details_by_file[filename] = dict(failure)
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
            parsed, duplicate_keys, parse_error = _loads_json_without_duplicate_keys(index_range.data)
            if parse_error is not None:
                raise ValueError(parse_error)
            if not isinstance(parsed, dict):
                raise ValueError("SafeTensors index root is not a JSON object")
            metadata = parsed.get("metadata")
            weight_map = parsed.get("weight_map")
            if metadata is not None and not isinstance(metadata, dict):
                raise ValueError("SafeTensors index metadata is not a JSON object")
            if not isinstance(weight_map, dict):
                raise ValueError("SafeTensors index weight_map is not a JSON object")
        except Exception as exc:
            failure = _index_failure_details(
                index_filename,
                "index_read_or_parse_failed",
                bytes_transferred=index_bytes_transferred,
                index_size=index_size,
                error=exc,
            )
            for filename in selected_under_index:
                details_by_file[filename] = dict(failure)
            continue

        referenced_by_file: dict[str, list[str]] = {}
        invalid_entries: list[str] = []
        for tensor_name, shard_name in weight_map.items():
            if not isinstance(tensor_name, str) or not tensor_name:
                invalid_entries.append("<invalid tensor key>")
                continue
            normalized_path, invalid_reason = _normalize_safetensors_index_shard_path(index_filename, shard_name)
            if normalized_path is None:
                invalid_entries.append(f"{tensor_name}: {invalid_reason}")
                continue
            referenced_by_file.setdefault(normalized_path, []).append(tensor_name)

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
            "index_weight_map_tensor_count": len(weight_map),
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
            "index_duplicate_json_key_count": len(duplicate_keys),
            "index_duplicate_json_keys": duplicate_keys[:20],
            "index_duplicate_json_keys_truncated": len(duplicate_keys) > 20,
            "index_metadata_total_size": metadata_total_size,
            "index_metadata_total_size_valid": not invalid_total_size,
            "message": (
                "SafeTensors index relationships are complete for this shard."
                if index_complete
                else "Remote SafeTensors index coverage is incomplete."
            ),
        }
        attach_filenames = (
            selected_under_index
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
            details_by_file[filename] = details

    return details_by_file, total_index_bytes


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
        index_complete = bool(index_detail.get("complete"))
        combined["filename_pattern_complete"] = filename_complete
        combined["index_complete"] = index_complete
        combined["complete"] = filename_complete and index_complete
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
) -> tuple[dict[str, dict[str, Any]], int]:
    """Return per-shard remote coverage details from filenames and index manifests."""
    filename_details = _remote_safetensors_filename_shard_details_by_file(model_files, repo_files)
    index_details, index_bytes = _remote_safetensors_index_details_by_file(
        repo_id,
        model_files,
        repo_files,
        revision,
        path_sizes,
        deadline=deadline,
        max_transferred_bytes=max_transferred_bytes,
    )
    return _combine_remote_safetensors_shard_details(filename_details, index_details), index_bytes


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

    budget.reserve(repo_id, max_bytes)
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
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            prefix = b"".join(chunks)[:max_bytes]
            file_size = _parse_huggingface_response_file_size(response, len(prefix), max_bytes)
            if file_size is not None:
                budget.record_file_size(repo_id, filename, file_size)
                if file_size <= len(prefix):
                    budget.refund(max_bytes - len(prefix))
            if len(prefix) > len(cached_prefix):
                budget.prefixes[filename] = prefix
        return prefix
    except Exception as exc:
        raise ValueError(
            "Hugging Face selective filtering incomplete: unable to inspect skipped file "
            f"{repo_id}/{filename} ({type(exc).__name__})"
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
    if Path(filename).suffix:
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


def _is_complete_huggingface_text_or_json(probe: bytes, *, sample_is_prefix: bool) -> bool:
    """Return whether a complete bounded probe is owned by benign text or JSON."""
    if sample_is_prefix:
        return False

    from modelaudit.utils.file.detection import _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES

    if not probe.translate(None, _CONTENT_ROUTE_PRINTABLE_TEXT_BYTES):
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


def _detect_huggingface_protobuf_model_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded TensorFlow, CoreML, ONNX, or unresolved protobuf model route."""
    from modelaudit.utils.file.detection import (
        _COREML_PROTO_SIGNATURE_READ_BYTES,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        _classify_bounded_tensorflow_protobuf_stream,
        _could_start_coreml_model_proto,
        _looks_like_coreml_model_proto_prefix,
        _looks_like_onnx_model_proto_stream,
    )

    if not _could_start_coreml_model_proto(prefix):
        return None

    max_probe_size = _COREML_PROTO_SIGNATURE_READ_BYTES
    raw_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size + 1)
    sample_is_prefix = len(raw_probe) > max_probe_size
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_or_json(probe, sample_is_prefix=sample_is_prefix):
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
    if sample_is_prefix or coreml_status is None or onnx_status is None:
        return PROTOBUF_MODEL_CANDIDATE_FORMAT
    return None


def _detect_huggingface_flax_msgpack_route(
    repo_id: str,
    filename: str,
    revision: str,
    budget: _HuggingFaceProbeBudget,
    prefix: bytes,
) -> str | None:
    """Return a bounded Flax MessagePack route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        FLAX_MSGPACK_STRUCTURE_READ_BYTES,
        _probe_flax_msgpack_checkpoint_stream,
    )

    if Path(filename).suffix.lower() in {".py", ".pyw"}:
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
    if initial_probe_state is False or len(prefix) < _HF_CONTENT_SNIFF_BYTES:
        return None

    max_probe_size = FLAX_MSGPACK_STRUCTURE_READ_BYTES
    raw_probe = _read_huggingface_probe(repo_id, filename, revision, budget, prefix, max_probe_size + 1)
    sample_is_prefix = len(raw_probe) > max_probe_size
    probe = raw_probe[:max_probe_size]
    if _is_complete_huggingface_text_or_json(probe, sample_is_prefix=sample_is_prefix):
        return None
    probe_state = _probe_flax_msgpack_checkpoint_stream(
        BytesIO(probe),
        len(probe),
        sample_is_prefix=sample_is_prefix,
        incomplete_prefix_is_inconclusive=True,
    )
    if probe_state is not False:
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
        _TFLITE_CONTENT_ROUTE_BLOCKED_EXTENSIONS,
        PROTO0_1_MAX_PROBE_BYTES,
        _allows_renamed_binary_content_route,
        _could_start_proto0_or_1_pickle,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _looks_like_proto0_or_1_pickle,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )

    llamafile_route = _detect_huggingface_llamafile_route(repo_id, filename, revision, budget, prefix)
    if llamafile_route is not None:
        return llamafile_route

    if _looks_like_safetensors_prefix(repo_id, filename, revision, budget, prefix):
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
    deadline: float | None = None,
) -> list[str]:
    """Select extension-matching files plus bounded content-routed renamed model files."""
    model_files = list(
        dict.fromkeys(filename for filename in repo_files if _is_scannable_hf_file(filename, model_extensions))
    )
    selected_files = set(model_files)
    inspected_files = 0
    probe_budget = _HuggingFaceProbeBudget(
        remaining_bytes=_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES,
        deadline=deadline,
    )

    for filename in repo_files:
        if filename in selected_files:
            continue
        if inspected_files >= _HF_CONTENT_SNIFF_MAX_FILES:
            raise ValueError(
                "Hugging Face selective filtering incomplete: skipped file inspection limit exceeded "
                f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_FILES} files)"
            )
        inspected_files += 1
        detected_format = _detect_huggingface_content_route_format(repo_id, filename, revision, probe_budget)
        if detected_format is None:
            continue
        model_files.append(filename)
        selected_files.add(filename)

    return model_files


def _build_literal_allow_patterns(filenames: list[str]) -> list[str]:
    """Escape repository filenames before passing them to the Hub glob filter."""
    return [escape_glob(filename) for filename in filenames]


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


def _is_scannable_hf_file(filename: str, extensions: Collection[str]) -> bool:
    """Return whether a listed Hugging Face file has a supported suffix."""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext.lower()) for ext in extensions if ext)


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


def _get_selected_hf_content_route_formats(
    scannable_extensions: Collection[str] | None,
    scannable_filenames: Collection[str] | None,
) -> set[str] | None:
    """Infer content formats when callers do not provide exact scanner policy."""
    if scannable_extensions is None and scannable_filenames is None:
        return None

    from ...scanner_registry_metadata import EXTENSION_FORMAT_MAP, get_scanner_registry_metadata

    content_route_formats = _get_hf_content_route_formats()
    selected_extensions = (
        set() if scannable_extensions is None else {str(extension).lower() for extension in scannable_extensions}
    )
    selected_filenames = (
        set() if scannable_filenames is None else {str(filename).lower() for filename in scannable_filenames}
    )
    selected_formats: set[str] = set()
    for scanner_id, scanner_info in get_scanner_registry_metadata().items():
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


def _select_streamable_hf_files(
    repo_id: str,
    repo_files: list[str],
    revision: str,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scannable_scanner_ids: Collection[str] | None = None,
    *,
    include_all_files: bool = False,
    deadline: float | None = None,
) -> list[str]:
    """Select bounded remotely scannable files without treating ``""`` as a wildcard."""
    selected_route_formats: set[str] | None = None
    selected_route_scanner_ids: set[str] | None = None
    if scannable_scanner_ids is not None:
        selected_route_scanner_ids = {str(scanner_id).lower() for scanner_id in scannable_scanner_ids}.intersection(
            _get_hf_content_route_scanner_ids()
        )
    elif scannable_filenames:
        from ...scanner_registry_metadata import EXTENSION_FORMAT_MAP

        authoritative_extensions = (
            set()
            if scannable_extensions is None
            else {
                str(extension).lower()
                for extension in scannable_extensions
                if str(extension).lower() in EXTENSION_FORMAT_MAP
            }
        )
        selected_route_formats = _get_selected_hf_content_route_formats(authoritative_extensions, None)
    else:
        selected_route_formats = _get_selected_hf_content_route_formats(scannable_extensions, scannable_filenames)
    safetensors_suffix_only = (
        selected_route_scanner_ids == {"safetensors"}
        and scannable_extensions is not None
        and {str(extension).lower() for extension in scannable_extensions} == {".safetensors"}
        and not scannable_filenames
    )
    sniff_renamed_files = not include_all_files and (
        bool(selected_route_scanner_ids)
        if selected_route_scanner_ids is not None
        else selected_route_formats is None or bool(selected_route_formats)
    )
    if safetensors_suffix_only:
        sniff_renamed_files = False
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
    extensionless_count = 0
    unfiltered_count = 0
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

        if include_all_files:
            unfiltered_count += 1
            if unfiltered_count > _MAX_HF_STREAMING_UNFILTERED_FILES:
                raise Exception(
                    f"Refusing to stream-download unfiltered files from {repo_id}: "
                    f"repository listing exceeds the bounded unfiltered candidate limit "
                    f"({_MAX_HF_STREAMING_UNFILTERED_FILES}); streaming coverage is incomplete"
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

    if sniff_renamed_files:
        inspected_files = 0
        probe_budget = _HuggingFaceProbeBudget(
            remaining_bytes=_HF_CONTENT_SNIFF_MAX_TOTAL_BYTES,
            deadline=deadline,
        )
        selected_files = set(model_files)
        for file_name in repo_files:
            if file_name in selected_files:
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
                    continue
            elif selected_route_formats is not None and detected_format not in selected_route_formats:
                continue
            model_files.append(file_name)
            selected_files.add(file_name)

    if not model_files:
        _raise_no_scannable_hf_files(repo_id)

    return model_files


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
) -> tuple[list[str] | None, str | None, str | None]:
    """Return repository files, their immutable revision, or a failure reason."""
    if deadline is not None:
        try:
            operation_kwargs: dict[str, Any] = {
                "repo_id": repo_id,
                "request_timeout": timeout_seconds,
            }
            if requested_revision is not None:
                operation_kwargs["requested_revision"] = requested_revision
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
        worker_files = cast(list[str], raw_files)
        revision = value.get("revision")
        if not _is_huggingface_commit_sha(revision):
            return worker_files, None, "repository listing did not include an immutable commit SHA"
        assert isinstance(revision, str)
        return worker_files, revision, None

    from huggingface_hub import HfApi

    try:
        repo_info_kwargs: dict[str, Any] = {"timeout": timeout_seconds, "files_metadata": False}
        if requested_revision is not None:
            repo_info_kwargs["revision"] = requested_revision
        repo_info = HfApi().repo_info(repo_id, **repo_info_kwargs)
    except Exception as exc:
        return None, None, str(exc)

    files = _extract_huggingface_repo_files(repo_info)
    if files is None:
        return None, None, "repository listing unavailable"

    revision = getattr(repo_info, "sha", None)
    if not _is_huggingface_commit_sha(revision):
        return files, None, "repository listing did not include an immutable commit SHA"

    return files, revision, None


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


def _list_huggingface_repo_files_at_revision(repo_id: str, timeout_seconds: float = 30) -> tuple[list[str], str]:
    """Return repository filenames and the revision that produced the listing."""
    from huggingface_hub import HfApi

    repo_info = HfApi().repo_info(repo_id, timeout=timeout_seconds, files_metadata=False)
    raw_revision = getattr(repo_info, "sha", None)
    if not _is_huggingface_commit_sha(raw_revision):
        raise Exception(f"Cannot enforce max-size for {repo_id}: repository revision unavailable")
    assert isinstance(raw_revision, str)

    files = _extract_huggingface_repo_files(repo_info)
    if files is None:
        raise Exception(f"Cannot enforce max-size for {repo_id}: repository listing unavailable")
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
            worker_sizes[item["path"]] = (
                raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) and raw_size >= 0 else None
            )
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
    path_info = api.get_paths_info(repo_id, filenames, revision=resolved_revision)
    sizes: dict[str, int | None] = {}
    for item in path_info:
        path = getattr(item, "path", None)
        if not isinstance(path, str):
            continue
        raw_size = getattr(item, "size", None)
        sizes[path] = (
            raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) and raw_size >= 0 else None
        )
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
        file_path = downloaded_path / filename
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


def get_model_info(url: str) -> dict:
    """Get information about a HuggingFace model without downloading it.

    Args:
        url: HuggingFace model URL

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

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)
    requested_revision = _requested_huggingface_revision(url)

    api = HfApi()
    try:
        # Get model info for metadata
        model_info_kwargs: dict[str, Any] = {}
        if requested_revision is not None:
            model_info_kwargs["revision"] = requested_revision
        model_info = api.model_info(repo_id, **model_info_kwargs)

        # Use list_repo_tree to get accurate file sizes
        # (model_info.siblings often returns None for size)
        total_size = 0
        files = []
        try:
            repo_files = api.list_repo_tree(repo_id, recursive=False)
            for item in repo_files:
                # Skip metadata files
                if hasattr(item, "path") and item.path not in [".gitattributes", "README.md"]:
                    file_size = getattr(item, "size", 0) or 0
                    total_size += file_size
                    files.append({"name": item.path, "size": file_size})
        except Exception as e:
            # If list_repo_tree fails, return 0 (will show as "Unknown size" in CLI)
            logger.debug(f"list_repo_tree failed for {repo_id}, falling back to unknown size: {e}")
            total_size = 0
            # Still try to get file count from siblings
            siblings = model_info.siblings or []
            for sibling in siblings:
                if sibling.rfilename not in [".gitattributes", "README.md"]:
                    files.append({"name": sibling.rfilename, "size": 0})

        return {
            "repo_id": repo_id,
            "total_size": total_size,
            "file_count": len(files),
            "files": files,
            "model_id": getattr(model_info, "modelId", repo_id),
            "author": getattr(model_info, "author", ""),
        }
    except Exception as e:
        raise Exception(f"Failed to get model info for {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e


def get_model_size(repo_id: str, timeout_seconds: float | None = None, *, revision: str | None = None) -> int | None:
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
    requested_revision: str | None = None,
) -> int | None:
    """Return model size without allowing the optional lookup to outlive acquisition."""
    if deadline is None:
        return get_model_size(repo_id, revision=requested_revision)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
    try:
        worker_result = _run_huggingface_worker_with_deadline(
            "get_model_size",
            {
                "repo_id": repo_id,
                "request_timeout": min(30.0, remaining),
                "requested_revision": requested_revision,
            },
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
) -> Path:
    """Download a model from HuggingFace.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress
        max_size: Optional maximum total selected download size in bytes
        timeout_seconds: Optional end-to-end acquisition deadline in seconds

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

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)
    requested_revision = _requested_huggingface_revision(url)
    deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None

    # Disk space check and path setup
    model_size = _get_model_size_with_deadline(
        repo_id,
        deadline,
        requested_revision=requested_revision,
    )
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

        size_limit = _normalize_download_size_limit(max_size)

        # Enable/disable progress bars based on parameter
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            # Force progress bar to show even in non-TTY environments
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # List files in the repository to identify model files
        listing_timeout = 30.0
        if deadline is not None:
            listing_timeout = min(listing_timeout, max(deadline - time.monotonic(), 0.0))
            if listing_timeout <= 0:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
        listing_kwargs: dict[str, Any] = {"deadline": deadline}
        if requested_revision is not None:
            listing_kwargs["requested_revision"] = requested_revision
        repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(
            repo_id,
            listing_timeout,
            **listing_kwargs,
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
        if requested_revision is not None and repo_revision != requested_revision:
            raise ValueError(
                "Hugging Face selective filtering incomplete: "
                f"resolved revision {repo_revision} did not match requested immutable revision {requested_revision}"
            )

        # Find model files in the repository (using centralized model extensions)
        model_extensions = _get_model_extensions()
        model_files = _select_huggingface_model_files(
            repo_id,
            repo_files,
            repo_revision,
            model_extensions,
            deadline=deadline,
        )
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

        # Download strategy:
        # - When cache_dir is provided: Use local_dir to place files directly there (safer)
        # - When cache_dir is None: Use HF's default caching mechanism (avoid interfering)

        download_kwargs: dict[str, Any] = {
            "repo_id": repo_id,
            "tqdm_class": None,  # Use default tqdm
        }
        download_kwargs["revision"] = repo_revision

        if cache_dir is not None:
            # User provided cache directory - use local_dir for direct placement
            download_kwargs["local_dir"] = str(download_path)
        else:
            # No cache directory provided - let HF use its default cache
            # This is safer as it doesn't risk deleting user's global cache
            pass

        # If we found specific model files, download them
        if model_files:
            _revision, _ = _ensure_huggingface_selection_within_max_size(
                repo_id,
                model_files,
                size_limit,
                resolved_revision=repo_revision,
                deadline=deadline,
            )
            download_kwargs["allow_patterns"] = _build_literal_allow_patterns(model_files)
        else:
            _raise_no_scannable_hf_files(repo_id)

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

    Yields:
        Tuple of (Path, bool) for downloaded files, or (Path, bool, ScanResult)
        for trusted source-native header scans.

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

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)
    requested_revision = _requested_huggingface_revision(url)

    try:
        # List all files in the repository
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        size_limit = _normalize_download_size_limit(max_size)
        deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None

        # Configure progress display
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # List files with timeout without leaking a blocking worker thread.
        listing_timeout = 30.0
        if deadline is not None:
            listing_timeout = min(listing_timeout, max(deadline - time.monotonic(), 0.0))
            if listing_timeout <= 0:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")
        repo_files, repo_revision, repo_listing_error = _list_repo_files_with_timeout(
            repo_id,
            listing_timeout,
            requested_revision=requested_revision,
            deadline=deadline,
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
        if requested_revision is not None and repo_revision != requested_revision:
            raise Exception(
                f"Failed listing files in repository {repo_id}: resolved revision {repo_revision} "
                f"did not match requested immutable revision {requested_revision}"
            )

        model_files = _select_streamable_hf_files(
            repo_id,
            repo_files,
            repo_revision,
            scannable_extensions,
            scannable_filenames,
            scannable_scanner_ids,
            include_all_files=include_all_files,
            deadline=deadline,
        )
        safetensors_header_streaming_allowed = scannable_scanner_ids is None or "safetensors" in {
            str(scanner_id).lower() for scanner_id in scannable_scanner_ids
        }
        safetensors_header_files = (
            {filename for filename in model_files if PurePosixPath(filename).suffix.lower() == ".safetensors"}
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
                    for selected_file in safetensors_header_files
                )
            }
            if safetensors_header_files
            else set()
        )
        selected_sizes: dict[str, int] = {}
        path_sizes: dict[str, int | None] = {}
        if size_limit is not None or safetensors_header_files:
            size_lookup_files = sorted(set(model_files).union(safetensors_index_files))
            path_sizes, metadata_revision = _get_huggingface_path_sizes(
                repo_id,
                size_lookup_files,
                requested_revision=requested_revision,
                resolved_revision=repo_revision,
                deadline=deadline,
            )
            if metadata_revision != repo_revision:
                raise Exception(
                    f"Cannot stream {repo_id}: file metadata revision {metadata_revision} "
                    f"did not match listing revision {repo_revision}"
                )
            for filename in model_files:
                if size_limit is None and filename not in safetensors_header_files:
                    continue
                file_size = path_sizes.get(filename)
                if file_size is None:
                    raise Exception(f"Cannot stream {repo_id}: unknown size for selected file {filename}")
                selected_sizes[filename] = file_size
        download_revision = repo_revision
        shard_details_by_file, remote_index_bytes_transferred = _remote_safetensors_shard_details_by_file(
            repo_id,
            model_files,
            repo_files,
            repo_revision,
            path_sizes,
            deadline=deadline,
            max_transferred_bytes=size_limit,
        )

        # Setup cache directory
        download_path = None
        if cache_dir is not None:
            download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
            download_path.mkdir(parents=True, exist_ok=True)

        # Download each file one at a time
        total_files = len(model_files)
        downloaded_total_size = remote_index_bytes_transferred
        for idx, filename in enumerate(model_files):
            is_last = idx == total_files - 1

            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

            if filename in safetensors_header_files:
                declared_size = selected_sizes[filename]
                if size_limit is not None and downloaded_total_size + 8 > size_limit:
                    raise ValueError(
                        f"Cannot stream {repo_id}: remote SafeTensors header preflight for {filename} "
                        f"would exceed max size {size_limit} bytes"
                    )
                scan_result = _scan_remote_huggingface_safetensors_header(
                    repo_id,
                    filename,
                    download_revision,
                    declared_size=declared_size,
                    deadline=deadline,
                    shard_details=shard_details_by_file.get(filename),
                    max_transferred_bytes=(size_limit - downloaded_total_size if size_limit is not None else None),
                )
                transferred = scan_result.metadata.get("remote_bytes_transferred", scan_result.bytes_scanned)
                transferred_bytes = (
                    transferred
                    if isinstance(transferred, int) and not isinstance(transferred, bool) and transferred >= 0
                    else scan_result.bytes_scanned
                )
                if size_limit is not None and downloaded_total_size + transferred_bytes > size_limit:
                    raise ValueError(
                        f"Cannot stream {repo_id}: remote SafeTensors header bytes plus prior downloads "
                        f"would total {downloaded_total_size + transferred_bytes} bytes, "
                        f"exceeding max size {size_limit} bytes"
                    )
                downloaded_total_size += transferred_bytes
                yield (Path(filename), is_last, scan_result)
                continue

            if size_limit is not None:
                advertised_size = selected_sizes[filename]
                projected_total = downloaded_total_size + advertised_size
                if projected_total > size_limit:
                    raise ValueError(
                        f"Cannot download {repo_id}: downloaded bytes plus selected file {filename} "
                        f"would total {projected_total} bytes, exceeding max size {size_limit} bytes"
                    )

            # Download single file
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

            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Hugging Face acquisition timed out for {repo_id}")

            downloaded_file = Path(local_path)
            downloaded_total_size = _verify_huggingface_selection_within_max_size(
                repo_id,
                downloaded_file.parent,
                [downloaded_file.name],
                size_limit,
                initial_size=downloaded_total_size,
            )
            yield (downloaded_file, is_last)

    except Exception as e:
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_file_from_hf(url: str, cache_dir: Path | None = None, max_size: int | None = None) -> Path:
    """Download a single file from HuggingFace using direct file URL.

    Args:
        url: Direct HuggingFace file URL (e.g., https://huggingface.co/user/repo/resolve/main/file.bin)
        cache_dir: Optional cache directory for downloads
        max_size: Optional maximum file size to download; 0 disables the limit

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
        from huggingface_hub import HfApi, hf_hub_download
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
        if size_limit is not None:
            api = HfApi()
            repo_info = api.repo_info(repo_id, revision=branch)
            pinned_revision = getattr(repo_info, "sha", None)
            if not _is_huggingface_commit_sha(pinned_revision):
                raise ValueError(f"Unable to determine immutable revision for {display_url}; refusing capped download")
            assert isinstance(pinned_revision, str)

            path_info = api.get_paths_info(repo_id, filename, revision=pinned_revision)
            file_metadata = path_info[0] if path_info else None
            file_size = getattr(file_metadata, "size", None)
            if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
                raise ValueError(f"Unable to determine file size for {display_url}; refusing capped download")
            if file_size > size_limit:
                raise ValueError(
                    f"File size ({_format_size(file_size)}) exceeds maximum allowed size ({_format_size(size_limit)})"
                )
            download_revision = pinned_revision

        # Use hf_hub_download for single file downloads
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            revision=download_revision,
            cache_dir=str(cache_dir) if cache_dir else None,
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
