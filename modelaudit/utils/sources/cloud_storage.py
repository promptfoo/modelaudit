import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import struct
import tempfile
import zipfile
from collections.abc import Callable, Collection, Coroutine, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse, urlsplit, urlunsplit

import click
from yaspin import yaspin

from modelaudit.config.constants import SCANNABLE_MODEL_EXTENSIONS
from modelaudit.utils.helpers.retry import retry_with_backoff

from ..helpers.disk_space import check_disk_space

logger = logging.getLogger(__name__)
_T = TypeVar("_T")

_SENSITIVE_QUERY_PARAM_RE = re.compile(
    (
        r"([?&][^=\s&]*(?:signature|credential|security-token|access-key|access_key|token|"
        r"secret|api-key|api_key|apikey|sig|sas)[^=\s&]*=)[^\s&#]+"
    ),
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)
_CLOUD_CONTENT_SNIFF_BYTES = 8 * 1024
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_BYTES = b"TFL3"
_MSGPACK_CONTAINER_MARKERS = frozenset((*range(0x80, 0x90), 0xDE, 0xDF))
_MAX_CLOUD_METADATA_ERROR_SAMPLES = 3
_MAX_CLOUD_METADATA_ERROR_DISPLAY_CHARS = 512


def _run_coroutine_sync(coro_factory: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
    """Run a coroutine from sync code without deadlocking an active event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())

    # A loop is already running in this thread. Running the coroutine in a worker
    # thread avoids blocking that loop while still giving synchronous call semantics.
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(lambda: asyncio.run(coro_factory())).result()


def is_cloud_url(url: str) -> bool:
    """Return True if the URL points to a supported cloud storage provider."""
    patterns = [
        r"^s3://.+",
        r"^gs://.+",
        r"^gcs://.+",
        r"^r2://.+",
        r"^https?://[^/]+\.s3\.amazonaws\.com/.+",
        r"^https?://storage.googleapis.com/.+",
        r"^https?://[^/]+\.r2\.cloudflarestorage\.com/.+",
    ]
    return any(re.match(p, url) for p in patterns)


def redact_url_for_display(url: str) -> str:
    """Remove credentials, query strings, and fragments from a URL for display."""
    try:
        parts = urlsplit(url)
    except Exception:
        return "<cloud URL redacted>"

    if not parts.scheme:
        return url

    netloc = parts.hostname or ""
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"

    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def redact_cloud_error_for_display(message: object, source_url: str | None = None) -> str:
    """Remove signed URL credentials from provider exception text."""
    redacted = str(message)
    if source_url:
        redacted = redacted.replace(source_url, redact_url_for_display(source_url))
    redacted = _URL_USERINFO_RE.sub(r"\1<credentials-redacted>@", redacted)
    return _SENSITIVE_QUERY_PARAM_RE.sub(r"\1<redacted>", redacted)


def _redact_cloud_path_for_display(path: object) -> str:
    """Redact credentials from cloud paths even when providers strip the protocol."""
    path_text = str(path)
    return redact_cloud_error_for_display(path_text, path_text)


def _bound_cloud_metadata_error_display(message: str) -> str:
    """Limit model-controlled cloud metadata diagnostics retained in memory."""
    if len(message) <= _MAX_CLOUD_METADATA_ERROR_DISPLAY_CHARS:
        return message
    return f"{message[: _MAX_CLOUD_METADATA_ERROR_DISPLAY_CHARS - 3]}..."


def _cloud_metadata_error_sample(path: object, error: object) -> dict[str, str]:
    """Return a bounded, credential-safe metadata failure sample."""
    path_text = str(path)
    return {
        "path": _bound_cloud_metadata_error_display(_redact_cloud_path_for_display(path_text)),
        "error": _bound_cloud_metadata_error_display(redact_cloud_error_for_display(error, path_text)),
    }


def _cloud_error_sanitizer(source_url: str) -> Callable[[Exception], str]:
    def sanitize(exc: Exception) -> str:
        return redact_cloud_error_for_display(exc, source_url)

    return sanitize


def _cloud_url_basename(url: str) -> str:
    """Return a local filename derived from a cloud URL without query secrets."""
    try:
        path = urlsplit(url).path
    except Exception:
        path = url
    return Path(path).name


def _metadata_etag(metadata: Mapping[str, Any] | None) -> str | None:
    """Extract a stable object validator from fsspec-style metadata."""
    if not metadata:
        return None
    for key in ("etag", "ETag", "Etag", "e_tag", "version_id", "VersionId", "generation"):
        value = metadata.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _cloud_url_without_query(url: str) -> str:
    """Return a cloud URL without signed query or fragment material for path comparison."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def get_fs_protocol(url: str) -> str:
    """Get the fsspec protocol for a given URL."""
    parsed = urlparse(url)
    scheme = parsed.scheme

    if scheme in {"http", "https"}:
        if parsed.netloc.endswith(".s3.amazonaws.com"):
            return "s3"
        elif parsed.netloc == "storage.googleapis.com":
            return "gcs"
        elif parsed.netloc.endswith(".r2.cloudflarestorage.com"):
            return "s3"
        else:
            raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}")
    elif scheme == "gcs" or scheme == "gs":
        return "gcs"
    elif scheme in {"s3", "r2"}:
        return "s3"
    else:
        raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}")


def estimate_download_time(size_bytes: int, bandwidth_mbps: float = 10.0) -> str:
    """Estimate download time based on file size and bandwidth."""
    if size_bytes == 0:
        return "instant"

    # Convert to seconds
    bandwidth_bps = bandwidth_mbps * 1_000_000 / 8  # Convert Mbps to bytes/second
    seconds = size_bytes / bandwidth_bps

    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _is_within_directory(base_dir: Path, target: Path) -> bool:
    """Return True if target resolves within base_dir."""
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


def _resolve_cloud_path(entry_name: str, base_dir: Path) -> tuple[Path, bool]:
    """Resolve a cloud object relative path and return whether it is safe."""
    entry = entry_name.replace("\\", "/")
    if entry.startswith("/") or (len(entry) > 1 and entry[1] == ":"):
        return (base_dir / entry.lstrip("/")).resolve(), False

    resolved = (base_dir / entry.lstrip("/")).resolve()
    return resolved, _is_within_directory(base_dir, resolved)


def _parse_size_value(size_value: Any) -> int:
    """Parse a cloud-reported size value to a non-negative integer."""
    parsed_size = int(size_value)
    if parsed_size < 0:
        raise ValueError(f"size must be non-negative, got {parsed_size}")
    return parsed_size


def get_cloud_object_size(fs: Any, url: str, strict: bool = False) -> int | None:
    """Get the size of a cloud storage object or directory.

    Args:
        fs: fsspec filesystem instance
        url: Cloud storage URL

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        info = fs.info(url)
    except Exception as exc:
        if strict:
            redacted_error = redact_cloud_error_for_display(exc, url)
            raise ValueError(
                f"Unable to read cloud object info for {redact_url_for_display(url)}: {redacted_error}"
            ) from exc
        return None

    top_level_size_error: Exception | None = None
    if info.get("type") != "directory" and "size" in info:
        try:
            return _parse_size_value(info["size"])
        except (TypeError, ValueError) as exc:
            top_level_size_error = exc

    total_size = 0
    walk_error: Exception | None = None
    ls_error: Exception | None = None

    # Try using fs.walk to traverse directories
    try:
        for _, _, files in fs.walk(url):
            for file_path in files:
                try:
                    file_info = fs.info(file_path)
                    if "size" in file_info:
                        total_size += _parse_size_value(file_info["size"])
                except Exception:
                    continue
        if total_size > 0:
            return total_size
    except Exception as exc:
        walk_error = exc

    # Fallback to recursive ls if walk is unavailable
    def _collect(path: str) -> None:
        nonlocal total_size, ls_error
        try:
            entries = fs.ls(path, detail=True)
        except Exception as exc:
            if ls_error is None:
                ls_error = exc
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or entry.get("path")
            if entry.get("type") == "directory" or (name and name.endswith("/")):
                if name:
                    _collect(name)
            elif "size" in entry:
                try:
                    total_size += _parse_size_value(entry["size"])
                except Exception:
                    continue

    _collect(url)
    if total_size > 0:
        return total_size

    if strict:
        error_parts = []
        if top_level_size_error is not None:
            error_parts.append(f"invalid size from info(): {top_level_size_error}")
        if walk_error:
            error_parts.append(f"walk() failed: {redact_cloud_error_for_display(walk_error, url)}")
        if ls_error:
            error_parts.append(f"ls() failed: {redact_cloud_error_for_display(ls_error, url)}")
        if not error_parts:
            error_parts.append("cloud provider did not return file sizes")
        raise ValueError(
            f"Unable to determine cloud object size for {redact_url_for_display(url)}: {'; '.join(error_parts)}"
        )

    return None


async def analyze_cloud_target(url: str) -> dict[str, Any]:
    """Analyze cloud target before downloading."""
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. "
            "Try reinstalling modelaudit: 'pip install --force-reinstall modelaudit'"
        ) from e

    fs_protocol = get_fs_protocol(url)
    fs_args = {"token": "anon"} if fs_protocol == "gcs" else {}

    try:
        # fsspec filesystems don't need explicit cleanup - use directly without 'with' statement
        fs = fsspec.filesystem(fs_protocol, **fs_args)

        # Get info about the target with retry
        @retry_with_backoff(
            max_retries=3,
            verbose=True,
            sanitize_error=_cloud_error_sanitizer(url),
        )
        def get_info():
            return fs.info(url)

        info = get_info()

        # Check if it's a file or directory
        if info.get("type") == "file" or (info.get("type") != "directory" and "size" in info):
            file_metadata: dict[str, Any] = {
                "type": "file",
                "size": info.get("size", 0),
                "name": _cloud_url_basename(url),
                "estimated_time": estimate_download_time(info.get("size", 0)),
                "human_size": format_size(info.get("size", 0)),
            }
            etag = _metadata_etag(info)
            if etag is not None:
                file_metadata["etag"] = etag
            return file_metadata

        # It's a directory, list contents
        files = []
        total_size = 0
        metadata_error_count = 0
        metadata_errors: list[dict[str, str]] = []

        # List all files recursively
        # Ensure URL ends with / for proper globbing
        glob_pattern = f"{url.rstrip('/')}/**"
        for item in fs.glob(glob_pattern):
            try:
                item_info = fs.info(item)
                item_type = item_info.get("type")
                if item_type == "directory":
                    continue
                if item_type == "file" or "size" in item_info:
                    size = item_info.get("size", 0)
                    file_metadata = {
                        "path": item,
                        "name": _cloud_url_basename(item),
                        "size": size,
                        "human_size": format_size(size),
                    }
                    etag = _metadata_etag(item_info)
                    if etag is not None:
                        file_metadata["etag"] = etag
                    files.append(file_metadata)
                    total_size += size
                else:
                    raise ValueError("cloud provider returned incomplete metadata for listed object")
            except Exception as exc:
                metadata_error_count += 1
                if len(metadata_errors) < _MAX_CLOUD_METADATA_ERROR_SAMPLES:
                    metadata_errors.append(_cloud_metadata_error_sample(item, exc))

        if metadata_error_count:
            sample_errors = "; ".join(f"{entry['path']}: {entry['error']}" for entry in metadata_errors)
            if metadata_error_count > len(metadata_errors):
                sample_errors = f"{sample_errors}; ..."
            return {
                "type": "unknown",
                "analysis_incomplete": True,
                "metadata_error_count": metadata_error_count,
                "metadata_errors": metadata_errors,
                "error": (
                    "Cloud directory analysis incomplete: metadata lookup failed for "
                    f"{metadata_error_count} object(s) under {redact_url_for_display(url)}: "
                    f"{sample_errors}"
                ),
            }

        directory_metadata: dict[str, Any] = {
            "type": "directory",
            "file_count": len(files),
            "total_size": total_size,
            "human_size": format_size(total_size),
            "files": files,
            "estimated_time": estimate_download_time(total_size),
        }
        etag = _metadata_etag(info)
        if etag is not None:
            directory_metadata["etag"] = etag
        return directory_metadata
    except Exception as e:
        # If we can't get info, assume it's a file
        return {"type": "unknown", "error": redact_cloud_error_for_display(e, url)}


def prompt_for_large_download(metadata: dict[str, Any]) -> bool:
    """Prompt user before large downloads."""
    size = metadata.get("total_size", metadata.get("size", 0))

    if size > 1_000_000_000:  # 1GB
        click.echo("\n⚠️  Large download detected:")
        click.echo(f"   Size: {metadata['human_size']}")
        click.echo(f"   Estimated time: {metadata['estimated_time']}")

        if metadata["type"] == "directory":
            click.echo(f"   Files: {metadata['file_count']} files")

        return click.confirm("\nContinue with download?", default=False)

    return True


class GCSCache:
    """Cache-aware download handling for cloud sources."""

    def __init__(self, cache_dir: Path | None = None):
        if cache_dir is None:
            self.cache_dir = Path.home() / ".modelaudit" / "cache"
        else:
            self.cache_dir = Path(cache_dir)

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.cache_dir.chmod(0o700)
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> dict[str, Any]:
        """Load cache metadata from disk."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, encoding="utf-8") as f:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        return {}
                    return {
                        str(cache_key): self._sanitize_metadata_entry(entry)
                        for cache_key, entry in data.items()
                        if isinstance(entry, dict)
                    }
            except Exception:
                return {}
        return {}

    def _url_metadata(self, url: str) -> dict[str, str]:
        """Return non-secret URL metadata safe to persist."""
        parsed = urlsplit(url)
        return {
            "url_sha256": self.get_cache_key(url),
            "url_display": redact_url_for_display(url),
            "url_scheme": parsed.scheme,
            "url_host": parsed.hostname or "",
            "url_path": parsed.path,
        }

    def _sanitize_metadata_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Remove legacy raw URL fields before metadata is persisted again."""
        sanitized = dict(entry)
        raw_url = sanitized.pop("url", None)
        if isinstance(raw_url, str):
            for key, value in self._url_metadata(raw_url).items():
                sanitized.setdefault(key, value)
        return sanitized

    def _save_metadata(self) -> None:
        """Save cache metadata to disk."""
        self.metadata = {
            str(cache_key): self._sanitize_metadata_entry(entry)
            for cache_key, entry in self.metadata.items()
            if isinstance(entry, dict)
        }
        temp_file = self.metadata_file.with_name(f"{self.metadata_file.name}.tmp")
        fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.metadata, f, indent=2)
                f.write("\n")
            os.replace(temp_file, self.metadata_file)
            if os.name != "nt":
                self.metadata_file.chmod(0o600)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def get_cache_key(self, url: str) -> str:
        """Generate cache key for URL."""
        return hashlib.sha256(url.encode()).hexdigest()

    def get_cached_path(self, url: str, etag: str | None = None) -> Path | None:
        """Return cached file if still valid."""
        cache_key = self.get_cache_key(url)

        if cache_key in self.metadata:
            cached = self.metadata[cache_key]
            cached_path = Path(cached["path"])

            if not _is_within_directory(self.cache_dir, cached_path):
                logger.warning(
                    "Dropping cache entry for %s because cached path %s is outside cache dir %s",
                    redact_url_for_display(url),
                    cached_path,
                    self.cache_dir,
                )
                del self.metadata[cache_key]
                self._save_metadata()
                return None

            # Check if file still exists
            if not cached_path.exists():
                del self.metadata[cache_key]
                self._save_metadata()
                return None

            cached_etag = cached.get("etag")
            if etag is None or not cached_etag:
                self._save_metadata()
                return None

            if cached_etag != etag:
                return None

            # Update last accessed time
            cached["last_accessed"] = datetime.now().isoformat()
            self._save_metadata()

            return cached_path

        return None

    def cache_file(self, url: str, local_path: Path, etag: str | None = None) -> None:
        """Cache downloaded file with metadata."""
        cache_key = self.get_cache_key(url)

        # Create cache subdirectory
        cache_subdir = self.cache_dir / cache_key[:2] / cache_key[2:4]
        cache_subdir.mkdir(parents=True, exist_ok=True)

        # Determine cache path
        if local_path.is_file():
            cache_path = cache_subdir / local_path.name
            # Don't copy if it's already in the cache directory
            if not _is_within_directory(self.cache_dir, local_path):
                shutil.copy2(local_path, cache_path)
            else:
                cache_path = local_path
        else:
            # It's a directory
            cache_path = cache_subdir / "content"
            # Don't copy if it's already in the cache directory
            if not _is_within_directory(self.cache_dir, local_path):
                if cache_path.exists():
                    shutil.rmtree(cache_path)
                shutil.copytree(local_path, cache_path)
            else:
                cache_path = local_path

        # Update metadata
        self.metadata[cache_key] = {
            **self._url_metadata(url),
            "path": str(cache_path),
            "etag": etag,
            "size": cache_path.stat().st_size if cache_path.is_file() else 0,
            "cached_at": datetime.now().isoformat(),
            "last_accessed": datetime.now().isoformat(),
        }
        self._save_metadata()

    def clean_old_cache(self, max_age_days: int = 7) -> None:
        """Clean cache entries older than max_age_days."""
        now = datetime.now()
        keys_to_remove = []

        for key, cached in self.metadata.items():
            last_accessed = datetime.fromisoformat(cached["last_accessed"])
            if now - last_accessed > timedelta(days=max_age_days):
                # Remove cached file
                cached_path = Path(cached["path"])
                if _is_within_directory(self.cache_dir, cached_path):
                    if cached_path.exists():
                        if cached_path.is_file():
                            cached_path.unlink()
                        else:
                            shutil.rmtree(cached_path)
                else:
                    logger.warning(
                        "Skipping deletion for cache metadata path %s because it is outside cache dir %s",
                        cached_path,
                        self.cache_dir,
                    )
                keys_to_remove.append(key)

        # Update metadata
        for key in keys_to_remove:
            del self.metadata[key]

        if keys_to_remove:
            self._save_metadata()
            click.echo(f"Cleaned {len(keys_to_remove)} old cache entries")


def filter_scannable_files(
    files: list[dict[str, Any]],
    scannable_extensions: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter files to only include scannable model types."""
    extensions = SCANNABLE_MODEL_EXTENSIONS if scannable_extensions is None else frozenset(scannable_extensions)
    scannable = []
    for file in files:
        file_path = str(file["path"])
        path = Path(_cloud_url_basename(file_path) if is_cloud_url(file_path) else file_path)
        suffixes = [s.lower() for s in path.suffixes]
        if not suffixes and "" in extensions:
            scannable.append(file)
            continue
        for i in range(1, len(suffixes) + 1):
            if "".join(suffixes[-i:]) in extensions:
                scannable.append(file)
                break

    return scannable


def _read_bounded_cloud_content(remote_file: Any, max_bytes: int) -> bytes:
    """Read through short transport reads without exceeding the requested bound."""
    payload = bytearray()
    while len(payload) < max_bytes:
        chunk = remote_file.read(max_bytes - len(payload))
        if not isinstance(chunk, bytes):
            raise TypeError("cloud filesystem returned non-bytes content")
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _read_cloud_content_prefix(fs: Any, file_url: str, max_bytes: int) -> bytes:
    """Read a bounded remote prefix or fail closed with a redacted error."""
    try:
        with fs.open(file_url, "rb") as remote_file:
            return _read_bounded_cloud_content(remote_file, max_bytes)
    except Exception as exc:
        raise ValueError(
            "Cloud directory selective filtering incomplete: unable to inspect skipped object "
            f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
        ) from exc


def _read_cloud_content_range(fs: Any, file_url: str, offset: int, max_bytes: int) -> bytes:
    """Read a bounded remote byte range or fail closed with a redacted error."""
    try:
        with fs.open(file_url, "rb") as remote_file:
            remote_file.seek(offset)
            return _read_bounded_cloud_content(remote_file, max_bytes)
    except Exception as exc:
        raise ValueError(
            "Cloud directory selective filtering incomplete: unable to inspect skipped object "
            f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
        ) from exc


def _get_cloud_content_size_for_routing(fs: Any, file_url: str) -> int:
    """Read the remote object's actual size for tail-sensitive content routing."""
    try:
        with fs.open(file_url, "rb") as remote_file:
            remote_file.seek(0, os.SEEK_END)
            return _parse_size_value(remote_file.tell())
    except Exception as exc:
        raise ValueError(
            "Cloud directory selective filtering incomplete: unable to inspect skipped object "
            f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
        ) from exc


def _detect_cloud_shared_skip_filter_route(
    fs: Any,
    file_url: str,
    prefix: bytes,
    size: int,
    *,
    size_is_known: bool,
) -> str | None:
    """Route skipped cloud objects through the same bounded detector as local skips."""
    from modelaudit.utils.file.detection import (
        _COREML_PROTO_SIGNATURE_READ_BYTES,
        _XML_MODEL_SIGNATURE_READ_BYTES,
        FLAX_MSGPACK_STRUCTURE_READ_BYTES,
        JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
        LLAMAFILE_ROUTE_SCAN_BYTES,
        LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
        MXNET_SYMBOL_SIGNATURE_READ_BYTES,
        _could_be_xml_prefix,
        _could_start_coreml_model_proto,
        _is_executorch_binary_signature,
        _is_supported_llamafile_executable_header,
        detect_file_format_for_skip_filter,
    )

    probe_size = _CLOUD_CONTENT_SNIFF_BYTES
    is_llamafile_candidate = _is_supported_llamafile_executable_header(prefix[:4])
    normalized_prefix = prefix.lstrip()
    if normalized_prefix.startswith(b"\xef\xbb\xbf"):
        normalized_prefix = normalized_prefix[3:].lstrip()
    if normalized_prefix.startswith((b"{", b"[")):
        probe_size = max(probe_size, MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1)
    if not normalized_prefix and not size_is_known:
        probe_size = max(
            probe_size,
            JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1,
            MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1,
        )
    if prefix and prefix[0] in _MSGPACK_CONTAINER_MARKERS:
        probe_size = max(probe_size, FLAX_MSGPACK_STRUCTURE_READ_BYTES)
    if _could_start_coreml_model_proto(prefix[:16]):
        probe_size = max(probe_size, _COREML_PROTO_SIGNATURE_READ_BYTES)
    if _is_executorch_binary_signature(prefix[:8]):
        probe_size = max(probe_size, 64 * 1024)
    if _could_be_xml_prefix(prefix):
        probe_size = max(probe_size, _XML_MODEL_SIGNATURE_READ_BYTES)
    if is_llamafile_candidate:
        size = _get_cloud_content_size_for_routing(fs, file_url)
        size_is_known = True
        probe_size = max(probe_size, LLAMAFILE_ROUTE_SCAN_BYTES)

    if size_is_known:
        probe_size = min(size, probe_size)

    probe_read_size = probe_size if size_is_known else probe_size + 1
    probe = prefix
    if len(probe) < probe_read_size:
        probe = _read_cloud_content_prefix(fs, file_url, probe_read_size)
    if not size_is_known and len(probe) < probe_read_size:
        size = len(probe)
        size_is_known = True

    tail: bytes | None = None
    tail_offset: int | None = None
    if size_is_known and size > LLAMAFILE_ROUTE_SCAN_BYTES and is_llamafile_candidate:
        tail_size = min(size, LLAMAFILE_ROUTE_TAIL_SCAN_BYTES)
        tail_offset = size - tail_size
        tail = _read_cloud_content_range(fs, file_url, tail_offset, tail_size)

    basename = _cloud_url_basename(file_url) or "cloud-object"
    with tempfile.TemporaryDirectory(prefix="modelaudit_cloud_probe_") as temp_dir:
        probe_path = Path(temp_dir) / Path(basename).name
        with probe_path.open("wb") as handle:
            handle.write(probe)
            if tail is not None and tail_offset is not None:
                handle.seek(tail_offset)
                handle.write(tail)
            if size_is_known and size > probe_path.stat().st_size:
                handle.truncate(size)

        detected_format = detect_file_format_for_skip_filter(str(probe_path))
        return None if detected_format == "unknown" else detected_format


def _is_cloud_safetensors_routing_candidate(
    fs: Any,
    file_url: str,
    prefix: bytes,
    size: int,
    *,
    size_is_known: bool,
) -> bool:
    """Recognize bounded remote SafeTensors framing without downloading tensor data."""
    if len(prefix) < 9:
        return False
    try:
        header_len = struct.unpack("<Q", prefix[:8])[0]
    except struct.error:
        return False
    if header_len <= 0 or (size_is_known and header_len > size - 8):
        return False

    from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES

    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        return prefix[8:9] == b"{"

    header_probe = _read_cloud_content_prefix(fs, file_url, 8 + header_len)
    if len(header_probe) != 8 + header_len or header_probe[8:9] != b"{":
        return False
    try:
        parsed_header = json.loads(header_probe[8:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed_header, dict)


def _detect_cloud_mxnet_symbol_route(
    fs: Any,
    file_url: str,
    prefix: bytes,
    size: int,
    *,
    size_is_known: bool,
) -> str | None:
    """Return a bounded MXNet JSON route for a suffix-skipped remote object."""
    from modelaudit.utils.file.detection import MXNET_SYMBOL_SIGNATURE_READ_BYTES, _detect_mxnet_symbol_prefix_route

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    if not normalized_prefix.lstrip().startswith(b"{"):
        return None

    max_probe_size = MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1
    if size_is_known:
        max_probe_size = min(size, max_probe_size)
    mxnet_probe = _read_cloud_content_prefix(fs, file_url, max_probe_size)
    mxnet_probe = mxnet_probe[3:] if mxnet_probe.startswith(b"\xef\xbb\xbf") else mxnet_probe
    if len(mxnet_probe) > MXNET_SYMBOL_SIGNATURE_READ_BYTES:
        return _detect_mxnet_symbol_prefix_route(
            mxnet_probe[:MXNET_SYMBOL_SIGNATURE_READ_BYTES],
            fail_closed_without_hint=True,
        )
    return _detect_mxnet_symbol_prefix_route(
        mxnet_probe,
        sample_is_prefix=(size_is_known and size > len(mxnet_probe))
        or (not size_is_known and len(mxnet_probe) >= max_probe_size),
        fail_closed_without_hint=True,
    )


def _detect_cloud_content_route_format(fs: Any, file_info: dict[str, Any]) -> str | None:
    """Return a content-routed model format for a remote object, if cheaply identifiable."""
    file_url = str(file_info["path"])
    prefix_limit = _CLOUD_CONTENT_SNIFF_BYTES
    prefix = _read_cloud_content_prefix(fs, file_url, prefix_limit)
    if not prefix:
        return None
    size = len(prefix)
    size_is_known = size < prefix_limit

    from modelaudit.utils.file.detection import (
        PROTO0_1_MAX_PROBE_BYTES,
        _could_start_proto0_or_1_pickle,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _is_keras_zip_archive_content,
        _looks_like_proto0_or_1_pickle,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )
    from modelaudit.utils.file.filtering import _zip_archive_has_scannable_content

    if _looks_like_uncompressed_tar_header(prefix):
        return "tar"

    if _is_cntk_signature(prefix):
        return "cntk"

    if _is_content_routed_lightgbm_signature(prefix):
        return "lightgbm"

    mxnet_route = _detect_cloud_mxnet_symbol_route(
        fs,
        file_url,
        prefix,
        size,
        size_is_known=size_is_known,
    )
    if mxnet_route is not None:
        return mxnet_route

    if _is_cloud_safetensors_routing_candidate(
        fs,
        file_url,
        prefix,
        size,
        size_is_known=size_is_known,
    ):
        return "safetensors"

    if _could_start_proto0_or_1_pickle(prefix):
        max_probe_size = min(size, PROTO0_1_MAX_PROBE_BYTES) if size_is_known else PROTO0_1_MAX_PROBE_BYTES
        pickle_probe = _read_cloud_content_prefix(fs, file_url, max_probe_size)
        if _looks_like_proto0_or_1_pickle(
            pickle_probe,
            sample_is_prefix=(not size_is_known and len(pickle_probe) >= max_probe_size) or size > len(pickle_probe),
        ):
            return "pickle"

    detected_format = detect_format_from_magic_bytes(
        prefix[:4],
        prefix[:8],
        prefix[:16],
        max(size, len(prefix)),
        None,
    )
    if (
        detected_format == "unknown"
        and prefix[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + len(_TFLITE_MAGIC_BYTES)] == _TFLITE_MAGIC_BYTES
    ):
        return "tflite"
    if detected_format == "zip":
        try:
            with fs.open(file_url, "rb") as remote_file, zipfile.ZipFile(remote_file, "r") as archive:
                return (
                    "zip"
                    if _is_keras_zip_archive_content(archive) or _zip_archive_has_scannable_content(archive)
                    else None
                )
        except Exception as exc:
            raise ValueError(
                "Cloud directory selective filtering incomplete: unable to classify skipped ZIP object "
                f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
            ) from exc
    if detected_format != "unknown":
        return detected_format

    return _detect_cloud_shared_skip_filter_route(
        fs,
        file_url,
        prefix,
        size,
        size_is_known=size_is_known,
    )


def _filter_scannable_cloud_files(
    files: list[dict[str, Any]],
    *,
    fs: Any,
    scannable_extensions: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    scannable = filter_scannable_files(files, scannable_extensions=scannable_extensions)
    if scannable_extensions is not None:
        return scannable

    scannable_paths = {str(file["path"]) for file in scannable}
    for file_info in files:
        file_path = str(file_info["path"])
        if file_path in scannable_paths:
            continue
        detected_format = _detect_cloud_content_route_format(fs, file_info)
        if detected_format is None:
            continue
        routed_file_info = dict(file_info)
        routed_file_info["content_detected_format"] = detected_format
        scannable.append(routed_file_info)
        scannable_paths.add(file_path)
    return scannable


def _build_safe_local_path(base_url: str, file_url: str, download_path: Path) -> Path:
    """Build a local path for a cloud object and reject traversal attempts."""
    normalized_base = _cloud_url_without_query(base_url)
    normalized_file_url = _cloud_url_without_query(file_url)

    if normalized_file_url.startswith(f"{normalized_base}/"):
        relative_path = normalized_file_url[len(normalized_base) + 1 :]
    elif normalized_file_url == normalized_base:
        relative_path = _cloud_url_basename(file_url)
    else:
        # Fallback to basename for unexpected path shapes.
        relative_path = _cloud_url_basename(file_url)

    relative_path = urlsplit(relative_path).path
    if not relative_path:
        raise ValueError(f"Invalid cloud object path: {file_url}")

    resolved_path, is_safe = _resolve_cloud_path(relative_path, download_path)
    if not is_safe:
        raise ValueError(f"Path traversal attempt detected in cloud object path: {file_url}")

    local_path = Path(resolved_path)
    if not _is_within_directory(download_path, local_path):
        raise ValueError(f"Cloud object path escaped download directory: {file_url}")

    return local_path


def _clear_directory_contents(path: Path) -> None:
    """Remove stale cache directory contents without deleting the directory itself."""
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def download_from_cloud(
    url: str,
    cache_dir: Path | None = None,
    max_size: int | None = None,
    use_cache: bool = True,
    show_progress: bool = True,
    selective: bool = True,
    stream_analyze: bool = False,
    scannable_extensions: Collection[str] | None = None,
) -> Path | str:
    """Download a file or directory from cloud storage to a local path.

    Raises:
        ImportError: If the :mod:`fsspec` package is not installed.
        ValueError: If the cloud target cannot be analyzed or its type is unknown.
        ValueError: If the object exceeds ``max_size``.
    """
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. "
            "Try reinstalling modelaudit: 'pip install --force-reinstall modelaudit'"
        ) from e

    # Initialize cache
    cache = GCSCache(cache_dir) if use_cache else None

    # Analyze target
    metadata = _run_coroutine_sync(lambda: analyze_cloud_target(url))

    # Ensure target was analyzed successfully
    if "error" in metadata or metadata.get("type") == "unknown":
        error_msg = redact_cloud_error_for_display(metadata.get("error", "Unknown cloud target type"), url)
        raise ValueError(f"Failed to analyze cloud target {redact_url_for_display(url)}: {error_msg}")

    etag = _metadata_etag(metadata)
    if cache:
        cached_path = cache.get_cached_path(url, etag=etag)
        if cached_path:
            if show_progress:
                click.echo(f"✓ Using cached version from {cached_path}")
            return cached_path

    # Check if we can use streaming analysis
    if stream_analyze and metadata.get("type") == "file":
        # Import here to avoid circular dependency
        from modelaudit.utils.file.streaming import get_streaming_preview

        # Try to get a preview first
        preview = get_streaming_preview(url)
        if preview and show_progress:
            click.echo(f"📄 File preview: {preview.get('detected_format', 'unknown')} format")

        # For streaming analysis, we don't need to download
        # Return a special marker path (string to preserve prefix)
        return f"stream://{url}"

    # Check size limits
    size = metadata.get("total_size", metadata.get("size", 0))
    if max_size and size > max_size:
        raise ValueError(f"File size ({format_size(size)}) exceeds maximum allowed size ({format_size(max_size)})")

    # Show warning for large files
    if size > 100_000_000 and show_progress:  # 100MB
        click.echo(f"⚠️  Downloading {metadata['human_size']} (estimated time: {metadata['estimated_time']})")

    # Create download directory
    if cache:
        # When using cache, download directly to cache location
        cache_key = cache.get_cache_key(url)
        cache_subdir = cache.cache_dir / cache_key[:2] / cache_key[2:4]
        cache_subdir.mkdir(parents=True, exist_ok=True)
        download_path = cache_subdir
    elif cache_dir is None:
        download_path = Path(tempfile.mkdtemp(prefix="modelaudit_cloud_"))
    else:
        download_path = Path(cache_dir)
        download_path.mkdir(parents=True, exist_ok=True)

    should_cleanup_temp_dir = cache is None and cache_dir is None
    try:
        # Get filesystem
        fs_protocol = get_fs_protocol(url)
        fs_args = {"token": "anon"} if fs_protocol == "gcs" else {}

        # fsspec filesystems don't need explicit cleanup - use directly without 'with' statement
        fs = fsspec.filesystem(fs_protocol, **fs_args)

        # Check available disk space before downloading
        object_size: int | None
        try:
            object_size = get_cloud_object_size(fs, url, strict=True)
        except ValueError as exc:
            # Fall back to metadata-derived size when available. If no reliable size is
            # available, continue without a pre-download disk check (legacy behavior).
            if size > 0:
                object_size = int(size)
                if show_progress:
                    click.echo(f"⚠️  Falling back to metadata size estimate for disk check: {exc}")
            else:
                object_size = None
                if show_progress:
                    click.echo(
                        "⚠️  Unable to determine download size for "
                        f"{redact_url_for_display(url)}; continuing without disk check: {exc}"
                    )

        if object_size is not None:
            has_space, message = check_disk_space(download_path, object_size)
            if not has_space:
                raise Exception(f"Cannot download from {redact_url_for_display(url)}: {message}")

        # Download based on type
        if metadata["type"] == "directory":
            if cache:
                _clear_directory_contents(download_path)

            # Handle directory download
            raw_files = metadata.get("files")
            if raw_files is None:
                files = []
            elif isinstance(raw_files, list):
                files = raw_files
            else:
                raise ValueError(f"Invalid metadata for 'files': expected list, got {type(raw_files).__name__}")

            if selective:
                # Filter to only scannable files
                files = _filter_scannable_cloud_files(files, fs=fs, scannable_extensions=scannable_extensions)
                if show_progress:
                    total = metadata.get("file_count", 0)
                    if files:
                        click.echo(f"Found {len(files)} scannable files out of {total} total files")
                    else:
                        click.echo(f"No scannable files found out of {total} total files")

            if not files:
                raise ValueError("No scannable model files found in directory")

            # Download files
            for file_info in files:
                file_url = file_info["path"]
                local_path = _build_safe_local_path(url, file_url, download_path)
                local_path.parent.mkdir(parents=True, exist_ok=True)

                if show_progress:
                    click.echo(f"Downloading {file_info['name']} ({file_info['human_size']})")

                @retry_with_backoff(
                    max_retries=3,
                    verbose=show_progress,
                    sanitize_error=_cloud_error_sanitizer(file_url),
                )
                def download_file(url=file_url, path=local_path):
                    fs.get(url, str(path))

                download_file()
        else:
            # Single file download
            file_name = _cloud_url_basename(url)
            local_file = download_path / file_name

            @retry_with_backoff(
                max_retries=3,
                verbose=show_progress,
                sanitize_error=_cloud_error_sanitizer(url),
            )
            def download_single_file():
                fs.get(url, str(local_file))

            if show_progress and size > 100 * 1024 * 1024 * 1024:  # Show progress for files > 100GB
                with yaspin(text=f"Downloading {file_name}") as spinner:
                    download_single_file()
                    spinner.ok("✓")
            else:
                download_single_file()

            # Cache the download
            if cache:
                cache.cache_file(url, local_file, etag=etag)  # Cache the actual file, not the directory

            return local_file  # Return the actual file path for single files

        # Cache the download (for directories)
        if cache:
            cache.cache_file(url, download_path, etag=etag)

        return download_path
    except Exception:
        if should_cleanup_temp_dir and download_path.exists():
            shutil.rmtree(download_path, ignore_errors=True)
        raise


def download_from_cloud_streaming(
    url: str,
    cache_dir: Path | None = None,
    max_size: int | None = None,
    show_progress: bool = True,
    selective: bool = True,
    scannable_extensions: Collection[str] | None = None,
) -> Iterator[tuple[Path, bool]]:
    """
    Download files from cloud storage one at a time (streaming mode).

    Yields (file_path, is_last) tuples for each downloaded file.
    Files are downloaded to temporary locations for immediate scanning.

    Args:
        url: Cloud storage URL (s3://, gs://, etc.)
        cache_dir: Optional cache directory (not used in streaming mode)
        max_size: Maximum total size allowed
        show_progress: Whether to show progress messages
        selective: Whether to filter to only scannable files

    Yields:
        Tuples of (file_path, is_last) for each downloaded file
    """
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. Install with 'pip install modelaudit[cloud]'"
        ) from e

    # Analyze target to get file list
    metadata = _run_coroutine_sync(lambda: analyze_cloud_target(url))

    if "error" in metadata or metadata.get("type") == "unknown":
        error_msg = metadata.get("error", "Unknown cloud target type")
        raise ValueError(f"Failed to analyze cloud target {redact_url_for_display(url)}: {error_msg}")

    # Check size limits
    size = metadata.get("total_size", metadata.get("size", 0))
    if max_size and size > max_size:
        raise ValueError(f"Total size ({format_size(size)}) exceeds maximum allowed size ({format_size(max_size)})")

    # Get filesystem
    fs_protocol = get_fs_protocol(url)
    fs_args = {"token": "anon"} if fs_protocol == "gcs" else {}
    fs = fsspec.filesystem(fs_protocol, **fs_args)

    # Get list of files to download
    if metadata["type"] == "directory":
        raw_files = metadata.get("files")
        if raw_files is None:
            files = []
        elif isinstance(raw_files, list):
            files = raw_files
        else:
            raise ValueError(f"Invalid metadata for 'files': expected list, got {type(raw_files).__name__}")

        if selective:
            files = _filter_scannable_cloud_files(files, fs=fs, scannable_extensions=scannable_extensions)
            if show_progress and files:
                click.echo(f"Found {len(files)} scannable files to stream")

        if not files:
            raise ValueError("No scannable model files found")
    else:
        # Single file
        files = [{"path": url, "name": _cloud_url_basename(url), "size": metadata.get("size", 0)}]

    # Create temp directory for downloads
    temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_stream_"))

    try:
        # Download files one at a time
        total_files = len(files)
        for i, file_info in enumerate(files):
            file_url = file_info["path"]
            file_name = file_info.get("name") or _cloud_url_basename(file_url)
            is_last = i == total_files - 1

            # Build a safe local path relative to the requested cloud base path.
            local_path = _build_safe_local_path(url, file_url, temp_dir)
            local_path.parent.mkdir(parents=True, exist_ok=True)

            if show_progress:
                click.echo(f"⬇️  Downloading {file_name} ({file_info.get('human_size', 'unknown size')})")

            @retry_with_backoff(
                max_retries=3,
                verbose=show_progress,
                sanitize_error=_cloud_error_sanitizer(file_url),
            )
            def download_file(url=file_url, path=local_path):
                fs.get(url, str(path))

            download_file()

            yield (local_path, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
