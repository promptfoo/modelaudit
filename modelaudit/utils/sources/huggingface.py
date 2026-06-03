"""Utilities for handling HuggingFace model downloads."""

import json
import logging
import os
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

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
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_BYTES = b"TFL3"

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


def _get_model_extensions() -> set[str]:
    """
    Lazy-load model extensions to avoid circular imports.

    Returns all file extensions that ModelAudit can scan - dynamically loaded from scanner registry.
    This ensures we download and scan everything we have scanners for.
    """
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _build_extension_allow_patterns() -> list[str]:
    """Build conservative glob patterns for scannable files."""
    extensions = _get_model_extensions()
    patterns = {f"*{ext}" for ext in extensions}
    patterns.update(f"**/*{ext}" for ext in extensions)
    return sorted(patterns)


def _has_model_extension(filename: str, model_extensions: set[str]) -> bool:
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext.lower()) for ext in model_extensions)


def _read_huggingface_prefix(repo_id: str, filename: str, max_bytes: int) -> bytes:
    """Read a bounded remote prefix for selective content routing."""
    try:
        import requests
        from huggingface_hub import hf_hub_url
        from huggingface_hub.utils import build_hf_headers

        file_url = hf_hub_url(repo_id=repo_id, filename=filename)
        headers = build_hf_headers(
            token=None,
            headers={"Range": f"bytes=0-{max_bytes - 1}"},
        )
        with requests.get(file_url, headers=headers, stream=True, timeout=30, allow_redirects=True) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=max_bytes):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
        return b"".join(chunks)[:max_bytes]
    except Exception as exc:
        raise ValueError(
            "Hugging Face selective filtering incomplete: unable to inspect skipped file "
            f"{repo_id}/{filename}: {redact_huggingface_urls_in_text(str(exc))}"
        ) from exc


def _read_huggingface_probe(repo_id: str, filename: str, prefix: bytes, max_bytes: int) -> bytes:
    """Return an existing or freshly expanded bounded remote prefix."""
    if len(prefix) >= max_bytes:
        return prefix[:max_bytes]
    return _read_huggingface_prefix(repo_id, filename, max_bytes)


def _looks_like_safetensors_prefix(repo_id: str, filename: str, prefix: bytes) -> bool:
    """Recognize bounded SafeTensors framing without requiring a local path."""
    if len(prefix) <= 8:
        return False

    header_len = struct.unpack("<Q", prefix[:8])[0]
    header_prefix = prefix[8:]
    if header_len <= 0 or not header_prefix.startswith(b"{"):
        return False

    from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES

    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        return True

    header_probe = _read_huggingface_prefix(repo_id, filename, 8 + header_len)
    if len(header_probe) != 8 + header_len or header_probe[8:9] != b"{":
        return False
    try:
        parsed_header = json.loads(header_probe[8:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed_header, dict)


def _detect_huggingface_mxnet_symbol_route(repo_id: str, filename: str, prefix: bytes) -> str | None:
    """Return a bounded MXNet JSON route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import MXNET_SYMBOL_SIGNATURE_READ_BYTES, _detect_mxnet_symbol_prefix_route

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    if not normalized_prefix.lstrip().startswith(b"{"):
        return None

    max_probe_size = MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1
    mxnet_probe = _read_huggingface_prefix(repo_id, filename, max_probe_size)
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


def _detect_huggingface_xml_model_route(repo_id: str, filename: str, prefix: bytes) -> str | None:
    """Return a bounded XML model route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        _XML_MODEL_SIGNATURE_READ_BYTES,
        _could_be_xml_prefix,
        _detect_xml_model_format,
    )

    if not _could_be_xml_prefix(prefix):
        return None

    xml_probe = _read_huggingface_probe(repo_id, filename, prefix, _XML_MODEL_SIGNATURE_READ_BYTES)
    detected_format = _detect_xml_model_format(
        xml_probe,
        sample_is_prefix=len(xml_probe) >= _XML_MODEL_SIGNATURE_READ_BYTES,
    )
    return None if detected_format == "unknown" else detected_format


def _detect_huggingface_jax_json_route(repo_id: str, filename: str, prefix: bytes) -> str | None:
    """Return a bounded JAX JSON checkpoint route for a suffix-skipped remote file."""
    from modelaudit.utils.file.detection import (
        JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
        _could_start_json_object,
        has_jax_json_checkpoint_structure,
    )

    jax_probe = prefix
    normalized_prefix = jax_probe.lstrip()
    if normalized_prefix.startswith(b"\xef\xbb\xbf"):
        normalized_prefix = normalized_prefix[3:].lstrip()

    if not normalized_prefix:
        max_probe_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1
        jax_probe = _read_huggingface_probe(repo_id, filename, prefix, max_probe_size)
        normalized_prefix = jax_probe.lstrip()
        if normalized_prefix.startswith(b"\xef\xbb\xbf"):
            normalized_prefix = normalized_prefix[3:].lstrip()
        if not normalized_prefix and len(jax_probe) > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            return "jax_checkpoint"

    if not _could_start_json_object(jax_probe):
        return None

    max_probe_size = JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1
    jax_probe = _read_huggingface_probe(repo_id, filename, jax_probe, max_probe_size)
    try:
        payload = json.loads(jax_probe.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        if len(jax_probe) > JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES:
            return "jax_checkpoint"
        return None
    return "jax_checkpoint" if has_jax_json_checkpoint_structure(payload) else None


def _detect_huggingface_xgboost_ubjson_route(repo_id: str, filename: str, prefix: bytes) -> str | None:
    """Return a bounded XGBoost UBJSON route for a suffix-skipped remote file."""
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

    xgboost_probe = _read_huggingface_probe(repo_id, filename, prefix, _XGBOOST_UBJSON_ROUTE_READ_BYTES)
    return _detect_extensionless_xgboost_ubjson_route(xgboost_probe)


def _detect_huggingface_content_route_format(repo_id: str, filename: str) -> str | None:
    """Return a content-routed model format for a remote file, if cheaply identifiable."""
    prefix = _read_huggingface_prefix(repo_id, filename, _HF_CONTENT_SNIFF_BYTES)
    if not prefix:
        return None

    from modelaudit.utils.file.detection import (
        PROTO0_1_MAX_PROBE_BYTES,
        _could_start_proto0_or_1_pickle,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _is_executorch_binary_signature,
        _looks_like_proto0_or_1_pickle,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )

    if _looks_like_safetensors_prefix(repo_id, filename, prefix):
        return "safetensors"
    if _looks_like_uncompressed_tar_header(prefix):
        return "tar"
    if _is_cntk_signature(prefix):
        return "cntk"
    if _is_content_routed_lightgbm_signature(prefix):
        return "lightgbm"

    xml_route = _detect_huggingface_xml_model_route(repo_id, filename, prefix)
    if xml_route is not None:
        return xml_route

    xgboost_ubjson_route = _detect_huggingface_xgboost_ubjson_route(repo_id, filename, prefix)
    if xgboost_ubjson_route is not None:
        return xgboost_ubjson_route

    jax_json_route = _detect_huggingface_jax_json_route(repo_id, filename, prefix)
    if jax_json_route is not None:
        return jax_json_route

    mxnet_route = _detect_huggingface_mxnet_symbol_route(repo_id, filename, prefix)
    if mxnet_route is not None:
        return mxnet_route

    if _could_start_proto0_or_1_pickle(prefix):
        pickle_probe = _read_huggingface_prefix(repo_id, filename, PROTO0_1_MAX_PROBE_BYTES)
        if _looks_like_proto0_or_1_pickle(
            pickle_probe,
            sample_is_prefix=len(pickle_probe) >= PROTO0_1_MAX_PROBE_BYTES,
        ):
            return "pickle"
    if _is_executorch_binary_signature(prefix):
        return "executorch"

    detected_format = detect_format_from_magic_bytes(
        prefix[:4],
        prefix[:8],
        prefix[:16],
        max(len(prefix), 1),
        None,
    )
    if (
        detected_format == "unknown"
        and prefix[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + len(_TFLITE_MAGIC_BYTES)] == _TFLITE_MAGIC_BYTES
    ):
        return "tflite"
    return None if detected_format == "unknown" else detected_format


def _select_huggingface_model_files(repo_id: str, repo_files: list[str], model_extensions: set[str]) -> list[str]:
    """Select extension-matching files plus bounded content-routed renamed model files."""
    model_files = [filename for filename in repo_files if _has_model_extension(filename, model_extensions)]
    selected_files = set(model_files)
    inspected_files = 0

    for filename in repo_files:
        if filename in selected_files:
            continue
        if inspected_files >= _HF_CONTENT_SNIFF_MAX_FILES:
            raise ValueError(
                "Hugging Face selective filtering incomplete: skipped file inspection limit exceeded "
                f"for {repo_id} ({_HF_CONTENT_SNIFF_MAX_FILES} files)"
            )
        inspected_files += 1
        detected_format = _detect_huggingface_content_route_format(repo_id, filename)
        if detected_format is None:
            continue
        model_files.append(filename)
        selected_files.add(filename)

    return model_files


def _get_hf_cache_root() -> Path:
    """Return the HuggingFace hub cache root."""
    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        return Path(HF_HUB_CACHE)
    except Exception:
        return Path.home() / ".cache" / "huggingface" / "hub"


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


def _list_repo_files_with_timeout(repo_id: str, timeout_seconds: float = 30) -> tuple[list[str] | None, str | None]:
    """Return repository files or a failure reason if listing times out/errors."""
    from huggingface_hub import HfApi

    try:
        repo_info = HfApi().repo_info(repo_id, timeout=timeout_seconds, files_metadata=False)
    except Exception as exc:
        return None, str(exc)

    siblings = getattr(repo_info, "siblings", None)
    if siblings is None:
        return None, "repository listing unavailable"

    files: list[str] = []
    for sibling in siblings:
        if isinstance(sibling, dict):
            file_name = sibling.get("rfilename") or sibling.get("path")
        else:
            file_name = getattr(sibling, "rfilename", None) or getattr(sibling, "path", None)

        if isinstance(file_name, str) and file_name:
            files.append(file_name)

    return files, None


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

    api = HfApi()
    try:
        # Get model info for metadata
        model_info = api.model_info(repo_id)

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


def get_model_size(repo_id: str) -> int | None:
    """Get the total size of a HuggingFace model repository.

    Args:
        repo_id: Repository ID (e.g., "namespace/model-name")

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        from huggingface_hub import HfApi

        api = HfApi()
        model_info = api.model_info(repo_id)

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


def download_model(url: str, cache_dir: Path | None = None, show_progress: bool = True) -> Path:
    """Download a model from HuggingFace.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress

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

    # Disk space check and path setup
    model_size = get_model_size(repo_id)
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

        # List files in the repository to identify model files
        repo_files, repo_listing_error = _list_repo_files_with_timeout(repo_id)
        if repo_files is None:
            repo_listing_failed = True
            logger.debug("Hugging Face repo listing failed for %s: %s", repo_id, repo_listing_error)
            repo_files = []
        else:
            repo_listing_failed = False

        # Find model files in the repository (using centralized model extensions)
        model_extensions = _get_model_extensions()
        model_files = (
            [] if repo_listing_failed else _select_huggingface_model_files(repo_id, repo_files, model_extensions)
        )

        # Download strategy:
        # - When cache_dir is provided: Use local_dir to place files directly there (safer)
        # - When cache_dir is None: Use HF's default caching mechanism (avoid interfering)

        download_kwargs: dict[str, Any] = {
            "repo_id": repo_id,
            "tqdm_class": None,  # Use default tqdm
        }

        if cache_dir is not None:
            # User provided cache directory - use local_dir for direct placement
            download_kwargs["local_dir"] = str(download_path)
        else:
            # No cache directory provided - let HF use its default cache
            # This is safer as it doesn't risk deleting user's global cache
            pass

        # If we found specific model files, download them
        if model_files:
            download_kwargs["allow_patterns"] = model_files
        elif repo_listing_failed:
            extension_allow_patterns = _build_extension_allow_patterns()
            if not extension_allow_patterns:
                raise Exception(
                    f"Refusing to download full snapshot for {repo_id}: no selective allowlist patterns available"
                )
            download_kwargs["allow_patterns"] = extension_allow_patterns

        if "allow_patterns" in download_kwargs:
            local_path = snapshot_download(**download_kwargs)  # type: ignore[call-arg]
        else:
            # Fallback: download everything if no model files identified
            local_path = snapshot_download(**download_kwargs)  # type: ignore[call-arg]

        # Verify we actually got model files
        downloaded_path = Path(local_path)
        model_extensions = _get_model_extensions()
        found_models = any(downloaded_path.glob(f"*{ext}") for ext in model_extensions)

        if not found_models and not any(downloaded_path.glob("config.json")):
            # If no model files and no config, warn the user
            import warnings

            warnings.warn(
                f"No model files found in {repo_id}. "
                "The repository may not contain model weights or uses an unsupported format.",
                UserWarning,
                stacklevel=2,
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
    url: str, cache_dir: Path | None = None, show_progress: bool = True
) -> Iterator[tuple[Path, bool]]:
    """Download a model from HuggingFace one file at a time (streaming mode).

    This generator yields (file_path, is_last_file) tuples as each file is downloaded.
    Designed for streaming workflows to minimize disk usage.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress

    Yields:
        Tuple of (Path, bool) - (downloaded file path, is_last_file flag)

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

        # List files with timeout without leaking a blocking worker thread.
        repo_files, repo_listing_error = _list_repo_files_with_timeout(repo_id)
        if repo_files is None:
            if repo_listing_error and repo_listing_error.startswith("timed out after"):
                raise Exception(f"Timeout listing files in repository {repo_id}")
            raise Exception(f"Failed listing files in repository {repo_id}: {repo_listing_error}")

        # Filter for model files
        model_extensions = _get_model_extensions()
        model_files = _select_huggingface_model_files(repo_id, repo_files, model_extensions)

        if not model_files:
            # Fallback: download all files if no recognized extensions found
            # This maintains parity with download_model() behavior
            model_files = repo_files

        # Setup cache directory
        download_path = None
        if cache_dir is not None:
            download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
            download_path.mkdir(parents=True, exist_ok=True)

        # Download each file one at a time
        total_files = len(model_files)
        for idx, filename in enumerate(model_files):
            is_last = idx == total_files - 1

            # Download single file
            if cache_dir is not None and download_path is not None:
                # Use specific cache dir for local placement
                local_path = hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                    cache_dir=str(cache_dir / "huggingface"),
                    local_dir=str(download_path),
                )
            else:
                # Use HF default cache
                local_path = hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                )

            yield (Path(local_path), is_last)

    except Exception as e:
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_file_from_hf(url: str, cache_dir: Path | None = None) -> Path:
    """Download a single file from HuggingFace using direct file URL.

    Args:
        url: Direct HuggingFace file URL (e.g., https://huggingface.co/user/repo/resolve/main/file.bin)
        cache_dir: Optional cache directory for downloads

    Returns:
        Path to the downloaded file

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

    repo_id, branch, filename = parse_huggingface_file_url(url)
    display_url = redact_huggingface_url_for_display(url)

    try:
        # Use hf_hub_download for single file downloads
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            revision=branch,
            cache_dir=str(cache_dir) if cache_dir else None,
        )
        return Path(local_path)
    except Exception as e:
        raise Exception(f"Failed to download file from {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e
