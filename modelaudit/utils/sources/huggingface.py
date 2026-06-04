"""Utilities for handling HuggingFace model downloads."""

import logging
import os
from collections.abc import Collection, Iterator
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

_MAX_HF_STREAMING_EXTENSIONLESS_FILES = 128

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
    suffix_globs = {_case_insensitive_suffix_glob(ext) for ext in extensions if ext}
    patterns = {f"*{suffix}" for suffix in suffix_globs}
    patterns.update(f"**/*{suffix}" for suffix in suffix_globs)
    return sorted(patterns)


def _case_insensitive_suffix_glob(extension: str) -> str:
    """Build a fnmatch suffix glob that preserves mixed-case remote files."""
    return "".join(f"[{char.lower()}{char.upper()}]" if char.isalpha() else char for char in extension)


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
        content_routed_filenames = {
            str(filename).lower() for filename in scanner_info.get("content_routed_filenames", [])
        }
        supports_extensionless = "" in scanner_extensions or any(
            not Path(filename).suffixes for filename in content_routed_filenames
        )
        if supports_extensionless and "" not in remote_excluded_extensions:
            extensions.add("")
            break
    return extensions


def _select_streamable_hf_files(
    repo_id: str,
    repo_files: list[str],
    scannable_extensions: Collection[str] | None = None,
) -> list[str]:
    """Select bounded remotely scannable files without treating ``""`` as a wildcard."""
    extensions = (
        _get_default_hf_streaming_extensions()
        if scannable_extensions is None
        else {str(extension).lower() for extension in scannable_extensions}
    )
    model_files: list[str] = []
    extensionless_count = 0

    for file_name in repo_files:
        if _is_scannable_hf_file(file_name, extensions):
            model_files.append(file_name)
            continue

        if "" in extensions and not Path(file_name).suffixes:
            extensionless_count += 1
            if extensionless_count > _MAX_HF_STREAMING_EXTENSIONLESS_FILES:
                raise Exception(
                    f"Refusing to stream-download extensionless files from {repo_id}: "
                    f"repository listing exceeds the bounded extensionless candidate limit "
                    f"({_MAX_HF_STREAMING_EXTENSIONLESS_FILES}); streaming coverage is incomplete"
                )
            model_files.append(file_name)

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
        model_files = [f for f in repo_files if _is_scannable_hf_file(f, model_extensions)]

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
        else:
            _raise_no_scannable_hf_files(repo_id)

        local_path = snapshot_download(**download_kwargs)  # type: ignore[call-arg]

        # Verify we actually got model files
        downloaded_path = Path(local_path)
        model_extensions = _get_model_extensions()
        found_models = any(
            path.is_file() and _is_scannable_hf_file(path.name, model_extensions) for path in downloaded_path.rglob("*")
        )

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
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    scannable_extensions: Collection[str] | None = None,
) -> Iterator[tuple[Path, bool]]:
    """Download a model from HuggingFace one file at a time (streaming mode).

    This generator yields (file_path, is_last_file) tuples as each file is downloaded.
    Designed for streaming workflows to minimize disk usage.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress
        scannable_extensions: Optional remote prefilter extensions from scanner selection policy

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

        model_files = _select_streamable_hf_files(repo_id, repo_files, scannable_extensions)

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
    try:
        from huggingface_hub import HfApi, hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    repo_id, branch, filename = parse_huggingface_file_url(url)
    display_url = redact_huggingface_url_for_display(url)

    try:
        if max_size is not None and max_size < 0:
            raise ValueError("Maximum file size must be non-negative")

        size_limit = max_size or None
        download_revision = branch
        if size_limit is not None:
            api = HfApi()
            repo_info = api.repo_info(repo_id, revision=branch)
            pinned_revision = getattr(repo_info, "sha", None)
            if not isinstance(pinned_revision, str) or not pinned_revision:
                raise ValueError(f"Unable to determine immutable revision for {display_url}; refusing capped download")

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
