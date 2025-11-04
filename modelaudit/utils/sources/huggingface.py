"""Utilities for handling HuggingFace model downloads."""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..helpers.disk_space import check_disk_space


def _get_model_extensions() -> set[str]:
    """
    Lazy-load model extensions to avoid circular imports.

    Returns all file extensions that ModelAudit can scan - dynamically loaded from scanner registry.
    This ensures we download and scan everything we have scanners for.
    """
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def is_huggingface_url(url: str) -> bool:
    """Check if a URL is a HuggingFace model URL."""
    # More robust patterns that handle special characters in model names
    patterns = [
        r"^https?://huggingface\.co/[^/]+(/[^/]+)?/?$",
        r"^https?://hf\.co/[^/]+(/[^/]+)?/?$",
        r"^hf://[^/]+(/[^/]+)?/?$",
    ]
    return any(re.match(pattern, url) for pattern in patterns)


def is_huggingface_file_url(url: str) -> bool:
    """Check if a URL is a direct HuggingFace file URL."""
    try:
        # Reuse the stricter URL structure validation
        parse_huggingface_file_url(url)
        return True
    except ValueError:
        return False


def parse_huggingface_file_url(url: str) -> tuple[str, str, str]:
    """Parse a HuggingFace file URL to extract repo_id and filename.

    Args:
        url: HuggingFace file URL like https://huggingface.co/user/repo/resolve/main/file.bin

    Returns:
        Tuple of (repo_id, branch, filename)

    Raises:
        ValueError: If URL format is invalid
    """
    parsed = urlparse(url)
    if parsed.netloc not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {url}")

    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) < 5 or path_parts[2] != "resolve":
        raise ValueError(f"Invalid HuggingFace file URL format: {url}")

    repo_id = f"{path_parts[0]}/{path_parts[1]}"
    # URL-decode individual parts to handle percent-encoded characters
    branch = unquote(path_parts[3])  # This will now be properly decoded
    filename = "/".join(unquote(part) for part in path_parts[4:])

    return repo_id, branch, filename


def parse_huggingface_url(url: str) -> tuple[str, str]:
    """Parse a HuggingFace URL to extract repo_id.

    Args:
        url: HuggingFace URL in various formats

    Returns:
        Tuple of (namespace, repo_name)

    Raises:
        ValueError: If URL format is invalid
    """
    # Handle hf:// format
    if url.startswith("hf://"):
        # URL-decode the path portion
        path = unquote(url[5:])
        parts = path.strip("/").split("/")
        if len(parts) == 1 and parts[0]:
            # Single component like "bert-base-uncased" - treat as model without namespace
            return parts[0], ""
        if len(parts) == 2:
            return parts[0], parts[1]
        raise ValueError(f"Invalid HuggingFace URL format: {url}")

    # Handle https:// format
    parsed = urlparse(url)
    if parsed.netloc not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {url}")

    # URL-decode the path to handle percent-encoded characters
    path = unquote(parsed.path)
    path_parts = path.strip("/").split("/")
    if len(path_parts) == 1 and path_parts[0]:
        # Single component like "bert-base-uncased" - treat as model without namespace
        return path_parts[0], ""
    if len(path_parts) >= 2:
        return path_parts[0], path_parts[1]
    raise ValueError(f"Invalid HuggingFace URL format: {url}")


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
            import logging

            logger = logging.getLogger(__name__)
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
        raise Exception(f"Failed to get model info for {url}: {e!s}") from e


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

    # Disk space check and path setup
    model_size = get_model_size(repo_id)
    download_path = None  # Will be set only if cache_dir is provided

    if cache_dir is not None:
        # Create a structured cache directory
        download_path = cache_dir / "huggingface" / namespace
        if repo_name:
            download_path = download_path / repo_name
        download_path.mkdir(parents=True, exist_ok=True)

        # Check if model already exists in cache
        if download_path.exists() and any(download_path.iterdir()):
            # Verify it's a valid model directory
            expected_files = [
                "config.json",
                "pytorch_model.bin",
                "model.safetensors",
                "flax_model.msgpack",
                "tf_model.h5",
            ]
            if any((download_path / f).exists() for f in expected_files):
                return download_path

        # Check available disk space when using custom cache directory
        if model_size:
            has_space, message = check_disk_space(download_path, model_size)
            if not has_space:
                raise Exception(f"Cannot download model from {url}: {message}")
    else:
        # When no cache_dir is provided, let HuggingFace handle caching
        # We skip disk space checks as we don't control where HF stores its cache
        pass

    try:
        # Configure progress display based on environment
        import os

        from huggingface_hub import list_repo_files
        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Enable/disable progress bars based on parameter
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            # Force progress bar to show even in non-TTY environments
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # List files in the repository to identify model files
        # Skip for large repos to avoid hanging - download all files instead
        try:
            # Add a timeout-like behavior by catching all exceptions
            # If this fails or hangs, we'll download everything (safer fallback)
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(list_repo_files, repo_id)
                try:
                    # Wait up to 30 seconds for file listing
                    repo_files = future.result(timeout=30)
                except concurrent.futures.TimeoutError:
                    # File listing took too long - skip it and download everything
                    repo_files = []
        except Exception:
            # Any error - just download everything
            repo_files = []

        # Find model files in the repository (using centralized model extensions)
        model_extensions = _get_model_extensions()
        model_files = [f for f in repo_files if any(f.endswith(ext) for ext in model_extensions)]

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
        if cache_dir is not None and download_path is not None and download_path.exists():
            import shutil

            shutil.rmtree(download_path)
        raise Exception(f"Failed to download model from {url}: {e!s}") from e


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
        from huggingface_hub import hf_hub_download, list_repo_files
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace

    try:
        # List all files in the repository
        import concurrent.futures
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Configure progress display
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # List files with timeout
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(list_repo_files, repo_id)
            try:
                repo_files = future.result(timeout=30)
            except concurrent.futures.TimeoutError as e:
                raise Exception(f"Timeout listing files in repository {repo_id}") from e

        # Filter for model files
        model_extensions = _get_model_extensions()
        model_files = [f for f in repo_files if any(f.endswith(ext) for ext in model_extensions)]

        if not model_files:
            # Fallback: download all files if no recognized extensions found
            # This maintains parity with download_model() behavior
            model_files = repo_files

        # Setup cache directory
        download_path = None
        if cache_dir is not None:
            download_path = cache_dir / "huggingface" / namespace
            if repo_name:
                download_path = download_path / repo_name
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
                    local_dir_use_symlinks=False,
                )
            else:
                # Use HF default cache
                local_path = hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                )

            yield (Path(local_path), is_last)

    except Exception as e:
        raise Exception(f"Failed to download model from {url}: {e!s}") from e


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
        raise Exception(f"Failed to download file from {url}: {e!s}") from e
