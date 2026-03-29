"""Utilities for handling HuggingFace model downloads."""

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..helpers.disk_space import check_disk_space

logger = logging.getLogger(__name__)


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


def _get_hf_cache_root() -> Path:
    """Return the HuggingFace hub cache root."""
    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        return Path(HF_HUB_CACHE)
    except Exception:
        return Path.home() / ".cache" / "huggingface" / "hub"


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
    disk_check_path = None

    if cache_dir is not None:
        # Create a structured cache directory
        download_path = cache_dir / "huggingface" / namespace
        if repo_name:
            download_path = download_path / repo_name
        download_path.mkdir(parents=True, exist_ok=True)
        disk_check_path = download_path

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

    else:
        disk_check_path = _get_hf_cache_root()
        disk_check_path.mkdir(parents=True, exist_ok=True)

    if model_size and disk_check_path is not None:
        has_space, message = check_disk_space(disk_check_path, model_size)
        if not has_space:
            raise Exception(f"Cannot download model from {url}: {message}")

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
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace

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


def _path_has_part(path: Path, part: str) -> bool:
    """Return True if any path segment matches part (case-insensitive)."""
    part_lower = part.lower()
    return any(segment.lower() == part_lower for segment in path.parts)


def _find_hf_cache_root(path: Path) -> Path | None:
    """Return the HuggingFace cache root containing models--* if present."""
    for index, segment in enumerate(path.parts):
        if (
            segment.lower().startswith("models--")
            and index >= 3
            and [part.lower() for part in path.parts[index - 3 : index]] == [".cache", "huggingface", "hub"]
        ):
            return Path(*path.parts[: index + 1])
    return None


def is_huggingface_cache_path(path: str | Path) -> bool:
    """Return True if a path is inside a HuggingFace cache layout."""
    path_obj = Path(path)
    cache_root = _find_hf_cache_root(path_obj)
    if cache_root is None:
        return False

    try:
        relative_parts = path_obj.relative_to(cache_root).parts
    except ValueError:
        return False

    return bool(relative_parts and relative_parts[0] in {"snapshots", "blobs", "refs"})


def extract_model_id_from_path(path: str) -> tuple[str | None, str | None]:
    """Extract HuggingFace model ID and source from a path or URL.

    Args:
        path: File path or URL that might contain model information

    Returns:
        Tuple of (model_id, source) where:
        - model_id: The HuggingFace model ID (e.g., "bert-base-uncased") or None
        - source: The source type ("huggingface", "local", etc.) or None
    """
    # Check if it's a HuggingFace URL
    if is_huggingface_url(path) or is_huggingface_file_url(path):
        try:
            namespace, repo_name = parse_huggingface_url(path)
            model_id = f"{namespace}/{repo_name}" if repo_name else namespace
            return model_id, "huggingface"
        except ValueError:
            pass

    # Check if it's a local path with HuggingFace cache structure.
    # HuggingFace cache typically has structure like: models--namespace--repo-name/...
    path_obj = Path(path)
    if is_huggingface_cache_path(path_obj):
        cache_root = _find_hf_cache_root(path_obj)
        if cache_root is not None:
            # Format: models--namespace--repo-name
            parts = cache_root.name[len("models--") :].split("--")
            if len(parts) >= 2:
                model_id = f"{parts[0]}/{parts[1]}"
                return model_id, "huggingface_cache"

    # Check for config.json or model metadata in parent directories
    current_path = path_obj if path_obj.is_dir() else path_obj.parent
    for _ in range(3):  # Check up to 3 levels up
        config_file = current_path / "config.json"
        if config_file.exists():
            try:
                with open(config_file, encoding="utf-8") as f:
                    config = json.load(f)
                    # Look for various model ID fields
                    model_id = config.get("_name_or_path") or config.get("model_name") or config.get("name")
                    if model_id and "/" in model_id:
                        return model_id, "local"
            except Exception:
                pass

        # Check model_index.json (Diffusers format)
        model_index = current_path / "model_index.json"
        if model_index.exists():
            try:
                with open(model_index, encoding="utf-8") as f:
                    config = json.load(f)
                    model_id = config.get("_name_or_path") or config.get("name")
                    if model_id and "/" in model_id:
                        return model_id, "local"
            except Exception:
                pass

        # Move up one directory
        if current_path.parent == current_path:
            break
        current_path = current_path.parent

    return None, None
