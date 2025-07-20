"""Utilities for handling HuggingFace model downloads."""

import re
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .disk_space import check_disk_space


def is_huggingface_url(url: str) -> bool:
    """Check if a URL is a HuggingFace model URL."""
    patterns = [
        r"^https?://huggingface\.co/[\w\-\.]+(/[\w\-\.]+)?/?$",
        r"^https?://hf\.co/[\w\-\.]+(/[\w\-\.]+)?/?$",
        r"^hf://[\w\-\.]+(/[\w\-\.]+)?/?$",
    ]
    return any(re.match(pattern, url) for pattern in patterns)


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
        parts = url[5:].strip("/").split("/")
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

    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) == 1 and path_parts[0]:
        # Single component like "bert-base-uncased" - treat as model without namespace
        return path_parts[0], ""
    if len(path_parts) >= 2:
        return path_parts[0], path_parts[1]
    raise ValueError(f"Invalid HuggingFace URL format: {url}")


def get_model_size(repo_id: str) -> Optional[int]:
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


def download_model(url: str, cache_dir: Optional[Path] = None) -> Path:
    """Download a model from HuggingFace.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads

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

    # Use a temporary directory if no cache_dir provided
    if cache_dir is None:
        temp_dir = tempfile.mkdtemp(prefix="modelaudit_hf_")
        download_path = Path(temp_dir)
    else:
        download_path = cache_dir / namespace / repo_name

    # Check available disk space before downloading
    model_size = get_model_size(repo_id)
    if model_size:
        # Ensure the parent directory exists for disk space check
        download_path.mkdir(parents=True, exist_ok=True)

        has_space, message = check_disk_space(download_path, model_size)
        if not has_space:
            # Clean up temp directory if we created one
            if cache_dir is None and download_path.exists():
                import shutil

                shutil.rmtree(download_path)
            raise Exception(f"Cannot download model from {url}: {message}")

    try:
        # Download the model snapshot
        local_path = snapshot_download(
            repo_id=repo_id,
            cache_dir=str(download_path),
            local_dir=str(download_path),
            local_dir_use_symlinks=False,  # Copy files instead of symlinks
        )
        return Path(local_path)
    except Exception as e:
        # Clean up temp directory on failure if we created one
        if cache_dir is None and download_path.exists():
            import shutil

            shutil.rmtree(download_path)
        raise Exception(f"Failed to download model from {url}: {e!s}") from e
