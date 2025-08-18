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
        # Get model info
        model_info = api.model_info(repo_id)

        # Calculate total size
        total_size = 0
        files = []
        siblings = model_info.siblings or []
        for sibling in siblings:
            if sibling.rfilename not in [".gitattributes", "README.md"]:
                total_size += sibling.size or 0
                files.append({"name": sibling.rfilename, "size": sibling.size or 0})

        return {
            "repo_id": repo_id,
            "total_size": total_size,
            "file_count": len(files),
            "files": files,
            "model_id": getattr(model_info, "modelId", repo_id),
            "author": model_info.author,
        }
    except Exception as e:
        raise Exception(f"Failed to get model info for {url}: {e!s}") from e


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


def download_model(url: str, cache_dir: Optional[Path] = None, show_progress: bool = True) -> Path:
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

    # Use a cache directory structure if cache_dir is provided
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
    else:
        # Use temporary directory if no cache specified
        temp_dir = tempfile.mkdtemp(prefix="modelaudit_hf_")
        download_path = Path(temp_dir)

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
        try:
            repo_files = list_repo_files(repo_id)
        except Exception:
            repo_files = []

        # Define model file extensions we're interested in
        MODEL_EXTENSIONS = {
            ".bin",
            ".pt",
            ".pth",
            ".pkl",
            ".safetensors",
            ".onnx",
            ".pb",
            ".h5",
            ".keras",
            ".tflite",
            ".ckpt",
            ".pdparams",
            ".joblib",
            ".dill",
        }

        # Find model files in the repository
        model_files = [f for f in repo_files if any(f.endswith(ext) for ext in MODEL_EXTENSIONS)]

        # If we found specific model files, download them
        if model_files:
            # Download only the model files (not docs, etc.)
            local_path = snapshot_download(
                repo_id=repo_id,
                cache_dir=str(download_path),
                local_dir=str(download_path),
                allow_patterns=model_files,  # Explicitly request model files
                tqdm_class=None,  # Use default tqdm
            )
        else:
            # Fallback: download everything if no model files identified
            # This handles edge cases where models might have unusual extensions
            local_path = snapshot_download(
                repo_id=repo_id,
                cache_dir=str(download_path),
                local_dir=str(download_path),
                tqdm_class=None,  # Use default tqdm
            )

        # Verify we actually got model files
        downloaded_path = Path(local_path)
        found_models = any(downloaded_path.glob(f"*{ext}") for ext in MODEL_EXTENSIONS)

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
        # Clean up temp directory on failure if we created one
        if cache_dir is None and download_path.exists():
            import shutil

            shutil.rmtree(download_path)
        raise Exception(f"Failed to download model from {url}: {e!s}") from e
