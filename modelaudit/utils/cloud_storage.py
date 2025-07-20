import re
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .disk_space import check_disk_space


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


def get_cloud_object_size(fs, url: str) -> Optional[int]:
    """Get the size of a cloud storage object or directory.

    Args:
        fs: fsspec filesystem instance
        url: Cloud storage URL

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        # Check if it's a single file or directory
        info = fs.info(url)
        if "size" in info:
            return int(info["size"])

        # If it's a directory, sum up all file sizes
        total_size = 0
        for item in fs.ls(url, detail=True):
            if isinstance(item, dict) and "size" in item:
                total_size += int(item["size"])

        return total_size if total_size > 0 else None
    except Exception:
        # If we can't get the size, return None
        return None


def download_from_cloud(url: str, cache_dir: Optional[Path] = None) -> Path:
    """Download a file or directory from cloud storage to a local path."""
    try:
        import fsspec
    except ImportError as e:  # pragma: no cover - import guard
        raise ImportError(
            "fsspec package is required for cloud storage URL support. Install with 'pip install modelaudit[cloud]'"
        ) from e

    parsed = urlparse(url)
    scheme = parsed.scheme
    if scheme in {"http", "https"}:
        if parsed.netloc.endswith(".s3.amazonaws.com"):
            scheme = "s3"
        elif parsed.netloc == "storage.googleapis.com":
            scheme = "gs"
        elif parsed.netloc.endswith(".r2.cloudflarestorage.com"):
            scheme = "s3"
        else:
            raise ValueError(f"Unsupported cloud storage URL: {url}")
    elif scheme == "gcs":
        scheme = "gs"
    elif scheme not in {"s3", "gs", "r2"}:
        raise ValueError(f"Unsupported cloud storage URL: {url}")

    fs_protocol = "s3" if scheme in {"s3", "r2"} else "gcs"
    fs = fsspec.filesystem(fs_protocol)

    if cache_dir is None:
        download_path = Path(tempfile.mkdtemp(prefix="modelaudit_cloud_"))
    else:
        download_path = Path(cache_dir)
        download_path.mkdir(parents=True, exist_ok=True)

    # Check available disk space before downloading
    object_size = get_cloud_object_size(fs, url)
    if object_size:
        has_space, message = check_disk_space(download_path, object_size)
        if not has_space:
            # Clean up temp directory if we created one
            if cache_dir is None and download_path.exists():
                import shutil

                shutil.rmtree(download_path)
            raise Exception(f"Cannot download from {url}: {message}")

    try:
        fs.get(url, str(download_path), recursive=True)
        return download_path
    except Exception:
        # Clean up temp directory on failure if we created one
        if cache_dir is None and download_path.exists():
            import shutil

            shutil.rmtree(download_path)
        raise
