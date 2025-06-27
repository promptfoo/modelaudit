import re
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


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

    fs.get(url, str(download_path), recursive=True)
    return download_path
