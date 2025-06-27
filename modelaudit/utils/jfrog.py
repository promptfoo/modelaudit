"""Utilities for handling JFrog Artifactory downloads."""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from urllib.request import urlretrieve


def is_jfrog_url(url: str) -> bool:
    """Check if a URL points to a JFrog Artifactory file."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    return parsed.netloc.endswith(".jfrog.io") or "/artifactory/" in parsed.path


def download_artifact(url: str, cache_dir: Optional[Path] = None) -> Path:
    """Download an artifact from JFrog Artifactory."""
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {url}")

    filename = os.path.basename(urlparse(url).path)
    if cache_dir is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_"))
        dest_path = temp_dir / filename
    else:
        temp_dir = cache_dir
        dest_path = cache_dir / filename
        dest_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        urlretrieve(url, dest_path)
        return dest_path
    except Exception as e:
        if cache_dir is None and temp_dir.exists():
            shutil.rmtree(temp_dir)
        raise Exception(f"Failed to download artifact from {url}: {e!s}") from e
