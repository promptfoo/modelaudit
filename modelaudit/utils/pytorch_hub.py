import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import requests

from .disk_space import check_disk_space

_PYTORCH_HUB_PATTERN = r"^https?://pytorch\.org/hub/[\w\-_.]+/?$"


def is_pytorch_hub_url(url: str) -> bool:
    """Return True if the URL points to a PyTorch Hub model page."""
    return bool(re.match(_PYTORCH_HUB_PATTERN, url))


def _extract_weight_urls(html: str) -> list[str]:
    """Extract weight file URLs from a PyTorch Hub page."""
    pattern = r"https://download\.pytorch\.org/models/[\w\-_.]+(?:\.pt|\.pth(?:\.tar\.gz|\.zip)?)(?![\w.])"
    return re.findall(pattern, html)


def _get_total_size(urls: list[str]) -> int:
    total = 0
    for u in urls:
        try:
            resp = requests.head(u, timeout=10)
            if resp.ok and "content-length" in resp.headers:
                total += int(resp.headers["content-length"])
        except Exception:
            continue
    return total


def download_pytorch_hub_model(url: str, cache_dir: Optional[Path] = None) -> Path:
    """Download model weights referenced from a PyTorch Hub page."""
    if not is_pytorch_hub_url(url):
        raise ValueError(f"Not a PyTorch Hub URL: {url}")

    try:
        page = requests.get(url, timeout=10)
        page.raise_for_status()
    except Exception as e:  # pragma: no cover - network errors
        raise Exception(f"Failed to fetch PyTorch Hub page {url}: {e!s}") from e

    weight_urls = _extract_weight_urls(page.text)
    if not weight_urls:
        raise Exception(f"No model files found at {url}")

    dest_dir = cache_dir or Path(tempfile.mkdtemp(prefix="modelaudit_pth_"))
    dest_dir.mkdir(parents=True, exist_ok=True)

    total_size = _get_total_size(weight_urls)
    if total_size > 0:
        has_space, message = check_disk_space(dest_dir, total_size)
        if not has_space:
            if cache_dir is None:
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise Exception(f"Cannot download model from {url}: {message}")

    for weight_url in weight_urls:
        filename = weight_url.split("/")[-1]
        dest_file = dest_dir / filename
        try:
            with requests.get(weight_url, stream=True, timeout=30) as resp:
                resp.raise_for_status()
                with open(dest_file, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
        except Exception as e:
            if cache_dir is None:
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise Exception(f"Failed to download weights from {weight_url}: {e!s}") from e

    return dest_dir
