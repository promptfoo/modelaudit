import posixpath
import re
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import click
import requests

from ..helpers.disk_space import check_disk_space

_PYTORCH_HUB_PATTERN = r"^https?://pytorch\.org/hub/[\w\-_.]+/?$"
_PYTORCH_MODEL_URL_PATTERN = r"https://download\.pytorch\.org/models/[^\s\"'<>\\)\]]+"


def _get_model_extensions() -> set[str]:
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _normalized_model_path(url: str) -> str | None:
    """Return a decoded path that remains within download.pytorch.org/models."""
    path = urlsplit(url).path
    decoded_path = unquote(path)
    while decoded_path != path:
        path = decoded_path
        decoded_path = unquote(path)

    if "\\" in path or "\x00" in path:
        return None
    normalized_path = posixpath.normpath(path)
    if not normalized_path.startswith("/models/"):
        return None
    return normalized_path


def _weight_relative_path(url: str) -> Path:
    """Return a safe local relative path for an extracted PyTorch Hub weight URL."""
    normalized_path = _normalized_model_path(url)
    if normalized_path is None:
        raise ValueError(f"Unsafe PyTorch Hub model URL: {url}")
    return Path(*PurePosixPath(normalized_path).relative_to("/models").parts)


def _artifact_download_paths(urls: list[str]) -> list[tuple[str, Path]]:
    """Preserve artifact subpaths and uniquify any remaining local collisions."""
    artifacts: list[tuple[str, Path]] = []
    used_paths: set[Path] = set()

    for url in urls:
        relative_path = _weight_relative_path(url)
        download_path = relative_path
        duplicate_index = 2
        while download_path in used_paths:
            download_path = Path(f"__modelaudit_duplicate_{duplicate_index}") / relative_path
            duplicate_index += 1

        used_paths.add(download_path)
        artifacts.append((url, download_path))

    return artifacts


def _safe_destination_path(dest_dir: Path, relative_path: Path) -> Path:
    """Return a contained local destination without following cache symlinks outside the root."""
    dest_file = dest_dir / relative_path
    if not dest_file.resolve().is_relative_to(dest_dir.resolve()):
        raise ValueError(f"Unsafe PyTorch Hub cache path: {relative_path.as_posix()}")
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    return dest_file


def is_pytorch_hub_url(url: str) -> bool:
    """Return True if the URL points to a PyTorch Hub model page."""
    return bool(re.match(_PYTORCH_HUB_PATTERN, url))


def _extract_weight_urls(html: str) -> list[str]:
    """Extract weight file URLs from a PyTorch Hub page."""
    model_extensions = {extension.lower() for extension in _get_model_extensions()}
    weight_urls: list[str] = []
    seen: set[str] = set()

    for raw_url in re.findall(_PYTORCH_MODEL_URL_PATTERN, html):
        url = raw_url.rstrip(".,;:")
        normalized_path = _normalized_model_path(url)
        if (
            normalized_path is not None
            and url not in seen
            and any(normalized_path.lower().endswith(extension) for extension in model_extensions)
        ):
            weight_urls.append(url)
            seen.add(url)

    return weight_urls


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


def download_pytorch_hub_model(url: str, cache_dir: Path | None = None) -> Path:
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

    for weight_url, relative_path in _artifact_download_paths(weight_urls):
        dest_file = _safe_destination_path(dest_dir, relative_path)
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


def download_pytorch_hub_model_streaming(url: str, show_progress: bool = True) -> Iterator[tuple[Path, bool]]:
    """
    Download model weights from PyTorch Hub one at a time (streaming mode).

    Yields (file_path, is_last) tuples for each downloaded weight file.

    Args:
        url: PyTorch Hub model page URL
        show_progress: Whether to show progress messages

    Yields:
        Tuples of (file_path, is_last) for each weight file
    """
    if not is_pytorch_hub_url(url):
        raise ValueError(f"Not a PyTorch Hub URL: {url}")

    try:
        page = requests.get(url, timeout=10)
        page.raise_for_status()
    except Exception as e:
        raise Exception(f"Failed to fetch PyTorch Hub page {url}: {e!s}") from e

    weight_urls = _extract_weight_urls(page.text)
    if not weight_urls:
        raise Exception(f"No model files found at {url}")

    if show_progress:
        click.echo(f"Found {len(weight_urls)} model weight files")

    # Create temp directory for downloads
    temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_pth_stream_"))

    try:
        total_files = len(weight_urls)
        for i, (weight_url, relative_path) in enumerate(_artifact_download_paths(weight_urls)):
            is_last = i == total_files - 1
            dest_file = _safe_destination_path(temp_dir, relative_path)

            if show_progress:
                click.echo(f"⬇️  Downloading {relative_path.as_posix()}")

            try:
                with requests.get(weight_url, stream=True, timeout=30) as resp:
                    resp.raise_for_status()
                    with open(dest_file, "wb") as f:
                        for chunk in resp.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
            except Exception as e:
                raise Exception(f"Failed to download weights from {weight_url}: {e!s}") from e

            yield (dest_file, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
