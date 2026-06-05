import contextlib
import re
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import click
import requests

from ..helpers.disk_space import check_disk_space

_PYTORCH_HUB_PATTERN = r"^https?://pytorch\.org/hub/[\w\-_.]+/?$"


def is_pytorch_hub_url(url: str) -> bool:
    """Return True if the URL points to a PyTorch Hub model page."""
    return bool(re.match(_PYTORCH_HUB_PATTERN, url))


def _extract_weight_urls(html: str) -> list[str]:
    """Extract weight file URLs from a PyTorch Hub page."""
    pattern = r"https://download\.pytorch\.org/models/[\w\-_.]+(?:\.pt|\.pth(?:\.tar\.gz|\.zip)?)(?![\w.])"
    return list(dict.fromkeys(re.findall(pattern, html)))


def _get_total_size(urls: list[str]) -> int:
    total = 0
    for u in urls:
        resp: requests.Response | None = None
        try:
            resp = requests.head(u, timeout=10, allow_redirects=True)
            if 200 <= resp.status_code < 300:
                content_length = _response_content_length(resp)
                if content_length is not None:
                    total += content_length
        except Exception:
            continue
        finally:
            if resp is not None:
                with contextlib.suppress(Exception):
                    resp.close()
    return total


def _format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    absolute_size = abs(size_bytes)
    for index, unit in enumerate(units):
        divisor = 1024**index
        if absolute_size < divisor * 1024:
            return f"{size_bytes / divisor:.1f} {unit}"
    return f"{size_bytes} B"


def _enforce_max_size(size_bytes: int, max_size: int | None) -> None:
    if max_size is not None and max_size > 0 and size_bytes > max_size:
        raise ValueError(
            f"PyTorch Hub model size ({_format_size(size_bytes)}) "
            f"exceeds maximum allowed size ({_format_size(max_size)})"
        )


def _response_content_length(resp: requests.Response) -> int | None:
    try:
        content_length = resp.headers.get("content-length")
        parsed_length = int(content_length) if content_length is not None else None
        return parsed_length if parsed_length is not None and parsed_length >= 0 else None
    except (TypeError, ValueError):
        return None


def _remove_partial_file(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()


def _download_weight_file(weight_url: str, dest_file: Path, downloaded_size: int, max_size: int | None) -> int:
    """Download one weight file atomically and return the cumulative byte count."""
    partial_file: Path | None = None
    try:
        with requests.get(weight_url, stream=True, timeout=30) as resp:
            resp.raise_for_status()
            content_length = _response_content_length(resp)
            if content_length is not None:
                _enforce_max_size(downloaded_size + content_length, max_size)

            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{dest_file.name}.",
                suffix=".part",
                dir=dest_file.parent,
                delete=False,
            ) as f:
                partial_file = Path(f.name)
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        _enforce_max_size(downloaded_size + len(chunk), max_size)
                        f.write(chunk)
                        downloaded_size += len(chunk)

        partial_file.replace(dest_file)
        return downloaded_size
    finally:
        if partial_file is not None:
            _remove_partial_file(partial_file)


def download_pytorch_hub_model(url: str, cache_dir: Path | None = None, max_size: int | None = None) -> Path:
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

    try:
        total_size = _get_total_size(weight_urls)
        if total_size > 0:
            _enforce_max_size(total_size, max_size)
            has_space, message = check_disk_space(dest_dir, total_size)
            if not has_space:
                raise Exception(f"Cannot download model from {url}: {message}")
    except Exception:
        if cache_dir is None:
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise

    staging_dir: Path | None = None
    download_dir = dest_dir
    if cache_dir is not None:
        staging_dir = Path(tempfile.mkdtemp(prefix=".modelaudit_pth_stage_", dir=dest_dir))
        download_dir = staging_dir

    try:
        downloaded_size = 0
        for weight_url in weight_urls:
            filename = weight_url.split("/")[-1]
            staged_file = download_dir / filename
            try:
                downloaded_size = _download_weight_file(weight_url, staged_file, downloaded_size, max_size)
            except ValueError:
                raise
            except Exception as e:
                raise Exception(f"Failed to download weights from {weight_url}: {e!s}") from e

        if staging_dir is not None:
            for weight_url in weight_urls:
                filename = weight_url.split("/")[-1]
                (staging_dir / filename).replace(dest_dir / filename)
    except Exception:
        if cache_dir is None:
            shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    finally:
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)

    return dest_dir


def download_pytorch_hub_model_streaming(
    url: str,
    show_progress: bool = True,
    max_size: int | None = None,
) -> Iterator[tuple[Path, bool]]:
    """
    Download model weights from PyTorch Hub one at a time (streaming mode).

    Yields (file_path, is_last) tuples for each downloaded weight file.

    Args:
        url: PyTorch Hub model page URL
        show_progress: Whether to show progress messages
        max_size: Maximum total download size in bytes

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

    total_size = _get_total_size(weight_urls)
    if total_size > 0:
        _enforce_max_size(total_size, max_size)

    # Create temp directory for downloads
    temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_pth_stream_"))

    try:
        total_files = len(weight_urls)
        downloaded_size = 0
        for i, weight_url in enumerate(weight_urls):
            is_last = i == total_files - 1
            filename = weight_url.split("/")[-1]
            dest_file = temp_dir / filename

            if show_progress:
                click.echo(f"⬇️  Downloading {filename}")

            try:
                downloaded_size = _download_weight_file(weight_url, dest_file, downloaded_size, max_size)
            except ValueError:
                raise
            except Exception as e:
                raise Exception(f"Failed to download weights from {weight_url}: {e!s}") from e

            yield (dest_file, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
