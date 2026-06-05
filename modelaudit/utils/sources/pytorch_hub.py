import contextlib
import re
import shutil
import tempfile
import time
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path

import click
import requests

from ..helpers.disk_space import check_disk_space

_PYTORCH_HUB_PATTERN = r"^https?://pytorch\.org/hub/[\w\-_.]+/?$"
_MAX_PYTORCH_HUB_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_PYTORCH_HUB_SOURCE_LINKS = 5


class _GithubSourceLinkParser(HTMLParser):
    """Collect trusted Python source links labeled as the Hub source."""

    def __init__(self) -> None:
        super().__init__()
        self._href: str | None = None
        self._text: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        self._href = dict(attrs).get("href")
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._href is None:
            return
        if "view on github" in "".join(self._text).lower():
            self.links.append(self._href)
        self._href = None
        self._text = []


def is_pytorch_hub_url(url: str) -> bool:
    """Return True if the URL points to a PyTorch Hub model page."""
    return bool(re.match(_PYTORCH_HUB_PATTERN, url))


def _extract_weight_urls(html: str) -> list[str]:
    """Extract weight file URLs from a PyTorch Hub page."""
    pattern = r"https://download\.pytorch\.org/models/[\w\-_.]+(?:\.pt|\.pth(?:\.tar\.gz|\.zip)?)(?![\w.])"
    return list(dict.fromkeys(re.findall(pattern, html)))


def _extract_github_source_urls(html: str) -> list[str]:
    """Return bounded raw GitHub Python sources linked by a Hub page."""
    parser = _GithubSourceLinkParser()
    parser.feed(html)
    raw_urls: list[str] = []
    pattern = re.compile(
        r"^https://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/blob/"
        r"(?P<ref>[\w.-]+)/(?P<path>[\w./-]+\.py)$"
    )
    for link in parser.links:
        match = pattern.fullmatch(link)
        if match is None or ".." in Path(match.group("path")).parts:
            continue
        raw_url = (
            f"https://raw.githubusercontent.com/{match.group('owner')}/{match.group('repo')}/"
            f"{match.group('ref')}/{match.group('path')}"
        )
        if raw_url not in raw_urls:
            raw_urls.append(raw_url)
        if len(raw_urls) >= _MAX_PYTORCH_HUB_SOURCE_LINKS:
            break
    return raw_urls


def _remaining_request_timeout(deadline: float | None, default: float) -> float:
    if deadline is None:
        return default
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("PyTorch Hub streaming download timed out")
    return min(default, remaining)


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("PyTorch Hub streaming download timed out")


def _resolve_weight_urls(html: str, deadline: float | None = None) -> list[str]:
    """Resolve weight URLs directly or from the page's trusted source link."""
    weight_urls = _extract_weight_urls(html)
    if weight_urls:
        return weight_urls

    for source_url in _extract_github_source_urls(html):
        _check_deadline(deadline)
        source_resp: requests.Response | None = None
        try:
            source_resp = requests.get(
                source_url,
                stream=True,
                timeout=_remaining_request_timeout(deadline, 10),
            )
            source_resp.raise_for_status()
            source_bytes = bytearray()
            for chunk in source_resp.iter_content(chunk_size=64 * 1024):
                _check_deadline(deadline)
                if not chunk:
                    continue
                source_bytes.extend(chunk)
                if len(source_bytes) > _MAX_PYTORCH_HUB_SOURCE_BYTES:
                    source_bytes.clear()
                    break
            if not source_bytes:
                continue
            weight_urls.extend(_extract_weight_urls(source_bytes.decode("utf-8", errors="ignore")))
        except TimeoutError:
            raise
        except Exception:
            continue
        finally:
            if source_resp is not None:
                with contextlib.suppress(Exception):
                    source_resp.close()
    return list(dict.fromkeys(weight_urls))


def _get_total_size(urls: list[str], deadline: float | None = None) -> int:
    total = 0
    for u in urls:
        resp: requests.Response | None = None
        try:
            _check_deadline(deadline)
            resp = requests.head(
                u,
                timeout=_remaining_request_timeout(deadline, 10),
                allow_redirects=True,
            )
            if 200 <= resp.status_code < 300:
                content_length = _response_content_length(resp)
                if content_length is not None:
                    total += content_length
        except TimeoutError:
            raise
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


def _path_entry_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _remove_path_entry(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _commit_staged_weight_files(weight_urls: list[str], staging_dir: Path, dest_dir: Path) -> None:
    """Install all staged weights or restore the original cache entries."""
    backup_dir = staging_dir / ".backups"
    backup_dir.mkdir()
    committed: list[tuple[Path, Path, bool]] = []
    try:
        for weight_url in weight_urls:
            filename = weight_url.split("/")[-1]
            staged_file = staging_dir / filename
            dest_file = dest_dir / filename
            backup_file = backup_dir / filename
            had_existing_entry = _path_entry_exists(dest_file)
            if dest_file.is_dir() and not dest_file.is_symlink():
                raise IsADirectoryError(f"PyTorch Hub cache destination is a directory: {dest_file}")
            if had_existing_entry:
                dest_file.replace(backup_file)
            try:
                staged_file.replace(dest_file)
            except Exception:
                if had_existing_entry and _path_entry_exists(backup_file):
                    backup_file.replace(dest_file)
                raise
            committed.append((dest_file, backup_file, had_existing_entry))
    except Exception as commit_error:
        rollback_errors: list[Exception] = []
        for dest_file, backup_file, had_existing_entry in reversed(committed):
            try:
                _remove_path_entry(dest_file)
                if had_existing_entry:
                    backup_file.replace(dest_file)
            except Exception as rollback_error:  # pragma: no cover - catastrophic filesystem failure
                rollback_errors.append(rollback_error)
        if rollback_errors:
            raise Exception("Failed to commit PyTorch Hub cache and restore its previous state") from commit_error
        raise


def _download_weight_file(
    weight_url: str,
    dest_file: Path,
    downloaded_size: int,
    max_size: int | None,
    deadline: float | None = None,
) -> int:
    """Download one weight file atomically and return the cumulative byte count."""
    partial_file: Path | None = None
    try:
        _check_deadline(deadline)
        with requests.get(
            weight_url,
            stream=True,
            timeout=_remaining_request_timeout(deadline, 30),
        ) as resp:
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
                    _check_deadline(deadline)
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

    weight_urls = _resolve_weight_urls(page.text)
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
            _commit_staged_weight_files(weight_urls, staging_dir, dest_dir)
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
    timeout: int | None = None,
) -> Iterator[tuple[Path, bool]]:
    """
    Download model weights from PyTorch Hub one at a time (streaming mode).

    Yields (file_path, is_last) tuples for each downloaded weight file.

    Args:
        url: PyTorch Hub model page URL
        show_progress: Whether to show progress messages
        max_size: Maximum total download size in bytes
        timeout: Maximum total acquisition time in seconds

    Yields:
        Tuples of (file_path, is_last) for each weight file
    """
    if not is_pytorch_hub_url(url):
        raise ValueError(f"Not a PyTorch Hub URL: {url}")

    deadline = time.monotonic() + timeout if timeout is not None else None

    try:
        _check_deadline(deadline)
        page = requests.get(url, timeout=_remaining_request_timeout(deadline, 10))
        page.raise_for_status()
    except TimeoutError:
        raise
    except Exception as e:
        raise Exception(f"Failed to fetch PyTorch Hub page {url}: {e!s}") from e

    weight_urls = _resolve_weight_urls(page.text, deadline)
    if not weight_urls:
        raise Exception(f"No model files found at {url}")

    if show_progress:
        click.echo(f"Found {len(weight_urls)} model weight files")

    if max_size is not None and max_size > 0:
        total_size = _get_total_size(weight_urls, deadline)
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
                downloaded_size = _download_weight_file(
                    weight_url,
                    dest_file,
                    downloaded_size,
                    max_size,
                    deadline,
                )
            except (TimeoutError, ValueError):
                raise
            except Exception as e:
                raise Exception(f"Failed to download weights from {weight_url}: {e!s}") from e

            yield (dest_file, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
