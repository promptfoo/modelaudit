import html as html_lib
import os
import posixpath
import re
import shutil
import tempfile
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

import click
import requests

from ..helpers.disk_space import check_disk_space

_PYTORCH_HUB_PATTERN = r"^https?://pytorch\.org/hub/[\w\-_.]+/?$"
_PYTORCH_MODEL_URL_PATTERN = re.compile(
    r"https://download\.pytorch\.org/models/[^\s\"'<>]+",
    re.IGNORECASE,
)
_MAX_MODEL_URL_DECODE_ROUNDS = 4
_MAX_ARTIFACT_REDIRECTS = 5
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_WINDOWS_INVALID_PATH_CHARS = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class _ModelURLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.candidates: list[tuple[str, bool, bool]] = []
        self._raw_text_depth = 0

    def _collect(self, value: str, *, prose: bool, entity_decoded: bool) -> None:
        self.candidates.extend(
            (match.group(0), prose, entity_decoded) for match in _PYTORCH_MODEL_URL_PATTERN.finditer(value)
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style"}:
            self._raw_text_depth += 1
        for _, value in attrs:
            if value is not None:
                stripped_value = value.strip()
                if _PYTORCH_MODEL_URL_PATTERN.fullmatch(stripped_value):
                    self.candidates.append((stripped_value, False, True))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() in {"script", "style"}:
            self._raw_text_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style"} and self._raw_text_depth:
            self._raw_text_depth -= 1

    def handle_data(self, data: str) -> None:
        self._collect(data, prose=True, entity_decoded=self._raw_text_depth == 0)

    def handle_comment(self, data: str) -> None:
        self._collect(data, prose=True, entity_decoded=False)


def _get_model_extensions() -> set[str]:
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _display_model_url(url: str) -> str:
    """Return an artifact URL without query credentials or fragments."""
    try:
        parsed_url = urlsplit(url)
    except ValueError:
        return "<PyTorch Hub artifact URL redacted>"
    return parsed_url._replace(query="", fragment="").geturl()


def _redact_model_error(message: object) -> str:
    """Remove query strings from artifact URLs embedded in an error."""
    return _PYTORCH_MODEL_URL_PATTERN.sub(lambda match: _display_model_url(match.group(0)), str(message))


def _normalized_model_path(url: str) -> str | None:
    """Return a decoded path that remains within download.pytorch.org/models."""
    try:
        parsed_url = urlsplit(url)
    except ValueError:
        return None
    if parsed_url.scheme.casefold() != "https" or parsed_url.netloc.casefold() != "download.pytorch.org":
        return None

    try:
        path = unquote(parsed_url.path, errors="strict")
    except UnicodeDecodeError:
        return None
    normalized_path: str | None = None
    for _ in range(_MAX_MODEL_URL_DECODE_ROUNDS):
        if "\\" in path or "\x00" in path:
            return None
        current_normalized_path = posixpath.normpath(path)
        if not current_normalized_path.startswith("/models/"):
            return None
        if normalized_path is None:
            normalized_path = current_normalized_path

        try:
            decoded_path = unquote(path, errors="strict")
        except UnicodeDecodeError:
            return None
        if decoded_path == path:
            return normalized_path
        path = decoded_path

    return None


def _safe_local_component(component: str) -> str:
    """Encode path characters that are unsafe or misleading on local filesystems."""
    trailing_start = len(component.rstrip(" ."))
    safe_chars: list[str] = []
    for index, char in enumerate(component):
        unsafe = (
            char in _WINDOWS_INVALID_PATH_CHARS
            or unicodedata.category(char) in {"Cc", "Cf"}
            or (index >= trailing_start and char in " .")
        )
        if unsafe:
            safe_chars.extend(f"%{byte:02X}" for byte in char.encode())
        else:
            safe_chars.append(char)

    safe_component = "".join(safe_chars)
    reserved_stem = component.split(".", 1)[0].rstrip(" .").upper()
    if reserved_stem in _WINDOWS_RESERVED_NAMES:
        safe_component = f"__modelaudit_{safe_component}"
    return safe_component


def _weight_relative_path(url: str) -> Path:
    """Return a safe local relative path for an extracted PyTorch Hub weight URL."""
    normalized_path = _normalized_model_path(url)
    if normalized_path is None:
        raise ValueError(f"Unsafe PyTorch Hub model URL: {_display_model_url(url)}")
    relative_parts = PurePosixPath(normalized_path).relative_to("/models").parts
    return Path(*(_safe_local_component(part) for part in relative_parts))


def _supported_model_extension(url: str, model_extensions: set[str] | None = None) -> str | None:
    """Return the longest registered suffix for a trusted model URL."""
    normalized_path = _normalized_model_path(url)
    if normalized_path is None:
        return None
    extensions = (
        model_extensions
        if model_extensions is not None
        else {extension.lower() for extension in _get_model_extensions()}
    )
    normalized_path = normalized_path.lower()
    return max(
        (extension.lower() for extension in extensions if extension and normalized_path.endswith(extension.lower())),
        key=len,
        default=None,
    )


def _is_supported_model_url(url: str, model_extensions: set[str] | None = None) -> bool:
    return _supported_model_extension(url, model_extensions) is not None


def _path_collision_key(path: Path) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _paths_conflict(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    shared_length = min(len(left), len(right))
    return left[:shared_length] == right[:shared_length]


def _trim_unmatched_closing_delimiters(url: str) -> str:
    unmatched = {
        ")": max(url.count(")") - url.count("("), 0),
        "]": max(url.count("]") - url.count("["), 0),
    }
    end = len(url)
    while end:
        closing = url[end - 1]
        if closing not in unmatched or unmatched[closing] == 0:
            break
        unmatched[closing] -= 1
        end -= 1
    return url[:end]


def _trim_prose_url(url: str) -> str:
    url = _trim_unmatched_closing_delimiters(url)
    if url.endswith((".", ",", ";", ":", "}")):
        url = _trim_unmatched_closing_delimiters(url[:-1])
    return url


def _model_url_candidates(html: str) -> list[tuple[str, bool, bool]]:
    parser = _ModelURLParser()
    parser.feed(html)
    parser.close()
    parsed_urls = {url if entity_decoded else html_lib.unescape(url) for url, _, entity_decoded in parser.candidates}
    # HTMLParser omits URLs inside malformed, unclosed attributes.
    parser.candidates.extend(
        (match.group(0), False, False)
        for match in _PYTORCH_MODEL_URL_PATTERN.finditer(html)
        if html_lib.unescape(match.group(0)) not in parsed_urls
    )
    return parser.candidates


def _artifact_download_paths(urls: list[str]) -> list[tuple[str, Path]]:
    """Preserve artifact subpaths and uniquify any remaining local collisions."""
    artifacts: list[tuple[str, Path]] = []
    used_paths: set[tuple[str, ...]] = set()

    for url in urls:
        relative_path = _weight_relative_path(url)
        download_path = relative_path
        duplicate_index = 2
        collision_key = _path_collision_key(download_path)
        while any(_paths_conflict(collision_key, used_path) for used_path in used_paths):
            download_path = Path(f"__modelaudit_duplicate_{duplicate_index}") / relative_path
            duplicate_index += 1
            collision_key = _path_collision_key(download_path)

        used_paths.add(collision_key)
        artifacts.append((url, download_path))

    return artifacts


def _safe_destination_path(dest_dir: Path, relative_path: Path) -> Path:
    """Return a contained local destination without resolving outside the root."""
    dest_file = dest_dir / relative_path
    if not dest_file.resolve().is_relative_to(dest_dir.resolve()):
        raise ValueError(f"Unsafe PyTorch Hub cache path: {relative_path.as_posix()}")
    return dest_file


def _supports_secure_dir_fd_open() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
    )


def _append_owned_fd(directory_fds: list[int], fd: int) -> None:
    try:
        directory_fds.append(fd)
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _open_binary_fd(fd: int) -> Iterator[BinaryIO]:
    try:
        handle = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        yield handle


def _artifact_format(
    url: str,
    model_extensions: set[str],
    extension_format_map: dict[str, str],
) -> str:
    extension = _supported_model_extension(url, model_extensions)
    if extension is None:
        raise ValueError(f"Unsafe PyTorch Hub model URL: {_display_model_url(url)}")
    return extension_format_map.get(extension, extension)


def _artifact_redirect_url(current_url: str, response: requests.Response) -> str:
    location = response.headers.get("location")
    if not isinstance(location, str) or not location:
        response.raise_for_status()
        raise ValueError(f"PyTorch Hub artifact redirect has no location: {_display_model_url(current_url)}")
    return urljoin(current_url, location)


@contextmanager
def _open_trusted_artifact_response(url: str) -> Iterator[requests.Response]:
    """Open an artifact while keeping every redirect inside the trusted model path."""
    from ...scanner_registry_metadata import get_extension_format_map

    model_extensions = {extension.lower() for extension in _get_model_extensions()}
    extension_format_map = get_extension_format_map()
    expected_format = _artifact_format(url, model_extensions, extension_format_map)

    current_url = url
    for _ in range(_MAX_ARTIFACT_REDIRECTS + 1):
        current_format = _artifact_format(current_url, model_extensions, extension_format_map)
        if current_format != expected_format:
            raise ValueError(
                "PyTorch Hub artifact redirect changed artifact format "
                f"from {expected_format} to {current_format}: {_display_model_url(current_url)}"
            )

        with requests.get(current_url, stream=True, timeout=30, allow_redirects=False) as response:
            status_code = response.status_code if isinstance(response.status_code, int) else 200
            if status_code not in _REDIRECT_STATUS_CODES:
                response.raise_for_status()
                if status_code != 200:
                    raise requests.HTTPError(
                        "Unexpected status code "
                        f"{status_code} for PyTorch Hub artifact: {_display_model_url(current_url)}",
                        response=response,
                    )
                yield response
                return

            current_url = _artifact_redirect_url(current_url, response)

    raise requests.TooManyRedirects(f"Too many PyTorch Hub artifact redirects: {_display_model_url(url)}")


@contextmanager
def _open_destination_file(dest_dir: Path, relative_path: Path) -> Iterator[BinaryIO]:
    """Open an artifact without following replaceable symlink path components."""
    dest_file = _safe_destination_path(dest_dir, relative_path)
    if not _supports_secure_dir_fd_open():
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file = _safe_destination_path(dest_dir, relative_path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(dest_file, flags, 0o600)
        with _open_binary_fd(fd) as handle:
            yield handle
        return

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    directory_fds: list[int] = []
    _append_owned_fd(directory_fds, os.open(dest_dir.resolve(), directory_flags))
    try:
        for part in relative_path.parent.parts:
            parent_fd = directory_fds[-1]
            try:
                child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            except FileNotFoundError:
                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=parent_fd)
                child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            _append_owned_fd(directory_fds, child_fd)

        fd = os.open(relative_path.name, file_flags, 0o600, dir_fd=directory_fds[-1])
        with _open_binary_fd(fd) as handle:
            yield handle
    finally:
        for directory_fd in reversed(directory_fds):
            with suppress(OSError):
                os.close(directory_fd)


def is_pytorch_hub_url(url: str) -> bool:
    """Return True if the URL points to a PyTorch Hub model page."""
    return bool(re.match(_PYTORCH_HUB_PATTERN, url, re.IGNORECASE))


def _extract_weight_urls(html: str) -> list[str]:
    """Extract weight file URLs from a PyTorch Hub page."""
    model_extensions = {extension.lower() for extension in _get_model_extensions()}
    weight_urls: list[str] = []
    seen: set[str] = set()

    for raw_url, prose, entity_decoded in _model_url_candidates(html):
        candidates = [raw_url]
        if prose:
            trimmed_url = _trim_prose_url(raw_url)
            if trimmed_url != raw_url:
                candidates.insert(0, trimmed_url)

        for candidate in candidates:
            decoded_candidate = candidate if entity_decoded else html_lib.unescape(candidate)
            url = urldefrag(decoded_candidate).url
            parsed_url = urlsplit(url)
            url = parsed_url._replace(scheme="https", netloc="download.pytorch.org").geturl()
            if _is_supported_model_url(url, model_extensions):
                if url not in seen:
                    weight_urls.append(url)
                    seen.add(url)
                break

    return weight_urls


def _get_total_size(urls: list[str]) -> int:
    from ...scanner_registry_metadata import get_extension_format_map

    model_extensions = {extension.lower() for extension in _get_model_extensions()}
    extension_format_map = get_extension_format_map()
    total = 0
    for url in urls:
        try:
            expected_format = _artifact_format(url, model_extensions, extension_format_map)
            current_url = url
            for _ in range(_MAX_ARTIFACT_REDIRECTS + 1):
                current_format = _artifact_format(current_url, model_extensions, extension_format_map)
                if current_format != expected_format:
                    raise ValueError(
                        "PyTorch Hub artifact redirect changed artifact format "
                        f"from {expected_format} to {current_format}: {_display_model_url(current_url)}"
                    )

                response = requests.head(current_url, timeout=10, allow_redirects=False)
                try:
                    status_code = response.status_code if isinstance(response.status_code, int) else 200
                    if status_code in _REDIRECT_STATUS_CODES:
                        current_url = _artifact_redirect_url(current_url, response)
                        continue
                    if response.ok and status_code == 200 and "content-length" in response.headers:
                        total += int(response.headers["content-length"])
                    break
                finally:
                    response.close()
            else:
                raise requests.TooManyRedirects(f"Too many PyTorch Hub artifact redirects: {_display_model_url(url)}")
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
        try:
            _safe_destination_path(dest_dir, relative_path)
            with (
                _open_trusted_artifact_response(weight_url) as resp,
                _open_destination_file(dest_dir, relative_path) as f,
            ):
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        except ValueError:
            if cache_dir is None:
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise
        except Exception as e:
            if cache_dir is None:
                shutil.rmtree(dest_dir, ignore_errors=True)
            raise Exception(
                f"Failed to download weights from {_display_model_url(weight_url)}: {_redact_model_error(e)}"
            ) from e

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
                with (
                    _open_trusted_artifact_response(weight_url) as resp,
                    _open_destination_file(temp_dir, relative_path) as f,
                ):
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            except Exception as e:
                raise Exception(
                    f"Failed to download weights from {_display_model_url(weight_url)}: {_redact_model_error(e)}"
                ) from e

            yield (dest_file, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
