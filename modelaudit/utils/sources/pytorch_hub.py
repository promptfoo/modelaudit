import html as html_lib
import os
import posixpath
import re
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
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
_NON_ARTIFACT_SCANNERS = frozenset({"jinja2_template", "manifest", "metadata", "oci_layer", "text"})
_SCANNER_EXTENSION_KEYS = ("extensions", "content_routed_extensions", "scanner_only_extensions")
_HTML_CONTENT_TYPES = frozenset({"application/xhtml+xml", "text/html"})
_HTML_PREFIX_PATTERN = re.compile(rb"^\s*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)", re.IGNORECASE)
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
    from ...scanner_registry_metadata import get_scanner_registry_metadata

    metadata = get_scanner_registry_metadata()
    return {
        str(extension).lower()
        for scanner_id, scanner_info in metadata.items()
        if scanner_id not in _NON_ARTIFACT_SCANNERS
        for key in _SCANNER_EXTENSION_KEYS
        for extension in scanner_info.get(key, ())
        if extension
    }


def _content_sniff_required_extensions() -> set[str]:
    """Return ambiguous suffixes shared by artifact and non-artifact scanners."""
    from ...scanner_registry_metadata import get_scanner_registry_metadata

    metadata = get_scanner_registry_metadata()
    artifact_extensions: set[str] = set()
    non_artifact_extensions: set[str] = set()
    for scanner_id, scanner_info in metadata.items():
        target = non_artifact_extensions if scanner_id in _NON_ARTIFACT_SCANNERS else artifact_extensions
        for key in _SCANNER_EXTENSION_KEYS:
            target.update(str(extension).lower() for extension in scanner_info.get(key, ()) if extension)
    return artifact_extensions & non_artifact_extensions


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
            if _is_supported_model_url(url, model_extensions):
                parsed_url = urlsplit(url)
                url = parsed_url._replace(scheme="https", netloc="download.pytorch.org").geturl()
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
                    if response.ok and status_code == 200:
                        content_length = _response_content_length(response)
                        if content_length is not None:
                            total += content_length
                    break
                finally:
                    with suppress(Exception):
                        response.close()
            else:
                raise requests.TooManyRedirects(f"Too many PyTorch Hub artifact redirects: {_display_model_url(url)}")
        except Exception:
            continue
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


def _response_content_length(response: requests.Response) -> int | None:
    try:
        content_length = response.headers.get("content-length")
        parsed_length = int(content_length) if content_length is not None else None
        return parsed_length if parsed_length is not None and parsed_length >= 0 else None
    except (TypeError, ValueError):
        return None


def _validate_artifact_response_type(url: str, response: requests.Response) -> None:
    content_type = response.headers.get("content-type")
    if isinstance(content_type, str) and content_type.split(";", 1)[0].strip().casefold() in _HTML_CONTENT_TYPES:
        raise ValueError(f"PyTorch Hub artifact returned HTML content: {_display_model_url(url)}")


def _validate_downloaded_artifact(url: str, path: Path) -> None:
    """Reject obvious response pages and ambiguous non-model payloads."""
    with path.open("rb") as handle:
        prefix = handle.read(4096)
    if _HTML_PREFIX_PATTERN.match(prefix):
        raise ValueError(f"PyTorch Hub artifact returned HTML content: {_display_model_url(url)}")

    extension = _supported_model_extension(url)
    if extension not in _content_sniff_required_extensions():
        return

    from ..file.detection import detect_file_format_from_magic

    if detect_file_format_from_magic(str(path)) == "unknown":
        raise ValueError(
            "PyTorch Hub artifact with an ambiguous suffix did not contain recognizable model content: "
            f"{_display_model_url(url)}"
        )


def _path_entry_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _remove_path_entry(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _prepare_destination_parent(
    dest_dir: Path,
    relative_path: Path,
    created_dirs: list[Path] | None = None,
) -> Path:
    """Create a destination parent without accepting symlinked path components."""
    current_dir = dest_dir
    for part in relative_path.parent.parts:
        current_dir /= part
        try:
            current_dir.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            if created_dirs is not None:
                created_dirs.append(current_dir)
        if current_dir.is_symlink():
            raise ValueError(f"Unsafe PyTorch Hub cache path: {relative_path.as_posix()}")
        if not current_dir.is_dir():
            raise NotADirectoryError(f"PyTorch Hub cache parent is not a directory: {current_dir}")
    return _safe_destination_path(dest_dir, relative_path)


def _supports_secure_cache_commit() -> bool:
    return (
        os.name != "nt"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
        and os.rmdir in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
    )


def _open_cache_parent_fd(
    root_fd: int,
    relative_path: Path,
    fd_stack: ExitStack,
    created_dirs: list[tuple[int, str]],
) -> int:
    """Pin a cache parent directory without following replaceable symlinks."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = root_fd
    for part in relative_path.parent.parts:
        try:
            child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(part, mode=0o700, dir_fd=parent_fd)
                created_dirs.append((parent_fd, part))
            except FileExistsError:
                # Another process won the create race; the no-follow open below validates it.
                pass
            child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
        fd_stack.callback(os.close, child_fd)
        parent_fd = child_fd
    return parent_fd


def _path_entry_exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _remove_path_entry_at(parent_fd: int, name: str) -> None:
    with suppress(FileNotFoundError):
        os.unlink(name, dir_fd=parent_fd)


def _commit_staged_weight_files_secure(
    artifacts: list[tuple[str, Path]],
    files_dir: Path,
    backup_dir: Path,
    dest_dir: Path,
) -> None:
    """Commit staged files through pinned cache directories."""
    committed: list[tuple[int, str, Path, bool]] = []
    created_dirs: list[tuple[int, str]] = []
    with ExitStack() as fd_stack:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_fd = os.open(dest_dir, directory_flags)
        fd_stack.callback(os.close, root_fd)
        try:
            for _, relative_path in artifacts:
                staged_file = _safe_destination_path(files_dir, relative_path)
                backup_file = _safe_destination_path(backup_dir, relative_path)
                backup_file.parent.mkdir(parents=True, exist_ok=True)
                parent_fd = _open_cache_parent_fd(root_fd, relative_path, fd_stack, created_dirs)
                filename = relative_path.name
                try:
                    destination_stat = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    had_existing_entry = False
                else:
                    had_existing_entry = True
                    if stat.S_ISDIR(destination_stat.st_mode):
                        raise IsADirectoryError(
                            f"PyTorch Hub cache destination is a directory: {dest_dir / relative_path}"
                        )

                committed.append((parent_fd, filename, backup_file, had_existing_entry))
                if had_existing_entry:
                    os.rename(filename, backup_file, src_dir_fd=parent_fd)
                os.rename(staged_file, filename, dst_dir_fd=parent_fd)
        except BaseException as commit_error:
            rollback_errors: list[BaseException] = []
            for parent_fd, filename, backup_file, had_existing_entry in reversed(committed):
                try:
                    if had_existing_entry:
                        if _path_entry_exists(backup_file):
                            _remove_path_entry_at(parent_fd, filename)
                            os.rename(backup_file, filename, dst_dir_fd=parent_fd)
                    else:
                        _remove_path_entry_at(parent_fd, filename)
                except BaseException as rollback_error:  # pragma: no cover - catastrophic filesystem failure
                    rollback_errors.append(rollback_error)
            for parent_fd, name in reversed(created_dirs):
                with suppress(OSError):
                    os.rmdir(name, dir_fd=parent_fd)
            if rollback_errors:
                raise Exception("Failed to commit PyTorch Hub cache and restore its previous state") from commit_error
            raise


def _commit_staged_weight_files_path(
    artifacts: list[tuple[str, Path]],
    files_dir: Path,
    backup_dir: Path,
    dest_dir: Path,
) -> None:
    """Install all staged weights or restore the original cache entries."""
    committed: list[tuple[Path, Path, bool]] = []
    created_dirs: list[Path] = []
    try:
        for _, relative_path in artifacts:
            staged_file = _safe_destination_path(files_dir, relative_path)
            dest_file = _prepare_destination_parent(dest_dir, relative_path, created_dirs)
            backup_file = _safe_destination_path(backup_dir, relative_path)
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            had_existing_entry = _path_entry_exists(dest_file)
            if dest_file.is_dir() and not dest_file.is_symlink():
                raise IsADirectoryError(f"PyTorch Hub cache destination is a directory: {dest_file}")
            committed.append((dest_file, backup_file, had_existing_entry))
            if had_existing_entry:
                dest_file.replace(backup_file)
            staged_file.replace(dest_file)
    except BaseException as commit_error:
        rollback_errors: list[BaseException] = []
        for dest_file, backup_file, had_existing_entry in reversed(committed):
            try:
                if had_existing_entry:
                    if _path_entry_exists(backup_file):
                        _remove_path_entry(dest_file)
                        backup_file.replace(dest_file)
                else:
                    _remove_path_entry(dest_file)
            except BaseException as rollback_error:  # pragma: no cover - catastrophic filesystem failure
                rollback_errors.append(rollback_error)
        for created_dir in reversed(created_dirs):
            with suppress(OSError):
                created_dir.rmdir()
        if rollback_errors:
            raise Exception("Failed to commit PyTorch Hub cache and restore its previous state") from commit_error
        raise


def _commit_staged_weight_files(
    artifacts: list[tuple[str, Path]],
    files_dir: Path,
    backup_dir: Path,
    dest_dir: Path,
) -> None:
    if _supports_secure_cache_commit():
        _commit_staged_weight_files_secure(artifacts, files_dir, backup_dir, dest_dir)
    else:
        _commit_staged_weight_files_path(artifacts, files_dir, backup_dir, dest_dir)


def _download_weight_file(
    weight_url: str,
    dest_file: Path,
    downloaded_size: int,
    max_size: int | None,
) -> int:
    """Download one weight file atomically and return the cumulative byte count."""
    partial_file: Path | None = None
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _open_trusted_artifact_response(weight_url) as response:
            _validate_artifact_response_type(weight_url, response)
            content_length = _response_content_length(response)
            if content_length is not None:
                _enforce_max_size(downloaded_size + content_length, max_size)

            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{dest_file.name}.",
                suffix=".part",
                dir=dest_file.parent,
                delete=False,
            ) as handle:
                partial_file = Path(handle.name)
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        _enforce_max_size(downloaded_size + len(chunk), max_size)
                        handle.write(chunk)
                        downloaded_size += len(chunk)

            _validate_downloaded_artifact(weight_url, partial_file)

        partial_file.replace(dest_file)
        return downloaded_size
    finally:
        if partial_file is not None:
            with suppress(OSError):
                partial_file.unlink()


def download_pytorch_hub_model(
    url: str,
    cache_dir: Path | None = None,
    max_size: int | None = None,
) -> Path:
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
    dest_root = dest_dir.resolve()
    artifacts = _artifact_download_paths(weight_urls)
    for _, relative_path in artifacts:
        _safe_destination_path(dest_root, relative_path)

    try:
        total_size = _get_total_size(weight_urls)
        if total_size > 0:
            _enforce_max_size(total_size, max_size)
            has_space, message = check_disk_space(dest_root, total_size)
            if not has_space:
                raise Exception(f"Cannot download model from {url}: {message}")
    except BaseException:
        if cache_dir is None:
            shutil.rmtree(dest_root, ignore_errors=True)
        raise

    staging_dir: Path | None = None
    files_dir = dest_root
    backup_dir: Path | None = None
    if cache_dir is not None:
        try:
            staging_dir = Path(tempfile.mkdtemp(prefix=".modelaudit_pth_stage_", dir=dest_root)).resolve()
            files_dir = staging_dir / "files"
            backup_dir = staging_dir / "backups"
            files_dir.mkdir()
            backup_dir.mkdir()
        except BaseException:
            if staging_dir is not None:
                shutil.rmtree(staging_dir, ignore_errors=True)
            raise

    try:
        downloaded_size = 0
        for weight_url, relative_path in artifacts:
            try:
                downloaded_size = _download_weight_file(
                    weight_url,
                    _safe_destination_path(files_dir, relative_path),
                    downloaded_size,
                    max_size,
                )
            except ValueError:
                raise
            except Exception as error:
                raise Exception(
                    f"Failed to download weights from {_display_model_url(weight_url)}: {_redact_model_error(error)}"
                ) from error

        if staging_dir is not None and backup_dir is not None:
            _commit_staged_weight_files(artifacts, files_dir, backup_dir, dest_root)
    except BaseException:
        if cache_dir is None:
            shutil.rmtree(dest_root, ignore_errors=True)
        raise
    finally:
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)

    return dest_root


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
        artifacts = _artifact_download_paths(weight_urls)
        total_files = len(artifacts)
        downloaded_size = 0
        for i, (weight_url, relative_path) in enumerate(artifacts):
            is_last = i == total_files - 1
            dest_file = _safe_destination_path(temp_dir, relative_path)

            if show_progress:
                click.echo(f"⬇️  Downloading {relative_path.as_posix()}")

            try:
                downloaded_size = _download_weight_file(weight_url, dest_file, downloaded_size, max_size)
            except ValueError:
                raise
            except Exception as e:
                raise Exception(
                    f"Failed to download weights from {_display_model_url(weight_url)}: {_redact_model_error(e)}"
                ) from e

            yield (dest_file, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
