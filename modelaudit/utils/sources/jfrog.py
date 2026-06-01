"""Utilities for handling JFrog Artifactory downloads and folder operations."""

import contextlib
import ipaddress
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Collection
from pathlib import Path, PurePosixPath
from typing import Any, Literal, TypedDict
from urllib.parse import urlparse, urlunparse

import click
import requests

from ...config.constants import SCANNABLE_MODEL_EXTENSIONS

logger = logging.getLogger(__name__)

# Constants
MAX_RECURSION_DEPTH = 64  # Prevent runaway recursion in folder traversal
JFROG_DOWNLOAD_CHUNK_SIZE = 8192
_SENSITIVE_QUERY_PARAM_RE = re.compile(
    r"([?&][^=\s&]*(?:signature|credential|security-token|access-key|access_key|token|secret|api-key|api_key|apikey|sig)[^=\s&]*=)[^\s&#]+",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)


def redact_jfrog_url_for_display(url: str) -> str:
    """Remove credentials, query strings, and fragments from a JFrog URL for display."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "<jfrog URL redacted>"

    if not parsed.scheme:
        return url

    netloc = parsed.netloc
    if "@" in parsed.netloc:
        netloc = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            netloc = f"{netloc}:{port}"
        netloc = f"<credentials-redacted>@{netloc}"

    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


def redact_jfrog_error_for_display(message: object, source_url: str | None = None) -> str:
    """Remove JFrog URL credentials from exception text."""
    redacted = str(message)
    if source_url:
        redacted = redacted.replace(source_url, redact_jfrog_url_for_display(source_url))
    redacted = _URL_USERINFO_RE.sub(r"\1<credentials-redacted>@", redacted)
    return _SENSITIVE_QUERY_PARAM_RE.sub(r"\1<redacted>", redacted)


def _safe_download_path(download_dir: Path, relative_path: str) -> Path:
    """Build a safe local path for downloaded JFrog artifacts."""
    normalized = PurePosixPath(relative_path)

    if normalized.is_absolute() or any(part in {"", ".", ".."} for part in normalized.parts):
        raise ValueError(f"Unsafe JFrog artifact path: {relative_path}")

    local_file = (download_dir / Path(*normalized.parts)).resolve()
    download_root = download_dir.resolve()

    if local_file != download_root and download_root not in local_file.parents:
        raise ValueError(f"Unsafe JFrog artifact path: {relative_path}")

    return local_file


def _cleanup_failed_folder_download(
    download_dir: Path,
    *,
    owns_download_dir: bool,
    downloaded_files: list[Path],
    current_file_candidates: list[Path],
) -> None:
    """Remove partial folder-download artifacts after an abort."""
    if owns_download_dir:
        if download_dir.exists():
            shutil.rmtree(download_dir, ignore_errors=True)
        return

    cleanup_paths = {
        path
        for path in [*downloaded_files, *current_file_candidates]
        if path.is_relative_to(download_dir) or path == download_dir
    }

    for path in sorted(cleanup_paths, key=lambda value: len(value.parts), reverse=True):
        if path.exists() and path.is_file():
            try:
                path.unlink()
            except OSError:
                continue

    parent_dirs = sorted({path.parent for path in cleanup_paths}, key=lambda value: len(value.parts), reverse=True)
    for directory in parent_dirs:
        current = directory
        while current != download_dir:
            try:
                current.rmdir()
            except OSError:
                break
            current = current.parent


# TypedDict definitions for JFrog API responses
class JFrogFileInfo(TypedDict):
    """Type definition for JFrog file response."""

    type: Literal["file"]
    size: int
    size_known: bool
    path: str
    repo: str


class JFrogFolderInfo(TypedDict):
    """Type definition for JFrog folder response."""

    type: Literal["folder"]
    children: list[dict[str, Any]]
    path: str
    repo: str


def is_jfrog_url(url: str) -> bool:
    """Check if a URL points to a JFrog Artifactory file or folder."""
    parsed = urlparse(url)
    hostname = _normalize_hostname(parsed.hostname or "")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and _is_local_jfrog_host(hostname)):
        return False
    if "/artifactory/" not in parsed.path:
        return False
    return _is_jfrog_service_host(hostname) or hostname in _get_trusted_jfrog_hosts()


def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def _host_from_config_value(value: str) -> str:
    """Normalize a configured host or base URL value to a hostname."""
    candidate = value.strip()
    if not candidate:
        return ""

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return _normalize_hostname(parsed.hostname or candidate.split("/", 1)[0].split(":", 1)[0])


def _get_trusted_jfrog_hosts() -> set[str]:
    """Return explicitly allowlisted JFrog hosts.

    MODELAUDIT_JFROG_ALLOWED_HOSTS accepts a comma-separated list of hostnames
    or JFrog base URLs.
    This keeps automatic credential forwarding opt-in for self-hosted JFrog
    instances while rejecting arbitrary lookalike URLs.
    """
    raw_hosts = os.getenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "")
    return {host for host in (_host_from_config_value(value) for value in raw_hosts.split(",")) if host}


def _is_local_jfrog_host(hostname: str) -> bool:
    """Return True when a hostname is local-only development infrastructure."""
    if not hostname:
        return False

    if hostname == "localhost":
        return True

    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    return parsed_ip is not None and parsed_ip.is_loopback


def _is_jfrog_service_host(hostname: str) -> bool:
    return hostname == "jfrog.io" or hostname.endswith(".jfrog.io") or _is_local_jfrog_host(hostname)


def _is_trusted_jfrog_auth_target(url: str) -> bool:
    """Return True when credentials may be sent to this JFrog URL."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False

    hostname = _normalize_hostname(parsed.hostname or "")
    return bool(hostname and hostname in _get_trusted_jfrog_hosts())


def _build_jfrog_auth_headers(
    url: str,
    *,
    api_token: str | None,
    access_token: str | None,
) -> dict[str, str]:
    """Build JFrog auth headers only for explicitly trusted HTTPS hosts."""
    if not _is_trusted_jfrog_auth_target(url):
        if api_token or access_token or os.getenv("JFROG_API_TOKEN") or os.getenv("JFROG_ACCESS_TOKEN"):
            logger.warning(
                "Skipping JFrog credentials for untrusted or insecure URL %s",
                redact_jfrog_url_for_display(url),
            )
        return {}

    if api_token:
        return {"X-JFrog-Art-Api": api_token}

    if access_token:
        return {"Authorization": f"Bearer {access_token}"}

    env_api_token = os.getenv("JFROG_API_TOKEN")
    if env_api_token:
        return {"X-JFrog-Art-Api": env_api_token}

    env_access_token = os.getenv("JFROG_ACCESS_TOKEN")
    if env_access_token:
        return {"Authorization": f"Bearer {env_access_token}"}

    return {}


def _positive_limit(*limits: int | None) -> int | None:
    positive_limits = [limit for limit in limits if limit is not None and limit > 0]
    return min(positive_limits) if positive_limits else None


def _coerce_nonnegative_size(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def _listed_file_known_size(file_info: dict[str, Any]) -> int | None:
    if file_info.get("size_known") is False:
        return None
    return _coerce_nonnegative_size(file_info.get("size"))


def _require_size_within_limit(
    *,
    size: int | None,
    limit: int | None,
    display_url: str,
    description: str,
) -> None:
    if limit is None:
        return

    if size is None:
        return

    if size > limit:
        raise ValueError(
            f"JFrog {description} size ({format_size(size)}) exceeds maximum allowed size "
            f"({format_size(limit)}) for {display_url}"
        )


def _require_known_size_within_limit(
    *,
    size: int | None,
    limit: int | None,
    display_url: str,
    description: str,
) -> None:
    if limit is None:
        return

    if size is None:
        raise ValueError(
            f"Cannot verify JFrog {description} size for {display_url}; refusing to download with maximum "
            f"allowed size {format_size(limit)}"
        )

    _require_size_within_limit(size=size, limit=limit, display_url=display_url, description=description)


def _cleanup_failed_artifact_download(temp_dir: Path | None, partial_path: Path | None) -> None:
    if temp_dir is not None and temp_dir.exists():
        shutil.rmtree(temp_dir)
        return
    if partial_path is not None and partial_path.exists() and partial_path.is_file():
        with contextlib.suppress(OSError):
            partial_path.unlink()


def download_artifact(
    url: str,
    cache_dir: Path | None = None,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    max_size: int | None = None,
    *,
    _enforce_zero_max_size: bool = False,
) -> Path:
    """
    Download an artifact from JFrog Artifactory with proper authentication.

    Authentication methods (in order of precedence):
    1. API Token via X-JFrog-Art-Api header (recommended)
    2. Access Token via Authorization: Bearer header
    3. Environment variables: JFROG_API_TOKEN, JFROG_ACCESS_TOKEN
    4. .env file variables: JFROG_API_TOKEN, JFROG_ACCESS_TOKEN

    Args:
        url: JFrog Artifactory URL to download from
        cache_dir: Optional directory to cache the download
        api_token: JFrog API token (recommended)
        access_token: JFrog access token
        timeout: Request timeout in seconds
        max_size: Maximum bytes to download (None = unlimited)

    Returns:
        Path to the downloaded file

    Raises:
        ValueError: If URL is not a valid JFrog URL
        requests.HTTPError: If authentication fails or download fails
        Exception: For other download errors
    """
    display_url = redact_jfrog_url_for_display(url)
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {display_url}")
    max_download_size = (
        max_size if max_size is not None and (max_size > 0 or (_enforce_zero_max_size and max_size == 0)) else None
    )

    filename = os.path.basename(urlparse(url).path)
    temp_dir: Path | None = None
    if cache_dir is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_"))
        dest_path = temp_dir / filename
    else:
        dest_path = cache_dir / filename
        dest_path.parent.mkdir(parents=True, exist_ok=True)
    partial_path: Path | None = None

    headers = _build_jfrog_auth_headers(url, api_token=api_token, access_token=access_token)

    # If no authentication is provided, proceed without auth (for public repos)
    if not headers:
        message = "No JFrog authentication provided. Attempting anonymous access."
        try:
            ctx = click.get_current_context(silent=True)
            if ctx:
                click.echo(f"⚠️  {message}")
            else:
                logger.warning(message)
        except Exception:
            logger.warning(message)

    response: requests.Response | None = None
    try:
        # Use requests for proper authentication and error handling
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            stream=True,  # Stream for large files
        )

        # Raise an exception for HTTP error responses
        response.raise_for_status()

        content_length = None
        response_headers = getattr(response, "headers", {})
        if hasattr(response_headers, "get"):
            content_length = _coerce_nonnegative_size(response_headers.get("Content-Length"))
        _require_size_within_limit(
            size=content_length,
            limit=max_download_size,
            display_url=display_url,
            description="artifact",
        )

        # Download the file to a staging path so failed attempts never clobber caller-owned cache files.
        bytes_written = 0
        with tempfile.NamedTemporaryFile(
            prefix=f".{filename}.",
            suffix=".tmp",
            dir=dest_path.parent,
            delete=False,
        ) as f:
            partial_path = Path(f.name)
            for chunk in response.iter_content(chunk_size=JFROG_DOWNLOAD_CHUNK_SIZE):
                if chunk:  # Filter out keep-alive chunks
                    bytes_written += len(chunk)
                    _require_size_within_limit(
                        size=bytes_written,
                        limit=max_download_size,
                        display_url=display_url,
                        description="artifact",
                    )
                    f.write(chunk)

        partial_path.replace(dest_path)
        return dest_path

    except requests.exceptions.HTTPError as e:  # type: ignore[attr-defined]
        _cleanup_failed_artifact_download(temp_dir, partial_path)
        error_msg = redact_jfrog_error_for_display(e, url)
        if e.response.status_code == 401:
            raise Exception(
                f"Authentication failed for JFrog URL {display_url}. Please provide a valid API token or access token."
            ) from e
        if e.response.status_code == 403:
            raise Exception(f"Access denied for JFrog URL {display_url}. Please check your permissions.") from e
        if e.response.status_code == 404:
            raise Exception(f"Artifact not found at {display_url}") from e

        raise Exception(f"HTTP error {e.response.status_code} downloading from {display_url}: {error_msg}") from e
    except requests.exceptions.RequestException as e:  # type: ignore[attr-defined]
        _cleanup_failed_artifact_download(temp_dir, partial_path)
        error_msg = redact_jfrog_error_for_display(e, url)
        raise Exception(f"Network error downloading from {display_url}: {error_msg}") from e
    except Exception as e:
        _cleanup_failed_artifact_download(temp_dir, partial_path)
        error_msg = redact_jfrog_error_for_display(e, url)
        raise Exception(f"Failed to download artifact from {display_url}: {error_msg}") from e
    finally:
        if response is not None:
            response.close()


def get_jfrog_base_url(url: str) -> str:
    """Extract the base JFrog URL from an artifact URL."""
    parsed = urlparse(url)

    # Find the artifactory part in the path
    path_parts = parsed.path.split("/")
    try:
        artifactory_index = path_parts.index("artifactory")
        # Base URL includes scheme, netloc, and path up to artifactory
        base_path = "/".join(path_parts[: artifactory_index + 1])
        return f"{parsed.scheme}://{parsed.netloc}{base_path}"
    except ValueError as e:
        raise ValueError(f"Invalid JFrog Artifactory URL format: {redact_jfrog_url_for_display(url)}") from e


def get_storage_api_url(url: str) -> str:
    """Convert a JFrog artifact URL to its Storage API equivalent."""
    parsed = urlparse(url)
    path_parts = parsed.path.split("/")

    try:
        artifactory_index = path_parts.index("artifactory")
        # Keep 'artifactory' and append 'api/storage' after it
        api_parts = [*path_parts[: artifactory_index + 1], "api", "storage", *path_parts[artifactory_index + 1 :]]
        api_path = "/".join(api_parts)
        return f"{parsed.scheme}://{parsed.netloc}{api_path}"
    except (ValueError, IndexError) as e:
        raise ValueError(f"Invalid JFrog Artifactory URL format: {redact_jfrog_url_for_display(url)}") from e


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def filter_scannable_files(
    files: list[dict[str, Any]],
    scannable_extensions: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter files to only include scannable model types."""
    extensions = SCANNABLE_MODEL_EXTENSIONS if scannable_extensions is None else frozenset(scannable_extensions)
    scannable = []
    for file in files:
        file_path = file["path"]

        # Handle URLs safely on Windows by extracting URL path component
        if file_path.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            parsed_url = urlparse(file_path)
            # Use the URL path component for suffix detection
            path = Path(parsed_url.path)
        else:
            path = Path(file_path)

        suffixes = [s.lower() for s in path.suffixes]
        if not suffixes and "" in extensions:
            scannable.append(file)
            continue
        for i in range(1, len(suffixes) + 1):
            if "".join(suffixes[-i:]) in extensions:
                scannable.append(file)
                break
    return scannable


def detect_jfrog_target_type(
    url: str, api_token: str | None = None, access_token: str | None = None, timeout: int = 30
) -> JFrogFileInfo | JFrogFolderInfo:
    """Detect if a JFrog URL points to a file or folder using Storage API.

    Args:
        url: JFrog Artifactory URL
        api_token: JFrog API token
        access_token: JFrog access token
        timeout: Request timeout in seconds

    Returns:
        JFrogFileInfo for files or JFrogFolderInfo for folders

    Raises:
        ValueError: If URL is not a valid JFrog URL
        Exception: If API request fails
    """
    display_url = redact_jfrog_url_for_display(url)
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {display_url}")

    storage_api_url = get_storage_api_url(url)
    display_storage_api_url = redact_jfrog_url_for_display(storage_api_url)

    headers = _build_jfrog_auth_headers(storage_api_url, api_token=api_token, access_token=access_token)

    try:
        response = requests.get(storage_api_url, headers=headers, timeout=timeout)
        response.raise_for_status()

        data = response.json()

        # If it has children, it's a folder
        if "children" in data:
            return JFrogFolderInfo(
                type="folder",
                children=data["children"],
                path=data.get("path", ""),
                repo=data.get("repo", ""),
            )
        else:
            # It's a file
            file_size = _coerce_nonnegative_size(data.get("size"))
            return JFrogFileInfo(
                type="file",
                size=file_size or 0,
                size_known=file_size is not None,
                path=data.get("path", ""),
                repo=data.get("repo", ""),
            )

    except requests.exceptions.HTTPError as e:
        error_msg = redact_jfrog_error_for_display(e, url)
        if e.response.status_code == 404:
            raise Exception(f"JFrog artifact not found at {display_url}") from e
        elif e.response.status_code in {401, 403}:
            raise Exception(
                f"Authentication failed for JFrog URL {display_url}. Please provide valid credentials."
            ) from e
        else:
            raise Exception(
                f"HTTP error {e.response.status_code} accessing {display_storage_api_url}: {error_msg}"
            ) from e
    except requests.exceptions.RequestException as e:
        error_msg = redact_jfrog_error_for_display(e, url)
        raise Exception(f"Network error accessing {display_storage_api_url}: {error_msg}") from e


def list_jfrog_folder_contents(
    url: str,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    recursive: bool = True,
    selective: bool = True,
    fetch_sizes: bool = False,
    scannable_extensions: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    """Recursively list all files in a JFrog folder.

    Args:
        url: JFrog folder URL
        api_token: JFrog API token
        access_token: JFrog access token
        timeout: Request timeout in seconds
        recursive: Whether to traverse subfolders
        selective: Whether to filter only scannable model files
        fetch_sizes: Whether to fetch accurate file sizes (slower but more accurate progress)

    Returns:
        List of file dictionaries with keys: name, path, size, human_size

    Raises:
        ValueError: If URL is not a JFrog folder
        Exception: If API requests fail
    """
    target_info = detect_jfrog_target_type(url, api_token, access_token, timeout)

    if target_info["type"] != "folder":
        raise ValueError(f"URL is not a JFrog folder: {redact_jfrog_url_for_display(url)}")

    files = []
    base_url = url.rstrip("/")

    def _collect_files(folder_url: str, depth: int = 0) -> None:
        """Recursively collect files from folder.

        Raises on any API or network error so that callers never operate
        on a partial file listing.
        """
        if depth > MAX_RECURSION_DEPTH:
            display_folder_url = redact_jfrog_url_for_display(folder_url)
            raise Exception(
                f"Maximum recursion depth ({MAX_RECURSION_DEPTH}) exceeded listing {display_folder_url}. "
                "Aborting to avoid incomplete file listing."
            )

        folder_info = detect_jfrog_target_type(folder_url, api_token, access_token, timeout)

        if folder_info["type"] != "folder":
            display_folder_url = redact_jfrog_url_for_display(folder_url)
            raise Exception(
                f"Expected JFrog folder while listing {display_folder_url}, got {folder_info['type']}. "
                "Aborting to avoid incomplete file listing."
            )

        for child in folder_info["children"]:
            child_name = child["uri"].lstrip("/")
            child_url = f"{folder_url.rstrip('/')}/{child_name}"

            if child["folder"]:
                # It's a subfolder
                if recursive:
                    _collect_files(child_url, depth + 1)
            else:
                # It's a file
                parsed_size = _coerce_nonnegative_size(child.get("size"))
                size = parsed_size or 0
                size_known = parsed_size is not None

                # Optionally fetch accurate size if requested
                if fetch_sizes and (not size_known or size == 0):
                    try:
                        file_info = detect_jfrog_target_type(child_url, api_token, access_token, timeout)
                        if file_info["type"] == "file":
                            fetched_size = _coerce_nonnegative_size(file_info.get("size"))
                            if fetched_size is not None:
                                size = fetched_size
                            size_known = bool(file_info.get("size_known", fetched_size is not None))
                    except Exception as e:
                        logger.warning(
                            "Failed to fetch size for "
                            f"{redact_jfrog_url_for_display(child_url)}: {redact_jfrog_error_for_display(e)}"
                        )

                files.append(
                    {
                        "name": child_name,
                        "path": child_url,
                        "size": size,
                        "size_known": size_known,
                        "human_size": format_size(size) if size > 0 else "Unknown",
                    }
                )

    _collect_files(base_url)

    if selective:
        files = filter_scannable_files(files, scannable_extensions=scannable_extensions)

    return files


def download_jfrog_folder(
    url: str,
    cache_dir: Path | None = None,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    selective: bool = True,
    show_progress: bool = True,
    fetch_sizes: bool = False,
    scannable_extensions: Collection[str] | None = None,
    max_size: int | None = None,
    max_file_size: int | None = None,
    max_total_size: int | None = None,
) -> Path:
    """Download all files from a JFrog folder.

    Args:
        url: JFrog folder URL
        cache_dir: Directory to download files to
        api_token: JFrog API token
        access_token: JFrog access token
        timeout: Request timeout in seconds
        selective: Whether to filter only scannable model files
        show_progress: Whether to show download progress
        fetch_sizes: Whether to fetch accurate file sizes for progress reporting
        max_size: Maximum cumulative bytes to download (None or 0 = unlimited)
        max_file_size: Maximum bytes for any single selected file (None or 0 = unlimited)
        max_total_size: Maximum cumulative bytes to download (None or 0 = unlimited)

    Returns:
        Path to directory containing downloaded files

    Raises:
        ValueError: If URL is not a valid JFrog folder
        Exception: If downloads fail
    """
    display_url = redact_jfrog_url_for_display(url)
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {display_url}")

    total_limit = _positive_limit(max_size, max_total_size)
    per_file_limit = _positive_limit(max_file_size)

    # List all files in the folder
    list_kwargs: dict[str, Any] = {}
    if scannable_extensions is not None:
        list_kwargs["scannable_extensions"] = scannable_extensions
    files = list_jfrog_folder_contents(
        url,
        api_token,
        access_token,
        timeout,
        recursive=True,
        selective=selective,
        fetch_sizes=fetch_sizes or total_limit is not None or per_file_limit is not None,
        **list_kwargs,
    )

    if not files:
        raise ValueError("No scannable model files found in JFrog folder")

    declared_total_size = 0
    for file_info in files:
        file_url = str(file_info["path"])
        display_file_url = redact_jfrog_url_for_display(file_url)
        file_size = _listed_file_known_size(file_info)
        _require_known_size_within_limit(
            size=file_size,
            limit=per_file_limit,
            display_url=display_file_url,
            description="artifact",
        )
        _require_known_size_within_limit(
            size=file_size,
            limit=total_limit,
            display_url=display_file_url,
            description="selected artifact",
        )
        if file_size is not None:
            declared_total_size += file_size
        _require_size_within_limit(
            size=declared_total_size,
            limit=total_limit,
            display_url=display_url,
            description="folder selected-file total",
        )

    # Create download directory
    owns_download_dir = cache_dir is None
    if owns_download_dir:
        download_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_folder_"))
    else:
        assert cache_dir is not None
        download_dir = cache_dir
        download_dir.mkdir(parents=True, exist_ok=True)

    if show_progress:
        total_size = sum(_listed_file_known_size(f) or 0 for f in files)
        size_info = format_size(total_size) if total_size > 0 else "size unknown"
        click.echo(f"Found {len(files)} scannable files ({size_info}) in JFrog folder")

    # Download each file
    base_url_parsed = urlparse(url)
    base_path_parts = base_url_parsed.path.strip("/").split("/")

    try:
        artifactory_index = base_path_parts.index("artifactory")
        base_repo_path = "/".join(base_path_parts[artifactory_index + 1 :])
    except (ValueError, IndexError):
        base_repo_path = ""

    completed_downloads = 0
    downloaded_files: list[Path] = []
    actual_downloaded_size = 0
    backup_dir: Path | None = None
    backup_paths: dict[Path, Path] = {}
    protected_existing_paths: set[Path] = set()
    backup_restore_failed = False

    def _backup_existing_file(path: Path) -> None:
        nonlocal backup_dir
        if owns_download_dir or path in backup_paths or not path.exists() or not path.is_file():
            return
        protected_existing_paths.add(path)
        if backup_dir is None:
            backup_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_folder_backup_"))
        backup_path = backup_dir / f"{len(backup_paths)}.bak"
        shutil.copy2(path, backup_path)
        backup_paths[path] = backup_path

    def _restore_backups() -> None:
        nonlocal backup_restore_failed
        for original_path, backup_path in backup_paths.items():
            try:
                original_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_path, original_path)
            except OSError as exc:
                backup_restore_failed = True
                raise Exception(
                    f"Failed to restore original JFrog cache file {original_path} from backup {backup_path}: {exc}"
                ) from exc

    def _cleanup_backups() -> None:
        if not backup_restore_failed and backup_dir is not None and backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)

    try:
        for file_info in files:
            local_file: Path | None = None
            downloaded_file: Path | None = None
            try:
                if show_progress:
                    size_display = file_info["human_size"] if file_info["human_size"] != "Unknown" else "size unknown"
                    click.echo(f"Downloading {file_info['name']} ({size_display})")

                # Calculate relative path for local storage
                file_url_parsed = urlparse(file_info["path"])
                file_path_parts = file_url_parsed.path.strip("/").split("/")

                try:
                    file_artifactory_index = file_path_parts.index("artifactory")
                    file_repo_path = "/".join(file_path_parts[file_artifactory_index + 1 :])

                    if base_repo_path and file_repo_path.startswith(base_repo_path + "/"):
                        relative_path = file_repo_path[len(base_repo_path) + 1 :]
                    elif base_repo_path and file_repo_path == base_repo_path:
                        relative_path = Path(file_info["name"]).name
                    else:
                        relative_path = Path(file_info["name"]).name
                except (ValueError, IndexError):
                    relative_path = Path(file_info["name"]).name

                local_file = _safe_download_path(download_dir, relative_path)
                local_file.parent.mkdir(parents=True, exist_ok=True)
                expected_downloaded_file = local_file.parent / Path(file_url_parsed.path).name
                _backup_existing_file(local_file)
                if expected_downloaded_file != local_file:
                    _backup_existing_file(expected_downloaded_file)
                remaining_total_size = total_limit - actual_downloaded_size if total_limit is not None else None
                file_limits = [limit for limit in (per_file_limit, remaining_total_size) if limit is not None]
                file_download_limit = min(file_limits) if file_limits else None

                # Download the individual file
                downloaded_file = download_artifact(
                    file_info["path"],
                    cache_dir=local_file.parent,
                    api_token=api_token,
                    access_token=access_token,
                    timeout=timeout,
                    max_size=file_download_limit,
                    _enforce_zero_max_size=file_download_limit == 0,
                )

                # Move to correct location if needed
                if downloaded_file != local_file and downloaded_file.exists():
                    if local_file.exists():
                        local_file.unlink()
                    downloaded_file.rename(local_file)
                    downloaded_file = local_file
                if downloaded_file.exists():
                    actual_downloaded_size += downloaded_file.stat().st_size
                _require_size_within_limit(
                    size=actual_downloaded_size,
                    limit=total_limit,
                    display_url=display_url,
                    description="folder selected-file total",
                )
                completed_downloads += 1
                downloaded_files.append(downloaded_file)

            except Exception as e:
                redacted_error = redact_jfrog_error_for_display(e)
                error_msg = f"Failed to download {file_info['name']}: {redacted_error}"
                logger.warning(error_msg)
                if show_progress:
                    click.echo("❌ Aborting JFrog folder download to avoid scanning a partial dataset")
                current_file_candidates = [
                    path
                    for path in (local_file, downloaded_file)
                    if path is not None and path not in backup_paths and path not in protected_existing_paths
                ]
                _cleanup_failed_folder_download(
                    download_dir,
                    owns_download_dir=owns_download_dir,
                    downloaded_files=[
                        path
                        for path in downloaded_files
                        if path not in backup_paths and path not in protected_existing_paths
                    ],
                    current_file_candidates=current_file_candidates,
                )
                _restore_backups()
                raise Exception(
                    "JFrog folder download failed after "
                    f"{completed_downloads} of {len(files)} file(s) completed. {file_info['name']}: {redacted_error}"
                ) from e

        return download_dir
    finally:
        _cleanup_backups()
