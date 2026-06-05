"""Utilities for handling JFrog Artifactory downloads and folder operations."""

import contextlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import struct
import tempfile
from collections.abc import Collection, Mapping
from http.cookiejar import CookieJar
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Literal, TypedDict
from urllib.parse import ParseResult, unquote, urljoin, urlparse, urlunparse

import click
import requests

from ...config.constants import SCANNABLE_MODEL_EXTENSIONS

logger = logging.getLogger(__name__)

# Constants
MAX_RECURSION_DEPTH = 64  # Prevent runaway recursion in folder traversal
JFROG_DOWNLOAD_CHUNK_SIZE = 8192
_MAX_JFROG_PROBE_REDIRECTS = 5
_MAX_JFROG_CONTENT_PROBES = 256
_MAX_JFROG_REDIRECTS = 5
_MAX_JFROG_LISTING_ENTRIES = 100_000
_MAX_JFROG_LISTED_FOLDERS = 10_000
_JFROG_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_QUERY_PARAM_RE = re.compile(
    r"([?&][^=\s&]*(?:signature|credential|security-token|access-key|access_key|token|secret|api-key|api_key|apikey|sig)[^=\s&]*=)[^\s&#]+",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)
_JFROG_CONTENT_SNIFF_BYTES = 64 * 1024
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_BYTES = b"TFL3"
_JFROG_ZIP_STRUCTURE_ROUTED_SCANNER_IDS = frozenset(
    {"executorch", "keras_zip", "pytorch_zip", "skops", "torchserve_mar", "zip"}
)


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
    if not hostname or hostname != _get_requests_prepared_hostname(url):
        return False
    if parsed.scheme != "https" or _is_local_jfrog_host(hostname):
        return False
    if "/artifactory/" not in parsed.path:
        return False
    return _is_jfrog_service_host(hostname) or hostname in _get_trusted_jfrog_hosts()


def is_jfrog_url_like(url: str) -> bool:
    """Return True for JFrog-shaped URLs that need safe user-facing redaction."""
    parsed = urlparse(url)
    hostname = _normalize_hostname(parsed.hostname or "")
    if parsed.scheme not in {"http", "https"} or not hostname or "/artifactory/" not in parsed.path:
        return False
    return (
        _is_jfrog_service_host(hostname) or _is_local_jfrog_host(hostname) or hostname in _get_configured_jfrog_hosts()
    )


def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def _host_from_config_value(value: str) -> str:
    """Normalize a configured host or base URL value to a hostname."""
    candidate = value.strip()
    if not candidate:
        return ""

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return _normalize_hostname(parsed.hostname or candidate.split("/", 1)[0].split(":", 1)[0])


def _get_configured_jfrog_hosts() -> set[str]:
    """Return normalized explicitly configured JFrog hosts.

    MODELAUDIT_JFROG_ALLOWED_HOSTS accepts a comma-separated list of hostnames
    or JFrog base URLs.
    This keeps automatic credential forwarding opt-in for self-hosted JFrog
    instances while rejecting arbitrary lookalike URLs.
    """
    raw_hosts = os.getenv("MODELAUDIT_JFROG_ALLOWED_HOSTS", "")
    return {host for host in (_host_from_config_value(value) for value in raw_hosts.split(",")) if host}


def _get_trusted_jfrog_hosts() -> set[str]:
    """Return configured JFrog hosts that are safe credential targets."""
    return {host for host in _get_configured_jfrog_hosts() if not _is_local_jfrog_host(host)}


def _is_local_jfrog_host(hostname: str) -> bool:
    """Return True when a hostname is local-only development infrastructure."""
    if not hostname:
        return False

    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True

    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            parsed_ip = ipaddress.ip_address(socket.inet_aton(hostname))
        except OSError:
            parsed_ip = None

    if parsed_ip is None:
        return False
    if parsed_ip.is_loopback or parsed_ip.is_unspecified:
        return True
    mapped_ip = getattr(parsed_ip, "ipv4_mapped", None)
    return mapped_ip is not None and (mapped_ip.is_loopback or mapped_ip.is_unspecified)


def _is_jfrog_service_host(hostname: str) -> bool:
    return hostname == "jfrog.io" or hostname.endswith(".jfrog.io")


def _get_requests_prepared_hostname(url: str) -> str:
    """Return the hostname Requests will connect to after URL preparation."""
    try:
        prepared_url = requests.Request("GET", url).prepare().url
    except requests.exceptions.RequestException:
        return ""

    if not prepared_url:
        return ""

    return _normalize_hostname(urlparse(prepared_url).hostname or "")


def _normalized_url_port(parsed_url: ParseResult) -> int | None:
    port = parsed_url.port
    if port is not None:
        return port
    scheme = parsed_url.scheme.lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _get_jfrog_probe_origin(url: str) -> tuple[str, str, int | None] | None:
    """Return one unambiguous effective origin for a probe URL."""
    try:
        parsed = urlparse(url)
        prepared_url = requests.Request("GET", url).prepare().url
        if not prepared_url:
            return None
        prepared = urlparse(prepared_url)
        parsed_origin = (
            parsed.scheme.lower(),
            _normalize_hostname(parsed.hostname or ""),
            _normalized_url_port(parsed),
        )
        prepared_origin = (
            prepared.scheme.lower(),
            _normalize_hostname(prepared.hostname or ""),
            _normalized_url_port(prepared),
        )
    except (requests.exceptions.RequestException, ValueError):
        return None

    return parsed_origin if parsed_origin == prepared_origin and parsed_origin[1] else None


def _canonical_jfrog_path(url: str) -> tuple[tuple[str, str, int | None], PurePosixPath]:
    """Return an unambiguous origin and decoded path for a JFrog URL."""
    origin = _get_jfrog_probe_origin(url)
    try:
        prepared_url = requests.Request("GET", url).prepare().url
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(url)}") from exc
    if origin is None or not prepared_url:
        raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(url)}")

    decoded_path = urlparse(prepared_url).path
    for _ in range(3):
        if re.search(r"%(?:2f|5c)", decoded_path, re.IGNORECASE):
            raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(url)}")
        try:
            next_path = unquote(decoded_path, errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(url)}") from exc
        if next_path == decoded_path:
            break
        decoded_path = next_path
    else:
        raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(url)}")

    path = PurePosixPath(decoded_path)
    if "\x00" in decoded_path or "\\" in decoded_path or any(part in {".", ".."} for part in path.parts):
        raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(url)}")
    return origin, path


def _safe_jfrog_child_name(uri: object, folder_url: str) -> str:
    """Validate one Storage API child URI before following it."""
    if not isinstance(uri, str) or not uri:
        raise ValueError(f"Unsafe JFrog child path in {redact_jfrog_url_for_display(folder_url)}")
    parsed = urlparse(uri)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError(f"Unsafe JFrog child path in {redact_jfrog_url_for_display(folder_url)}")

    child_name = uri.lstrip("/")
    decoded_name = child_name
    for _ in range(3):
        if re.search(r"%(?:2f|5c)", decoded_name, re.IGNORECASE):
            raise ValueError(f"Unsafe JFrog child path in {redact_jfrog_url_for_display(folder_url)}")
        try:
            next_name = unquote(decoded_name, errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Unsafe JFrog child path in {redact_jfrog_url_for_display(folder_url)}") from exc
        if next_name == decoded_name:
            break
        decoded_name = next_name
    else:
        raise ValueError(f"Unsafe JFrog child path in {redact_jfrog_url_for_display(folder_url)}")

    parts = decoded_name.split("/")
    if not decoded_name or "\\" in decoded_name or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"Unsafe JFrog child path in {redact_jfrog_url_for_display(folder_url)}")
    return child_name


def _safe_jfrog_relative_path(base_url: str, artifact_url: str) -> str:
    """Return an artifact path only when it remains below the requested folder."""
    base_origin, base_path = _canonical_jfrog_path(base_url)
    artifact_origin, artifact_path = _canonical_jfrog_path(artifact_url)
    if artifact_origin != base_origin:
        raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(artifact_url)}")

    base_parts = base_path.parts
    artifact_parts = artifact_path.parts
    if len(artifact_parts) <= len(base_parts) or artifact_parts[: len(base_parts)] != base_parts:
        raise ValueError(f"Unsafe JFrog artifact path: {redact_jfrog_url_for_display(artifact_url)}")

    prepared_base_url = requests.Request("GET", base_url).prepare().url
    prepared_artifact_url = requests.Request("GET", artifact_url).prepare().url
    if prepared_base_url and prepared_artifact_url:
        raw_base_parts = PurePosixPath(urlparse(prepared_base_url).path).parts
        raw_artifact_parts = PurePosixPath(urlparse(prepared_artifact_url).path).parts
        if (
            len(raw_artifact_parts) > len(raw_base_parts)
            and raw_artifact_parts[: len(raw_base_parts)] == raw_base_parts
        ):
            return PurePosixPath(*raw_artifact_parts[len(raw_base_parts) :]).as_posix()
    return PurePosixPath(*artifact_parts[len(base_parts) :]).as_posix()


def _is_safe_jfrog_download_target(url: str) -> bool:
    """Return True for unambiguous, non-local HTTPS download targets."""
    origin = _get_jfrog_probe_origin(url)
    return origin is not None and origin[0] == "https" and not _is_local_jfrog_host(origin[1])


def _is_trusted_jfrog_auth_target(url: str) -> bool:
    """Return True when credentials may be sent to this JFrog URL."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False

    hostname = _normalize_hostname(parsed.hostname or "")
    prepared_hostname = _get_requests_prepared_hostname(url)
    return bool(
        hostname
        and not _is_local_jfrog_host(hostname)
        and hostname == prepared_hostname
        and hostname in _get_trusted_jfrog_hosts()
    )


def _is_trusted_jfrog_probe_auth_target(url: str) -> bool:
    """Return True when bounded probe credentials may be sent to this effective JFrog URL."""
    return _is_trusted_jfrog_auth_target(url)


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


def _get_with_jfrog_redirect_policy(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int,
    stream: bool = False,
) -> requests.Response:
    """GET a JFrog URL while isolating credentials from untrusted redirects."""
    current_url = url
    current_headers = headers
    current_is_trusted = _is_trusted_jfrog_auth_target(url)
    trusted_redirect_cookies = requests.cookies.RequestsCookieJar()
    untrusted_redirect_cookies = requests.cookies.RequestsCookieJar()
    for _redirect_count in range(_MAX_JFROG_REDIRECTS + 1):
        if not _is_safe_jfrog_download_target(current_url):
            raise requests.exceptions.RequestException(
                f"Refusing unsafe JFrog download target {redact_jfrog_url_for_display(current_url)}"
            )
        current_cookies = trusted_redirect_cookies if current_is_trusted else untrusted_redirect_cookies
        response = requests.get(
            current_url,
            headers=current_headers,
            cookies=current_cookies,
            timeout=timeout,
            stream=stream,
            allow_redirects=False,
        )
        if response.status_code not in _JFROG_REDIRECT_STATUS_CODES:
            return response

        location = response.headers.get("Location")
        response_cookies = getattr(response, "cookies", None)
        if isinstance(response_cookies, CookieJar):
            requests.cookies.merge_cookies(current_cookies, response_cookies)
        response.close()
        if not location:
            raise requests.exceptions.RequestException(
                f"JFrog redirect response missing Location header for {redact_jfrog_url_for_display(current_url)}"
            )

        current_url = urljoin(current_url, location)
        current_is_trusted = _is_trusted_jfrog_auth_target(current_url)
        current_headers = headers if current_is_trusted else {}

    raise requests.exceptions.TooManyRedirects(
        f"Exceeded {_MAX_JFROG_REDIRECTS} redirects for JFrog URL {redact_jfrog_url_for_display(url)}"
    )


def download_artifact(
    url: str,
    cache_dir: Path | None = None,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    max_size: int | None = None,
    *,
    _enforce_zero_max_size: bool = False,
    require_same_origin_redirects: bool = False,
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
        require_same_origin_redirects: Refuse redirects outside the original URL origin

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
        if require_same_origin_redirects:
            response, _ = _get_jfrog_response_with_redirect_policy(
                url,
                headers=headers,
                timeout=timeout,
            )
        else:
            response = _get_with_jfrog_redirect_policy(
                url,
                headers=headers,
                timeout=timeout,
                stream=True,
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
    except BaseException:
        _cleanup_failed_artifact_download(temp_dir, partial_path)
        raise
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
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    absolute_size = abs(size_bytes)
    for index, unit in enumerate(units):
        divisor = 1024**index
        if absolute_size < divisor * 1024:
            return f"{size_bytes / divisor:.1f} {unit}"
    return f"{size_bytes} B"


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


def _build_jfrog_probe_auth_headers(
    url: str,
    *,
    api_token: str | None,
    access_token: str | None,
) -> dict[str, str]:
    """Build JFrog auth headers for bounded probes only when Requests' effective host is trusted."""
    headers = _build_jfrog_auth_headers(url, api_token=api_token, access_token=access_token)
    if not headers or _is_trusted_jfrog_probe_auth_target(url):
        return headers
    logger.warning(
        "Skipping JFrog probe credentials for parser-confused or untrusted URL %s",
        redact_jfrog_url_for_display(url),
    )
    return {}


def _get_jfrog_response_with_redirect_policy(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int,
) -> tuple[requests.Response, str]:
    """GET a JFrog URL while refusing ambiguous or cross-origin redirects."""
    current_url = url
    original_origin = _get_jfrog_probe_origin(url)
    if original_origin is None:
        raise requests.exceptions.RequestException(
            f"Refusing parser-confused JFrog URL {redact_jfrog_url_for_display(url)}"
        )

    redirect_cookies = requests.cookies.RequestsCookieJar()
    for _redirect_count in range(_MAX_JFROG_PROBE_REDIRECTS + 1):
        response = requests.get(
            current_url,
            headers=headers,
            cookies=redirect_cookies,
            stream=True,
            timeout=timeout,
            allow_redirects=False,
        )
        if response.status_code not in _JFROG_REDIRECT_STATUS_CODES:
            return response, current_url

        location = response.headers.get("Location")
        response_cookies = getattr(response, "cookies", None)
        if isinstance(response_cookies, CookieJar):
            requests.cookies.merge_cookies(redirect_cookies, response_cookies)
        if not location:
            response.close()
            raise requests.exceptions.TooManyRedirects(
                "JFrog probe redirect from "
                f"{redact_jfrog_url_for_display(current_url)} did not include a Location header"
            )

        response.close()
        redirected_url = urljoin(current_url, location)
        if _get_jfrog_probe_origin(redirected_url) != original_origin:
            raise requests.exceptions.RequestException(
                "Refusing cross-origin JFrog redirect from "
                f"{redact_jfrog_url_for_display(current_url)} to {redact_jfrog_url_for_display(redirected_url)}"
            )
        current_url = redirected_url

    raise requests.exceptions.TooManyRedirects(
        f"Exceeded {_MAX_JFROG_PROBE_REDIRECTS} redirects for JFrog URL {redact_jfrog_url_for_display(url)}"
    )


def _looks_like_remote_safetensors(prefix: bytes, size_hint: int) -> bool:
    """Recognize enough SafeTensors framing to preserve a remote candidate."""
    if len(prefix) < 9:
        return False
    if 0 < size_hint <= 8:
        return False

    try:
        header_len = struct.unpack("<Q", prefix[:8])[0]
    except struct.error:
        return False

    if header_len <= 0:
        return False
    if prefix[8:9] != b"{":
        return False
    if size_hint > 0 and header_len > size_hint - 8:
        return False

    header = prefix[8 : 8 + header_len]
    if len(header) < header_len:
        return True

    try:
        return isinstance(json.loads(header.decode("utf-8")), dict)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _read_jfrog_content_prefix(
    file_url: str,
    *,
    headers: dict[str, str],
    timeout: int,
    max_bytes: int,
) -> tuple[bytes, str]:
    """Read a bounded JFrog artifact prefix or fail closed with a redacted error."""
    request_headers = {
        **headers,
        "Range": f"bytes=0-{max_bytes - 1}",
        "Accept-Encoding": "identity",
    }
    response: requests.Response | None = None
    try:
        response, probe_download_url = _get_jfrog_response_with_redirect_policy(
            file_url,
            headers=request_headers,
            timeout=timeout,
        )
        response.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=max_bytes):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        return b"".join(chunks)[:max_bytes], probe_download_url
    except Exception as exc:
        raise ValueError(
            "JFrog folder selective filtering incomplete: unable to inspect skipped artifact "
            f"{redact_jfrog_url_for_display(file_url)}: {redact_jfrog_error_for_display(exc, file_url)}"
        ) from exc
    finally:
        if response is not None:
            response.close()


def _detect_jfrog_mxnet_symbol_route(
    prefix: bytes,
    size_hint: int,
    file_url: str,
) -> str | None:
    """Return a bounded MXNet/XGBoost JSON route for a suffix-skipped JFrog artifact."""
    from modelaudit.utils.file.detection import MXNET_SYMBOL_SIGNATURE_READ_BYTES, _detect_mxnet_symbol_prefix_route

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    if not normalized_prefix.lstrip().startswith(b"{"):
        return None

    mxnet_route = _detect_mxnet_symbol_prefix_route(
        normalized_prefix,
        sample_is_prefix=(size_hint > len(prefix)) or (size_hint <= 0 and len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES),
        fail_closed_without_hint=True,
    )
    suffix = PurePosixPath(urlparse(file_url).path).suffix.lower()
    if mxnet_route != "mxnet" or (suffix != ".json" and size_hint > MXNET_SYMBOL_SIGNATURE_READ_BYTES):
        return mxnet_route

    from modelaudit.scanners.xgboost_scanner import XGBoostScanner

    with tempfile.TemporaryDirectory(prefix="modelaudit_jfrog_probe_") as probe_dir:
        probe_path = Path(probe_dir) / f"probe{suffix}"
        probe_path.write_bytes(prefix)
        xgboost_probe_bytes = None if suffix == ".json" else MXNET_SYMBOL_SIGNATURE_READ_BYTES
        if XGBoostScanner._is_xgboost_json(str(probe_path), max_bytes=xgboost_probe_bytes):
            return "xgboost"
        if XGBoostScanner._is_probable_mxnet_overlap_candidate(str(probe_path), max_bytes=xgboost_probe_bytes):
            return "xgboost"

    return mxnet_route


def _detect_jfrog_extensionless_xgboost_ubjson_route(file_url: str, prefix: bytes) -> str | None:
    """Preserve bounded XGBoost UBJSON routes only for extensionless artifacts."""
    if PurePosixPath(urlparse(file_url).path).suffix:
        return None

    from modelaudit.utils.file.detection import _detect_extensionless_xgboost_ubjson_route

    return _detect_extensionless_xgboost_ubjson_route(prefix)


def _detect_jfrog_jax_json_checkpoint_route(prefix: bytes, size_hint: int) -> str | None:
    from modelaudit.utils.file.detection import has_jax_json_checkpoint_structure

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    sample_is_prefix = (size_hint > len(prefix)) or (size_hint <= 0 and len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES)
    trimmed_prefix = normalized_prefix.lstrip()
    if not trimmed_prefix:
        return "jax_checkpoint" if sample_is_prefix else None
    if not trimmed_prefix.startswith(b"{"):
        return None

    try:
        payload = json.loads(prefix.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return "jax_checkpoint" if sample_is_prefix else None

    if has_jax_json_checkpoint_structure(payload):
        return "jax_checkpoint"
    return None


def _detect_jfrog_tensorflow_protobuf_route(prefix: bytes) -> str | None:
    """Classify bounded TensorFlow protobuf evidence using the local path-backed parser."""
    from modelaudit.utils.file.detection import (
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        _classify_bounded_tensorflow_protobuf,
    )

    with tempfile.TemporaryDirectory(prefix="modelaudit_jfrog_probe_") as probe_dir:
        probe_path = Path(probe_dir) / "probe.pb"
        probe_path.write_bytes(prefix)
        route = _classify_bounded_tensorflow_protobuf(probe_path, len(prefix))

    if route in {"tf_metagraph", "tf_savedmodel"}:
        return route
    if route == "oversized":
        return "tf_metagraph"
    if route in {"oversized_candidate", "inconclusive"}:
        return TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    return None


def _detect_jfrog_xml_model_route(prefix: bytes, size_hint: int) -> str | None:
    """Classify bounded XML model evidence using the local root-tag parser."""
    from modelaudit.utils.file.detection import _could_be_xml_prefix, _detect_xml_model_format

    if not _could_be_xml_prefix(prefix):
        return None

    route = _detect_xml_model_format(
        prefix,
        sample_is_prefix=size_hint <= 0 or size_hint > len(prefix) or len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES,
    )
    return None if route == "unknown" else route


def _detect_jfrog_flax_msgpack_route(prefix: bytes, size_hint: int) -> str | None:
    """Recognize Flax MessagePack roots using the bounded local structure probe."""
    from modelaudit.utils.file.detection import _probe_flax_msgpack_checkpoint_stream

    sample_is_prefix = size_hint <= 0 or size_hint > len(prefix) or len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES
    declared_size = max(size_hint, len(prefix) + (1 if sample_is_prefix else 0))
    route_state = _probe_flax_msgpack_checkpoint_stream(
        BytesIO(prefix),
        declared_size,
        sample_is_prefix=sample_is_prefix,
    )
    return "flax_msgpack" if route_state is not False else None


def _detect_jfrog_llamafile_route(prefix: bytes, size_hint: int) -> str | None:
    """Recognize llamafile executable evidence within the bounded remote prefix."""
    import zipfile

    from modelaudit.utils.file.detection import (
        EXECUTABLE_ZIP_POLYGLOT_FORMAT,
        LLAMAFILE_MARKER,
        LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
        _is_supported_llamafile_executable_header,
    )

    if not _is_supported_llamafile_executable_header(prefix[:4]):
        return None
    if LLAMAFILE_MARKER in prefix.lower():
        return "llamafile"
    if zipfile.is_zipfile(BytesIO(prefix)):
        return EXECUTABLE_ZIP_POLYGLOT_FORMAT
    if size_hint <= 0 or size_hint > len(prefix) or len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES:
        return LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT
    return None


def _detect_jfrog_content_route_format(
    file_info: dict[str, Any],
    *,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    max_probe_bytes: int = _JFROG_CONTENT_SNIFF_BYTES,
    probe_bytes_counter: list[int] | None = None,
) -> tuple[str | None, str]:
    """Return a content-routed model format for a JFrog file, if cheaply identifiable."""
    if max_probe_bytes <= 0:
        raise ValueError("JFrog folder selective filtering incomplete: content probe download budget exhausted")
    file_url = str(file_info["path"])
    headers = _build_jfrog_probe_auth_headers(file_url, api_token=api_token, access_token=access_token)
    prefix, probe_download_url = _read_jfrog_content_prefix(
        file_url,
        headers=headers,
        timeout=timeout,
        max_bytes=min(max_probe_bytes, _JFROG_CONTENT_SNIFF_BYTES),
    )
    if probe_bytes_counter is not None:
        probe_bytes_counter[0] += len(prefix)

    if not prefix:
        return None, probe_download_url

    try:
        size_hint = int(file_info.get("size", 0) or 0)
    except (TypeError, ValueError):
        size_hint = 0

    if _looks_like_remote_safetensors(prefix, size_hint):
        return "safetensors", probe_download_url

    from modelaudit.utils.file.detection import (
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        _could_start_proto0_or_1_pickle,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _is_executorch_binary_signature,
        _is_torch7_signature,
        _looks_like_coreml_model_proto_prefix,
        _looks_like_onnx_model_proto_stream,
        _looks_like_proto0_or_1_pickle,
        _looks_like_proto_message_prefix,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )

    if _is_cntk_signature(prefix):
        return "cntk", probe_download_url
    if _is_content_routed_lightgbm_signature(prefix):
        return "lightgbm", probe_download_url

    xgboost_ubjson_route = _detect_jfrog_extensionless_xgboost_ubjson_route(file_url, prefix)
    if xgboost_ubjson_route is not None:
        return xgboost_ubjson_route, probe_download_url
    mxnet_route = _detect_jfrog_mxnet_symbol_route(
        prefix,
        size_hint,
        file_url,
    )
    if mxnet_route is not None:
        return mxnet_route, probe_download_url
    jax_route = _detect_jfrog_jax_json_checkpoint_route(prefix, size_hint)
    if jax_route is not None:
        return jax_route, probe_download_url
    llamafile_route = _detect_jfrog_llamafile_route(prefix, size_hint)
    if llamafile_route is not None:
        return llamafile_route, probe_download_url
    if _is_executorch_binary_signature(prefix):
        return "executorch", probe_download_url

    detected_format = detect_format_from_magic_bytes(
        prefix[:4],
        prefix[:8],
        prefix[:16],
        max(size_hint, len(prefix), 1),
        None,
    )
    if (
        detected_format == "unknown"
        and prefix[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + len(_TFLITE_MAGIC_BYTES)] == _TFLITE_MAGIC_BYTES
    ):
        return "tflite", probe_download_url
    if (
        detected_format == "unknown"
        and _could_start_proto0_or_1_pickle(prefix)
        and _looks_like_proto0_or_1_pickle(
            prefix,
            sample_is_prefix=size_hint > len(prefix) or len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES,
        )
    ):
        return "pickle", probe_download_url
    if detected_format == "unknown" and _looks_like_uncompressed_tar_header(prefix):
        return "tar", probe_download_url
    if detected_format == "unknown" and _is_torch7_signature(prefix):
        return "torch7", probe_download_url
    if detected_format == "unknown":
        xml_route = _detect_jfrog_xml_model_route(prefix, size_hint)
        if xml_route is not None:
            return xml_route, probe_download_url
        sample_is_prefix = size_hint <= 0 or size_hint > len(prefix) or len(prefix) >= _JFROG_CONTENT_SNIFF_BYTES
        coreml_status = _looks_like_coreml_model_proto_prefix(prefix, sample_is_prefix=sample_is_prefix)
        if coreml_status is True:
            return "coreml", probe_download_url
        onnx_status = _looks_like_onnx_model_proto_stream(BytesIO(prefix), len(prefix))
        if onnx_status is True:
            return "onnx", probe_download_url
        tensorflow_route = _detect_jfrog_tensorflow_protobuf_route(prefix)
        if tensorflow_route is not None:
            return tensorflow_route, probe_download_url
        flax_route = _detect_jfrog_flax_msgpack_route(prefix, size_hint)
        if flax_route is not None:
            return flax_route, probe_download_url
        if sample_is_prefix and (
            coreml_status is None or onnx_status is None or _looks_like_proto_message_prefix(prefix)
        ):
            return PROTOBUF_MODEL_CANDIDATE_FORMAT, probe_download_url
    return (None if detected_format == "unknown" else detected_format), probe_download_url


def _scanner_ids_for_detected_jfrog_format(detected_format: str) -> set[str]:
    from modelaudit.scanner_registry_metadata import get_scanner_registry_metadata
    from modelaudit.utils.file.detection import (
        EXECUTABLE_ZIP_POLYGLOT_FORMAT,
        LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
        MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
        TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
        XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
        XML_MODEL_INCONCLUSIVE_FORMAT,
    )

    scanner_ids: set[str] = set()
    for scanner_id, scanner_info in get_scanner_registry_metadata().items():
        if detected_format == scanner_id or detected_format in scanner_info.get("header_formats", ()):
            scanner_ids.add(scanner_id)
    if detected_format in {"zip", EXECUTABLE_ZIP_POLYGLOT_FORMAT}:
        scanner_ids.update(_JFROG_ZIP_STRUCTURE_ROUTED_SCANNER_IDS)
    if detected_format in {"tar", "gzip", "bzip2", "xz"}:
        scanner_ids.add("nemo")
    if detected_format in {"gzip", "bzip2", "xz"}:
        scanner_ids.add("tar")
    if detected_format == LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.add("llamafile")
        scanner_ids.update(_JFROG_ZIP_STRUCTURE_ROUTED_SCANNER_IDS)
    if detected_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
        scanner_ids.update({"coreml", "onnx", "tf_metagraph", "tf_savedmodel"})
    if detected_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.update({"tf_metagraph", "tf_savedmodel"})
    if detected_format == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.update({"jax_checkpoint", "mxnet"})
    if detected_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT:
        scanner_ids.add("xgboost")
    if detected_format == XML_MODEL_INCONCLUSIVE_FORMAT:
        scanner_ids.update({"openvino", "pmml"})
    return scanner_ids


def _jfrog_detected_format_allowed(detected_format: str, scanner_selection: Mapping[str, Any] | None) -> bool:
    if not scanner_selection:
        return True

    from modelaudit.scanner_selection import SCANNER_SELECTION_CONFIG_KEY, policy_from_config

    policy = policy_from_config({SCANNER_SELECTION_CONFIG_KEY: scanner_selection})
    if not policy.active:
        return True

    scanner_ids = _scanner_ids_for_detected_jfrog_format(detected_format)
    return any(policy.allows(scanner_id) for scanner_id in scanner_ids)


def _filter_scannable_jfrog_files(
    files: list[dict[str, Any]],
    *,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    scannable_extensions: Collection[str] | None = None,
    scanner_selection: Mapping[str, Any] | None = None,
    max_probe_bytes_per_file: int | None = None,
    max_total_probe_bytes: int | None = None,
    probe_bytes_counter: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Select suffix-matching files plus bounded content-routed renamed model files."""
    scannable = filter_scannable_files(files, scannable_extensions=scannable_extensions)
    if scannable_extensions is not None and scanner_selection is None:
        return scannable

    scannable_paths = {str(file["path"]) for file in scannable}
    probe_count = 0
    if probe_bytes_counter is None:
        probe_bytes_counter = [0]
    for file_info in files:
        file_path = str(file_info["path"])
        if file_path in scannable_paths:
            continue
        probe_count += 1
        if probe_count > _MAX_JFROG_CONTENT_PROBES:
            raise ValueError(
                "JFrog folder selective filtering incomplete: skipped artifact content probe limit "
                f"({_MAX_JFROG_CONTENT_PROBES}) exceeded"
            )
        remaining_probe_bytes = (
            max_total_probe_bytes - probe_bytes_counter[0] if max_total_probe_bytes is not None else None
        )
        if remaining_probe_bytes is not None and remaining_probe_bytes <= 0:
            raise ValueError("JFrog folder selective filtering incomplete: content probe download budget exhausted")
        probe_limits = [
            limit
            for limit in (max_probe_bytes_per_file, remaining_probe_bytes, _JFROG_CONTENT_SNIFF_BYTES)
            if limit is not None
        ]
        max_probe_bytes = min(probe_limits)
        probe_bytes_before = probe_bytes_counter[0]
        detected_format, probe_download_url = _detect_jfrog_content_route_format(
            file_info,
            api_token=api_token,
            access_token=access_token,
            timeout=timeout,
            max_probe_bytes=max_probe_bytes,
            probe_bytes_counter=probe_bytes_counter,
        )
        if detected_format is None:
            probe_bytes_read = probe_bytes_counter[0] - probe_bytes_before
            if max_probe_bytes < _JFROG_CONTENT_SNIFF_BYTES and probe_bytes_read >= max_probe_bytes:
                raise ValueError(
                    "JFrog folder selective filtering incomplete: content probe was truncated by the download budget"
                )
            continue
        if not _jfrog_detected_format_allowed(detected_format, scanner_selection):
            continue
        routed_file_info = dict(file_info)
        routed_file_info["content_detected_format"] = detected_format
        routed_file_info["content_probe_download_url"] = probe_download_url
        scannable.append(routed_file_info)
        scannable_paths.add(file_path)

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
        response = _get_with_jfrog_redirect_policy(storage_api_url, headers=headers, timeout=timeout)
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
    visited_folders: set[tuple[tuple[str, str, int | None], PurePosixPath]] = set()
    listing_entry_count = 0

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

        nonlocal listing_entry_count
        folder_identity = _canonical_jfrog_path(folder_url)
        if folder_identity in visited_folders:
            return
        if len(visited_folders) >= _MAX_JFROG_LISTED_FOLDERS:
            raise Exception(
                f"JFrog folder listing exceeded the maximum of {_MAX_JFROG_LISTED_FOLDERS} folders. "
                "Aborting to avoid incomplete or resource-intensive traversal."
            )
        visited_folders.add(folder_identity)

        folder_info = detect_jfrog_target_type(folder_url, api_token, access_token, timeout)

        if folder_info["type"] != "folder":
            display_folder_url = redact_jfrog_url_for_display(folder_url)
            raise Exception(
                f"Expected JFrog folder while listing {display_folder_url}, got {folder_info['type']}. "
                "Aborting to avoid incomplete file listing."
            )

        for child in folder_info["children"]:
            listing_entry_count += 1
            if listing_entry_count > _MAX_JFROG_LISTING_ENTRIES:
                raise Exception(
                    f"JFrog folder listing exceeded the maximum of {_MAX_JFROG_LISTING_ENTRIES} entries. "
                    "Aborting to avoid incomplete or resource-intensive traversal."
                )
            child_name = _safe_jfrog_child_name(child.get("uri"), folder_url)
            child_url = f"{folder_url.rstrip('/')}/{child_name}"
            _safe_jfrog_relative_path(base_url, child_url)

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
    scanner_selection: Mapping[str, Any] | None = None,
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
        scanner_selection: Optional normalized scanner-selection policy for content-routed filtering

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
        selective=False,
        fetch_sizes=fetch_sizes or total_limit is not None or per_file_limit is not None,
        **list_kwargs,
    )
    for file_info in files:
        _safe_jfrog_relative_path(url, str(file_info["path"]))
    probe_bytes_counter = [0]
    if selective:
        files = _filter_scannable_jfrog_files(
            files,
            api_token=api_token,
            access_token=access_token,
            timeout=timeout,
            scannable_extensions=scannable_extensions,
            scanner_selection=scanner_selection,
            max_probe_bytes_per_file=per_file_limit,
            max_total_probe_bytes=total_limit,
            probe_bytes_counter=probe_bytes_counter,
        )

    if not files:
        raise ValueError("No scannable model files found in JFrog folder")

    declared_total_size = probe_bytes_counter[0]
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
    completed_downloads = 0
    downloaded_files: list[Path] = []
    actual_downloaded_size = probe_bytes_counter[0]
    backup_dir: Path | None = None
    backup_paths: dict[Path, Path] = {}
    protected_existing_paths: set[Path] = set()
    backup_restore_failed = False

    def _backup_existing_file(path: Path) -> None:
        nonlocal backup_dir
        path_exists = path.exists() or path.is_symlink()
        if owns_download_dir or path in backup_paths or not path_exists:
            return
        if path.is_dir() and not path.is_symlink():
            return
        if not path.is_file() and not path.is_symlink():
            raise ValueError(f"Unsupported JFrog cache entry type: {path}")
        protected_existing_paths.add(path)
        if backup_dir is None:
            backup_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_folder_backup_"))
        backup_path = backup_dir / f"{len(backup_paths)}.bak"
        shutil.copy2(path, backup_path, follow_symlinks=False)
        backup_paths[path] = backup_path

    def _restore_backups() -> None:
        nonlocal backup_restore_failed
        for original_path, backup_path in backup_paths.items():
            try:
                original_path.parent.mkdir(parents=True, exist_ok=True)
                if original_path.is_dir() and not original_path.is_symlink():
                    raise IsADirectoryError(f"Cannot restore JFrog cache entry over directory: {original_path}")
                if (original_path.is_symlink() or backup_path.is_symlink()) and (
                    original_path.exists() or original_path.is_symlink()
                ):
                    original_path.unlink()
                shutil.copy2(backup_path, original_path, follow_symlinks=False)
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
                relative_path = _safe_jfrog_relative_path(url, str(file_info["path"]))

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
                download_url = str(file_info["path"])
                content_was_probed = "content_probe_download_url" in file_info
                artifact_download_kwargs: dict[str, Any] = {}
                if file_download_limit is not None:
                    artifact_download_kwargs["max_size"] = file_download_limit
                    artifact_download_kwargs["_enforce_zero_max_size"] = file_download_limit == 0
                downloaded_file = download_artifact(
                    download_url,
                    cache_dir=local_file.parent,
                    api_token=api_token,
                    access_token=access_token,
                    timeout=timeout,
                    require_same_origin_redirects=content_was_probed,
                    **artifact_download_kwargs,
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

            except BaseException as e:
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
                if not isinstance(e, Exception):
                    raise
                raise Exception(
                    "JFrog folder download failed after "
                    f"{completed_downloads} of {len(files)} file(s) completed. {file_info['name']}: {redacted_error}"
                ) from e

        return download_dir
    finally:
        _cleanup_backups()
