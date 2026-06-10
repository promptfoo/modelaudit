import asyncio
import hashlib
import io
import json
import logging
import os
import re
import shutil
import struct
import tempfile
import unicodedata
import zipfile
from collections.abc import Callable, Collection, Coroutine, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar
from urllib.parse import unquote, unquote_plus, urlparse, urlsplit, urlunsplit

import click
from yaspin import yaspin

from modelaudit.config.constants import SCANNABLE_MODEL_EXTENSIONS
from modelaudit.scanner_selection import (
    SCANNER_SELECTION_CONFIG_KEY,
    ScannerSelectionPolicy,
    policy_from_config,
    scanner_ids_for_detected_format,
    scanner_ids_for_extension,
)
from modelaudit.utils.helpers.retry import retry_with_backoff

from ..helpers.disk_space import check_disk_space

logger = logging.getLogger(__name__)
_T = TypeVar("_T")
_CLOUD_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
_CLEARTEXT_CLOUD_ERROR = "Cleartext cloud storage URL is not supported"
_CACHE_ENTRY_NAMESPACE = ".entries-v2"

_QUERY_PARAM_RE = re.compile(r"(?P<prefix>[?&#;])(?P<key>[^=\s&#;]+)=(?P<value>[^\s&#;]*)")
_BARE_ASSIGNMENT_RE = re.compile(
    r"""(?<![0-9A-Za-z_%.-])(?P<key>[0-9A-Za-z_%.-]+)(?P<separator>\s*=\s*)(?![=])"""
    r"""(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|"[^"\r\n]*|'[^'\r\n]*|"""
    r"""(?:(?:bearer|basic|digest|negotiate|token|aws4-hmac-sha256)\s+)?[^\s&#;,)}\]]+)""",
    re.IGNORECASE,
)
_HEADER_KEY_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?P<key>[0-9A-Za-z_%.-]+)\s*:",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)
_URL_TEXT_CHARACTER = r'(?:[^\s"\'<>]|<redacted>|<credentials-redacted>)'
_URL_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z+._%-])"
    rf"(stream://[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+|[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+)",
    re.IGNORECASE,
)
_ESCAPED_URL_DELIMITER_RE = re.compile(
    r"\\(?P<delimiter>/|u002f|u003a|u003f|u003d|u0026|u0023|u003b|x2f|x3a|x3f|x3d|x26|x23|x3b)",
    re.IGNORECASE,
)
_PERCENT_ENCODED_URL_DELIMITER_RE = re.compile(
    r"%(?:25)*(?P<delimiter>3f|3d|26|23|3b)",
    re.IGNORECASE,
)
_PERCENT_ENCODED_URL_BOUNDARY_RE = re.compile(r"%(?:25)*(?:3f|23|3b)", re.IGNORECASE)
_PERCENT_ENCODED_URL_PREFIX_RE = re.compile(
    r"(?<![0-9A-Za-z+._%-])"
    r"(?P<scheme>[a-z][a-z0-9+.-]*)(?:%(?:25)*3a|:)(?:%(?:25)*2f|/)(?:%(?:25)*2f|/)",
    re.IGNORECASE,
)
_PERCENT_ENCODED_AUTHORITY_DELIMITER_RE = re.compile(
    r"%(?:25)*(?P<delimiter>3a|40|5b|5d)",
    re.IGNORECASE,
)
_PERCENT_ENCODED_SLASH_RE = re.compile(r"%(?:25)*2f", re.IGNORECASE)
_SAFE_DISPLAY_QUERY_KEYS = frozenset(
    {
        "campaign",
        "download",
        "lang",
        "language",
        "locale",
        "page",
        "section",
        "tokenizer",
        "visible",
    }
)
_MAX_QUERY_VALUE_DECODE_PASSES = 4
_SENSITIVE_ASSIGNMENT_KEY_TOKENS = frozenset(
    {
        "auth",
        "authorization",
        "credential",
        "credentials",
        "password",
        "passwd",
        "sas",
        "secret",
        "session",
        "sig",
        "signature",
        "token",
    }
)
_SENSITIVE_ASSIGNMENT_KEY_MARKERS = (
    "accesskey",
    "accesstoken",
    "apikey",
    "authkey",
    "authtoken",
    "clientsecret",
    "privatekey",
    "securitytoken",
)
_CLOUD_CONTENT_SNIFF_BYTES = 8 * 1024
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_BYTES = b"TFL3"
_MSGPACK_CONTAINER_MARKERS = frozenset((*range(0x80, 0x90), 0xDE, 0xDF))
_MAX_CLOUD_METADATA_ERROR_SAMPLES = 3
_MAX_CLOUD_METADATA_ERROR_DISPLAY_CHARS = 512
_MAX_CLOUD_DIRECTORY_ANALYSIS_OBJECTS = 10_000
_CLOUD_PROBE_SUFFIX_RE = re.compile(r"\.[0-9A-Za-z][0-9A-Za-z_-]{0,31}\Z")
_CLOUD_LOCAL_PATH_ESCAPE_CHARS = frozenset('<>:"/\\|?*%#')
_WINDOWS_RESERVED_LOCAL_PATH_NAMES = frozenset(
    {"con", "conin$", "conout$", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
    | {f"com{index}" for index in ("\u00b9", "\u00b2", "\u00b3")}
    | {f"lpt{index}" for index in ("\u00b9", "\u00b2", "\u00b3")}
)
_CLOUD_LOCAL_IDENTITY_HASH_CHARS = 16
_CLOUD_LOCAL_COMPONENT_MAX_BYTES = 240
_CLOUD_LOCAL_GENERATED_IDENTITY_RE = re.compile(
    rf"~[0-9a-f]{{{_CLOUD_LOCAL_IDENTITY_HASH_CHARS}}}(?:\.[0-9A-Za-z][0-9A-Za-z_-]{{0,31}})?\Z",
    re.IGNORECASE,
)
_AWS_REGION_HOST_PART = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d"
_AWS_S3_DNS_SUFFIX = (
    r"(?:amazonaws\.com(?:\.cn)?|amazonaws\.eu|c2s\.ic\.gov|sc2s\.sgov\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)"
)
_S3_PATH_STYLE_HTTPS_HOST_RE = re.compile(
    rf"^s3(?:[.-]{_AWS_REGION_HOST_PART}|\.dualstack\.{_AWS_REGION_HOST_PART})?\.{_AWS_S3_DNS_SUFFIX}$"
)
_S3_VIRTUAL_HOSTED_HTTPS_HOST_RE = re.compile(
    rf"^.+\.s3(?:[.-]{_AWS_REGION_HOST_PART}|\.dualstack\.{_AWS_REGION_HOST_PART})?\.{_AWS_S3_DNS_SUFFIX}$"
)
_S3_FIPS_PATH_STYLE_HTTPS_HOST_RE = re.compile(
    rf"^s3-fips(?:[.-]{_AWS_REGION_HOST_PART}|\.dualstack\.{_AWS_REGION_HOST_PART})\.{_AWS_S3_DNS_SUFFIX}$"
)
_S3_FIPS_VIRTUAL_HOSTED_HTTPS_HOST_RE = re.compile(
    rf"^.+\.s3-fips(?:[.-]{_AWS_REGION_HOST_PART}|\.dualstack\.{_AWS_REGION_HOST_PART})\.{_AWS_S3_DNS_SUFFIX}$"
)
_S3_ACCELERATE_VIRTUAL_HOSTED_HTTPS_HOST_RE = re.compile(r"^.+\.s3-accelerate(?:\.dualstack)?\.amazonaws\.com$")


class _CloudObjectMetadataSizeError(ValueError):
    """Raised when strict directory sizing finds an unmeasurable listed object."""


def _run_coroutine_sync(coro_factory: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
    """Run a coroutine from sync code without deadlocking an active event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())

    # A loop is already running in this thread. Running the coroutine in a worker
    # thread avoids blocking that loop while still giving synchronous call semantics.
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(lambda: asyncio.run(coro_factory())).result()


def _http_cloud_protocol(url: str) -> str | None:
    """Return the provider protocol for a recognized HTTP(S) cloud URL."""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"}:
            return None
        if scheme == "https":
            if parsed.username is not None or parsed.password is not None:
                return None
            if parsed.port not in {None, 443}:
                return None
        hostname = (parsed.hostname or "").casefold().rstrip(".")
    except ValueError:
        return None

    if _is_s3_https_host(hostname):
        return "s3"
    if _is_gcs_https_host(hostname):
        return "gcs"
    if _is_r2_https_host(hostname):
        return "s3"
    return None


def _is_s3_https_host(hostname: str) -> bool:
    return bool(
        _S3_PATH_STYLE_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_FIPS_PATH_STYLE_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_FIPS_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_ACCELERATE_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
    )


def _is_gcs_https_host(hostname: str) -> bool:
    return hostname in {"storage.googleapis.com", "storage.cloud.google.com"} or hostname.endswith(
        ".storage.googleapis.com"
    )


def _is_r2_https_host(hostname: str) -> bool:
    return hostname.endswith(".r2.cloudflarestorage.com")


def is_cleartext_cloud_url(url: str) -> bool:
    """Return True for HTTP URLs targeting a supported cloud provider."""
    try:
        parsed = urlparse(url)
        if parsed.scheme.casefold() != "http":
            return False
        hostname = (parsed.hostname or "").casefold().rstrip(".")
    except ValueError:
        return False

    return _is_s3_https_host(hostname) or _is_gcs_https_host(hostname) or _is_r2_https_host(hostname)


def is_cloud_url(url: str) -> bool:
    """Return True if the URL points to a supported cloud storage provider."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    scheme = parsed.scheme.casefold()
    if scheme in {"s3", "gs", "gcs", "r2"}:
        return bool(parsed.netloc or parsed.path)
    if scheme != "https" or _http_cloud_protocol(url) is None:
        return False
    if parsed.path.lstrip("/"):
        return True

    hostname = (parsed.hostname or "").casefold().rstrip(".")
    if (
        _S3_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_FIPS_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_ACCELERATE_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
    ):
        return True
    if hostname.endswith(".storage.googleapis.com"):
        return bool(hostname[: -len(".storage.googleapis.com")])
    if _is_r2_https_host(hostname):
        host_prefix = hostname[: -len(".r2.cloudflarestorage.com")]
        return "." in host_prefix
    return False


def is_stream_url(url: str) -> bool:
    """Return True for a stream source identifier, regardless of scheme casing."""
    return url[:9].casefold() == "stream://"


def redact_url_for_display(url: str) -> str:
    """Remove credentials, query strings, and fragments from a URL for display."""
    try:
        normalized_url = _normalize_percent_encoded_url_delimiters_for_display(
            normalize_escaped_url_delimiters_for_display(url)
        )
        normalized_url = _normalize_percent_encoded_url_authority_for_display(normalized_url)
        parts = urlsplit(normalized_url)
        if not parts.scheme:
            return url

        hostname = parts.hostname or ""
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"

        safe_path = _strip_url_path_assignments_for_display(parts.path)
        return urlunsplit((parts.scheme, netloc, safe_path, "", ""))
    except Exception:
        return "<cloud URL redacted>"


def redact_cloud_error_for_display(message: object, source_url: str | None = None) -> str:
    """Remove signed URL credentials from provider exception text."""
    redacted = _normalize_percent_encoded_url_delimiters_for_display(
        normalize_escaped_url_delimiters_for_display(str(message))
    )
    if source_url:
        normalized_source_url = normalize_escaped_url_delimiters_for_display(source_url)
        redacted = redacted.replace(normalized_source_url, redact_url_for_display(normalized_source_url))
    redacted = _URL_TOKEN_RE.sub(lambda match: _redact_embedded_url_for_display(match.group(0)), redacted)
    redacted = _URL_USERINFO_RE.sub(r"\1<credentials-redacted>@", redacted)
    redacted = _BARE_ASSIGNMENT_RE.sub(_redact_bare_sensitive_assignment, redacted)
    redacted = _QUERY_PARAM_RE.sub(_redact_sensitive_query_param, redacted)
    return _redact_sensitive_header_assignments(redacted)


def normalize_escaped_url_delimiters_for_display(value: str) -> str:
    """Expose backslash-escaped URL structure so reporting redactors can inspect it."""
    replacements = {
        "/": "/",
        "u002f": "/",
        "u003a": ":",
        "u003f": "?",
        "u003d": "=",
        "u0026": "&",
        "u0023": "#",
        "u003b": ";",
        "x2f": "/",
        "x3a": ":",
        "x3f": "?",
        "x3d": "=",
        "x26": "&",
        "x23": "#",
        "x3b": ";",
    }
    normalized = _ESCAPED_URL_DELIMITER_RE.sub(
        lambda match: replacements[match.group("delimiter").lower()],
        value,
    )
    return _PERCENT_ENCODED_URL_PREFIX_RE.sub(lambda match: f"{match.group('scheme')}://", normalized)


def _normalize_percent_encoded_url_delimiters_for_display(url: str) -> str:
    """Expose encoded query structure without decoding ordinary path escapes."""
    percent_replacements = {
        "3f": "?",
        "3d": "=",
        "26": "&",
        "23": "#",
        "3b": ";",
    }

    def normalize_token(match: re.Match[str]) -> str:
        token = match.group(0)
        for boundary in _PERCENT_ENCODED_URL_BOUNDARY_RE.finditer(token):
            decoded_suffix = _PERCENT_ENCODED_URL_DELIMITER_RE.sub(
                lambda delimiter_match: percent_replacements[delimiter_match.group("delimiter").lower()],
                token[boundary.start() :],
            )
            next_major_boundary = len(decoded_suffix)
            for delimiter in "?#":
                delimiter_index = decoded_suffix.find(delimiter, 1)
                if delimiter_index >= 0:
                    next_major_boundary = min(next_major_boundary, delimiter_index)
            if _QUERY_PARAM_RE.search(decoded_suffix[:next_major_boundary]):
                return f"{token[: boundary.start()]}{decoded_suffix}"
        return token

    return re.sub(r"""[^\s"'<>]+""", normalize_token, url)


def _normalize_percent_encoded_url_authority_for_display(url: str) -> str:
    """Expose encoded authority separators without decoding ordinary path escapes."""
    scheme_end = url.find("://")
    if scheme_end < 0:
        return url

    authority_start = scheme_end + 3
    authority_end = len(url)
    for delimiter in "/?#":
        delimiter_index = url.find(delimiter, authority_start)
        if delimiter_index >= 0:
            authority_end = min(authority_end, delimiter_index)

    authority = url[authority_start:authority_end]
    replacements = {"3a": ":", "40": "@", "5b": "[", "5d": "]"}
    normalized_authority = _PERCENT_ENCODED_AUTHORITY_DELIMITER_RE.sub(
        lambda match: replacements[match.group("delimiter").lower()],
        authority,
    )
    if "@" in normalized_authority:
        userinfo, host_and_path = normalized_authority.rsplit("@", 1)
        normalized_authority = f"{userinfo}@{_PERCENT_ENCODED_SLASH_RE.sub('/', host_and_path)}"
    else:
        normalized_authority = _PERCENT_ENCODED_SLASH_RE.sub("/", normalized_authority)
    return f"{url[:authority_start]}{normalized_authority}{url[authority_end:]}"


def _redact_embedded_url_for_display(url: str) -> str:
    if is_stream_url(url):
        return f"stream://{redact_stream_url_for_display(url[9:])}"
    url = _normalize_percent_encoded_url_delimiters_for_display(url)
    url = _normalize_percent_encoded_url_authority_for_display(url)
    try:
        parts = urlsplit(url)
        safe_base = redact_url_for_display(url)
        if safe_base == "<cloud URL redacted>":
            return safe_base
        safe_parts = urlsplit(safe_base)
    except Exception:
        return "<cloud URL redacted>"

    safe_query = _redact_url_component_for_display(parts.query)
    safe_fragment = _redact_url_component_for_display(parts.fragment)
    return urlunsplit((safe_parts.scheme, safe_parts.netloc, safe_parts.path, safe_query, safe_fragment))


def _redact_url_component_for_display(value: str) -> str:
    safe_parts: list[str] = []
    for part in re.split(r"[&;]", value):
        if "=" not in part:
            continue
        key, parameter_value = part.split("=", 1)
        if _is_safe_display_query_param(key, parameter_value):
            safe_parts.append(part)
        else:
            safe_parts.append(f"{key}=<redacted>")
    return "&".join(safe_parts)


def _redact_bare_sensitive_assignment(match: re.Match[str]) -> str:
    key = match.group("key")
    if not _is_sensitive_assignment_key(key):
        return match.group(0)
    return f"{key}{match.group('separator')}<redacted>"


def _redact_sensitive_header_assignments(value: str) -> str:
    matches = [match for match in _HEADER_KEY_RE.finditer(value) if _is_sensitive_assignment_key(match.group("key"))]
    for match in reversed(matches):
        value_end = len(value)
        for delimiter in ("\r", "\n", ",", ";"):
            delimiter_index = value.find(delimiter, match.end())
            if delimiter_index >= 0:
                value_end = min(value_end, delimiter_index)
        value = f"{value[: match.start()]}{match.group('key')}: <redacted>{value[value_end:]}"
    return value


def _strip_url_path_assignments_for_display(path: str) -> str:
    safe_segments: list[str] = []
    for segment in path.split("/"):
        base, *parameters = segment.split(";")
        safe_parameters = [parameter for parameter in parameters if "=" not in parameter]
        safe_segments.append(";".join((base, *safe_parameters)))
    return "/".join(safe_segments)


def _is_sensitive_assignment_key(key: str) -> bool:
    decoded_key = key
    for _ in range(_MAX_QUERY_VALUE_DECODE_PASSES):
        next_key = unquote_plus(decoded_key)
        if next_key == decoded_key:
            break
        decoded_key = next_key
    else:
        if unquote_plus(decoded_key) != decoded_key:
            return True

    normalized_key = decoded_key.casefold()
    key_tokens = {token for token in re.split(r"[^a-z0-9]+", normalized_key) if token}
    if key_tokens & _SENSITIVE_ASSIGNMENT_KEY_TOKENS:
        return True
    collapsed_key = re.sub(r"[^a-z0-9]+", "", normalized_key)
    return any(marker in collapsed_key for marker in _SENSITIVE_ASSIGNMENT_KEY_MARKERS)


def is_sensitive_credential_key(key: object) -> bool:
    """Return whether a structured metadata key identifies credential material."""
    if isinstance(key, bytes):
        try:
            key = key.decode("utf-8")
        except UnicodeDecodeError:
            return False
    return isinstance(key, str) and _is_sensitive_assignment_key(key)


def _redact_sensitive_query_param(match: re.Match[str]) -> str:
    if _is_safe_display_query_param(match.group("key"), match.group("value")):
        return match.group(0)
    return f"{match.group('prefix')}{match.group('key')}=<redacted>"


def _is_safe_display_query_param(key: str, value: str) -> bool:
    decoded_key = unquote_plus(key).lower()
    if decoded_key not in _SAFE_DISPLAY_QUERY_KEYS:
        return False

    decoded_value = value
    for _ in range(_MAX_QUERY_VALUE_DECODE_PASSES):
        if _has_unsafe_display_query_value_structure(decoded_value):
            return False
        next_value = unquote_plus(decoded_value)
        if next_value == decoded_value:
            return True
        decoded_value = next_value

    # Values that remain encoded after the bounded pass may conceal nested
    # query structure under additional encoding layers.
    return not _has_unsafe_display_query_value_structure(decoded_value) and unquote_plus(decoded_value) == decoded_value


def _has_unsafe_display_query_value_structure(value: str) -> bool:
    return any(delimiter in value for delimiter in "?&#;=") or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    )


def redact_stream_url_for_display(url: str) -> str:
    """Return a fail-closed display identifier for a stream source URL."""
    try:
        if not urlsplit(url).scheme:
            return "<cloud URL redacted>"
    except Exception:
        return "<cloud URL redacted>"
    return redact_url_for_display(url)


def redact_stream_error_for_display(message: object, source_url: str) -> str:
    """Remove a stream source URL from exception text, including malformed identifiers."""
    safe_url = redact_stream_url_for_display(source_url)
    redacted = str(message)
    if not source_url:
        return redact_cloud_error_for_display(redacted.replace("stream://", f"stream://{safe_url}"))
    redacted = redacted.replace(f"stream://{source_url}", f"stream://{safe_url}")
    redacted = redacted.replace(source_url, safe_url)
    return redact_cloud_error_for_display(redacted)


def _redact_cloud_path_for_display(path: object) -> str:
    """Redact credentials from cloud paths even when providers strip the protocol."""
    path_text = str(path)
    return redact_cloud_error_for_display(path_text, path_text)


def _bound_cloud_metadata_error_display(message: str) -> str:
    """Limit model-controlled cloud metadata diagnostics retained in memory."""
    if len(message) <= _MAX_CLOUD_METADATA_ERROR_DISPLAY_CHARS:
        return message
    return f"{message[: _MAX_CLOUD_METADATA_ERROR_DISPLAY_CHARS - 3]}..."


def _cloud_metadata_error_sample(path: object, error: object) -> dict[str, str]:
    """Return a bounded, credential-safe metadata failure sample."""
    path_text = str(path)
    return {
        "path": _bound_cloud_metadata_error_display(_redact_cloud_path_for_display(path_text)),
        "error": _bound_cloud_metadata_error_display(redact_cloud_error_for_display(error, path_text)),
    }


def _cloud_error_sanitizer(source_url: str) -> Callable[[Exception], str]:
    def sanitize(exc: Exception) -> str:
        return redact_cloud_error_for_display(exc, source_url)

    return sanitize


def _cloud_url_basename(url: str) -> str:
    """Return a local filename while stripping only HTTPS query credentials."""
    try:
        parts = urlsplit(url)
        if parts.scheme.casefold() in {"s3", "gs", "gcs", "r2"}:
            return url.rstrip("/").rsplit("/", 1)[-1]
        path = parts.path
    except Exception:
        path = url
    return Path(path).name


def _cloud_probe_basename(url: str) -> str:
    """Return a credential-free, cross-platform filename for content routing."""
    try:
        parts = urlsplit(url)
        basename = parts.path.rsplit("/", 1)[-1]
        if parts.scheme.casefold() in {"s3", "gs", "gcs", "r2"}:
            basename = url.rstrip("/").rsplit("/", 1)[-1]
        suffix = PurePosixPath(basename).suffix
    except Exception:
        suffix = ""
    if not _CLOUD_PROBE_SUFFIX_RE.fullmatch(suffix):
        suffix = ""
    return f"cloud-object{suffix}"


def _encode_cloud_local_character(character: str) -> str:
    """Return a reversible ASCII encoding for one local-path character."""
    return "".join(f"%{byte:02X}" for byte in character.encode("utf-8", errors="surrogatepass"))


def _truncate_cloud_local_component(text: str, max_bytes: int) -> str:
    """Truncate a path component without splitting a UTF-8 code point."""
    if len(text.encode("utf-8", errors="surrogatepass")) <= max_bytes:
        return text
    parts: list[str] = []
    used_bytes = 0
    for character in text:
        character_size = len(character.encode("utf-8", errors="surrogatepass"))
        if used_bytes + character_size > max_bytes:
            break
        parts.append(character)
        used_bytes += character_size
    return "".join(parts)


def _cloud_local_component_identity(component: str) -> str:
    """Return the bounded identity used for collision-resistant local paths."""
    return hashlib.sha256(component.encode("utf-8", errors="surrogatepass")).hexdigest()[
        :_CLOUD_LOCAL_IDENTITY_HASH_CHARS
    ]


def _cloud_local_reserved_stem(component: str) -> str:
    """Return the Windows device-name stem after filesystem normalization."""
    return component.split(".", 1)[0].rstrip(" .").casefold()


def _cloud_local_component_is_literal_safe(component: str) -> bool:
    """Return whether a component can be preserved literally on Windows."""
    if not component or component != component.rstrip(" ."):
        return False
    if any(
        character in _CLOUD_LOCAL_PATH_ESCAPE_CHARS or ord(character) < 0x20 or 0xD800 <= ord(character) <= 0xDFFF
        for character in component
    ):
        return False
    return (
        _cloud_local_reserved_stem(component) not in _WINDOWS_RESERVED_LOCAL_PATH_NAMES
        and len(component.encode("utf-8", errors="surrogatepass")) <= _CLOUD_LOCAL_COMPONENT_MAX_BYTES
    )


def _cloud_local_path_component(component: str) -> str:
    """Map one cloud key component to a collision-resistant Windows-safe name."""
    if not component:
        return f"~{_cloud_local_component_identity(component)}"

    trailing_start = len(component.rstrip(" ."))
    encoded_parts: list[str] = []
    changed = False
    for index, character in enumerate(component):
        if (
            character in _CLOUD_LOCAL_PATH_ESCAPE_CHARS
            or ord(character) < 0x20
            or 0xD800 <= ord(character) <= 0xDFFF
            or index >= trailing_start
        ):
            encoded_parts.append(_encode_cloud_local_character(character))
            changed = True
        else:
            encoded_parts.append(character)

    encoded = "".join(encoded_parts)
    reserved_stem = _cloud_local_reserved_stem(component)
    if reserved_stem in _WINDOWS_RESERVED_LOCAL_PATH_NAMES:
        encoded = f"{_encode_cloud_local_character(component[0])}{encoded[1:]}"
        changed = True

    encoded_size = len(encoded.encode("utf-8", errors="surrogatepass"))
    needs_case_identity = not component.isascii() or component != component.casefold()
    uses_generated_identity = _CLOUD_LOCAL_GENERATED_IDENTITY_RE.search(component) is not None
    if (
        not changed
        and not needs_case_identity
        and not uses_generated_identity
        and encoded_size <= _CLOUD_LOCAL_COMPONENT_MAX_BYTES
    ):
        return component

    # The digest keeps transformed and case-only variants distinct on case-insensitive filesystems.
    identity = _cloud_local_component_identity(component)
    suffix = Path(encoded).suffix
    if not _CLOUD_PROBE_SUFFIX_RE.fullmatch(suffix):
        suffix = ""
    stem = encoded[: -len(suffix)] if suffix else encoded
    identity_suffix = f"~{identity}{suffix}"
    stem_budget = _CLOUD_LOCAL_COMPONENT_MAX_BYTES - len(identity_suffix.encode("ascii"))
    bounded_stem = _truncate_cloud_local_component(stem, stem_budget)
    return f"{bounded_stem}{identity_suffix}"


def _cloud_local_leaf_components(component: str) -> tuple[str, ...]:
    """Preserve scanner-significant basenames while isolating case collisions."""
    transformed = _cloud_local_path_component(component)
    if transformed == component or not _cloud_local_component_is_literal_safe(component):
        return (transformed,)
    return (f"~{_cloud_local_component_identity(component)}", component)


def _cloud_local_directory_component(component: str) -> str:
    """Map a cloud key directory without colliding with a leaf object."""
    transformed = _cloud_local_path_component(component)
    identity_suffix = f"~{_cloud_local_component_identity(component)}"
    stem_budget = _CLOUD_LOCAL_COMPONENT_MAX_BYTES - len(identity_suffix)
    return f"{_truncate_cloud_local_component(transformed, stem_budget)}{identity_suffix}"


def _cloud_object_relative_path(base_url: str, file_url: str) -> str:
    """Return a listed object's path relative to the requested cloud target."""
    normalized_base = _cloud_url_without_query(base_url)
    normalized_file_url = _cloud_url_without_query(file_url)

    if normalized_file_url.startswith(f"{normalized_base}/"):
        relative_path = normalized_file_url[len(normalized_base) + 1 :]
    elif normalized_file_url == normalized_base:
        relative_path = _cloud_url_local_basename(file_url)
    else:
        file_parts = urlsplit(normalized_file_url)
        file_scheme = file_parts.scheme.casefold()
        structured_file_url = file_scheme in {"s3", "gs", "gcs", "r2"} or (
            file_scheme in {"http", "https"} and _http_cloud_protocol(file_url) is not None
        )
        if structured_file_url or file_parts.netloc or "://" in normalized_file_url:
            raise ValueError(f"Cloud object path is outside requested target: {redact_url_for_display(file_url)}")
        relative_path = _protocol_less_cloud_relative_path(normalized_base, file_url)

    if not relative_path:
        raise ValueError(f"Invalid cloud object basename: {redact_url_for_display(file_url)}")
    return relative_path


def _cloud_object_prefix_conflicts(base_url: str, file_urls: Collection[str]) -> frozenset[str]:
    """Return object keys that are also directory prefixes of selected objects."""
    relative_paths = {_cloud_object_relative_path(base_url, file_url) for file_url in file_urls}
    conflicts: set[str] = set()
    for relative_path in relative_paths:
        components = relative_path.split("/")
        for component_count in range(1, len(components)):
            prefix = "/".join(components[:component_count])
            if prefix in relative_paths:
                conflicts.add(prefix)
    return frozenset(conflicts)


def _cloud_url_local_basename(url: str) -> str:
    """Return the raw final URL path segment for local file creation."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() in {"s3", "gs", "gcs", "r2"}:
            if not parsed.path or parsed.path.endswith("/"):
                return ""
            return url.rstrip("/").rsplit("/", 1)[-1]
        return parsed.path.rsplit("/", 1)[-1]
    except Exception:
        logger.debug("Unable to parse cloud URL for local basename; using fallback path handling")
        return url.rstrip("/").rsplit("/", 1)[-1]


def _normalize_cloud_local_separators(path: str) -> str:
    """Interpret backslashes as separators only on filesystems that do so."""
    return path.replace("\\", "/") if _uses_windows_filename_rules() else path


def _remove_path(path: Path) -> None:
    """Remove a file, directory, symlink, or special path without following symlinks."""
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path)


def _prepare_cache_subdirectory(cache_dir: Path, cache_key: str) -> Path:
    """Create a cache-key directory without following replaced path components."""
    cache_subdir = cache_dir
    for component in (_CACHE_ENTRY_NAMESPACE, cache_key[:2], cache_key[2:4], cache_key):
        cache_subdir /= component
        if cache_subdir.is_symlink() or (cache_subdir.exists() and not cache_subdir.is_dir()):
            cache_subdir.unlink()
        cache_subdir.mkdir(exist_ok=True)
    return cache_subdir


def _metadata_etag(metadata: Mapping[str, Any] | None) -> str | None:
    """Extract a stable object validator from fsspec-style metadata."""
    if not metadata:
        return None
    for key in ("etag", "ETag", "Etag", "e_tag", "version_id", "VersionId", "generation"):
        value = metadata.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _cloud_url_without_query(url: str) -> str:
    """Return a cloud URL without signed query or fragment material for path comparison."""
    parsed = urlsplit(url)
    if parsed.scheme.casefold() in {"s3", "gs", "gcs", "r2"}:
        return url.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _normalize_cloud_listing_path(base_url: str, listed_path: object) -> str:
    """Resolve provider listing variants to a canonical child URL."""
    child = str(listed_path)
    child_parts = urlsplit(child)
    if child_parts.scheme and "://" in child:
        return child

    base_parts = urlsplit(base_url)
    if not base_parts.scheme or not base_parts.netloc:
        return child

    child = child.lstrip("/")
    bucket = base_parts.netloc
    base_key = base_parts.path.strip("/")
    if child == bucket or child.startswith(f"{bucket}/"):
        return f"{base_parts.scheme}://{child}"
    if base_key and (child == base_key or child.startswith(f"{base_key}/")):
        return f"{base_parts.scheme}://{bucket}/{child}"
    return f"{base_url.rstrip('/')}/{child}"


def get_fs_protocol(url: str) -> str:
    """Get the fsspec protocol for a given URL."""
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}") from exc
    scheme = parsed.scheme.casefold()
    if scheme in {"http", "https"}:
        protocol = _http_cloud_protocol(url)
        if protocol is None:
            raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}")
        if scheme == "http":
            raise ValueError(f"{_CLEARTEXT_CLOUD_ERROR}: {redact_url_for_display(url)}")
        return protocol
    elif scheme == "gcs" or scheme == "gs":
        return "gcs"
    elif scheme in {"s3", "r2"}:
        return "s3"
    else:
        raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}")


def get_cloud_filesystem_config(url: str) -> tuple[str, str, dict[str, Any]]:
    """Return the fsspec protocol, canonical object path, and filesystem arguments."""
    protocol = get_fs_protocol(url)
    fs_args: dict[str, Any] = {"token": "anon"} if protocol == "gcs" else {}
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.casefold()
        hostname = (parsed.hostname or "").casefold().rstrip(".")
    except ValueError as exc:
        raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}") from exc

    if scheme in {"s3", "gs", "gcs"}:
        canonical_scheme = "gcs" if protocol == "gcs" else "s3"
        canonical_url = urlunsplit((canonical_scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
        return protocol, canonical_url, fs_args
    if scheme == "r2":
        canonical_url = urlunsplit(("s3", parsed.netloc, parsed.path, parsed.query, parsed.fragment))
        return protocol, canonical_url, fs_args
    if scheme != "https":
        return protocol, url, fs_args
    if parsed.query:
        return "https", url, {}

    encoded_path = parsed.path[1:] if parsed.path.startswith("/") else parsed.path
    path = unquote(encoded_path)
    bucket = ""
    key = ""
    endpoint_host: str | None = None
    if _is_r2_https_host(hostname):
        host_prefix = hostname[: -len(".r2.cloudflarestorage.com")]
        host_parts = host_prefix.split(".")
        account = host_parts[-1]
        if len(host_parts) > 1:
            bucket = ".".join(host_parts[:-1])
            key = path
        else:
            bucket, _, key = path.partition("/")
        endpoint_host = f"{account}.r2.cloudflarestorage.com"
        if parsed.port is not None:
            endpoint_host = f"{endpoint_host}:{parsed.port}"
        fs_args["client_kwargs"] = {"endpoint_url": f"https://{endpoint_host}"}
    elif _S3_PATH_STYLE_HTTPS_HOST_RE.fullmatch(hostname) or _S3_FIPS_PATH_STYLE_HTTPS_HOST_RE.fullmatch(hostname):
        bucket, _, key = path.partition("/")
        endpoint_host = hostname
    elif (
        _S3_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_FIPS_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
        or _S3_ACCELERATE_VIRTUAL_HOSTED_HTTPS_HOST_RE.fullmatch(hostname)
    ):
        endpoint_boundary = hostname.rfind(".s3")
        bucket = hostname[:endpoint_boundary]
        endpoint_host = hostname[endpoint_boundary + 1 :]
        key = path
    elif hostname.endswith(".storage.googleapis.com"):
        bucket = hostname[: -len(".storage.googleapis.com")]
        key = path
    elif hostname in {"storage.googleapis.com", "storage.cloud.google.com"}:
        bucket, _, key = path.partition("/")

    if not bucket:
        raise ValueError(f"Unsupported cloud storage URL: {redact_url_for_display(url)}")
    if endpoint_host is not None and endpoint_host != "s3.amazonaws.com":
        fs_args["client_kwargs"] = {"endpoint_url": f"https://{endpoint_host}"}
        if "s3-accelerate" in endpoint_host:
            fs_args["config_kwargs"] = {"s3": {"addressing_style": "virtual"}}
    canonical_scheme = "gcs" if protocol == "gcs" else "s3"
    canonical_url = f"{canonical_scheme}://{bucket}"
    if key:
        canonical_url = f"{canonical_url}/{key}"
    return protocol, canonical_url, fs_args


def estimate_download_time(size_bytes: int, bandwidth_mbps: float = 10.0) -> str:
    """Estimate download time based on file size and bandwidth."""
    if size_bytes == 0:
        return "instant"

    # Convert to seconds
    bandwidth_bps = bandwidth_mbps * 1_000_000 / 8  # Convert Mbps to bytes/second
    seconds = size_bytes / bandwidth_bps

    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _is_within_directory(base_dir: Path, target: Path) -> bool:
    """Return True if target resolves within base_dir."""
    base_path = base_dir.resolve()
    target_path = target.resolve()
    return _is_resolved_path_within_base(base_path, target_path)


def _is_resolved_path_within_base(base_path: Path, target_path: Path) -> bool:
    """Return True if two already-resolved paths have a base/child relationship."""
    if os.name == "nt":
        base_norm = os.path.normcase(os.path.normpath(str(base_path)))
        target_norm = os.path.normcase(os.path.normpath(str(target_path)))
        try:
            return os.path.commonpath([target_norm, base_norm]) == base_norm
        except ValueError:
            return False
    return target_path.is_relative_to(base_path)


def _resolve_cloud_path(entry_name: str, base_dir: Path) -> tuple[Path, bool]:
    """Resolve a cloud object relative path and return whether it is safe."""
    entry = _normalize_cloud_local_separators(entry_name)
    if entry.startswith("/") or (os.name == "nt" and len(entry) > 1 and entry[1] == ":"):
        return (base_dir / entry.lstrip("/")).resolve(), False

    candidate = base_dir / entry.lstrip("/")
    parent = candidate.parent.resolve()
    resolved = parent / candidate.name
    return resolved, _is_resolved_path_within_base(base_dir.resolve(), parent)


def _parse_size_value(size_value: Any) -> int:
    """Parse a cloud-reported size value to a non-negative integer."""
    parsed_size = int(size_value)
    if parsed_size < 0:
        raise ValueError(f"size must be non-negative, got {parsed_size}")
    return parsed_size


def get_cloud_object_size(fs: Any, url: str, strict: bool = False) -> int | None:
    """Get the size of a cloud storage object or directory.

    Args:
        fs: fsspec filesystem instance
        url: Cloud storage URL

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        info = fs.info(url)
    except Exception as exc:
        if strict:
            redacted_error = _bound_cloud_metadata_error_display(redact_cloud_error_for_display(exc, url))
            raise ValueError(
                f"Unable to read cloud object info for {redact_url_for_display(url)}: {redacted_error}"
            ) from exc
        return None

    top_level_size_error: Exception | None = None
    if info.get("type") != "directory" and "size" in info:
        try:
            return _parse_size_value(info["size"])
        except (TypeError, ValueError) as exc:
            top_level_size_error = exc

    total_size = 0
    measured_file_count = 0
    measured_sizes: dict[str, int] = {}
    walk_observed = False
    walk_error: Exception | None = None
    ls_error: Exception | None = None
    ls_error_path: str | None = None

    def _record_size(path: object, raw_size: object) -> None:
        nonlocal total_size, measured_file_count
        path_key = str(path)
        parsed_size = _parse_size_value(raw_size)
        previous_size = measured_sizes.get(path_key)
        if previous_size is None:
            measured_sizes[path_key] = parsed_size
            total_size += parsed_size
            measured_file_count += 1
            return
        if previous_size == parsed_size:
            return
        if strict:
            raise ValueError(f"inconsistent size metadata for duplicate listed object {path_key}")
        retained_size = max(previous_size, parsed_size)
        measured_sizes[path_key] = retained_size
        total_size += retained_size - previous_size

    # Try using fs.walk to traverse directories
    try:
        for root, _, files in fs.walk(url):
            walk_observed = True
            for file_path in files:
                listed_path = str(file_path)
                if "://" not in listed_path and "/" not in listed_path.strip("/"):
                    listed_path = f"{str(root).rstrip('/')}/{listed_path}"
                resolved_file_path = _normalize_cloud_listing_path(url, listed_path)
                try:
                    file_info = fs.info(resolved_file_path)
                    if "size" in file_info:
                        _record_size(resolved_file_path, file_info["size"])
                    elif strict:
                        raise ValueError("cloud provider did not return file size")
                except Exception as exc:
                    if strict:
                        safe_path = _bound_cloud_metadata_error_display(
                            _redact_cloud_path_for_display(resolved_file_path)
                        )
                        safe_error = _bound_cloud_metadata_error_display(
                            redact_cloud_error_for_display(exc, resolved_file_path)
                        )
                        raise _CloudObjectMetadataSizeError(
                            "Unable to determine cloud object size for "
                            f"{redact_url_for_display(url)}: metadata lookup failed for listed object "
                            f"{safe_path}: {safe_error}"
                        ) from exc
                    continue
        if walk_observed and (info.get("type") == "directory" or measured_file_count > 0):
            return total_size
    except _CloudObjectMetadataSizeError:
        raise
    except Exception as exc:
        walk_error = exc
        total_size = 0
        measured_file_count = 0
        measured_sizes.clear()

    # Fallback to recursive ls if walk is unavailable
    ls_observed = False
    visited_listing_paths: set[str] = set()

    def _collect(path: str) -> None:
        nonlocal total_size, measured_file_count, ls_error, ls_error_path, ls_observed
        if path in visited_listing_paths:
            if strict:
                raise ValueError(
                    "Unable to determine cloud object size for "
                    f"{redact_url_for_display(url)}: duplicate or cyclic directory listing at "
                    f"{_bound_cloud_metadata_error_display(_redact_cloud_path_for_display(path))}"
                )
            return
        visited_listing_paths.add(path)
        try:
            entries = fs.ls(path, detail=True)
            ls_observed = True
        except Exception as exc:
            if ls_error is None:
                ls_error = exc
                ls_error_path = path
            return
        for entry in entries:
            if not isinstance(entry, dict):
                if strict:
                    raise ValueError(
                        "Unable to determine cloud object size for "
                        f"{redact_url_for_display(url)}: cloud provider returned an invalid detailed listing entry"
                    )
                continue
            name = entry.get("name") or entry.get("path")
            if not isinstance(name, str) or not name:
                if strict:
                    raise ValueError(
                        "Unable to determine cloud object size for "
                        f"{redact_url_for_display(url)}: cloud provider returned a listed object without a valid path"
                    )
                continue
            if entry.get("type") == "directory" or (name and name.endswith("/")):
                _collect(name)
            elif "size" in entry:
                try:
                    _record_size(name, entry["size"])
                except Exception as exc:
                    if strict:
                        raise ValueError(
                            "Unable to determine cloud object size for "
                            f"{redact_url_for_display(url)}: invalid size metadata for listed object "
                            f"{_bound_cloud_metadata_error_display(_redact_cloud_path_for_display(name))}: "
                            f"{_bound_cloud_metadata_error_display(redact_cloud_error_for_display(exc, str(name)))}"
                        ) from exc
                    continue
            elif strict and name:
                raise ValueError(
                    "Unable to determine cloud object size for "
                    f"{redact_url_for_display(url)}: missing size metadata for listed object "
                    f"{_bound_cloud_metadata_error_display(_redact_cloud_path_for_display(name))}"
                )

    _collect(url)
    if (
        (not strict or ls_error is None)
        and ls_observed
        and (info.get("type") == "directory" or measured_file_count > 0)
    ):
        return total_size

    if strict:
        error_parts = []
        if top_level_size_error is not None:
            error_parts.append(f"invalid size from info(): {top_level_size_error}")
        if walk_error:
            error_parts.append(f"walk() failed: {redact_cloud_error_for_display(walk_error, url)}")
        if ls_error:
            safe_path = _bound_cloud_metadata_error_display(_redact_cloud_path_for_display(ls_error_path or url))
            error_parts.append(
                f"recursive listing failed for {safe_path}: "
                f"{redact_cloud_error_for_display(ls_error, ls_error_path or url)}"
            )
        if not error_parts:
            error_parts.append("cloud provider did not return file sizes")
        bounded_errors = _bound_cloud_metadata_error_display("; ".join(error_parts))
        raise ValueError(f"Unable to determine cloud object size for {redact_url_for_display(url)}: {bounded_errors}")

    return None


def _iter_cloud_directory_items(fs: Any, url: str) -> Iterator[object]:
    """Yield directory entries incrementally when the filesystem supports it."""
    walk_observed = False
    try:
        for root, _, files in fs.walk(url):
            walk_observed = True
            entries = files.keys() if isinstance(files, Mapping) else files
            for item in entries:
                listed_path = str(item)
                if "://" not in listed_path and "/" not in listed_path.strip("/"):
                    listed_path = f"{str(root).rstrip('/')}/{listed_path}"
                yield listed_path
    except (AttributeError, NotImplementedError, TypeError):
        if walk_observed:
            raise
    if walk_observed:
        return

    glob_pattern = f"{url.rstrip('/')}/**"
    yield from fs.glob(glob_pattern)


async def analyze_cloud_target(
    url: str,
    *,
    max_size: int | None = None,
    max_objects: int = _MAX_CLOUD_DIRECTORY_ANALYSIS_OBJECTS,
) -> dict[str, Any]:
    """Analyze cloud target before downloading."""
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. "
            "Try reinstalling modelaudit: 'pip install --force-reinstall modelaudit'"
        ) from e

    fs_protocol, fs_url, fs_args = get_cloud_filesystem_config(url)

    try:
        # fsspec filesystems don't need explicit cleanup - use directly without 'with' statement
        fs = fsspec.filesystem(fs_protocol, **fs_args)

        # Get info about the target with retry
        @retry_with_backoff(
            max_retries=3,
            verbose=True,
            sanitize_error=_cloud_error_sanitizer(url),
        )
        def get_info():
            return fs.info(fs_url)

        info = get_info()

        # Check if it's a file or directory
        if info.get("type") == "file" or (info.get("type") != "directory" and "size" in info):
            file_metadata: dict[str, Any] = {
                "type": "file",
                "size": info.get("size", 0),
                "name": _cloud_url_basename(url),
                "estimated_time": estimate_download_time(info.get("size", 0)),
                "human_size": format_size(info.get("size", 0)),
            }
            etag = _metadata_etag(info)
            if etag is not None:
                file_metadata["etag"] = etag
            return file_metadata

        # It's a directory, list contents
        files = []
        total_size = 0
        listed_object_count = 0
        metadata_error_count = 0
        metadata_errors: list[dict[str, str]] = []

        for item in _iter_cloud_directory_items(fs, fs_url):
            listed_object_count += 1
            if listed_object_count > max_objects:
                raise ValueError(
                    "Cloud directory analysis exceeds the maximum object count "
                    f"({max_objects}) for {redact_url_for_display(url)}"
                )
            item_url = _normalize_cloud_listing_path(fs_url, item)
            try:
                item_info = fs.info(item_url)
                item_type = item_info.get("type")
                if item_type == "directory":
                    continue
                if item_type == "file" or "size" in item_info:
                    size = _parse_size_value(item_info.get("size", 0))
                    file_metadata = {
                        "path": item_url,
                        "name": _cloud_url_basename(item_url),
                        "size": size,
                        "human_size": format_size(size),
                    }
                    etag = _metadata_etag(item_info)
                    if etag is not None:
                        file_metadata["etag"] = etag
                    files.append(file_metadata)
                    total_size += size
                else:
                    raise ValueError("cloud provider returned incomplete metadata for listed object")
            except Exception as exc:
                metadata_error_count += 1
                if len(metadata_errors) < _MAX_CLOUD_METADATA_ERROR_SAMPLES:
                    metadata_errors.append(_cloud_metadata_error_sample(item, exc))
            if max_size is not None and total_size > max_size:
                raise ValueError(
                    f"Cloud directory size ({format_size(total_size)}) exceeds maximum allowed size "
                    f"({format_size(max_size)})"
                )

        if metadata_error_count:
            sample_errors = "; ".join(f"{entry['path']}: {entry['error']}" for entry in metadata_errors)
            if metadata_error_count > len(metadata_errors):
                sample_errors = f"{sample_errors}; ..."
            return {
                "type": "unknown",
                "analysis_incomplete": True,
                "metadata_error_count": metadata_error_count,
                "metadata_errors": metadata_errors,
                "error": (
                    "Cloud directory analysis incomplete: metadata lookup failed for "
                    f"{metadata_error_count} object(s) under {redact_url_for_display(url)}: "
                    f"{sample_errors}"
                ),
            }

        directory_metadata: dict[str, Any] = {
            "type": "directory",
            "file_count": len(files),
            "total_size": total_size,
            "human_size": format_size(total_size),
            "files": files,
            "estimated_time": estimate_download_time(total_size),
        }
        etag = _metadata_etag(info)
        if etag is not None:
            directory_metadata["etag"] = etag
        return directory_metadata
    except Exception as e:
        # If we can't get info, assume it's a file
        return {"type": "unknown", "error": redact_cloud_error_for_display(e, url)}


def prompt_for_large_download(metadata: dict[str, Any]) -> bool:
    """Prompt user before large downloads."""
    size = metadata.get("total_size", metadata.get("size", 0))

    if size > 1_000_000_000:  # 1GB
        click.echo("\n⚠️  Large download detected:")
        click.echo(f"   Size: {metadata['human_size']}")
        click.echo(f"   Estimated time: {metadata['estimated_time']}")

        if metadata["type"] == "directory":
            click.echo(f"   Files: {metadata['file_count']} files")

        return click.confirm("\nContinue with download?", default=False)

    return True


class GCSCache:
    """Cache-aware download handling for cloud sources."""

    def __init__(self, cache_dir: Path | None = None):
        if cache_dir is None:
            self.cache_dir = Path.home() / ".modelaudit" / "cache"
        else:
            self.cache_dir = Path(cache_dir)

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.cache_dir.chmod(0o700)
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> dict[str, Any]:
        """Load cache metadata from disk."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, encoding="utf-8") as f:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        return {}
                    return {
                        str(cache_key): self._sanitize_metadata_entry(entry)
                        for cache_key, entry in data.items()
                        if isinstance(entry, dict)
                    }
            except Exception:
                return {}
        return {}

    def _url_metadata(self, url: str) -> dict[str, str]:
        """Return non-secret URL metadata safe to persist."""
        parsed = urlsplit(url)
        return {
            "url_sha256": self.get_cache_key(url),
            "url_display": redact_url_for_display(url),
            "url_scheme": parsed.scheme,
            "url_host": parsed.hostname or "",
            "url_path": parsed.path,
        }

    def _sanitize_metadata_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Remove legacy raw URL fields before metadata is persisted again."""
        sanitized = dict(entry)
        raw_url = sanitized.pop("url", None)
        if isinstance(raw_url, str):
            for key, value in self._url_metadata(raw_url).items():
                sanitized.setdefault(key, value)
        return sanitized

    def _save_metadata(self) -> None:
        """Save cache metadata to disk."""
        self.metadata = {
            str(cache_key): self._sanitize_metadata_entry(entry)
            for cache_key, entry in self.metadata.items()
            if isinstance(entry, dict)
        }
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.metadata_file.name}.",
            suffix=".tmp",
            dir=self.cache_dir,
        )
        temp_file = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.metadata, f, indent=2)
                f.write("\n")
            os.replace(temp_file, self.metadata_file)
            if os.name != "nt":
                self.metadata_file.chmod(0o600)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def get_cache_key(self, url: str, *, cache_scope: str | None = None) -> str:
        """Generate cache key for URL."""
        cache_identity = url if cache_scope is None else f"{url}\0{cache_scope}"
        return hashlib.sha256(cache_identity.encode()).hexdigest()

    def get_cached_path(
        self,
        url: str,
        etag: str | None = None,
        *,
        cache_scope: str | None = None,
    ) -> Path | None:
        """Return cached file if still valid."""
        cache_key = self.get_cache_key(url, cache_scope=cache_scope)

        if cache_key in self.metadata:
            cached = self.metadata[cache_key]
            cached_path = Path(cached["path"])

            if not _is_within_directory(self.cache_dir, cached_path):
                logger.warning(
                    "Dropping cache entry for %s because cached path %s is outside cache dir %s",
                    redact_url_for_display(url),
                    cached_path,
                    self.cache_dir,
                )
                del self.metadata[cache_key]
                self._save_metadata()
                return None

            # Check if file still exists
            if not cached_path.exists():
                del self.metadata[cache_key]
                self._save_metadata()
                return None

            cached_etag = cached.get("etag")
            if etag is None or not cached_etag:
                self._save_metadata()
                return None

            if cached_etag != etag:
                return None

            # Update last accessed time
            cached["last_accessed"] = datetime.now().isoformat()
            self._save_metadata()

            return cached_path

        return None

    def cache_file(
        self,
        url: str,
        local_path: Path,
        etag: str | None = None,
        *,
        cache_scope: str | None = None,
    ) -> None:
        """Cache downloaded file with metadata."""
        cache_key = self.get_cache_key(url, cache_scope=cache_scope)

        # Create cache subdirectory
        cache_subdir = _prepare_cache_subdirectory(self.cache_dir, cache_key)

        # Determine cache path
        if local_path.is_file():
            cache_path = cache_subdir / local_path.name
            # Don't copy if it's already in the cache directory
            if not _is_within_directory(self.cache_dir, local_path):
                _remove_path(cache_path)
                shutil.copy2(local_path, cache_path)
            else:
                cache_path = local_path
        else:
            # It's a directory
            cache_path = cache_subdir / "content"
            # Don't copy if it's already in the cache directory
            if not _is_within_directory(self.cache_dir, local_path):
                _remove_path(cache_path)
                shutil.copytree(local_path, cache_path)
            else:
                cache_path = local_path

        # Update metadata
        self.metadata[cache_key] = {
            **self._url_metadata(url),
            "path": str(cache_path),
            "etag": etag,
            "size": cache_path.stat().st_size if cache_path.is_file() else 0,
            "cached_at": datetime.now().isoformat(),
            "last_accessed": datetime.now().isoformat(),
        }
        self._save_metadata()

    def clean_old_cache(self, max_age_days: int = 7) -> None:
        """Clean cache entries older than max_age_days."""
        now = datetime.now()
        keys_to_remove = []

        for key, cached in self.metadata.items():
            last_accessed = datetime.fromisoformat(cached["last_accessed"])
            if now - last_accessed > timedelta(days=max_age_days):
                # Remove cached file
                cached_path = Path(cached["path"])
                if _is_within_directory(self.cache_dir, cached_path):
                    if cached_path.exists():
                        if cached_path.is_file():
                            cached_path.unlink()
                        else:
                            shutil.rmtree(cached_path)
                else:
                    logger.warning(
                        "Skipping deletion for cache metadata path %s because it is outside cache dir %s",
                        cached_path,
                        self.cache_dir,
                    )
                keys_to_remove.append(key)

        # Update metadata
        for key in keys_to_remove:
            del self.metadata[key]

        if keys_to_remove:
            self._save_metadata()
            click.echo(f"Cleaned {len(keys_to_remove)} old cache entries")


def filter_scannable_files(
    files: list[dict[str, Any]],
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter files to only include scannable model types."""
    extensions = SCANNABLE_MODEL_EXTENSIONS if scannable_extensions is None else frozenset(scannable_extensions)
    filenames = frozenset(str(filename).lower() for filename in (scannable_filenames or ()))
    scannable = []
    for file in files:
        file_path = str(file["path"])
        path = Path(_cloud_url_basename(file_path) if is_cloud_url(file_path) else file_path)
        if path.name.lower() in filenames:
            scannable.append(file)
            continue
        suffixes = [s.lower() for s in path.suffixes]
        if not suffixes and "" in extensions:
            scannable.append(file)
            continue
        for i in range(1, len(suffixes) + 1):
            if "".join(suffixes[-i:]) in extensions:
                scannable.append(file)
                break

    return scannable


def _matching_scannable_extensions(file_path: str, extensions: Collection[str]) -> frozenset[str]:
    path = Path(_cloud_url_basename(file_path) if is_cloud_url(file_path) else file_path)
    suffixes = [suffix.lower() for suffix in path.suffixes]
    normalized_extensions = frozenset(str(extension).lower() for extension in extensions)
    if not suffixes:
        return frozenset({""}) if "" in normalized_extensions else frozenset()
    return frozenset(
        candidate
        for index in range(1, len(suffixes) + 1)
        if (candidate := "".join(suffixes[-index:])) in normalized_extensions
    )


def _selected_suffix_needs_content_validation(
    file_path: str,
    extensions: Collection[str] | None,
    scanner_policy: ScannerSelectionPolicy | None,
) -> bool:
    if extensions is None or scanner_policy is None or not scanner_policy.active:
        return False
    owners = {
        scanner_id
        for extension in _matching_scannable_extensions(file_path, extensions)
        for scanner_id in scanner_ids_for_extension(extension)
    }
    return (
        bool(owners)
        and any(scanner_policy.allows(scanner_id) for scanner_id in owners)
        and any(not scanner_policy.allows(scanner_id) for scanner_id in owners)
    )


def _cloud_directory_cache_scope(
    metadata: Mapping[str, Any],
    *,
    selective: bool,
    scannable_extensions: Collection[str] | None,
    scannable_filenames: Collection[str] | None,
    scanner_selection: Mapping[str, Any] | None,
) -> str | None:
    """Return a stable cache scope for directory downloads."""
    if metadata.get("type") != "directory":
        return None
    payload: dict[str, Any] = {"selective": selective}
    if selective:
        payload.update(
            {
                "routing_version": 2,
                "extensions": (
                    None
                    if scannable_extensions is None
                    else sorted(str(extension).lower() for extension in scannable_extensions)
                ),
                "filenames": (
                    None
                    if scannable_filenames is None
                    else sorted(str(filename).lower() for filename in scannable_filenames)
                ),
                "scanner_selection": (
                    None
                    if scanner_selection is None
                    else policy_from_config({SCANNER_SELECTION_CONFIG_KEY: scanner_selection}).to_config()
                ),
            }
        )
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _read_bounded_cloud_content(remote_file: Any, max_bytes: int) -> bytes:
    """Read through short transport reads without exceeding the requested bound."""
    payload = bytearray()
    while len(payload) < max_bytes:
        chunk = remote_file.read(max_bytes - len(payload))
        if not isinstance(chunk, bytes):
            raise TypeError("cloud filesystem returned non-bytes content")
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


class _CloudContentSniffBudgetExceeded(ValueError):
    """Raised when a random-access classifier needs bytes beyond its sniff budget."""


class _CloudContentSniffBudget:
    """Bound aggregate reads used to route suffix-skipped cloud objects."""

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self.remaining_bytes = max_bytes
        self._prefixes: dict[str, bytes] = {}
        self._complete_prefixes: set[str] = set()
        self.incomplete_stream_reads = 0

    def _read_bounded(self, remote_file: Any, max_bytes: int) -> bytes:
        """Charge each transferred chunk before a later transport read can fail."""
        payload = bytearray()
        while len(payload) < max_bytes:
            chunk = remote_file.read(max_bytes - len(payload))
            if not isinstance(chunk, bytes):
                raise TypeError("cloud filesystem returned non-bytes content")
            if not chunk:
                break
            payload.extend(chunk)
            self.remaining_bytes -= len(chunk)
        return bytes(payload)

    def read_prefix(self, fs: Any, file_url: str, max_bytes: int) -> bytes:
        """Return a cached prefix, extending it without rereading transferred bytes."""
        prefix = self._prefixes.get(file_url, b"")
        if len(prefix) >= max_bytes or file_url in self._complete_prefixes:
            return prefix[:max_bytes]

        read_size = min(max_bytes - len(prefix), self.remaining_bytes)
        if read_size <= 0:
            return prefix

        with fs.open(file_url, "rb") as remote_file:
            if prefix:
                remote_file.seek(len(prefix))
            chunk = self._read_bounded(remote_file, read_size)

        prefix += chunk
        self._prefixes[file_url] = prefix
        if len(chunk) < read_size:
            self._complete_prefixes.add(file_url)
        return prefix[:max_bytes]

    def read_range(self, fs: Any, file_url: str, offset: int, max_bytes: int) -> bytes:
        """Read a bounded range while reusing overlapping cached prefix bytes."""
        prefix = self._prefixes.get(file_url, b"")
        cached = prefix[offset : offset + max_bytes] if offset < len(prefix) else b""
        if len(cached) >= max_bytes:
            return cached

        range_offset = offset + len(cached)
        read_size = min(max_bytes - len(cached), self.remaining_bytes)
        if read_size <= 0:
            return cached

        with fs.open(file_url, "rb") as remote_file:
            remote_file.seek(range_offset)
            chunk = self._read_bounded(remote_file, read_size)

        return cached + chunk

    def read_stream(self, remote_file: Any, requested_bytes: int | None = -1) -> bytes:
        """Read from a random-access stream without exceeding the shared budget."""
        if requested_bytes == 0:
            return b""
        if self.remaining_bytes <= 0:
            raise _CloudContentSniffBudgetExceeded

        if requested_bytes is None or requested_bytes < 0:
            read_size = self.remaining_bytes
            was_capped = True
        else:
            read_size = min(requested_bytes, self.remaining_bytes)
            was_capped = requested_bytes > self.remaining_bytes
        chunk = remote_file.read(read_size)
        if not isinstance(chunk, bytes):
            raise TypeError("cloud filesystem returned non-bytes content")
        self.remaining_bytes -= len(chunk)
        if was_capped and len(chunk) == read_size:
            self.incomplete_stream_reads += 1
        return chunk

    def prefix_is_complete(self, file_url: str) -> bool:
        """Return whether a prefix read observed the end of the remote object."""
        return file_url in self._complete_prefixes

    def cached_prefix(self, file_url: str) -> bytes:
        """Return bytes already transferred for a remote prefix."""
        return self._prefixes.get(file_url, b"")

    def classification_error(self, file_url: str) -> ValueError:
        """Build a redacted error for an inconclusive budget-limited probe."""
        return ValueError(
            "Cloud directory selective filtering incomplete: maximum content inspection budget "
            f"({format_size(self.max_bytes)}) exhausted while classifying skipped object "
            f"{_redact_cloud_path_for_display(file_url)}"
        )

    def require_classification_capacity(self, file_url: str) -> None:
        """Fail closed when an incomplete object consumed the shared sniff budget."""
        if self.remaining_bytes > 0 or self.prefix_is_complete(file_url):
            return
        raise self.classification_error(file_url)


class _BudgetedCloudContentReader:
    """Expose a seekable cloud stream while charging reads to a sniff budget."""

    def __init__(
        self,
        remote_file: Any,
        budget: _CloudContentSniffBudget,
        file_url: str,
        file_size: int,
    ):
        self._remote_file = remote_file
        self._budget = budget
        self._file_size = file_size
        prefix = budget.cached_prefix(file_url)
        self._cached_ranges = [(0, prefix)] if prefix else []

    def _cache_range(self, offset: int, data: bytes) -> None:
        if not data:
            return

        new_start = offset
        new_data = data
        merged: list[tuple[int, bytes]] = []
        inserted = False
        for start, cached in self._cached_ranges:
            end = start + len(cached)
            new_end = new_start + len(new_data)
            if end < new_start:
                merged.append((start, cached))
                continue
            if new_end < start:
                if not inserted:
                    merged.append((new_start, new_data))
                    inserted = True
                merged.append((start, cached))
                continue

            merged_start = min(start, new_start)
            merged_end = max(end, new_end)
            combined = bytearray(merged_end - merged_start)
            combined[start - merged_start : end - merged_start] = cached
            combined[new_start - merged_start : new_end - merged_start] = new_data
            new_start = merged_start
            new_data = bytes(combined)

        if not inserted:
            merged.append((new_start, new_data))
        self._cached_ranges = merged

    def _read_cached(self, offset: int, max_bytes: int) -> bytes:
        for start, cached in self._cached_ranges:
            end = start + len(cached)
            if start <= offset < end:
                return cached[offset - start : offset - start + max_bytes]
            if start > offset:
                break
        return b""

    def _next_cached_offset(self, offset: int) -> int | None:
        return next((start for start, _cached in self._cached_ranges if start > offset), None)

    def read(self, size: int | None = -1) -> bytes:
        if size == 0:
            return b""

        offset = self.tell()
        available = max(self._file_size - offset, 0)
        remaining = available if size is None or size < 0 else min(size, available)
        result = bytearray()
        while remaining > 0:
            offset = self.tell()
            cached = self._read_cached(offset, remaining)
            if cached:
                result.extend(cached)
                self._remote_file.seek(offset + len(cached))
                remaining -= len(cached)
                continue

            read_size = remaining
            next_cached_offset = self._next_cached_offset(offset)
            if next_cached_offset is not None:
                read_size = min(read_size, next_cached_offset - offset)
            chunk = self._budget.read_stream(self._remote_file, read_size)
            if not chunk:
                break
            self._cache_range(offset, chunk)
            result.extend(chunk)
            remaining -= len(chunk)

        return bytes(result)

    def readinto(self, buffer: Any) -> int:
        chunk = self.read(len(buffer))
        buffer[: len(chunk)] = chunk
        return len(chunk)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return int(self._remote_file.seek(offset, whence))

    def tell(self) -> int:
        return int(self._remote_file.tell())

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True


def _read_cloud_content_prefix(
    fs: Any,
    file_url: str,
    max_bytes: int,
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> bytes:
    """Read a bounded remote prefix or fail closed with a redacted error."""
    try:
        if sniff_budget is not None:
            return sniff_budget.read_prefix(fs, file_url, max_bytes)
        with fs.open(file_url, "rb") as remote_file:
            return _read_bounded_cloud_content(remote_file, max_bytes)
    except Exception as exc:
        raise ValueError(
            "Cloud directory selective filtering incomplete: unable to inspect skipped object "
            f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
        ) from exc


def _read_cloud_content_range(
    fs: Any,
    file_url: str,
    offset: int,
    max_bytes: int,
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> bytes:
    """Read a bounded remote byte range or fail closed with a redacted error."""
    try:
        if sniff_budget is not None:
            return sniff_budget.read_range(fs, file_url, offset, max_bytes)
        with fs.open(file_url, "rb") as remote_file:
            remote_file.seek(offset)
            return _read_bounded_cloud_content(remote_file, max_bytes)
    except Exception as exc:
        raise ValueError(
            "Cloud directory selective filtering incomplete: unable to inspect skipped object "
            f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
        ) from exc


def _get_cloud_content_size_for_routing(fs: Any, file_url: str) -> int:
    """Read the remote object's actual size for tail-sensitive content routing."""
    try:
        with fs.open(file_url, "rb") as remote_file:
            remote_file.seek(0, os.SEEK_END)
            return _parse_size_value(remote_file.tell())
    except Exception as exc:
        raise ValueError(
            "Cloud directory selective filtering incomplete: unable to inspect skipped object "
            f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
        ) from exc


def _detect_cloud_shared_skip_filter_route(
    fs: Any,
    file_url: str,
    prefix: bytes,
    size: int,
    *,
    size_is_known: bool,
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> str | None:
    """Route skipped cloud objects through the same bounded detector as local skips."""
    from modelaudit.utils.file.detection import (
        _COREML_PROTO_SIGNATURE_READ_BYTES,
        _XML_MODEL_SIGNATURE_READ_BYTES,
        FLAX_MSGPACK_STRUCTURE_READ_BYTES,
        JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES,
        LLAMAFILE_ROUTE_SCAN_BYTES,
        LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
        MXNET_SYMBOL_SIGNATURE_READ_BYTES,
        _could_be_xml_prefix,
        _could_start_coreml_model_proto,
        _is_executorch_binary_signature,
        _is_supported_llamafile_executable_header,
        detect_file_format_for_skip_filter,
    )

    probe_size = _CLOUD_CONTENT_SNIFF_BYTES
    is_llamafile_candidate = _is_supported_llamafile_executable_header(prefix[:4])
    normalized_prefix = prefix.lstrip()
    if normalized_prefix.startswith(b"\xef\xbb\xbf"):
        normalized_prefix = normalized_prefix[3:].lstrip()
    if normalized_prefix.startswith((b"{", b"[")):
        probe_size = max(probe_size, MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1)
    if not normalized_prefix and not size_is_known:
        probe_size = max(
            probe_size,
            JAX_JSON_CHECKPOINT_ROUTING_READ_BYTES + 1,
            MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1,
        )
    if prefix and prefix[0] in _MSGPACK_CONTAINER_MARKERS:
        probe_size = max(probe_size, FLAX_MSGPACK_STRUCTURE_READ_BYTES)
    if _could_start_coreml_model_proto(prefix[:16]):
        probe_size = max(probe_size, _COREML_PROTO_SIGNATURE_READ_BYTES)
    if _is_executorch_binary_signature(prefix[:8]):
        probe_size = max(probe_size, 64 * 1024)
    if _could_be_xml_prefix(prefix):
        probe_size = max(probe_size, _XML_MODEL_SIGNATURE_READ_BYTES)
    if is_llamafile_candidate:
        size = _get_cloud_content_size_for_routing(fs, file_url)
        size_is_known = True
        probe_size = max(probe_size, LLAMAFILE_ROUTE_SCAN_BYTES)

    if size_is_known:
        probe_size = min(size, probe_size)

    probe_read_size = probe_size if size_is_known else probe_size + 1
    probe = prefix
    if len(probe) < probe_read_size:
        probe = _read_cloud_content_prefix(fs, file_url, probe_read_size, sniff_budget)
    if (
        not size_is_known
        and len(probe) < probe_read_size
        and (sniff_budget is None or sniff_budget.prefix_is_complete(file_url))
    ):
        size = len(probe)
        size_is_known = True

    tail: bytes | None = None
    tail_offset: int | None = None
    if size_is_known and size > LLAMAFILE_ROUTE_SCAN_BYTES and is_llamafile_candidate:
        tail_size = min(size, LLAMAFILE_ROUTE_TAIL_SCAN_BYTES)
        tail_offset = size - tail_size
        tail = _read_cloud_content_range(fs, file_url, tail_offset, tail_size, sniff_budget)

    basename = _cloud_probe_basename(file_url)
    with tempfile.TemporaryDirectory(prefix="modelaudit_cloud_probe_") as temp_dir:
        probe_path = Path(temp_dir) / Path(basename).name
        with probe_path.open("wb") as handle:
            handle.write(probe)
            if tail is not None and tail_offset is not None:
                handle.seek(tail_offset)
                handle.write(tail)
            if size_is_known and size > probe_path.stat().st_size:
                handle.truncate(size)

        detected_format = detect_file_format_for_skip_filter(str(probe_path))
        return None if detected_format == "unknown" else detected_format


def _is_cloud_safetensors_routing_candidate(
    fs: Any,
    file_url: str,
    prefix: bytes,
    size: int,
    *,
    size_is_known: bool,
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> bool:
    """Recognize bounded remote SafeTensors framing without downloading tensor data."""
    if len(prefix) < 9:
        return False
    try:
        header_len = struct.unpack("<Q", prefix[:8])[0]
    except struct.error:
        return False
    if header_len <= 0 or (size_is_known and header_len > size - 8):
        return False

    from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES

    if header_len > SAFETENSORS_ROUTING_HEADER_PARSE_BYTES:
        return prefix[8:9] == b"{"

    header_probe = _read_cloud_content_prefix(fs, file_url, 8 + header_len, sniff_budget)
    if len(header_probe) != 8 + header_len or header_probe[8:9] != b"{":
        return False
    try:
        parsed_header = json.loads(header_probe[8:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed_header, dict)


def _detect_cloud_mxnet_symbol_route(
    fs: Any,
    file_url: str,
    prefix: bytes,
    size: int,
    *,
    size_is_known: bool,
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> str | None:
    """Return a bounded MXNet JSON route for a suffix-skipped remote object."""
    from modelaudit.utils.file.detection import MXNET_SYMBOL_SIGNATURE_READ_BYTES, _detect_mxnet_symbol_prefix_route

    normalized_prefix = prefix[3:] if prefix.startswith(b"\xef\xbb\xbf") else prefix
    if not normalized_prefix.lstrip().startswith(b"{"):
        return None

    max_probe_size = MXNET_SYMBOL_SIGNATURE_READ_BYTES + 1
    if size_is_known:
        max_probe_size = min(size, max_probe_size)
    mxnet_probe = _read_cloud_content_prefix(fs, file_url, max_probe_size, sniff_budget)
    mxnet_probe = mxnet_probe[3:] if mxnet_probe.startswith(b"\xef\xbb\xbf") else mxnet_probe
    if len(mxnet_probe) > MXNET_SYMBOL_SIGNATURE_READ_BYTES:
        return _detect_mxnet_symbol_prefix_route(
            mxnet_probe[:MXNET_SYMBOL_SIGNATURE_READ_BYTES],
            fail_closed_without_hint=True,
        )
    return _detect_mxnet_symbol_prefix_route(
        mxnet_probe,
        sample_is_prefix=(size_is_known and size > len(mxnet_probe))
        or (
            not size_is_known
            and (
                len(mxnet_probe) >= max_probe_size
                or (sniff_budget is not None and not sniff_budget.prefix_is_complete(file_url))
            )
        ),
        fail_closed_without_hint=True,
    )


def _detect_cloud_content_route_format(
    fs: Any,
    file_info: dict[str, Any],
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> str | None:
    """Return a content-routed model format for a remote object, if cheaply identifiable."""
    file_url = str(file_info["path"])
    prefix_limit = _CLOUD_CONTENT_SNIFF_BYTES
    prefix = _read_cloud_content_prefix(fs, file_url, prefix_limit, sniff_budget)
    if not prefix:
        if sniff_budget is not None:
            sniff_budget.require_classification_capacity(file_url)
        return None
    size = len(prefix)
    size_is_known = sniff_budget.prefix_is_complete(file_url) if sniff_budget is not None else size < prefix_limit

    from modelaudit.utils.file.detection import (
        PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
        PROTO0_1_MAX_PROBE_BYTES,
        _could_start_proto0_or_1_pickle,
        _is_cntk_signature,
        _is_content_routed_lightgbm_signature,
        _is_keras_zip_archive_content,
        _looks_like_proto0_or_1_pickle,
        _looks_like_uncompressed_tar_header,
        detect_format_from_magic_bytes,
    )
    from modelaudit.utils.file.filtering import _zip_archive_has_scannable_content

    if _looks_like_uncompressed_tar_header(prefix):
        return "tar"

    if _is_cntk_signature(prefix):
        return "cntk"

    if _is_content_routed_lightgbm_signature(prefix):
        return "lightgbm"

    mxnet_route = _detect_cloud_mxnet_symbol_route(
        fs,
        file_url,
        prefix,
        size,
        size_is_known=size_is_known,
        sniff_budget=sniff_budget,
    )
    if mxnet_route is not None:
        return mxnet_route

    if _is_cloud_safetensors_routing_candidate(
        fs,
        file_url,
        prefix,
        size,
        size_is_known=size_is_known,
        sniff_budget=sniff_budget,
    ):
        return "safetensors"

    if _could_start_proto0_or_1_pickle(prefix):
        max_probe_size = min(size, PROTO0_1_MAX_PROBE_BYTES) if size_is_known else PROTO0_1_MAX_PROBE_BYTES
        pickle_probe = _read_cloud_content_prefix(fs, file_url, max_probe_size, sniff_budget)
        if _looks_like_proto0_or_1_pickle(
            pickle_probe,
            sample_is_prefix=(not size_is_known and len(pickle_probe) >= max_probe_size) or size > len(pickle_probe),
        ):
            return "pickle"

    detected_format = detect_format_from_magic_bytes(
        prefix[:4],
        prefix[:8],
        prefix[:16],
        max(size, len(prefix)),
        None,
        pickle_probe_sample=prefix,
        pickle_probe_is_prefix=not size_is_known,
    )
    if (
        sniff_budget is not None
        and not size_is_known
        and detected_format in {"pickle", PICKLE_ROUTING_INCONCLUSIVE_FORMAT}
    ):
        cached_prefix = sniff_budget.cached_prefix(file_url)
        try:
            proven_size = _get_cloud_content_size_for_routing(fs, file_url)
        except ValueError:
            if detected_format != "pickle":
                raise
            proven_size = None
        if (
            proven_size is not None
            and proven_size >= len(cached_prefix)
            and proven_size - len(cached_prefix) <= sniff_budget.remaining_bytes
        ):
            try:
                reported_size = _parse_size_value(file_info.get("size"))
            except (TypeError, ValueError):
                reported_size = None
            size_proof_is_contradicted = reported_size is not None and reported_size > proven_size
            if not size_proof_is_contradicted:
                remaining_probe_bytes = proven_size - len(cached_prefix)
                complete_probe_limit = proven_size + int(remaining_probe_bytes < sniff_budget.remaining_bytes)
                try:
                    complete_probe = _read_cloud_content_prefix(fs, file_url, complete_probe_limit, sniff_budget)
                except ValueError:
                    if detected_format != "pickle":
                        raise
                else:
                    if len(complete_probe) != proven_size:
                        return detected_format
                    prefix = complete_probe
                    size = proven_size
                    size_is_known = True
                    detected_format = detect_format_from_magic_bytes(
                        prefix[:4],
                        prefix[:8],
                        prefix[:16],
                        size,
                        None,
                        pickle_probe_sample=prefix,
                        pickle_probe_is_prefix=False,
                    )
    if (
        detected_format == "unknown"
        and prefix[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + len(_TFLITE_MAGIC_BYTES)] == _TFLITE_MAGIC_BYTES
    ):
        return "tflite"
    if detected_format == "zip":
        incomplete_stream_reads = sniff_budget.incomplete_stream_reads if sniff_budget is not None else 0
        try:
            if sniff_budget is not None:
                actual_size = _get_cloud_content_size_for_routing(fs, file_url)
                cached_prefix = sniff_budget.cached_prefix(file_url)
                if actual_size <= len(cached_prefix):
                    with zipfile.ZipFile(io.BytesIO(cached_prefix[:actual_size]), "r") as archive:
                        return (
                            "zip"
                            if _is_keras_zip_archive_content(archive) or _zip_archive_has_scannable_content(archive)
                            else None
                        )
            with fs.open(file_url, "rb") as remote_file:
                zip_source = (
                    remote_file
                    if sniff_budget is None
                    else _BudgetedCloudContentReader(remote_file, sniff_budget, file_url, actual_size)
                )
                with zipfile.ZipFile(zip_source, "r") as archive:
                    return (
                        "zip"
                        if _is_keras_zip_archive_content(archive) or _zip_archive_has_scannable_content(archive)
                        else None
                    )
        except _CloudContentSniffBudgetExceeded as exc:
            assert sniff_budget is not None
            raise sniff_budget.classification_error(file_url) from exc
        except Exception as exc:
            if sniff_budget is not None and sniff_budget.incomplete_stream_reads > incomplete_stream_reads:
                raise sniff_budget.classification_error(file_url) from exc
            raise ValueError(
                "Cloud directory selective filtering incomplete: unable to classify skipped ZIP object "
                f"{_redact_cloud_path_for_display(file_url)}: {redact_cloud_error_for_display(exc, file_url)}"
            ) from exc
    if detected_format != "unknown":
        return detected_format

    shared_detected_format = _detect_cloud_shared_skip_filter_route(
        fs,
        file_url,
        prefix,
        size,
        size_is_known=size_is_known,
        sniff_budget=sniff_budget,
    )
    if shared_detected_format is None and sniff_budget is not None:
        if size_is_known or (
            sniff_budget.remaining_bytes == 0
            and _get_cloud_content_size_for_routing(fs, file_url) == len(sniff_budget.cached_prefix(file_url))
        ):
            return None
        sniff_budget.require_classification_capacity(file_url)
    return shared_detected_format


def _filter_scannable_cloud_files(
    files: list[dict[str, Any]],
    *,
    fs: Any,
    scannable_extensions: Collection[str] | None = None,
    scannable_filenames: Collection[str] | None = None,
    scanner_selection: Mapping[str, Any] | None = None,
    max_sniff_bytes: int | None = None,
    sniff_budget: _CloudContentSniffBudget | None = None,
) -> list[dict[str, Any]]:
    scannable = filter_scannable_files(
        files,
        scannable_extensions=scannable_extensions,
        scannable_filenames=scannable_filenames,
    )
    if (scannable_extensions is not None or scannable_filenames is not None) and scanner_selection is None:
        return scannable

    scannable_by_path = {str(file["path"]): file for file in scannable}
    if sniff_budget is None and max_sniff_bytes:
        sniff_budget = _CloudContentSniffBudget(max_sniff_bytes)
    scanner_policy = (
        policy_from_config({SCANNER_SELECTION_CONFIG_KEY: scanner_selection}) if scanner_selection is not None else None
    )
    for file_info in files:
        file_path = str(file_info["path"])
        suffix_selected = file_path in scannable_by_path
        if suffix_selected and not _selected_suffix_needs_content_validation(
            file_path,
            scannable_extensions,
            scanner_policy,
        ):
            continue
        try:
            detected_format = _detect_cloud_content_route_format(fs, file_info, sniff_budget)
        except Exception as exc:
            if suffix_selected:
                logger.debug("Unable to validate shared cloud suffix for %s: %s", file_path, exc)
                continue
            raise
        if detected_format is None:
            continue
        allowed = not (
            scanner_policy is not None
            and scanner_policy.active
            and not any(
                scanner_policy.allows(scanner_id) for scanner_id in scanner_ids_for_detected_format(detected_format)
            )
        )
        if not allowed:
            scannable_by_path.pop(file_path, None)
            continue
        routed_file_info = dict(file_info)
        routed_file_info["content_detected_format"] = detected_format
        scannable_by_path[file_path] = routed_file_info
    return list(scannable_by_path.values())


def _build_safe_local_path(
    base_url: str,
    file_url: str,
    download_path: Path,
    *,
    object_prefix_conflicts: Collection[str] = (),
) -> Path:
    """Build a collision-resistant local path for a cloud object."""
    relative_path = _cloud_object_relative_path(base_url, file_url)

    remote_components = relative_path.split("/")
    local_components: list[str] = []
    remote_prefix_components: list[str] = []
    for component in remote_components[:-1]:
        remote_prefix_components.append(component)
        remote_prefix = "/".join(remote_prefix_components)
        if remote_prefix in object_prefix_conflicts:
            local_components.append(_cloud_local_directory_component(component))
        else:
            local_components.append(_cloud_local_path_component(component))
    local_components.extend(_cloud_local_leaf_components(remote_components[-1]))
    local_relative_path = "/".join(local_components)
    resolved_path, is_safe = _resolve_cloud_path(local_relative_path, download_path)
    if not is_safe:
        raise ValueError(f"Encoded cloud object path escaped download directory: {file_url}")

    local_path = Path(resolved_path)
    if not _is_local_destination_within_directory(download_path, local_path):
        raise ValueError(f"Cloud object path escaped download directory: {file_url}")

    return local_path


def _protocol_less_cloud_relative_path(base_url: str, file_url: str) -> str:
    """Preserve provider-returned bucket/prefix paths when the scheme is omitted."""
    try:
        base = urlsplit(base_url)
        parsed_file = urlsplit(file_url)
        # Provider listings commonly return bare object keys. In that form,
        # URL delimiters are literal key text rather than query/fragment syntax.
        file_scheme = parsed_file.scheme.casefold()
        structured_file_url = file_scheme in {"s3", "gs", "gcs", "r2"} or (
            file_scheme in {"http", "https"} and _http_cloud_protocol(file_url) is not None
        )
        file_path = parsed_file.path if structured_file_url else file_url
        file_path = file_path.lstrip("/")
    except Exception:
        return _cloud_url_local_basename(file_url)

    if base.scheme.casefold() in {"http", "https"}:
        try:
            _protocol, canonical_url, _fs_args = get_cloud_filesystem_config(base_url)
            canonical = urlsplit(canonical_url)
            provider_prefix = "/".join(
                part.strip("/") for part in (canonical.netloc, canonical.path) if part.strip("/")
            )
        except ValueError:
            provider_prefix = "/".join(part.strip("/") for part in (base.netloc, base.path) if part.strip("/"))
    else:
        provider_prefix = "/".join(part.strip("/") for part in (base.netloc, base.path) if part.strip("/"))
    if provider_prefix and file_path.startswith(f"{provider_prefix}/"):
        return file_path[len(provider_prefix) + 1 :]
    if provider_prefix and file_path == provider_prefix:
        return _cloud_url_local_basename(file_url)
    if not structured_file_url:
        return file_path
    return _cloud_url_local_basename(file_url)


def _is_local_destination_within_directory(base_dir: Path, target: Path) -> bool:
    """Return True if a destination's resolved parent remains under base_dir."""
    return _is_resolved_path_within_base(base_dir.resolve(), target.parent.resolve())


def _validate_cloud_local_path(relative_path: str, file_url: str) -> None:
    """Reject cloud object paths that cannot safely become local files."""
    components = relative_path.split("/")
    leaf = relative_path.rsplit("/", 1)[-1]
    if (
        not relative_path
        or not leaf
        or leaf in {".", ".."}
        or "/" in leaf
        or (
            _uses_windows_filename_rules()
            and any(_is_unsafe_windows_cloud_filename(component) for component in components if component)
        )
    ):
        raise ValueError(f"Invalid cloud object basename: {redact_url_for_display(file_url)}")


_WINDOWS_RESERVED_FILE_STEMS = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    *(f"com{suffix}" for suffix in ("\u00b9", "\u00b2", "\u00b3")),
    *(f"lpt{suffix}" for suffix in ("\u00b9", "\u00b2", "\u00b3")),
}


def _is_unsafe_windows_cloud_filename(leaf: str) -> bool:
    """Return whether a cloud object leaf cannot safely name a Win32 file."""
    if leaf != leaf.rstrip(" ."):
        return True
    if any(ord(char) < 32 or char in '<>:"|?*' for char in leaf):
        return True
    stem = leaf.split(".", 1)[0].rstrip(" ").casefold()
    return stem in _WINDOWS_RESERVED_FILE_STEMS


def _uses_windows_filename_rules() -> bool:
    """Return whether local destinations must obey Win32 filename rules."""
    return os.name == "nt"


def _is_case_sensitive_directory(path: Path) -> bool:
    """Probe the target filesystem's case behavior without retaining a file."""
    probe_path: Path | None = None
    probe_fd = -1
    try:
        probe_fd, probe_name = tempfile.mkstemp(prefix=".modelaudit_case_probe_Aa", dir=path)
        probe_path = Path(probe_name)
        os.close(probe_fd)
        probe_fd = -1
        alternate = probe_path.with_name(probe_path.name.swapcase())
        if not alternate.exists():
            return True
        return not os.path.samefile(probe_path, alternate)
    except OSError:
        # Destination aliasing is security-sensitive, so uncertain filesystems
        # are treated conservatively as case-insensitive.
        return False
    finally:
        if probe_fd >= 0:
            os.close(probe_fd)
        if probe_path is not None:
            probe_path.unlink(missing_ok=True)


def _is_unicode_normalization_sensitive_directory(path: Path) -> bool:
    """Probe whether canonically equivalent names remain distinct on the target filesystem."""
    probe_path: Path | None = None
    probe_fd = -1
    try:
        probe_fd, probe_name = tempfile.mkstemp(prefix=".modelaudit_unicode_probe_\u00e9_", dir=path)
        probe_path = Path(probe_name)
        os.close(probe_fd)
        probe_fd = -1
        alternate = probe_path.with_name(probe_path.name.replace("\u00e9", "e\u0301", 1))
        if not alternate.exists():
            return True
        return not os.path.samefile(probe_path, alternate)
    except OSError:
        # Fail closed when the target filesystem's alias behavior cannot be probed.
        return False
    finally:
        if probe_fd >= 0:
            os.close(probe_fd)
        if probe_path is not None:
            probe_path.unlink(missing_ok=True)


def _local_destination_key(
    path: Path,
    *,
    case_sensitive: bool,
    unicode_normalization_sensitive: bool,
) -> str:
    """Return a canonical key for local download destination comparisons."""
    resolved = path.parent.resolve() / path.name
    normalized = os.path.normpath(str(resolved))
    if not unicode_normalization_sensitive:
        normalized = unicodedata.normalize("NFC", normalized)
    if not case_sensitive:
        normalized = normalized.lower()
    return normalized


def _local_destination_ancestor_keys(destination_key: str) -> Iterator[str]:
    """Yield canonical parent keys up to the filesystem root."""
    parent = os.path.dirname(destination_key)
    while parent and parent != destination_key:
        yield parent
        destination_key, parent = parent, os.path.dirname(parent)


def _build_cloud_download_plan(
    base_url: str,
    files: list[dict[str, Any]],
    download_path: Path,
) -> list[tuple[dict[str, Any], str, Path]]:
    """Resolve all cloud objects to local paths and fail on destination aliases."""
    planned: list[tuple[dict[str, Any], str, Path]] = []
    destinations: dict[str, str] = {}
    descendant_destinations: dict[str, str] = {}
    object_prefix_conflicts = _cloud_object_prefix_conflicts(
        base_url,
        [str(file_info["path"]) for file_info in files],
    )
    case_sensitive = _is_case_sensitive_directory(download_path)
    unicode_normalization_sensitive = _is_unicode_normalization_sensitive_directory(download_path)
    for file_info in files:
        file_url = str(file_info["path"])
        local_path = _build_safe_local_path(
            base_url,
            file_url,
            download_path,
            object_prefix_conflicts=object_prefix_conflicts,
        )
        destination_key = _local_destination_key(
            local_path,
            case_sensitive=case_sensitive,
            unicode_normalization_sensitive=unicode_normalization_sensitive,
        )
        previous_url = destinations.get(destination_key) or descendant_destinations.get(destination_key)
        ancestor_keys = tuple(_local_destination_ancestor_keys(destination_key))
        if previous_url is None:
            previous_url = next(
                (destinations[ancestor_key] for ancestor_key in ancestor_keys if ancestor_key in destinations),
                None,
            )
        if previous_url is not None:
            raise ValueError(
                "Cloud object path alias collision: "
                f"{_redact_cloud_path_for_display(previous_url)} and "
                f"{_redact_cloud_path_for_display(file_url)} overlap at {local_path.name}"
            )
        destinations[destination_key] = file_url
        for ancestor_key in ancestor_keys:
            descendant_destinations.setdefault(ancestor_key, file_url)
        planned.append((file_info, file_url, local_path))
    return planned


def _clear_directory_contents(path: Path) -> None:
    """Remove stale cache directory contents without deleting the directory itself."""
    if not path.exists():
        return
    for child in path.iterdir():
        _remove_path(child)


def _cached_path_within_size_limit(path: Path, max_size: int) -> bool:
    """Return whether a cached file or directory can be proven within a size limit."""
    try:
        if path.is_symlink():
            return False
        if path.is_file():
            return path.stat().st_size <= max_size
        if not path.is_dir():
            return False

        total_size = 0
        for child in path.rglob("*"):
            if child.is_symlink():
                return False
            if child.is_dir():
                continue
            if not child.is_file():
                return False
            total_size += child.stat().st_size
            if total_size > max_size:
                return False
        return True
    except OSError:
        return False


def _selected_cloud_download_size(
    fs: Any,
    files: list[dict[str, Any]],
    max_size: int,
    *,
    acquired_bytes: int = 0,
) -> int:
    """Return the late-bound size of selected objects, failing closed on unknown sizes."""
    selected_size = 0
    for file_info in files:
        file_url = str(file_info["path"])
        try:
            file_size = get_cloud_object_size(fs, file_url, strict=True)
        except ValueError as exc:
            raise ValueError(
                "Unable to enforce maximum cloud download size for selected object "
                f"{redact_url_for_display(file_url)} because its size could not be determined"
            ) from exc
        if file_size is None:
            raise ValueError(
                "Unable to enforce maximum cloud download size for selected object "
                f"{redact_url_for_display(file_url)} because its size could not be determined"
            )
        selected_size += file_size
        if acquired_bytes + selected_size > max_size:
            raise ValueError(
                f"File size ({format_size(acquired_bytes + selected_size)}) exceeds maximum allowed size "
                f"({format_size(max_size)})"
            )
    return selected_size


class _CloudDownloadBudgetExceeded(ValueError):
    """Raised when a cloud transfer exceeds its bounded acquisition budget."""


class _UnsafeCloudDownloadDestination(ValueError):
    """Raised when a local cloud download destination is unsafe to write."""


class _CloudDownloadBudget:
    """Track a cloud acquisition budget across objects and retry attempts."""

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self.remaining_bytes = max_bytes

    def read_size(self) -> int:
        """Return a bounded read size that can detect one byte over budget."""
        return min(_CLOUD_DOWNLOAD_CHUNK_BYTES, self.remaining_bytes + 1)

    def consume(self, byte_count: int) -> None:
        """Charge transferred bytes to the shared acquisition budget."""
        if byte_count > self.remaining_bytes:
            raise _CloudDownloadBudgetExceeded(
                f"Cloud download exceeds maximum allowed size ({format_size(self.max_bytes)})"
            )
        self.remaining_bytes -= byte_count


def _ensure_cloud_download_destination_is_safe(local_path: Path, base_dir: Path) -> None:
    """Reject escaped parents and final-component symlinks before writing an object."""
    if not _is_local_destination_within_directory(base_dir, local_path):
        raise _UnsafeCloudDownloadDestination(
            f"Refusing to download cloud object through escaped parent directory: {local_path.name}"
        )
    if local_path.is_symlink():
        raise _UnsafeCloudDownloadDestination(
            f"Refusing to download cloud object through symlink destination: {local_path.name}"
        )


def _download_cloud_object(
    fs: Any,
    file_url: str,
    local_path: Path,
    budget: _CloudDownloadBudget | None,
    base_dir: Path,
) -> int:
    """Download one cloud object while enforcing an optional transfer budget."""
    _ensure_cloud_download_destination_is_safe(local_path, base_dir)
    temp_fd, temp_name = tempfile.mkstemp(prefix=".modelaudit-", dir=local_path.parent)
    os.close(temp_fd)
    temp_path = Path(temp_name)
    temp_parent = temp_path.parent.resolve()
    bytes_written = 0
    try:
        if budget is None:
            fs.get(file_url, str(temp_path))
        else:
            with fs.open(file_url, "rb") as remote_file, temp_path.open("wb") as local_file:
                while True:
                    chunk = remote_file.read(budget.read_size())
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise TypeError("cloud filesystem returned non-bytes content")
                    budget.consume(len(chunk))
                    bytes_written += len(chunk)
                    local_file.write(chunk)

        _ensure_cloud_download_destination_is_safe(local_path, base_dir)
        os.replace(temp_path, local_path)
        return bytes_written
    except Exception:
        try:
            if temp_path.parent.resolve() == temp_parent:
                temp_path.unlink(missing_ok=True)
        except OSError as cleanup_error:
            logger.debug("Unable to remove temporary cloud download after failure: %s", cleanup_error)
        raise


def download_from_cloud(
    url: str,
    cache_dir: Path | None = None,
    max_size: int | None = None,
    use_cache: bool = True,
    show_progress: bool = True,
    selective: bool = True,
    stream_analyze: bool = False,
    scannable_extensions: Collection[str] | None = None,
    scanner_selection: Mapping[str, Any] | None = None,
    scannable_filenames: Collection[str] | None = None,
) -> Path | str:
    """Download a file or directory from cloud storage to a local path.

    Raises:
        ImportError: If the :mod:`fsspec` package is not installed.
        ValueError: If the cloud target cannot be analyzed or its type is unknown.
        ValueError: If the object exceeds ``max_size``.
    """
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. "
            "Try reinstalling modelaudit: 'pip install --force-reinstall modelaudit'"
        ) from e

    # Initialize cache
    cache = GCSCache(cache_dir) if use_cache else None

    # Analyze target
    analysis_max_size = max_size if not selective else None
    if analysis_max_size is None:
        metadata = _run_coroutine_sync(lambda: analyze_cloud_target(url))
    else:
        metadata = _run_coroutine_sync(lambda: analyze_cloud_target(url, max_size=analysis_max_size))

    # Ensure target was analyzed successfully
    if "error" in metadata or metadata.get("type") == "unknown":
        error_msg = redact_cloud_error_for_display(metadata.get("error", "Unknown cloud target type"), url)
        raise ValueError(f"Failed to analyze cloud target {redact_url_for_display(url)}: {error_msg}")

    etag = _metadata_etag(metadata)
    cache_scope = _cloud_directory_cache_scope(
        metadata,
        selective=selective,
        scannable_extensions=scannable_extensions,
        scannable_filenames=scannable_filenames,
        scanner_selection=scanner_selection,
    )
    if cache:
        cached_path = cache.get_cached_path(url, etag=etag, cache_scope=cache_scope)
        if cached_path:
            if max_size and not _cached_path_within_size_limit(cached_path, max_size):
                logger.warning(
                    "Ignoring cached version for %s because its local size exceeds or cannot be validated against "
                    "the maximum download size",
                    redact_url_for_display(url),
                )
            else:
                if show_progress:
                    click.echo(f"✓ Using cached version from {cached_path}")
                return cached_path

    # Check size limits
    try:
        size = _parse_size_value(metadata.get("total_size", metadata.get("size", 0)))
    except (TypeError, ValueError) as exc:
        if max_size and not (metadata["type"] == "directory" and selective):
            raise ValueError(
                "Unable to enforce maximum cloud download size for "
                f"{redact_url_for_display(url)}: invalid size metadata"
            ) from exc
        size = 0
    if max_size and size > max_size and not (metadata["type"] == "directory" and selective):
        raise ValueError(f"File size ({format_size(size)}) exceeds maximum allowed size ({format_size(max_size)})")

    # Show warning for large files
    if size > 100_000_000 and show_progress:  # 100MB
        click.echo(f"⚠️  Downloading {metadata['human_size']} (estimated time: {metadata['estimated_time']})")

    # Get filesystem before any acquisition, including stream previews, so size
    # enforcement does not rely only on provider summary metadata.
    fs_protocol, fs_url, fs_args = get_cloud_filesystem_config(url)
    fs = fsspec.filesystem(fs_protocol, **fs_args)

    # Check if we can use streaming analysis. Preview reads are still cloud
    # acquisition and must stay inside the same maximum-transfer budget.
    if stream_analyze and metadata.get("type") == "file":
        if max_size:
            try:
                stream_object_size = get_cloud_object_size(fs, fs_url, strict=True)
            except ValueError as exc:
                raise ValueError(
                    "Unable to enforce maximum cloud download size for "
                    f"{redact_url_for_display(url)} because the object size could not be determined"
                ) from exc
            if stream_object_size is None:
                raise ValueError(
                    "Unable to enforce maximum cloud download size for "
                    f"{redact_url_for_display(url)} because the object size could not be determined"
                )
            if stream_object_size > max_size:
                raise ValueError(
                    f"File size ({format_size(stream_object_size)}) exceeds maximum allowed size "
                    f"({format_size(max_size)})"
                )

        # Import here to avoid circular dependency
        from modelaudit.utils.file.streaming import get_streaming_preview

        preview = None if max_size else get_streaming_preview(url, max_bytes=1024)
        if preview and show_progress:
            click.echo(f"📄 File preview: {preview.get('detected_format', 'unknown')} format")

        # For streaming analysis, we don't need to download.
        # Return a special marker path (string to preserve prefix).
        return f"stream://{url}"

    # Create download directory
    if cache:
        # When using cache, download directly to cache location
        cache_key = cache.get_cache_key(url, cache_scope=cache_scope)
        download_path = _prepare_cache_subdirectory(cache.cache_dir, cache_key)
    elif cache_dir is None:
        download_path = Path(tempfile.mkdtemp(prefix="modelaudit_cloud_"))
    else:
        download_path = Path(cache_dir)
        download_path.mkdir(parents=True, exist_ok=True)

    should_cleanup_temp_dir = cache is None and cache_dir is None
    try:
        files: list[dict[str, Any]] | None = None
        content_sniff_budget = _CloudContentSniffBudget(max_size) if max_size else None
        if metadata["type"] == "directory":
            raw_files = metadata.get("files")
            if raw_files is None:
                files = []
            elif isinstance(raw_files, list):
                files = raw_files
            else:
                raise ValueError(f"Invalid metadata for 'files': expected list, got {type(raw_files).__name__}")

            if selective:
                # Content-route skipped objects before enforcing acquisition budgets.
                files = _filter_scannable_cloud_files(
                    files,
                    fs=fs,
                    scannable_extensions=scannable_extensions,
                    scannable_filenames=scannable_filenames,
                    scanner_selection=scanner_selection,
                    sniff_budget=content_sniff_budget,
                )
                if show_progress:
                    total = metadata.get("file_count", 0)
                    if files:
                        click.echo(f"Found {len(files)} scannable files out of {total} total files")
                    else:
                        click.echo(f"No scannable files found out of {total} total files")

            if not files:
                raise ValueError("No scannable model files found in directory")

        # Check available disk space before downloading
        object_size: int | None
        acquired_probe_bytes = (
            content_sniff_budget.max_bytes - content_sniff_budget.remaining_bytes
            if content_sniff_budget is not None
            else 0
        )
        if max_size and files is not None:
            object_size = _selected_cloud_download_size(
                fs,
                files,
                max_size,
                acquired_bytes=acquired_probe_bytes,
            )
        else:
            try:
                object_size = get_cloud_object_size(fs, fs_url, strict=True)
            except ValueError as exc:
                if max_size:
                    raise ValueError(
                        "Unable to enforce maximum cloud download size for "
                        f"{redact_url_for_display(url)} because the object size could not be determined"
                    ) from exc
                # Fall back to metadata-derived size when available. If no reliable size is
                # available, continue without a pre-download disk check (legacy behavior).
                if size > 0:
                    object_size = int(size)
                    if show_progress:
                        click.echo(f"⚠️  Falling back to metadata size estimate for disk check: {exc}")
                else:
                    object_size = None
                    if show_progress:
                        click.echo(
                            "⚠️  Unable to determine download size for "
                            f"{redact_url_for_display(url)}; continuing without disk check: {exc}"
                        )

        if object_size is not None:
            if max_size and object_size > max_size:
                raise ValueError(
                    f"File size ({format_size(object_size)}) exceeds maximum allowed size ({format_size(max_size)})"
                )
            has_space, message = check_disk_space(download_path, object_size)
            if not has_space:
                raise Exception(f"Cannot download from {redact_url_for_display(url)}: {message}")
        elif max_size:
            raise ValueError(
                "Unable to enforce maximum cloud download size for "
                f"{redact_url_for_display(url)} because the object size could not be determined"
            )

        # Download based on type
        if metadata["type"] == "directory":
            assert files is not None
            if cache:
                with tempfile.TemporaryDirectory(
                    prefix="modelaudit_cloud_plan_",
                    dir=download_path.parent,
                ) as preflight_dir:
                    _build_cloud_download_plan(fs_url, files, Path(preflight_dir))
                _clear_directory_contents(download_path)

            download_plan = _build_cloud_download_plan(fs_url, files, download_path)
            for _, _, local_path in download_plan:
                _ensure_cloud_download_destination_is_safe(local_path, download_path)

            # Download files
            download_budget = _CloudDownloadBudget(max_size) if max_size else None
            if download_budget is not None:
                download_budget.consume(acquired_probe_bytes)
            for file_info, file_url, local_path in download_plan:
                local_path.parent.mkdir(parents=True, exist_ok=True)

                if show_progress:
                    click.echo(f"Downloading {file_info['name']} ({file_info['human_size']})")

                @retry_with_backoff(
                    max_retries=3,
                    do_not_retry_on=(_CloudDownloadBudgetExceeded, _UnsafeCloudDownloadDestination),
                    verbose=show_progress,
                    sanitize_error=_cloud_error_sanitizer(file_url),
                )
                def download_file(url=file_url, path=local_path, budget=download_budget):
                    return _download_cloud_object(fs, url, path, budget, download_path)

                download_file()
        else:
            # Single file download
            local_file = _build_safe_local_path(url, url, download_path)
            file_name = local_file.name
            local_file.parent.mkdir(parents=True, exist_ok=True)
            download_budget = _CloudDownloadBudget(max_size) if max_size else None
            if cache:
                _remove_path(local_file)
            _ensure_cloud_download_destination_is_safe(local_file, download_path)

            @retry_with_backoff(
                max_retries=3,
                do_not_retry_on=(_CloudDownloadBudgetExceeded, _UnsafeCloudDownloadDestination),
                verbose=show_progress,
                sanitize_error=_cloud_error_sanitizer(url),
            )
            def download_single_file():
                return _download_cloud_object(fs, fs_url, local_file, download_budget, download_path)

            if show_progress and size > 100 * 1024 * 1024 * 1024:  # Show progress for files > 100GB
                with yaspin(text=f"Downloading {file_name}") as spinner:
                    download_single_file()
                    spinner.ok("✓")
            else:
                download_single_file()

            # Cache the download
            if cache:
                cache.cache_file(url, local_file, etag=etag)  # Cache the actual file, not the directory

            return local_file  # Return the actual file path for single files

        # Cache the download (for directories)
        if cache:
            cache.cache_file(url, download_path, etag=etag, cache_scope=cache_scope)

        return download_path
    except Exception:
        if should_cleanup_temp_dir and download_path.exists():
            shutil.rmtree(download_path, ignore_errors=True)
        raise


def download_from_cloud_streaming(
    url: str,
    cache_dir: Path | None = None,
    max_size: int | None = None,
    show_progress: bool = True,
    selective: bool = True,
    scannable_extensions: Collection[str] | None = None,
    scanner_selection: Mapping[str, Any] | None = None,
    scannable_filenames: Collection[str] | None = None,
) -> Iterator[tuple[Path, bool]]:
    """
    Download files from cloud storage one at a time (streaming mode).

    Yields (file_path, is_last) tuples for each downloaded file.
    Files are downloaded to temporary locations for immediate scanning.

    Args:
        url: Cloud storage URL (s3://, gs://, etc.)
        cache_dir: Optional cache directory (not used in streaming mode)
        max_size: Maximum total size allowed
        show_progress: Whether to show progress messages
        selective: Whether to filter to only scannable files

    Yields:
        Tuples of (file_path, is_last) for each downloaded file
    """
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. Install with 'pip install modelaudit[cloud]'"
        ) from e

    # Analyze target to get file list
    analysis_max_size = max_size if not selective else None
    if analysis_max_size is None:
        metadata = _run_coroutine_sync(lambda: analyze_cloud_target(url))
    else:
        metadata = _run_coroutine_sync(lambda: analyze_cloud_target(url, max_size=analysis_max_size))

    if "error" in metadata or metadata.get("type") == "unknown":
        error_msg = metadata.get("error", "Unknown cloud target type")
        raise ValueError(f"Failed to analyze cloud target {redact_url_for_display(url)}: {error_msg}")

    # Check size limits. Selective directory downloads are capped after filtering
    # so unrelated prefix contents do not reject a bounded acquisition.
    try:
        size = _parse_size_value(metadata.get("total_size", metadata.get("size", 0)))
    except (TypeError, ValueError) as exc:
        if max_size and not (metadata["type"] == "directory" and selective):
            raise ValueError(
                "Unable to enforce maximum cloud download size for "
                f"{redact_url_for_display(url)}: invalid size metadata"
            ) from exc
        size = 0
    if max_size and size > max_size and not (metadata["type"] == "directory" and selective):
        raise ValueError(f"Total size ({format_size(size)}) exceeds maximum allowed size ({format_size(max_size)})")

    # Get filesystem
    fs_protocol, fs_url, fs_args = get_cloud_filesystem_config(url)
    fs = fsspec.filesystem(fs_protocol, **fs_args)

    # Get list of files to download
    content_sniff_budget = _CloudContentSniffBudget(max_size) if max_size else None
    if metadata["type"] == "directory":
        raw_files = metadata.get("files")
        if raw_files is None:
            files = []
        elif isinstance(raw_files, list):
            files = raw_files
        else:
            raise ValueError(f"Invalid metadata for 'files': expected list, got {type(raw_files).__name__}")

        if selective:
            files = _filter_scannable_cloud_files(
                files,
                fs=fs,
                scannable_extensions=scannable_extensions,
                scannable_filenames=scannable_filenames,
                scanner_selection=scanner_selection,
                sniff_budget=content_sniff_budget,
            )
            if show_progress and files:
                click.echo(f"Found {len(files)} scannable files to stream")

        if not files:
            raise ValueError("No scannable model files found")
    else:
        # Single file
        files = [{"path": fs_url, "name": _cloud_url_basename(url), "size": metadata.get("size", 0)}]

    acquired_probe_bytes = (
        content_sniff_budget.max_bytes - content_sniff_budget.remaining_bytes if content_sniff_budget is not None else 0
    )
    if max_size:
        _selected_cloud_download_size(
            fs,
            files,
            max_size,
            acquired_bytes=acquired_probe_bytes,
        )

    # Create temp directory for downloads
    temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_stream_"))

    try:
        # Download files one at a time
        total_files = len(files)
        download_budget = _CloudDownloadBudget(max_size) if max_size else None
        if download_budget is not None:
            download_budget.consume(acquired_probe_bytes)
        download_plan = _build_cloud_download_plan(fs_url, files, temp_dir)
        for _, _, local_path in download_plan:
            _ensure_cloud_download_destination_is_safe(local_path, temp_dir)
        for i, (file_info, file_url, local_path) in enumerate(download_plan):
            file_name = file_info.get("name") or _cloud_url_basename(file_url)
            is_last = i == total_files - 1

            local_path.parent.mkdir(parents=True, exist_ok=True)

            if show_progress:
                click.echo(f"⬇️  Downloading {file_name} ({file_info.get('human_size', 'unknown size')})")

            @retry_with_backoff(
                max_retries=3,
                do_not_retry_on=(_CloudDownloadBudgetExceeded, _UnsafeCloudDownloadDestination),
                verbose=show_progress,
                sanitize_error=_cloud_error_sanitizer(file_url),
            )
            def download_file(url=file_url, path=local_path, budget=download_budget):
                return _download_cloud_object(fs, url, path, budget, temp_dir)

            download_file()

            yield (local_path, is_last)

    finally:
        # Clean up temp directory after all files are processed
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
