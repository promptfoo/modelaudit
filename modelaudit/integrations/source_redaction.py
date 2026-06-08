"""Credential-safe source identifier redaction for exported reports."""

import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel

from modelaudit.utils.sources.cloud_storage import (
    _normalize_percent_encoded_url_delimiters_for_display as _normalize_percent_encoded_url_delimiters_for_display,
)
from modelaudit.utils.sources.cloud_storage import is_sensitive_credential_key, is_stream_url
from modelaudit.utils.sources.cloud_storage import (
    normalize_escaped_url_delimiters_for_display as _normalize_escaped_url_delimiters_for_display,
)
from modelaudit.utils.sources.cloud_storage import redact_cloud_error_for_display as _redact_cloud_error_for_display
from modelaudit.utils.sources.cloud_storage import redact_stream_url_for_display as _redact_stream_url_for_display
from modelaudit.utils.sources.cloud_storage import redact_url_for_display as _redact_url_for_display

_URL_TEXT_CHARACTER = r'(?:[^\s"\'<>]|<redacted>|<credentials-redacted>)'
_URL_TOKEN_RE = re.compile(
    rf"(stream://[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+|[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+)",
    re.IGNORECASE,
)
_URL_LIKE_PREFIX_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_USERINFO_IDENTIFIER_RE = re.compile(
    r"^(?P<prefix>(?:(?P<scheme>[a-z][a-z0-9+.-]*):/{1,2}|//)?)"
    r"(?P<userinfo>[^/\s?#@]+(?::|%(?:25)*3a)[^/\s?#@]+(?:@|%(?:25)*40))"
    r"(?P<host>[^/\s?#]+)(?P<suffix>.*)$",
    re.IGNORECASE,
)
_USERINFO_TOKEN_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?P<identifier>"
    r"(?:(?:[a-z][a-z0-9+.-]*):/{1,2}|//)?"
    r"[^\s\"'<>/@?#]+(?::|%(?:25)*3a)[^\s\"'<>/@?#]+(?:@|%(?:25)*40)"
    r"[^\s\"'<>/?#]+(?:/[^\s\"'<>]*)?"
    r")",
    re.IGNORECASE,
)
_SCHEMELESS_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%.-])(?P<identifier>"
    rf"(?:(?:[a-z]:[\\/]|/|\.\.?/)?(?:[^\s\"'<>/?#]+/)+)"
    rf"[^\s\"'<>?#]+[?#]{_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_SCHEMELESS_ENCODED_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%.-])(?P<identifier>"
    rf"(?:(?:[a-z]:[\\/]|/|\.\.?/)?(?:[^\s\"'<>/?#]+/)+)"
    rf"[^\s\"'<>?#]+%(?:25)*(?:3f|23){_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_WINDOWS_DRIVE_PATH_RE = re.compile(r"^[a-z]:[\\/]", re.IGNORECASE)
_ENCODED_ASSIGNMENT_SEPARATOR_RE = re.compile(r"%(?:25)*3d", re.IGNORECASE)
_ENCODED_MAJOR_SUFFIX_RE = re.compile(r"%(?:25)*(?:3f|23)", re.IGNORECASE)
_ENCODED_FILENAME_SUFFIX_RE = re.compile(r"^[0-9A-Za-z._~-]+\.[0-9A-Za-z]{1,16}$")
_MAX_REDACTION_DEPTH = 32
_MAX_PROVENANCE_QUERY_CHARS = 4096
_MAX_PROVENANCE_PARAMS = 16
_SAFE_PROVENANCE_QUERY_KEYS = frozenset({"branch", "ref", "revision", "tag", "version"})
_SAFE_PROVENANCE_VALUE_RE = re.compile(r"^[0-9A-Za-z._~:+/-]{1,128}$")


def redact_source_identifier(source: str) -> str:
    """Return an exported source identifier without signed URL material."""
    normalized_source = _normalize_escaped_url_delimiters_for_display(source)
    if is_stream_url(normalized_source):
        safe_stream_url = _redact_stream_url_for_display(normalized_source[9:])
        return f"stream://{_redact_url_identifier(safe_stream_url)}"
    if _URL_LIKE_PREFIX_RE.match(normalized_source):
        parts = urlsplit(normalized_source)
        if (
            parts.scheme.casefold() == "file"
            and not parts.username
            and not parts.password
            and not parts.query
            and not parts.fragment
        ):
            return source
        return _redact_url_identifier(normalized_source)

    if _is_windows_or_unc_path(source):
        return source
    redacted_userinfo = _redact_userinfo_identifier(normalized_source)
    if redacted_userinfo is not None:
        return redacted_userinfo
    if _is_local_path_identifier(source):
        return source
    if _has_safe_schemeless_provenance_suffix(source):
        return source

    comparison_source = _normalize_percent_encoded_url_delimiters_for_display(normalized_source)
    path_prefix = re.split(r"[?#;&]", comparison_source, maxsplit=1)[0]
    if _has_sensitive_path_assignment(path_prefix):
        return "<source redacted>"
    redacted_source = _redact_cloud_error_for_display(comparison_source)
    if redacted_source != comparison_source:
        suffix_indexes = [index for delimiter in "?#;&" if (index := comparison_source.find(delimiter)) >= 0]
        if not suffix_indexes:
            return "<source redacted>"
        prefix = comparison_source[: min(suffix_indexes)]
        if _redact_cloud_error_for_display(prefix) != prefix:
            return "<source redacted>"
        return prefix or "<source redacted>"

    opaque_suffix_indexes = [index for delimiter in "?#" if (index := comparison_source.find(delimiter)) >= 0]
    if opaque_suffix_indexes:
        suffix_index = min(opaque_suffix_indexes)
        suffix = comparison_source[suffix_index + 1 :]
        if suffix and "=" not in suffix:
            return comparison_source[:suffix_index] or "<source redacted>"
    encoded_safe_source = _strip_encoded_opaque_suffix(comparison_source)
    if encoded_safe_source != comparison_source:
        return encoded_safe_source
    return source


def redact_source_text(text: str) -> str:
    """Redact signed URL tokens embedded in exported text fields."""
    normalized_text = _normalize_escaped_url_delimiters_for_display(text)
    redacted_text = _URL_TOKEN_RE.sub(lambda match: _redact_url_token(match.group(0)), normalized_text)
    redacted_text = _USERINFO_TOKEN_RE.sub(
        lambda match: redact_source_identifier(match.group("identifier")),
        redacted_text,
    )
    redacted_text = _SCHEMELESS_SUFFIX_TOKEN_RE.sub(
        lambda match: _redact_schemeless_suffix_token(match.group("identifier")),
        redacted_text,
    )
    redacted_text = _SCHEMELESS_ENCODED_SUFFIX_TOKEN_RE.sub(
        lambda match: _redact_encoded_suffix_token(match.group("identifier")),
        redacted_text,
    )
    return _redact_cloud_error_for_display(redacted_text)


def redact_source_reference(source: str) -> str:
    """Return a credential-safe source reference with bounded provenance context."""
    safe_identifier = redact_source_identifier(source)
    normalized_source = _normalize_percent_encoded_url_delimiters_for_display(
        _normalize_escaped_url_delimiters_for_display(source)
    )
    parts = urlsplit(normalized_source)

    safe_params: list[tuple[str, str]] = []
    for raw_params, key_prefix in ((parts.query, ""), (parts.fragment, "fragment-")):
        if not raw_params or len(raw_params) > _MAX_PROVENANCE_QUERY_CHARS:
            continue
        for key, value in parse_qsl(raw_params, keep_blank_values=True)[:_MAX_PROVENANCE_PARAMS]:
            normalized_key = key.casefold()
            if (
                normalized_key in _SAFE_PROVENANCE_QUERY_KEYS
                and not is_sensitive_credential_key(normalized_key)
                and _SAFE_PROVENANCE_VALUE_RE.fullmatch(value)
            ):
                safe_params.append((f"{key_prefix}{normalized_key}", value))
    if not safe_params:
        return safe_identifier
    return f"{safe_identifier}?{urlencode(sorted(safe_params))}"


def _has_safe_schemeless_provenance_suffix(source: str) -> bool:
    """Preserve bounded, explicitly non-sensitive assignments in local-looking names."""
    suffix_indexes = [index for delimiter in "?#;" if (index := source.find(delimiter)) >= 0]
    if not suffix_indexes:
        return False
    suffix = source[min(suffix_indexes) + 1 :]
    if not suffix or len(suffix) > _MAX_PROVENANCE_QUERY_CHARS:
        return False

    assignments = re.split(r"[&#;]", suffix)
    if len(assignments) > _MAX_PROVENANCE_PARAMS:
        return False
    for assignment in assignments:
        key, separator, value = assignment.partition("=")
        normalized_key = key.casefold()
        if (
            not separator
            or normalized_key not in _SAFE_PROVENANCE_QUERY_KEYS
            or is_sensitive_credential_key(normalized_key)
            or _SAFE_PROVENANCE_VALUE_RE.fullmatch(value) is None
        ):
            return False
    return True


def redact_source_value(value: Any) -> Any:
    """Recursively redact exported values that may contain source identifiers."""
    return _redact_source_value(value, seen=set(), depth=0)


def _redact_source_value(value: Any, *, seen: set[int], depth: int) -> Any:
    if depth > _MAX_REDACTION_DEPTH:
        return "<redacted>"
    if isinstance(value, BaseModel):
        return _redact_source_value(value.model_dump(mode="python"), seen=seen, depth=depth + 1)
    if isinstance(value, str):
        return redact_source_text(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            return redact_source_text(bytes(value).decode("utf-8"))
        except UnicodeDecodeError:
            return "<binary data>"
    if isinstance(value, dict):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return {
                _redact_mapping_key(key): (
                    "<redacted>"
                    if _mapping_key_requires_redaction(key)
                    else _redact_source_value(item, seen=seen, depth=depth + 1)
                )
                for key, item in value.items()
            }
        finally:
            seen.remove(id(value))
    if isinstance(value, list):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return [_redact_source_value(item, seen=seen, depth=depth + 1) for item in value]
        finally:
            seen.remove(id(value))
    if isinstance(value, tuple):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return tuple(_redact_source_value(item, seen=seen, depth=depth + 1) for item in value)
        finally:
            seen.remove(id(value))
    if isinstance(value, (set, frozenset)):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return sorted(
                (_redact_source_value(item, seen=seen, depth=depth + 1) for item in value),
                key=repr,
            )
        finally:
            seen.remove(id(value))
    return value


def _redact_userinfo_identifier(source: str) -> str | None:
    match = _USERINFO_IDENTIFIER_RE.match(source)
    if match is None:
        return None

    scheme = match.group("scheme")
    prefix = match.group("prefix")
    safe_url = _redact_url_identifier(
        f"{scheme or 'https'}://{match.group('userinfo')}{match.group('host')}{match.group('suffix')}"
    )
    if scheme:
        return safe_url

    safe_identifier = safe_url.removeprefix("https://")
    return f"//{safe_identifier}" if prefix == "//" else safe_identifier


def _redact_schemeless_suffix_token(source: str) -> str:
    if _URL_LIKE_PREFIX_RE.match(source):
        return source
    return redact_source_identifier(source)


def _redact_encoded_suffix_token(source: str) -> str:
    if _URL_LIKE_PREFIX_RE.match(source):
        return _redact_url_token(source)
    return redact_source_identifier(source)


def _redact_url_identifier(source: str) -> str:
    source = _strip_encoded_opaque_suffix(source)
    if source == "<source redacted>":
        return source
    safe_url = _redact_url_for_display(source)
    if safe_url == "<cloud URL redacted>":
        return safe_url
    return _redact_url_path_assignments(safe_url)


def _redact_url_path_assignments(source: str) -> str:
    try:
        parts = urlsplit(source)
    except Exception:
        return "<cloud URL redacted>"

    safe_segments: list[str] = []
    for segment in parts.path.split("/"):
        safe_segments.append(_redact_path_segment_assignment(segment))
    return urlunsplit((parts.scheme, parts.netloc, "/".join(safe_segments), parts.query, parts.fragment))


def _redact_path_segment_assignment(segment: str) -> str:
    if "=" in segment:
        key = segment.split("=", 1)[0]
    else:
        encoded_separator = _ENCODED_ASSIGNMENT_SEPARATOR_RE.search(segment)
        if encoded_separator is None:
            return segment
        key = segment[: encoded_separator.start()]
    if is_sensitive_credential_key(key):
        return f"{key}=<redacted>"
    return segment


def _has_sensitive_path_assignment(path: str) -> bool:
    return any(_redact_path_segment_assignment(segment) != segment for segment in path.split("/"))


def _strip_encoded_opaque_suffix(source: str) -> str:
    if _normalize_percent_encoded_url_delimiters_for_display(source) != source:
        return source
    encoded_suffix = _ENCODED_MAJOR_SUFFIX_RE.search(source)
    if encoded_suffix is None:
        return source
    prefix = source[: encoded_suffix.start()]
    suffix = source[encoded_suffix.end() :]
    if _looks_like_encoded_filename_continuation(prefix, suffix):
        return source
    return prefix or "<source redacted>"


def _looks_like_encoded_filename_continuation(prefix: str, suffix: str) -> bool:
    try:
        prefix_name = os.path.basename(urlsplit(prefix).path)
    except Exception:
        return False
    return "." not in prefix_name and _ENCODED_FILENAME_SUFFIX_RE.fullmatch(suffix) is not None


def _is_windows_or_unc_path(source: str) -> bool:
    return bool(_WINDOWS_DRIVE_PATH_RE.match(source)) or source.startswith("\\\\")


def _is_local_path_identifier(source: str) -> bool:
    if os.path.isabs(source) or _is_windows_or_unc_path(source):
        return True
    if source.startswith(("./", "../", ".\\", "..\\", "~/", "~\\", "\\\\")):
        return True
    try:
        return os.path.lexists(source)
    except OSError:
        return False


def _mapping_key_requires_redaction(key: Any) -> bool:
    if is_sensitive_credential_key(key):
        return True
    if isinstance(key, bytes):
        try:
            key.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return False
    return not (isinstance(key, (str, int, float, bool)) or key is None)


def _redact_url_token(url: str) -> str:
    """Preserve benign query context while removing credentials from evidence URLs."""
    if is_stream_url(url):
        return redact_source_identifier(url)
    encoded_safe_url = _strip_encoded_opaque_suffix(url)
    if encoded_safe_url != url:
        return _redact_url_path_assignments(encoded_safe_url)
    preserve_redacted_params = "<redacted>" in url
    path_redacted_url = _redact_url_path_assignments(url)
    redacted_url = _redact_cloud_error_for_display(path_redacted_url)
    parts = urlsplit(path_redacted_url) if redacted_url == path_redacted_url else urlsplit(redacted_url)

    safe_query = _filter_url_params(parts.query, preserve_redacted_params=preserve_redacted_params)
    safe_fragment = _filter_url_params(parts.fragment, preserve_redacted_params=preserve_redacted_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, safe_query, safe_fragment))


def _filter_url_params(value: str, *, preserve_redacted_params: bool) -> str:
    """Keep structured safe URL parameters and discard opaque credential material."""
    safe_parts: list[str] = []
    for part in re.split(r"[&;]", value):
        if "=" not in part:
            continue
        if part.endswith("=<redacted>") and not preserve_redacted_params:
            continue
        safe_parts.append(part)
    return "&".join(safe_parts)


def _redact_mapping_key(value: Any) -> str | int | float | bool | None:
    redacted = redact_source_value(value)
    if isinstance(redacted, (str, int, float, bool)) or redacted is None:
        return redacted
    return str(redacted)
