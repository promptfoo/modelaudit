"""Credential-safe source identifier redaction for exported reports."""

import os
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from pydantic import AnyUrl, BaseModel

from modelaudit.utils.sources.cloud_storage import (
    _normalize_percent_encoded_url_authority_for_display as _normalize_percent_encoded_url_authority_for_display,
)
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
    rf"(?<![0-9A-Za-z+._%-])"
    rf"(stream://[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+|[a-z][a-z0-9+.-]*://{_URL_TEXT_CHARACTER}+)",
    re.IGNORECASE,
)
_URL_LIKE_PREFIX_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_USERINFO_IDENTIFIER_RE = re.compile(
    r"^(?P<prefix>(?:(?P<scheme>[a-z][a-z0-9+.-]*):/{1,2}|//)?)"
    r"(?P<userinfo>[^/\s?#@]+(?:@|%(?:25)*40))"
    r"(?P<host>[^/\s?#@]+)(?P<suffix>.*)$",
    re.IGNORECASE,
)
_USERINFO_TOKEN_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?P<identifier>"
    r"(?:(?:[a-z][a-z0-9+.-]*):/{1,2}|//)?"
    r"[^\s\"'<>/@?#]+(?:@|%(?:25)*40)"
    r"[^\s\"'<>/\\?#@]+(?:[\\/][^\s\"'<>]*)?"
    r")",
    re.IGNORECASE,
)
_SCHEMELESS_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%.-])(?P<identifier>"
    rf"(?:(?:[a-z]:[\\/]|/|\.\.?/)?(?:[^\s\"'<>/?#]+/)+)"
    rf"[^\s\"'<>?#]+[?#;]{_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_SCHEMELESS_ENCODED_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%.-])(?P<identifier>"
    rf"(?:(?:[a-z]:[\\/]|/|\.\.?/)?(?:[^\s\"'<>/?#]+/)+)"
    rf"[^\s\"'<>?#]+%(?:25)*(?:3f|23|3b){_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_BARE_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%@.-])(?P<identifier>"
    rf"[0-9A-Za-z._~-]+\.[A-Za-z][0-9A-Za-z]{{0,15}}"
    rf"[?#;]{_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_BARE_ENCODED_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%@.-])(?P<identifier>"
    rf"[0-9A-Za-z._~-]+\.[A-Za-z][0-9A-Za-z]{{0,15}}"
    rf"%(?:25)*(?:3f|23|3b){_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_EMAIL_SUFFIX_TOKEN_RE = re.compile(
    rf"(?<![0-9A-Za-z_%+.-])(?P<identifier>"
    rf"[0-9A-Za-z._%+-]+@[0-9A-Za-z.-]+\.[A-Za-z]{{2,}}"
    rf"[?#]{_URL_TEXT_CHARACTER}+"
    rf")",
    re.IGNORECASE,
)
_WINDOWS_DRIVE_PATH_RE = re.compile(r"^[a-z]:[\\/]", re.IGNORECASE)
_ENCODED_ASSIGNMENT_SEPARATOR_RE = re.compile(r"%(?:25)*(?:3a|3d)", re.IGNORECASE)
_ENCODED_MAJOR_SUFFIX_RE = re.compile(r"%(?:25)*(?:3f|23|3b)", re.IGNORECASE)
_ENCODED_FILENAME_SUFFIX_RE = re.compile(r"^[0-9A-Za-z._~-]+\.[0-9A-Za-z]{1,16}$")
_ENCODED_AT_RE = re.compile(r"%(?:25)*40", re.IGNORECASE)
_EXPORT_KEY_TOKEN = r"(?:[0-9A-Za-z_%.-]|\\(?:u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}))+"
_EXPORT_BRACKET_KEY = rf"\[\s*(?:{_EXPORT_KEY_TOKEN}|\"{_EXPORT_KEY_TOKEN}\"|'{_EXPORT_KEY_TOKEN}')?\s*\]"
_EXPORT_QUOTED_VALUE = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
_ESCAPED_KEY_CHARACTER_RE = re.compile(
    r"\\(?:u(?P<unicode>[0-9A-Fa-f]{4})|x(?P<hex>[0-9A-Fa-f]{2}))",
    re.IGNORECASE,
)
_MAX_REDACTION_DEPTH = 32
_MAX_SOURCE_TEXT_CHARS = 256 * 1024
_MAX_PROVENANCE_QUERY_CHARS = 4096
_MAX_PROVENANCE_PARAMS = 16
_SAFE_PROVENANCE_QUERY_KEYS = frozenset({"branch", "ref", "revision", "tag", "version"})
_SAFE_PROVENANCE_VALUE_RE = re.compile(r"^[0-9A-Za-z._~:+/-]{1,128}$")
_EXPORT_ASSIGNMENT_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?:"
    rf"(?P<key_escape>\\?)(?P<quote>[\"'])"
    rf"(?P<quoted_key>{_EXPORT_KEY_TOKEN}(?:{_EXPORT_BRACKET_KEY})*)(?P=key_escape)(?P=quote)"
    rf"|(?P<key>{_EXPORT_KEY_TOKEN}(?:{_EXPORT_BRACKET_KEY})*))"
    r"(?P<separator>\s*(?::|(?<![!<=>])=(?!=)|<<?-)\s*)",
    re.IGNORECASE,
)
_EXPORT_COMPARISON_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?:"
    rf"(?P<key_escape>\\?)(?P<quote>[\"'])"
    rf"(?P<quoted_key>{_EXPORT_KEY_TOKEN}(?:{_EXPORT_BRACKET_KEY})*)(?P=key_escape)(?P=quote)"
    rf"|(?P<key>{_EXPORT_KEY_TOKEN}(?:{_EXPORT_BRACKET_KEY})*))"
    r"(?P<separator>\s*={2,}\s*)",
    re.IGNORECASE,
)
_EXPORT_EQUALS_KEY_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?P<key>[0-9A-Za-z_%.-]+)(?P<separator>\s*=\s*)",
    re.IGNORECASE,
)
_EXPORT_HEADER_KEY_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?P<quote>[\"']?)(?P<key>[0-9A-Za-z_%.-]+)(?P=quote)(?P<separator>\s*:\s*)",
    re.IGNORECASE,
)
_EXPORT_ENCODED_SEPARATOR_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])(?P<key>[0-9A-Za-z_%.-]+?)"
    r"(?P<separator>%(?:25)*(?P<separator_code>3a|3d)(?:%(?:25)*20)*)",
    re.IGNORECASE,
)
_EXPORT_OPTION_RE = re.compile(
    rf"(?<!\S)(?P<prefix>--(?P<key>[0-9A-Za-z_%.-]+)\s+)(?P<value>{_EXPORT_QUOTED_VALUE}|[^\s,;]+)",
    re.IGNORECASE,
)
_EXPORT_AUTHORIZATION_RE = re.compile(
    r"(?<![0-9A-Za-z_%.-])"
    r"(?P<prefix>(?P<key>(?:proxy[_.-]?)?authorization)\s+"
    r"(?!(?:algorithm|enabled|header|method|name|status|type)\b)"
    r"[0-9A-Za-z][0-9A-Za-z+._-]{0,63}\s+)"
    rf"(?P<value>{_EXPORT_QUOTED_VALUE}|[^\s,;]+)",
    re.IGNORECASE,
)
_EXPORT_VALUE_BOUNDARY_RE = re.compile(r"[\r\n,;)}\]]|\s+(?=--[0-9A-Za-z])")
_MAX_CREDENTIAL_KEY_DECODE_PASSES = 4
_EXPORT_CREDENTIAL_KEY_ALIASES = frozenset(
    {
        "dbpassword",
        "googleaccessid",
        "jwt",
        "passphrase",
        "pwd",
        "refreshtoken",
        "secretkey",
        "sessionid",
        "sessiontoken",
    }
)
_EXPORT_CREDENTIAL_KEY_TOKENS = frozenset(
    {
        "auth",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "session",
        "sig",
        "signature",
        "token",
    }
)
_EXPORT_CREDENTIAL_KEY_NEAR_MATCHES = frozenset(
    {
        "accesstokencount",
        "apikeyhint",
        "apikeyvalueset",
        "authorizationheadername",
        "authorizationmethod",
        "authorizationstatus",
        "googleaccessidentifier",
        "mysecretingredient",
        "passwordpolicy",
        "privatekeyformat",
        "proxyauthorizationenabled",
        "requestsignaturealgorithm",
        "sessiontokencache",
        "signaturealgorithm",
        "tokencount",
        "tokentypeid",
        "tokentypeids",
        "tokenizer",
    }
)
_EXPORT_SAFE_METADATA_KEY_SUFFIXES = (
    "authmethod",
    "authenticationmethod",
    "authorizationmethod",
    "passwordlength",
    "sessionduration",
    "signaturealgorithm",
    "tokencount",
)
_CREDENTIAL_SHAPED_PROVENANCE_VALUE_RE = re.compile(
    r"(?:gh[pousr]_[0-9A-Za-z_]{20,}|sk-[0-9A-Za-z_-]{12,}|AKIA[0-9A-Z]{16}|"
    r"eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,})"
)


def redact_source_identifier(source: str) -> str:
    """Return an exported source identifier without signed URL material."""
    if len(source) > _MAX_SOURCE_TEXT_CHARS:
        return "<source redacted>"
    normalized_source = _normalize_escaped_url_delimiters_for_display(source)
    if is_stream_url(normalized_source):
        safe_stream_url = _redact_stream_url_for_display(normalized_source[9:])
        if safe_stream_url == "<cloud URL redacted>":
            return "stream://<cloud URL redacted>"
        return f"stream://{redact_source_text(safe_stream_url)}"
    if _URL_LIKE_PREFIX_RE.match(normalized_source):
        try:
            authority_normalized_source = _normalize_percent_encoded_url_authority_for_display(normalized_source)
            parts = urlsplit(authority_normalized_source)
        except Exception:
            return "<cloud URL redacted>"
        if parts.scheme.casefold() == "file" and not parts.username and not parts.password:
            comparison_source = _normalize_percent_encoded_url_delimiters_for_display(normalized_source)
            comparison_parts = urlsplit(comparison_source)
            if _has_sensitive_path_assignment(comparison_parts.path):
                return _redact_url_identifier(comparison_source)
            if not comparison_parts.query and not comparison_parts.fragment:
                return source
            if _has_safe_schemeless_provenance_suffix(source):
                return source
            return _redact_url_identifier(comparison_source)
        return _redact_url_identifier(normalized_source)
    if normalized_source.startswith("//") and not normalized_source.startswith("///"):
        if os.name != "nt" and _local_path_exists(source):
            return source
        safe_url = _redact_url_identifier(f"https:{normalized_source}")
        return safe_url.removeprefix("https:")
    if _local_path_exists(source):
        return source

    if _is_local_path_identifier(source):
        return _redact_local_path_identifier(source)
    redacted_userinfo = _redact_userinfo_identifier(normalized_source)
    if redacted_userinfo is not None:
        return redacted_userinfo
    if "@" in normalized_source or _ENCODED_AT_RE.search(normalized_source):
        nested_userinfo = _USERINFO_TOKEN_RE.sub(
            _redact_nested_userinfo_token,
            normalized_source,
        )
        if nested_userinfo != normalized_source:
            return nested_userinfo

    comparison_source = _normalize_percent_encoded_url_delimiters_for_display(normalized_source)
    suffix_indexes = [index for delimiter in "?#;" if (index := comparison_source.find(delimiter)) >= 0]
    if suffix_indexes:
        suffix_index = min(suffix_indexes)
        prefix = comparison_source[:suffix_index]
        suffix = comparison_source[suffix_index + 1 :]
        if _contains_sensitive_assignment(suffix):
            return prefix or "<source redacted>"
        if _contains_opaque_suffix_part(suffix):
            return prefix or "<source redacted>"
    path_prefix = re.split(r"[?#;&]", comparison_source, maxsplit=1)[0]
    if _has_sensitive_path_assignment(path_prefix):
        return "<source redacted>"
    if _has_safe_schemeless_provenance_suffix(source):
        if _redact_export_alias_assignments(path_prefix) != path_prefix:
            return "<source redacted>"
        return source
    redacted_source = _redact_export_alias_assignments(comparison_source)
    if redacted_source != comparison_source:
        suffix_indexes = [index for delimiter in "?#;&" if (index := comparison_source.find(delimiter)) >= 0]
        if not suffix_indexes:
            return "<source redacted>"
        prefix = comparison_source[: min(suffix_indexes)]
        if _redact_export_alias_assignments(prefix) != prefix:
            return "<source redacted>"
        return prefix or "<source redacted>"
    encoded_safe_source = _strip_encoded_opaque_suffix(comparison_source)
    if encoded_safe_source != comparison_source:
        return encoded_safe_source
    return source


def redact_source_text(text: str) -> str:
    """Redact signed URL tokens embedded in exported text fields."""
    return _redact_source_text(text, preserve_redacted_assignments=False)


def _redact_prevalidated_source_text(text: str) -> str:
    """Redact source identifiers after a domain sanitizer validated markers."""
    return _redact_source_text(text, preserve_redacted_assignments=True)


def _redact_source_text(text: str, *, preserve_redacted_assignments: bool) -> str:
    if len(text) > _MAX_SOURCE_TEXT_CHARS:
        return "<redacted oversized value>"
    normalized_text = _normalize_escaped_url_delimiters_for_display(text)
    normalized_text = _redact_url_adjacent_assignments(normalized_text)
    redacted_text = _URL_TOKEN_RE.sub(lambda match: _redact_url_token(match.group(0)), normalized_text)
    if "@" in redacted_text or _ENCODED_AT_RE.search(redacted_text):
        redacted_text = _USERINFO_TOKEN_RE.sub(
            lambda match: _redact_userinfo_text_token(redacted_text, match), redacted_text
        )
    if "/" in redacted_text or "\\" in redacted_text:
        redacted_text = _SCHEMELESS_SUFFIX_TOKEN_RE.sub(
            lambda match: _redact_schemeless_suffix_token(match.group("identifier")),
            redacted_text,
        )
        redacted_text = _SCHEMELESS_ENCODED_SUFFIX_TOKEN_RE.sub(
            lambda match: _redact_encoded_suffix_token(match.group("identifier")),
            redacted_text,
        )
    redacted_text = _BARE_SUFFIX_TOKEN_RE.sub(
        lambda match: redact_source_identifier(match.group("identifier")),
        redacted_text,
    )
    redacted_text = _BARE_ENCODED_SUFFIX_TOKEN_RE.sub(
        lambda match: redact_source_identifier(match.group("identifier")),
        redacted_text,
    )
    redacted_text = _EMAIL_SUFFIX_TOKEN_RE.sub(
        lambda match: _redact_email_suffix_token(match.group("identifier")),
        redacted_text,
    )
    return _redact_assignments_outside_url_tokens(
        redacted_text,
        preserve_redacted_assignments=preserve_redacted_assignments,
    )


def _redact_assignments_outside_url_tokens(
    text: str,
    *,
    preserve_redacted_assignments: bool,
) -> str:
    """Redact free-text assignments after source tokens have been sanitized."""
    return _redact_export_alias_assignments(
        text,
        preserve_redacted_assignments=preserve_redacted_assignments,
    )


def _redact_url_adjacent_assignments(text: str) -> str:
    """Redact credential fields swallowed by a permissive URL token match."""
    url_spans = [(match.start(), match.end()) for match in _URL_TOKEN_RE.finditer(text)]
    if not url_spans:
        return text

    assignment_starts: list[int] = []
    for pattern in (_EXPORT_EQUALS_KEY_RE, _EXPORT_HEADER_KEY_RE, _EXPORT_ENCODED_SEPARATOR_RE):
        for match in pattern.finditer(text):
            if not _is_sensitive_export_key(match.group("key")):
                continue
            preceding = text[: match.start()].rstrip()
            if not preceding or preceding[-1] not in ",;":
                continue
            if any(start <= match.start() < end for start, end in url_spans):
                assignment_starts.append(match.start())
    if not assignment_starts:
        return text
    first_assignment = min(assignment_starts)
    return f"{text[:first_assignment]}{_redact_export_alias_assignments(text[first_assignment:])}"


def redact_source_reference(source: str) -> str:
    """Return a credential-safe source reference with bounded provenance context."""
    safe_identifier = redact_source_identifier(source)
    if safe_identifier == source:
        return safe_identifier
    normalized_source = _normalize_percent_encoded_url_delimiters_for_display(
        _normalize_escaped_url_delimiters_for_display(source)
    )
    try:
        parts = urlsplit(normalized_source)
    except Exception:
        return safe_identifier

    safe_params: list[tuple[str, str]] = []
    for raw_params, key_prefix in ((parts.query, ""), (parts.fragment, "fragment-")):
        if not raw_params or len(raw_params) > _MAX_PROVENANCE_QUERY_CHARS:
            continue
        for key, value in parse_qsl(raw_params, keep_blank_values=True)[:_MAX_PROVENANCE_PARAMS]:
            normalized_key = key.casefold()
            if (
                normalized_key in _SAFE_PROVENANCE_QUERY_KEYS
                and not _is_sensitive_export_key(normalized_key)
                and _SAFE_PROVENANCE_VALUE_RE.fullmatch(value)
                and not _looks_like_credential_value(value)
            ):
                safe_params.append((f"{key_prefix}{normalized_key}", value))
    if not safe_params:
        return safe_identifier
    return f"{safe_identifier}?{urlencode(sorted(safe_params))}"


def _has_safe_schemeless_provenance_suffix(source: str) -> bool:
    """Preserve bounded, explicitly non-sensitive assignments in local-looking names."""
    normalized_source = _normalize_percent_encoded_url_delimiters_for_display(
        _normalize_escaped_url_delimiters_for_display(source)
    )
    suffix_indexes = [index for delimiter in "?#;" if (index := normalized_source.find(delimiter)) >= 0]
    if not suffix_indexes:
        return False
    suffix = normalized_source[min(suffix_indexes) + 1 :]
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
            or _is_sensitive_export_key(normalized_key)
            or _SAFE_PROVENANCE_VALUE_RE.fullmatch(value) is None
            or _looks_like_credential_value(value)
        ):
            return False
    return True


def redact_source_value(value: Any) -> Any:
    """Recursively redact exported values that may contain source identifiers."""
    return _redact_source_value(
        value,
        seen=set(),
        depth=0,
        preserve_redacted_assignments=False,
    )


def redact_prevalidated_source_value(value: Any) -> Any:
    """Redact source identifiers after a domain sanitizer validated markers."""
    return _redact_source_value(
        value,
        seen=set(),
        depth=0,
        preserve_redacted_assignments=True,
    )


def _redact_source_value(
    value: Any,
    *,
    seen: set[int],
    depth: int,
    preserve_redacted_assignments: bool,
) -> Any:
    if depth > _MAX_REDACTION_DEPTH:
        return "<redacted>"
    if isinstance(value, BaseModel):
        return _redact_source_value(
            value.model_dump(mode="python"),
            seen=seen,
            depth=depth + 1,
            preserve_redacted_assignments=preserve_redacted_assignments,
        )
    if isinstance(value, AnyUrl):
        return redact_source_text(str(value))
    if isinstance(value, str):
        if preserve_redacted_assignments:
            return _redact_prevalidated_source_text(value)
        return redact_source_text(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            decoded = bytes(value).decode("utf-8")
            if preserve_redacted_assignments:
                return _redact_prevalidated_source_text(decoded)
            return redact_source_text(decoded)
        except UnicodeDecodeError:
            return "<binary data>"
    if isinstance(value, dict):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            redacted_mapping: dict[Any, Any] = {}
            next_key_occurrences: dict[str, int] = {}
            for key, item in value.items():
                redacted_key = _unique_redacted_mapping_key(
                    _redact_mapping_key(key),
                    redacted_mapping,
                    next_occurrences=next_key_occurrences,
                )
                redacted_mapping[redacted_key] = (
                    "<redacted>"
                    if _mapping_key_requires_redaction(key)
                    else _redact_source_value(
                        item,
                        seen=seen,
                        depth=depth + 1,
                        preserve_redacted_assignments=preserve_redacted_assignments,
                    )
                )
            return redacted_mapping
        finally:
            seen.remove(id(value))
    if isinstance(value, list):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return [
                _redact_source_value(
                    item,
                    seen=seen,
                    depth=depth + 1,
                    preserve_redacted_assignments=preserve_redacted_assignments,
                )
                for item in value
            ]
        finally:
            seen.remove(id(value))
    if isinstance(value, tuple):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return tuple(
                _redact_source_value(
                    item,
                    seen=seen,
                    depth=depth + 1,
                    preserve_redacted_assignments=preserve_redacted_assignments,
                )
                for item in value
            )
        finally:
            seen.remove(id(value))
    if isinstance(value, (set, frozenset)):
        if id(value) in seen:
            return "<redacted recursive value>"
        seen.add(id(value))
        try:
            return sorted(
                (
                    _redact_source_value(
                        item,
                        seen=seen,
                        depth=depth + 1,
                        preserve_redacted_assignments=preserve_redacted_assignments,
                    )
                    for item in value
                ),
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
    userinfo = match.group("userinfo")
    suffix = match.group("suffix")
    if (
        not prefix
        and not suffix.startswith(("/", "\\"))
        and re.search(
            r":|%(?:25)*3a",
            userinfo,
            re.IGNORECASE,
        )
        is None
    ):
        return None
    safe_url = _redact_url_identifier(f"{scheme or 'https'}://{userinfo}{match.group('host')}{suffix}")
    if scheme:
        return safe_url

    safe_identifier = safe_url.removeprefix("https://")
    return f"//{safe_identifier}" if prefix == "//" else safe_identifier


def _redact_userinfo_text_token(text: str, match: re.Match[str]) -> str:
    identifier = match.group("identifier")
    if match.start() > 0 and text[match.start() - 1] in "/\\":
        authority = re.split(r"[\\/]", identifier, maxsplit=1)[0]
        decoded_authority, _ = _bounded_unquote(authority)
        userinfo = decoded_authority.rsplit("@", 1)[0]
        if ":" not in userinfo:
            return identifier
    return redact_source_identifier(identifier)


def _redact_nested_userinfo_token(match: re.Match[str]) -> str:
    identifier = match.group("identifier")
    return _redact_userinfo_identifier(identifier) or identifier


def _redact_schemeless_suffix_token(source: str) -> str:
    if _URL_LIKE_PREFIX_RE.match(source):
        return source
    return redact_source_identifier(source)


def _redact_encoded_suffix_token(source: str) -> str:
    if _URL_LIKE_PREFIX_RE.match(source):
        return _redact_url_token(source)
    return redact_source_identifier(source)


def _redact_email_suffix_token(source: str) -> str:
    suffix_indexes = [index for delimiter in "?#" if (index := source.find(delimiter)) >= 0]
    if not suffix_indexes:
        return source
    suffix_index = min(suffix_indexes)
    suffix = source[suffix_index + 1 :]
    if _contains_sensitive_assignment(suffix) or _contains_opaque_suffix_part(suffix):
        return source[:suffix_index]
    return source


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
    separator_indexes = [index for delimiter in "=:" if (index := segment.find(delimiter)) >= 0]
    encoded_separator = _ENCODED_ASSIGNMENT_SEPARATOR_RE.search(segment)
    if encoded_separator is not None:
        separator_indexes.append(encoded_separator.start())
    if not separator_indexes:
        return segment
    key = segment[: min(separator_indexes)]
    if _is_sensitive_export_key(key):
        return f"{key}=<redacted>"
    return segment


def _has_sensitive_path_assignment(path: str) -> bool:
    return any(_redact_path_segment_assignment(segment) != segment for segment in re.split(r"[\\/]", path))


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


def _local_path_exists(source: str) -> bool:
    try:
        return os.path.lexists(source)
    except (OSError, ValueError):
        return False


def _redact_local_path_suffix(source: str) -> str:
    normalized_source = _normalize_percent_encoded_url_delimiters_for_display(
        _normalize_escaped_url_delimiters_for_display(source)
    )
    suffix_indexes = [index for delimiter in "?#;" if (index := normalized_source.find(delimiter)) >= 0]
    if not suffix_indexes:
        return source
    suffix_index = min(suffix_indexes)
    suffix = normalized_source[suffix_index + 1 :]
    if _contains_sensitive_assignment(suffix) or _contains_opaque_suffix_part(suffix):
        return normalized_source[:suffix_index] or "<source redacted>"
    return source


def _redact_local_path_identifier(source: str) -> str:
    safe_source = _redact_local_path_suffix(source)
    normalized_source = _normalize_percent_encoded_url_delimiters_for_display(
        _normalize_escaped_url_delimiters_for_display(safe_source)
    )
    path_prefix = re.split(r"[?#;]", normalized_source, maxsplit=1)[0]
    if _has_sensitive_path_assignment(path_prefix):
        return "<source redacted>"
    if safe_source != source:
        if _has_local_userinfo_credentials(path_prefix, allow_username_only=True):
            return "<source redacted>"
        return safe_source
    if _is_windows_or_unc_path(source):
        return source
    if _has_local_userinfo_credentials(path_prefix):
        return "<source redacted>"
    return source


def _mapping_key_requires_redaction(key: Any) -> bool:
    if isinstance(key, str):
        if _mapping_key_is_direct_sensitive_assignment(key):
            return True
        if redact_source_identifier(key) != key:
            return False
    if _is_sensitive_export_key(key):
        return True
    if isinstance(key, bytes):
        try:
            key.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return False
    return not (isinstance(key, (str, int, float, bool)) or key is None)


def _mapping_key_is_direct_sensitive_assignment(key: str) -> bool:
    normalized_key = _normalize_escaped_url_delimiters_for_display(key)
    decoded_key, _ = _bounded_unquote(normalized_key)
    stripped_key = decoded_key.lstrip()
    for pattern in (_EXPORT_EQUALS_KEY_RE, _EXPORT_HEADER_KEY_RE, _EXPORT_ENCODED_SEPARATOR_RE):
        match = pattern.match(stripped_key)
        if match is not None and _is_sensitive_export_key(match.group("key")):
            return True
    return False


def _has_local_userinfo_credentials(path: str, *, allow_username_only: bool = False) -> bool:
    for segment in re.split(r"[\\/]", path):
        decoded_segment, decode_incomplete = _bounded_unquote(segment)
        if decode_incomplete or "@" not in decoded_segment:
            continue
        userinfo, _ = decoded_segment.rsplit("@", 1)
        if allow_username_only and userinfo:
            return True
        if ":" in userinfo and userinfo.split(":", 1)[1]:
            return True
    return False


def _contains_sensitive_assignment(value: str) -> bool:
    decoded_value, decode_incomplete = _bounded_unquote(value)
    if decode_incomplete:
        return True
    for part in re.split(r"[?&#;]", decoded_value):
        for separator in ("=", ":"):
            if separator not in part:
                continue
            key, assignment_value = part.split(separator, 1)
            if _looks_like_credential_value(assignment_value.strip()):
                return True
            if _is_sensitive_export_key(key.strip()) and assignment_value.strip() not in {
                "<redacted>",
                "<credentials-redacted>",
            }:
                return True
    return False


def _contains_opaque_suffix_part(value: str) -> bool:
    decoded_value, decode_incomplete = _bounded_unquote(value)
    if decode_incomplete:
        return True
    return any(part and "=" not in part for part in re.split(r"[?&#;]", decoded_value))


def _bounded_unquote(value: str) -> tuple[str, bool]:
    decoded_value = value
    for _ in range(_MAX_CREDENTIAL_KEY_DECODE_PASSES):
        next_value = unquote(decoded_value)
        if next_value == decoded_value:
            return decoded_value, False
        decoded_value = next_value
    return decoded_value, unquote(decoded_value) != decoded_value


def _is_sensitive_export_key(key: object) -> bool:
    if isinstance(key, bytes):
        try:
            key = key.decode("utf-8")
        except UnicodeDecodeError:
            return False
    if not isinstance(key, str):
        return False

    key = _ESCAPED_KEY_CHARACTER_RE.sub(
        lambda match: chr(int(match.group("unicode") or match.group("hex"), 16)),
        key,
    )
    decoded_key, decode_incomplete = _bounded_unquote(key)
    if decode_incomplete:
        return True
    separated_key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", decoded_key)
    separated_key = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", separated_key)
    normalized_key = re.sub(r"[^a-z0-9]+", "", separated_key.casefold())
    if normalized_key in _EXPORT_CREDENTIAL_KEY_NEAR_MATCHES:
        return False
    key_tokens = {token for token in re.split(r"[^a-z0-9]+", separated_key.casefold()) if token}
    if normalized_key.endswith(_EXPORT_SAFE_METADATA_KEY_SUFFIXES):
        return False
    return (
        is_sensitive_credential_key(decoded_key)
        or normalized_key in _EXPORT_CREDENTIAL_KEY_ALIASES
        or bool(key_tokens & _EXPORT_CREDENTIAL_KEY_TOKENS)
    )


def _redact_export_alias_assignments(
    value: str,
    *,
    preserve_redacted_assignments: bool = False,
) -> str:
    value = _normalize_encoded_sensitive_assignment_separators(value)
    if not preserve_redacted_assignments:
        # Prevalidated text already had sensitive comparisons redacted by a
        # domain sanitizer that preserves command operands; generic exports
        # need this backstop so `key == value` cannot smuggle a credential.
        value = _redact_sensitive_comparison_values(value)
    redacted_parts: list[str] = []
    previous_end = 0
    for match in _EXPORT_ASSIGNMENT_RE.finditer(value):
        if match.start() < previous_end:
            continue
        key = match.group("key") or match.group("quoted_key")
        if not _is_sensitive_export_key(key) or _assignment_value_is_already_redacted(value, match.end()):
            continue
        value_end = _assignment_value_end(value, match.end(), key=key)
        if preserve_redacted_assignments:
            marker_start = _first_redaction_marker_start(value, match.end(), value_end)
            if marker_start is not None:
                next_sensitive_start = _next_sensitive_assignment_start(value, match.end(), value_end)
                if next_sensitive_start is None or marker_start < next_sensitive_start:
                    # The upstream sanitizer already redacted within this value.
                    continue
                # The marker belongs to a later assignment; stop short of it so
                # this raw value is redacted without erasing validated context.
                value_end = next_sensitive_start
        redacted_parts.extend((value[previous_end : match.end()], "<redacted>"))
        previous_end = value_end
    redacted_parts.append(value[previous_end:])
    redacted = "".join(redacted_parts)

    def redact_whitespace_value(match: re.Match[str]) -> str:
        if not _is_sensitive_export_key(match.group("key")):
            return match.group(0)
        return f"{match.group('prefix')}<redacted>"

    redacted = _EXPORT_OPTION_RE.sub(redact_whitespace_value, redacted)
    return _EXPORT_AUTHORIZATION_RE.sub(redact_whitespace_value, redacted)


def _redact_sensitive_comparison_values(value: str) -> str:
    """Redact values compared against sensitive keys in generic export text."""
    redacted_parts: list[str] = []
    previous_end = 0
    for match in _EXPORT_COMPARISON_RE.finditer(value):
        if match.start() < previous_end:
            continue
        key = match.group("key") or match.group("quoted_key")
        if _is_sensitive_export_key(key):
            value_end = _assignment_value_end(value, match.end(), key=key)
            # Skip only values that are exactly a marker; an embedded marker
            # followed by raw content must not shield the tail.
            if value[match.end() : value_end].strip() in ("<redacted>", "<credentials-redacted>"):
                continue
            redacted_parts.extend((value[previous_end : match.end()], "<redacted>"))
            previous_end = value_end
            continue
        literal_end = _sensitive_reversed_comparison_literal_end(value, match)
        if literal_end is not None:
            redacted_parts.extend(
                (value[previous_end : match.start()], "<redacted>", value[match.start("separator") : literal_end])
            )
            previous_end = literal_end
    redacted_parts.append(value[previous_end:])
    return "".join(redacted_parts)


def _sensitive_reversed_comparison_literal_end(value: str, match: re.Match[str]) -> int | None:
    """Return the right-literal end when a literal candidate value is compared to a key name."""
    if match.group("quoted_key") is None:
        return None
    value_start = match.end()
    while value_start < len(value) and value[value_start].isspace() and value[value_start] not in "\r\n":
        value_start += 1
    if value_start >= len(value) or value[value_start] not in {'"', "'"}:
        return None
    quote_end = _find_closing_quote(value, value_start, value[value_start])
    if quote_end < 0:
        return None
    if not _is_sensitive_export_key(value[value_start + 1 : quote_end]):
        return None
    return quote_end + 1


def _first_redaction_marker_start(value: str, start: int, end: int) -> int | None:
    marker_starts = [
        marker_start
        for marker_start in (value.find(marker, start, end) for marker in ("<redacted>", "<credentials-redacted>"))
        if marker_start != -1
    ]
    return min(marker_starts) if marker_starts else None


def _next_sensitive_assignment_start(value: str, start: int, end: int) -> int | None:
    for match in _EXPORT_ASSIGNMENT_RE.finditer(value, start, end):
        key = match.group("key") or match.group("quoted_key")
        if _is_sensitive_export_key(key):
            return match.start()
    return None


def _normalize_encoded_sensitive_assignment_separators(value: str) -> str:
    normalized = value
    sensitive_separators = [
        match
        for match in _EXPORT_ENCODED_SEPARATOR_RE.finditer(normalized)
        if _is_sensitive_export_key(match.group("key"))
    ]
    for match in reversed(sensitive_separators):
        separator = ":" if match.group("separator_code").casefold() == "3a" else "="
        normalized = f"{normalized[: match.start('separator')]}{separator}{normalized[match.end('separator') :]}"
    return normalized


def _looks_like_credential_value(value: str) -> bool:
    return _CREDENTIAL_SHAPED_PROVENANCE_VALUE_RE.search(value) is not None


def _assignment_value_end(value: str, start: int, *, key: str) -> int:
    value_start = start
    while value_start < len(value) and value[value_start].isspace() and value[value_start] not in "\r\n":
        value_start += 1
    if value_start < len(value) and value[value_start] in {'"', "'"}:
        quote = value[value_start]
        quote_end = _find_closing_quote(value, value_start, quote)
        if quote_end >= 0:
            return quote_end + 1
        start = value_start
    if value_start < len(value) and value[value_start] in {"|", ">"}:
        return _yaml_block_value_end(value, value_start)

    if _is_cookie_export_key(key):
        line_end = re.search(r"[\r\n]", value[start:])
        return len(value) if line_end is None else start + line_end.start()
    boundary = _EXPORT_VALUE_BOUNDARY_RE.search(value, start)
    return len(value) if boundary is None else boundary.start()


def _yaml_block_value_end(value: str, indicator_start: int) -> int:
    line_end = re.search(r"\r?\n", value[indicator_start:])
    if line_end is None:
        return len(value)
    cursor = indicator_start + line_end.end()
    while cursor < len(value):
        next_line_end = re.search(r"\r?\n", value[cursor:])
        end = len(value) if next_line_end is None else cursor + next_line_end.start()
        line = value[cursor:end]
        if line.strip() and not line[0].isspace():
            return cursor - (2 if value[cursor - 2 : cursor] == "\r\n" else 1)
        if next_line_end is None:
            return len(value)
        cursor += next_line_end.end()
    return len(value)


def _find_closing_quote(value: str, quote_start: int, quote: str) -> int:
    escaped = False
    for index in range(quote_start + 1, len(value)):
        character = value[index]
        if character == "\\":
            escaped = not escaped
            continue
        if character == quote and not escaped:
            return index
        escaped = False
    return -1


def _assignment_value_is_already_redacted(value: str, start: int) -> bool:
    value_start = start
    while value_start < len(value) and value[value_start].isspace():
        value_start += 1
    for marker in ("<redacted>", "<credentials-redacted>"):
        if not value.startswith(marker, value_start):
            continue
        marker_end = value_start + len(marker)
        if marker_end == len(value) or value[marker_end].isspace() or value[marker_end] in "/?&#;,)}]":
            return True
    return False


def _is_cookie_export_key(key: str) -> bool:
    decoded_key, _ = _bounded_unquote(key)
    return re.sub(r"[^a-z0-9]+", "", decoded_key.casefold()) in {"cookie", "setcookie"}


def _redact_url_token(url: str) -> str:
    """Preserve benign query context while removing credentials from evidence URLs."""
    if is_stream_url(url):
        return redact_source_identifier(url)
    url = _normalize_percent_encoded_url_delimiters_for_display(url)
    encoded_safe_url = _strip_encoded_opaque_suffix(url)
    if encoded_safe_url != url:
        return _redact_url_path_assignments(encoded_safe_url)
    preserve_redacted_params = "<redacted>" in url
    path_redacted_url = _redact_url_path_assignments(url)
    try:
        original_parts = urlsplit(path_redacted_url)
        safe_base = _redact_url_identifier(path_redacted_url)
        if safe_base in {"<source redacted>", "<cloud URL redacted>"}:
            return safe_base
        safe_parts = urlsplit(safe_base)
        component_probe = urlunsplit(("https", "redaction.invalid", "/", original_parts.query, original_parts.fragment))
        redacted_parts = urlsplit(_redact_cloud_error_for_display(component_probe))
    except Exception:
        return "<cloud URL redacted>"

    safe_query = _filter_url_params(redacted_parts.query, preserve_redacted_params=preserve_redacted_params)
    safe_fragment = _filter_url_params(redacted_parts.fragment, preserve_redacted_params=preserve_redacted_params)
    return urlunsplit((safe_parts.scheme, safe_parts.netloc, safe_parts.path, safe_query, safe_fragment))


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
    return redact_source_text(str(redacted))


def _unique_redacted_mapping_key(
    key: Any,
    mapping: dict[Any, Any],
    *,
    next_occurrences: dict[str, int],
) -> Any:
    """Preserve entries whose credential-safe mapping keys collide."""
    if key not in mapping:
        next_occurrences.setdefault(str(key), 2)
        return key
    base_key = str(key)
    occurrence = next_occurrences.get(base_key, 2)
    candidate = f"{base_key}#modelaudit-redacted-key-{occurrence}"
    while candidate in mapping:
        occurrence += 1
        candidate = f"{base_key}#modelaudit-redacted-key-{occurrence}"
    next_occurrences[base_key] = occurrence + 1
    return candidate
