"""URL normalization retained for historical SARIF identity compatibility."""

import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

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
