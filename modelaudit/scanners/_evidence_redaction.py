"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from modelaudit.detectors.network_comm import _redact_url_path_tokens

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(?:https?|wss?|ftp|tcp|udp|s3|gs|file)://[^\s\"'<>]+")
SENSITIVE_QUERY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access-key",
        "access_token",
        "access-token",
        "api_key",
        "api-key",
        "apikey",
        "auth_token",
        "auth-token",
        "client_secret",
        "client-secret",
        "credential",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "private-key",
        "refresh_token",
        "refresh-token",
        "sas",
        "secret",
        "secret_key",
        "secret-key",
        "sig",
        "signature",
        "token",
        "x-amz-credential",
        "x-amz-security-token",
        "x-amz-signature",
        "x-goog-credential",
        "x-goog-signature",
    }
)
SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[_.-])*"
    r"(?:access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret|credential|"
    r"password|passwd|private[_-]?key|pwd|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
    r"(?:[_.-][a-z0-9]+)*"
)
SENSITIVE_CONTAINER_KEY: Final[str] = rf"(?:{SENSITIVE_ASSIGNMENT_KEY}|authorization)"
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?)" r"[^\s\"';&|]+"
)
AUTH_SCHEME_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\b(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}")
QUOTED_VALUE_PATTERN: Final[str] = r"(?P<quote>\"\"\"|'''|[\"'])(?:\\.|(?!(?P=quote)).)*?(?P=quote)"
UNTERMINATED_QUOTED_VALUE_PATTERN: Final[str] = r"(?P<quote>\"\"\"|'''|[\"'])(?:\\.|(?!(?P=quote)).)*\Z"
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)[^\s\"';&|,}}]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*){QUOTED_VALUE_PATTERN}"
)
QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*:\s*)"
    rf"{QUOTED_VALUE_PATTERN}"
)
SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*=\s*)"
    rf"{QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*){UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*:\s*)"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*=\s*)"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<prefix>(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*:\s*)"
    r"[^\s\"';&|,}]+"
)
SUBSCRIPTED_SENSITIVE_UNQUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<prefix>\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*=\s*)"
    r"[^\s\"';&|,\]}]+"
)
HTML_QUERY_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"(?i)&amp;")
NESTED_SENSITIVE_QUERY_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?:^|[?&;])(?:amp;)?{SENSITIVE_ASSIGNMENT_KEY}\s*[:=]"
)


def _redact_malformed_url(raw_url: str) -> str:
    """Fail closed for URL-like strings that the parser rejects."""
    scheme_match = re.match(r"(?i)^([a-z][a-z0-9+.-]*://)(.*)$", raw_url)
    if scheme_match is None:
        return REDACTED_EVIDENCE_VALUE

    scheme, rest = scheme_match.groups()
    rest = re.split(r"[?#]", rest, maxsplit=1)[0]
    if "@" not in rest:
        return f"{scheme}{REDACTED_EVIDENCE_VALUE}"

    return f"{scheme}{REDACTED_URL_CREDENTIALS}@{rest.rsplit('@', 1)[1]}"


def _redact_url(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return _redact_malformed_url(raw_url)

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = f"{REDACTED_URL_CREDENTIALS}@{netloc.rsplit('@', 1)[1]}"
    hostname = parsed.hostname or ""
    path = _redact_url_path_tokens(parsed.scheme.lower(), hostname.lower(), parsed.path) if hostname else parsed.path

    query_items = []
    normalized_query = HTML_QUERY_SEPARATOR_RE.sub("&", parsed.query).replace(";", "&")
    for key, value in parse_qsl(normalized_query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS or _contains_nested_sensitive_query_assignment(value):
            query_items.append((key, REDACTED_EVIDENCE_VALUE))
        else:
            query_items.append((key, value))

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            path,
            urlencode(query_items, doseq=True, safe="<>"),
            "",
        )
    )


def _contains_nested_sensitive_query_assignment(value: str) -> bool:
    """Recognize credential assignments nested inside encoded query values."""
    decoded = value
    for _ in range(3):
        next_decoded = unquote_plus(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return bool(NESTED_SENSITIVE_QUERY_ASSIGNMENT_RE.search(decoded))


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    quote = match.group("quote")
    return f"{match.group('prefix')}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_unterminated_quoted_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{match.group('quote')}{REDACTED_EVIDENCE_VALUE}"


def _redact_unquoted_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{REDACTED_EVIDENCE_VALUE}"


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int | None = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = URL_RE.sub(_redact_url, text)
    redacted = QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = AUTH_SCHEME_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SUBSCRIPTED_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    return redacted if max_chars is None else _truncate(redacted, max_chars)
