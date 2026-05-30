"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(?:https?|ftp|s3|gs|file)://[^\s\"'<>]+")
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
    }
)
SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[_-])*"
    r"(?:access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret|credential|"
    r"password|passwd|private[_-]?key|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
)
QUOTED_SENSITIVE_KEY: Final[str] = rf"(?:{SENSITIVE_ASSIGNMENT_KEY}|authorization)"
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?)" r"[^\s\"';&|]+"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?![rubf]*[\"'])[^\s\"';&|]+"
)
PYTHON_STRING_PREFIX: Final[str] = r"[rubf]*"
PYTHON_QUOTE_DELIMITER: Final[str] = r"(?:'''|\"\"\"|[\"'])"
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:\\.|(?!\4)[\s\S])*\4"
)
QUOTED_SENSITIVE_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)([\"']{QUOTED_SENSITIVE_KEY}[\"']\s*:\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:\\.|(?!\3)[\s\S])*\3"
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

    query_items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            query_items.append((key, REDACTED_EVIDENCE_VALUE))
        else:
            query_items.append((key, value))

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            urlencode(query_items, doseq=True, safe="<>"),
            "",
        )
    )


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    quote = match.group(4)
    return f"{match.group(1)}{match.group(3)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_quoted_key_value(match: re.Match[str]) -> str:
    quote = match.group(3)
    return f"{match.group(1)}{match.group(2)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = URL_RE.sub(_redact_url, text)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_SENSITIVE_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    return _truncate(redacted, max_chars)
