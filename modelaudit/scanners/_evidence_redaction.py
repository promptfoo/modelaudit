"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_EVIDENCE_VALUE = "<redacted>"
REDACTED_URL_CREDENTIALS = "<credentials-redacted>"

URL_RE = re.compile(r"(?i)\b(?:https?|ftp|s3|gs|file)://[^\s\"'<>]+")
SENSITIVE_QUERY_KEYS = {
    "access_key",
    "access-key",
    "access_token",
    "access-token",
    "api_key",
    "api-key",
    "apikey",
    "credential",
    "password",
    "passwd",
    "sas",
    "secret",
    "sig",
    "signature",
    "token",
    "x-amz-credential",
    "x-amz-security-token",
    "x-amz-signature",
}
AUTHORIZATION_VALUE_RE = re.compile(r"(?i)(\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?)" r"[^\s\"';&|]+")
BEARER_VALUE_RE = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b((?:api[_-]?key|access[_-]?token|token|password|passwd|secret|credential|signature|sig|sas)"
    r"\s*[:=]\s*)[^\s\"';&|]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b((?:api[_-]?key|access[_-]?token|token|password|passwd|secret|credential|signature|sig|sas)"
    r"\s*[:=]\s*)([\"']).*?\2"
)


def _redact_url(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return raw_url

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
    return f"{match.group(1)}{match.group(2)}{REDACTED_EVIDENCE_VALUE}{match.group(2)}"


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
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    return _truncate(redacted, max_chars)
