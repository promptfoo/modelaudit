"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import json
import re
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(?:https?|ftp|s3|gs|file)://[^\s\"'<>]+")
SENSITIVE_QUERY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access-key",
        "access_key_id",
        "access-key-id",
        "access_token",
        "access-token",
        "api_key",
        "api-key",
        "apikey",
        "aws_access_key_id",
        "aws-access-key-id",
        "aws_secret_access_key",
        "aws-secret-access-key",
        "aws_session_token",
        "aws-session-token",
        "auth_token",
        "auth-token",
        "authorization",
        "client_secret",
        "client-secret",
        "credential",
        "password",
        "passwd",
        "private_key",
        "private-key",
        "proxy_authorization",
        "proxy-authorization",
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
    r"(?:access[_-]?key[_-]?id|access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret|"
    r"credential|"
    r"password|passwd|private[_-]?key|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
)
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?)" r"[^\s\"';&|]+"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)[^\s\"';&|]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
QUOTED_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<key_quote>[\"'])(?P<key>[A-Za-z][A-Za-z0-9_-]{0,80})(?P=key_quote)"
    r"(?P<separator>\s*:\s*)(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
GENERIC_QUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?P<key>[A-Za-z][A-Za-z0-9_-]{0,80})(?P<separator>\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
GENERIC_CONTAINER_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?P<key>[A-Za-z][A-Za-z0-9_-]{0,80})(?P<separator>\s*[:=]\s*)"
    r"(?P<value>\[(?:\\.|[^\]\\])*\]|\{(?:\\.|[^}\\])*\})"
)
GENERIC_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?P<key>[A-Za-z][A-Za-z0-9_-]{0,80})(?P<separator>\s*[:=]\s*)[^\s\"';&|]+"
)
SENSITIVE_DETAIL_KEY_SUFFIXES: Final[tuple[str, ...]] = (
    "accesskeyid",
    "accesskey",
    "accesstoken",
    "apikey",
    "authtoken",
    "clientsecret",
    "credential",
    "password",
    "passwd",
    "privatekey",
    "refreshtoken",
    "sas",
    "secretkey",
    "signature",
    "secret",
    "sig",
    "token",
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
        if _is_sensitive_detail_key(key):
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
    quote = match.group("value")[0]
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_quoted_key_value(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    return (
        f"{match.group('key_quote')}{match.group('key')}{match.group('key_quote')}"
        f"{match.group('separator')}{match.group('value')[0]}"
        f"{REDACTED_EVIDENCE_VALUE}{match.group('value')[0]}"
    )


def _redact_generic_quoted_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    quote = match.group("value")[0]
    return f"{match.group('key')}{match.group('separator')}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_generic_container_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    return f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}"


def _redact_generic_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    return f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}"


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(parsed, (dict, list)):
                return _truncate(json.dumps(redact_evidence_value(parsed), separators=(",", ":")), max_chars)

    redacted = URL_RE.sub(_redact_url, text)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = GENERIC_CONTAINER_ASSIGNMENT_RE.sub(_redact_generic_container_assignment, redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = QUOTED_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
    redacted = GENERIC_QUOTED_ASSIGNMENT_RE.sub(_redact_generic_quoted_assignment, redacted)
    redacted = GENERIC_ASSIGNMENT_RE.sub(_redact_generic_assignment, redacted)
    return _truncate(redacted, max_chars)


def _canonicalize_detail_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.lower())


def _is_sensitive_detail_key(key: str) -> bool:
    normalized = key.lower()
    canonical = _canonicalize_detail_key(key)
    return (
        normalized in SENSITIVE_QUERY_KEYS
        or re.fullmatch(SENSITIVE_ASSIGNMENT_KEY, normalized) is not None
        or any(canonical.endswith(suffix) for suffix in SENSITIVE_DETAIL_KEY_SUFFIXES)
    )


def redact_evidence_value(value: Any, max_string_chars: int = 180) -> Any:
    """Recursively redact credentials from scanner detail values."""
    if isinstance(value, str):
        return redact_evidence_string(value, max_chars=max_string_chars)
    if isinstance(value, dict):
        redacted_items: dict[Any, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                redacted_items[key] = redact_evidence_value(child, max_string_chars=max_string_chars)
                continue

            redacted_key = redact_evidence_string(key, max_chars=max_string_chars)
            if _is_sensitive_detail_key(key):
                redacted_items[redacted_key] = REDACTED_EVIDENCE_VALUE
            else:
                redacted_items[redacted_key] = redact_evidence_value(child, max_string_chars=max_string_chars)
        return redacted_items
    if isinstance(value, list):
        return [redact_evidence_value(child, max_string_chars=max_string_chars) for child in value]
    if isinstance(value, tuple):
        return tuple(redact_evidence_value(child, max_string_chars=max_string_chars) for child in value)
    return value
