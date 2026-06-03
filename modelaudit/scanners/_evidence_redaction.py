"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import re
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
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
    r"(?:access[_-]?key[_-]?id|access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|"
    r"authorization|client[_-]?secret|credential|password|passwd|private[_-]?key|proxy[_-]?authorization|"
    r"refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
)
QUOTED_SENSITIVE_KEY: Final[str] = SENSITIVE_ASSIGNMENT_KEY
PYTHON_STRING_PREFIX: Final[str] = r"[rubf]*"
PYTHON_QUOTE_DELIMITER: Final[str] = r"(?:'''|\"\"\"|\"(?!\")|'(?!'))"
PYTHON_STRING_LITERAL: Final[str] = (
    rf"{PYTHON_STRING_PREFIX}(?:"
    r"'''(?:\\.|(?!''')[\s\S])*'''|"
    r'"""(?:\\.|(?!""")[\s\S])*"""|'
    r'"(?!")(?:\\.|[^"\\])*"|'
    r"'(?!')(?:\\.|[^'\\])*'"
    r")"
)
PYTHON_STRING_LITERAL_SEQUENCE: Final[str] = rf"{PYTHON_STRING_LITERAL}(?:\s+{PYTHON_STRING_LITERAL})*"
STRING_LITERAL_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<prefix>{PYTHON_STRING_PREFIX})(?P<quote>{PYTHON_QUOTE_DELIMITER})"
)
QUOTED_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*[:=]\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:\\.|(?!\3)[^\\])*\3"
)
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\b(?:proxy[-_]?authorization|authorization)\s*[:=]\s*)(?!\s*[rubf]*[\"'])"
    r"(?:digest\s+[^;&|\r\n]+?(?=$|[;&|\r\n]|\s+[A-Za-z][A-Za-z0-9+.-]*://|[\"']\s+\S)|"
    r"(?:bearer|basic|ntlm)\s+[^\s\"';&|]+|[^\s\"';&|]+)"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?![rubf]*[\"'])[^\s\"';&|]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:\\.|(?!\4)[^\\])*\4"
)
CONCATENATED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)"
    rf"(?P<value>{PYTHON_STRING_LITERAL}\s+{PYTHON_STRING_LITERAL}(?:\s+{PYTHON_STRING_LITERAL})*)"
)
SENSITIVE_CALL_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)"
    r"(?:(?P<callee>[A-Za-z_][A-Za-z0-9_.]{0,120})\s*)?"
    r"(?P<opener>[\[({])"
)
QUOTED_SENSITIVE_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)([\"']{QUOTED_SENSITIVE_KEY}[\"']\s*:\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:\\.|(?!\3)[^\\])*\3"
)
GENERIC_QUOTED_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<key_quote>[\"'])(?P<key>(?:\\.|(?!(?P=key_quote))[^\\]){{1,120}})(?P=key_quote)"
    rf"(?P<separator>\s*:\s*)(?P<value>{PYTHON_STRING_LITERAL_SEQUENCE})"
)
GENERIC_UNTERMINATED_QUOTED_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<key_quote>[\"'])(?P<key>(?:\\.|(?!(?P=key_quote))[^\\]){{1,120}})(?P=key_quote)"
    rf"(?P<separator>\s*:\s*)(?P<prefix>{PYTHON_STRING_PREFIX})(?P<quote>{PYTHON_QUOTE_DELIMITER})"
    r"(?:(?:\\.)|(?!(?P=quote))[^\\;&|])*(?=$|[;&|])"
)
UNTERMINATED_QUOTED_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*[:=]\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:(?:\\.)|(?!\3)[^\\;&|])*(?=$|[;&|])"
)
UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:(?:\\.)|(?!\4)[^\\;&|])*(?=$|[;&|])"
)
UNTERMINATED_QUOTED_SENSITIVE_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)([\"']{QUOTED_SENSITIVE_KEY}[\"']\s*:\s*)({PYTHON_STRING_PREFIX})"
    rf"({PYTHON_QUOTE_DELIMITER})(?:(?:\\.)|(?!\3)[^\\;&|])*(?=$|[;&|])"
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
    for key, value in parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True):
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


def _redact_quoted_authorization(match: re.Match[str]) -> str:
    quote = match.group(3)
    return f"{match.group(1)}{match.group(2)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redacted_literal_from_value(value: str) -> str:
    match = STRING_LITERAL_START_RE.match(value)
    if match is None:
        return REDACTED_EVIDENCE_VALUE
    quote = match.group("quote")
    return f"{match.group('prefix')}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_concatenated_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{_redacted_literal_from_value(match.group('value'))}"


def _decode_quoted_key(quote: str, key: str) -> str | None:
    try:
        decoded = ast.literal_eval(f"{quote}{key}{quote}")
    except (SyntaxError, ValueError):
        return None
    return decoded if isinstance(decoded, str) else None


def _redact_generic_quoted_key_value(match: re.Match[str]) -> str:
    decoded_key = _decode_quoted_key(match.group("key_quote"), match.group("key"))
    if decoded_key is None or re.fullmatch(QUOTED_SENSITIVE_KEY, decoded_key, re.IGNORECASE) is None:
        return match.group(0)
    return (
        f"{match.group('key_quote')}{match.group('key')}{match.group('key_quote')}"
        f"{match.group('separator')}{_redacted_literal_from_value(match.group('value'))}"
    )


def _redact_generic_unterminated_quoted_key_value(match: re.Match[str]) -> str:
    decoded_key = _decode_quoted_key(match.group("key_quote"), match.group("key"))
    if decoded_key is None or re.fullmatch(QUOTED_SENSITIVE_KEY, decoded_key, re.IGNORECASE) is None:
        return match.group(0)
    return (
        f"{match.group('key_quote')}{match.group('key')}{match.group('key_quote')}"
        f"{match.group('separator')}{match.group('prefix')}{match.group('quote')}"
        f"{REDACTED_EVIDENCE_VALUE}{match.group('quote')}"
    )


def _find_balanced_container_end(text: str, start: int) -> int | None:
    if start >= len(text) or text[start] not in "[{(":
        return None

    matching_closer = {"[": "]", "{": "}", "(": ")"}
    stack = [text[start]]
    quote: str | None = None
    escaped = False

    for index in range(start + 1, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in ("'", '"'):
            quote = char
        elif char in matching_closer:
            stack.append(char)
        elif char in "])}":
            if not stack or matching_closer[stack[-1]] != char:
                return None
            stack.pop()
            if not stack:
                return index + 1

    return None


def _redact_sensitive_call_assignments(text: str) -> str:
    redacted_chunks: list[str] = []
    last_index = 0
    search_index = 0

    while match := SENSITIVE_CALL_ASSIGNMENT_START_RE.search(text, search_index):
        container_end = _find_balanced_container_end(text, match.start("opener"))
        redacted_chunks.append(text[last_index : match.start()])
        redacted_chunks.append(f"{match.group('prefix')}{REDACTED_EVIDENCE_VALUE}")
        if container_end is None:
            last_index = len(text)
            break

        last_index = container_end
        search_index = container_end

    if not redacted_chunks:
        return text

    redacted_chunks.append(text[last_index:])
    return "".join(redacted_chunks)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = URL_RE.sub(_redact_url, text)
    redacted = CONCATENATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_concatenated_assignment, redacted)
    redacted = GENERIC_QUOTED_KEY_VALUE_RE.sub(_redact_generic_quoted_key_value, redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_SENSITIVE_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
    redacted = QUOTED_AUTHORIZATION_VALUE_RE.sub(_redact_quoted_authorization, redacted)
    redacted = GENERIC_UNTERMINATED_QUOTED_KEY_VALUE_RE.sub(_redact_generic_unterminated_quoted_key_value, redacted)
    redacted = UNTERMINATED_QUOTED_SENSITIVE_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
    redacted = UNTERMINATED_QUOTED_AUTHORIZATION_VALUE_RE.sub(_redact_quoted_authorization, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = _redact_sensitive_call_assignments(redacted)
    redacted = UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    return _truncate(redacted, max_chars)
