"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import re
from collections.abc import Iterator
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
    r"(?:[a-z0-9]+[._-])*"
    r"(?:access[._-]?key|access[._-]?token|api[._-]?key|apikey|auth[._-]?token|client[._-]?secret|"
    r"credential|password|passwd|private[._-]?key|refresh[._-]?token|sas|secret|secret[._-]?key|"
    r"signature|sig|token)"
)
SENSITIVE_BACKTICK_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[\s._-]+)*"
    r"(?:access[\s._-]*key|access[\s._-]*token|api[\s._-]*key|apikey|auth[\s._-]*token|"
    r"client[\s._-]*secret|credential|password|passwd|private[\s._-]*key|refresh[\s._-]*token|sas|"
    r"secret|secret[\s._-]*key|signature|sig|token)"
)
SENSITIVE_ASSIGNMENT_IDENTIFIER: Final[str] = (
    rf"""(?:`{SENSITIVE_BACKTICK_ASSIGNMENT_KEY}`|"{SENSITIVE_BACKTICK_ASSIGNMENT_KEY}"|"""
    rf"""'{SENSITIVE_BACKTICK_ASSIGNMENT_KEY}'|\b{SENSITIVE_ASSIGNMENT_KEY}\b)"""
)
SENSITIVE_ASSIGNMENT_OPERATOR: Final[str] = r"(?:[:=]|<{1,2}-)"
QUOTED_EVIDENCE_VALUE: Final[str] = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
R_RAW_STRING_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"""[rR]"(?P<dashes>-*)(?P<delimiter>[\(\[\{])""")
R_RAW_STRING_CLOSING_DELIMITERS: Final[dict[str, str]] = {"(": ")", "[": "]", "{": "}"}
R_RAW_LEFT_ASSIGNMENT_CONTEXT_CHARS: Final[int] = 4_096
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?)" r"[^\s\"';&|]+"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)({SENSITIVE_ASSIGNMENT_IDENTIFIER}\s*{SENSITIVE_ASSIGNMENT_OPERATOR}\s*)[^\s\"';&|]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)({SENSITIVE_ASSIGNMENT_IDENTIFIER}\s*{SENSITIVE_ASSIGNMENT_OPERATOR}\s*)({QUOTED_EVIDENCE_VALUE})"
)
RIGHTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)->{{1,2}}\s*{SENSITIVE_ASSIGNMENT_IDENTIFIER}"
)
QUOTED_RIGHTWARD_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)({QUOTED_EVIDENCE_VALUE})(\s*->{{1,2}}\s*{SENSITIVE_ASSIGNMENT_IDENTIFIER})"
)
LEFTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i){SENSITIVE_ASSIGNMENT_IDENTIFIER}\s*{SENSITIVE_ASSIGNMENT_OPERATOR}\s*$"
)
RIGHTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\s*->{{1,2}}\s*{SENSITIVE_ASSIGNMENT_IDENTIFIER}"
)


def _iter_r_raw_string_spans(text: str) -> Iterator[tuple[int, int, int, int, bool]]:
    """Yield raw R literal and content spans, including unterminated candidates."""
    cursor = 0
    while prefix_match := R_RAW_STRING_PREFIX_RE.search(text, cursor):
        literal_start = prefix_match.start()
        content_start = prefix_match.end()
        dashes = prefix_match.group("dashes")
        closing_delimiter = R_RAW_STRING_CLOSING_DELIMITERS[prefix_match.group("delimiter")]
        closing_sequence = f'{closing_delimiter}{dashes}"'
        content_end = text.find(closing_sequence, content_start)
        if content_end < 0:
            yield literal_start, len(text), content_start, len(text), False
            return

        literal_end = content_end + len(closing_sequence)
        yield literal_start, literal_end, content_start, content_end, True
        cursor = literal_end


def _replace_spans(text: str, replacements: list[tuple[int, int]]) -> str:
    if not replacements:
        return text

    parts: list[str] = []
    cursor = 0
    for start, end in replacements:
        if start < cursor:
            continue
        parts.extend((text[cursor:start], REDACTED_EVIDENCE_VALUE))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _redact_r_raw_assignments(text: str) -> str:
    replacements: list[tuple[int, int]] = []
    for literal_start, literal_end, _content_start, _content_end, _is_terminated in _iter_r_raw_string_spans(text):
        left_context = text[max(0, literal_start - R_RAW_LEFT_ASSIGNMENT_CONTEXT_CHARS) : literal_start]
        if LEFTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE.search(left_context) or RIGHTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE.match(
            text,
            literal_end,
        ):
            replacements.append((literal_start, literal_end))

    return _replace_spans(text, replacements)


def _redact_bare_rightward_assignments(text: str) -> str:
    replacements: list[tuple[int, int]] = []
    for target_match in RIGHTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE.finditer(text):
        value_end = target_match.start()
        while value_end > 0 and text[value_end - 1].isspace():
            value_end -= 1

        value_start = value_end
        while value_start > 0:
            character = text[value_start - 1]
            if character.isspace() or character in "\"';&|":
                break
            value_start -= 1

        if value_start < value_end:
            replacements.append((value_start, value_end))

    return _replace_spans(text, replacements)


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
    quote = match.group(2)[0]
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_quoted_rightward_assignment(match: re.Match[str]) -> str:
    quote = match.group(1)[0]
    return f"{quote}{REDACTED_EVIDENCE_VALUE}{quote}{match.group(2)}"


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = _redact_r_raw_assignments(text)
    redacted = URL_RE.sub(_redact_url, redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_RIGHTWARD_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_rightward_assignment, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = _redact_bare_rightward_assignments(redacted)
    return _truncate(redacted, max_chars)
