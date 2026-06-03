"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import json
import re
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"
STRUCTURED_REDACTION_PARSE_LIMIT: Final[int] = 10 * 1024
MAX_URL_QUERY_REDACTION_DEPTH: Final[int] = 8
MAX_REDACTION_VALUE_DEPTH: Final[int] = 100
MAX_EMBEDDED_CONTAINER_MALFORMED_COUNT: Final[int] = 64

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
    r"_*(?:[a-z0-9]+[_-])*"
    r"(?:access[_-]?key[_-]?id|access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret|"
    r"credential|"
    r"password|passwd|private[_-]?key|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
    r"(?:\[[a-z0-9_-]{0,32}\])*"
)
DETAIL_KEY_PATTERN: Final[str] = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,80}(?:\[[A-Za-z0-9_-]{0,32}\]){0,8}"
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?)" r"[^\s\"';&|]+"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_FLAG_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<prefix>(?:^|(?<=\s))-{{1,2}})(?P<key>{DETAIL_KEY_PATTERN})"
    r"(?P<separator>\s+)(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s\"';&|-][^\s\"';&|]*)"
)
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?![rubf]{{0,3}}[\"'])[^\s\"';&|]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*(?:[rubf]{{0,3}})?)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
CALL_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    r"(?:(?P<callee>[A-Za-z_][A-Za-z0-9_.]{0,120})\s*)?"
    r"(?P<opener>[\[({])"
)
QUOTED_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<key_quote>[\"'])(?P<key>{DETAIL_KEY_PATTERN})(?P=key_quote)"
    r"(?P<separator>\s*:\s*)(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
GENERIC_QUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
GENERIC_CONTAINER_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    r"(?P<opener>[\[({])"
)
GENERIC_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)(?![rRuUbBfF]{{0,3}}[\"'])[^\s\"';&|]+"
)
EMBEDDED_SENSITIVE_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<quote>[\"']?)(?P<key>{DETAIL_KEY_PATTERN})(?P=quote)\s*:"
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


def _redact_url_query_value(value: str, url_depth: int) -> str:
    if not value:
        return value
    if url_depth >= MAX_URL_QUERY_REDACTION_DEPTH:
        return REDACTED_EVIDENCE_VALUE
    try:
        return redact_evidence_string(
            value,
            max_chars=max(len(value), len(REDACTED_EVIDENCE_VALUE)),
            _url_depth=url_depth + 1,
        )
    except RecursionError:
        return REDACTED_EVIDENCE_VALUE


def _redact_url(match: re.Match[str], *, url_depth: int = 0) -> str:
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
        if _is_sensitive_detail_key(key):
            query_items.append((key, REDACTED_EVIDENCE_VALUE))
        else:
            query_items.append((key, _redact_url_query_value(value, url_depth=url_depth)))

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


def _redact_sensitive_flag_value(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    value = match.group("value")
    if value.startswith(("'", '"')):
        redacted_value = f"{value[0]}{REDACTED_EVIDENCE_VALUE}{value[0]}"
    else:
        redacted_value = REDACTED_EVIDENCE_VALUE
    return f"{match.group('prefix')}{match.group('key')}{match.group('separator')}{redacted_value}"


def _redact_generic_quoted_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    quote = match.group("value")[0]
    return f"{match.group('key')}{match.group('separator')}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_generic_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    return f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}"


def _find_balanced_container_end(text: str, start: int, *, max_scan_chars: int | None = None) -> int | None:
    if start >= len(text) or text[start] not in "[{(":
        return None

    matching_closer = {"[": "]", "{": "}", "(": ")"}
    stack = [text[start]]
    quote: str | None = None
    escaped = False
    scan_end = len(text) if max_scan_chars is None else min(len(text), start + max_scan_chars)

    for index in range(start + 1, scan_end):
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


def _redact_container_assignments(text: str) -> str:
    redacted_chunks: list[str] = []
    last_index = 0
    search_index = 0

    while match := GENERIC_CONTAINER_ASSIGNMENT_START_RE.search(text, search_index):
        container_start = match.start("opener")
        container_end = _find_balanced_container_end(text, container_start)
        if container_end is None:
            search_index = match.end()
            continue

        if _is_sensitive_detail_key(match.group("key")):
            redacted_chunks.append(text[last_index : match.start()])
            redacted_chunks.append(f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}")
            last_index = container_end
        else:
            container_text = text[container_start:container_end]
            redacted_container = _redact_structured_evidence(container_text, max_chars=len(container_text))
            if redacted_container is not None and redacted_container != container_text:
                redacted_chunks.append(text[last_index:container_start])
                redacted_chunks.append(redacted_container)
                last_index = container_end

        search_index = container_end

    if not redacted_chunks:
        return text

    redacted_chunks.append(text[last_index:])
    return "".join(redacted_chunks)


def _redact_call_assignments(text: str) -> str:
    redacted_chunks: list[str] = []
    last_index = 0
    search_index = 0

    while match := CALL_ASSIGNMENT_START_RE.search(text, search_index):
        container_start = match.start("opener")
        container_end = _find_balanced_container_end(text, container_start)
        if not _is_sensitive_detail_key(match.group("key")):
            search_index = match.end()
            continue

        redacted_chunks.append(text[last_index : match.start()])
        redacted_chunks.append(f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}")
        if container_end is None:
            last_index = len(text)
            break

        last_index = container_end
        search_index = container_end

    if not redacted_chunks:
        return text

    redacted_chunks.append(text[last_index:])
    return "".join(redacted_chunks)


def _redact_embedded_structured_containers(text: str) -> str:
    redacted_chunks: list[str] = []
    last_index = 0
    search_index = 0
    malformed_container_count = 0

    while search_index < len(text):
        container_starts = [
            index
            for index in (text.find("{", search_index), text.find("[", search_index), text.find("(", search_index))
            if index != -1
        ]
        if not container_starts:
            break

        container_start = min(container_starts)
        container_end = _find_balanced_container_end(
            text,
            container_start,
            max_scan_chars=STRUCTURED_REDACTION_PARSE_LIMIT,
        )
        if container_end is None:
            malformed_container_count += 1
            if (
                malformed_container_count >= MAX_EMBEDDED_CONTAINER_MALFORMED_COUNT
                or len(text) - container_start > STRUCTURED_REDACTION_PARSE_LIMIT
            ):
                return REDACTED_EVIDENCE_VALUE
            search_index = container_start + 1
            continue

        container_text = text[container_start:container_end]
        redacted_container = _redact_structured_evidence(
            container_text,
            max_chars=len(container_text),
            fail_closed=False,
        )
        if redacted_container is None and _contains_sensitive_key_literal(container_text):
            redacted_container = REDACTED_EVIDENCE_VALUE
        if redacted_container is not None and redacted_container != container_text:
            redacted_chunks.append(text[last_index:container_start])
            redacted_chunks.append(redacted_container)
            last_index = container_end

        search_index = container_end

    if not redacted_chunks:
        return text

    redacted_chunks.append(text[last_index:])
    return "".join(redacted_chunks)


def _contains_sensitive_key_literal(text: str) -> bool:
    return any(_is_sensitive_detail_key(match.group("key")) for match in EMBEDDED_SENSITIVE_KEY_RE.finditer(text))


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def _serialize_redacted_structured_value(value: Any, max_chars: int) -> str:
    redacted_value = redact_evidence_value(value)
    try:
        serialized_value = json.dumps(redacted_value, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        serialized_value = repr(redacted_value)
    return _truncate(serialized_value, max_chars)


def _redact_structured_evidence(text: str, max_chars: int, *, fail_closed: bool = True) -> str | None:
    stripped = text.strip()
    if not stripped.startswith(("{", "[", "(")):
        return None
    if len(stripped) > STRUCTURED_REDACTION_PARSE_LIMIT:
        return _truncate(REDACTED_EVIDENCE_VALUE, max_chars)

    try:
        parsed = json.loads(stripped)
    except (MemoryError, RecursionError, json.JSONDecodeError):
        try:
            parsed = ast.literal_eval(stripped)
        except (MemoryError, RecursionError, SyntaxError, ValueError):
            return _truncate(REDACTED_EVIDENCE_VALUE, max_chars) if fail_closed else None

    if isinstance(parsed, (dict, list, tuple, set)):
        try:
            return _serialize_redacted_structured_value(parsed, max_chars)
        except (MemoryError, RecursionError):
            return _truncate(REDACTED_EVIDENCE_VALUE, max_chars)
    return None


def _redact_quoted_structured_literal(text: str, max_chars: int) -> str | None:
    stripped = text.strip()
    if not stripped.startswith(('"', "'")) or len(stripped) > STRUCTURED_REDACTION_PARSE_LIMIT:
        return None

    try:
        unquoted = json.loads(stripped) if stripped.startswith('"') else ast.literal_eval(stripped)
    except (MemoryError, RecursionError, json.JSONDecodeError, SyntaxError, ValueError):
        return None
    if not isinstance(unquoted, str):
        return None

    redacted_unquoted = redact_evidence_string(unquoted, max_chars=max(len(unquoted), len(REDACTED_EVIDENCE_VALUE)))
    if redacted_unquoted == unquoted:
        return None
    return _truncate(redacted_unquoted, max_chars)


def redact_evidence_string(text: str, max_chars: int = 180, *, _url_depth: int = 0) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    structured_redaction = _redact_structured_evidence(text, max_chars=max_chars)
    if structured_redaction is not None:
        return structured_redaction
    quoted_structured_redaction = _redact_quoted_structured_literal(text, max_chars=max_chars)
    if quoted_structured_redaction is not None:
        return quoted_structured_redaction

    redacted = URL_RE.sub(lambda match: _redact_url(match, url_depth=_url_depth), text)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_FLAG_VALUE_RE.sub(_redact_sensitive_flag_value, redacted)
    redacted = _redact_call_assignments(redacted)
    redacted = _redact_container_assignments(redacted)
    redacted = _redact_embedded_structured_containers(redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = QUOTED_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
    redacted = GENERIC_QUOTED_ASSIGNMENT_RE.sub(_redact_generic_quoted_assignment, redacted)
    redacted = GENERIC_ASSIGNMENT_RE.sub(_redact_generic_assignment, redacted)
    return _truncate(redacted, max_chars)


def _strip_bracket_suffixes(key: str) -> str:
    return re.sub(r"(?:\[[^\[\]]{0,32}\])+$", "", key)


def _canonicalize_detail_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _strip_bracket_suffixes(key).lower())


def _is_sensitive_detail_key(key: str) -> bool:
    normalized = _strip_bracket_suffixes(key).lower()
    canonical = _canonicalize_detail_key(key)
    return (
        normalized in SENSITIVE_QUERY_KEYS
        or re.fullmatch(SENSITIVE_ASSIGNMENT_KEY, normalized) is not None
        or any(
            canonical.endswith(suffix)
            or canonical.endswith(f"{suffix}s")
            or canonical.endswith(f"{suffix}value")
            or canonical.endswith(f"{suffix}values")
            for suffix in SENSITIVE_DETAIL_KEY_SUFFIXES
        )
    )


def redact_evidence_value(value: Any, max_string_chars: int = 180, *, _depth: int = 0) -> Any:
    """Recursively redact credentials from scanner detail values."""
    if _depth >= MAX_REDACTION_VALUE_DEPTH:
        return REDACTED_EVIDENCE_VALUE
    if isinstance(value, str):
        return redact_evidence_string(value, max_chars=max_string_chars)
    if isinstance(value, (bytes, bytearray)):
        return redact_evidence_string(repr(value), max_chars=max_string_chars)
    if isinstance(value, dict):
        redacted_items: dict[Any, Any] = {}
        string_keys_by_lower = {key.lower(): key for key in value if isinstance(key, str)}
        sensitive_name_value_pair = "value" in string_keys_by_lower and any(
            isinstance(value.get(string_keys_by_lower[key]), str)
            and _is_sensitive_detail_key(value[string_keys_by_lower[key]])
            for key in ("name", "key")
            if key in string_keys_by_lower
        )
        for key, child in value.items():
            if not isinstance(key, str):
                redacted_items[f"<{type(key).__name__}-key>"] = redact_evidence_value(
                    child,
                    max_string_chars=max_string_chars,
                    _depth=_depth + 1,
                )
                continue

            redacted_key = redact_evidence_string(key, max_chars=max_string_chars)
            if _is_sensitive_detail_key(key) or (sensitive_name_value_pair and key.lower() == "value"):
                redacted_items[redacted_key] = REDACTED_EVIDENCE_VALUE
            else:
                redacted_items[redacted_key] = redact_evidence_value(
                    child,
                    max_string_chars=max_string_chars,
                    _depth=_depth + 1,
                )
        return redacted_items
    if isinstance(value, list):
        if len(value) == 2 and isinstance(value[0], str) and _is_sensitive_detail_key(value[0]):
            return [redact_evidence_string(value[0], max_chars=max_string_chars), REDACTED_EVIDENCE_VALUE]
        return [redact_evidence_value(child, max_string_chars=max_string_chars, _depth=_depth + 1) for child in value]
    if isinstance(value, tuple):
        if len(value) == 2 and isinstance(value[0], str) and _is_sensitive_detail_key(value[0]):
            return (redact_evidence_string(value[0], max_chars=max_string_chars), REDACTED_EVIDENCE_VALUE)
        return tuple(
            redact_evidence_value(child, max_string_chars=max_string_chars, _depth=_depth + 1) for child in value
        )
    if isinstance(value, set):
        return [
            redact_evidence_value(child, max_string_chars=max_string_chars, _depth=_depth + 1)
            for child in sorted(value, key=repr)
        ]
    return value
