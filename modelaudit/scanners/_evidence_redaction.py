"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from typing import Final
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from modelaudit.detectors.network_comm import _redact_url_path_tokens

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"

URL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:https?|ftp|ftps|ssh|telnet|wss?|tcp|udp|s3|gs|az|wasbs?|abfss?|file)://[^\s\"'<>]+"
)
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
SEPARATED_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[_.-])*"
    r"(?:access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|client[_-]?secret|credential|"
    r"password|passwd|private[_-]?key|pwd|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
    r"(?:[_.-][a-z0-9]+)*"
)
CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z][A-Za-z0-9]*)?"
    r"(?:AccessKey|accessKey|AccessToken|accessToken|APIKey|ApiKey|apiKey|AuthToken|authToken|"
    r"ClientSecret|clientSecret|Credential|Password|Passwd|PrivateKey|privateKey|Pwd|"
    r"RefreshToken|refreshToken|SAS|Secret|SecretKey|secretKey|Signature|Sig|Token)"
    r"(?:[A-Z][A-Za-z0-9]*)?"
)
SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_ASSIGNMENT_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY}))"
)
SENSITIVE_CONTAINER_KEY: Final[str] = rf"(?:{SENSITIVE_ASSIGNMENT_KEY}|authorization)"
SEPARATED_SENSITIVE_R_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[._-])*"
    r"(?:access[._-]?key|access[._-]?token|api[._-]?key|apikey|auth[._-]?token|client[._-]?secret|"
    r"credential|password|passwd|private[._-]?key|pwd|refresh[._-]?token|sas|secret|"
    r"secret[._-]?key|signature|sig|token)"
    r"(?:[._-][a-z0-9]+)*"
)
SENSITIVE_R_BARE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_R_ASSIGNMENT_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY}))"
)
SEPARATED_SENSITIVE_R_QUOTED_IDENTIFIER_KEY: Final[str] = (
    r"(?:[a-z0-9]+[\s._-]+)*"
    r"(?:access[\s._-]*key|access[\s._-]*token|api[\s._-]*key|apikey|auth[\s._-]*token|"
    r"client[\s._-]*secret|credential|password|passwd|private[\s._-]*key|pwd|"
    r"refresh[\s._-]*token|sas|secret|secret[\s._-]*key|signature|sig|token)"
    r"(?:[\s._-]+[a-z0-9]+)*"
)
SENSITIVE_R_QUOTED_IDENTIFIER_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_R_QUOTED_IDENTIFIER_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY}))"
)
SENSITIVE_R_ASSIGNMENT_IDENTIFIER: Final[str] = (
    rf"""(?:`{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}`|"{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}"|"""
    rf"""'{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}'|\b{SENSITIVE_R_BARE_ASSIGNMENT_KEY}\b)"""
)
R_LEFTWARD_ASSIGNMENT_OPERATOR: Final[str] = r"<{1,2}-"
R_RAW_STRING_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"""[rR]"(?P<dashes>-*)(?P<delimiter>[\(\[\{])""")
R_RAW_STRING_CLOSING_DELIMITERS: Final[dict[str, str]] = {"(": ")", "[": "]", "{": "}"}
R_RAW_LEFT_ASSIGNMENT_CONTEXT_CHARS: Final[int] = 4_096
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*[:=]\s*"
    r"(?!(?:\(\s*)*(?:[rRuUbBfF]{0,3})?[\"'])"
    r")"
    r"(?:[A-Za-z][A-Za-z0-9._-]*\s+)?[^\s\"';&|,}\]]+"
)
AUTH_SCHEME_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\b(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}")
STRING_LITERAL_PREFIX_PATTERN: Final[str] = r"(?P<string_prefix>[rRuUbBfF]{0,3})?"
QUOTED_VALUE_PATTERN: Final[str] = (
    rf"{STRING_LITERAL_PREFIX_PATTERN}(?P<quote>\"\"\"|'''|[\"'])(?:\\.|(?!(?P=quote)).)*?(?P=quote)"
)
UNTERMINATED_QUOTED_VALUE_PATTERN: Final[str] = (
    rf"{STRING_LITERAL_PREFIX_PATTERN}(?P<quote>\"\"\"|'''|[\"'])(?:\\.|(?!(?P=quote)).)*\Z"
)
VALUE_OPENERS_PATTERN: Final[str] = r"(?:\(\s*)*"
UNQUOTED_VALUE_PATTERN: Final[str] = r"(?!\()[^\s\"';&|,}\]]+(?![\"'])"
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*{VALUE_OPENERS_PATTERN})"
    rf"{UNQUOTED_VALUE_PATTERN}"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*{VALUE_OPENERS_PATTERN})"
    rf"{QUOTED_VALUE_PATTERN}"
)
QUOTED_AUTHORIZATION_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>authorization\s*[:=]\s*{VALUE_OPENERS_PATTERN}){QUOTED_VALUE_PATTERN}"
)
QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*:\s*"
    rf"{VALUE_OPENERS_PATTERN})"
    rf"{QUOTED_VALUE_PATTERN}"
)
SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*=\s*"
    rf"{VALUE_OPENERS_PATTERN})"
    rf"{QUOTED_VALUE_PATTERN}"
)
ESCAPED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\\(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})\\(?P=key_quote)\s*:\s*)"
    r"\\(?P<value_quote>[\"'])(?:(?!\\(?P=value_quote)).)*?\\(?P=value_quote)"
)
BRACKETED_MAPPING_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?:(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)"
    rf"|\b(?:{SENSITIVE_ASSIGNMENT_KEY})\b)\s*:\s*)"
    r"(?:\[[^\]]{0,4096}\]|\{[^}]{0,4096}\})"
)
UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*{VALUE_OPENERS_PATTERN})"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_QUOTED_AUTHORIZATION_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>authorization\s*[:=]\s*{VALUE_OPENERS_PATTERN})"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*:\s*"
    rf"{VALUE_OPENERS_PATTERN})"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*=\s*"
    rf"{VALUE_OPENERS_PATTERN})"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<prefix>(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*:\s*"
    rf"{VALUE_OPENERS_PATTERN}){UNQUOTED_VALUE_PATTERN}"
)
SUBSCRIPTED_SENSITIVE_UNQUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<prefix>\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*=\s*"
    rf"{VALUE_OPENERS_PATTERN}){UNQUOTED_VALUE_PATTERN}"
)
HTML_QUERY_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"(?i)&amp;")
SEMICOLON_QUERY_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"(?i);(?=(?:amp;)?[a-z0-9%_.\-\[\]]+\s*=)")
NESTED_SENSITIVE_QUERY_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?:^|[?&;])(?:amp;)?{SENSITIVE_ASSIGNMENT_KEY}(?:\[[^\]]*\])*\s*[:=]"
)
BLOCK_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?im)(?P<prefix>\b(?:{SENSITIVE_ASSIGNMENT_KEY})\s*:\s*[|>][+-]?)"
    r"(?P<block>(?:\n(?P<indent>[ \t]+)[^\n]*)+)"
)
BRACKETED_QUERY_KEY_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"(?:\[[^\]]*\])+\Z")
R_SENSITIVE_ASSIGNMENT_PREFIX: Final[str] = (
    rf"(?P<prefix>{SENSITIVE_R_ASSIGNMENT_IDENTIFIER}\s*{R_LEFTWARD_ASSIGNMENT_OPERATOR}\s*"
    rf"{VALUE_OPENERS_PATTERN})"
)
R_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i){R_SENSITIVE_ASSIGNMENT_PREFIX}{UNQUOTED_VALUE_PATTERN}"
)
R_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is){R_SENSITIVE_ASSIGNMENT_PREFIX}{QUOTED_VALUE_PATTERN}"
)
R_UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is){R_SENSITIVE_ASSIGNMENT_PREFIX}{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
R_RIGHTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)->{{1,2}}\s*{SENSITIVE_R_ASSIGNMENT_IDENTIFIER}"
)
R_QUOTED_RIGHTWARD_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<value>(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'))"
    rf"(?P<suffix>\s*->{{1,2}}\s*{SENSITIVE_R_ASSIGNMENT_IDENTIFIER})"
)
LEFTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i){SENSITIVE_R_ASSIGNMENT_IDENTIFIER}\s*{R_LEFTWARD_ASSIGNMENT_OPERATOR}\s*$"
)
RIGHTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\s*->{{1,2}}\s*{SENSITIVE_R_ASSIGNMENT_IDENTIFIER}"
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
        next_prefix_match = R_RAW_STRING_PREFIX_RE.search(text, content_start)
        if content_end < 0 and next_prefix_match is not None:
            yield literal_start, next_prefix_match.start(), content_start, next_prefix_match.start(), False
            cursor = next_prefix_match.start()
            continue
        if content_end < 0:
            yield literal_start, len(text), content_start, len(text), False
            return

        literal_end = content_end + len(closing_sequence)
        yield literal_start, literal_end, content_start, content_end, True
        cursor = literal_end


def _r_non_code_spans(text: str) -> list[tuple[int, int]]:
    """Return R string, raw literal, backtick, and comment spans."""
    spans: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(text):
        raw_prefix_match = R_RAW_STRING_PREFIX_RE.match(text, cursor)
        if raw_prefix_match is not None:
            closing_delimiter = R_RAW_STRING_CLOSING_DELIMITERS[raw_prefix_match.group("delimiter")]
            closing_sequence = f'{closing_delimiter}{raw_prefix_match.group("dashes")}"'
            content_end = text.find(closing_sequence, raw_prefix_match.end())
            if content_end < 0:
                next_prefix_match = R_RAW_STRING_PREFIX_RE.search(text, raw_prefix_match.end())
                literal_end = next_prefix_match.start() if next_prefix_match is not None else len(text)
            else:
                literal_end = content_end + len(closing_sequence)
            spans.append((cursor, literal_end))
            cursor = literal_end
            continue

        character = text[cursor]
        if character == "#":
            comment_end = text.find("\n", cursor)
            if comment_end < 0:
                comment_end = len(text)
            spans.append((cursor, comment_end))
            cursor = comment_end
            continue

        if character in "\"'`":
            quote = character
            literal_end = cursor + 1
            escaped = False
            while literal_end < len(text):
                literal_character = text[literal_end]
                literal_end += 1
                if escaped:
                    escaped = False
                elif literal_character == "\\":
                    escaped = True
                elif literal_character == quote:
                    break
            spans.append((cursor, literal_end))
            cursor = literal_end
            continue

        cursor += 1

    return spans


def _position_is_in_spans(position: int, spans: Sequence[tuple[int, int]]) -> bool:
    span_index = bisect_right(spans, position, key=lambda span: span[0]) - 1
    return span_index >= 0 and position < spans[span_index][1]


def _r_statement_starts(text: str, non_code_spans: Sequence[tuple[int, int]]) -> list[int]:
    """Return statement starts while ignoring separators inside non-code spans."""
    statement_starts = [0]
    nesting_depth = 0
    cursor = 0
    span_index = 0

    while cursor < len(text):
        if span_index < len(non_code_spans) and cursor == non_code_spans[span_index][0]:
            cursor = non_code_spans[span_index][1]
            span_index += 1
            continue

        character = text[cursor]
        if character in "([{":
            nesting_depth += 1
        elif character in ")]}":
            nesting_depth = max(0, nesting_depth - 1)
        elif character in ";\r\n" and nesting_depth == 0:
            statement_starts.append(cursor + 1)
        cursor += 1

    return statement_starts


def _r_statement_start_before(statement_starts: Sequence[int], position: int) -> int:
    """Return the precomputed R statement start containing position."""
    return statement_starts[bisect_right(statement_starts, position) - 1]


def _replace_spans(text: str, replacements: list[tuple[int, int]]) -> str:
    if not replacements:
        return text

    merged_replacements: list[tuple[int, int]] = []
    for start, end in replacements:
        if merged_replacements and start <= merged_replacements[-1][1]:
            previous_start, previous_end = merged_replacements[-1]
            merged_replacements[-1] = (previous_start, max(previous_end, end))
        else:
            merged_replacements.append((start, end))

    parts: list[str] = []
    cursor = 0
    for start, end in merged_replacements:
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


def _redact_rightward_assignment_expressions(text: str) -> str:
    replacements: list[tuple[int, int]] = []
    previous_target_end = 0
    non_code_spans = _r_non_code_spans(text)
    statement_starts = _r_statement_starts(text, non_code_spans)
    for target_match in R_RIGHTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE.finditer(text):
        if _position_is_in_spans(target_match.start(), non_code_spans):
            continue

        value_end = target_match.start()
        while value_end > 0 and text[value_end - 1].isspace():
            value_end -= 1

        value_start = max(
            _r_statement_start_before(statement_starts, target_match.start()),
            previous_target_end,
        )
        statement_prefix_start = value_start
        statement_prefix = text[statement_prefix_start:value_end]
        for assignment_pattern in (
            R_QUOTED_SENSITIVE_ASSIGNMENT_RE,
            R_SENSITIVE_ASSIGNMENT_RE,
            QUOTED_SENSITIVE_ASSIGNMENT_RE,
            SENSITIVE_ASSIGNMENT_RE,
        ):
            for assignment_match in assignment_pattern.finditer(statement_prefix):
                trailing = statement_prefix[assignment_match.end() :]
                if trailing[:1].isspace() and trailing.strip():
                    value_start = max(value_start, statement_prefix_start + assignment_match.end())
        while value_start < value_end and text[value_start].isspace():
            value_start += 1

        value = text[value_start:value_end]
        already_redacted = value in {
            REDACTED_EVIDENCE_VALUE,
            f'"{REDACTED_EVIDENCE_VALUE}"',
            f"'{REDACTED_EVIDENCE_VALUE}'",
        }
        if value_start < value_end and not already_redacted:
            replacements.append((value_start, value_end))
        previous_target_end = target_match.end()

    return _replace_spans(text, replacements)


def _unfinished_r_assignment_literal_closing_sequence(text: str) -> str | None:
    """Return the expected closer when an R assignment literal continues on the next line."""
    for literal_start, literal_end, _content_start, _content_end, is_terminated in _iter_r_raw_string_spans(text):
        if is_terminated or literal_end != len(text):
            continue
        prefix_match = R_RAW_STRING_PREFIX_RE.match(text, literal_start)
        assert prefix_match is not None
        closing_delimiter = R_RAW_STRING_CLOSING_DELIMITERS[prefix_match.group("delimiter")]
        return f'{closing_delimiter}{prefix_match.group("dashes")}"'

    if match := R_UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.search(text):
        return match.group("quote")
    return None


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
    path = _redact_url_path_tokens(parsed.scheme.lower(), hostname.lower(), parsed.path)

    query_items = []
    normalized_query = SEMICOLON_QUERY_SEPARATOR_RE.sub("&", HTML_QUERY_SEPARATOR_RE.sub("&", parsed.query))
    for key, value in parse_qsl(normalized_query, keep_blank_values=True):
        if _normalize_query_key(key) in SENSITIVE_QUERY_KEYS or _contains_nested_sensitive_query_assignment(value):
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
    return bool(
        NESTED_SENSITIVE_QUERY_ASSIGNMENT_RE.search(decoded)
        or QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.search(decoded)
        or ESCAPED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.search(decoded)
        or BRACKETED_MAPPING_SENSITIVE_ASSIGNMENT_RE.search(decoded)
        or BLOCK_SENSITIVE_ASSIGNMENT_RE.search(decoded)
        or _contains_nested_url_secret(decoded)
        or QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.search(decoded)
        or UNTERMINATED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.search(decoded)
    )


def _contains_nested_url_secret(value: str) -> bool:
    """Detect credential-bearing URLs embedded inside decoded query values."""
    for match in URL_RE.finditer(value):
        raw_url = match.group(0)
        try:
            parsed = urlsplit(raw_url)
        except ValueError:
            if "@" in raw_url:
                return True
            continue

        hostname = parsed.hostname or ""
        if "@" in parsed.netloc:
            return True
        if _redact_url_path_tokens(parsed.scheme.lower(), hostname.lower(), parsed.path) != parsed.path:
            return True
        normalized_query = SEMICOLON_QUERY_SEPARATOR_RE.sub("&", HTML_QUERY_SEPARATOR_RE.sub("&", parsed.query))
        if any(
            _normalize_query_key(key) in SENSITIVE_QUERY_KEYS
            or _contains_nested_sensitive_query_assignment(query_value)
            for key, query_value in parse_qsl(normalized_query, keep_blank_values=True)
        ):
            return True
    return False


def _normalize_query_key(key: str) -> str:
    return BRACKETED_QUERY_KEY_SUFFIX_RE.sub("", key).lower()


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    quote = match.group("quote")
    string_prefix = match.group("string_prefix") or ""
    return f"{match.group('prefix')}{string_prefix}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_escaped_quoted_mapping_assignment(match: re.Match[str]) -> str:
    value_quote = match.group("value_quote")
    return f"{match.group('prefix')}\\{value_quote}{REDACTED_EVIDENCE_VALUE}\\{value_quote}"


def _redact_block_assignment(match: re.Match[str]) -> str:
    indent = match.group("indent") or "  "
    return f"{match.group('prefix')}\n{indent}{REDACTED_EVIDENCE_VALUE}"


def _redact_unterminated_quoted_assignment(match: re.Match[str]) -> str:
    string_prefix = match.group("string_prefix") or ""
    return f"{match.group('prefix')}{string_prefix}{match.group('quote')}{REDACTED_EVIDENCE_VALUE}"


def _redact_unquoted_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{REDACTED_EVIDENCE_VALUE}"


def _redact_r_quoted_rightward_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    quote = value[0]
    return f"{quote}{REDACTED_EVIDENCE_VALUE}{quote}{match.group('suffix')}"


def _redact_r_unterminated_quoted_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{REDACTED_EVIDENCE_VALUE}"


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int | None = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = _redact_r_raw_assignments(text)
    redacted = URL_RE.sub(_redact_url, redacted)
    redacted = ESCAPED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_escaped_quoted_mapping_assignment, redacted)
    redacted = BRACKETED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = BLOCK_SENSITIVE_ASSIGNMENT_RE.sub(_redact_block_assignment, redacted)
    redacted = QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_AUTHORIZATION_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_AUTHORIZATION_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = AUTH_SCHEME_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SUBSCRIPTED_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = R_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = R_UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(
        _redact_r_unterminated_quoted_assignment,
        redacted,
    )
    redacted = R_QUOTED_RIGHTWARD_SENSITIVE_ASSIGNMENT_RE.sub(
        _redact_r_quoted_rightward_assignment,
        redacted,
    )
    redacted = R_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = _redact_rightward_assignment_expressions(redacted)
    return redacted if max_chars is None else _truncate(redacted, max_chars)
