"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import json
import re
import unicodedata
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from typing import Any, Final
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

from modelaudit.detectors.network_comm import (
    _is_azure_container_authority,
    _redact_url_path_tokens,
)

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"
STRUCTURED_REDACTION_PARSE_LIMIT: Final[int] = 10 * 1024
MAX_URL_QUERY_REDACTION_DEPTH: Final[int] = 8
MAX_REDACTION_VALUE_DEPTH: Final[int] = 100
MAX_EMBEDDED_CONTAINER_MALFORMED_COUNT: Final[int] = 64
MAX_PERCENT_DECODE_PASSES: Final[int] = 32

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
STANDALONE_SECRET_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[opsur]_[A-Za-z0-9]{36}|"
    r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|"
    r"glpat-[A-Za-z0-9_-]{20}|"
    r"hf_[A-Za-z0-9]{30,}|"
    r"npm_[A-Za-z0-9]{36}|"
    r"sq0atp-[0-9A-Za-z_-]{22}|"
    r"sq0csp-[0-9A-Za-z_-]{43}|"
    r"(?:stripe|[sr]k)_live_[A-Za-z0-9]{24}|"
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*|"
    r"sk-(?:proj-[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])|[A-Za-z0-9]{24,})|"
    r"xox[baprs]-[0-9A-Za-z-]{20,}"
    r")(?![A-Za-z0-9])"
)
PERCENT_ENCODED_SECRET_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9_.+/=-]){20,}")
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
        "pwd",
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
        "x-goog-credential",
        "x-goog-signature",
    }
)
SEPARATED_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[_.-])*"
    r"(?:access[_-]?key[_-]?id|access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|"
    r"client[_-]?secret|credential|"
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
AUTHORIZATION_ALIAS_ASSIGNMENT_KEY: Final[str] = r"[a-z0-9_.-]*authorization(?:s|[_.-]?(?:headers?|values?))?"
AUTHORIZATION_ALIAS_R_QUOTED_IDENTIFIER_KEY: Final[str] = (
    r"[a-z0-9\s._-]*authorization(?:s|[\s._-]*(?:headers?|values?))?"
)
SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_ASSIGNMENT_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY})|"
    rf"{AUTHORIZATION_ALIAS_ASSIGNMENT_KEY})"
    r"(?:\[[a-z0-9_-]{0,32}\])*"
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
    rf"(?:{SEPARATED_SENSITIVE_R_ASSIGNMENT_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY})|"
    rf"{AUTHORIZATION_ALIAS_ASSIGNMENT_KEY})"
)
SEPARATED_SENSITIVE_R_QUOTED_IDENTIFIER_KEY: Final[str] = (
    r"(?:[a-z0-9]+[\s._-]+)*"
    r"(?:access[\s._-]*key|access[\s._-]*token|api[\s._-]*key|apikey|auth[\s._-]*token|"
    r"client[\s._-]*secret|credential|password|passwd|private[\s._-]*key|pwd|"
    r"refresh[\s._-]*token|sas|secret|secret[\s._-]*key|signature|sig|token)"
    r"(?:[\s._-]+[a-z0-9]+)*"
)
SENSITIVE_R_QUOTED_IDENTIFIER_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_R_QUOTED_IDENTIFIER_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY})|"
    rf"{AUTHORIZATION_ALIAS_R_QUOTED_IDENTIFIER_KEY})"
)
SENSITIVE_R_ASSIGNMENT_IDENTIFIER: Final[str] = (
    rf"""(?:`{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}`|"{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}"|"""
    rf"""'{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}'|\b{SENSITIVE_R_BARE_ASSIGNMENT_KEY}\b)"""
)
R_ASSIGNMENT_INDEX_SUFFIX: Final[str] = r"(?:\s*(?:\[\[[^\]\r\n]{1,120}\]\]|\[[^\]\r\n]{1,120}\]))*"
R_SENSITIVE_MEMBER_TARGET: Final[str] = (
    rf"\b[a-z.][a-z0-9._]*\s*(?:\$|@)\s*"
    rf"(?:`{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}`|\b{SENSITIVE_R_BARE_ASSIGNMENT_KEY}\b)"
    rf"{R_ASSIGNMENT_INDEX_SUFFIX}"
)
R_SENSITIVE_QUOTED_SUBSCRIPT_TARGET: Final[str] = (
    rf"\b[a-z.][a-z0-9._]*\s*(?:\[\[\s*|\[\s*)"
    rf"(?:\"{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}\"|'{SENSITIVE_R_QUOTED_IDENTIFIER_KEY}')"
    rf"\s*(?:\]\]|\]){R_ASSIGNMENT_INDEX_SUFFIX}"
)
R_SENSITIVE_ASSIGNMENT_TARGET: Final[str] = (
    rf"(?:{R_SENSITIVE_MEMBER_TARGET}|{R_SENSITIVE_QUOTED_SUBSCRIPT_TARGET}|"
    rf"{SENSITIVE_R_ASSIGNMENT_IDENTIFIER}{R_ASSIGNMENT_INDEX_SUFFIX})"
)
R_LEFTWARD_ASSIGNMENT_OPERATOR: Final[str] = r"<{1,2}-"
R_SENSITIVE_LEFTWARD_ASSIGNMENT_OPERATOR: Final[str] = rf"(?:=|{R_LEFTWARD_ASSIGNMENT_OPERATOR})"
R_RAW_STRING_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"""[rR]"(?P<dashes>-*)(?P<delimiter>[\(\[\{])""")
R_RAW_STRING_CLOSING_DELIMITERS: Final[dict[str, str]] = {"(": ")", "[": "]", "{": "}"}
R_RAW_LEFT_ASSIGNMENT_CONTEXT_CHARS: Final[int] = 4_096
DETAIL_KEY_PATTERN: Final[str] = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,80}(?:\[[A-Za-z0-9_-]{0,32}\]){0,8}"
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
UNQUOTED_VALUE_PATTERN: Final[str] = r"(?!(?:[rRuUbBfF]{0,3})(?:\"\"\"|'''|[\"']))(?!\()[^\s\"';&|,}\]]+"
SENSITIVE_FLAG_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<prefix>(?:^|(?<=\s))-{{1,2}})(?P<key>{DETAIL_KEY_PATTERN})"
    r"(?P<separator>\s+)(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s\"';&|-][^\s\"';&|]*)"
)
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*{VALUE_OPENERS_PATTERN})"
    rf"{UNQUOTED_VALUE_PATTERN}"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*{VALUE_OPENERS_PATTERN})"
    rf"{QUOTED_VALUE_PATTERN}"
)
CALL_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    r"(?:(?P<callee>[A-Za-z_][A-Za-z0-9_.]{0,120})\s*)?"
    r"(?P<opener>[\[({])"
)
QUOTED_KEY_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<key_quote>[\"'])(?P<key>{DETAIL_KEY_PATTERN})(?P=key_quote)"
    rf"(?P<separator>\s*:\s*){QUOTED_VALUE_PATTERN}"
)
GENERIC_QUOTED_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    rf"{QUOTED_VALUE_PATTERN}"
)
GENERIC_CONTAINER_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    r"(?P<opener>[\[({])"
)
GENERIC_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?P<key>{DETAIL_KEY_PATTERN})(?P<separator>\s*[:=]\s*)"
    rf"(?P<openers>{VALUE_OPENERS_PATTERN}){UNQUOTED_VALUE_PATTERN}"
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
    "authorization",
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
    rf"(?P<prefix>{R_SENSITIVE_ASSIGNMENT_TARGET}\s*{R_SENSITIVE_LEFTWARD_ASSIGNMENT_OPERATOR}\s*"
    rf"{VALUE_OPENERS_PATTERN})"
)
R_LEFTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i){R_SENSITIVE_ASSIGNMENT_TARGET}\s*{R_LEFTWARD_ASSIGNMENT_OPERATOR}\s*"
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
    rf"(?i)->{{1,2}}\s*{R_SENSITIVE_ASSIGNMENT_TARGET}"
)
R_QUOTED_RIGHTWARD_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<value>(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'))"
    rf"(?P<suffix>\s*->{{1,2}}\s*{R_SENSITIVE_ASSIGNMENT_TARGET})"
)
LEFTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i){R_SENSITIVE_ASSIGNMENT_TARGET}\s*{R_SENSITIVE_LEFTWARD_ASSIGNMENT_OPERATOR}\s*$"
)
RIGHTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\s*->{{1,2}}\s*{R_SENSITIVE_ASSIGNMENT_TARGET}"
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


def _redact_leftward_assignment_expressions(text: str) -> str:
    replacements: list[tuple[int, int]] = []
    non_code_spans = _r_non_code_spans(text)
    statement_starts = _r_statement_starts(text, non_code_spans)
    for target_match in R_LEFTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE.finditer(text):
        if _position_is_in_spans(target_match.start(), non_code_spans):
            continue

        value_start = target_match.end()
        statement_index = bisect_right(statement_starts, target_match.start()) - 1
        value_end = (
            statement_starts[statement_index + 1] - 1 if statement_index + 1 < len(statement_starts) else len(text)
        )
        while value_end > value_start and text[value_end - 1].isspace():
            value_end -= 1

        value = text[value_start:value_end]
        if (
            not value
            or value == REDACTED_EVIDENCE_VALUE
            or value.startswith(("'", '"'))
            or R_RAW_STRING_PREFIX_RE.match(value) is not None
            or re.fullmatch(r"[^\s,;(){}\[\]]+", value) is not None
        ):
            continue
        if value_start < value_end:
            replacements.append((value_start, value_end))

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
        direct_quoted_value = re.fullmatch(r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')""", value, re.DOTALL)
        if value_start < value_end and not already_redacted and direct_quoted_value is None:
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

    hostname = parsed.hostname or ""
    netloc = parsed.netloc
    if "@" in netloc:
        authority_prefix, _separator, authority_hostname = netloc.rpartition("@")
        if not _is_azure_container_authority(parsed.scheme.lower(), hostname, authority_prefix):
            netloc = f"{REDACTED_URL_CREDENTIALS}@{authority_hostname}"
    path = _redact_url_path_tokens(parsed.scheme.lower(), hostname.lower(), parsed.path)

    query_items = []
    normalized_query = SEMICOLON_QUERY_SEPARATOR_RE.sub("&", HTML_QUERY_SEPARATOR_RE.sub("&", parsed.query))
    raw_query_values = [segment.partition("=")[2] for segment in normalized_query.split("&")]
    for index, (key, value) in enumerate(parse_qsl(normalized_query, keep_blank_values=True)):
        if _is_sensitive_detail_key(_normalize_query_key(key)):
            query_items.append((key, REDACTED_EVIDENCE_VALUE))
            continue
        redacted_value = _redact_url_query_value(value, url_depth=url_depth)
        encoded_nested_url = index < len(raw_query_values) and "%3a%2f%2f" in raw_query_values[index].lower()
        if REDACTED_URL_CREDENTIALS in redacted_value and not encoded_nested_url:
            query_items.append((key, redacted_value))
        elif _contains_nested_sensitive_query_assignment(value):
            query_items.append((key, REDACTED_EVIDENCE_VALUE))
        else:
            query_items.append((key, redacted_value))

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            path,
            urlencode(query_items, doseq=True, safe="<>"),
            "",
        )
    )


def _redact_percent_encoded_secret_candidate(match: re.Match[str], *, url_depth: int = 0) -> str:
    raw_value = match.group(0)
    if "%" not in raw_value:
        return raw_value

    decoded = raw_value
    for _ in range(MAX_PERCENT_DECODE_PASSES):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
        if STANDALONE_SECRET_RE.search(decoded):
            return REDACTED_EVIDENCE_VALUE
        normalized_decoded = _remove_unsafe_evidence_characters(decoded)
        if normalized_decoded != decoded:
            redacted_decoded = redact_evidence_string(normalized_decoded, max_chars=None, _url_depth=url_depth)
            if redacted_decoded != normalized_decoded:
                return redacted_decoded
    else:
        # Excessively nested encoding is attacker-controlled and too opaque to
        # preserve safely in evidence.
        return REDACTED_EVIDENCE_VALUE
    return raw_value


def _remove_unsafe_evidence_characters(text: str) -> str:
    """Remove model-controlled characters that can alter rendered evidence."""
    safe_characters: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char in {"\n", "\r", "\t"} or category not in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            safe_characters.append(char)
    return "".join(safe_characters)


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
            authority_prefix, _separator, _authority_hostname = parsed.netloc.rpartition("@")
            if not _is_azure_container_authority(parsed.scheme.lower(), hostname, authority_prefix):
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
    if "=" in match.group("prefix"):
        string_prefix = match.group("string_prefix") or ""
        return f"{match.group('prefix')}{string_prefix}{match.group('quote')}{REDACTED_EVIDENCE_VALUE}"
    return f"{match.group('prefix')}{REDACTED_EVIDENCE_VALUE}"


def _redact_quoted_key_value(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    quote = match.group("quote")
    string_prefix = match.group("string_prefix") or ""
    return (
        f"{match.group('key_quote')}{match.group('key')}{match.group('key_quote')}"
        f"{match.group('separator')}{string_prefix}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"
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
    quote = match.group("quote")
    string_prefix = match.group("string_prefix") or ""
    return f"{match.group('key')}{match.group('separator')}{string_prefix}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_generic_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_detail_key(match.group("key")):
        return match.group(0)
    return f"{match.group('key')}{match.group('separator')}{match.group('openers')}{REDACTED_EVIDENCE_VALUE}"


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


def _contains_only_redacted_marker_values(container_text: str) -> bool:
    try:
        parsed = ast.literal_eval(container_text)
    except (MemoryError, RecursionError, SyntaxError, ValueError):
        return False

    def is_redacted(value: Any) -> bool:
        if isinstance(value, str):
            return value == REDACTED_EVIDENCE_VALUE
        if isinstance(value, dict):
            return bool(value) and all(is_redacted(key) and is_redacted(child) for key, child in value.items())
        if isinstance(value, list | tuple | set):
            return bool(value) and all(is_redacted(child) for child in value)
        return False

    return is_redacted(parsed)


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
        container_text = text[container_start:container_end]
        if container_start == 0 and text[container_end:].strip():
            search_index = container_end
            continue
        if _is_sensitive_detail_key(match.group("key")):
            if _contains_only_redacted_marker_values(container_text):
                search_index = container_end
                continue
            redacted_chunks.append(text[last_index : match.start()])
            redacted_chunks.append(f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}")
            last_index = container_end
        elif REDACTED_EVIDENCE_VALUE not in container_text:
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
        if container_end is not None and _contains_only_redacted_marker_values(text[container_start:container_end]):
            search_index = container_end
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
        if container_start == 0 and text[container_end:].strip():
            search_index = container_end
            continue
        if REDACTED_EVIDENCE_VALUE in container_text:
            search_index = container_end
            continue
        redacted_container = _redact_structured_evidence(
            container_text,
            max_chars=len(container_text),
            fail_closed=False,
        )
        if (
            redacted_container is None
            and REDACTED_EVIDENCE_VALUE not in container_text
            and _contains_sensitive_key_literal(container_text)
        ):
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
    container_end = _find_balanced_container_end(
        stripped,
        0,
        max_scan_chars=STRUCTURED_REDACTION_PARSE_LIMIT,
    )
    if container_end is not None and container_end != len(stripped):
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


def redact_evidence_string(text: str, max_chars: int | None = 180, *, _url_depth: int = 0) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    text = _remove_unsafe_evidence_characters(text)
    effective_max_chars = len(text) if max_chars is None else max_chars
    structured_redaction = _redact_structured_evidence(text, max_chars=effective_max_chars)
    if structured_redaction is not None:
        return structured_redaction
    quoted_structured_redaction = _redact_quoted_structured_literal(text, max_chars=effective_max_chars)
    if quoted_structured_redaction is not None:
        return quoted_structured_redaction

    redacted = _redact_r_raw_assignments(text)
    redacted = _redact_leftward_assignment_expressions(redacted)
    redacted = _redact_rightward_assignment_expressions(redacted)
    redacted = URL_RE.sub(lambda match: _redact_url(match, url_depth=_url_depth), redacted)
    redacted = STANDALONE_SECRET_RE.sub(REDACTED_EVIDENCE_VALUE, redacted)
    redacted = PERCENT_ENCODED_SECRET_CANDIDATE_RE.sub(
        lambda match: _redact_percent_encoded_secret_candidate(match, url_depth=_url_depth),
        redacted,
    )
    redacted = ESCAPED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_escaped_quoted_mapping_assignment, redacted)
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
    redacted = SENSITIVE_FLAG_VALUE_RE.sub(_redact_sensitive_flag_value, redacted)
    redacted = _redact_call_assignments(redacted)
    redacted = _redact_container_assignments(redacted)
    redacted = _redact_embedded_structured_containers(redacted)
    redacted = BRACKETED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
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
    redacted = QUOTED_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
    redacted = GENERIC_QUOTED_ASSIGNMENT_RE.sub(_redact_generic_quoted_assignment, redacted)
    redacted = GENERIC_ASSIGNMENT_RE.sub(_redact_generic_assignment, redacted)
    compact_redacted = redacted.replace("\r", "").replace("\n", "").replace("\t", "")
    if compact_redacted != redacted:
        compact_candidate = redact_evidence_string(compact_redacted, max_chars=None, _url_depth=_url_depth)
        if compact_candidate != compact_redacted:
            redacted = compact_candidate
    return redacted if max_chars is None else _truncate(redacted, max_chars)


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
