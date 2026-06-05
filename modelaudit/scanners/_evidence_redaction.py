"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import io
import json
import re
import textwrap
import tokenize
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from typing import Any, Final
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from modelaudit.detectors.network_comm import _redact_url_path_tokens

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"
STRUCTURED_REDACTION_PARSE_LIMIT: Final[int] = 10 * 1024
MAX_URL_QUERY_REDACTION_DEPTH: Final[int] = 8
MAX_REDACTION_VALUE_DEPTH: Final[int] = 100
MAX_EMBEDDED_CONTAINER_MALFORMED_COUNT: Final[int] = 64
REDACTION_LOOKAHEAD_CHARS: Final[int] = 4096

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
        "awsaccesskeyid",
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
    r"(?:access[_.-]?key[_.-]?id|access[_.-]?key|access[_.-]?token|api[_.-]?key|apikey|auth[_.-]?token|"
    r"client[_.-]?secret|credential|"
    r"password|passwd|private[_-]?key|pwd|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
    r"(?!(?:[_.-](?:cache|count))\b)"
    r"(?:[_.-][a-z0-9]+)*"
)
CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:(?:[a-z][A-Za-z0-9]*)|(?:[A-Z]{2,}[A-Za-z0-9]*))?"
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
    rf"_*(?!credentials(?![A-Za-z0-9]))"
    rf"(?:{SEPARATED_SENSITIVE_ASSIGNMENT_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY})|"
    rf"{AUTHORIZATION_ALIAS_ASSIGNMENT_KEY})(?:s|[0-9]+)?"
)
SENSITIVE_CONTAINER_KEY: Final[str] = (
    rf"(?:{SENSITIVE_ASSIGNMENT_KEY}|auth|basic[_-]?auth|authorization|cookie|set[_-]?cookie|"
    rf"session[_-]?id|sessionid)"
)
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
PYTHON_ANNOTATION_PATTERN: Final[str] = r"(?:[A-Za-z_][\w.\[\](), |]*|[\"'][^\"'\r\n]+[\"'])"
SCALAR_ASSIGNMENT_OPERATOR_PATTERN: Final[str] = rf"(?:(?<![=!<>])=(?!=)|:(?!=)(?!\s*{PYTHON_ANNOTATION_PATTERN}\s*=))"
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{SCALAR_ASSIGNMENT_OPERATOR_PATTERN}\s*"
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
    rf"(?i)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*{SCALAR_ASSIGNMENT_OPERATOR_PATTERN}\s*"
    rf"{VALUE_OPENERS_PATTERN})"
    rf"{UNQUOTED_VALUE_PATTERN}"
)
INDEXED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})(?:\[[a-z0-9_-]{{0,32}}\])+\s*[:=]\s*"
    rf"{VALUE_OPENERS_PATTERN}){UNQUOTED_VALUE_PATTERN}"
)
CREDENTIALS_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(?P<prefix>credentials\s*[:=]\s*{VALUE_OPENERS_PATTERN})(?![\[{{]){UNQUOTED_VALUE_PATTERN}"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*{SCALAR_ASSIGNMENT_OPERATOR_PATTERN}\s*"
    rf"{VALUE_OPENERS_PATTERN})"
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
    rf"(?is)\b(?P<prefix>authorization\s*{SCALAR_ASSIGNMENT_OPERATOR_PATTERN}\s*"
    rf"{VALUE_OPENERS_PATTERN}){QUOTED_VALUE_PATTERN}"
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
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY})\s*{SCALAR_ASSIGNMENT_OPERATOR_PATTERN}\s*"
    rf"{VALUE_OPENERS_PATTERN})"
    rf"{UNTERMINATED_QUOTED_VALUE_PATTERN}"
)
UNTERMINATED_QUOTED_AUTHORIZATION_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>authorization\s*{SCALAR_ASSIGNMENT_OPERATOR_PATTERN}\s*"
    rf"{VALUE_OPENERS_PATTERN})"
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

SIMPLE_QUOTED_VALUE_RE: Final[re.Pattern[str]] = re.compile(rf"(?is)\A(?:\(\s*)*{QUOTED_VALUE_PATTERN}(?:\s*\))*\Z")

REGEX_REDACTABLE_SUBSCRIPT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\A\s*\b[a-z_][\w.]*(?:\s*\[[^\]\n]{{1,120}}\])*\s*"
    rf"\[\s*(?P<key_quote>[\"'])(?:{SENSITIVE_CONTAINER_KEY})(?P=key_quote)\s*\]\s*\Z"
)

SENSITIVE_ASSIGNMENT_TARGET: Final[str] = (
    rf"(?<![?&;=/%])(?:\b{SENSITIVE_CONTAINER_KEY}(?:\s*:\s*{PYTHON_ANNOTATION_PATTERN})?|"
    rf"\[\s*(?:[rubf]{{0,3}})?[\"']{SENSITIVE_CONTAINER_KEY}[\"']\s*\])"
)

SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"{SENSITIVE_ASSIGNMENT_TARGET}\s*$",
    re.IGNORECASE,
)

ANNOTATED_SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b{SENSITIVE_CONTAINER_KEY}\s*:\s*{PYTHON_ANNOTATION_PATTERN}\s*$",
    re.IGNORECASE,
)

TOKEN_ONLY_SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(?:auth|basic[_-]?auth)(?:\s*:\s*{PYTHON_ANNOTATION_PATTERN})?\s*$",
    re.IGNORECASE,
)

QUOTED_SENSITIVE_MAPPING_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?:[rubf]{{0,3}})?(?P<mapping_quote>[\"']){SENSITIVE_CONTAINER_KEY}(?P=mapping_quote)\s*$",
    re.IGNORECASE,
)

PREFIXED_QUOTED_SENSITIVE_MAPPING_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?:[rubf]{{1,3}})[\"']{SENSITIVE_CONTAINER_KEY}[\"']",
    re.IGNORECASE,
)

SENSITIVE_CONTAINER_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"\A(?:{SENSITIVE_CONTAINER_KEY})\Z",
    re.IGNORECASE,
)

SENSITIVE_OPTION_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(?:(?:[a-z0-9]+[-_.])*(?:access[-_]?key(?:[-_]?id)?|access[-_]?token|api[-_]?key|apikey|"
    r"auth[-_]?token|client[-_]?secret|credential|password|passwd|private[-_]?key|pwd|"
    r"refresh[-_]?token|sas|secret|secret[-_]?key|signature|sig|token)|authorization)\Z",
    re.IGNORECASE,
)

PYTHON_COMPOUND_ASSIGNMENT_OPERATORS: Final[tuple[str, ...]] = (
    "**=",
    "//=",
    "<<=",
    ">>=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "@=",
    "&=",
    "|=",
    "^=",
)

PYTHON_VALUE_ASSIGNMENT_OPERATORS: Final[frozenset[str]] = frozenset({"=", ":=", *PYTHON_COMPOUND_ASSIGNMENT_OPERATORS})

PYTHON_ASSIGNMENT_OPERATORS: Final[frozenset[str]] = PYTHON_VALUE_ASSIGNMENT_OPERATORS | {":"}

PYTHON_SENSITIVE_COMPARISON_OPERATORS: Final[frozenset[str]] = frozenset({"==", "!="})

PYTHON_ASSIGNMENT_OPERATOR_PATTERN: Final[str] = "|".join(
    re.escape(operator) if operator != "=" else r"(?<![=!<>])=(?!=)"
    for operator in (*PYTHON_COMPOUND_ASSIGNMENT_OPERATORS, ":=", "=")
)

SENSITIVE_EXPRESSION_ASSIGNMENT_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<target>{SENSITIVE_ASSIGNMENT_TARGET})\s*(?P<operator>{PYTHON_ASSIGNMENT_OPERATOR_PATTERN})",
    re.IGNORECASE,
)

UNPACKING_EXPRESSION_ASSIGNMENT_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"(?m)(?P<target>[^;=\r\n]{1,512},[^;=\r\n]{1,512})\s*(?P<operator>=)(?!=)"
)

STRING_LITERAL_START_RE: Final[re.Pattern[str]] = re.compile(r"(?:[rubf]{0,3})?[\"']", re.IGNORECASE)

GENERIC_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![a-z0-9_])(?:[a-z_]\w*(?:\.[a-z_]\w*)*(?:\[\s*[\"'][^\"']+[\"']\s*\])?|[\"'][^\"']+[\"'])"
    rf"\s*(?:{PYTHON_ASSIGNMENT_OPERATOR_PATTERN}|:(?![^\r\n=]*=))",
    re.IGNORECASE,
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

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = f"{REDACTED_URL_CREDENTIALS}@{netloc.rsplit('@', 1)[1]}"
    hostname = parsed.hostname or ""
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


def _redact_bracketed_mapping_assignment(match: re.Match[str]) -> str:
    context_start = max(0, match.start() - 160)
    context = match.string[context_start : match.start()]
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_.-]*\s*[:=]\s*\{\s*$", context) is not None:
        return f'{match.group("prefix")}"{REDACTED_EVIDENCE_VALUE}"'
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
        if REDACTED_EVIDENCE_VALUE in container_text:
            search_index = container_end
            continue

        if _is_sensitive_detail_key(match.group("key")):
            redacted_chunks.append(text[last_index : match.start()])
            redacted_chunks.append(f"{match.group('key')}{match.group('separator')}{REDACTED_EVIDENCE_VALUE}")
            last_index = container_end
        else:
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
        if container_end is not None and REDACTED_EVIDENCE_VALUE in text[container_start:container_end]:
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


def _redact_scalar_unquoted_assignment(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    if ":" in prefix and "=" not in prefix:
        statement_start = max(match.string.rfind("\n", 0, match.start()), match.string.rfind(";", 0, match.start())) + 1
        statement_prefix = match.string[statement_start : match.start()]
        if (
            re.search(r"\b(?:if|elif|while|lambda|case)\b", statement_prefix)
            or re.search(r"->\s*$", statement_prefix)
            or any(operator in statement_prefix for operator in PYTHON_SENSITIVE_COMPARISON_OPERATORS)
        ):
            return match.group(0)
    return f"{prefix}{REDACTED_EVIDENCE_VALUE}"


def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _position_offset(offsets: list[int], position: tuple[int, int], text_length: int) -> int:
    row, column = position
    if row <= 0:
        return 0
    if row > len(offsets):
        return text_length
    return min(offsets[row - 1] + column, text_length)


def _assignment_target_start(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    operator_index: int,
    operator_depth: int,
    *,
    stop_at_comma: bool,
) -> int:
    for index in range(operator_index - 1, -1, -1):
        token = tokens[index]
        if depths[index] < operator_depth:
            return index + 1
        if depths[index] != operator_depth:
            continue
        if token.type in {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}:
            return index + 1
        if token.type == tokenize.OP and (
            token.string == ";" or (token.string == "," and (operator_depth > 0 or stop_at_comma))
        ):
            return index + 1
    return 0


def _is_lambda_default_operator(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    operator_index: int,
    operator_depth: int,
) -> bool:
    for index in range(operator_index - 1, -1, -1):
        token = tokens[index]
        if depths[index] < operator_depth:
            return False
        if depths[index] != operator_depth:
            continue
        if token.type in {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}:
            return False
        if token.type == tokenize.OP and token.string == ";":
            return False
        if token.type == tokenize.NAME and token.string == "lambda":
            return True
    return False


def _assignment_value_end(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    value_index: int,
    operator: str,
    operator_depth: int,
    text_length: int,
    offsets: list[int],
    *,
    is_lambda_default: bool,
) -> tuple[int, list[tokenize.TokenInfo]]:
    significant: list[tokenize.TokenInfo] = []
    for index in range(value_index, len(tokens)):
        token = tokens[index]
        depth = depths[index]
        if token.type == tokenize.ENDMARKER:
            return text_length, significant
        if token.type == tokenize.NEWLINE and depth == operator_depth:
            return _position_offset(offsets, token.start, text_length), significant
        if token.type == tokenize.OP and depth == operator_depth:
            if token.string == ";" or token.string in ")]}":
                return _position_offset(offsets, token.start, text_length), significant
            if token.string == "," and (operator == ":" or operator_depth > 0 or is_lambda_default):
                return _position_offset(offsets, token.start, text_length), significant
            if token.string == ":" and is_lambda_default:
                return _position_offset(offsets, token.start, text_length), significant
        if token.type not in {
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.COMMENT,
        }:
            significant.append(token)
    return text_length, significant


def _is_simple_sensitive_assignment_tokens(tokens: list[tokenize.TokenInfo]) -> bool:
    significant = tokens
    while (
        len(significant) >= 3
        and significant[0].type == tokenize.OP
        and significant[0].string == "("
        and significant[-1].type == tokenize.OP
        and significant[-1].string == ")"
    ):
        depth = 0
        wraps_entire_value = True
        for index, token in enumerate(significant):
            if token.type != tokenize.OP:
                continue
            if token.string == "(":
                depth += 1
            elif token.string == ")":
                depth -= 1
                if depth == 0 and index != len(significant) - 1:
                    wraps_entire_value = False
                    break
        if depth != 0 or not wraps_entire_value:
            break
        significant = significant[1:-1]

    return len(significant) == 1 and significant[0].type in {tokenize.NAME, tokenize.NUMBER, tokenize.STRING}


def _is_simple_sensitive_assignment_value(value: str) -> bool:
    if SIMPLE_QUOTED_VALUE_RE.fullmatch(value.strip()) is not None:
        return True

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(value).readline))
    except (IndentationError, tokenize.TokenError):
        return False
    significant = [
        token
        for token in tokens
        if token.type
        not in {
            tokenize.ENDMARKER,
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.COMMENT,
        }
    ]
    return _is_simple_sensitive_assignment_tokens(significant)


def _contains_sensitive_unpacking_target(target: str) -> bool:
    return any(SENSITIVE_ASSIGNMENT_TARGET_RE.search(item) is not None for item in target.split(","))


def _assignment_boundary_start(text: str, assignment_start: int, value_start: int) -> int:
    boundary = assignment_start
    while boundary > value_start and text[boundary - 1] in " \t":
        boundary -= 1
    while boundary > value_start and text[boundary - 1] in "([{":
        boundary -= 1
        while boundary > value_start and text[boundary - 1] in " \t":
            boundary -= 1
    return boundary


def _unparseable_assignment_value_end(text: str, value_start: int) -> tuple[int, bool]:
    """Find a statement boundary while respecting strings and continued expressions."""
    index = value_start
    depth = 0
    quote: str | None = None
    escaped = False
    had_explicit_continuation = False

    while index < len(text):
        if quote is not None:
            if escaped:
                escaped = False
                index += 1
                continue
            if text[index] == "\\":
                escaped = True
                index += 1
                continue
            if text.startswith(quote, index):
                index += len(quote)
                quote = None
                continue
            index += 1
            continue

        if text.startswith('"""', index) or text.startswith("'''", index):
            quote = text[index : index + 3]
            index += 3
            continue
        if text[index] in "\"'":
            quote = text[index]
            index += 1
            continue
        if text[index] in "([{":
            depth += 1
            index += 1
            continue
        if text[index] in ")]}":
            if depth == 0:
                return index, had_explicit_continuation
            depth -= 1
            index += 1
            continue
        if text[index] == ";" and depth == 0:
            return index, had_explicit_continuation
        if text[index] != "\n":
            index += 1
            continue

        backslash_index = index - 1
        if backslash_index >= value_start and text[backslash_index] == "\r":
            backslash_index -= 1
        backslash_count = 0
        while backslash_index >= value_start and text[backslash_index] == "\\":
            backslash_count += 1
            backslash_index -= 1
        if backslash_count % 2 == 1:
            had_explicit_continuation = True
            index += 1
            continue
        if depth == 0:
            return index, had_explicit_continuation
        index += 1

    return len(text), had_explicit_continuation


def _is_top_level_assignment_boundary(text: str, value_start: int, boundary: int) -> bool:
    depth = 0
    quote: str | None = None
    escaped = False
    index = value_start
    while index < boundary:
        if quote is not None:
            if escaped:
                escaped = False
            elif text[index] == "\\":
                escaped = True
            elif text.startswith(quote, index):
                index += len(quote) - 1
                quote = None
            index += 1
            continue
        if text.startswith(('"""', "'''"), index):
            quote = text[index : index + 3]
            index += 3
            continue
        if text[index] in "\"'":
            quote = text[index]
        elif text[index] in "([{":
            depth += 1
        elif text[index] in ")]}" and depth > 0:
            depth -= 1
        index += 1
    return depth == 0 and quote is None


def _redact_unparseable_sensitive_expression_assignments(text: str) -> str:
    matches = list(SENSITIVE_EXPRESSION_ASSIGNMENT_PREFIX_RE.finditer(text))
    matches.extend(
        match
        for match in UNPACKING_EXPRESSION_ASSIGNMENT_PREFIX_RE.finditer(text)
        if _contains_sensitive_unpacking_target(match.group("target"))
    )
    assignment_starts = sorted(
        {
            _assignment_boundary_start(text, match.start(), 0)
            for match in (*matches, *GENERIC_ASSIGNMENT_START_RE.finditer(text))
        }
    )
    replacements: list[tuple[int, int]] = []
    for match in matches:
        value_start = match.end()
        while value_start < len(text) and text[value_start] in " \t":
            value_start += 1

        value_end, had_continuation = _unparseable_assignment_value_end(text, value_start)
        next_assignment_start = next(
            (assignment_start for assignment_start in assignment_starts if value_start < assignment_start < value_end),
            None,
        )
        if next_assignment_start is not None and _is_top_level_assignment_boundary(
            text,
            value_start,
            next_assignment_start,
        ):
            value_end = next_assignment_start

        candidate = text[value_start:value_end].rstrip()
        if not candidate:
            continue
        is_simple_value = _is_simple_sensitive_assignment_value(candidate)
        is_annotated_target = ANNOTATED_SENSITIVE_ASSIGNMENT_TARGET_RE.search(match.group("target")) is not None
        is_compound_assignment = match.group("operator") in PYTHON_COMPOUND_ASSIGNMENT_OPERATORS
        requires_fallback_redaction = (
            match.group("operator") == ":="
            or "," in match.group("target")
            or PREFIXED_QUOTED_SENSITIVE_MAPPING_KEY_RE.search(match.group("target")) is not None
        )
        if is_simple_value and not (
            had_continuation or is_annotated_target or is_compound_assignment or requires_fallback_redaction
        ):
            continue

        try:
            ast.parse(candidate, mode="eval")
        except (RecursionError, SyntaxError, ValueError):
            if STRING_LITERAL_START_RE.match(candidate):
                continue
            if any(delimiter in candidate for delimiter in "([{"):
                value_end = len(text)
        while value_end > value_start and text[value_end - 1].isspace():
            value_end -= 1
        replacements.append((value_start, value_end))

    for start, end in reversed(_merge_replacement_ranges(replacements)):
        text = f"{text[:start]}{REDACTED_EVIDENCE_VALUE}{text[end:]}"
    return text


def _token_depths(tokens: list[tokenize.TokenInfo]) -> list[int]:
    depths: list[int] = []
    depth = 0
    for token in tokens:
        depths.append(depth)
        if token.type != tokenize.OP:
            continue
        if token.string in "([{":
            depth += 1
        elif token.string in ")]}":
            depth = max(0, depth - 1)
    return depths


def _delimited_item_ranges(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    open_index: int,
) -> list[tuple[int, int]]:
    closing_token = {"(": ")", "[": "]"}.get(tokens[open_index].string)
    if closing_token is None:
        return []
    item_depth = depths[open_index] + 1
    item_start = open_index + 1
    ranges: list[tuple[int, int]] = []
    for index in range(item_start, len(tokens)):
        token = tokens[index]
        if token.type == tokenize.OP and token.string == closing_token and depths[index] == item_depth:
            if item_start < index:
                ranges.append((item_start, index))
            return ranges
        if token.type == tokenize.OP and token.string == "," and depths[index] == item_depth:
            ranges.append((item_start, index))
            item_start = index + 1
    return []


def _call_argument_ranges(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    open_paren_index: int,
) -> list[tuple[int, int]]:
    return _delimited_item_ranges(tokens, depths, open_paren_index)


def _significant_tokens(tokens: list[tokenize.TokenInfo]) -> list[tokenize.TokenInfo]:
    return [
        token
        for token in tokens
        if token.type
        not in {
            tokenize.ENDMARKER,
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.COMMENT,
        }
    ]


def _argument_keyword_and_value(
    tokens: list[tokenize.TokenInfo],
) -> tuple[str | None, list[tokenize.TokenInfo]]:
    significant = _significant_tokens(tokens)
    if (
        len(significant) >= 3
        and significant[0].type == tokenize.NAME
        and significant[1].type == tokenize.OP
        and significant[1].string == "="
    ):
        return significant[0].string, significant[2:]
    return None, significant


def _is_sensitive_literal_key(key: object) -> bool:
    if isinstance(key, bytes):
        try:
            key = key.decode()
        except UnicodeDecodeError:
            return False
    return isinstance(key, str) and SENSITIVE_CONTAINER_KEY_RE.fullmatch(key) is not None


def _static_string_literal_value(expression: ast.expr, depth: int = 0) -> str | bytes | None:
    if depth >= 64:
        return None
    if isinstance(expression, ast.Constant) and isinstance(expression.value, (str, bytes)):
        return expression.value
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        left = _static_string_literal_value(expression.left, depth + 1)
        right = _static_string_literal_value(expression.right, depth + 1)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, bytes) and isinstance(right, bytes):
            return left + right
        return None
    if isinstance(expression, ast.JoinedStr):
        parts: list[str] = []
        for value in expression.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        return "".join(parts)
    return None


def _literal_sensitive_key(tokens: list[tokenize.TokenInfo]) -> bool:
    significant = _significant_tokens(tokens)
    if not significant:
        return False
    try:
        expression = ast.parse("".join(token.string for token in significant), mode="eval").body
    except (RecursionError, SyntaxError, ValueError):
        return False
    return _is_sensitive_literal_key(_static_string_literal_value(expression))


def _target_contains_sensitive_literal_key(target: str) -> bool:
    try:
        expression = ast.parse(target.strip(), mode="eval").body
    except (RecursionError, SyntaxError, ValueError):
        return False
    if _is_sensitive_literal_key(_static_string_literal_value(expression)):
        return True
    for node in ast.walk(expression):
        if isinstance(node, ast.Subscript) and _is_sensitive_literal_key(_static_string_literal_value(node.slice)):
            return True
    return False


def _target_supports_regex_redaction(target: str) -> bool:
    try:
        expression = ast.parse(target.strip(), mode="eval").body
    except (RecursionError, SyntaxError, ValueError):
        return False

    if _is_sensitive_literal_key(_static_string_literal_value(expression)):
        return True
    return REGEX_REDACTABLE_SUBSCRIPT_TARGET_RE.fullmatch(target) is not None


def _literal_sensitive_option(tokens: list[tokenize.TokenInfo]) -> bool:
    significant = _significant_tokens(tokens)
    if not significant:
        return False
    try:
        expression = ast.parse("".join(token.string for token in significant), mode="eval").body
    except (RecursionError, SyntaxError, ValueError):
        return False
    option = _static_string_literal_value(expression)
    return isinstance(option, str) and SENSITIVE_OPTION_KEY_RE.fullmatch(option.lstrip("-")) is not None


def _ast_position_offset(text: str, offsets: list[int], lineno: int, byte_column: int) -> int:
    line_start = offsets[lineno - 1]
    line_end = offsets[lineno] if lineno < len(offsets) else len(text)
    line = text[line_start:line_end]
    character_column = len(line.encode("utf-8")[:byte_column].decode("utf-8"))
    return line_start + character_column


def _is_literal_container_open(tokens: list[tokenize.TokenInfo], open_index: int) -> bool:
    prefix_keywords = {
        "and",
        "assert",
        "case",
        "elif",
        "else",
        "for",
        "if",
        "in",
        "lambda",
        "not",
        "or",
        "return",
        "while",
        "yield",
    }
    for token in reversed(tokens[:open_index]):
        if not _significant_tokens([token]):
            continue
        if token.type == tokenize.NAME:
            return token.string in prefix_keywords
        if token.type in {tokenize.NUMBER, tokenize.STRING}:
            return False
        return token.type != tokenize.OP or token.string not in {")", "]", "}"}
    return True


def _redact_sensitive_literal_pairs(text: str) -> str:
    """Redact values in literal two-item containers headed by a credential key."""
    offsets = _line_offsets(text)
    replacements: list[tuple[int, int]] = []
    try:
        tree = ast.parse(text)
    except (RecursionError, SyntaxError, ValueError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) != 2:
                continue
            key_node, value_node = node.elts
            if not _is_sensitive_literal_key(_static_string_literal_value(key_node)):
                continue
            if value_node.end_lineno is None or value_node.end_col_offset is None:
                continue
            replacements.append(
                (
                    _ast_position_offset(text, offsets, value_node.lineno, value_node.col_offset),
                    _ast_position_offset(text, offsets, value_node.end_lineno, value_node.end_col_offset),
                )
            )
    else:
        token_input = text.replace("\x00", " ")
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(token_input).readline))
        except (IndentationError, tokenize.TokenError):
            return text
        depths = _token_depths(tokens)
        for open_index, token in enumerate(tokens):
            if token.type != tokenize.OP or token.string not in {"(", "["}:
                continue
            if not _is_literal_container_open(tokens, open_index):
                continue
            item_ranges = _delimited_item_ranges(tokens, depths, open_index)
            if len(item_ranges) != 2:
                continue
            key_start, key_end = item_ranges[0]
            value_start, value_end = item_ranges[1]
            if not _literal_sensitive_key(tokens[key_start:key_end]):
                continue
            value_tokens = _significant_tokens(tokens[value_start:value_end])
            if not value_tokens:
                continue
            replacements.append(
                (
                    _position_offset(offsets, value_tokens[0].start, len(text)),
                    _position_offset(offsets, value_tokens[-1].end, len(text)),
                )
            )

    for start, end in reversed(_merge_replacement_ranges(replacements)):
        text = f"{text[:start]}{REDACTED_EVIDENCE_VALUE}{text[end:]}"
    return text


def _comparison_target_start(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    operator_index: int,
    operator_depth: int,
) -> int:
    for index in range(operator_index - 1, -1, -1):
        token = tokens[index]
        if depths[index] < operator_depth:
            return index + 1
        if depths[index] != operator_depth:
            continue
        if token.type in {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}:
            return index + 1
        if token.type == tokenize.NAME and token.string in {"and", "or", "if", "in", "not", "while", "assert"}:
            return index + 1
        if token.type == tokenize.OP and (
            token.string in {",", ";", ":"} or token.string in PYTHON_SENSITIVE_COMPARISON_OPERATORS
        ):
            return index + 1
    return 0


def _keyed_call_argument(
    arguments: list[tuple[str | None, list[tokenize.TokenInfo]]],
    positional_index: int,
    keywords: frozenset[str],
) -> list[tokenize.TokenInfo] | None:
    for keyword, value_tokens in arguments:
        if keyword in keywords:
            return value_tokens
    positional_arguments = [value_tokens for keyword, value_tokens in arguments if keyword is None]
    if positional_index >= len(positional_arguments):
        return None
    return positional_arguments[positional_index]


def _redact_sensitive_keyed_calls(text: str) -> str:
    """Redact credential values/defaults in bounded key/value call patterns."""
    token_input = text.replace("\x00", " ")
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(token_input).readline))
    except (IndentationError, tokenize.TokenError):
        return text

    depths = _token_depths(tokens)
    offsets = _line_offsets(text)
    keyed_call_arguments = {
        "putenv": (0, 1, frozenset({"key"}), frozenset({"value"})),
        "setattr": (1, 2, frozenset({"name"}), frozenset({"value"})),
        "setdefault": (0, 1, frozenset({"key"}), frozenset({"default"})),
        "__setitem__": (0, 1, frozenset({"key"}), frozenset({"value"})),
        "getenv": (0, 1, frozenset({"key"}), frozenset({"default"})),
        "get": (0, 1, frozenset({"key"}), frozenset({"default"})),
        "getattr": (1, 2, frozenset({"name"}), frozenset({"default"})),
        "pop": (0, 1, frozenset({"key"}), frozenset({"default"})),
    }
    replacements: list[tuple[int, int]] = []
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME:
            continue
        argument_spec = keyed_call_arguments.get(token.string)
        open_paren_index = index + 1
        while open_paren_index < len(tokens) and tokens[open_paren_index].type in {tokenize.NL, tokenize.COMMENT}:
            open_paren_index += 1
        if (
            open_paren_index >= len(tokens)
            or tokens[open_paren_index].type != tokenize.OP
            or tokens[open_paren_index].string != "("
        ):
            continue

        argument_ranges = _call_argument_ranges(tokens, depths, open_paren_index)
        arguments = [
            _argument_keyword_and_value(tokens[argument_start:argument_end])
            for argument_start, argument_end in argument_ranges
        ]
        for keyword, argument_value_tokens in arguments:
            if keyword in {"auth", "cookie", "cookies"} and argument_value_tokens:
                replacements.append(
                    (
                        _position_offset(offsets, argument_value_tokens[0].start, len(text)),
                        _position_offset(offsets, argument_value_tokens[-1].end, len(text)),
                    )
                )

        if token.string in {"add_argument", "option"}:
            default_tokens = next(
                (argument_value_tokens for keyword, argument_value_tokens in arguments if keyword == "default"),
                None,
            )
            positional_arguments = [
                argument_value_tokens for keyword, argument_value_tokens in arguments if keyword is None
            ]
            if default_tokens and any(_literal_sensitive_option(value_tokens) for value_tokens in positional_arguments):
                replacements.append(
                    (
                        _position_offset(offsets, default_tokens[0].start, len(text)),
                        _position_offset(offsets, default_tokens[-1].end, len(text)),
                    )
                )

        if argument_spec is None:
            continue
        key_index, value_index, key_keywords, value_keywords = argument_spec
        key_tokens = _keyed_call_argument(arguments, key_index, key_keywords)
        value_tokens = _keyed_call_argument(arguments, value_index, value_keywords)
        if key_tokens is None or value_tokens is None:
            continue
        if not _literal_sensitive_key(key_tokens):
            continue
        if not value_tokens:
            continue
        value_start = _position_offset(offsets, value_tokens[0].start, len(text))
        value_end = _position_offset(offsets, value_tokens[-1].end, len(text))
        replacements.append((value_start, value_end))

    for start, end in reversed(_merge_replacement_ranges(replacements)):
        text = f"{text[:start]}{REDACTED_EVIDENCE_VALUE}{text[end:]}"
    return text


def _comparison_value_end(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    value_index: int,
    operator_depth: int,
    text_length: int,
    offsets: list[int],
) -> tuple[int, list[tokenize.TokenInfo]]:
    significant: list[tokenize.TokenInfo] = []
    for index in range(value_index, len(tokens)):
        token = tokens[index]
        depth = depths[index]
        if token.type == tokenize.ENDMARKER:
            return text_length, significant
        if token.type == tokenize.NEWLINE and depth == operator_depth:
            return _position_offset(offsets, token.start, text_length), significant
        if depth == operator_depth:
            if token.type == tokenize.OP and (
                token.string in ":;,)]}" or token.string in PYTHON_SENSITIVE_COMPARISON_OPERATORS
            ):
                return _position_offset(offsets, token.start, text_length), significant
            if token.type == tokenize.NAME and token.string in {"and", "in", "not", "or"}:
                return _position_offset(offsets, token.start, text_length), significant
        if token.type not in {
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.COMMENT,
        }:
            significant.append(token)
    return text_length, significant


def _redact_sensitive_comparisons(text: str) -> str:
    """Redact literal comparison operands for sensitive code targets."""
    token_input = text.replace("\x00", " ")
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(token_input).readline))
    except (IndentationError, tokenize.TokenError):
        return text

    depths = _token_depths(tokens)
    offsets = _line_offsets(text)
    text_length = len(text)
    replacements: list[tuple[int, int]] = []
    ignored_value_tokens = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT}
    for index, token in enumerate(tokens):
        is_symbol_comparison = token.type == tokenize.OP and token.string in PYTHON_SENSITIVE_COMPARISON_OPERATORS
        is_membership_comparison = token.type == tokenize.NAME and token.string == "in"
        if not is_symbol_comparison and not is_membership_comparison:
            continue
        operator_depth = depths[index]
        operator_start_index = index
        if is_membership_comparison:
            previous_index = index - 1
            while previous_index >= 0 and tokens[previous_index].type in ignored_value_tokens:
                previous_index -= 1
            if (
                previous_index >= 0
                and depths[previous_index] == operator_depth
                and tokens[previous_index].type == tokenize.NAME
                and tokens[previous_index].string == "not"
            ):
                operator_start_index = previous_index
        target_start_index = _comparison_target_start(tokens, depths, operator_start_index, operator_depth)
        target_start = _position_offset(offsets, tokens[target_start_index].start, text_length)
        target_end = _position_offset(offsets, tokens[operator_start_index].start, text_length)
        target = text[target_start:target_end]
        left_target_is_sensitive = SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None

        value_index = index + 1
        while value_index < len(tokens) and tokens[value_index].type in ignored_value_tokens:
            value_index += 1
        if value_index >= len(tokens) or tokens[value_index].type == tokenize.ENDMARKER:
            continue
        value_end, significant = _comparison_value_end(
            tokens,
            depths,
            value_index,
            operator_depth,
            text_length,
            offsets,
        )
        value_start = _position_offset(offsets, tokens[value_index].start, text_length)
        while value_end > value_start and text[value_end - 1].isspace():
            value_end -= 1
        if left_target_is_sensitive and any(value_token.type == tokenize.STRING for value_token in significant):
            replacements.append((value_start, value_end))
            continue

        right_target = text[value_start:value_end]
        if SENSITIVE_ASSIGNMENT_TARGET_RE.search(right_target) is None:
            continue
        for left_token in _significant_tokens(tokens[target_start_index:index]):
            if left_token.type == tokenize.STRING:
                replacements.append(
                    (
                        _position_offset(offsets, left_token.start, text_length),
                        _position_offset(offsets, left_token.end, text_length),
                    )
                )

    for start, end in reversed(_merge_replacement_ranges(replacements)):
        text = f"{text[:start]}{REDACTED_EVIDENCE_VALUE}{text[end:]}"
    return text


def _redact_python_expression_assignments(text: str) -> str:
    """Redact expression-valued sensitive assignments while preserving nearby code."""
    try:
        ast.parse(textwrap.dedent(text))
    except (RecursionError, SyntaxError, ValueError):
        return _redact_unparseable_sensitive_expression_assignments(text)

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (IndentationError, tokenize.TokenError):
        return _redact_unparseable_sensitive_expression_assignments(text)

    depths = _token_depths(tokens)

    offsets = _line_offsets(text)
    text_length = len(text)
    replacements: list[tuple[int, int]] = []
    ignored_value_tokens = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT}

    for index, token in enumerate(tokens):
        if token.type != tokenize.OP or token.string not in PYTHON_ASSIGNMENT_OPERATORS:
            continue

        operator_depth = depths[index]
        is_lambda_default = _is_lambda_default_operator(tokens, depths, index, operator_depth)
        target_start_index = _assignment_target_start(
            tokens,
            depths,
            index,
            operator_depth,
            stop_at_comma=is_lambda_default,
        )
        target_start = _position_offset(offsets, tokens[target_start_index].start, text_length)
        target_end = _position_offset(offsets, token.start, text_length)
        target = text[target_start:target_end]
        source_target_is_sensitive = SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None
        literal_target_is_sensitive = _target_contains_sensitive_literal_key(target)
        if token.string == ":":
            source_target_is_sensitive = QUOTED_SENSITIVE_MAPPING_KEY_RE.fullmatch(target.strip()) is not None
            if not source_target_is_sensitive and not literal_target_is_sensitive:
                continue
        elif (
            not source_target_is_sensitive
            and not literal_target_is_sensitive
            and not ("," in target and _contains_sensitive_unpacking_target(target))
        ):
            continue

        value_index = index + 1
        while value_index < len(tokens) and tokens[value_index].type in ignored_value_tokens:
            value_index += 1
        if value_index >= len(tokens) or tokens[value_index].type == tokenize.ENDMARKER:
            continue

        value_end, significant = _assignment_value_end(
            tokens,
            depths,
            value_index,
            token.string,
            operator_depth,
            text_length,
            offsets,
            is_lambda_default=is_lambda_default,
        )
        value_start = _position_offset(offsets, tokens[value_index].start, text_length)
        is_simple_value = _is_simple_sensitive_assignment_tokens(significant) or (
            SIMPLE_QUOTED_VALUE_RE.fullmatch(text[value_start:value_end].strip()) is not None
        )
        is_annotated_target = ANNOTATED_SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None
        requires_token_redaction = (
            token.string == ":="
            or "," in target
            or PREFIXED_QUOTED_SENSITIVE_MAPPING_KEY_RE.search(target) is not None
            or TOKEN_ONLY_SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None
            or (
                literal_target_is_sensitive
                and (not source_target_is_sensitive or not _target_supports_regex_redaction(target))
            )
        )
        if (
            is_simple_value
            and token.string not in PYTHON_COMPOUND_ASSIGNMENT_OPERATORS
            and not is_annotated_target
            and not requires_token_redaction
        ):
            continue

        while value_end > value_start and text[value_end - 1].isspace():
            value_end -= 1
        if value_end > value_start:
            replacements.append((value_start, value_end))

    for start, end in reversed(_merge_replacement_ranges(replacements)):
        text = f"{text[:start]}{REDACTED_EVIDENCE_VALUE}{text[end:]}"
    return text


def _merge_replacement_ranges(replacements: list[tuple[int, int]]) -> list[tuple[int, int]]:
    non_overlapping_replacements: list[tuple[int, int]] = []
    for start, end in sorted(replacements):
        if non_overlapping_replacements and end <= non_overlapping_replacements[-1][1]:
            continue
        if non_overlapping_replacements and start < non_overlapping_replacements[-1][1]:
            previous_start, _previous_end = non_overlapping_replacements[-1]
            non_overlapping_replacements[-1] = (previous_start, end)
            continue
        non_overlapping_replacements.append((start, end))
    return non_overlapping_replacements


def _looks_like_python_evidence(text: str) -> bool:
    try:
        ast.parse(text.replace("\x00", " "))
        return True
    except (RecursionError, SyntaxError, ValueError):
        return (
            SENSITIVE_EXPRESSION_ASSIGNMENT_PREFIX_RE.search(text) is not None
            or UNPACKING_EXPRESSION_ASSIGNMENT_PREFIX_RE.search(text) is not None
        )


def _looks_like_r_evidence(text: str) -> bool:
    """Recognize syntax that should receive R-specific assignment handling."""
    if re.search(r"<{1,2}-|::|\$|`[^`\r\n]+`\s*=", text) is not None:
        return True
    if R_RAW_STRING_PREFIX_RE.search(text) is not None:
        return True
    if R_RIGHTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE.search(text) is None:
        return False
    try:
        ast.parse(text.replace("\x00", " "))
    except (RecursionError, SyntaxError, ValueError):
        return True
    return False


def _redact_evidence_content(text: str, *, url_depth: int = 0) -> str:
    effective_max_chars = max(len(text), len(REDACTED_EVIDENCE_VALUE))
    structured_redaction = _redact_structured_evidence(text, max_chars=effective_max_chars)
    if structured_redaction is not None:
        return structured_redaction
    quoted_structured_redaction = _redact_quoted_structured_literal(text, max_chars=effective_max_chars)
    if quoted_structured_redaction is not None:
        return quoted_structured_redaction

    python_evidence = _looks_like_python_evidence(text)
    r_evidence = _looks_like_r_evidence(text)
    redacted = text
    if r_evidence:
        redacted = _redact_r_raw_assignments(redacted)
        redacted = _redact_leftward_assignment_expressions(redacted)
        redacted = _redact_rightward_assignment_expressions(redacted)
    redacted = _redact_sensitive_literal_pairs(redacted)
    redacted = URL_RE.sub(lambda match: _redact_url(match, url_depth=url_depth), redacted)
    if python_evidence:
        redacted = _redact_python_expression_assignments(redacted)
    elif not python_evidence:
        redacted = _redact_call_assignments(redacted)
        redacted = _redact_container_assignments(redacted)
        redacted = _redact_embedded_structured_containers(redacted)
    redacted = ESCAPED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_escaped_quoted_mapping_assignment, redacted)
    redacted = BRACKETED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_bracketed_mapping_assignment, redacted)
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
    redacted = QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SUBSCRIPTED_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = INDEXED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = CREDENTIALS_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(_redact_scalar_unquoted_assignment, redacted)
    if python_evidence:
        redacted = _redact_sensitive_comparisons(redacted)
        redacted = _redact_sensitive_keyed_calls(redacted)
    if r_evidence:
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
    if not python_evidence and not r_evidence:
        redacted = QUOTED_KEY_VALUE_RE.sub(_redact_quoted_key_value, redacted)
        redacted = GENERIC_QUOTED_ASSIGNMENT_RE.sub(_redact_generic_quoted_assignment, redacted)
        redacted = GENERIC_ASSIGNMENT_RE.sub(_redact_generic_assignment, redacted)
    return redacted


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
    if max_chars is None:
        return _redact_evidence_content(text, url_depth=_url_depth)

    limit = max(0, max_chars)
    bounded_redacted = _redact_evidence_content(text[:limit], url_depth=_url_depth)
    if len(text) <= limit:
        return bounded_redacted
    if bounded_redacted == REDACTED_EVIDENCE_VALUE:
        return REDACTED_EVIDENCE_VALUE

    lookahead_redacted = _redact_evidence_content(
        text[: limit + REDACTION_LOOKAHEAD_CHARS],
        url_depth=_url_depth,
    )
    common_length = 0
    for bounded_character, lookahead_character in zip(bounded_redacted, lookahead_redacted, strict=False):
        if bounded_character != lookahead_character:
            break
        common_length += 1
    safe_redacted_prefix = lookahead_redacted[:common_length]

    if safe_redacted_prefix == REDACTED_EVIDENCE_VALUE:
        return REDACTED_EVIDENCE_VALUE
    if (
        REDACTED_EVIDENCE_VALUE in lookahead_redacted
        and REDACTED_EVIDENCE_VALUE not in safe_redacted_prefix
        and safe_redacted_prefix.rstrip().endswith(("?", "&", "="))
    ):
        safe_redacted_prefix = f"{safe_redacted_prefix}{REDACTED_EVIDENCE_VALUE}"

    if max_chars <= 3:
        return safe_redacted_prefix[:limit]
    return f"{safe_redacted_prefix[: max_chars - 3]}..."


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
