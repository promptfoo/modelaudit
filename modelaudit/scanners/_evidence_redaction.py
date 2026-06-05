"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import copy
import io
import json
import re
import textwrap
import tokenize
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
DANGEROUS_EVIDENCE_CALL_NAMES: Final[frozenset[str]] = frozenset({"compile", "eval", "exec"})
PYTHON_STRING_QUOTE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)\A(?P<prefix>[rubf]{0,3})(?P<quote>\"\"\"|'''|[\"'])"
)
STRUCTURED_REDACTION_PARSE_LIMIT: Final[int] = 10 * 1024
MAX_URL_QUERY_REDACTION_DEPTH: Final[int] = 8
MAX_REDACTION_VALUE_DEPTH: Final[int] = 100
MAX_EMBEDDED_CONTAINER_MALFORMED_COUNT: Final[int] = 64
MAX_PERCENT_DECODE_PASSES: Final[int] = 32
REDACTION_LOOKAHEAD_CHARS: Final[int] = 4096
UNRESOLVED_VALUE_CALL_LOOKAHEAD_CHARS: Final[int] = 512
UNSAFE_ASCII_EVIDENCE_TRANSLATION: Final[dict[int, None]] = dict.fromkeys((*range(9), 11, 12, *range(14, 32), 127))

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
PERCENT_ENCODED_SECRET_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9_.+/=-]){7,}")
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
        "google_access_id",
        "google-access-id",
        "googleaccessid",
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
    r"client[_.-]?secret|credential|google[_.-]?access[_.-]?id|"
    r"password|passwd|private[_-]?key|pwd|refresh[_-]?token|sas|secret|secret[_-]?key|signature|sig|token)"
    r"(?!(?:[_.-](?:cache|count))\b)"
    r"(?:[_.-][a-z0-9]+)*"
)
CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:(?:[a-z][A-Za-z0-9]*)|(?:[A-Z]{2,}[A-Za-z0-9]*))?"
    r"(?:AccessKey|accessKey|AccessToken|accessToken|APIKey|ApiKey|apiKey|AuthToken|authToken|"
    r"ClientSecret|clientSecret|Credential|Password|Passwd|PrivateKey|privateKey|Pwd|"
    r"RefreshToken|refreshToken|GoogleAccessId|googleAccessId|SAS|Secret|SecretKey|secretKey|"
    r"Signature|Sig|Token)"
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
    rf"(?:{SENSITIVE_ASSIGNMENT_KEY}|auth|basic[_-]?auth|authorization|cookies?|set[_-]?cookie|"
    rf"session[_-]?id|sessionid)"
)
SEPARATED_SENSITIVE_R_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[._-])*"
    r"(?:access[._-]?key(?:[._-]?id)?|access[._-]?token|api[._-]?key|apikey|auth[._-]?token|"
    r"client[._-]?secret|credential|google[._-]?access[._-]?id|password|passwd|private[._-]?key|"
    r"pwd|refresh[._-]?token|sas|secret|secret[._-]?key|signature|sig|token)"
    r"(?:[._-][a-z0-9]+)*"
)
SENSITIVE_R_BARE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_R_ASSIGNMENT_KEY}|(?-i:{CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY})|"
    rf"{AUTHORIZATION_ALIAS_ASSIGNMENT_KEY})"
)
SEPARATED_SENSITIVE_R_QUOTED_IDENTIFIER_KEY: Final[str] = (
    r"(?:[a-z0-9]+[\s._-]+)*"
    r"(?:access[\s._-]*key(?:[\s._-]*id)?|access[\s._-]*token|api[\s._-]*key|apikey|"
    r"auth[\s._-]*token|client[\s._-]*secret|credential|google[\s._-]*access[\s._-]*id|"
    r"password|passwd|private[\s._-]*key|pwd|refresh[\s._-]*token|sas|secret|"
    r"secret[\s._-]*key|signature|sig|token)"
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
CONTROL_SPLIT_ASSIGNMENT_KEY_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)(?=(?P<key>{DETAIL_KEY_PATTERN})\s*[:=])")
CONTROL_SPLIT_QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?=(?P<quote>[\"'])(?P<key>{DETAIL_KEY_PATTERN})(?P=quote)\s*:)"
)
CONTROL_SPLIT_FLAG_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?=(?:^|\s)-{{1,2}}(?P<key>{DETAIL_KEY_PATTERN})\s+)"
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
    "googleaccessid",
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
TRUNCATED_R_RIGHTWARD_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    r"""(?i)->{1,2}\s*(?:[a-z.][a-z0-9._$@]*|`[^`\r\n]*|"[^"\r\n]*|'[^'\r\n]*)\Z"""
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
    rf"\b(?:auth|basic[_-]?auth|cookies?|set[_-]?cookie|session[_-]?id|sessionid)"
    rf"(?:\s*:\s*{PYTHON_ANNOTATION_PATTERN})?\s*$",
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
SENSITIVE_IDENTIFIER_SUBSCRIPT_CONTAINERS: Final[frozenset[str]] = frozenset(
    {
        "config",
        "credential",
        "credentials",
        "env",
        "environ",
        "environb",
        "environment",
        "secret",
        "secrets",
        "settings",
    }
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


def _r_raw_assignment_replacements(text: str) -> list[tuple[int, int]]:
    replacements: list[tuple[int, int]] = []
    for literal_start, literal_end, _content_start, _content_end, _is_terminated in _iter_r_raw_string_spans(text):
        left_context = text[max(0, literal_start - R_RAW_LEFT_ASSIGNMENT_CONTEXT_CHARS) : literal_start]
        if LEFTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE.search(left_context) or RIGHTWARD_R_RAW_SENSITIVE_ASSIGNMENT_RE.match(
            text,
            literal_end,
        ):
            replacements.append((literal_start, literal_end))

    return replacements


def _redact_r_raw_assignments(text: str) -> str:
    return _replace_spans(text, _r_raw_assignment_replacements(text))


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

    authority_and_path = rest.rsplit("@", 1)[1]
    authority, separator, path = authority_and_path.partition("/")
    if separator:
        safe_path = _redact_url_path_tokens(scheme[:-3].lower(), "", f"/{path}")
        authority_and_path = f"{authority}{safe_path}"

    return f"{scheme}{REDACTED_URL_CREDENTIALS}@{authority_and_path}"


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


def _decode_percent_layer_with_spans(
    value: str,
    source_spans: list[tuple[int, int]],
) -> tuple[str, list[tuple[int, int]]]:
    decoded_chars: list[str] = []
    decoded_spans: list[tuple[int, int]] = []
    index = 0
    while index < len(value):
        if (
            index + 2 < len(value)
            and value[index] == "%"
            and all(char in "0123456789abcdefABCDEF" for char in value[index + 1 : index + 3])
        ):
            decoded_chars.append(chr(int(value[index + 1 : index + 3], 16)))
            decoded_spans.append((source_spans[index][0], source_spans[index + 2][1]))
            index += 3
            continue

        decoded_chars.append(value[index])
        decoded_spans.append(source_spans[index])
        index += 1

    return "".join(decoded_chars), decoded_spans


def _redact_percent_encoded_standalone_secret_spans(raw_value: str) -> str:
    decoded = raw_value
    source_spans = [(index, index + 1) for index in range(len(raw_value))]
    secret_spans: list[tuple[int, int]] = []
    for _ in range(MAX_PERCENT_DECODE_PASSES):
        next_decoded, next_source_spans = _decode_percent_layer_with_spans(decoded, source_spans)
        if next_decoded == decoded:
            break
        decoded = next_decoded
        source_spans = next_source_spans
        for secret_match in STANDALONE_SECRET_RE.finditer(decoded):
            secret_spans.append(
                (
                    source_spans[secret_match.start()][0],
                    source_spans[secret_match.end() - 1][1],
                )
            )
    else:
        next_decoded, _ = _decode_percent_layer_with_spans(decoded, source_spans)
        if next_decoded != decoded:
            return REDACTED_EVIDENCE_VALUE

    if not secret_spans:
        return raw_value

    merged_spans: list[tuple[int, int]] = []
    for start, end in sorted(secret_spans):
        if merged_spans and start <= merged_spans[-1][1]:
            merged_spans[-1] = (merged_spans[-1][0], max(end, merged_spans[-1][1]))
        else:
            merged_spans.append((start, end))

    parts: list[str] = []
    cursor = 0
    for start, end in merged_spans:
        parts.extend((raw_value[cursor:start], REDACTED_EVIDENCE_VALUE))
        cursor = end
    parts.append(raw_value[cursor:])
    return "".join(parts)


def _redact_percent_encoded_secret_text(raw_value: str, *, url_depth: int) -> str:
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
        redacted_decoded = redact_evidence_string(
            normalized_decoded,
            max_chars=None,
            _url_depth=url_depth,
            _decode_percent=False,
        )
        if redacted_decoded != normalized_decoded:
            return redacted_decoded
    else:
        # Excessively nested encoding is attacker-controlled and too opaque to
        # preserve safely in evidence.
        return REDACTED_EVIDENCE_VALUE
    return raw_value


def _redact_percent_encoded_secret_candidate(match: re.Match[str], *, url_depth: int = 0) -> str:
    raw_value = match.group(0)
    span_redacted = _redact_percent_encoded_standalone_secret_spans(raw_value)
    if span_redacted == raw_value:
        return _redact_percent_encoded_secret_text(raw_value, url_depth=url_depth)
    if span_redacted == REDACTED_EVIDENCE_VALUE:
        return span_redacted
    return PERCENT_ENCODED_SECRET_CANDIDATE_RE.sub(
        lambda nested_match: _redact_percent_encoded_secret_text(nested_match.group(0), url_depth=url_depth),
        span_redacted,
    )


def _remove_unsafe_evidence_characters(text: str) -> str:
    """Remove model-controlled characters that can alter rendered evidence."""
    if text.isascii():
        return text.translate(UNSAFE_ASCII_EVIDENCE_TRANSLATION)

    safe_characters: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char in {"\n", "\r", "\t"} or category not in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            safe_characters.append(char)
    return "".join(safe_characters)


def _controls_split_sensitive_assignment(text: str, compact_text: str) -> bool:
    """Return whether removing controls reveals a previously split credential key."""
    original_positions = [index for index, char in enumerate(text) if char not in {"\r", "\n", "\t"}]
    exact_sensitive_keys = {
        variant
        for suffix in SENSITIVE_DETAIL_KEY_SUFFIXES
        for variant in (suffix, f"{suffix}s", f"{suffix}value", f"{suffix}values")
    }
    for pattern in (CONTROL_SPLIT_ASSIGNMENT_KEY_RE, CONTROL_SPLIT_QUOTED_KEY_RE, CONTROL_SPLIT_FLAG_KEY_RE):
        for match in pattern.finditer(compact_text):
            key = match.group("key")
            if not _is_sensitive_detail_key(key):
                continue
            key_start, key_end = match.span("key")
            if key_start >= len(original_positions) or key_end <= key_start:
                continue
            original_start = original_positions[key_start]
            original_end = original_positions[key_end - 1] + 1
            original_key = text[original_start:original_end]
            control_indexes = [index for index, char in enumerate(original_key) if char in {"\r", "\n", "\t"}]
            if not control_indexes:
                continue
            if _canonicalize_detail_key(key) in exact_sensitive_keys:
                return True
            if any(
                (index > 0 and original_key[index - 1] in {"_", "-", "."})
                or (index + 1 < len(original_key) and original_key[index + 1] in {"_", "-", "."})
                for index in control_indexes
            ):
                return True
    return False


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


def _colon_assignment_is_control_context(match: re.Match[str]) -> bool:
    prefix = match.group("prefix")
    if ":" not in prefix or "=" in prefix:
        return False
    statement_start = max(match.string.rfind("\n", 0, match.start()), match.string.rfind(";", 0, match.start())) + 1
    statement_prefix = match.string[statement_start : match.start()]
    return (
        re.match(
            r"\s*(?:(?:async\s+)?(?:class|def|for|with)|elif|else|except|finally|if|match|try|while)\b",
            statement_prefix,
        )
        is not None
        or re.search(r"\b(?:lambda|case)\b", statement_prefix) is not None
        or re.search(r"->\s*$", statement_prefix) is not None
        or any(operator in statement_prefix for operator in PYTHON_SENSITIVE_COMPARISON_OPERATORS)
    )


def _redact_unquoted_assignment(match: re.Match[str]) -> str:
    if _colon_assignment_is_control_context(match):
        return match.group(0)
    if _assignment_value_starts_redacted_dangerous_call(match):
        return match.group(0)
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


def _redact_scalar_unquoted_assignment(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    if _colon_assignment_is_control_context(match):
        return match.group(0)
    if _auth_assignment_starts_call(match):
        return match.group(0)
    return f"{prefix}{REDACTED_EVIDENCE_VALUE}"


def _auth_assignment_starts_call(match: re.Match[str]) -> bool:
    if not _assignment_value_starts_redacted_dangerous_call(match):
        return False
    prefix = match.group("prefix")
    target = re.split(r"(?<![=!<>])=(?!=)|:(?!=)", prefix, maxsplit=1)[0].strip()
    return target.lower() in {"auth", "basic_auth", "cookie", "cookies"}


def _assignment_value_starts_redacted_dangerous_call(match: re.Match[str]) -> bool:
    if match.end() >= len(match.string) or match.string[match.end()] != "(":
        return False
    value_name = re.search(r"([A-Za-z_]\w*)\Z", match.group(0))
    if value_name is None or value_name.group(1) not in DANGEROUS_EVIDENCE_CALL_NAMES:
        return False
    call_end = _find_balanced_container_end(match.string, match.end())
    return call_end is not None and REDACTED_EVIDENCE_VALUE in match.string[match.end() : call_end]


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
    closing_token = {"(": ")", "[": "]", "{": "}"}.get(tokens[open_index].string)
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


def _tokens_contain_dangerous_call(tokens: list[tokenize.TokenInfo]) -> bool:
    significant = _significant_tokens(tokens)
    return any(
        token.type == tokenize.NAME
        and token.string in DANGEROUS_EVIDENCE_CALL_NAMES
        and index + 1 < len(significant)
        and significant[index + 1].type == tokenize.OP
        and significant[index + 1].string == "("
        for index, token in enumerate(significant)
    )


def _is_sensitive_literal_key(key: object) -> bool:
    if isinstance(key, bytes):
        try:
            key = key.decode()
        except UnicodeDecodeError:
            return False
    return isinstance(key, str) and SENSITIVE_CONTAINER_KEY_RE.fullmatch(key) is not None


def _literal_sensitive_detail_key(tokens: list[tokenize.TokenInfo]) -> bool:
    significant = _significant_tokens(tokens)
    if not significant:
        return False
    try:
        expression = ast.parse("".join(token.string for token in significant), mode="eval").body
    except (RecursionError, SyntaxError, ValueError):
        return False
    key = _static_text_literal_value(expression)
    return key is not None and _is_sensitive_detail_key(key)


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


def _static_text_literal_value(expression: ast.expr) -> str | None:
    value = _static_string_literal_value(expression)
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return None
    return value if isinstance(value, str) else None


def _static_text_contains_sensitive_label(expression: ast.expr) -> bool:
    value = _static_text_literal_value(expression)
    if value is None:
        return False
    return any(_is_sensitive_detail_key(candidate) for candidate in re.findall(r"[A-Za-z][A-Za-z0-9_.-]*", value))


def _subscript_base_supports_identifier_key(expression: ast.expr) -> bool:
    if isinstance(expression, ast.Name):
        return expression.id.lower() in SENSITIVE_IDENTIFIER_SUBSCRIPT_CONTAINERS
    if isinstance(expression, ast.Attribute):
        return (
            expression.attr.lower() in SENSITIVE_IDENTIFIER_SUBSCRIPT_CONTAINERS
            or _subscript_base_supports_identifier_key(expression.value)
        )
    return False


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
        if isinstance(node, ast.Subscript):
            if _is_sensitive_literal_key(_static_string_literal_value(node.slice)):
                return True
            if (
                isinstance(node.slice, ast.Name)
                and _subscript_base_supports_identifier_key(node.value)
                and _is_sensitive_literal_key(node.slice.id)
            ):
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


def _append_ast_node_replacement(
    text: str,
    offsets: list[int],
    node: ast.AST,
    replacements: list[tuple[int, int, str]],
    replacement: str = REDACTED_EVIDENCE_VALUE,
) -> None:
    lineno = getattr(node, "lineno", None)
    col_offset = getattr(node, "col_offset", None)
    end_lineno = getattr(node, "end_lineno", None)
    end_col_offset = getattr(node, "end_col_offset", None)
    if lineno is None or col_offset is None or end_lineno is None or end_col_offset is None:
        return
    replacements.append(
        (
            _ast_position_offset(text, offsets, lineno, col_offset),
            _ast_position_offset(text, offsets, end_lineno, end_col_offset),
            replacement,
        )
    )


def _append_ast_literal_replacements(
    text: str,
    offsets: list[int],
    node: ast.AST,
    replacements: list[tuple[int, int, str]],
) -> None:
    if isinstance(node, ast.Constant) and not isinstance(node.value, (bool, type(None))):
        source = ast.get_source_segment(text, node)
        replacement = _redacted_python_string_source(source) if source is not None else None
        if replacement is None:
            replacement = (
                repr(REDACTED_EVIDENCE_VALUE.encode())
                if isinstance(node.value, bytes)
                else repr(REDACTED_EVIDENCE_VALUE)
            )
        _append_ast_node_replacement(text, offsets, node, replacements, replacement)
        return
    if isinstance(node, ast.expr) and _static_string_literal_value(node) is not None:
        _append_ast_node_replacement(text, offsets, node, replacements, repr(REDACTED_EVIDENCE_VALUE))
        return
    if isinstance(node, ast.JoinedStr):
        return
    for child in ast.iter_child_nodes(node):
        _append_ast_literal_replacements(text, offsets, child, replacements)


def _redacted_python_string_source(source: str) -> str | None:
    match = PYTHON_STRING_QUOTE_RE.match(source)
    if match is None:
        return None
    return f"{match.group('prefix')}{match.group('quote')}{REDACTED_EVIDENCE_VALUE}{match.group('quote')}"


def _ast_node_references_sensitive_value(text: str, node: ast.AST) -> bool:
    if not isinstance(node, (ast.Attribute, ast.Name, ast.Subscript)):
        return False
    source = ast.get_source_segment(text, node)
    if source is None:
        return False
    stripped = source.strip()
    return bool(
        SENSITIVE_ASSIGNMENT_TARGET_RE.search(stripped)
        or _target_contains_sensitive_literal_key(stripped)
        or (re.fullmatch(DETAIL_KEY_PATTERN, stripped) is not None and _is_sensitive_detail_key(stripped))
    )


def _ast_assignment_target_is_sensitive(text: str, node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_ast_assignment_target_is_sensitive(text, child) for child in node.elts)
    return _ast_node_references_sensitive_value(text, node)


def _string_annotation_looks_sensitive(node: ast.AST) -> bool:
    value = _static_text_literal_value(node) if isinstance(node, ast.expr) else None
    if value is None:
        return False
    return any(character.isdigit() for character in value) or (
        len(value) >= 12 and any(character.isalpha() for character in value) and value.upper() == value
    )


def _append_sensitive_ast_value_replacement(
    text: str,
    offsets: list[int],
    node: ast.AST,
    replacements: list[tuple[int, int, str]],
    *,
    preserve_executable_calls: bool = False,
) -> None:
    static_literal = _static_string_literal_value(node) if isinstance(node, ast.expr) else None
    if preserve_executable_calls and (static_literal is not None or _ast_contains_dangerous_call(node)):
        _append_ast_literal_replacements(text, offsets, node, replacements)
    else:
        _append_ast_node_replacement(text, offsets, node, replacements)


def _ast_contains_dangerous_call(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Call)
        and (
            (isinstance(child.func, ast.Name) and child.func.id in DANGEROUS_EVIDENCE_CALL_NAMES)
            or (isinstance(child.func, ast.Attribute) and child.func.attr in DANGEROUS_EVIDENCE_CALL_NAMES)
        )
        for child in ast.walk(node)
    )


def _fstring_literal_ends_sensitive_assignment(value: str) -> bool:
    separators = list(re.finditer(SCALAR_ASSIGNMENT_OPERATOR_PATTERN, value))
    if not separators:
        return False
    target = value[: separators[-1].start()].rstrip()
    return bool(SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) or QUOTED_SENSITIVE_MAPPING_KEY_RE.search(target))


def _redact_ast_literal_values(node: ast.AST) -> None:
    for child in ast.walk(node):
        if not isinstance(child, ast.Constant) or isinstance(child.value, (bool, type(None))):
            continue
        child.value = REDACTED_EVIDENCE_VALUE.encode() if isinstance(child.value, bytes) else REDACTED_EVIDENCE_VALUE


def _redact_fstring_formatted_value(node: ast.FormattedValue) -> None:
    if _ast_contains_dangerous_call(node.value):
        _redact_ast_literal_values(node.value)
    else:
        node.value = ast.Constant(REDACTED_EVIDENCE_VALUE)
    node.conversion = -1
    node.format_spec = None


def _redact_fstring_value_tail(values: list[ast.expr], start_index: int) -> None:
    for value in values[start_index:]:
        if isinstance(value, ast.FormattedValue):
            _redact_fstring_formatted_value(value)
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            value.value = REDACTED_EVIDENCE_VALUE


def _redacted_sensitive_fstring(node: ast.JoinedStr) -> str | None:
    redacted = copy.deepcopy(node)
    changed = False
    for index, value in enumerate(redacted.values[:-1]):
        next_value = redacted.values[index + 1]
        if (
            not isinstance(value, ast.Constant)
            or not isinstance(value.value, str)
            or not isinstance(next_value, ast.FormattedValue)
            or not _fstring_literal_ends_sensitive_assignment(value.value)
        ):
            continue
        value.value = REDACTED_EVIDENCE_VALUE
        _redact_fstring_value_tail(redacted.values, index + 1)
        changed = True
        break
    for index, key_value in enumerate(redacted.values[:-2]):
        separator = redacted.values[index + 1]
        candidate_value = redacted.values[index + 2]
        if (
            not isinstance(key_value, ast.FormattedValue)
            or not _is_sensitive_literal_key(_static_string_literal_value(key_value.value))
            or not isinstance(separator, ast.Constant)
            or not isinstance(separator.value, str)
            or re.fullmatch(r"\s*[:=]\s*", separator.value) is None
            or not isinstance(candidate_value, ast.FormattedValue)
        ):
            continue
        _redact_fstring_value_tail(redacted.values, index + 2)
        changed = True
        break
    return ast.unparse(redacted) if changed else None


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
    replacements: list[tuple[int, int, str]] = []
    try:
        tree = ast.parse(text.replace("\x00", " "))
    except (RecursionError, SyntaxError, ValueError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                replacement = _redacted_sensitive_fstring(node)
                if replacement is not None:
                    _append_ast_node_replacement(text, offsets, node, replacements, replacement)
                continue
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Mod)
                and _static_text_contains_sensitive_label(node.left)
            ):
                _append_sensitive_ast_value_replacement(
                    text,
                    offsets,
                    node.right,
                    replacements,
                    preserve_executable_calls=True,
                )
                continue
            value_node: ast.expr | None = None
            assignment_targets: list[ast.expr] = []
            assignment_value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                assignment_targets = node.targets
                assignment_value = node.value
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                assignment_targets = [node.target]
                assignment_value = node.value

            if assignment_targets and any(
                _ast_assignment_target_is_sensitive(text, target) for target in assignment_targets
            ):
                if isinstance(node, ast.AnnAssign) and _string_annotation_looks_sensitive(node.annotation):
                    _append_ast_literal_replacements(text, offsets, node.annotation, replacements)
                if assignment_value is not None and _ast_contains_dangerous_call(assignment_value):
                    _append_ast_literal_replacements(text, offsets, assignment_value, replacements)

            if isinstance(node, ast.Call):
                call_name = (
                    node.func.attr.lower()
                    if isinstance(node.func, ast.Attribute)
                    else node.func.id.lower()
                    if isinstance(node.func, ast.Name)
                    else ""
                )
                sensitive_arguments = [_ast_node_references_sensitive_value(text, argument) for argument in node.args]
                if call_name == "compare_digest" and any(sensitive_arguments):
                    for argument, is_sensitive in zip(node.args, sensitive_arguments, strict=True):
                        if not is_sensitive:
                            _append_ast_literal_replacements(text, offsets, argument, replacements)
                elif (
                    call_name in {"endswith", "startswith"}
                    and isinstance(node.func, ast.Attribute)
                    and _ast_node_references_sensitive_value(text, node.func.value)
                ):
                    for argument in node.args:
                        _append_ast_literal_replacements(text, offsets, argument, replacements)
                for index, argument in enumerate(node.args[:-1]):
                    if not _static_text_contains_sensitive_label(argument):
                        continue
                    for candidate_value in node.args[index + 1 :]:
                        _append_sensitive_ast_value_replacement(
                            text,
                            offsets,
                            candidate_value,
                            replacements,
                            preserve_executable_calls=True,
                        )
                    break
                if (
                    call_name == "format"
                    and isinstance(node.func, ast.Attribute)
                    and _static_text_contains_sensitive_label(node.func.value)
                ):
                    for argument in node.args:
                        _append_sensitive_ast_value_replacement(
                            text,
                            offsets,
                            argument,
                            replacements,
                            preserve_executable_calls=True,
                        )
                    for keyword in node.keywords:
                        _append_sensitive_ast_value_replacement(
                            text,
                            offsets,
                            keyword.value,
                            replacements,
                            preserve_executable_calls=True,
                        )
                for keyword in node.keywords:
                    if keyword.arg in {"auth", "cookie", "cookies"} and _ast_contains_dangerous_call(keyword.value):
                        _append_ast_literal_replacements(text, offsets, keyword.value, replacements)
                continue
            if isinstance(node, ast.Match) and _ast_node_references_sensitive_value(text, node.subject):
                for case in node.cases:
                    _append_ast_literal_replacements(text, offsets, case.pattern, replacements)
                continue
            if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) == 2:
                key_node, candidate_value_node = node.elts
                if _is_sensitive_literal_key(_static_string_literal_value(key_node)):
                    value_node = candidate_value_node
            elif isinstance(node, ast.Dict):
                items = [
                    (key, child)
                    for key_node, child in zip(node.keys, node.values, strict=True)
                    if key_node is not None and (key := _static_text_literal_value(key_node)) is not None
                ]
                for key, child in items:
                    if _is_sensitive_detail_key(key):
                        _append_sensitive_ast_value_replacement(
                            text,
                            offsets,
                            child,
                            replacements,
                            preserve_executable_calls=True,
                        )
                sensitive_descriptor = any(
                    key.lower() in {"name", "key"}
                    and (name := _static_text_literal_value(child)) is not None
                    and _is_sensitive_detail_key(name)
                    for key, child in items
                )
                if sensitive_descriptor:
                    for key, child in items:
                        if key.lower() != "value":
                            continue
                        _append_sensitive_ast_value_replacement(text, offsets, child, replacements)
                continue
            if value_node is None:
                continue
            if value_node.end_lineno is None or value_node.end_col_offset is None:
                continue
            if _ast_contains_dangerous_call(value_node):
                _append_sensitive_ast_value_replacement(
                    text,
                    offsets,
                    value_node,
                    replacements,
                    preserve_executable_calls=True,
                )
            else:
                _append_ast_node_replacement(text, offsets, value_node, replacements)
    else:
        token_input = text.replace("\x00", " ")
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(token_input).readline))
        except (IndentationError, tokenize.TokenError):
            return text
        depths = _token_depths(tokens)
        for open_index, token in enumerate(tokens):
            if token.type != tokenize.OP or token.string not in {"(", "[", "{"}:
                continue
            if not _is_literal_container_open(tokens, open_index):
                continue
            item_ranges = _delimited_item_ranges(tokens, depths, open_index)
            if token.string == "{" and "\x00" in text:
                item_depth = depths[open_index] + 1
                for item_start, item_end in item_ranges:
                    colon_index = next(
                        (
                            index
                            for index in range(item_start, item_end)
                            if tokens[index].type == tokenize.OP
                            and tokens[index].string == ":"
                            and depths[index] == item_depth
                        ),
                        None,
                    )
                    if colon_index is None or not _literal_sensitive_detail_key(tokens[item_start:colon_index]):
                        continue
                    value_tokens = _significant_tokens(tokens[colon_index + 1 : item_end])
                    if value_tokens:
                        replacement = REDACTED_EVIDENCE_VALUE
                        if len(value_tokens) == 1 and value_tokens[0].type == tokenize.STRING:
                            replacement = _redacted_python_string_source(value_tokens[0].string) or replacement
                        replacements.append(
                            (
                                _position_offset(offsets, value_tokens[0].start, len(text)),
                                _position_offset(offsets, value_tokens[-1].end, len(text)),
                                replacement,
                            )
                        )
                continue
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
                    REDACTED_EVIDENCE_VALUE,
                )
            )

    for start, end, replacement in reversed(_merge_ast_replacements(replacements)):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _merge_ast_replacements(
    replacements: list[tuple[int, int, str]],
) -> list[tuple[int, int, str]]:
    merged: list[tuple[int, int, str]] = []
    for replacement in sorted(replacements, key=lambda item: (item[0], -item[1])):
        start, end, _value = replacement
        if merged and start < merged[-1][1]:
            previous_start, previous_end, previous_value = merged[-1]
            if end <= previous_end:
                continue
            merged[-1] = (previous_start, end, previous_value)
            continue
        merged.append(replacement)
    return merged


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


def _append_token_literal_replacements(
    text: str,
    offsets: list[int],
    tokens: list[tokenize.TokenInfo],
    replacements: list[tuple[int, int, str]],
) -> None:
    for token in _significant_tokens(tokens):
        if token.type == tokenize.STRING:
            replacement = _redacted_python_string_source(token.string)
            replacement = replacement or repr(REDACTED_EVIDENCE_VALUE)
        elif token.type == tokenize.NUMBER:
            replacement = repr(REDACTED_EVIDENCE_VALUE)
        else:
            continue
        replacements.append(
            (
                _position_offset(offsets, token.start, len(text)),
                _position_offset(offsets, token.end, len(text)),
                replacement,
            )
        )


def _append_token_value_replacement(
    text: str,
    offsets: list[int],
    tokens: list[tokenize.TokenInfo],
    replacements: list[tuple[int, int]],
    literal_replacements: list[tuple[int, int, str]],
) -> None:
    significant = _significant_tokens(tokens)
    if _tokens_contain_dangerous_call(significant):
        _append_token_literal_replacements(text, offsets, significant, literal_replacements)
        return
    replacements.append(
        (
            _position_offset(offsets, tokens[0].start, len(text)),
            _position_offset(offsets, tokens[-1].end, len(text)),
        )
    )


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
    ignored_tokens = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT}
    previous_significant_tokens: list[tokenize.TokenInfo | None] = []
    previous_significant: tokenize.TokenInfo | None = None
    for candidate in tokens:
        previous_significant_tokens.append(previous_significant)
        if candidate.type not in ignored_tokens:
            previous_significant = candidate
    replacements: list[tuple[int, int]] = []
    literal_replacements: list[tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME:
            continue
        previous_significant = previous_significant_tokens[index]
        if (
            previous_significant is not None
            and previous_significant.type == tokenize.NAME
            and previous_significant.string
            in {
                "class",
                "def",
            }
        ):
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
                significant_value_tokens = _significant_tokens(argument_value_tokens)
                if _tokens_contain_dangerous_call(significant_value_tokens):
                    _append_token_literal_replacements(
                        text,
                        offsets,
                        significant_value_tokens,
                        literal_replacements,
                    )
                    continue
                replacements.append(
                    (
                        _position_offset(offsets, argument_value_tokens[0].start, len(text)),
                        _position_offset(offsets, argument_value_tokens[-1].end, len(text)),
                    )
                )

        generic_value_tokens = next(
            (argument_value_tokens for keyword, argument_value_tokens in arguments if keyword == "value"),
            None,
        )
        generic_key_tokens = next(
            (
                argument_value_tokens
                for keyword, argument_value_tokens in arguments
                if keyword in {"key", "name"} and _literal_sensitive_key(argument_value_tokens)
            ),
            None,
        )
        if generic_key_tokens is not None and generic_value_tokens:
            _append_token_value_replacement(
                text,
                offsets,
                generic_value_tokens,
                replacements,
                literal_replacements,
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
                _append_token_value_replacement(
                    text,
                    offsets,
                    default_tokens,
                    replacements,
                    literal_replacements,
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
        _append_token_value_replacement(
            text,
            offsets,
            value_tokens,
            replacements,
            literal_replacements,
        )

    combined_replacements = [
        *((start, end, REDACTED_EVIDENCE_VALUE) for start, end in replacements),
        *literal_replacements,
    ]
    for start, end, replacement in reversed(_merge_ast_replacements(combined_replacements)):
        text = f"{text[:start]}{replacement}{text[end:]}"
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
    literal_replacements: list[tuple[int, int, str]] = []
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
        if left_target_is_sensitive and any(
            value_token.type in {tokenize.NUMBER, tokenize.STRING} for value_token in significant
        ):
            if _tokens_contain_dangerous_call(significant):
                _append_token_literal_replacements(text, offsets, significant, literal_replacements)
            else:
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

    combined_replacements = [
        *((start, end, REDACTED_EVIDENCE_VALUE) for start, end in replacements),
        *literal_replacements,
    ]
    for start, end, replacement in reversed(_merge_ast_replacements(combined_replacements)):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_python_expression_assignments(text: str) -> str:
    """Redact expression-valued sensitive assignments while preserving nearby code."""
    try:
        ast.parse(textwrap.dedent(text.replace("\x00", " ")))
    except (RecursionError, SyntaxError, ValueError):
        return _redact_unparseable_sensitive_expression_assignments(text)

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text.replace("\x00", " ")).readline))
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
        stripped_target = target.strip()
        detail_target_is_sensitive = re.fullmatch(
            DETAIL_KEY_PATTERN, stripped_target
        ) is not None and _is_sensitive_detail_key(stripped_target)
        regex_target_is_sensitive = SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None
        source_target_is_sensitive = regex_target_is_sensitive or detail_target_is_sensitive
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
        preserves_executable_value = _tokens_contain_dangerous_call(significant)
        if preserves_executable_value:
            continue
        is_simple_value = _is_simple_sensitive_assignment_tokens(significant) or (
            SIMPLE_QUOTED_VALUE_RE.fullmatch(text[value_start:value_end].strip()) is not None
        )
        generic_detail_container_value = (
            detail_target_is_sensitive
            and not regex_target_is_sensitive
            and significant
            and significant[0].type == tokenize.OP
            and significant[0].string in {"(", "[", "{"}
        )
        if generic_detail_container_value and REDACTED_EVIDENCE_VALUE in text[value_start:value_end]:
            continue
        is_annotated_target = ANNOTATED_SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None
        requires_token_redaction = (
            token.string == ":="
            or "," in target
            or PREFIXED_QUOTED_SENSITIVE_MAPPING_KEY_RE.search(target) is not None
            or TOKEN_ONLY_SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is not None
            or (
                detail_target_is_sensitive
                and not regex_target_is_sensitive
                and not (
                    significant and significant[0].type == tokenize.OP and significant[0].string in {"(", "[", "{"}
                )
            )
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
    if _is_parseable_python_evidence(text):
        return True
    return SENSITIVE_EXPRESSION_ASSIGNMENT_PREFIX_RE.search(text) is not None or (
        UNPACKING_EXPRESSION_ASSIGNMENT_PREFIX_RE.search(text) is not None
    )


def _is_parseable_python_evidence(text: str) -> bool:
    try:
        ast.parse(textwrap.dedent(text.replace("\x00", " ")))
        return True
    except (RecursionError, SyntaxError, ValueError):
        return False


def _looks_like_r_evidence(text: str) -> bool:
    """Recognize syntax that should receive R-specific assignment handling."""
    if re.search(r"<{1,2}-|::|\$|`[^`\r\n]+`\s*=", text) is not None:
        return True
    if R_RAW_STRING_PREFIX_RE.search(text) is not None:
        try:
            ast.parse(textwrap.dedent(text).replace("\x00", " "))
        except (RecursionError, SyntaxError, ValueError):
            return True
        return False
    if R_RIGHTWARD_SENSITIVE_ASSIGNMENT_TARGET_RE.search(text) is None:
        return False
    try:
        ast.parse(textwrap.dedent(text).replace("\x00", " "))
    except (RecursionError, SyntaxError, ValueError):
        return True
    return False


def _lookahead_ends_inside_r_rightward_target(
    text: str,
    lookahead_text: str,
    *,
    source_truncated: bool = False,
) -> bool:
    match = TRUNCATED_R_RIGHTWARD_TARGET_RE.search(lookahead_text)
    if match is None:
        return False
    if len(lookahead_text) >= len(text):
        return source_truncated
    next_character = text[len(lookahead_text)]
    target_fragment = re.sub(r"^->{1,2}\s*", "", match.group(0))
    target_continues = re.match(r"[A-Za-z0-9._$@]", next_character) is not None
    quoted_target_closes = (
        bool(target_fragment) and target_fragment[0] in "`\"'" and next_character == target_fragment[0]
    )
    if not target_continues and not quoted_target_closes:
        return False
    statement_start = max(lookahead_text.rfind("\n", 0, match.start()), lookahead_text.rfind(";", 0, match.start())) + 1
    statement_prefix = lookahead_text[statement_start : match.start()]
    return re.match(r"\s*(?:async\s+)?def\s+", statement_prefix) is None


def _unfinished_value_call_sensitivity(
    text: str,
    lookahead_text: str,
    *,
    source_truncated: bool = False,
) -> bool | None:
    if len(lookahead_text) >= len(text) and not source_truncated:
        return None

    tokens: list[tokenize.TokenInfo] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(lookahead_text.replace("\x00", " ")).readline):
            tokens.append(token)
    except (IndentationError, tokenize.TokenError):
        # Incomplete bounded lookahead may end mid-token; partial tokens still support conservative classification.
        pass
    depths = _token_depths(tokens)
    offsets = _line_offsets(lookahead_text)
    ignored_tokens = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT}
    checked_open_parens: set[int] = set()
    found_unresolved_value_call = False
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME or token.string != "value":
            continue
        equals_index = index + 1
        while equals_index < len(tokens) and tokens[equals_index].type in ignored_tokens:
            equals_index += 1
        if (
            equals_index >= len(tokens)
            or tokens[equals_index].type != tokenize.OP
            or tokens[equals_index].string != "="
        ):
            continue

        item_depth = depths[index]
        open_paren_index = next(
            (
                candidate_index
                for candidate_index in range(index - 1, -1, -1)
                if tokens[candidate_index].type == tokenize.OP
                and tokens[candidate_index].string == "("
                and depths[candidate_index] + 1 == item_depth
            ),
            None,
        )
        if open_paren_index is None:
            continue
        open_paren = _position_offset(offsets, tokens[open_paren_index].start, len(lookahead_text))
        if open_paren in checked_open_parens:
            continue
        checked_open_parens.add(open_paren)

        declaration_prefix = lookahead_text[max(0, open_paren - 160) : open_paren]
        if re.search(r"\b(?:(?:async\s+)?def|class)\s+[A-Za-z_]\w*\s*$", declaration_prefix) is not None:
            continue
        if _find_balanced_container_end(lookahead_text, open_paren) is not None:
            continue
        found_unresolved_value_call = True

        item_depth = depths[open_paren_index] + 1
        argument_start = open_paren_index + 1
        argument_ranges: list[tuple[int, int]] = []
        for candidate_index in range(argument_start, len(tokens)):
            candidate = tokens[candidate_index]
            if candidate.type == tokenize.OP and candidate.string == "," and depths[candidate_index] == item_depth:
                argument_ranges.append((argument_start, candidate_index))
                argument_start = candidate_index + 1
        argument_ranges.append((argument_start, len(tokens)))
        visible_sensitive_descriptor = any(
            keyword in {"key", "name"} and _literal_sensitive_key(value_tokens)
            for keyword, value_tokens in (
                _argument_keyword_and_value(tokens[start:end]) for start, end in argument_ranges
            )
        )

        callee = next(
            (
                candidate.string
                for candidate in reversed(tokens[:open_paren_index])
                if candidate.type not in ignored_tokens and candidate.type == tokenize.NAME
            ),
            "",
        )
        callee_words = {
            word.lower() for word in re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+", callee.replace("_", " "))
        }
        if visible_sensitive_descriptor or callee_words.intersection(
            {"credential", "credentials", "secret", "secrets"}
        ):
            return True
    return False if found_unresolved_value_call else None


def _common_dedent_prefix(text: str, dedented: str) -> str:
    for original_line, dedented_line in zip(text.splitlines(), dedented.splitlines(), strict=False):
        if not dedented_line.strip():
            continue
        removed_count = len(original_line) - len(dedented_line)
        return original_line[:removed_count] if removed_count > 0 else ""
    return ""


def _redact_evidence_content(text: str, *, url_depth: int = 0, decode_percent: bool = True) -> str:
    effective_max_chars = max(len(text), len(REDACTED_EVIDENCE_VALUE))
    parseable_python_evidence = _is_parseable_python_evidence(text)
    parenthesized_python_evidence = parseable_python_evidence and text.lstrip().startswith("(")
    structured_redaction = _redact_structured_evidence(
        text,
        max_chars=effective_max_chars,
        fail_closed=not parenthesized_python_evidence,
    )
    if structured_redaction is not None:
        return structured_redaction
    quoted_structured_redaction = _redact_quoted_structured_literal(text, max_chars=effective_max_chars)
    if quoted_structured_redaction is not None:
        return quoted_structured_redaction

    python_evidence = _looks_like_python_evidence(text)
    r_evidence = _looks_like_r_evidence(text)
    dedented = textwrap.dedent(text) if python_evidence else text
    python_indent = _common_dedent_prefix(text, dedented) if python_evidence else ""
    redacted = dedented
    if r_evidence:
        redacted = _redact_r_raw_assignments(redacted)
        redacted = _redact_leftward_assignment_expressions(redacted)
        redacted = _redact_rightward_assignment_expressions(redacted)
    redacted = _redact_sensitive_literal_pairs(redacted)
    redacted = URL_RE.sub(lambda match: _redact_url(match, url_depth=url_depth), redacted)
    redacted = STANDALONE_SECRET_RE.sub(REDACTED_EVIDENCE_VALUE, redacted)
    if decode_percent:
        redacted = PERCENT_ENCODED_SECRET_CANDIDATE_RE.sub(
            lambda match: _redact_percent_encoded_secret_candidate(match, url_depth=url_depth),
            redacted,
        )
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

    def redact_quoted_assignment(match: re.Match[str]) -> str:
        if parseable_python_evidence and ":" in match.group("prefix") and "=" not in match.group("prefix"):
            return match.group(0)
        return _redact_quoted_assignment(match)

    def redact_unterminated_assignment(match: re.Match[str]) -> str:
        if parseable_python_evidence and ":" in match.group("prefix") and "=" not in match.group("prefix"):
            return match.group(0)
        return _redact_unterminated_quoted_assignment(match)

    def redact_unquoted_assignment(match: re.Match[str]) -> str:
        if parseable_python_evidence and ":" in match.group("prefix") and "=" not in match.group("prefix"):
            return match.group(0)
        return _redact_unquoted_assignment(match)

    def redact_scalar_assignment(match: re.Match[str]) -> str:
        if parseable_python_evidence and ":" in match.group("prefix") and "=" not in match.group("prefix"):
            return match.group(0)
        if parseable_python_evidence:
            value_start = match.start() + len(match.group("prefix"))
            value_end, _continued = _unparseable_assignment_value_end(match.string, value_start)
            try:
                value_tokens = list(tokenize.generate_tokens(io.StringIO(match.string[value_start:value_end]).readline))
            except (IndentationError, tokenize.TokenError):
                value_tokens = []
            if _tokens_contain_dangerous_call(value_tokens):
                return match.group(0)
        return _redact_scalar_unquoted_assignment(match)

    redacted = QUOTED_AUTHORIZATION_ASSIGNMENT_RE.sub(redact_quoted_assignment, redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(redact_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_MAPPING_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_SUBSCRIPTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unterminated_quoted_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_AUTHORIZATION_ASSIGNMENT_RE.sub(redact_unterminated_assignment, redacted)
    redacted = UNTERMINATED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(redact_unterminated_assignment, redacted)
    if not parseable_python_evidence:
        redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = AUTH_SCHEME_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_FLAG_VALUE_RE.sub(_redact_sensitive_flag_value, redacted)
    redacted = QUOTED_MAPPING_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = SUBSCRIPTED_SENSITIVE_UNQUOTED_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = INDEXED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_assignment, redacted)
    redacted = CREDENTIALS_ASSIGNMENT_RE.sub(redact_unquoted_assignment, redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(redact_scalar_assignment, redacted)
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
    if python_indent:
        return textwrap.indent(redacted, python_indent, predicate=lambda line: bool(line.strip()))
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


def redact_evidence_string(
    text: str,
    max_chars: int | None = 180,
    *,
    _url_depth: int = 0,
    _decode_percent: bool = True,
    _compact_controls: bool = True,
) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    raw_text = text
    if max_chars is None:
        text = _remove_unsafe_evidence_characters(raw_text)
        source_exceeds_limit = False
        source_truncated = False
    else:
        limit = max(0, max_chars)
        source_exceeds_limit = len(raw_text) > limit
        normalization_end = limit + REDACTION_LOOKAHEAD_CHARS + 1
        source_truncated = len(raw_text) > normalization_end
        text = _remove_unsafe_evidence_characters(raw_text[:normalization_end])

    compact_redacted: str | None = None
    if _compact_controls:
        control_text = text if max_chars is None else text[: max(0, max_chars) + REDACTION_LOOKAHEAD_CHARS]
        compact_text = control_text.replace("\r", "").replace("\n", "").replace("\t", "")
        if compact_text != control_text and _controls_split_sensitive_assignment(control_text, compact_text):
            compact_candidate = redact_evidence_string(
                compact_text,
                max_chars=max_chars,
                _url_depth=_url_depth,
                _decode_percent=_decode_percent,
                _compact_controls=False,
            )
            compact_baseline = compact_text if max_chars is None else _truncate(compact_text, max(0, max_chars))
            if compact_candidate != compact_baseline:
                compact_redacted = compact_candidate

    def finalize(redacted: str) -> str:
        baseline = text if max_chars is None else _truncate(text, max(0, max_chars))
        if compact_redacted is not None and redacted == baseline:
            return compact_redacted
        return redacted

    if max_chars is None:
        return finalize(_redact_evidence_content(text, url_depth=_url_depth, decode_percent=_decode_percent))

    bounded_text = text[:limit]
    lookahead_text = text[: limit + REDACTION_LOOKAHEAD_CHARS]
    unfinished_value_call_sensitivity = _unfinished_value_call_sensitivity(
        text,
        lookahead_text,
        source_truncated=source_truncated,
    )
    if (
        _lookahead_ends_inside_r_rightward_target(
            text,
            lookahead_text,
            source_truncated=source_truncated,
        )
        or unfinished_value_call_sensitivity is True
    ):
        return finalize(_truncate(REDACTED_EVIDENCE_VALUE, limit))
    if unfinished_value_call_sensitivity is False:
        lookahead_text = text[: limit + UNRESOLVED_VALUE_CALL_LOOKAHEAD_CHARS]
    raw_replacements = _r_raw_assignment_replacements(lookahead_text)
    if raw_replacements:
        bounded_text = _replace_spans(
            bounded_text,
            [(start, min(end, limit)) for start, end in raw_replacements if start < limit],
        )
    bounded_redacted = _redact_evidence_content(
        bounded_text,
        url_depth=_url_depth,
        decode_percent=_decode_percent,
    )
    if not source_exceeds_limit:
        return finalize(_truncate(bounded_redacted, limit))
    if bounded_redacted == REDACTED_EVIDENCE_VALUE:
        return finalize(_truncate(REDACTED_EVIDENCE_VALUE, limit))

    lookahead_redacted = _redact_evidence_content(
        lookahead_text,
        url_depth=_url_depth,
        decode_percent=_decode_percent,
    )
    common_length = 0
    for bounded_character, lookahead_character in zip(bounded_redacted, lookahead_redacted, strict=False):
        if bounded_character != lookahead_character:
            break
        common_length += 1
    safe_redacted_prefix = lookahead_redacted[:common_length]

    if safe_redacted_prefix == REDACTED_EVIDENCE_VALUE:
        return finalize(_truncate(REDACTED_EVIDENCE_VALUE, limit))
    if (
        REDACTED_EVIDENCE_VALUE in lookahead_redacted
        and REDACTED_EVIDENCE_VALUE not in safe_redacted_prefix
        and safe_redacted_prefix.rstrip().endswith(("?", "&", "="))
    ):
        safe_redacted_prefix = f"{safe_redacted_prefix}{REDACTED_EVIDENCE_VALUE}"

    if max_chars <= 3:
        return finalize(safe_redacted_prefix[:limit])
    return finalize(f"{safe_redacted_prefix[: max_chars - 3]}...")


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


def is_sensitive_evidence_key(key: str) -> bool:
    """Return whether a field name identifies a credential-bearing value."""
    return _is_sensitive_detail_key(key)


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
