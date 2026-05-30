"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import re
import string
import unicodedata
from typing import Final, TypeAlias
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"
EVIDENCE_REDACTION_LOOKAHEAD_CHARS: Final[int] = 4096
MAX_EVALUATED_KEY_CHARS: Final[int] = 256
MAX_KEY_EXPRESSION_CHARS: Final[int] = 300
MAX_KEY_EXPRESSION_PARSE_ATTEMPTS: Final[int] = 64
MAX_KEY_EXPRESSION_CANDIDATES: Final[int] = 8
DICT_LOOKUP_MISSING: Final[object] = object()
DICT_LOOKUP_UNKNOWN: Final[object] = object()
NONE_COMPARABLE: Final[object] = object()
EvaluatedStringSequence: TypeAlias = list[str] | tuple[str, ...] | frozenset[str]
EvaluatedStringValue: TypeAlias = str | EvaluatedStringSequence
ComparableLiteral: TypeAlias = bool | int | EvaluatedStringValue
MembershipContainer: TypeAlias = str | list[object] | tuple[object, ...] | frozenset[object]

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(?:https?|ftp|s3|gs|file)://[^\s\"'<>]+")
PYTHON_STRING_PREFIX_RE: Final[str] = r"[rubf]{0,3}"
PYTHON_LITERAL_OPEN_RE: Final[str] = r"(?:\s*\(\s*)*"
PYTHON_STRING_LITERAL_FRAGMENT_RE: Final[str] = (
    rf"(?:{PYTHON_STRING_PREFIX_RE})(?:(?:\\*[\"']){{3}}[\s\S]*?(?:\\*[\"']){{3}}|"
    r"(?:\\*[\"'])[\s\S]*?(?:\\*[\"']))"
)
PYTHON_STRING_LITERAL_DETECT_RE: Final[re.Pattern[str]] = re.compile(PYTHON_STRING_LITERAL_FRAGMENT_RE, re.IGNORECASE)
PYTHON_LITERAL_JOINED_FRAGMENT_RE: Final[str] = (
    rf"(?:(?:\s+|\s*\+\s*|\s*%\s*\(?\s*){PYTHON_STRING_LITERAL_FRAGMENT_RE}\s*\)?)"
)
PYTHON_RESIDUAL_LITERAL_OPERATOR_RE: Final[str] = r"(?:[\(\.,+*/%]|\b(?:or|and|if|else)\b)"
QUOTED_KEY_CONTENT_PATTERN: Final[str] = rf"(?:[^\\\"']|\\[\s\S]){{0,{MAX_KEY_EXPRESSION_CHARS}}}"
SERIALIZED_BACKSLASH_ESCAPE_TOKEN: Final[str] = (
    r"\\+(?:u+005c|x5c|134|U0000005c|u\{0*5c\}|N\{(?:reverse solidus|backslash)\})"
)
SERIALIZED_BACKSLASH_ESCAPE_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:u+005c|x5c|134|U0000005c|u\{0*5c\}|N\{(?:reverse solidus|backslash)\})"
)
SERIALIZED_QUOTE_ESCAPE_TOKEN: Final[str] = (
    r"(?:u+0022|u+0027|x22|x27|0?42|0?47|U00000022|U00000027|u\{0*22\}|u\{0*27\}|"
    r"N\{(?:quotation mark|double quote|apostrophe|single quote)\})"
)
SERIALIZED_QUOTE_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:{SERIALIZED_BACKSLASH_ESCAPE_TOKEN})*)\\+({SERIALIZED_QUOTE_ESCAPE_TOKEN})"
)
SERIALIZED_BACKSLASH_ESCAPED_QUOTE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:{SERIALIZED_BACKSLASH_ESCAPE_TOKEN})+)(\\+)([\"'])"
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
ASSIGNMENT_SEPARATOR: Final[str] = r"(?::=|\*\*=|//=|<<=|>>=|[+\-*/%@&|^]=|[:=](?!=))"
ASSIGNMENT_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)\s*{ASSIGNMENT_SEPARATOR}\s*")
AUTHORIZATION_SCHEME_PATTERN: Final[str] = r"(?:[a-z0-9!#$%&'*+.^_`|~-]+\s+)?"
SENSITIVE_ASSIGNMENT_KEY_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)^{SENSITIVE_ASSIGNMENT_KEY}$")
AUTHORIZATION_KEY_RE: Final[re.Pattern[str]] = re.compile(r"(?i)^authorization$")
QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\\*)([\"'])({QUOTED_KEY_CONTENT_PATTERN})\1\2\s*{ASSIGNMENT_SEPARATOR}\s*"
)
KEY_LITERAL_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)(\\*)([\"'])({QUOTED_KEY_CONTENT_PATTERN})\1\2")
COMPOSED_QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:{PYTHON_STRING_LITERAL_FRAGMENT_RE}(?:\s*\+\s*|\s+))+{PYTHON_STRING_LITERAL_FRAGMENT_RE})"
    rf"\s*{ASSIGNMENT_SEPARATOR}\s*"
)
KEY_ESCAPE_PATTERN: Final[str] = (
    r"\\+(?:u\{([0-9a-f]+)\}|U([0-9a-f]{8})|u([0-9a-f]{4})|x([0-9a-f]{2})|([0-7]{1,3})|N\{([^}]+)\})"
)
KEY_ESCAPE_TOKEN_PATTERN: Final[str] = (
    r"\\+(?:u\{[0-9a-f]+\}|U[0-9a-f]{8}|u[0-9a-f]{4}|x[0-9a-f]{2}|[0-7]{1,3}|N\{[^}]+\})"
)
KEY_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    KEY_ESCAPE_PATTERN,
    re.IGNORECASE,
)
UNQUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b((?:[a-z0-9_-]|{KEY_ESCAPE_TOKEN_PATTERN})+)(\s*{ASSIGNMENT_SEPARATOR}\s*)"
)
SUBSCRIPT_QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?:\b[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\s*)?"
    rf"\[\s*(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])((?:\\.|[^\"'])*)\1\2\s*\]"
    rf"(\s*{ASSIGNMENT_SEPARATOR}\s*)"
)
SUBSCRIPT_EXPRESSION_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?:\b[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\s*)?"
    rf"\[\s*([^\]\n]{{1,{MAX_KEY_EXPRESSION_CHARS}}})\s*\](\s*{ASSIGNMENT_SEPARATOR}\s*)"
)
SENSITIVE_EVIDENCE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*|"
    rf"\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}|\bbearer\s+)"
)
COMMAND_EXPRESSION_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)^\s*(?:\(\s*)*(?:(?:os\.system|subprocess\.(?:popen|run|call|check_output|check_call)|eval|exec|__import__)\s*\(|(?:bash|sh)\s+-c\b|cmd\.exe\s*/c\b|powershell(?:\.exe)?\b)"
)
COMMAND_EVIDENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:(?:os\.system|subprocess\.(?:popen|run|call|check_output|check_call)|eval|exec|__import__)\s*\(|(?:bash|sh)\s+-c\b|cmd\.exe\s*/c\b|powershell(?:\.exe)?\b)"
)
COMMAND_CONTEXT_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:os\.system|subprocess|__import__|bash\s+-c|sh\s+-c|cmd\.exe|powershell|curl|wget|nc\s+|netcat|"
    r"\b(?:cat|id|touch)\b|/[A-Za-z0-9_./-]+)"
)
COMMAND_BARE_SENSITIVE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b[A-Za-z0-9_.+/=-]*(?:api[_-]?key|client[_-]?secret|credential|password|passwd|private[_-]?key|"
    r"secret|signature|token)[A-Za-z0-9_.+/=-]*\b"
)
COMMAND_LITERAL_SENSITIVE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?<![-/\w.])(?![-/])[A-Za-z0-9_.+/=-]*(?:api[_-]?key|client[_-]?secret|credential|password|passwd|"
    r"private[_-]?key|secret|signature|token)[A-Za-z0-9_.+/=-]*(?![/\w.-])"
)
COMMAND_SECRET_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)((?<!\w)--(?:password|passwd|pass|proxy-password|client[_-]?secret|api[_-]?key|token|secret)"
    r"(?:=|\s+))(?:\"[^\"]*\"|'[^']*'|[^\s\"';&|)]+)"
)
COMMAND_USER_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)((?:(?<!\w)--(?:user|proxy-user)|(?<!\w)-[a-z]*u)(?:=|\s+)?)([\"']?)([^:\s\"';&|]+:)"
    r"([^\"'\s;&|)]+)([\"']?)"
)
HIGH_ENTROPY_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|[A-Za-z0-9_+/=-]{24,})\b")
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN})"
    rf"((?:(?!\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}).)*?)"
    rf"(?=[\"';&|\n]|$|\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}|\bbearer\s+)"
)
TRIPLE_QUOTED_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3[\s\S]*?\2\3\2\3\2\3"
)
TRIPLE_QUOTED_AUTHORIZATION_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3"
)
QUOTED_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"']).*?\2\3"
)
QUOTED_AUTHORIZATION_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[^\"'\s;&|]+")
TRIPLE_QUOTED_BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3[\s\S]*?\2\3\2\3\2\3"
)
TRIPLE_QUOTED_BEARER_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3"
)
QUOTED_BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"']).*?\2\3"
)
QUOTED_BEARER_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])"
)
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)"
    rf"((?:(?!\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}).)*?)"
    rf"(?=[;&|\n]|$|\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}|\bauthorization\s*{ASSIGNMENT_SEPARATOR}|\bbearer\s+)"
)
TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\3\4\3\4[\s\S]*?\3\4\3\4\3\4"
)
TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\3\4\3\4"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"']).*?\3\4"
)
QUOTED_SENSITIVE_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])"
)
ADJACENT_LITERAL_AUTHORIZATION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN})[^\s;&|]*{re.escape(REDACTED_EVIDENCE_VALUE)}[^\s;&|]*(?:{PYTHON_LITERAL_JOINED_FRAGMENT_RE})+"
)
ADJACENT_LITERAL_BEARER_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+)[^\s;&|]*{re.escape(REDACTED_EVIDENCE_VALUE)}[^\s;&|]*(?:{PYTHON_LITERAL_JOINED_FRAGMENT_RE})+"
)
ADJACENT_LITERAL_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)[^\s;&|]*{re.escape(REDACTED_EVIDENCE_VALUE)}[^\s;&|]*(?:{PYTHON_LITERAL_JOINED_FRAGMENT_RE})+"
)
RESIDUAL_LITERAL_AUTHORIZATION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bauthorization\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN})[^;&|\n]*?{re.escape(REDACTED_EVIDENCE_VALUE)}[^;&|\n]*{PYTHON_RESIDUAL_LITERAL_OPERATOR_RE}[^;&|\n]*{PYTHON_STRING_LITERAL_FRAGMENT_RE}[^;&|\n]*"
)
RESIDUAL_LITERAL_BEARER_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+)[^;&|\n]*?{re.escape(REDACTED_EVIDENCE_VALUE)}[^;&|\n]*{PYTHON_RESIDUAL_LITERAL_OPERATOR_RE}[^;&|\n]*{PYTHON_STRING_LITERAL_FRAGMENT_RE}[^;&|\n]*"
)
RESIDUAL_LITERAL_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)[^;&|\n]*?{re.escape(REDACTED_EVIDENCE_VALUE)}[^;&|\n]*{PYTHON_RESIDUAL_LITERAL_OPERATOR_RE}[^;&|\n]*{PYTHON_STRING_LITERAL_FRAGMENT_RE}[^;&|\n]*"
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


def _normalize_serialized_quote_escapes(text: str) -> str:
    def is_single_quote_escape(token: str) -> bool:
        quote_token = token.lower()
        return (
            quote_token in {"x27", "47", "047", "u00000027"}
            or re.fullmatch(r"u+0027", quote_token) is not None
            or re.fullmatch(r"u\{0*27\}", quote_token) is not None
            or "apostrophe" in quote_token
            or "single" in quote_token
        )

    def replace_backslash_quote(match: re.Match[str]) -> str:
        encoded_backslashes = len(SERIALIZED_BACKSLASH_ESCAPE_VALUE_RE.findall(match.group(1)))
        quote_backslashes = len(match.group(2))
        return "\\" * (encoded_backslashes + quote_backslashes) + match.group(3)

    def replace_escape(match: re.Match[str]) -> str:
        encoded_backslashes = len(SERIALIZED_BACKSLASH_ESCAPE_VALUE_RE.findall(match.group(1)))
        quote = "'" if is_single_quote_escape(match.group(2)) else '"'
        return "\\" * (encoded_backslashes + 1) + quote

    text = SERIALIZED_BACKSLASH_ESCAPED_QUOTE_RE.sub(replace_backslash_quote, text)
    return SERIALIZED_QUOTE_ESCAPE_RE.sub(replace_escape, text)


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    slash = match.group(3)
    quote = match.group(4)
    return f"{match.group(1)}{slash}{quote}{REDACTED_EVIDENCE_VALUE}{slash}{quote}"


def _redact_quoted_authorization(match: re.Match[str]) -> str:
    slash = match.group(2)
    quote = match.group(3)
    return f"{match.group(1)}{slash}{quote}{REDACTED_EVIDENCE_VALUE}{slash}{quote}"


def _redact_prefixed_quoted_value(match: re.Match[str]) -> str:
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}"


def _decode_key_escapes(key: str) -> str:
    def replace_escape(match: re.Match[str]) -> str:
        if match.group(6) is not None:
            try:
                return unicodedata.lookup(match.group(6))
            except KeyError:
                return match.group(0)

        raw_value = next(group for group in match.groups()[:5] if group is not None)
        codepoint = int(raw_value, 8 if match.group(5) is not None else 16)
        if codepoint > 0x10FFFF:
            return match.group(0)
        return chr(codepoint)

    return KEY_ESCAPE_RE.sub(replace_escape, key)


def _normalize_quoted_sensitive_keys(text: str) -> str:
    def replace_composed_key(match: re.Match[str]) -> str:
        decoded_key = "".join(
            _decode_key_escapes(key_match.group(3)) for key_match in KEY_LITERAL_RE.finditer(match.group(1))
        )
        normalized_key = _normalize_sensitive_key(decoded_key)
        if normalized_key is not None:
            return f"{normalized_key}="
        return match.group(0)

    def replace_key(match: re.Match[str]) -> str:
        if _is_composed_key_fragment(text, match.start()):
            return match.group(0)
        decoded_key = _decode_key_escapes(match.group(3))
        normalized_key = _normalize_sensitive_key(decoded_key)
        if normalized_key is not None:
            return f"{normalized_key}="
        return match.group(0)

    text = COMPOSED_QUOTED_KEY_RE.sub(replace_composed_key, text)
    return QUOTED_KEY_RE.sub(replace_key, text)


def _normalize_unquoted_sensitive_keys(text: str) -> str:
    def replace_key(match: re.Match[str]) -> str:
        decoded_key = _decode_key_escapes(match.group(1))
        normalized_key = _normalize_sensitive_key(decoded_key)
        if normalized_key is not None:
            return f"{normalized_key}{match.group(2)}"
        return match.group(0)

    return UNQUOTED_KEY_RE.sub(replace_key, text)


def _normalize_subscript_sensitive_keys(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        if text[index] != "[" or _is_inside_quoted_literal(text, 0, index):
            index += 1
            continue
        expression_end = _find_subscript_expression_end(text, index)
        if expression_end is None:
            index += 1
            continue
        separator_match = ASSIGNMENT_SEPARATOR_RE.match(text, expression_end + 1)
        if separator_match is None:
            index = expression_end + 1
            continue

        expression = text[index + 1 : expression_end].strip()
        normalized_key = _sensitive_key_from_safe_expression(expression)
        if normalized_key is not None:
            replacement_start = _subscript_target_start(text, index)
            replacements.append(
                (
                    replacement_start,
                    separator_match.end(),
                    f"{normalized_key}{separator_match.group(0)}",
                )
            )
        index = expression_end + 1

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _sensitive_key_from_safe_expression(expression: str) -> str | None:
    if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS:
        return None
    if not _has_sensitive_literal_signal(expression):
        return None
    try:
        value = _safe_eval_string_expr(ast.parse(expression, mode="eval"))
    except SyntaxError:
        value = None
    return _normalize_sensitive_key(value) if isinstance(value, str) else None


def _subscript_target_start(text: str, bracket_start: int) -> int:
    index = bracket_start - 1
    while index >= 0 and text[index].isspace():
        index -= 1
    target_end = index + 1
    while index >= 0 and (text[index].isalnum() or text[index] in {"_", "."}):
        index -= 1
    target_start = index + 1
    target = text[target_start:target_end]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", target):
        return target_start
    return bracket_start


def _find_subscript_expression_end(text: str, start: int) -> int | None:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start + 1
    while index < len(text):
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char == "[":
            bracket_depth += 1
        elif char == "]":
            if bracket_depth == 0:
                return index
            bracket_depth -= 1
        elif char in {";", "\n"}:
            return None
        index += 1
    return None


def _normalize_sensitive_key(decoded_key: str) -> str | None:
    if SENSITIVE_ASSIGNMENT_KEY_RE.fullmatch(decoded_key):
        return decoded_key
    if AUTHORIZATION_KEY_RE.fullmatch(decoded_key):
        return "Authorization"
    return None


def _is_composed_key_fragment(text: str, start: int) -> bool:
    prefix = text[:start].rstrip()
    return bool(prefix) and (prefix[-1] == "+" or prefix[-1] in {"'", '"'})


def _safe_eval_string_expr(node: ast.AST) -> EvaluatedStringValue | None:
    if isinstance(node, ast.Expression):
        return _safe_eval_string_expr(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= MAX_EVALUATED_KEY_CHARS else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for joined_value in node.values:
            if isinstance(joined_value, ast.Constant) and isinstance(joined_value.value, str):
                parts.append(joined_value.value)
                continue
            if (
                isinstance(joined_value, ast.FormattedValue)
                and joined_value.conversion in {-1, ord("s")}
                and _safe_eval_format_spec(joined_value.format_spec) in {None, "", "s"}
            ):
                formatted_value = _safe_eval_string_expr(joined_value.value)
                if isinstance(formatted_value, str):
                    parts.append(formatted_value)
                    continue
            return None
        return _join_bounded(parts)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for element in node.elts:  # type: ignore[attr-defined]
            element_value = _safe_eval_string_expr(element)
            if not isinstance(element_value, str):
                return None
            values.append(element_value)
        if isinstance(node, ast.List):
            return _list_bounded(values)
        if isinstance(node, ast.Set):
            return _frozenset_bounded(values)
        return _tuple_bounded(values)
    if isinstance(node, ast.IfExp):
        condition = _safe_eval_truthy_literal(node.test)
        if condition is not None:
            return _safe_eval_string_expr(node.body if condition else node.orelse)
    if isinstance(node, ast.BoolOp):
        last_value: str | None = None
        for value_node in node.values:
            value = _safe_eval_string_expr(value_node)
            if not isinstance(value, str):
                return None
            last_value = value
            if isinstance(node.op, ast.Or) and value:
                return value
            if isinstance(node.op, ast.And) and not value:
                return value
        if last_value is None:
            return None
        if isinstance(node.op, (ast.Or, ast.And)):
            return last_value
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Dict):
            key = _safe_eval_string_expr(node.slice)
            if isinstance(key, str):
                return _safe_eval_string_dict_lookup(node.value, key)
        base = _safe_eval_string_expr(node.value)
        if isinstance(base, str):
            value_slice = _safe_eval_slice(node.slice)
            if value_slice is not None:
                sliced = base[value_slice]
                return sliced if len(sliced) <= MAX_EVALUATED_KEY_CHARS else None
        index = _safe_eval_int_literal(node.slice)
        if isinstance(base, (tuple, list)) and index is not None and -len(base) <= index < len(base):
            return base[index]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _safe_eval_string_expr(node.left)
        right = _safe_eval_string_expr(node.right)
        if isinstance(left, str) and isinstance(right, str):
            return _join_bounded([left, right])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left = _safe_eval_string_expr(node.left)
        right = _safe_eval_string_expr(node.right)
        if isinstance(left, str):
            multiplier = _safe_eval_int_literal(node.right)
            if multiplier is not None:
                return _repeat_bounded(left, multiplier)
        if isinstance(right, str):
            multiplier = _safe_eval_int_literal(node.left)
            if multiplier is not None:
                return _repeat_bounded(right, multiplier)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = _safe_eval_string_expr(node.left)
        right = _safe_eval_string_expr(node.right)
        if isinstance(left, str) and isinstance(right, (str, tuple)):
            return _safe_percent_literal(left, right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "decode"
        and not node.keywords
        and len(node.args) <= 1
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Attribute)
        and node.func.value.func.attr == "encode"
        and not node.func.value.keywords
        and len(node.func.value.args) <= 1
    ):
        base = _safe_eval_string_expr(node.func.value.func.value)
        encode_arg = _safe_eval_string_expr(node.func.value.args[0]) if node.func.value.args else "utf-8"
        decode_arg = _safe_eval_string_expr(node.args[0]) if node.args else "utf-8"
        if isinstance(base, str) and encode_arg == decode_arg and isinstance(encode_arg, str):
            return base
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        base = _safe_eval_string_expr(node.func.value)
        args = tuple(_safe_eval_string_expr(arg) for arg in node.args)
        kwargs = {
            keyword.arg: _safe_eval_string_expr(keyword.value) for keyword in node.keywords if keyword.arg is not None
        }
        if (
            isinstance(base, str)
            and all(isinstance(arg, str) for arg in args)
            and len(kwargs) == len(node.keywords)
            and all(isinstance(value, str) for value in kwargs.values())
        ):
            return _safe_format_literal(base, args, kwargs)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"strip", "lstrip", "rstrip"}
    ):
        base = _safe_eval_string_expr(node.func.value)
        if isinstance(base, str) and len(node.args) <= 1 and not node.keywords:
            chars = _safe_eval_string_expr(node.args[0]) if node.args else None
            if node.args and not isinstance(chars, str):
                return None
            if chars == "":
                return None
            result = getattr(base, node.func.attr)(chars)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"capitalize", "casefold", "lower", "swapcase", "title", "upper"}
        and not node.args
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        if isinstance(base, str):
            result = getattr(base, node.func.attr)()
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"removeprefix", "removesuffix"}
        and len(node.args) == 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        affix = _safe_eval_string_expr(node.args[0])
        if isinstance(base, str) and isinstance(affix, str):
            result = getattr(base, node.func.attr)(affix)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"split", "rsplit"}
        and len(node.args) <= 2
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        separator = _safe_eval_string_expr(node.args[0]) if node.args else None
        maxsplit = _safe_eval_int_literal(node.args[1]) if len(node.args) == 2 else -1
        if (
            isinstance(base, str)
            and (not node.args or isinstance(separator, str))
            and (len(node.args) < 2 or maxsplit is not None)
            and separator != ""
        ):
            parts = getattr(base, node.func.attr)(separator, maxsplit)
            return _tuple_bounded(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"partition", "rpartition"}
        and len(node.args) == 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        separator = _safe_eval_string_expr(node.args[0])
        if isinstance(base, str) and isinstance(separator, str) and separator:
            return _tuple_bounded(list(getattr(base, node.func.attr)(separator)))
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "zfill"
        and len(node.args) == 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        width = _safe_eval_int_literal(node.args[0])
        if isinstance(base, str) and width is not None:
            result = base.zfill(width)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"center", "ljust", "rjust"}
        and len(node.args) in {1, 2}
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        width = _safe_eval_int_literal(node.args[0])
        fillchar = _safe_eval_string_expr(node.args[1]) if len(node.args) == 2 else " "
        if isinstance(base, str) and width is not None and isinstance(fillchar, str) and len(fillchar) == 1:
            result = getattr(base, node.func.attr)(width, fillchar)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "expandtabs"
        and len(node.args) <= 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        tabsize = _safe_eval_int_literal(node.args[0]) if node.args else 8
        if isinstance(base, str) and tabsize is not None:
            result = base.expandtabs(tabsize)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and len(node.args) in {2, 3}
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        old = _safe_eval_string_expr(node.args[0])
        new = _safe_eval_string_expr(node.args[1])
        count = _safe_eval_int_literal(node.args[2]) if len(node.args) == 3 else None
        if (
            isinstance(base, str)
            and isinstance(old, str)
            and isinstance(new, str)
            and (len(node.args) == 2 or count is not None)
        ):
            if old == "":
                return base if new == "" else None
            result = base.replace(old, new) if count is None else base.replace(old, new, count)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
    ):
        separator = _safe_eval_string_expr(node.func.value)
        join_values = _safe_eval_string_expr(node.args[0])
        if isinstance(separator, str) and isinstance(join_values, (tuple, list)) and not node.keywords:
            join_parts: list[str] = []
            for index, value in enumerate(join_values):
                if index:
                    join_parts.append(separator)
                join_parts.append(value)
            return _join_bounded(join_parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and len(node.args) == 1
        and not node.keywords
    ):
        str_value = _safe_eval_string_expr(node.args[0])
        if isinstance(str_value, str):
            return str_value
    return None


def _safe_eval_int_literal(node: ast.AST) -> int | None:
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
        and abs(node.value) <= MAX_EVALUATED_KEY_CHARS
    ):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _safe_eval_int_literal(node.operand)
        return -value if value is not None else None
    return None


def _safe_eval_bool_literal(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _safe_eval_truthy_literal(node: ast.AST) -> bool | None:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _safe_eval_truthy_literal(node.operand)
        return not value if value is not None else None
    if isinstance(node, ast.Constant) and node.value is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, (float, complex)):
        return bool(node.value)
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return bool(node.value) if len(node.value) <= MAX_EVALUATED_KEY_CHARS else None
    if isinstance(node, ast.Dict) and not node.keys:
        return False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"dict", "frozenset", "list", "set", "tuple"}
        and not node.keywords
    ):
        if not node.args:
            return False
        if len(node.args) == 1:
            argument_truth = _safe_eval_truthy_literal(node.args[0])
            if argument_truth is False:
                return False
            if argument_truth is True and node.func.id in {"frozenset", "list", "set", "tuple"}:
                return True
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.Or):
            saw_value = False
            for value_node in node.values:
                value = _safe_eval_truthy_literal(value_node)
                if value is None:
                    return None
                saw_value = True
                if value:
                    return True
            return False if saw_value else None
        if isinstance(node.op, ast.And):
            saw_value = False
            for value_node in node.values:
                value = _safe_eval_truthy_literal(value_node)
                if value is None:
                    return None
                saw_value = True
                if not value:
                    return False
            return True if saw_value else None
    bool_value = _safe_eval_bool_literal(node)
    if bool_value is not None:
        return bool_value
    compare_value = _safe_eval_compare_literal(node)
    if compare_value is not None:
        return compare_value
    int_value = _safe_eval_int_literal(node)
    if int_value is not None:
        return bool(int_value)
    string_value = _safe_eval_string_expr(node)
    if isinstance(string_value, (str, tuple, list, frozenset)):
        return bool(string_value)
    return None


def _safe_eval_compare_literal(node: ast.AST) -> bool | None:
    if not isinstance(node, ast.Compare):
        return None
    left_value = _safe_eval_comparable_or_none_literal(node.left)
    if left_value is None:
        return None
    left: object = left_value
    for operator, comparator in zip(node.ops, node.comparators, strict=True):
        if isinstance(operator, (ast.In, ast.NotIn)):
            container = _safe_eval_membership_container(comparator)
            if container is None:
                return None
            result = _safe_eval_membership_literal(left, container)
            if result is None:
                return None
            if isinstance(operator, ast.NotIn):
                result = not result
            if not result:
                return False
            left = container
            continue
        else:
            right = _safe_eval_comparable_or_none_literal(comparator)
            if right is None:
                return None
        if isinstance(operator, ast.Eq):
            result = left == right
        elif isinstance(operator, ast.NotEq):
            result = left != right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.Lt):
            result = left < right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.LtE):
            result = left <= right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.Gt):
            result = left > right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.GtE):
            result = left >= right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.Lt):
            result = left < right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.LtE):
            result = left <= right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.Gt):
            result = left > right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.GtE):
            result = left >= right
        else:
            identity_result = _safe_eval_identity_compare(left, right, operator)
            if identity_result is not None:
                result = identity_result
                if not result:
                    return False
                left = right
                continue
            container_result = _safe_eval_container_compare(left, right, operator)
            if container_result is None:
                return None
            result = container_result
        if not result:
            return False
        left = right
    return True


def _safe_eval_membership_literal(left: object, container: MembershipContainer) -> bool | None:
    if isinstance(container, str):
        if not isinstance(left, str):
            return None
        return left in container
    try:
        return left in container
    except TypeError:
        return None


def _safe_eval_identity_compare(left: object, right: object, operator: ast.cmpop) -> bool | None:
    if not isinstance(operator, (ast.Is, ast.IsNot)):
        return None
    if not (
        left is NONE_COMPARABLE or right is NONE_COMPARABLE or (isinstance(left, bool) and isinstance(right, bool))
    ):
        return None
    result = left is right
    return not result if isinstance(operator, ast.IsNot) else result


def _safe_eval_container_compare(left: object, right: object, operator: ast.cmpop) -> bool | None:
    if isinstance(left, list) and isinstance(right, list):
        return _safe_eval_list_compare(left, right, operator)
    if isinstance(left, tuple) and isinstance(right, tuple):
        return _safe_eval_tuple_compare(left, right, operator)
    if isinstance(left, frozenset) and isinstance(right, frozenset):
        return _safe_eval_set_compare(left, right, operator)
    return None


def _safe_eval_list_compare(left: list[str], right: list[str], operator: ast.cmpop) -> bool | None:
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    return None


def _safe_eval_tuple_compare(left: tuple[str, ...], right: tuple[str, ...], operator: ast.cmpop) -> bool | None:
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    return None


def _safe_eval_set_compare(left: frozenset[str], right: frozenset[str], operator: ast.cmpop) -> bool | None:
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    return None


def _safe_eval_comparable_literal(node: ast.AST) -> ComparableLiteral | None:
    bool_value = _safe_eval_bool_literal(node)
    if bool_value is not None:
        return bool_value
    int_value = _safe_eval_int_literal(node)
    if int_value is not None:
        return int_value
    string_value = _safe_eval_string_expr(node)
    return string_value if isinstance(string_value, (str, tuple, list, frozenset)) else None


def _safe_eval_comparable_or_none_literal(node: ast.AST) -> object | None:
    value = _safe_eval_comparable_literal(node)
    if value is not None:
        return value
    if isinstance(node, ast.Constant) and node.value is None:
        return NONE_COMPARABLE
    return None


def _safe_eval_membership_container(node: ast.AST) -> MembershipContainer | None:
    value = _safe_eval_string_expr(node)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        members: list[object] = list(value)
        return members
    if isinstance(value, (tuple, frozenset)):
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[object] = []
        total = 0
        for element in node.elts:  # type: ignore[attr-defined]
            element_value = _safe_eval_comparable_literal(element)
            if element_value is None:
                return None
            total += _safe_eval_literal_size(element_value)
            if total > MAX_EVALUATED_KEY_CHARS:
                return None
            values.append(element_value)
        if isinstance(node, ast.List):
            return values
        if isinstance(node, ast.Set):
            try:
                return frozenset(values)
            except TypeError:
                return None
        return tuple(values)
    return None


def _safe_eval_literal_size(value: object) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, (bool, int)):
        return 1
    if isinstance(value, (tuple, list, frozenset)):
        return sum(_safe_eval_literal_size(item) for item in value)
    return MAX_EVALUATED_KEY_CHARS + 1


def _safe_eval_string_dict_lookup(node: ast.Dict, lookup_key: str) -> str | None:
    result = _safe_eval_string_dict_lookup_result(node, lookup_key)
    return result if isinstance(result, str) else None


def _safe_eval_string_dict_lookup_result(node: ast.Dict, lookup_key: str) -> str | None | object:
    total = 0
    selected_value: str | None | object = DICT_LOOKUP_MISSING
    unknown_before_selection = False
    unknown_after_selection = False
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if key_node is None:
            if not isinstance(value_node, ast.Dict):
                return DICT_LOOKUP_UNKNOWN
            unpacked_value = _safe_eval_string_dict_lookup_result(value_node, lookup_key)
            if unpacked_value is DICT_LOOKUP_UNKNOWN:
                if selected_value is DICT_LOOKUP_MISSING:
                    unknown_before_selection = True
                else:
                    unknown_after_selection = True
                continue
            if unpacked_value is not DICT_LOOKUP_MISSING:
                selected_value = unpacked_value
            continue
        key = _safe_eval_string_expr(key_node)
        if not isinstance(key, str):
            if isinstance(key_node, ast.Constant):
                continue
            if selected_value is not DICT_LOOKUP_MISSING:
                unknown_after_selection = True
            else:
                unknown_before_selection = True
            continue
        total += len(key)
        if total > MAX_EVALUATED_KEY_CHARS:
            return DICT_LOOKUP_UNKNOWN
        if key != lookup_key:
            continue
        value = _safe_eval_string_expr(value_node)
        selected_value = value if isinstance(value, str) else None
        unknown_before_selection = False
        unknown_after_selection = False
    if unknown_after_selection:
        return DICT_LOOKUP_UNKNOWN
    if selected_value is DICT_LOOKUP_MISSING and unknown_before_selection:
        return DICT_LOOKUP_UNKNOWN
    return selected_value


def _safe_eval_slice(node: ast.AST) -> slice | None:
    if not isinstance(node, ast.Slice):
        return None
    lower = _safe_eval_int_literal(node.lower) if node.lower is not None else None
    upper = _safe_eval_int_literal(node.upper) if node.upper is not None else None
    step = _safe_eval_int_literal(node.step) if node.step is not None else None
    if (
        (node.lower is not None and lower is None)
        or (node.upper is not None and upper is None)
        or (node.step is not None and step is None)
    ):
        return None
    if step == 0:
        return None
    return slice(lower, upper, step)


def _safe_eval_format_spec(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    value = _safe_eval_string_expr(node)
    return value if isinstance(value, str) else None


def _join_bounded(parts: list[str]) -> str | None:
    total = 0
    for part in parts:
        total += len(part)
        if total > MAX_EVALUATED_KEY_CHARS:
            return None
    return "".join(parts)


def _tuple_bounded(parts: list[str]) -> tuple[str, ...] | None:
    if not _strings_within_bound(parts):
        return None
    return tuple(parts)


def _list_bounded(parts: list[str]) -> list[str] | None:
    if not _strings_within_bound(parts):
        return None
    return list(parts)


def _frozenset_bounded(parts: list[str]) -> frozenset[str] | None:
    if not _strings_within_bound(parts):
        return None
    return frozenset(parts)


def _strings_within_bound(parts: list[str]) -> bool:
    total = 0
    for part in parts:
        total += len(part)
        if total > MAX_EVALUATED_KEY_CHARS:
            return False
    return True


def _repeat_bounded(value: str, multiplier: int) -> str | None:
    if multiplier < 0:
        return None
    if len(value) * multiplier > MAX_EVALUATED_KEY_CHARS:
        return None
    return value * multiplier


def _safe_percent_literal(format_string: str, values: str | tuple[str, ...]) -> str | None:
    value_tuple = (values,) if isinstance(values, str) else values
    value_index = 0
    parts: list[str] = []
    index = 0
    while index < len(format_string):
        char = format_string[index]
        if char != "%":
            parts.append(char)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
            index += 1
            continue
        if index + 1 >= len(format_string):
            return None
        marker = format_string[index + 1]
        if marker == "%":
            parts.append("%")
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
            index += 2
            continue
        if marker != "s" or value_index >= len(value_tuple):
            return None
        parts.append(value_tuple[value_index])
        if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
            return None
        value_index += 1
        index += 2

    if value_index != len(value_tuple):
        return None
    return "".join(parts)


def _safe_format_literal(
    base: str, args: tuple[EvaluatedStringValue | None, ...], kwargs: dict[str, EvaluatedStringValue | None]
) -> str | None:
    formatter = string.Formatter()
    parts: list[str] = []
    automatic_index = 0
    try:
        parsed = list(formatter.parse(base))
    except ValueError:
        return None

    for literal_text, field_name, format_spec, conversion in parsed:
        parts.append(literal_text)
        if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
            return None
        if field_name is None:
            continue
        if format_spec or conversion:
            return None
        if field_name == "":
            if automatic_index >= len(args):
                return None
            arg_value = args[automatic_index]
            if not isinstance(arg_value, str):
                return None
            parts.append(arg_value)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
            automatic_index += 1
        elif field_name.isdecimal():
            index = int(field_name)
            if index >= len(args):
                return None
            arg_value = args[index]
            if not isinstance(arg_value, str):
                return None
            parts.append(arg_value)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
        elif field_name.isidentifier():
            value = kwargs.get(field_name)
            if not isinstance(value, str):
                return None
            parts.append(value)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
        else:
            return None

    return "".join(parts)


def _normalize_expression_sensitive_keys(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    parse_attempts = 0
    for separator in re.finditer(r":\s*", text):
        window_start = max(0, separator.start() - MAX_KEY_EXPRESSION_CHARS)
        window_start = _last_unquoted_statement_boundary(text, window_start, separator.start())
        if not _has_sensitive_literal_signal(text[window_start : separator.start()]):
            continue
        following = text[separator.end() :].lstrip()
        if not following or following[0] not in {"'", '"', "{", "[", "("}:
            continue
        if _is_inside_quoted_literal(text, 0, separator.start()):
            continue
        for expression_start in _candidate_expression_starts(text, window_start, separator.start()):
            if parse_attempts >= MAX_KEY_EXPRESSION_PARSE_ATTEMPTS:
                break
            if _is_inside_quoted_literal(text, 0, expression_start):
                continue
            raw_expression = text[expression_start : separator.start()]
            expression = raw_expression.strip()
            if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS:
                continue
            if KEY_LITERAL_RE.search(expression) is None:
                continue
            if not _has_sensitive_literal_signal(expression):
                continue
            parse_attempts += 1
            parse_failed = False
            try:
                value = _safe_eval_string_expr(ast.parse(expression, mode="eval"))
            except SyntaxError:
                parse_failed = True
                value = None
            fallback_key = _sensitive_key_from_expression_literals(expression) if parse_failed else None
            normalized_key = _normalize_sensitive_key(value) if isinstance(value, str) else None
            if normalized_key is not None:
                leading = raw_expression[: len(raw_expression) - len(raw_expression.lstrip())]
                replacements.append((expression_start, separator.end(), f"{leading}{normalized_key}="))
                break
            if fallback_key is not None:
                leading = raw_expression[: len(raw_expression) - len(raw_expression.lstrip())]
                replacements.append((expression_start, separator.end(), f"{leading}{fallback_key}="))
                break
            if isinstance(value, str) or not parse_failed:
                break

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _candidate_expression_starts(text: str, start: int, end: int) -> list[int]:
    starts = [start]
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            previous = text[:index].rstrip()
            if char == "{" and bracket_depth == 0 and not previous.endswith("{"):
                starts.append(index + 1)
            bracket_depth += 1
        elif char in ")]}":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "," and bracket_depth <= 1:
            starts.append(index + 1)
        index += 1
    return list(reversed(starts))[:MAX_KEY_EXPRESSION_CANDIDATES]


def _last_unquoted_statement_boundary(text: str, start: int, end: int) -> int:
    boundary = start
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            bracket_depth += 1
        elif char in ")]}":
            if bracket_depth > 0:
                bracket_depth -= 1
            if char == "}" and bracket_depth == 0:
                whitespace_end = index + 1
                while whitespace_end < end and text[whitespace_end].isspace():
                    whitespace_end += 1
                if whitespace_end > index + 1:
                    boundary = whitespace_end
                    index = whitespace_end
                    continue
        elif char in {";", "\n"} and bracket_depth == 0:
            boundary = index + 1
        index += 1
    return boundary


def _sensitive_key_from_expression_literals(expression: str) -> str | None:
    literal_parts = [_decode_key_escapes(match.group(3)).lower() for match in KEY_LITERAL_RE.finditer(expression)]
    if not literal_parts:
        return None
    compact = re.sub(r"[^a-z0-9]+", "", "".join(literal_parts))
    reversed_compact = compact[::-1]
    for candidate in (compact, reversed_compact):
        sensitive_key = _sensitive_key_from_compact(candidate)
        if sensitive_key is not None:
            return sensitive_key
    return None


def _has_sensitive_literal_signal(expression: str) -> bool:
    if _sensitive_key_from_expression_literals(expression) is not None:
        return True
    compact = re.sub(r"[^a-z0-9]+", "", expression.lower())
    return _sensitive_key_from_compact(compact) is not None or _sensitive_key_from_compact(compact[::-1]) is not None


def _sensitive_key_from_compact(compact: str) -> str | None:
    if "authorization" in compact:
        return "Authorization"
    if "client" in compact and "secret" in compact:
        return "client_secret"
    if "api" in compact and "key" in compact:
        return "api_key"
    if "private" in compact and "key" in compact:
        return "private_key"
    for key in (
        "refresh_token",
        "access_token",
        "auth_token",
        "password",
        "passwd",
        "credential",
        "signature",
        "secret",
        "sig",
        "sas",
        "token",
    ):
        if key.replace("_", "") in compact:
            return key
    return None


def _is_inside_quoted_literal(text: str, start: int, position: int) -> bool:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    index = start
    while index < position:
        char = text[index]
        if quote is None:
            if char in {"'", '"'}:
                quote = char
                quote_slashes = _count_preceding_backslashes(text, index)
                triple = text.startswith(char * 3, index)
                index += 3 if triple else 1
            else:
                index += 1
            continue

        current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
        closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
        closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
        if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
            quote = None
            quote_slashes = 0
            triple = False
            index += 3
        elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
            quote = None
            quote_slashes = 0
            index += 1
        else:
            index += 1

    return quote is not None


def _find_value_expression_end(text: str, start: int, default_end: int) -> int:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < default_end:
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            bracket_depth += 1
        elif char in ")]}":
            if bracket_depth == 0:
                return index
            bracket_depth -= 1
        elif char in {";", "\n"} and bracket_depth == 0:
            return index
        index += 1
    return default_end


def _count_preceding_backslashes(text: str, position: int) -> int:
    count = 0
    index = position - 1
    while index >= 0 and text[index] == "\\":
        count += 1
        index -= 1
    return count


def _redact_sensitive_literal_expressions(text: str) -> str:
    matches = list(SENSITIVE_EVIDENCE_PREFIX_RE.finditer(text))
    if not matches:
        return text

    pieces: list[str] = []
    cursor = 0
    for index, match in enumerate(matches):
        if match.start() < cursor:
            continue
        segment_end = len(text)
        for next_match in matches[index + 1 :]:
            if not _is_inside_quoted_literal(text, match.end(), next_match.start()):
                segment_end = next_match.start()
                break
        segment_end = _find_value_expression_end(text, match.end(), segment_end)
        segment = text[match.end() : segment_end]
        pieces.append(text[cursor : match.start()])
        if COMMAND_EVIDENCE_RE.search(segment):
            pieces.append(
                f"{text[match.start() : match.end()]}"
                f"{_redact_command_evidence_text(_redact_command_string_literals(segment))}"
            )
        elif PYTHON_STRING_LITERAL_DETECT_RE.search(segment):
            trailing_whitespace = re.search(r"\s*$", segment)
            suffix = trailing_whitespace.group(0) if trailing_whitespace else ""
            pieces.append(f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{suffix}")
        else:
            pieces.append(text[match.start() : segment_end])
        cursor = segment_end

    pieces.append(text[cursor:])
    return "".join(pieces)


def _redact_unclosed_quoted_values(text: str) -> str:
    starts: list[tuple[int, str]] = []
    for pattern, slash_group, quote_group in (
        (TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_START_RE, 3, 4),
        (TRIPLE_QUOTED_AUTHORIZATION_START_RE, 2, 3),
        (TRIPLE_QUOTED_BEARER_START_RE, 2, 3),
    ):
        for match in pattern.finditer(text):
            closing_marker = f"{match.group(slash_group)}{match.group(quote_group)}" * 3
            if text.find(closing_marker, match.end()) == -1:
                starts.append((match.start(), match.group(1)))

    for pattern, slash_group, quote_group in (
        (QUOTED_SENSITIVE_ASSIGNMENT_START_RE, 3, 4),
        (QUOTED_AUTHORIZATION_START_RE, 2, 3),
        (QUOTED_BEARER_START_RE, 2, 3),
    ):
        for match in pattern.finditer(text):
            closing_marker = f"{match.group(slash_group)}{match.group(quote_group)}"
            if text.find(closing_marker, match.end()) == -1:
                starts.append((match.start(), match.group(1)))

    if not starts:
        return text

    start, prefix = min(starts, key=lambda item: item[0])
    return f"{text[:start]}{prefix}{REDACTED_EVIDENCE_VALUE}"


def _redact_adjacent_string_literals(text: str) -> str:
    for pattern in (
        ADJACENT_LITERAL_SENSITIVE_ASSIGNMENT_RE,
        ADJACENT_LITERAL_AUTHORIZATION_RE,
        ADJACENT_LITERAL_BEARER_RE,
    ):
        text = pattern.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", text)
    return text


def _redact_residual_expression_literals(text: str) -> str:
    for pattern in (
        RESIDUAL_LITERAL_SENSITIVE_ASSIGNMENT_RE,
        RESIDUAL_LITERAL_AUTHORIZATION_RE,
        RESIDUAL_LITERAL_BEARER_RE,
    ):
        text = pattern.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", text)
    return text


def _redact_unquoted_sensitive_assignment(match: re.Match[str]) -> str:
    value = match.group(3)
    if COMMAND_EVIDENCE_RE.search(value):
        return f"{match.group(1)}{_redact_command_evidence_text(_redact_command_string_literals(value))}"
    trailing_whitespace = re.search(r"\s*$", value)
    suffix = trailing_whitespace.group(0) if trailing_whitespace else ""
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _redact_authorization_value(match: re.Match[str]) -> str:
    value = match.group(2)
    trailing_whitespace = re.search(r"\s*$", value)
    suffix = trailing_whitespace.group(0) if trailing_whitespace else ""
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _redact_command_user_password(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED_EVIDENCE_VALUE}{match.group(5)}"


def _redact_command_string_literals(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for match in PYTHON_STRING_LITERAL_DETECT_RE.finditer(text):
        pieces.append(COMMAND_BARE_SENSITIVE_RE.sub(REDACTED_EVIDENCE_VALUE, text[cursor : match.start()]))
        pieces.append(_redact_sensitive_command_literal(match))
        cursor = match.end()
    pieces.append(COMMAND_BARE_SENSITIVE_RE.sub(REDACTED_EVIDENCE_VALUE, text[cursor:]))
    return "".join(pieces)


def _redact_command_evidence_text(text: str) -> str:
    redacted = URL_RE.sub(_redact_url, text)
    redacted = AUTHORIZATION_VALUE_RE.sub(_redact_authorization_value, redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = COMMAND_SECRET_OPTION_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = COMMAND_USER_PASSWORD_RE.sub(_redact_command_user_password, redacted)
    redacted = HIGH_ENTROPY_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, redacted)
    return COMMAND_LITERAL_SENSITIVE_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, redacted)


def _redact_sensitive_command_literal(match: re.Match[str]) -> str:
    literal = match.group(0)
    if COMMAND_CONTEXT_LITERAL_RE.search(literal):
        return _redact_command_evidence_text(literal)
    return REDACTED_EVIDENCE_VALUE


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = URL_RE.sub(_redact_url, text)
    redaction_budget = max(0, max_chars) + EVIDENCE_REDACTION_LOOKAHEAD_CHARS
    redacted = redacted[:redaction_budget]
    redacted = _normalize_serialized_quote_escapes(redacted)
    redacted = _normalize_expression_sensitive_keys(redacted)
    redacted = _normalize_quoted_sensitive_keys(redacted)
    redacted = _normalize_subscript_sensitive_keys(redacted)
    redacted = _normalize_unquoted_sensitive_keys(redacted)
    redacted = _redact_sensitive_literal_expressions(redacted)
    redacted = TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_prefixed_quoted_value, redacted)
    redacted = TRIPLE_QUOTED_AUTHORIZATION_VALUE_RE.sub(_redact_prefixed_quoted_value, redacted)
    redacted = TRIPLE_QUOTED_BEARER_VALUE_RE.sub(_redact_prefixed_quoted_value, redacted)
    redacted = _redact_unclosed_quoted_values(redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = QUOTED_AUTHORIZATION_VALUE_RE.sub(_redact_quoted_authorization, redacted)
    redacted = QUOTED_BEARER_VALUE_RE.sub(_redact_quoted_authorization, redacted)
    redacted = _redact_adjacent_string_literals(redacted)
    redacted = _redact_residual_expression_literals(redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(_redact_authorization_value, redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_sensitive_assignment, redacted)
    return _truncate(redacted, max_chars)
