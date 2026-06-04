"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import io
import re
import textwrap
import tokenize
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from modelaudit.detectors.network_comm import redact_url_for_finding

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"
REDACTION_LOOKAHEAD_CHARS: Final[int] = 4096

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+")
SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:(?:[a-z0-9]+[_.-])*authorization|"
    r"(?:[a-z0-9]+[_.-])*(?:access[_-]?key|access[_-]?token|api[_-]?key|apikey|auth[_-]?token|"
    r"client[_-]?secret|credential|password|passwd|private[_-]?key|pwd|refresh[_-]?token|sas|secret|"
    r"secret[_-]?key|signature|sig|token)(?:[_.-][a-z0-9]+)*)"
)
SENSITIVE_ASSIGNMENT_TARGET: Final[str] = (
    rf"(?:\b{SENSITIVE_ASSIGNMENT_KEY}(?:\s*:\s*[^=\r\n]+)?|"
    rf"\[\s*(?:[rubf]{{0,2}})?[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"']\s*\])"
)
SENSITIVE_ASSIGNMENT_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"{SENSITIVE_ASSIGNMENT_TARGET}\s*$",
    re.IGNORECASE,
)
QUOTED_SENSITIVE_MAPPING_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?:[rubf]{{0,2}})?(?P<mapping_quote>[\"']){SENSITIVE_ASSIGNMENT_KEY}(?P=mapping_quote)\s*$",
    re.IGNORECASE,
)
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(\bauthorization\s*(?:=|:(?![^\r\n=]*=))\s*(?:(?:bearer|basic|token)\s+)?)"
    r"[^\s\"';&|,\)\]\}]+"
)
AUTH_SCHEME_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\b(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}")
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*(?:=|:(?![^\r\n=]*=))\s*)[^\s\"';&|,\)\]\}}]+"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?P<assignment_prefix>[rubf]{{0,2}})"
    rf"(?P<assignment_quote>[\"']{{1,3}})(?![\"'])"
    rf"(?:\\.|(?!(?P=assignment_quote)).)*(?P=assignment_quote)",
    re.IGNORECASE | re.DOTALL,
)
PYTHON_CONTAINER_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:\[\s*[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"']\s*\]|[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"'])"
    rf"\s*[:=]\s*)(?P<container_prefix>[rubf]{{0,2}})(?P<container_quote>[\"']{{1,3}})(?![\"'])"
    rf"(?:\\.|(?!(?P=container_quote)).)*"
    rf"(?P=container_quote)",
    re.IGNORECASE | re.DOTALL,
)
MULTILINE_MALFORMED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?P<multiline_assignment_quote>[\"'])"
    rf"(?!(?P=multiline_assignment_quote)(?P=multiline_assignment_quote))"
    rf"(?:\\.|(?!(?P=multiline_assignment_quote))[^\r\n])*[\r\n].*$",
    re.IGNORECASE | re.DOTALL,
)
MULTILINE_MALFORMED_PYTHON_CONTAINER_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"((?:\[\s*[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"']\s*\]|[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"'])"
    rf"\s*[:=]\s*)(?P<multiline_container_quote>[\"'])"
    rf"(?!(?P=multiline_container_quote)(?P=multiline_container_quote))"
    rf"(?:\\.|(?!(?P=multiline_container_quote))[^\r\n])*[\r\n].*$",
    re.IGNORECASE | re.DOTALL,
)
MALFORMED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"\b(({SENSITIVE_ASSIGNMENT_KEY})\s*[:=]\s*)(?P<malformed_assignment_quote>[\"']{{1,3}})(?![\"'])"
    rf"(?!{re.escape(REDACTED_EVIDENCE_VALUE)}(?P=malformed_assignment_quote)).*$",
    re.IGNORECASE | re.DOTALL,
)
MALFORMED_PYTHON_CONTAINER_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"((?:\[\s*[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"']\s*\]|[\"']{SENSITIVE_ASSIGNMENT_KEY}[\"'])"
    rf"\s*[:=]\s*)(?P<malformed_container_quote>[\"']{{1,3}})(?![\"'])"
    rf"(?!{re.escape(REDACTED_EVIDENCE_VALUE)}(?P=malformed_container_quote)).*$",
    re.IGNORECASE | re.DOTALL,
)
SENSITIVE_EXPRESSION_ASSIGNMENT_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"{SENSITIVE_ASSIGNMENT_TARGET}\s*(?:=|:=)",
    re.IGNORECASE,
)
STRING_LITERAL_START_RE: Final[re.Pattern[str]] = re.compile(r"(?:[rubf]{0,2})?[\"']", re.IGNORECASE)
GENERIC_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![a-z0-9_])(?:[a-z_]\w*(?:\.[a-z_]\w*)*(?:\[\s*[\"'][^\"']+[\"']\s*\])?|[\"'][^\"']+[\"'])"
    r"\s*(?:=|:(?![^\r\n=]*=))",
    re.IGNORECASE,
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


def _redact_file_url(raw_url: str) -> str | None:
    """Preserve valid absolute file paths while removing URL credentials."""
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return None

    if parsed.scheme.lower() != "file" or not parsed.path.startswith("/"):
        return None

    hostname = parsed.hostname
    if parsed.netloc and hostname is None:
        return None
    if hostname is not None and ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    return urlunsplit((parsed.scheme, hostname or "", parsed.path, "", ""))


def _redact_url(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    safe_file_url = _redact_file_url(raw_url)
    if safe_file_url is not None:
        return safe_file_url

    safe_url = redact_url_for_finding(raw_url)
    if safe_url == "[invalid-url]":
        return _redact_malformed_url(raw_url)
    return safe_url


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    prefix = match.group("assignment_prefix")
    quote = match.group("assignment_quote")
    return f"{match.group(1)}{prefix}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_python_container_assignment(match: re.Match[str]) -> str:
    prefix = match.group("container_prefix")
    quote = match.group("container_quote")
    return f"{match.group(1)}{prefix}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_multiline_malformed_quoted_assignment(match: re.Match[str]) -> str:
    quote = match.group("multiline_assignment_quote")
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_multiline_malformed_python_container_assignment(match: re.Match[str]) -> str:
    quote = match.group("multiline_container_quote")
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_malformed_quoted_assignment(match: re.Match[str]) -> str:
    quote = match.group("malformed_assignment_quote")
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_malformed_python_container_assignment(match: re.Match[str]) -> str:
    quote = match.group("malformed_container_quote")
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


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
) -> int:
    for index in range(operator_index - 1, -1, -1):
        token = tokens[index]
        if depths[index] < operator_depth:
            return index + 1
        if depths[index] != operator_depth:
            continue
        if token.type in {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}:
            return index + 1
        if token.type == tokenize.OP and token.string in {",", ";"}:
            return index + 1
    return 0


def _assignment_value_end(
    tokens: list[tokenize.TokenInfo],
    depths: list[int],
    value_index: int,
    operator: str,
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
        if token.type == tokenize.OP and depth == operator_depth:
            if token.string == ";" or token.string in ")]}":
                return _position_offset(offsets, token.start, text_length), significant
            if token.string == "," and (operator == ":" or operator_depth > 0):
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


def _is_simple_sensitive_assignment_value(value: str) -> bool:
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
    return len(significant) == 1 and significant[0].type in {tokenize.NAME, tokenize.NUMBER, tokenize.STRING}


def _redact_unparseable_sensitive_expression_assignments(text: str) -> str:
    matches = list(SENSITIVE_EXPRESSION_ASSIGNMENT_PREFIX_RE.finditer(text))
    assignment_starts = [match.start() for match in GENERIC_ASSIGNMENT_START_RE.finditer(text)]
    replacements: list[tuple[int, int]] = []
    for match in matches:
        value_start = match.end()
        while value_start < len(text) and text[value_start] in " \t":
            value_start += 1

        line_end_candidates = [
            position for position in (text.find("\n", value_start), text.find(";", value_start)) if position >= 0
        ]
        value_end = min(line_end_candidates, default=len(text))
        next_assignment_start = next(
            (assignment_start for assignment_start in assignment_starts if value_start < assignment_start < value_end),
            None,
        )
        if next_assignment_start is not None and _is_simple_sensitive_assignment_value(
            text[value_start:next_assignment_start].strip()
        ):
            value_end = next_assignment_start

        candidate = text[value_start:value_end].rstrip()
        if not candidate or _is_simple_sensitive_assignment_value(candidate):
            continue

        try:
            ast.parse(candidate, mode="eval")
        except (SyntaxError, ValueError):
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


def _redact_python_expression_assignments(text: str) -> str:
    """Redact expression-valued sensitive assignments while preserving nearby code."""
    try:
        ast.parse(textwrap.dedent(text))
    except (SyntaxError, ValueError):
        return _redact_unparseable_sensitive_expression_assignments(text)

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (IndentationError, tokenize.TokenError):
        return _redact_unparseable_sensitive_expression_assignments(text)

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

    offsets = _line_offsets(text)
    text_length = len(text)
    replacements: list[tuple[int, int]] = []
    ignored_value_tokens = {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT}

    for index, token in enumerate(tokens):
        if token.type != tokenize.OP or token.string not in {"=", ":=", ":"}:
            continue

        operator_depth = depths[index]
        target_start_index = _assignment_target_start(tokens, depths, index, operator_depth)
        target_start = _position_offset(offsets, tokens[target_start_index].start, text_length)
        target_end = _position_offset(offsets, token.start, text_length)
        target = text[target_start:target_end]
        if token.string == ":":
            if QUOTED_SENSITIVE_MAPPING_KEY_RE.search(target) is None:
                continue
        elif SENSITIVE_ASSIGNMENT_TARGET_RE.search(target) is None:
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
        )
        if len(significant) == 1 and significant[0].type in {tokenize.NAME, tokenize.NUMBER, tokenize.STRING}:
            continue

        value_start = _position_offset(offsets, tokens[value_index].start, text_length)
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


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redacted = URL_RE.sub(_redact_url, text[: max(0, max_chars) + REDACTION_LOOKAHEAD_CHARS])
    redacted = _redact_python_expression_assignments(redacted)
    redacted = MULTILINE_MALFORMED_PYTHON_CONTAINER_SENSITIVE_ASSIGNMENT_RE.sub(
        _redact_multiline_malformed_python_container_assignment,
        redacted,
    )
    redacted = MULTILINE_MALFORMED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(
        _redact_multiline_malformed_quoted_assignment,
        redacted,
    )
    redacted = PYTHON_CONTAINER_SENSITIVE_ASSIGNMENT_RE.sub(_redact_python_container_assignment, redacted)
    redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    redacted = MALFORMED_PYTHON_CONTAINER_SENSITIVE_ASSIGNMENT_RE.sub(
        _redact_malformed_python_container_assignment,
        redacted,
    )
    redacted = MALFORMED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_malformed_quoted_assignment, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = AUTH_SCHEME_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    return _truncate(redacted, max_chars)
