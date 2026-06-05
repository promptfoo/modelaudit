"""Scanner for R serialized model artifacts."""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import os
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from ..core_results import mark_operational_scan_error
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ._evidence_redaction import (
    _iter_r_raw_string_spans,
    _position_is_in_spans,
    _r_non_code_spans,
    _r_statement_start_before,
    _r_statement_starts,
    _unfinished_r_assignment_literal_closing_sequence,
    redact_evidence_string,
)
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

_DECODE_INCONCLUSIVE_REASON = "r_serialized_decode_incomplete"
_READ_INCONCLUSIVE_REASON = "r_serialized_read_failed"
_STRING_EXTRACTION_INCONCLUSIVE_REASON = "r_serialized_string_extraction_incomplete"
_CONTINUATION_ANALYSIS_INCONCLUSIVE_REASON = "r_serialized_continuation_analysis_incomplete"
_EXPRESSION_DEPTH_INCONCLUSIVE_REASON = "r_serialized_expression_depth_incomplete"
_R_SEPARATED_CREDENTIAL_KEY_PATTERN = (
    r"(?:[a-z0-9]+[._-])*"
    r"(?:access[._-]?key|access[._-]?token|api[._-]?key|apikey|auth[._-]?token|client[._-]?secret|"
    r"password|passwd|private[._-]?key|pwd|refresh[._-]?token|secret|secret[._-]?key|token)"
)
_R_CAMEL_CASE_CREDENTIAL_KEY_PATTERN = (
    r"(?:[a-z][A-Za-z0-9]*)?"
    r"(?:AccessKey|accessKey|AccessToken|accessToken|APIKey|ApiKey|apiKey|AuthToken|authToken|"
    r"ClientSecret|clientSecret|Password|Passwd|PrivateKey|privateKey|Pwd|RefreshToken|refreshToken|"
    r"Secret|SecretKey|secretKey|Token)"
    r"(?:[A-Z][A-Za-z0-9]*)?"
)
_R_CREDENTIAL_KEY_PATTERN = rf"(?:{_R_SEPARATED_CREDENTIAL_KEY_PATTERN}|(?-i:{_R_CAMEL_CASE_CREDENTIAL_KEY_PATTERN}))"
_R_SEPARATED_QUOTED_CREDENTIAL_KEY_PATTERN = (
    r"(?:[a-z0-9]+[\s._-]+)*"
    r"(?:access[\s._-]*key|access[\s._-]*token|api[\s._-]*key|apikey|auth[\s._-]*token|"
    r"client[\s._-]*secret|password|passwd|private[\s._-]*key|pwd|refresh[\s._-]*token|secret|"
    r"secret[\s._-]*key|token)"
)
_R_QUOTED_CREDENTIAL_KEY_PATTERN = (
    rf"(?:{_R_SEPARATED_QUOTED_CREDENTIAL_KEY_PATTERN}|(?-i:{_R_CAMEL_CASE_CREDENTIAL_KEY_PATTERN}))"
)
_R_UNQUOTED_CREDENTIAL_IDENTIFIER = rf"(?:`{_R_QUOTED_CREDENTIAL_KEY_PATTERN}`|\b{_R_CREDENTIAL_KEY_PATTERN}\b)"
_R_QUOTED_CREDENTIAL_IDENTIFIER = rf"""(?:"{_R_QUOTED_CREDENTIAL_KEY_PATTERN}"|'{_R_QUOTED_CREDENTIAL_KEY_PATTERN}')"""
_R_CREDENTIAL_IDENTIFIER = rf"(?:{_R_UNQUOTED_CREDENTIAL_IDENTIFIER}|{_R_QUOTED_CREDENTIAL_IDENTIFIER})"
_R_ASSIGNMENT_INDEX_SUFFIX = r"(?:\s*(?:\[\[[^\]\r\n]{1,120}\]\]|\[[^\]\r\n]{1,120}\]))*"
_R_MEMBER_CREDENTIAL_TARGET = (
    rf"\b[a-z.][a-z0-9._]*\s*(?:\$|@)\s*{_R_UNQUOTED_CREDENTIAL_IDENTIFIER}{_R_ASSIGNMENT_INDEX_SUFFIX}"
)
_R_QUOTED_SUBSCRIPT_CREDENTIAL_TARGET = (
    rf"\b[a-z.][a-z0-9._]*\s*(?:\[\[\s*|\[\s*){_R_QUOTED_CREDENTIAL_IDENTIFIER}"
    rf"\s*(?:\]\]|\]){_R_ASSIGNMENT_INDEX_SUFFIX}"
)
_R_CREDENTIAL_TARGET = (
    rf"(?:{_R_MEMBER_CREDENTIAL_TARGET}|{_R_QUOTED_SUBSCRIPT_CREDENTIAL_TARGET}|"
    rf"{_R_CREDENTIAL_IDENTIFIER}{_R_ASSIGNMENT_INDEX_SUFFIX})"
)
_R_QUOTED_CREDENTIAL_VALUE = r"""(?:"(?:\\.|[^"\\]){6,}"|'(?:\\.|[^'\\]){6,}')"""
_R_QUOTED_CREDENTIAL_VALUE_RE = re.compile(_R_QUOTED_CREDENTIAL_VALUE)
_R_LEFTWARD_QUOTED_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf"""(?ix){_R_CREDENTIAL_TARGET}\s*(?P<operator>=|<{{1,2}}-)\s*{_R_QUOTED_CREDENTIAL_VALUE}"""
)
_R_RIGHTWARD_QUOTED_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf"""(?ix){_R_QUOTED_CREDENTIAL_VALUE}\s*(?P<operator>->{{1,2}})\s*{_R_CREDENTIAL_TARGET}"""
)
_R_RIGHTWARD_RAW_CREDENTIAL_ASSIGNMENT_RE = re.compile(rf"(?i)\s*(?P<operator>->{{1,2}})\s*{_R_CREDENTIAL_TARGET}")
_R_LEFTWARD_CREDENTIAL_TARGET_RE = re.compile(rf"(?i){_R_CREDENTIAL_TARGET}\s*(?P<operator>=|<{{1,2}}-)\s*")
_R_RIGHTWARD_CREDENTIAL_TARGET_RE = re.compile(rf"(?i)->{{1,2}}\s*{_R_CREDENTIAL_TARGET}")
_R_CONTROL_WORDS = frozenset(
    {
        "break",
        "else",
        "for",
        "function",
        "if",
        "in",
        "next",
        "repeat",
        "while",
    }
)
_R_RESERVED_WORDS = _R_CONTROL_WORDS | frozenset(
    {
        "FALSE",
        "Inf",
        "NA",
        "NA_character_",
        "NA_complex_",
        "NA_integer_",
        "NA_real_",
        "NULL",
        "NaN",
        "TRUE",
    }
)
_R_SIMPLE_NUMERIC_TOKEN_RE = re.compile(
    r"(?i)(?:0x[0-9a-f]+(?:p[+-]?[0-9]+)?|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:e[+-]?[0-9]+)?)[li]?"
)
_R_DOT_ARGUMENT_TOKEN_RE = re.compile(r"\.\.[0-9]+")
_R_OBVIOUS_NONCALLABLE_GROUPED_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<value>
            (?i:(?:0x[0-9a-f]+(?:p[+-]?[0-9]+)?|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:e[+-]?[0-9]+)?)[li]?)
            |FALSE|Inf|NA_character_|NA_complex_|NA_integer_|NA_real_|NULL|NaN|TRUE|NA
        )
        |(?P<operator>%%|%/%|%\*%|%in%|&&|\|\||<=|>=|==|!=|[()+\-*/^:!&|<>])
    )
    """,
    re.VERBOSE,
)
_R_INCOMPLETE_EXPRESSION_TRAILING_CHARACTERS = frozenset("+-*/^:!&|<>$@~?%\\")
_R_EXPRESSION_MAX_DEPTH = 128
_R_CONTINUATION_ANALYSIS_MAX_CHARS = 16 * 1024
_R_CONTINUATION_ANALYSIS_MAX_WORK = 256 * 1024


class _RExpressionDepthExceeded(Exception):
    pass


def _r_function_keyword_before_position(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    cursor = position - 1
    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor < 0:
            return False

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            break
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return False
        cursor = span_start - 1

    token_end = cursor + 1
    while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
        cursor -= 1
    if text[cursor + 1 : token_end] != "function":
        return False

    crossed_newline = False
    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            crossed_newline = crossed_newline or text[cursor] in "\r\n"
            cursor -= 1
        if cursor < 0:
            return True

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            character = text[cursor]
            if crossed_newline:
                return character not in "$@:"
            if character in "$@:":
                return False
            if character.isalnum() or character in "._":
                previous_token_end = cursor + 1
                while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
                    cursor -= 1
                return text[cursor + 1 : previous_token_end] in {"else", "repeat"}
            if character in ")]}":
                opener_position = _r_matching_open_delimiter_position(
                    text,
                    cursor,
                    non_code_spans,
                    delimiter_pairs,
                )
                if opener_position is None:
                    cursor -= 1
                    continue
                if character != ")":
                    return False
                return _r_identifier_before_position(text, opener_position, non_code_spans) in {"for", "if", "while"}
            return character in "([{,;=<>+-*/^!&|~"
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return crossed_newline
        cursor = span_start - 1
    return True


def _r_function_keyword_awaits_formals(
    text: str,
    non_code_spans: list[tuple[int, int]] | None = None,
) -> bool:
    if non_code_spans is None:
        non_code_spans = _r_non_code_spans(text)
    return _r_function_keyword_before_position(text, len(text), non_code_spans)


def _r_lambda_shorthand_before_position(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    cursor = position - 1
    slash_position: int | None = None
    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor < 0:
            return False

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            if text[cursor] != "\\":
                return False
            slash_position = cursor
            break
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return False
        cursor = span_start - 1
    if slash_position is None:
        return False

    cursor = slash_position - 1
    crossed_newline = False
    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            crossed_newline = crossed_newline or text[cursor] in "\r\n"
            cursor -= 1
        if cursor < 0:
            return True

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            character = text[cursor]
            if crossed_newline:
                return character not in "$@:"
            if character in "$@:":
                return False
            if character.isalnum() or character in "._":
                token_end = cursor + 1
                while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
                    cursor -= 1
                return text[cursor + 1 : token_end] in {"else", "repeat"}
            if character in ")]}":
                opener_position = _r_matching_open_delimiter_position(
                    text,
                    cursor,
                    non_code_spans,
                    delimiter_pairs,
                )
                if opener_position is None:
                    cursor -= 1
                    continue
                if character != ")":
                    return False
                return _r_identifier_before_position(text, opener_position, non_code_spans) in {"for", "if", "while"}
            return character in "([{,;=<>+-*/^!&|~"
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return crossed_newline
        cursor = span_start - 1
    return True


def _r_unterminated_literal_span_starts(
    text: str,
    non_code_spans: list[tuple[int, int]],
) -> set[int]:
    unterminated_starts = {
        literal_start
        for literal_start, _literal_end, _content_start, _content_end, is_terminated in _iter_r_raw_string_spans(text)
        if not is_terminated
    }
    for span_start, span_end in non_code_spans:
        quote = text[span_start]
        if quote not in "\"'`":
            continue
        if span_end <= span_start + 1 or text[span_end - 1] != quote:
            unterminated_starts.add(span_start)
            continue
        backslash_count = 0
        cursor = span_end - 2
        while cursor > span_start and text[cursor] == "\\":
            backslash_count += 1
            cursor -= 1
        if backslash_count % 2 == 1:
            unterminated_starts.add(span_start)
    return unterminated_starts


def _position_is_in_r_suppressing_non_code_span(
    position: int,
    non_code_spans: list[tuple[int, int]],
    malformed_raw_span_starts: set[int],
) -> bool:
    span_index = bisect_right(non_code_spans, position, key=lambda span: span[0]) - 1
    if span_index < 0 or position >= non_code_spans[span_index][1]:
        return False
    return non_code_spans[span_index][0] not in malformed_raw_span_starts


def _r_named_argument_target_kind(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
) -> str | None:
    """Return the R tag kind immediately before ``=`` when it is syntactically simple."""
    cursor = position - 1
    target_kind: str | None = None
    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor < 0:
            return None

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            break
        span_start, span_end = non_code_spans[span_index]
        if text[span_start] == "#":
            cursor = span_start - 1
            continue
        if span_end != cursor + 1:
            return None
        if text[span_start] == "`":
            target_kind = "symbol"
        elif text[span_start] in "\"'":
            target_kind = "string"
        else:
            return None
        cursor = span_start - 1
        break

    if target_kind is None:
        if not (text[cursor].isalnum() or text[cursor] in "._"):
            return None
        token_end = cursor + 1
        while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
            cursor -= 1
        target_kind = _r_unquoted_named_argument_target_kind(text[cursor + 1 : token_end])
        if target_kind is None:
            return None

    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor < 0:
            return None

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            break
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return None
        cursor = span_start - 1

    return target_kind if text[cursor] in "([," else None


def _r_unquoted_named_argument_target_kind(token: str) -> str | None:
    if token == "NULL":
        return "null"
    if (
        not token
        or token.startswith("_")
        or token[0].isdigit()
        or (token.startswith(".") and len(token) > 1 and token[1].isdigit())
        or token in _R_RESERVED_WORDS
    ):
        return None
    return "symbol"


def _r_named_argument_equals_positions(
    text: str,
    positions: set[int],
    non_code_spans: list[tuple[int, int]],
) -> set[int]:
    if not positions:
        return set()

    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    stack: list[tuple[str, int]] = []
    contexts: dict[int, tuple[tuple[str, int], tuple[str, int]]] = {}
    delimiter_pairs: dict[int, int] = {}
    cursor = 0
    span_index = 0
    while cursor < len(text):
        if span_index < len(non_code_spans) and cursor == non_code_spans[span_index][0]:
            cursor = non_code_spans[span_index][1]
            span_index += 1
            continue

        if cursor in positions and stack:
            contexts[cursor] = (stack[-1], stack[0])

        character = text[cursor]
        if character in "([{":
            stack.append((character, cursor))
        elif character in ")]}" and stack:
            if closing_delimiters[stack[-1][0]] != character:
                stack.clear()
                cursor += 1
                continue
            closed = stack.pop()
            delimiter_pairs[closed[1]] = cursor
            delimiter_pairs[cursor] = closed[1]
        cursor += 1

    valid_positions: set[int] = set()
    target_validity: dict[int, bool] = {}
    function_body_validity: dict[int, bool] = {}
    unterminated_literal_starts = _r_unterminated_literal_span_starts(text, non_code_spans)
    for position in positions:
        context = contexts.get(position)
        if context is None:
            continue

        target, outermost = context
        target_close = delimiter_pairs.get(target[1])
        if target_close is None or outermost[1] not in delimiter_pairs or target[0] not in {"(", "["}:
            continue

        target_kind = _r_named_argument_target_kind(text, position, non_code_spans)
        if target_kind is None:
            continue
        target_is_function_formals = target[0] == "(" and (
            _r_function_keyword_before_position(text, target[1], non_code_spans, delimiter_pairs)
            or _r_lambda_shorthand_before_position(text, target[1], non_code_spans, delimiter_pairs)
        )
        if target_is_function_formals and target_kind != "symbol":
            continue
        if target[1] not in target_validity:
            target_validity[target[1]] = (
                _r_open_paren_starts_argument_list(text, target[1], non_code_spans, delimiter_pairs)
                if target[0] == "("
                else _r_open_bracket_starts_subscript(text, target[1], non_code_spans, delimiter_pairs)
            )
        if not target_validity[target[1]]:
            continue

        if target_is_function_formals:
            if target[1] not in function_body_validity:
                body_start = target_close + 1
                function_body_validity[target[1]] = (
                    _r_expression_follows(
                        text,
                        body_start,
                        non_code_spans,
                        delimiter_pairs,
                        unterminated_literal_starts,
                    )
                    and not _r_expression_is_obviously_incomplete(
                        text,
                        body_start,
                        non_code_spans,
                        unterminated_literal_starts,
                    )
                    and not _r_expression_has_obvious_adjacent_values(
                        text,
                        body_start,
                        len(text),
                        non_code_spans,
                        delimiter_pairs,
                    )
                )
            if not function_body_validity[target[1]]:
                continue
        if not _r_named_argument_value_is_complete(
            text,
            position + 1,
            target_close,
            non_code_spans,
            delimiter_pairs,
            unterminated_literal_starts,
            allow_missing=not target_is_function_formals,
        ):
            continue
        valid_positions.add(position)
    return valid_positions


def _r_named_argument_value_is_complete(
    text: str,
    value_start: int,
    target_close: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int],
    unterminated_literal_starts: set[int],
    *,
    allow_missing: bool,
) -> bool:
    first_code = _r_next_code_position(text, value_start, non_code_spans)
    if first_code is None or first_code >= target_close or text[first_code] == ",":
        return allow_missing
    if not _r_expression_follows(
        text,
        first_code,
        non_code_spans,
        delimiter_pairs,
        unterminated_literal_starts,
    ) or _r_expression_is_obviously_incomplete(
        text,
        first_code,
        non_code_spans,
        unterminated_literal_starts,
    ):
        return False
    if _r_expression_has_obvious_adjacent_values(
        text,
        first_code,
        target_close,
        non_code_spans,
        delimiter_pairs,
    ):
        return False
    span_index = bisect_right(non_code_spans, first_code, key=lambda span: span[0]) - 1
    if span_index < 0 or first_code >= non_code_spans[span_index][1]:
        return True
    span_start, span_end = non_code_spans[span_index]
    if text[span_start] == "#" or span_start in unterminated_literal_starts:
        return False
    continuation = _r_next_code_position(text, span_end, non_code_spans)
    if continuation is None or continuation >= target_close or text[continuation] in ",)]":
        return True
    return text[continuation] in "+-*/^:!&|<>$@~?%(["


def _r_expression_has_obvious_adjacent_values(
    text: str,
    position: int,
    stop: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int],
    *,
    allow_newline_separator: bool = False,
) -> bool:
    cursor = position
    expects_value = True
    namespace_receiver_is_valid = False
    while cursor < stop:
        search_start = cursor
        cursor = _r_next_code_position(text, cursor, non_code_spans) or stop
        if allow_newline_separator and not expects_value and "\n" in text[search_start:cursor]:
            expects_value = True
        if cursor >= stop or text[cursor] in ",;)]}":
            return False

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index >= 0 and cursor < non_code_spans[span_index][1]:
            span_start, span_end = non_code_spans[span_index]
            if text[span_start] == "#":
                cursor = span_end
                continue
            if not expects_value:
                return True
            expects_value = False
            namespace_receiver_is_valid = text[span_start] != "#"
            cursor = span_end
            continue

        character = text[cursor]
        if character in "([{":
            closer = delimiter_pairs.get(cursor)
            if closer is None or closer >= stop:
                return False
            if expects_value and _r_expression_has_obvious_adjacent_values(
                text,
                cursor + 1,
                closer,
                non_code_spans,
                delimiter_pairs,
                allow_newline_separator=character == "{",
            ):
                return True
            expects_value = False
            namespace_receiver_is_valid = False
            cursor = closer + 1
            continue
        if character == "\\":
            if not expects_value:
                return True
            opener = _r_next_code_position(text, cursor + 1, non_code_spans)
            if opener is None or opener >= stop or text[opener] != "(":
                return True
            closer = delimiter_pairs.get(opener)
            if closer is None or closer >= stop:
                return True
            expects_value = True
            cursor = closer + 1
            continue
        if character == "%":
            operator_end = text.find("%", cursor + 1, stop)
            if expects_value or operator_end < 0:
                return True
            expects_value = True
            namespace_receiver_is_valid = False
            cursor = operator_end + 1
            continue
        if character in "+-":
            expects_value = True
            namespace_receiver_is_valid = False
            cursor += 1
            continue
        if character in "~?":
            expects_value = True
            namespace_receiver_is_valid = False
            cursor += 1
            continue
        if character == "!" and (cursor + 1 >= stop or text[cursor + 1] != "="):
            if not expects_value:
                return True
            cursor += 1
            continue
        if character == "=":
            if cursor + 1 >= stop or text[cursor + 1] != "=":
                return True
            operator = "=="
        else:
            operator = next(
                (
                    candidate
                    for candidate in ("<<-", "->>", ":::", "::", "|>", "||", "&&", "<=", ">=", "!=", "<-", "->")
                    if text.startswith(candidate, cursor)
                ),
                character if character in "*/^:&|<>$@" else "",
            )
        if operator:
            if expects_value:
                return True
            if operator in {"::", ":::"} and not namespace_receiver_is_valid:
                return True
            expects_value = True
            namespace_receiver_is_valid = False
            cursor += len(operator)
            continue
        if character.isalnum() or character in "._":
            token_end = cursor + 1
            while token_end < stop and (text[token_end].isalnum() or text[token_end] in "._"):
                token_end += 1
            token = text[cursor:token_end]
            if token in {"for", "function", "if", "while"}:
                if not expects_value:
                    return True
                opener = _r_next_code_position(text, token_end, non_code_spans)
                if opener is None or opener >= stop or text[opener] != "(":
                    return False
                closer = delimiter_pairs.get(opener)
                if closer is None or closer >= stop:
                    return False
                expects_value = True
                namespace_receiver_is_valid = False
                cursor = closer + 1
                continue
            if token == "repeat":
                if not expects_value:
                    return True
                expects_value = True
                namespace_receiver_is_valid = False
                cursor = token_end
                continue
            if token == "else":
                if expects_value:
                    return True
                expects_value = True
                namespace_receiver_is_valid = False
                cursor = token_end
                continue
            if not expects_value:
                return True
            if token[0].isdigit() or (token.startswith(".") and len(token) > 1 and token[1].isdigit()):
                if _R_SIMPLE_NUMERIC_TOKEN_RE.fullmatch(token) is None:
                    return True
                namespace_receiver_is_valid = False
            elif token.startswith("_") or token in _R_CONTROL_WORDS - {"break", "next"}:
                return True
            else:
                namespace_receiver_is_valid = token not in _R_RESERVED_WORDS
            expects_value = False
            cursor = token_end
            continue

        cursor += 1
    return False


def _r_open_paren_starts_argument_list(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    if _r_function_keyword_before_position(
        text,
        position,
        non_code_spans,
        delimiter_pairs,
    ) or _r_lambda_shorthand_before_position(
        text,
        position,
        non_code_spans,
        delimiter_pairs,
    ):
        return True

    cursor = position - 1
    crossed_newline = False
    while cursor >= 0 and text[cursor].isspace():
        crossed_newline = crossed_newline or text[cursor] in "\r\n"
        cursor -= 1

    if cursor < 0:
        return False

    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    if span_index >= 0 and cursor < non_code_spans[span_index][1]:
        span_start, span_end = non_code_spans[span_index]
        return not crossed_newline and span_end == cursor + 1 and text[span_start] != "#"

    character = text[cursor]
    if character == "]":
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        return (
            not crossed_newline
            and opener_position is not None
            and _r_subscript_result_can_start_call(text, opener_position, non_code_spans, delimiter_pairs)
        )
    if character == ")":
        if crossed_newline:
            return False
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        if opener_position is None:
            return False
        opener_prefix = _r_identifier_before_position(text, opener_position, non_code_spans)
        return (
            _r_delimited_expression_can_start_call(text, opener_position, cursor, non_code_spans, delimiter_pairs)
            if opener_prefix is None
            else opener_prefix in {"else", "repeat"} or _r_token_can_start_call(opener_prefix)
        )
    if character == "}":
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        return (
            not crossed_newline
            and opener_position is not None
            and _r_delimited_expression_can_start_call(
                text,
                opener_position,
                cursor,
                non_code_spans,
                delimiter_pairs,
            )
        )
    if character == "\\":
        return False
    if not (character.isalnum() or character in "._"):
        return False

    token_end = cursor + 1
    while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
        cursor -= 1
    token = text[cursor + 1 : token_end]
    if crossed_newline or not _r_token_can_start_call(token):
        return False

    while cursor >= 0 and text[cursor].isspace():
        cursor -= 1
    if cursor >= 0 and text[cursor] in "$@:":
        operator_start = cursor
        if text[cursor] == ":":
            while operator_start >= 0 and text[operator_start] == ":":
                operator_start -= 1
            operator_start += 1
            if cursor - operator_start + 1 not in {2, 3}:
                return False
            return _r_namespace_receiver_is_valid(text, operator_start, non_code_spans)
        return not _r_expression_before_position_is_obviously_non_callable(
            text,
            operator_start,
            non_code_spans,
            delimiter_pairs,
        )
    return True


def _r_namespace_receiver_is_valid(
    text: str,
    operator_start: int,
    non_code_spans: list[tuple[int, int]],
) -> bool:
    cursor = operator_start - 1
    while cursor >= 0 and text[cursor].isspace():
        cursor -= 1
    if cursor < 0:
        return False

    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    if span_index >= 0 and cursor < non_code_spans[span_index][1]:
        span_start, span_end = non_code_spans[span_index]
        return span_end == cursor + 1 and text[span_start] in "\"'`" and text[span_end - 1] == text[span_start]

    if not (text[cursor].isalnum() or text[cursor] in "._"):
        return False
    token_end = cursor + 1
    while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
        cursor -= 1
    return _r_token_can_start_call(text[cursor + 1 : token_end])


def _r_token_can_start_call(token: str) -> bool:
    if token == "function":
        return False
    token_starts_like_number = token[0].isdigit() or (token.startswith(".") and len(token) > 1 and token[1].isdigit())
    return (
        not token_starts_like_number
        and not token.startswith("_")
        and token != "..."
        and _R_DOT_ARGUMENT_TOKEN_RE.fullmatch(token) is None
        and token not in _R_RESERVED_WORDS
    )


def _r_delimited_expression_can_start_call(
    text: str,
    opener_position: int,
    closer_position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    chunks: list[str] = []
    cursor = opener_position + 1
    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    span_index = max(0, span_index)
    while cursor < closer_position:
        while span_index < len(non_code_spans) and non_code_spans[span_index][1] <= cursor:
            span_index += 1
        if span_index < len(non_code_spans) and non_code_spans[span_index][0] <= cursor:
            span_start, span_end = non_code_spans[span_index]
            if text[span_start] == "#":
                cursor = min(span_end, closer_position)
                continue
            chunks.append(text[cursor : min(span_end, closer_position)])
            cursor = min(span_end, closer_position)
            continue
        next_span_start = (
            min(non_code_spans[span_index][0], closer_position) if span_index < len(non_code_spans) else closer_position
        )
        chunks.append(text[cursor:next_span_start])
        cursor = next_span_start

    expression = "".join(chunks).strip()
    if not expression:
        return False
    if all(character.isalnum() or character in "._" for character in expression):
        return _r_token_can_start_call(expression)
    if _r_expression_before_position_is_obviously_non_callable(
        text,
        closer_position,
        non_code_spans,
        delimiter_pairs,
    ):
        return False
    return not _r_grouped_expression_is_obviously_non_callable(expression)


def _r_grouped_expression_is_obviously_non_callable(expression: str) -> bool:
    cursor = 0
    saw_value = False
    while cursor < len(expression):
        token_match = _R_OBVIOUS_NONCALLABLE_GROUPED_TOKEN_RE.match(expression, cursor)
        if token_match is None:
            return False
        saw_value = saw_value or token_match.group("value") is not None
        cursor = token_match.end()
    return saw_value


def _r_next_code_position(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
) -> int | None:
    cursor = position
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            return None

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            return cursor
        span_start, span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return cursor
        cursor = span_end
    return None


def _r_expression_is_obviously_incomplete(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    unterminated_literal_starts: set[int],
) -> bool:
    """Reject clear truncation without attempting to parse the full R grammar."""
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    last_code_positions: list[int | None] = [None]
    saw_code = False
    cursor = position
    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    span_index = max(0, span_index)

    def current_expression_ends_with_operator() -> bool:
        last_code_position = last_code_positions[-1]
        return last_code_position is not None and (
            text[last_code_position] in _R_INCOMPLETE_EXPRESSION_TRAILING_CHARACTERS
            or (not stack and text[last_code_position] == "=")
        )

    while cursor < len(text):
        while span_index < len(non_code_spans) and non_code_spans[span_index][1] <= cursor:
            span_index += 1
        if span_index < len(non_code_spans) and non_code_spans[span_index][0] <= cursor:
            span_start, span_end = non_code_spans[span_index]
            if text[span_start] == "#":
                cursor = span_end
                continue
            if span_start in unterminated_literal_starts:
                return True
            last_code_positions[-1] = span_end - 1
            saw_code = True
            cursor = span_end
            continue

        character = text[cursor]
        if character.isspace():
            if character in "\r\n" and not stack:
                if not saw_code:
                    cursor += 1
                    continue
                if current_expression_ends_with_operator():
                    cursor += 1
                    continue
                return False
            cursor += 1
            continue
        if not stack and character == ";":
            return current_expression_ends_with_operator()
        if not stack and character in ",)]}":
            return current_expression_ends_with_operator()
        if character in closing_delimiters:
            last_code_positions[-1] = cursor
            stack.append(character)
            last_code_positions.append(None)
            saw_code = True
            cursor += 1
            continue
        if character in ")]}":
            if not stack or closing_delimiters[stack[-1]] != character:
                return True
            if current_expression_ends_with_operator():
                return True
            stack.pop()
            last_code_positions.pop()
            last_code_positions[-1] = cursor
            saw_code = True
            cursor += 1
            continue

        last_code_positions[-1] = cursor
        saw_code = True
        cursor += 1

    return bool(stack) or current_expression_ends_with_operator()


def _r_function_body_awaits_continuation(
    text: str,
    non_code_spans: list[tuple[int, int]] | None = None,
) -> bool:
    if non_code_spans is None:
        non_code_spans = _r_non_code_spans(text)
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    stack: list[tuple[str, int]] = []
    delimiter_pairs: dict[int, int] = {}
    cursor = 0
    span_index = 0
    while cursor < len(text):
        if span_index < len(non_code_spans) and cursor == non_code_spans[span_index][0]:
            cursor = non_code_spans[span_index][1]
            span_index += 1
            continue

        character = text[cursor]
        if character in closing_delimiters:
            stack.append((character, cursor))
        elif character in ")]}" and stack:
            if closing_delimiters[stack[-1][0]] != character:
                stack.clear()
                cursor += 1
                continue
            opener, opener_position = stack.pop()
            if opener == "(":
                delimiter_pairs[opener_position] = cursor
                delimiter_pairs[cursor] = opener_position
        cursor += 1

    unterminated_literal_starts = _r_unterminated_literal_span_starts(text, non_code_spans)
    for opener_position, closer_position in delimiter_pairs.items():
        if opener_position > closer_position:
            continue
        if not (
            _r_function_keyword_before_position(text, opener_position, non_code_spans, delimiter_pairs)
            or _r_lambda_shorthand_before_position(text, opener_position, non_code_spans, delimiter_pairs)
        ):
            continue
        body_start = closer_position + 1
        if _r_next_code_position(text, body_start, non_code_spans) is None or _r_expression_is_obviously_incomplete(
            text,
            body_start,
            non_code_spans,
            unterminated_literal_starts,
        ):
            return True
    return False


def _r_expression_follows(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
    unterminated_literal_starts: set[int] | None = None,
    remaining_depth: int = _R_EXPRESSION_MAX_DEPTH,
) -> bool:
    if remaining_depth <= 0:
        raise _RExpressionDepthExceeded
    cursor = _r_next_code_position(text, position, non_code_spans)
    if cursor is None:
        return False

    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    if span_index >= 0 and cursor < non_code_spans[span_index][1]:
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] == "#":
            return False
        if unterminated_literal_starts is None:
            unterminated_literal_starts = _r_unterminated_literal_span_starts(text, non_code_spans)
        return span_start not in unterminated_literal_starts
    if text[cursor] in ";,)]}":
        return False
    if text[cursor] in "([{":
        closer_position = _r_matching_close_delimiter_position(
            text,
            cursor,
            non_code_spans,
            delimiter_pairs,
        )
        if closer_position is None:
            return False
        return text[cursor] == "{" or _r_expression_follows(
            text,
            cursor + 1,
            non_code_spans,
            delimiter_pairs,
            unterminated_literal_starts,
            remaining_depth - 1,
        )
    while text[cursor] in "+-!~?":
        cursor = _r_next_code_position(text, cursor + 1, non_code_spans)
        if cursor is None:
            return False
        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index >= 0 and cursor < non_code_spans[span_index][1]:
            span_start, _span_end = non_code_spans[span_index]
            if text[span_start] == "#":
                return False
            if unterminated_literal_starts is None:
                unterminated_literal_starts = _r_unterminated_literal_span_starts(text, non_code_spans)
            return span_start not in unterminated_literal_starts

    if text[cursor].isalnum() or text[cursor] in "._":
        token_end = cursor + 1
        while token_end < len(text) and (text[token_end].isalnum() or text[token_end] in "._"):
            token_end += 1
        token = text[cursor:token_end]
        if token in {"else", "in"}:
            return False
        if token in {"break", "next"}:
            return True
        if token == "repeat":
            repeat_cursor = token_end
            while True:
                cursor = _r_next_code_position(text, repeat_cursor, non_code_spans)
                if cursor is None:
                    return False
                if not (text[cursor].isalnum() or text[cursor] in "._"):
                    break
                repeat_token_end = cursor + 1
                while repeat_token_end < len(text) and (
                    text[repeat_token_end].isalnum() or text[repeat_token_end] in "._"
                ):
                    repeat_token_end += 1
                if text[cursor:repeat_token_end] != "repeat":
                    break
                repeat_cursor = repeat_token_end
            return _r_expression_follows(
                text,
                cursor,
                non_code_spans,
                delimiter_pairs,
                unterminated_literal_starts,
                remaining_depth - 1,
            )
        if token in {"for", "function", "if", "while"}:
            opener_position = _r_next_code_position(text, token_end, non_code_spans)
            if opener_position is None or text[opener_position] != "(":
                return False
            closer_position = _r_matching_close_delimiter_position(
                text,
                opener_position,
                non_code_spans,
                delimiter_pairs,
            )
            if (
                closer_position is None
                or not _r_control_header_is_complete(
                    text,
                    token,
                    opener_position,
                    closer_position,
                    non_code_spans,
                    delimiter_pairs,
                    unterminated_literal_starts,
                )
                or not _r_expression_follows(
                    text,
                    closer_position + 1,
                    non_code_spans,
                    delimiter_pairs,
                    unterminated_literal_starts,
                    remaining_depth - 1,
                )
            ):
                return False
            return token != "if" or not _r_has_incomplete_top_level_else(
                text,
                closer_position + 1,
                non_code_spans,
                delimiter_pairs,
                unterminated_literal_starts,
                remaining_depth - 1,
            )
        return True
    return text[cursor] not in ";,)]}*/^:%<>=&|"


def _r_control_header_is_complete(
    text: str,
    token: str,
    opener_position: int,
    closer_position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None,
    unterminated_literal_starts: set[int] | None,
) -> bool:
    if token == "function":
        return True
    if unterminated_literal_starts is None:
        unterminated_literal_starts = _r_unterminated_literal_span_starts(text, non_code_spans)

    expression_start = _r_next_code_position(text, opener_position + 1, non_code_spans)
    if expression_start is None or expression_start >= closer_position:
        return False
    if token == "for":
        if not (text[expression_start].isalpha() or text[expression_start] in "._"):
            return False
        symbol_end = expression_start + 1
        while symbol_end < closer_position and (text[symbol_end].isalnum() or text[symbol_end] in "._"):
            symbol_end += 1
        if _r_unquoted_named_argument_target_kind(text[expression_start:symbol_end]) != "symbol":
            return False
        in_position = _r_next_code_position(text, symbol_end, non_code_spans)
        if in_position is None or not (
            text[in_position : in_position + 2] == "in"
            and (
                in_position + 2 >= closer_position
                or not (text[in_position + 2].isalnum() or text[in_position + 2] in "._")
            )
        ):
            return False
        expression_start = _r_next_code_position(text, in_position + 2, non_code_spans)
        if expression_start is None or expression_start >= closer_position:
            return False

    return _r_expression_follows(
        text,
        expression_start,
        non_code_spans,
        delimiter_pairs,
        unterminated_literal_starts,
    ) and not _r_expression_is_obviously_incomplete(
        text,
        expression_start,
        non_code_spans,
        unterminated_literal_starts,
    )


def _r_has_incomplete_top_level_else(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
    unterminated_literal_starts: set[int] | None = None,
    remaining_depth: int = _R_EXPRESSION_MAX_DEPTH,
) -> bool:
    if remaining_depth <= 0:
        raise _RExpressionDepthExceeded
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    cursor = position
    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    span_index = max(0, span_index)
    while cursor < len(text):
        while span_index < len(non_code_spans) and non_code_spans[span_index][1] <= cursor:
            span_index += 1
        if span_index < len(non_code_spans) and non_code_spans[span_index][0] <= cursor:
            cursor = non_code_spans[span_index][1]
            continue

        character = text[cursor]
        if not stack and character in ";,)]}":
            return False
        if character in closing_delimiters:
            stack.append(character)
            cursor += 1
            continue
        if character in ")]}":
            if not stack or closing_delimiters[stack[-1]] != character:
                return False
            stack.pop()
            cursor += 1
            continue
        if not stack and (character.isalnum() or character in "._"):
            token_end = cursor + 1
            while token_end < len(text) and (text[token_end].isalnum() or text[token_end] in "._"):
                token_end += 1
            if text[cursor:token_end] == "else" and not _r_expression_follows(
                text,
                token_end,
                non_code_spans,
                delimiter_pairs,
                unterminated_literal_starts,
                remaining_depth - 1,
            ):
                return True
            cursor = token_end
            continue
        cursor += 1
    return False


def _r_expression_before_position_is_obviously_non_callable(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    cursor = position - 1
    while cursor >= 0 and text[cursor].isspace():
        cursor -= 1
    if cursor < 0:
        return True

    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    if span_index >= 0 and cursor < non_code_spans[span_index][1]:
        return text[non_code_spans[span_index][0]] != "`"

    character = text[cursor]
    if character == "]":
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        return opener_position is None or _r_expression_before_position_is_obviously_non_callable(
            text,
            opener_position,
            non_code_spans,
            delimiter_pairs,
        )
    if character == ")":
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        if opener_position is None:
            return True
        if _r_open_paren_starts_argument_list(text, opener_position, non_code_spans, delimiter_pairs):
            return False
        opener_prefix = _r_identifier_before_position(text, opener_position, non_code_spans)
        if opener_prefix is not None:
            return not _r_token_can_start_call(opener_prefix)
        return not _r_delimited_expression_can_start_call(
            text,
            opener_position,
            cursor,
            non_code_spans,
            delimiter_pairs,
        )
    if character == "}":
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        return opener_position is None or not _r_delimited_expression_can_start_call(
            text,
            opener_position,
            cursor,
            non_code_spans,
            delimiter_pairs,
        )
    if not (character.isalnum() or character in "._"):
        return False

    token_end = cursor + 1
    while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
        cursor -= 1
    return not _r_token_can_start_call(text[cursor + 1 : token_end])


def _r_subscript_result_can_start_call(
    text: str,
    opener_position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    return _r_open_bracket_starts_subscript(
        text,
        opener_position,
        non_code_spans,
        delimiter_pairs,
    ) and not _r_expression_before_position_is_obviously_non_callable(
        text,
        opener_position,
        non_code_spans,
        delimiter_pairs,
    )


def _r_token_can_start_subscript(token: str) -> bool:
    if (
        not token
        or token.startswith("_")
        or token == "..."
        or _R_DOT_ARGUMENT_TOKEN_RE.fullmatch(token) is not None
        or token in _R_CONTROL_WORDS
    ):
        return False
    if token[0].isdigit() or (token.startswith(".") and len(token) > 1 and token[1].isdigit()):
        return _R_SIMPLE_NUMERIC_TOKEN_RE.fullmatch(token) is not None
    return True


def _r_open_bracket_starts_subscript(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> bool:
    while True:
        cursor = position - 1
        crossed_newline = False
        while cursor >= 0 and text[cursor].isspace():
            crossed_newline = crossed_newline or text[cursor] in "\r\n"
            cursor -= 1

        if cursor < 0 or crossed_newline:
            return False
        if text[cursor] == "[":
            position = cursor
            continue
        if text[cursor] == "]":
            opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
            if opener_position is None:
                return False
            position = opener_position
            continue
        break
    if text[cursor] == ")":
        opener_position = _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs)
        if opener_position is None:
            return False
        if _r_open_paren_starts_argument_list(text, opener_position, non_code_spans, delimiter_pairs):
            return True
        opener_prefix = _r_identifier_before_position(text, opener_position, non_code_spans)
        return opener_prefix is None
    if text[cursor] == "}":
        return _r_matching_open_delimiter_position(text, cursor, non_code_spans, delimiter_pairs) is not None

    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    if span_index >= 0 and cursor < non_code_spans[span_index][1]:
        span_start, span_end = non_code_spans[span_index]
        return span_end == cursor + 1 and text[span_start] != "#"
    if not (text[cursor].isalnum() or text[cursor] in "._"):
        return False

    token_end = cursor + 1
    while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
        cursor -= 1
    token = text[cursor + 1 : token_end]
    return _r_token_can_start_subscript(token)


def _r_open_call_or_subscript_awaits_continuation(
    text: str,
    non_code_spans: list[tuple[int, int]],
) -> bool:
    stack: list[tuple[str, int]] = []
    closing_delimiters = {")": "(", "]": "[", "}": "{"}
    cursor = 0
    span_index = 0
    while cursor < len(text):
        if span_index < len(non_code_spans) and cursor == non_code_spans[span_index][0]:
            cursor = non_code_spans[span_index][1]
            span_index += 1
            continue
        character = text[cursor]
        if character in "([{":
            stack.append((character, cursor))
        elif character in closing_delimiters:
            if not stack or stack[-1][0] != closing_delimiters[character]:
                stack.clear()
            else:
                stack.pop()
        cursor += 1

    return any(
        (opener == "(" and _r_open_paren_starts_argument_list(text, position, non_code_spans))
        or (opener == "[" and _r_open_bracket_starts_subscript(text, position, non_code_spans))
        for opener, position in stack
    )


def _r_identifier_before_position(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
) -> str | None:
    cursor = position - 1
    crossed_newline = False
    while cursor >= 0:
        while cursor >= 0 and text[cursor].isspace():
            crossed_newline = crossed_newline or text[cursor] in "\r\n"
            cursor -= 1
        if cursor < 0:
            return None

        span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
        if span_index < 0 or cursor >= non_code_spans[span_index][1]:
            break
        span_start, _span_end = non_code_spans[span_index]
        if text[span_start] != "#":
            return None
        cursor = span_start - 1

    if not (text[cursor].isalnum() or text[cursor] in "._"):
        return None
    token_end = cursor + 1
    while cursor >= 0 and (text[cursor].isalnum() or text[cursor] in "._"):
        cursor -= 1
    token = text[cursor + 1 : token_end]
    if crossed_newline and token not in {"else", "for", "function", "if", "repeat", "while"}:
        return None
    return token


def _r_matching_open_delimiter_position(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> int | None:
    if delimiter_pairs is not None:
        return delimiter_pairs.get(position)
    closing_delimiters = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    cursor = 0
    span_index = 0
    while cursor <= position:
        if span_index < len(non_code_spans) and cursor == non_code_spans[span_index][0]:
            cursor = non_code_spans[span_index][1]
            span_index += 1
            continue

        character = text[cursor]
        if character in "([{":
            stack.append((character, cursor))
        elif character in ")]}":
            if stack and stack[-1][0] != closing_delimiters[character]:
                return None
            is_matched = bool(stack)
            if cursor == position:
                return stack[-1][1] if is_matched else None
            if is_matched:
                stack.pop()
        cursor += 1
    return None


def _r_matching_close_delimiter_position(
    text: str,
    position: int,
    non_code_spans: list[tuple[int, int]],
    delimiter_pairs: dict[int, int] | None = None,
) -> int | None:
    if delimiter_pairs is not None:
        return delimiter_pairs.get(position)
    if position >= len(text) or text[position] not in "([{":
        return None

    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    stack = [text[position]]
    cursor = position + 1
    span_index = bisect_right(non_code_spans, cursor, key=lambda span: span[0]) - 1
    span_index = max(0, span_index)
    while cursor < len(text):
        while span_index < len(non_code_spans) and non_code_spans[span_index][1] <= cursor:
            span_index += 1
        if span_index < len(non_code_spans) and non_code_spans[span_index][0] <= cursor:
            cursor = non_code_spans[span_index][1]
            continue

        character = text[cursor]
        if character in closing_delimiters:
            stack.append(character)
        elif character in ")]}":
            if closing_delimiters[stack[-1]] != character:
                return None
            stack.pop()
            if not stack:
                return cursor
        cursor += 1
    return None


def _contains_r_raw_credential_assignment(text: str) -> bool:
    raw_string_spans = list(_iter_r_raw_string_spans(text))
    non_code_spans = _r_non_code_spans(text)
    left_operator_positions = {
        assignment_match.end(): assignment_match.start("operator")
        for assignment_match in _R_LEFTWARD_CREDENTIAL_TARGET_RE.finditer(text)
    }
    malformed_raw_span_starts = {
        literal_start
        for literal_start, _literal_end, _content_start, _content_end, is_terminated in raw_string_spans
        if not is_terminated
    }
    equals_positions: set[int] = set()
    for literal_start, literal_end, content_start, content_end, is_terminated in raw_string_spans:
        if not is_terminated or content_end - content_start < 6:
            continue

        operator_start = left_operator_positions.get(literal_start)
        if operator_start is not None:
            operator_is_suppressed = _position_is_in_r_suppressing_non_code_span(
                operator_start,
                non_code_spans,
                malformed_raw_span_starts,
            )
            if not operator_is_suppressed:
                if text[operator_start] != "=":
                    return True
                equals_positions.add(operator_start)

        right_match = _R_RIGHTWARD_RAW_CREDENTIAL_ASSIGNMENT_RE.match(text, literal_end)
        if right_match is not None and not _position_is_in_r_suppressing_non_code_span(
            right_match.start("operator"),
            non_code_spans,
            malformed_raw_span_starts,
        ):
            return True
    named_argument_positions = _r_named_argument_equals_positions(text, equals_positions, non_code_spans)
    return not equals_positions.issubset(named_argument_positions)


def _contains_r_quoted_credential_assignment(text: str) -> bool:
    non_code_spans = _r_non_code_spans(text)
    equals_positions: set[int] = set()
    for assignment_match in _R_LEFTWARD_QUOTED_CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        operator_start = assignment_match.start("operator")
        if _position_is_in_spans(operator_start, non_code_spans):
            continue
        if text[operator_start] != "=":
            return True
        equals_positions.add(operator_start)

    named_argument_positions = _r_named_argument_equals_positions(text, equals_positions, non_code_spans)
    if not equals_positions.issubset(named_argument_positions):
        return True

    for assignment_match in _R_RIGHTWARD_QUOTED_CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        if not _position_is_in_spans(assignment_match.start("operator"), non_code_spans):
            return True
    return False


def _r_expression_contains_credential_literal(expression: str) -> bool:
    if _R_QUOTED_CREDENTIAL_VALUE_RE.search(expression):
        return True
    return any(
        is_terminated and content_end - content_start >= 6
        for _start, _end, content_start, content_end, is_terminated in _iter_r_raw_string_spans(expression)
    )


def _contains_r_expression_credential_assignment(text: str) -> bool:
    non_code_spans = _r_non_code_spans(text)
    statement_starts = _r_statement_starts(text, non_code_spans)
    target_matches = [
        target_match
        for target_match in _R_LEFTWARD_CREDENTIAL_TARGET_RE.finditer(text)
        if not _position_is_in_spans(target_match.start("operator"), non_code_spans)
    ]
    equals_positions = {
        target_match.start("operator") for target_match in target_matches if text[target_match.start("operator")] == "="
    }
    named_argument_positions = _r_named_argument_equals_positions(text, equals_positions, non_code_spans)
    for target_match in target_matches:
        operator_start = target_match.start("operator")
        if operator_start in named_argument_positions:
            continue

        statement_index = bisect_right(statement_starts, target_match.start()) - 1
        expression_end = (
            statement_starts[statement_index + 1] - 1 if statement_index + 1 < len(statement_starts) else len(text)
        )
        if _r_expression_contains_credential_literal(text[target_match.end() : expression_end]):
            return True

    previous_target_end = 0
    for target_match in _R_RIGHTWARD_CREDENTIAL_TARGET_RE.finditer(text):
        if _position_is_in_spans(target_match.start(), non_code_spans):
            continue

        statement_start = max(
            _r_statement_start_before(statement_starts, target_match.start()),
            previous_target_end,
        )
        expression = text[statement_start : target_match.start()]
        if _r_expression_contains_credential_literal(expression):
            return True
        previous_target_end = target_match.end()
    return False


def _redact_url_for_display(url: str) -> str:
    """Return a URL safe for scan output while preserving routing context."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.hostname:
        return "[invalid-url]"

    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _redact_sample_for_display(text: str) -> str:
    return redact_evidence_string(text, max_chars=200)


@dataclass(frozen=True)
class _ExtractedString:
    text: str
    offset: int


class RSerializedScanner(BaseScanner):
    """Static scanner for R serialized files."""

    name = "r_serialized"
    description = "Scans R serialized model files for unsafe deserialization indicators"
    supported_extensions: ClassVar[list[str]] = [".rds", ".rda", ".rdata"]

    _SERIALIZATION_MARKERS: ClassVar[tuple[bytes, ...]] = (b"X\n", b"A\n", b"B\n")
    _WORKSPACE_HEADERS: ClassVar[tuple[bytes, ...]] = (b"RDX2\n", b"RDX3\n", b"RDA2\n", b"RDA3\n")

    _GZIP_MAGIC: ClassVar[bytes] = b"\x1f\x8b"
    _BZIP2_MAGIC: ClassVar[bytes] = b"BZh"
    _XZ_MAGIC: ClassVar[bytes] = b"\xfd7zXZ\x00"

    _CAN_HANDLE_DECOMPRESSED_LIMIT: ClassVar[int] = 128 * 1024
    _SIGNATURE_PROBE_BYTES: ClassVar[int] = 7
    _XZ_DECOMPRESS_MEMLIMIT: ClassVar[int] = 128 * 1024 * 1024
    _XZ_READ_CHUNK_SIZE: ClassVar[int] = 64 * 1024
    _PRINTABLE_RE: ClassVar[re.Pattern[bytes]] = re.compile(rb"[ -~]{3,512}")
    _EXECUTABLE_SYMBOL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w.])(?:base::|utils::)?"
        r"(?:system2?|eval|parse|source|do\.call|dyn\.load|socketconnection|pipe|url|download\.file)"
        r"(?![\w.])",
        re.IGNORECASE,
    )
    _EXECUTABLE_CALL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w.])(?:base::|utils::)?"
        r"(?:system2?|eval|parse|source|do\.call|dyn\.load|socketConnection|pipe|url|download\.file)\s*\(",
        re.IGNORECASE,
    )
    _COMMAND_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b("
        r"curl|wget|powershell|invoke-webrequest|cmd(?:\.exe)?|/bin/sh|/bin/bash|"
        r"python\s+-c|rscript\s+-e|rm\s+-rf|chmod\s+\+x|nc|netcat"
        r")\b"
    )
    _URL_RE: ClassVar[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    _IP_RE: ClassVar[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _CODE_CONTEXT_MARKERS: ClassVar[tuple[str, ...]] = (
        "expression",
        "language",
        "call",
        "function",
        "quote",
        "substitute",
        "closure",
        "promise",
    )
    _CREDENTIAL_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "github_token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        "openai_key_like": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    }

    def __init__(self, config: dict[str, object] | None = None):
        super().__init__(config=config)
        self.max_scan_bytes = int(self.config.get("r_max_scan_bytes", 16 * 1024 * 1024))
        self.max_decompressed_bytes = int(self.config.get("r_max_decompressed_bytes", 64 * 1024 * 1024))
        self.max_decompression_ratio = float(self.config.get("r_max_decompression_ratio", 250.0))
        self.max_extracted_strings = int(self.config.get("r_max_extracted_strings", 12_000))
        self.read_chunk_size = int(self.config.get("r_read_chunk_size", 64 * 1024))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        known_extension = os.path.splitext(path)[1].lower() in cls.supported_extensions

        try:
            with open(path, "rb") as file_obj:
                header = file_obj.read(16)
        except OSError:
            # Preserve declared ownership so scan() can report unavailable
            # coverage; readable suffix-only near matches are still rejected.
            return True

        compression = cls._detect_compression(header)
        if compression is None:
            if known_extension:
                return cls._looks_like_r_serialization(header)
            return cls._looks_like_renamed_r_serialization(header)

        if not known_extension:
            return False

        try:
            prefix = cls._read_decompressed_prefix(path, compression, cls._CAN_HANDLE_DECOMPRESSED_LIMIT)
        except (EOFError, OSError, gzip.BadGzipFile, lzma.LZMAError):
            # Corrupt compressed wrappers should still route to this scanner.
            return True

        return cls._looks_like_r_serialization(prefix)

    @classmethod
    def _looks_like_renamed_r_serialization(cls, data: bytes) -> bool:
        return any(
            data.startswith(workspace_header + marker)
            for workspace_header in cls._WORKSPACE_HEADERS
            for marker in cls._SERIALIZATION_MARKERS
        )

    @classmethod
    def _detect_compression(cls, header: bytes) -> str | None:
        if header.startswith(cls._GZIP_MAGIC):
            return "gzip"
        if header.startswith(cls._BZIP2_MAGIC):
            return "bzip2"
        if header.startswith(cls._XZ_MAGIC):
            return "xz"
        return None

    @classmethod
    def _looks_like_r_serialization(cls, data: bytes) -> bool:
        if any(data.startswith(marker) for marker in cls._SERIALIZATION_MARKERS):
            return True

        for header in cls._WORKSPACE_HEADERS:
            if data.startswith(header):
                trailing = data[len(header) : len(header) + 2]
                if not trailing or trailing in cls._SERIALIZATION_MARKERS:
                    return True

        return False

    @classmethod
    def _read_decompressed_prefix(cls, path: str, compression: str, limit: int) -> bytes:
        read_limit = limit + 1
        if compression == "gzip":
            with gzip.open(path, "rb") as stream:
                return stream.read(read_limit)[:limit]
        if compression == "bzip2":
            with bz2.open(path, "rb") as stream:
                return stream.read(read_limit)[:limit]
        if compression == "xz":
            return cls._read_xz_signature_prefix(
                path=path,
                limit=min(limit, cls._SIGNATURE_PROBE_BYTES),
                memlimit=cls._XZ_DECOMPRESS_MEMLIMIT,
            )
        return b""

    @classmethod
    def _read_xz_signature_prefix(cls, path: str, limit: int, memlimit: int) -> bytes:
        if limit <= 0:
            return b""

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
        prefix = bytearray()
        pending = b""

        with open(path, "rb") as file_obj:
            while len(prefix) < limit:
                if not pending:
                    pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)

                if not pending:
                    if not decompressor.eof:
                        raise EOFError("Incomplete XZ stream ended before EOF marker")
                    break

                piece = decompressor.decompress(pending, max_length=limit - len(prefix))
                pending = decompressor.unused_data

                while True:
                    if piece:
                        prefix.extend(piece)
                        if len(prefix) >= limit:
                            return bytes(prefix)

                    if decompressor.eof or decompressor.needs_input:
                        break

                    piece = decompressor.decompress(b"", max_length=limit - len(prefix))

                if decompressor.eof:
                    if not pending:
                        pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)
                        if not pending:
                            break
                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
                    continue

                pending = b""

        return bytes(prefix)

    @classmethod
    def _read_xz_with_memlimit(
        cls,
        path: str,
        output_limit: int,
        memlimit: int,
        *,
        compressed_size: int,
        max_decompressed_bytes: int,
        max_decompression_ratio: float,
    ) -> tuple[bytes, bool, int]:
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
        decompressed = bytearray()
        total_decompressed = 0
        truncated = False
        pending = b""

        with open(path, "rb") as file_obj:
            while True:
                if not pending:
                    pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)

                if not pending:
                    if not truncated and not decompressor.eof:
                        raise EOFError("Incomplete XZ stream ended before EOF marker")
                    break

                piece = decompressor.decompress(pending, max_length=cls._XZ_READ_CHUNK_SIZE)
                pending = decompressor.unused_data
                while True:
                    if piece:
                        total_decompressed += len(piece)
                        if total_decompressed > max_decompressed_bytes:
                            raise ValueError(f"Decompressed stream exceeded limit ({max_decompressed_bytes} bytes)")

                        if compressed_size > 0 and total_decompressed / compressed_size > max_decompression_ratio:
                            raise ValueError(
                                f"Suspicious decompression ratio ({total_decompressed / compressed_size:.1f}x > "
                                f"{max_decompression_ratio:.1f}x)"
                            )

                        remaining = max(output_limit - len(decompressed), 0)
                        decompressed.extend(piece[:remaining])
                        if len(piece) > remaining:
                            truncated = True

                    if truncated or decompressor.eof or decompressor.needs_input:
                        break

                    piece = decompressor.decompress(b"", max_length=cls._XZ_READ_CHUNK_SIZE)

                if truncated:
                    break

                if decompressor.eof:
                    if not pending:
                        pending = file_obj.read(cls._XZ_READ_CHUNK_SIZE)
                        if not pending:
                            break
                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memlimit)
                    continue

                pending = b""

        return bytes(decompressed), truncated, total_decompressed

    def _read_payload_for_analysis(self, path: str, file_size: int) -> tuple[bytes, str, bool, int]:
        with open(path, "rb") as file_obj:
            header = file_obj.read(16)

        compression = self._detect_compression(header)
        if compression is None:
            with open(path, "rb") as file_obj:
                payload = file_obj.read(self.max_scan_bytes + 1)
            truncated = len(payload) > self.max_scan_bytes
            return payload[: self.max_scan_bytes], "none", truncated, min(len(payload), self.max_scan_bytes)

        if compression == "gzip":
            with gzip.open(path, "rb") as stream:
                payload, truncated, total_decompressed = self._read_decompressed_stream(stream, file_size)
        elif compression == "bzip2":
            with bz2.open(path, "rb") as stream:
                payload, truncated, total_decompressed = self._read_decompressed_stream(stream, file_size)
        else:
            payload, truncated, total_decompressed = self._read_xz_with_memlimit(
                path=path,
                output_limit=self.max_scan_bytes,
                memlimit=self.max_decompressed_bytes,
                compressed_size=file_size,
                max_decompressed_bytes=self.max_decompressed_bytes,
                max_decompression_ratio=self.max_decompression_ratio,
            )

        return payload, compression, truncated, total_decompressed

    def _read_decompressed_stream(self, stream: Any, file_size: int) -> tuple[bytes, bool, int]:
        decompressed = bytearray()
        total_decompressed = 0
        truncated = False

        while True:
            chunk = stream.read(self.read_chunk_size)
            if not chunk:
                break

            total_decompressed += len(chunk)
            if total_decompressed > self.max_decompressed_bytes:
                raise ValueError(f"Decompressed stream exceeded limit ({self.max_decompressed_bytes} bytes)")

            if file_size > 0 and total_decompressed / file_size > self.max_decompression_ratio:
                raise ValueError(
                    f"Suspicious decompression ratio ({total_decompressed / file_size:.1f}x > "
                    f"{self.max_decompression_ratio:.1f}x)"
                )

            if len(decompressed) >= self.max_scan_bytes:
                truncated = True
                break

            remaining = self.max_scan_bytes - len(decompressed)
            decompressed.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
                break

        return bytes(decompressed), truncated, total_decompressed

    def _extract_strings(self, payload: bytes) -> tuple[list[_ExtractedString], str | None, int, int]:
        strings: list[_ExtractedString] = []
        incomplete_reason: str | None = None
        total_printable_bytes = 0
        longest_string = 0
        current_parts: list[str] = []
        current_length = 0
        current_offset = 0
        previous_match_end: int | None = None
        continuation_active = False
        continuation_analysis_work = 0

        def append_current_run() -> bool:
            nonlocal total_printable_bytes, longest_string
            if not current_parts:
                return True
            text = "".join(current_parts).strip()
            if not text:
                return True
            longest_string = max(longest_string, len(text))
            if len(strings) >= self.max_extracted_strings:
                return False
            strings.append(_ExtractedString(text=text, offset=current_offset))
            total_printable_bytes += len(text)
            return True

        def append_part(part: str) -> None:
            nonlocal current_length
            current_parts.append(part)
            current_length += len(part)

        def append_printable_tail(start: int, end: int) -> None:
            if not current_parts or start >= end:
                return
            tail_start = start
            if continuation_active:
                while tail_start < end and payload[tail_start] in (0x09, 0x0A, 0x0D, 0x20):
                    tail_start += 1
            tail_end = tail_start
            while tail_end < end and 0x20 <= payload[tail_end] <= 0x7E:
                tail_end += 1
            if tail_end == tail_start:
                return
            tail = payload[start if continuation_active else tail_start : tail_end]
            append_part(tail.decode("utf-8", errors="ignore"))

        def append_short_continuation_prefix(end: int) -> None:
            nonlocal continuation_active, current_offset
            prefix_end = end
            while True:
                while prefix_end > 0 and payload[prefix_end - 1] in (0x09, 0x0A, 0x0D, 0x20):
                    prefix_end -= 1
                line_start = max(payload.rfind(b"\n", 0, prefix_end), payload.rfind(b"\r", 0, prefix_end)) + 1
                if payload[line_start:prefix_end].lstrip().startswith(b"#"):
                    prefix_end = line_start
                    continue
                break
            prefix_start = prefix_end
            while prefix_start > 0 and 0x21 <= payload[prefix_start - 1] <= 0x7E:
                prefix_start -= 1
            if not 0 < prefix_end - prefix_start < 3:
                return
            prefix = payload[prefix_start:prefix_end].decode("utf-8", errors="ignore")
            non_code_spans = _r_non_code_spans(prefix)
            if not _r_open_call_or_subscript_awaits_continuation(prefix, non_code_spans):
                return
            current_offset = prefix_start
            append_part(payload[prefix_start:end].decode("utf-8", errors="ignore"))
            continuation_active = True

        def gap_supports_continuation(gap: bytes) -> bool:
            if not gap or not any(byte in (0x0A, 0x0D) for byte in gap):
                return False
            try:
                lines = gap.decode("ascii").splitlines()
            except UnicodeDecodeError:
                return False
            return all(not line.strip() or line.lstrip().startswith("#") for line in lines)

        for match in self._PRINTABLE_RE.finditer(payload):
            if previous_match_end != match.start():
                if previous_match_end is not None:
                    append_printable_tail(previous_match_end, match.start())
                    gap = payload[previous_match_end : match.start()]
                    is_newline_whitespace_gap = gap_supports_continuation(gap)
                    if (
                        is_newline_whitespace_gap
                        and continuation_active
                        and (current_length > _R_CONTINUATION_ANALYSIS_MAX_CHARS)
                    ):
                        incomplete_reason = _CONTINUATION_ANALYSIS_INCONCLUSIVE_REASON
                        break
                    if is_newline_whitespace_gap and current_length <= _R_CONTINUATION_ANALYSIS_MAX_CHARS:
                        continuation_analysis_work += current_length
                        if continuation_analysis_work > _R_CONTINUATION_ANALYSIS_MAX_WORK:
                            incomplete_reason = _CONTINUATION_ANALYSIS_INCONCLUSIVE_REASON
                            break
                        current_text = "".join(current_parts)
                        non_code_spans = _r_non_code_spans(current_text)
                        continuation_active = (
                            _unfinished_r_assignment_literal_closing_sequence(current_text) is not None
                            or _r_function_keyword_awaits_formals(current_text, non_code_spans)
                            or _r_function_body_awaits_continuation(current_text, non_code_spans)
                            or _r_lambda_shorthand_before_position(
                                current_text,
                                len(current_text),
                                non_code_spans,
                            )
                            or _r_open_call_or_subscript_awaits_continuation(current_text, non_code_spans)
                        )
                    else:
                        continuation_active = False
                    if continuation_active:
                        append_part(gap.decode("ascii"))
                        append_part(match.group().decode("utf-8", errors="ignore"))
                        previous_match_end = match.end()
                        continue
                if not append_current_run():
                    incomplete_reason = _STRING_EXTRACTION_INCONCLUSIVE_REASON
                    break
                current_parts = []
                current_length = 0
                continuation_active = False
                current_offset = match.start()
                append_short_continuation_prefix(match.start())

            append_part(match.group().decode("utf-8", errors="ignore"))
            previous_match_end = match.end()
        else:
            if previous_match_end is not None:
                append_printable_tail(previous_match_end, len(payload))
            if not append_current_run():
                incomplete_reason = _STRING_EXTRACTION_INCONCLUSIVE_REASON

        return strings, incomplete_reason, total_printable_bytes, longest_string

    def _context_window(self, strings: list[_ExtractedString], index: int, window_size: int = 2) -> str:
        start = max(0, index - window_size)
        end = min(len(strings), index + window_size + 1)
        return " ".join(item.text for item in strings[start:end])

    def _is_primarily_documentation(self, text: str) -> bool:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False

        documentation_lines = sum(
            1
            for line in lines
            if line.startswith(("#", "//", "*", ";"))
            or line.lower().startswith(("note:", "description:", "documentation:", "comment:"))
        )
        return documentation_lines / len(lines) > 0.5

    def _is_valid_public_ip(self, candidate: str) -> bool:
        try:
            value = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return not (value.is_private or value.is_loopback or value.is_link_local or value.is_multicast)

    def _add_symbol_and_payload_checks(self, result: ScanResult, strings: list[_ExtractedString], path: str) -> None:
        critical_symbol_hits: list[dict[str, object]] = []
        metadata_symbol_hits: list[dict[str, object]] = []
        critical_payload_hits: list[dict[str, object]] = []
        warning_payload_hits: list[dict[str, object]] = []
        url_hits: set[str] = set()
        ip_hits: set[str] = set()
        credential_hits: set[str] = set()
        expression_analysis_incomplete = False

        for index, extracted in enumerate(strings):
            text = extracted.text
            lowered = text.lower()
            context = self._context_window(strings, index).lower()
            has_code_context = any(marker in context for marker in self._CODE_CONTEXT_MARKERS)
            has_exec_symbol = bool(self._EXECUTABLE_SYMBOL_RE.search(lowered))
            has_exec_call = bool(self._EXECUTABLE_CALL_RE.search(lowered))
            documentation_only = self._is_primarily_documentation(text)

            if has_exec_symbol:
                match = self._EXECUTABLE_SYMBOL_RE.search(lowered)
                assert match is not None
                hit = {"symbol": match.group(0), "offset": extracted.offset, "sample": _redact_sample_for_display(text)}
                if has_exec_call or has_code_context:
                    if not documentation_only or has_exec_call:
                        critical_symbol_hits.append(hit)
                else:
                    metadata_symbol_hits.append(hit)

            command_match = self._COMMAND_RE.search(text)
            if command_match:
                hit = {
                    "pattern": command_match.group(0),
                    "offset": extracted.offset,
                    "sample": _redact_sample_for_display(text),
                }
                if has_exec_call or has_code_context or has_exec_symbol:
                    critical_payload_hits.append(hit)
                elif not documentation_only:
                    warning_payload_hits.append(hit)

            for url in self._URL_RE.findall(text):
                url_hits.add(_redact_url_for_display(url))

            for ip in self._IP_RE.findall(text):
                if self._is_valid_public_ip(ip):
                    ip_hits.add(ip)

            for name, pattern in self._CREDENTIAL_PATTERNS.items():
                if pattern.search(text):
                    credential_hits.add(name)
            try:
                has_credential_assignment = (
                    _contains_r_quoted_credential_assignment(text)
                    or _contains_r_raw_credential_assignment(text)
                    or _contains_r_expression_credential_assignment(text)
                )
            except _RExpressionDepthExceeded:
                expression_analysis_incomplete = True
                has_credential_assignment = False
            except RecursionError:
                # Ambiguous deeply nested R syntax must not turn into lost coverage.
                has_credential_assignment = True
            if has_credential_assignment:
                credential_hits.add("generic_secret_assignment")

        if critical_symbol_hits:
            result.add_check(
                name="Executable Symbol Context Analysis",
                passed=False,
                message=(
                    f"Found {len(critical_symbol_hits)} risky R symbol reference(s) in executable serialization context"
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "hit_count": len(critical_symbol_hits),
                    "examples": critical_symbol_hits[:5],
                    "detection_scope": "serialized_code_context",
                },
                why=(
                    "R serialized language objects can execute these functions when loaded/evaluated. "
                    "Treat artifacts containing executable symbol contexts as untrusted."
                ),
            )
        else:
            result.add_check(
                name="Executable Symbol Context Analysis",
                passed=True,
                message="No risky executable symbol references detected in code-like contexts",
                location=path,
            )

        if metadata_symbol_hits:
            result.add_check(
                name="Risky Symbol Metadata Mentions",
                passed=False,
                message=(f"Found {len(metadata_symbol_hits)} risky symbol mention(s) outside executable context"),
                severity=IssueSeverity.INFO,
                location=path,
                details={"hit_count": len(metadata_symbol_hits), "examples": metadata_symbol_hits[:5]},
                why=(
                    "These names may be benign metadata, but should be reviewed when artifacts come from "
                    "untrusted sources."
                ),
            )

        if critical_payload_hits:
            result.add_check(
                name="Serialized Expression Payload Detection",
                passed=False,
                message=f"Detected {len(critical_payload_hits)} command-like payload indicator(s) in code context",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"hit_count": len(critical_payload_hits), "examples": critical_payload_hits[:5]},
                why=(
                    "Command-oriented payload markers inside serialized expression contexts are strong indicators "
                    "of unsafe deserialization behavior."
                ),
            )
        elif warning_payload_hits:
            result.add_check(
                name="Serialized Expression Payload Detection",
                passed=False,
                message=f"Detected {len(warning_payload_hits)} command-like payload indicator(s)",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"hit_count": len(warning_payload_hits), "examples": warning_payload_hits[:5]},
                why=("Command-like tokens may indicate staging content. Review file provenance and loading path."),
            )
        else:
            result.add_check(
                name="Serialized Expression Payload Detection",
                passed=True,
                message="No command-like payload indicators detected",
                location=path,
            )

        if url_hits or ip_hits:
            result.add_check(
                name="Embedded Network Indicator Detection",
                passed=False,
                message=(f"Detected {len(url_hits)} URL indicator(s) and {len(ip_hits)} public IP indicator(s)"),
                severity=IssueSeverity.WARNING,
                location=path,
                details={"urls": sorted(url_hits)[:10], "public_ips": sorted(ip_hits)[:10]},
                why=(
                    "Embedded external endpoints can indicate data-exfiltration or payload-fetch behavior when "
                    "coupled with dynamic evaluation."
                ),
            )
        else:
            result.add_check(
                name="Embedded Network Indicator Detection",
                passed=True,
                message="No suspicious URL/IP indicators detected",
                location=path,
            )

        if expression_analysis_incomplete:
            mark_inconclusive_scan_result(result, _EXPRESSION_DEPTH_INCONCLUSIVE_REASON)
            result.add_check(
                name="R Expression Analysis Ceiling",
                passed=False,
                message=f"R expression analysis exceeded the nesting ceiling ({_R_EXPRESSION_MAX_DEPTH})",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "max_expression_depth": _R_EXPRESSION_MAX_DEPTH,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": _EXPRESSION_DEPTH_INCONCLUSIVE_REASON,
                },
                why="A nesting ceiling bounds parser work. Review deeply nested expressions manually.",
            )

        if credential_hits:
            result.add_check(
                name="Credential-like String Detection",
                passed=False,
                message=f"Detected {len(credential_hits)} credential-like pattern class(es)",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"pattern_classes": sorted(credential_hits)},
                why="Serialized artifacts should not contain long-lived secrets or access tokens.",
            )
        else:
            result.add_check(
                name="Credential-like String Detection",
                passed=True,
                message="No credential-like patterns detected",
                location=path,
            )

    def _add_payload_stuffing_check(
        self,
        result: ScanResult,
        path: str,
        payload_size: int,
        string_count: int,
        total_printable_bytes: int,
        longest_string: int,
        strings_truncated: bool,
    ) -> None:
        printable_ratio = total_printable_bytes / payload_size if payload_size > 0 else 0.0
        looks_stuffed = longest_string > 8_192 or (payload_size >= 1_000_000 and printable_ratio > 0.80)

        if looks_stuffed:
            result.add_check(
                name="Serialized Payload Stuffing Detection",
                passed=False,
                message="Serialized object contains unusually dense or oversized embedded text payloads",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "string_count": string_count,
                    "max_allowed_strings": self.max_extracted_strings,
                    "total_printable_bytes": total_printable_bytes,
                    "printable_ratio": round(printable_ratio, 4),
                    "longest_string": longest_string,
                    "truncated_string_extraction": strings_truncated,
                },
                why=(
                    "Abnormally dense textual content in serialized objects can indicate payload stuffing "
                    "for staged execution."
                ),
            )
            return

        result.add_check(
            name="Serialized Payload Stuffing Detection",
            passed=True,
            message="No payload stuffing anomalies detected",
            location=path,
            details={
                "string_count": string_count,
                "total_printable_bytes": total_printable_bytes,
                "printable_ratio": round(printable_ratio, 4),
                "longest_string": longest_string,
            },
        )

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            if any(
                check.name == "Path Readable" and check.status == CheckStatus.FAILED
                for check in path_check_result.checks
            ):
                result = self._create_result()
                self._mark_read_failure(result, path, PermissionError(f"Path is not readable: {path}"))
                result.finish(success=False)
                return result
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            payload, compression, truncated, decompressed_bytes = self._read_payload_for_analysis(path, file_size)
        except gzip.BadGzipFile as exc:
            self._mark_decode_failure(result, path, exc)
            result.finish(success=False)
            return result
        except OSError as exc:
            if exc.errno is not None:
                self._mark_read_failure(result, path, exc)
            else:
                self._mark_decode_failure(result, path, exc)
            result.finish(success=False)
            return result
        except (EOFError, ValueError, MemoryError, lzma.LZMAError) as exc:
            self._mark_decode_failure(result, path, exc)
            result.finish(success=False)
            return result

        result.add_check(
            name="R Serialized Decompression",
            passed=True,
            message="Safely decoded R serialized payload for analysis",
            location=path,
            details={
                "compression": compression,
                "compressed_bytes": file_size,
                "decompressed_bytes": decompressed_bytes,
            },
        )

        if not payload:
            result.add_check(
                name="R Serialization Signature",
                passed=False,
                message="R serialized payload is empty after decoding",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

        if not self._looks_like_r_serialization(payload):
            result.add_check(
                name="R Serialization Signature",
                passed=False,
                message="File does not contain a recognized R serialization header/signature",
                severity=IssueSeverity.INFO,
                location=path,
                details={"compression": compression},
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="R Serialization Signature",
            passed=True,
            message="Recognized R serialization header/signature",
            location=path,
            details={"compression": compression},
        )

        if truncated:
            mark_inconclusive_scan_result(result, "r_serialized_byte_ceiling_incomplete")
            result.add_check(
                name="Byte Scan Ceiling",
                passed=False,
                message=f"Analysis truncated at configured byte ceiling ({self.max_scan_bytes} bytes)",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_scan_bytes": self.max_scan_bytes, "compression": compression},
                why="A scan ceiling limits resource usage. Review with higher limits if deeper inspection is needed.",
            )
        else:
            result.add_check(
                name="Byte Scan Ceiling",
                passed=True,
                message="File analyzed within configured byte ceiling",
                location=path,
                details={"max_scan_bytes": self.max_scan_bytes, "compression": compression},
            )

        extracted_strings, extraction_incomplete_reason, total_printable_bytes, longest_string = self._extract_strings(
            payload
        )
        strings_truncated = extraction_incomplete_reason is not None
        result.metadata["compression"] = compression
        result.metadata["decompressed_bytes"] = decompressed_bytes
        result.metadata["extracted_string_count"] = len(extracted_strings)
        result.bytes_scanned = len(payload)

        if extraction_incomplete_reason is not None:
            mark_inconclusive_scan_result(result, extraction_incomplete_reason)
            continuation_analysis_incomplete = (
                extraction_incomplete_reason == _CONTINUATION_ANALYSIS_INCONCLUSIVE_REASON
            )
            message = (
                f"Analysis reached the R continuation-analysis ceiling "
                f"({_R_CONTINUATION_ANALYSIS_MAX_CHARS} characters)"
                if continuation_analysis_incomplete
                else f"Analysis reached configured extracted-string ceiling ({self.max_extracted_strings} strings)"
            )
            result.add_check(
                name="String Extraction Ceiling",
                passed=False,
                message=message,
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "max_extracted_strings": self.max_extracted_strings,
                    "max_continuation_analysis_chars": _R_CONTINUATION_ANALYSIS_MAX_CHARS,
                    "max_continuation_analysis_work": _R_CONTINUATION_ANALYSIS_MAX_WORK,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": extraction_incomplete_reason,
                },
                why=(
                    "Parser work ceilings limit resource usage. Review the artifact manually when deeper "
                    "inspection is required."
                ),
            )

        self._add_symbol_and_payload_checks(result, extracted_strings, path)
        self._add_payload_stuffing_check(
            result=result,
            path=path,
            payload_size=len(payload),
            string_count=len(extracted_strings),
            total_printable_bytes=total_printable_bytes,
            longest_string=longest_string,
            strings_truncated=strings_truncated,
        )

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
        )
        return result

    @staticmethod
    def _mark_read_failure(result: ScanResult, path: str, error: OSError) -> None:
        """Record file-access coverage loss separately from malformed serialized data."""
        mark_inconclusive_scan_result(result, _READ_INCONCLUSIVE_REASON)
        mark_operational_scan_error(result, _READ_INCONCLUSIVE_REASON)
        result.add_check(
            name="R Serialized Read",
            passed=False,
            message=f"Unable to read R serialized payload for analysis: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": _READ_INCONCLUSIVE_REASON,
            },
            why="The artifact could not be read, so R serialized security analysis did not complete.",
        )

    @staticmethod
    def _mark_decode_failure(result: ScanResult, path: str, error: Exception) -> None:
        """Record bounded decode or decompression coverage loss."""
        mark_inconclusive_scan_result(result, _DECODE_INCONCLUSIVE_REASON)
        result.add_check(
            name="R Serialized Decompression",
            passed=False,
            message=f"Failed to safely read R serialized payload: {error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": _DECODE_INCONCLUSIVE_REASON,
            },
            why=(
                "Malformed or unsafe compressed streams are treated as scan failures to avoid unsafe parsing behavior."
            ),
        )
