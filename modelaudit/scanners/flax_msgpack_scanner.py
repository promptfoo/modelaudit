"""Scanner for Flax/JAX MessagePack serialized model files (.msgpack)."""

from __future__ import annotations

import codecs
import hashlib
import os
import re
import struct
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, BinaryIO, ClassVar

from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..utils.file.detection import has_inconclusive_renamed_flax_msgpack_routing, is_flax_msgpack_checkpoint_file

try:
    import msgpack

    HAS_MSGPACK = True
except Exception:  # pragma: no cover - optional dependency missing
    HAS_MSGPACK = False

from ._evidence_redaction import REDACTED_EVIDENCE_VALUE, redact_evidence_string
from .base import BaseScanner, IssueSeverity, ScanResult

_DANGEROUS_JAX_TRANSFORMS = ("jit_compile", "eval_jit", "exec_transform", "dynamic_eval", "runtime_eval")
_EVIDENCE_SAMPLE_CHARS = 200
_EVIDENCE_LOCATION_CHARS = 300
_EVIDENCE_REDACTION_INPUT_CHARS = 4096
_MIN_SHORT_BINARY_TEXT_PERCENT = 85
_MAX_STREAM_TENSOR_SAMPLES = 64
_MAX_STREAM_SEQUENCE_EVIDENCE = 64
_STREAM_MARKER_CHUNK_BYTES = 64 * 1024
_STREAM_TEXT_CHUNK_BYTES = 64 * 1024
_STREAM_TEXT_OVERLAP_CHARS = 4096
_DEFAULT_MAX_STREAM_KEY_LENGTH = 1024 * 1024
_DEFAULT_MAX_DUPLICATE_KEY_TRACKING_BYTES = 4 * 1024 * 1024
_UNBOUNDED_GETATTR_PATTERN = r"getattr\s*\(\s*.*\s*,\s*['\"]__.*__['\"]"
_WHITESPACE_RUN_PATTERN = re.compile(r"\s+")
_JAX_TRANSFORM_DEDUP_METADATA_KEY = "flax_msgpack_jax_transform_findings"
_FLAX_NDARRAY_DTYPE_ITEM_SIZES = {
    "?": 1,
    "bool": 1,
    "bool_": 1,
    "byte": 1,
    "float4_e2m1fn": 1,
    "float6_e2m3fn": 1,
    "float6_e3m2fn": 1,
    "float8_e3m4": 1,
    "float8_e4m3": 1,
    "float8_e4m3b11fnuz": 1,
    "float8_e4m3fn": 1,
    "float8_e4m3fnuz": 1,
    "float8_e5m2": 1,
    "float8_e5m2fnuz": 1,
    "float8_e8m0fnu": 1,
    "int8": 1,
    "int2": 1,
    "int4": 1,
    "uint8": 1,
    "uint2": 1,
    "uint4": 1,
    "i1": 1,
    "u1": 1,
    "float16": 2,
    "bfloat16": 2,
    "int16": 2,
    "uint16": 2,
    "f2": 2,
    "i2": 2,
    "u2": 2,
    "float32": 4,
    "int32": 4,
    "uint32": 4,
    "f4": 4,
    "i4": 4,
    "u4": 4,
    "float64": 8,
    "int64": 8,
    "uint64": 8,
    "complex64": 8,
    "f8": 8,
    "i8": 8,
    "u8": 8,
    "c8": 8,
    "complex128": 16,
    "c16": 16,
}


class _StreamCoverageStopped(Exception):
    """Internal signal that a fail-closed container budget ended the walk."""


class OutOfData(Exception):
    """Internal MessagePack cursor signal for truncated input."""


class _MsgpackStreamFormatError(ValueError):
    """Internal MessagePack cursor signal for malformed input."""


@dataclass
class _StreamValue:
    type_name: str
    value: Any = None
    direct_string_keys: set[str] = field(default_factory=set)
    sequence_summary: _StreamSequenceSummary | None = None

    @property
    def is_container(self) -> bool:
        return self.type_name in {"dict", "list"}


@dataclass
class _StreamTraversalState:
    max_nodes: int
    nodes: int = 0
    node_budget_reported: bool = False
    decode_limit_reported: bool = False
    recursion_limit_reported: bool = False


@dataclass
class _StreamMarkerReader:
    source: BinaryIO
    chunk_start: int = -1
    chunk: bytes = b""

    def read(self, offset: int, max_bytes: int) -> bytes:
        chunk_offset = offset - self.chunk_start
        if chunk_offset >= 0 and chunk_offset + max_bytes <= len(self.chunk):
            return self.chunk[chunk_offset : chunk_offset + max_bytes]

        source_offset = self.source.tell()
        try:
            self.source.seek(offset)
            self.chunk_start = offset
            self.chunk = self.source.read(_STREAM_MARKER_CHUNK_BYTES)
        finally:
            self.source.seek(source_offset)
        return self.chunk[:max_bytes]

    def peek(self, offset: int) -> int | None:
        prefix = self.read(offset, 1)
        return prefix[0] if prefix else None


@dataclass
class _MsgpackStreamCursor:
    source: BinaryIO
    stream_size: int
    offset: int = 0

    def tell(self) -> int:
        return self.offset

    def _read_exact(self, size: int) -> bytes:
        if size < 0:
            raise _MsgpackStreamFormatError("negative MessagePack read length")
        if size == 0:
            return b""
        self.source.seek(self.offset)
        data = self.source.read(size)
        self.offset += len(data)
        if len(data) != size:
            raise OutOfData
        return data

    def _peek_bytes(self, size: int) -> bytes:
        if size <= 0 or self.offset >= self.stream_size:
            return b""
        source_offset = self.source.tell()
        try:
            self.source.seek(self.offset)
            return self.source.read(size)
        finally:
            self.source.seek(source_offset)

    def peek_marker(self) -> int | None:
        prefix = self._peek_bytes(1)
        return prefix[0] if prefix else None

    def peek_declared_data_bytes(self) -> int | None:
        marker = self.peek_marker()
        if marker is None:
            return None
        header_bytes = _msgpack_marker_header_bytes(marker)
        prefix = self._peek_bytes(header_bytes)
        if len(prefix) < header_bytes:
            return None
        return _msgpack_declared_data_bytes(marker, prefix)

    def read_marker(self) -> int:
        return self._read_exact(1)[0]

    def read_uint(self, size: int) -> int:
        return int.from_bytes(self._read_exact(size), "big", signed=False)

    def read_int(self, size: int) -> int:
        return int.from_bytes(self._read_exact(size), "big", signed=True)

    def skip(self, size: int) -> None:
        if size < 0:
            raise _MsgpackStreamFormatError("negative MessagePack skip length")
        if self.stream_size - self.offset < size:
            self.offset = self.stream_size
            self.source.seek(self.offset)
            raise OutOfData
        self.offset += size
        self.source.seek(self.offset)

    def read_map_header(self) -> int:
        marker = self.read_marker()
        if 0x80 <= marker <= 0x8F:
            return marker & 0x0F
        if marker == 0xDE:
            return self.read_uint(2)
        if marker == 0xDF:
            return self.read_uint(4)
        raise _MsgpackStreamFormatError(f"expected map header, found marker 0x{marker:02x}")

    def read_array_header(self) -> int:
        marker = self.read_marker()
        if 0x90 <= marker <= 0x9F:
            return marker & 0x0F
        if marker == 0xDC:
            return self.read_uint(2)
        if marker == 0xDD:
            return self.read_uint(4)
        raise _MsgpackStreamFormatError(f"expected array header, found marker 0x{marker:02x}")

    def iter_utf8_chunks(self, size: int) -> Iterable[str]:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        remaining = size
        while remaining > 0:
            chunk = self._read_exact(min(remaining, _STREAM_TEXT_CHUNK_BYTES))
            remaining -= len(chunk)
            decoded = decoder.decode(chunk, final=False)
            if decoded:
                yield decoded
        final_chunk = decoder.decode(b"", final=True)
        if final_chunk:
            yield final_chunk


@dataclass
class _StreamSequenceSummary:
    item_count: int
    evidence_values: list[Any] = field(default_factory=list)
    evidence_complete: bool = True
    negative_dimension: tuple[int, int] | None = None
    oversized_dimension: tuple[int, int] | None = None


@dataclass
class _FlaxStreamSummary:
    analysis_complete: bool = True
    top_level_type: str = "unknown"
    top_level_keys: list[Any] = field(default_factory=list)
    top_level_string_keys: set[str] = field(default_factory=set)
    top_level_key_count: int = 0
    has_nested_transformer_keys: bool = False
    orbax_format: bool = False
    architecture_hints: set[str] = field(default_factory=set)
    layer_keywords: set[str] = field(default_factory=set)
    parameter_count: int = 0
    layer_count: int = 0
    has_optimizer_state: bool = False
    tensor_count: int = 0
    large_tensor_count: int = 0
    compatible_tensor_count: int = 0
    compatible_tensor_samples: list[dict[str, Any]] = field(default_factory=list)
    embedding_tensor_count: int = 0
    embedding_evidence: list[str] = field(default_factory=list)
    suspicious_tensor_count: int = 0
    bounded_text_chars: int = 0


_MSGPACK_MARKER_HEADER_BYTES = {
    0xC4: 2,
    0xC5: 3,
    0xC6: 5,
    0xC7: 3,
    0xC8: 4,
    0xC9: 6,
    0xCA: 5,
    0xCB: 9,
    0xCC: 2,
    0xCD: 3,
    0xCE: 5,
    0xCF: 9,
    0xD0: 2,
    0xD1: 3,
    0xD2: 5,
    0xD3: 9,
    0xD4: 2,
    0xD5: 2,
    0xD6: 2,
    0xD7: 2,
    0xD8: 2,
    0xD9: 2,
    0xDA: 3,
    0xDB: 5,
    0xDC: 3,
    0xDD: 5,
    0xDE: 3,
    0xDF: 5,
}


def _msgpack_marker_header_bytes(marker: int) -> int:
    return _MSGPACK_MARKER_HEADER_BYTES.get(marker, 1)


def _msgpack_declared_data_bytes(marker: int, prefix: bytes) -> int | None:
    if 0xA0 <= marker <= 0xBF:
        return marker & 0x1F
    if marker in {0xC4, 0xC7, 0xD9} and len(prefix) >= 2:
        return prefix[1]
    if marker in {0xC5, 0xC8, 0xDA} and len(prefix) >= 3:
        return int.from_bytes(prefix[1:3], "big")
    if marker in {0xC6, 0xC9, 0xDB} and len(prefix) >= 5:
        return int.from_bytes(prefix[1:5], "big")
    return {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}.get(marker)


def _matching_jax_transforms(key_str: str, value_str: str) -> list[str]:
    value_lower = value_str.lower()
    return [transform for transform in _DANGEROUS_JAX_TRANSFORMS if transform in key_str or transform in value_lower]


def _contains_suspicious_getattr(value: str) -> bool:
    """Match the default unbounded getattr rule without catastrophic regex backtracking."""
    lowered = value.lower()
    search_offset = 0
    has_getattr_call = False
    while search_offset < len(value):
        getattr_index = lowered.find("getattr", search_offset)
        comma_index = value.find(",", search_offset)
        if getattr_index == -1 and comma_index == -1:
            return False
        if getattr_index != -1 and (comma_index == -1 or getattr_index < comma_index):
            open_index = getattr_index + len("getattr")
            while open_index < len(value) and value[open_index].isspace():
                open_index += 1
            if open_index < len(value) and value[open_index] == "(":
                has_getattr_call = True
            search_offset = getattr_index + len("getattr")
            continue

        if comma_index == -1:
            return False
        if has_getattr_call:
            quote_index = comma_index + 1
            while quote_index < len(value) and value[quote_index].isspace():
                quote_index += 1
            if quote_index < len(value) and value[quote_index] in {'"', "'"}:
                quote = value[quote_index]
                end_quote = value.find(quote, quote_index + 1)
                if end_quote != -1:
                    attribute = value[quote_index + 1 : end_quote]
                    if attribute.startswith("__") and attribute.endswith("__"):
                        return True
        search_offset = comma_index + 1
    return False


def _contains_getattr_call_anchor(value: str) -> bool:
    lowered = value.lower()
    search_offset = 0
    while search_offset < len(value):
        getattr_index = lowered.find("getattr", search_offset)
        if getattr_index == -1:
            return False
        open_index = getattr_index + len("getattr")
        while open_index < len(value) and value[open_index].isspace():
            open_index += 1
        if open_index < len(value) and value[open_index] == "(":
            return True
        search_offset = getattr_index + len("getattr")
    return False


def _contains_quoted_dunder_attribute_after_comma(value: str) -> bool:
    search_offset = 0
    while search_offset < len(value):
        comma_index = value.find(",", search_offset)
        if comma_index == -1:
            return False
        quote_index = comma_index + 1
        while quote_index < len(value) and value[quote_index].isspace():
            quote_index += 1
        if quote_index < len(value) and value[quote_index] in {'"', "'"}:
            quote = value[quote_index]
            end_quote = value.find(quote, quote_index + 1)
            if end_quote == -1:
                if value[quote_index + 1 :].startswith("__"):
                    return True
            else:
                attribute = value[quote_index + 1 : end_quote]
                if attribute.startswith("__") and attribute.endswith("__"):
                    return True
        search_offset = comma_index + 1
    return False


def _get_regex_parser() -> Any:
    return vars(re).get("_parser")


def _strip_stream_safe_whitespace_repeats(pattern: str) -> str:
    remaining: list[str] = []
    in_character_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "[":
            in_character_class = True
            remaining.append(char)
            index += 1
            continue
        if char == "]" and in_character_class:
            in_character_class = False
            remaining.append(char)
            index += 1
            continue
        if char != "\\" or index + 1 >= len(pattern):
            remaining.append(char)
            index += 1
            continue

        escaped_char = pattern[index + 1]
        if not in_character_class and escaped_char == "s":
            suffix = pattern[index + 2 :]
            if suffix.startswith(("*", "+")):
                index += 3
                continue
            if suffix.startswith(("{0,}", "{1,}")):
                index += 6
                continue

        remaining.extend((char, escaped_char))
        index += 2

    return "".join(remaining)


def _pattern_has_stream_unsafe_repeat(pattern: str) -> bool:
    """Return whether bounded streaming search cannot safely execute this regex."""
    remaining = _strip_stream_safe_whitespace_repeats(pattern)
    parser = _get_regex_parser()
    if parser is not None:
        try:
            parsed_pattern = parser.parse(pattern, re.IGNORECASE)
            parsed_remaining = parser.parse(remaining, re.IGNORECASE)
        except Exception:
            return True
        repeat_ops = {op for name in ("MAX_REPEAT", "MIN_REPEAT") if (op := getattr(parser, name, None)) is not None}
        branch_op = getattr(parser, "BRANCH", None)
        subpattern_op = getattr(parser, "SUBPATTERN", None)
        assertion_ops = {
            op for name in ("ASSERT", "ASSERT_NOT", "ATOMIC_GROUP") if (op := getattr(parser, name, None)) is not None
        }

        def has_ambiguous_repeat(subpattern: Any, *, inside_repeat: bool = False) -> bool:
            for op, argument in subpattern.data:
                if op in repeat_ops:
                    repeated = argument[-1]
                    if inside_repeat or has_ambiguous_repeat(repeated, inside_repeat=True):
                        return True
                    continue
                if branch_op is not None and op is branch_op:
                    if inside_repeat:
                        return True
                    if any(has_ambiguous_repeat(branch, inside_repeat=inside_repeat) for branch in argument[1]):
                        return True
                    continue
                if subpattern_op is not None and op is subpattern_op:
                    if has_ambiguous_repeat(argument[-1], inside_repeat=inside_repeat):
                        return True
                    continue
                if op in assertion_ops and has_ambiguous_repeat(argument[-1], inside_repeat=inside_repeat):
                    return True
            return False

        if has_ambiguous_repeat(parsed_pattern):
            return True
        _, max_width = parsed_remaining.getwidth()
        return max_width > _STREAM_TEXT_OVERLAP_CHARS

    escaped = False
    in_character_class = False
    for index, char in enumerate(remaining):
        if escaped:
            if char.isdigit() and char != "0":
                return True
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[":
            in_character_class = True
            continue
        if char == "]" and in_character_class:
            in_character_class = False
            continue
        if in_character_class:
            continue
        if char in {"*", "+"}:
            return True
        if char == "?" and (index == 0 or remaining[index - 1] != "("):
            return True
        if char == "{" and re.match(r"(?:\d+(?:,\d*)?|,\d+)\}", remaining[index + 1 :]):
            return True
        if remaining.startswith("(?P=", index):
            return True

    if re.search(r"\((?:[^()\\]|\\.)*[|](?:[^()\\]|\\.)*\)\s*(?:[*+?]|\{)", remaining):
        return True
    if re.search(r"\((?:[^()\\]|\\.)*(?:[*+?]|\{[^}]+\})(?:[^()\\]|\\.)*\)\s*(?:[*+?]|\{)", remaining):
        return True

    return len(remaining) > _STREAM_TEXT_OVERLAP_CHARS


def _pattern_literal_anchors(pattern: str) -> tuple[str, ...] | None:
    """Return literals required by a simple regex, or None when that cannot be proven."""
    if "(?" in pattern:
        return None
    literal_runs: list[str] = []
    current_run: list[str] = []
    escaped = False
    in_character_class = False
    index = 0

    def flush_run() -> None:
        if len(current_run) >= 2:
            literal_runs.append("".join(current_run).lower()[:64])
        current_run.clear()

    while index < len(pattern):
        char = pattern[index]
        if escaped:
            escaped = False
            flush_run()
            if char in {"x", "u", "U", "N"}:
                return None
            index += 1
            continue
        if char == "\\":
            escaped = True
            flush_run()
            index += 1
            continue
        if char == "[":
            in_character_class = True
            flush_run()
            index += 1
            continue
        if char == "]" and in_character_class:
            in_character_class = False
            index += 1
            continue
        if in_character_class:
            index += 1
            continue
        if char == "|":
            return None
        if char in {"?", "*"}:
            if current_run:
                current_run.pop()
            elif index > 0 and pattern[index - 1] == ")":
                return None
            flush_run()
            index += 1
            continue
        if char == "{":
            closing_index = pattern.find("}", index + 1)
            if closing_index == -1:
                return None
            repeat_range = pattern[index + 1 : closing_index]
            repeat_match = re.fullmatch(r"(\d+)(?:,\d*)?", repeat_range)
            if repeat_match is None:
                return None
            if int(repeat_match.group(1)) == 0:
                if current_run:
                    current_run.pop()
                elif index > 0 and pattern[index - 1] == ")":
                    return None
            flush_run()
            index = closing_index + 1
            continue
        if char.isascii() and (char.isalnum() or char == "_"):
            current_run.append(char)
        else:
            flush_run()
        index += 1
    flush_run()
    if not literal_runs:
        return None
    return tuple(dict.fromkeys(literal_runs))


def _is_text_like_short_binary(value: bytes | bytearray) -> bool:
    raw_value = bytes(value)
    if not raw_value:
        return False
    text_bytes = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in raw_value)
    return text_bytes * 100 >= len(raw_value) * _MIN_SHORT_BINARY_TEXT_PERCENT


def _stringify_evidence_fragment(value: Any) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _stringify_safe_evidence_fragment(value: Any) -> str:
    if HAS_MSGPACK and isinstance(value, msgpack.ExtType):
        try:
            decoded_data = value.data.decode("utf-8")
        except UnicodeDecodeError:
            return REDACTED_EVIDENCE_VALUE
        if not decoded_data.isprintable():
            return REDACTED_EVIDENCE_VALUE
        return f"ExtType(code={value.code}, data={decoded_data})"
    if isinstance(value, bytes | bytearray):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return REDACTED_EVIDENCE_VALUE
    return _stringify_evidence_fragment(value)


def _text_for_security_matching(value: Any) -> str | None:
    if HAS_MSGPACK and isinstance(value, msgpack.ExtType):
        value = value.data
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        with suppress(UnicodeDecodeError):
            return bytes(value).decode("utf-8")
    return None


def _join_evidence_path(path: str, key: Any) -> str:
    key_str = _stringify_safe_evidence_fragment(key)
    return f"{path}/{key_str}" if path else key_str


def _redact_evidence_fragment(value: Any, max_chars: int) -> str:
    text = _stringify_safe_evidence_fragment(value)
    if text == REDACTED_EVIDENCE_VALUE:
        return text
    if len(text) > _EVIDENCE_REDACTION_INPUT_CHARS:
        return REDACTED_EVIDENCE_VALUE
    redacted = redact_evidence_string(text, max_chars=max_chars)
    return redacted.replace("\r", " ").replace("\n", " ").replace("\t", " ")


def _redact_evidence_location(location: Any) -> str:
    return _redact_evidence_fragment(location, _EVIDENCE_LOCATION_CHARS)


def _redact_evidence_sample(value: Any) -> str:
    return _redact_evidence_fragment(value, _EVIDENCE_SAMPLE_CHARS)


def _redact_evidence_key(key: Any) -> Any:
    if key is None or isinstance(key, bool | int | float):
        return key
    return _redact_evidence_location(key)


class FlaxMsgpackScanner(BaseScanner):
    """Scanner for Flax/JAX msgpack checkpoint files with enhanced security threat detection."""

    name = "flax_msgpack"
    description = "Scans Flax/JAX msgpack checkpoints for security threats and integrity issues"
    RECURSION_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "flax_msgpack_recursion_limit_exceeded"
    STRUCTURE_BUDGET_INCONCLUSIVE_REASON: ClassVar[str] = "flax_msgpack_structure_budget_exceeded"
    DECODE_LIMIT_INCONCLUSIVE_REASON: ClassVar[str] = "flax_msgpack_decode_limit_exceeded"
    BINARY_PATTERN_INCONCLUSIVE_REASON: ClassVar[str] = "flax_msgpack_binary_pattern_coverage_incomplete"
    TRUNCATED_STREAM_INCONCLUSIVE_REASON: ClassVar[str] = "flax_msgpack_truncated_stream"
    DUPLICATE_KEY_TRACKING_INCONCLUSIVE_REASON: ClassVar[str] = "flax_msgpack_duplicate_key_tracking_incomplete"
    DEFAULT_MAX_STRUCTURE_NODES: ClassVar[int] = 200_000
    DEFAULT_MAX_BOUNDED_TEXT_CHARS: ClassVar[int] = 1_000_000
    DEFAULT_MAX_MSGPACK_DECODE_BYTES: ClassVar[int] = 512 * 1024 * 1024
    # Container traversal is streaming, so total file size is no longer a memory proxy.
    default_max_file_read_size: ClassVar[int] = 0
    # Enhanced file extension support for JAX/Flax ecosystem
    supported_extensions: ClassVar[list[str]] = [
        ".msgpack",
        ".flax",
        ".orbax",  # Orbax checkpoint format
        ".jax",  # Generic JAX model files
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_blob_bytes = self.config.get(
            "max_blob_bytes",
            500 * 1024 * 1024,  # Increased to 500MB for large language models
        )
        self.max_recursion_depth = self.config.get("max_recursion_depth", 100)
        self.max_items_per_container = self.config.get("max_items_per_container", 50000)  # Increased for large models
        self.max_msgpack_stream_objects = self.config.get("max_msgpack_stream_objects", 4096)
        default_decode_limit = (
            self.max_file_read_size if self.max_file_read_size > 0 else self.DEFAULT_MAX_MSGPACK_DECODE_BYTES
        )
        self.max_msgpack_decode_bytes = self._positive_int_config("max_msgpack_decode_bytes", default_decode_limit)
        self.max_structure_nodes = self._positive_int_config(
            "max_msgpack_structure_nodes",
            self.DEFAULT_MAX_STRUCTURE_NODES,
        )
        self.max_stream_key_length = self._positive_int_config(
            "max_msgpack_key_length",
            _DEFAULT_MAX_STREAM_KEY_LENGTH,
        )
        self.max_duplicate_key_tracking_bytes = self._positive_int_config(
            "max_msgpack_duplicate_key_tracking_bytes",
            _DEFAULT_MAX_DUPLICATE_KEY_TRACKING_BYTES,
        )
        self.max_bounded_text_chars = self._positive_int_config(
            "max_msgpack_bounded_text_chars",
            self.DEFAULT_MAX_BOUNDED_TEXT_CHARS,
        )

        # Enhanced suspicious patterns for JAX/Flax specific threats
        configured_patterns = self.config.get(
            "suspicious_patterns",
            [
                # Standard serialization attacks
                r"__reduce__",
                r"__getstate__",
                r"__setstate__",
                r"eval\s*\(",
                r"exec\s*\(",
                r"subprocess",
                r"os\.system",
                r"import\s+os",
                r"import\s+subprocess",
                r"__import__",
                r"compile\s*\(",
                r"pickle\.loads",
                r"marshal\.loads",
                r"base64\.decode",
                # JAX/Flax specific patterns
                r"jax\.eval_shape",
                r"jax\.numpy\.eval",
                r"flax\.core\.eval",
                r"haiku\.eval",
                # Code injection through JAX transforms
                r"jax\.jit\s*\(\s*eval",
                r"jax\.vmap\s*\(\s*exec",
                r"jax\.pmap\s*\(\s*eval",
                # Dynamic code execution
                _UNBOUNDED_GETATTR_PATTERN,
                # Dangerous imports in serialized functions
                r"from\s+subprocess\s+import",
                r"import\s+sys",
                r"from\s+os\s+import\s+system",
            ],
        )
        self.suspicious_patterns = list(dict.fromkeys(configured_patterns))
        self._compiled_suspicious_patterns = tuple(
            (pattern, re.compile(pattern, re.IGNORECASE), pattern.lower()) for pattern in self.suspicious_patterns
        )
        binary_stream_requires_full_scan = False
        binary_stream_pattern_matchers: list[tuple[bytes, str, re.Pattern[str], str]] = []
        for pattern, compiled_pattern, lowered_pattern in self._compiled_suspicious_patterns:
            anchors = _pattern_literal_anchors(pattern)
            if anchors is None:
                binary_stream_requires_full_scan = True
                continue
            anchor = max(anchors, key=len)
            if len(anchor) < 3:
                binary_stream_requires_full_scan = True
                continue
            binary_stream_pattern_matchers.append((anchor.encode("utf-8"), pattern, compiled_pattern, lowered_pattern))
        self._binary_stream_requires_full_scan = binary_stream_requires_full_scan
        self._binary_stream_pattern_matchers = tuple(binary_stream_pattern_matchers)
        self._binary_stream_transform_matchers = tuple(
            (transform.encode("utf-8"), transform) for transform in _DANGEROUS_JAX_TRANSFORMS
        )
        self._stream_unsafe_pattern_anchors = {
            pattern: _pattern_literal_anchors(pattern)
            for pattern in self.suspicious_patterns
            if _pattern_has_stream_unsafe_repeat(pattern)
        }
        self._stream_unsafe_anchor_matchers = {
            pattern: (
                None
                if anchors is None
                else tuple((anchor, re.compile(re.escape(anchor), re.IGNORECASE)) for anchor in anchors)
            )
            for pattern, anchors in self._stream_unsafe_pattern_anchors.items()
        }

        self.suspicious_keys = self.config.get(
            "suspicious_keys",
            {
                # Standard Python serialization threats
                "__class__",
                "__module__",
                "__reduce__",
                "__getstate__",
                "__setstate__",
                "__dict__",
                "__code__",
                "__globals__",
                "__builtins__",
                "__import__",
            },
        )
        self.function_metadata_keys = self.config.get(
            "function_metadata_keys",
            {
                "jax_fn",
                "compiled_fn",
                "eval_fn",
                "exec_fn",
                "restore_fn",
                "transform_fn",
                "__tree_flatten__",
                "__tree_unflatten__",
            },
        )
        self.dangerous_callable_names = self.config.get(
            "dangerous_callable_names",
            {
                "eval",
                "exec",
                "compile",
                "__import__",
                "os.system",
                "os.popen",
                "subprocess.run",
                "subprocess.call",
                "subprocess.popen",
            },
        )

        # JAX/Flax architecture patterns for better ML detection
        self.jax_patterns: dict[str, list[str]] = {
            "transformer_patterns": [
                "attention",
                "self_attention",
                "multi_head",
                "mha",
                "mqa",
                "gqa",
                "feed_forward",
                "ffn",
                "mlp",
                "dense",
                "linear",
                "layer_norm",
                "rms_norm",
                "batch_norm",
                "encoder",
                "decoder",
                "transformer_block",
            ],
            "cnn_patterns": [
                "conv1d",
                "conv2d",
                "conv3d",
                "convolution",
                "batch_norm",
                "group_norm",
                "layer_norm",
                "pool",
                "pooling",
                "max_pool",
                "avg_pool",
                "dropout",
                "activation",
            ],
            "embedding_patterns": [
                "embedding",
                "embed",
                "token_embedding",
                "position_embedding",
                "vocab_embedding",
                "word_embedding",
            ],
            "optimization_patterns": [
                "adam",
                "sgd",
                "rmsprop",
                "adagrad",
                "momentum",
                "learning_rate",
                "lr",
                "optimizer",
                "opt_state",
                "gradient",
                "grad",
            ],
        }

    @staticmethod
    def _positive_int_config_value(value: Any, default: int) -> int:
        if isinstance(value, bool):
            return default
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    def _positive_int_config(self, key: str, default: int) -> int:
        return self._positive_int_config_value(self.config.get(key, default), default)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()

        # Check file extension first
        if ext in cls.supported_extensions:
            return True

        # For files without clear extensions, check if they might be msgpack
        if HAS_MSGPACK and ext in [".ckpt", ""]:  # Some JAX checkpoints have no extension
            with suppress(Exception), open(path, "rb") as f:
                # Read first few bytes to check for msgpack format
                header = f.read(32)
                if len(header) > 0 and header[0:1] in [
                    b"\x80",
                    b"\x81",
                    b"\x82",
                    b"\x83",
                    b"\x84",
                    b"\x85",
                    b"\x86",
                    b"\x87",
                    b"\x88",
                    b"\x89",
                    b"\x8a",
                    b"\x8b",
                    b"\x8c",
                    b"\x8d",
                    b"\x8e",
                    b"\x8f",
                    b"\xde",
                    b"\xdf",  # Common msgpack format markers
                ]:
                    return True

        return is_flax_msgpack_checkpoint_file(path)

    def _extract_jax_metadata(
        self,
        obj: Any,
        result: ScanResult,
        *,
        ml_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Extract JAX/Flax specific metadata from the checkpoint."""
        if isinstance(obj, _FlaxStreamSummary):
            architecture_hints = sorted(obj.architecture_hints)
            model_type = "unknown"
            if any(pattern in architecture_hints for pattern in self.jax_patterns["transformer_patterns"]):
                model_type = "transformer"
            elif any(pattern in architecture_hints for pattern in self.jax_patterns["cnn_patterns"]):
                model_type = "cnn"
            elif any(pattern in architecture_hints for pattern in self.jax_patterns["embedding_patterns"]):
                model_type = "embedding"

            if ml_analysis is None:
                ml_analysis = self._analyze_ml_structure(obj, result)
            stream_metadata: dict[str, Any] = {
                "model_type": model_type,
                "architecture_hints": architecture_hints,
                "parameter_count": obj.parameter_count,
                "layer_count": obj.layer_count,
                "has_optimizer_state": obj.has_optimizer_state,
                "jax_version_hints": [],
                "orbax_format": obj.orbax_format,
                "confidence": ml_analysis["confidence"],
                "is_ml_model": ml_analysis["is_ml_model"],
                "ml_evidence": ml_analysis["evidence"],
                "tensor_count": ml_analysis["tensor_count"],
            }
            if obj.orbax_format:
                result.add_check(
                    name="Checkpoint Format Detection",
                    passed=True,
                    message="Orbax checkpoint format detected",
                    location="root",
                    details={"checkpoint_format": "orbax"},
                    rule_code=None,
                )
            result.metadata.update(
                {
                    "jax_metadata": stream_metadata,
                    "estimated_parameters": obj.parameter_count,
                    "model_architecture": model_type,
                    "layer_count": obj.layer_count,
                }
            )
            return stream_metadata

        metadata: dict[str, Any] = {
            "model_type": "unknown",
            "architecture_hints": [],
            "parameter_count": 0,
            "layer_count": 0,
            "has_optimizer_state": False,
            "jax_version_hints": [],
            "orbax_format": False,
        }

        if not isinstance(obj, dict):
            return metadata

        # Check for Orbax format indicators
        # Guard against non-string keys (msgpack allows int/bytes keys)
        if any(isinstance(key, str) and key.startswith("__orbax") for key in obj):
            metadata["orbax_format"] = True
            result.add_check(
                name="Checkpoint Format Detection",
                passed=True,
                message="Orbax checkpoint format detected",
                location="root",
                details={"checkpoint_format": "orbax"},
                rule_code=None,  # Passing check
            )

        # Analyze architecture patterns with a bounded text view.
        obj_str = self._bounded_structure_text(obj)
        for _pattern_type, patterns in self.jax_patterns.items():
            found_patterns = [p for p in patterns if p in obj_str]
            if found_patterns:
                metadata["architecture_hints"].extend(found_patterns)

        # Determine likely model type based on patterns
        if any(p in metadata["architecture_hints"] for p in self.jax_patterns["transformer_patterns"]):
            metadata["model_type"] = "transformer"
        elif any(p in metadata["architecture_hints"] for p in self.jax_patterns["cnn_patterns"]):
            metadata["model_type"] = "cnn"
        elif any(p in metadata["architecture_hints"] for p in self.jax_patterns["embedding_patterns"]):
            metadata["model_type"] = "embedding"

        # Check for optimizer state
        opt_indicators = ["opt_state", "optimizer", "adam", "sgd", "learning_rate"]
        if any(indicator in obj_str for indicator in opt_indicators):
            metadata["has_optimizer_state"] = True

        # Estimate parameter count and layer count
        def count_parameters(data: Any, path: str = "") -> int:
            count = 0
            if isinstance(data, dict):
                # Count layers
                layer_keys = [
                    k for k in data if any(layer_word in str(k).lower() for layer_word in ["layer", "block", "level"])
                ]
                if layer_keys:
                    metadata["layer_count"] += len(layer_keys)

                for key, value in data.items():
                    count += count_parameters(value, f"{path}/{key}" if path else key)
            elif isinstance(data, list | tuple):
                for i, value in enumerate(data):
                    count += count_parameters(value, f"{path}[{i}]")
            elif isinstance(data, bytes | bytearray):
                # Estimate parameter count from byte arrays (assuming float32)
                if len(data) >= 16 and len(data) % 4 == 0:
                    count += len(data) // 4
            return count

        metadata["parameter_count"] = count_parameters(obj)

        # Perform ML structure analysis to get confidence score
        if ml_analysis is None:
            ml_analysis = self._analyze_ml_structure(obj, result)

        # Add confidence and ML analysis results to metadata
        metadata["confidence"] = ml_analysis["confidence"]
        metadata["is_ml_model"] = ml_analysis["is_ml_model"]
        metadata["ml_evidence"] = ml_analysis["evidence"]
        metadata["tensor_count"] = ml_analysis["tensor_count"]

        # Add metadata to scan result
        result.metadata.update(
            {
                "jax_metadata": metadata,
                "estimated_parameters": metadata["parameter_count"],
                "model_architecture": metadata["model_type"],
                "layer_count": metadata["layer_count"],
            }
        )

        return metadata

    def _check_jax_transform(
        self,
        key: str,
        value: str,
        location: str,
        result: ScanResult,
    ) -> None:
        """Check one visible key/value pair for dangerous JAX transforms."""
        for transform in _matching_jax_transforms(key.lower(), value):
            self._add_jax_transform_check(transform, value, location, result)

    @staticmethod
    def _add_jax_transform_check(transform: str, context: str, location: str, result: ScanResult) -> None:
        safe_location = _redact_evidence_location(location)
        seen_findings = result._private_metadata.get(_JAX_TRANSFORM_DEDUP_METADATA_KEY)
        if not isinstance(seen_findings, set):
            seen_findings = set()
            result._private_metadata[_JAX_TRANSFORM_DEDUP_METADATA_KEY] = seen_findings
        finding_key = (safe_location, transform)
        if finding_key in seen_findings:
            return
        seen_findings.add(finding_key)
        result.add_check(
            name="JAX Transform Security Check",
            passed=False,
            message=f"Suspicious JAX transform detected: {transform}",
            severity=IssueSeverity.CRITICAL,
            location=safe_location,
            details={
                "transform": transform,
                "context": _redact_evidence_sample(context),
            },
            rule_code="S1105",
        )

    @staticmethod
    def _check_jax_array_metadata(value: dict[Any, Any], location: str, result: ScanResult) -> None:
        """Check one visible dictionary for suspicious JAX array metadata."""
        if "__jax_array__" in value:
            result.add_check(
                name="JAX Array Metadata Check",
                passed=False,
                message="Suspicious JAX array metadata detected",
                severity=IssueSeverity.WARNING,
                location=_redact_evidence_location(location),
                details={"suspicious_key": "__jax_array__"},
                rule_code="S905",
            )

        shape = value.get("shape")
        if not isinstance(shape, list | tuple):
            return
        shape_evidence = [_redact_evidence_key(dim) for dim in shape]
        if any(dim < 0 for dim in shape if isinstance(dim, int)):
            result.add_check(
                name="Tensor Shape Validation",
                passed=False,
                message="Invalid tensor shape with negative dimensions",
                severity=IssueSeverity.INFO,
                location=_redact_evidence_location(location),
                details={"shape": shape_evidence},
                rule_code="S902",
            )
        elif any(dim > 10**9 for dim in shape if isinstance(dim, int)):
            result.add_check(
                name="Tensor Dimension Check",
                passed=False,
                message="Suspiciously large tensor dimensions",
                severity=IssueSeverity.WARNING,
                location=_redact_evidence_location(location),
                details={"shape": shape_evidence, "max_safe_dimension": 10**9},
                rule_code="S804",
            )

    @classmethod
    def _check_stream_shape_metadata(
        cls,
        shape: _StreamSequenceSummary,
        location: str,
        result: ScanResult,
    ) -> None:
        """Preserve shape validation without retaining arbitrarily large arrays."""
        if shape.evidence_complete and len(shape.evidence_values) == shape.item_count:
            cls._check_jax_array_metadata({"shape": shape.evidence_values}, location, result)
            return

        shape_evidence = [_redact_evidence_key(dim) for dim in shape.evidence_values]
        common_details = {
            "shape": shape_evidence,
            "shape_item_count": shape.item_count,
            "shape_evidence_truncated": True,
        }
        if shape.negative_dimension is not None:
            dimension_index, dimension = shape.negative_dimension
            result.add_check(
                name="Tensor Shape Validation",
                passed=False,
                message="Invalid tensor shape with negative dimensions",
                severity=IssueSeverity.INFO,
                location=_redact_evidence_location(location),
                details={
                    **common_details,
                    "dimension_index": dimension_index,
                    "dimension": dimension,
                },
                rule_code="S902",
            )
        elif shape.oversized_dimension is not None:
            dimension_index, dimension = shape.oversized_dimension
            result.add_check(
                name="Tensor Dimension Check",
                passed=False,
                message="Suspiciously large tensor dimensions",
                severity=IssueSeverity.WARNING,
                location=_redact_evidence_location(location),
                details={
                    **common_details,
                    "dimension_index": dimension_index,
                    "dimension": dimension,
                    "max_safe_dimension": 10**9,
                },
                rule_code="S804",
            )

    def _check_suspicious_strings(
        self,
        value: str,
        location: str,
        result: ScanResult,
        *,
        evidence_value: Any | None = None,
    ) -> None:
        """Check string values for suspicious patterns that might indicate code injection."""
        self._analyze_streamed_text_chunks(
            (value,),
            location,
            result,
            full_length=len(value),
            finding_location=location,
            coverage_details={"text_length": len(value)},
            check_jax_transform=False,
            evidence_sample=evidence_value,
        )

    @staticmethod
    def _suspicious_pattern_rule_code(lowered_pattern: str) -> str:
        if "eval" in lowered_pattern:
            return "S104"
        if "compile" in lowered_pattern:
            return "S105"
        if "import\\s+os" in lowered_pattern or "os\\.system" in lowered_pattern:
            return "S101"
        return "S999"

    def _add_suspicious_string_check(
        self,
        pattern: str,
        lowered_pattern: str,
        sample_value: Any,
        full_length: int,
        location: str,
        result: ScanResult,
    ) -> None:
        result.add_check(
            name="Code Pattern Security Check",
            passed=False,
            message=f"Suspicious code pattern detected: {pattern}",
            severity=IssueSeverity.CRITICAL,
            location=_redact_evidence_location(location),
            details={
                "pattern": pattern,
                "sample": _redact_evidence_sample(sample_value),
                "full_length": full_length,
            },
            rule_code=self._suspicious_pattern_rule_code(lowered_pattern),
        )

    def _check_suspicious_keys(
        self,
        key: str,
        value: Any,
        location: str,
        result: ScanResult,
    ) -> None:
        """Check dictionary keys for suspicious names that might indicate serialization attacks."""
        if key in self.suspicious_keys:
            # Determine appropriate rule code based on key
            rule_code = "S201" if key.lower() == "__reduce__" else "S999"
            safe_key = _redact_evidence_location(key)

            result.add_check(
                name="Object Attribute Security Check",
                passed=False,
                message=f"Suspicious object attribute detected: {safe_key}",
                severity=IssueSeverity.CRITICAL,
                location=_redact_evidence_location(location),
                details={"suspicious_key": safe_key},
                rule_code=rule_code,
            )
            return

        if key in self.function_metadata_keys and self._value_names_dangerous_callable(value):
            result.add_check(
                name="Object Attribute Security Check",
                passed=False,
                message=f"Suspicious object attribute value detected: {key}",
                severity=IssueSeverity.CRITICAL,
                location=_redact_evidence_location(location),
                details={
                    "suspicious_key": key,
                    "value_sample": _redact_evidence_sample(value),
                },
                rule_code="S999",
            )

    def _value_names_dangerous_callable(self, value: Any) -> bool:
        """Return whether a metadata value directly names a dangerous callable."""
        value_text = _text_for_security_matching(value)
        if value_text is None:
            return False
        normalized = value_text.strip().lower()
        return normalized in self.dangerous_callable_names

    def _add_incomplete_check(
        self,
        result: ScanResult,
        *,
        reason: str,
        name: str,
        message: str,
        location: str,
        details: dict[str, Any],
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        check_details = {
            **details,
            "analysis_incomplete": True,
            "scan_outcome_reason": reason,
        }
        result.add_check(
            name=name,
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=_redact_evidence_location(location),
            details=check_details,
            rule_code="S902",
        )

    def _add_structure_budget_check(
        self,
        result: ScanResult,
        *,
        location: str,
        budget: str,
        observed: int,
        maximum: int,
    ) -> None:
        self._add_incomplete_check(
            result,
            reason=self.STRUCTURE_BUDGET_INCONCLUSIVE_REASON,
            name="Flax MessagePack Structure Budget",
            message=f"Flax MessagePack structure analysis exceeded the {budget} budget",
            location=location,
            details={
                "budget": budget,
                "observed": observed,
                "max_allowed": maximum,
            },
        )

    def _check_preanalysis_structure_budget(
        self,
        obj: Any,
        result: ScanResult,
        *,
        location: str,
        max_nodes: int | None = None,
    ) -> bool:
        """Bound helper-analysis traversal before running ML/JAX metadata prechecks."""
        stack: list[tuple[Any, str, int]] = [(obj, location, 0)]
        visited_nodes = 0
        node_limit = self.max_structure_nodes if max_nodes is None else max_nodes

        while stack:
            value, value_location, depth = stack.pop()
            visited_nodes += 1
            if visited_nodes > node_limit:
                self._add_structure_budget_check(
                    result,
                    location=value_location,
                    budget="node_count",
                    observed=visited_nodes,
                    maximum=node_limit,
                )
                return False
            if depth > self.max_recursion_depth:
                self._add_incomplete_check(
                    result,
                    reason=self.RECURSION_LIMIT_INCONCLUSIVE_REASON,
                    name="Flax MessagePack Preanalysis Depth Limit",
                    message=f"Maximum preanalysis recursion depth exceeded: {depth}",
                    location=value_location,
                    details={
                        "depth": depth,
                        "max_allowed": self.max_recursion_depth,
                    },
                )
                return False

            if isinstance(value, dict):
                if len(value) > self.max_items_per_container:
                    self._add_structure_budget_check(
                        result,
                        location=value_location,
                        budget="dict_items",
                        observed=len(value),
                        maximum=self.max_items_per_container,
                    )
                    return False
                for key, nested_value in value.items():
                    stack.append((nested_value, _join_evidence_path(value_location, key), depth + 1))
            elif isinstance(value, list | tuple):
                if len(value) > self.max_items_per_container:
                    self._add_structure_budget_check(
                        result,
                        location=value_location,
                        budget="sequence_items",
                        observed=len(value),
                        maximum=self.max_items_per_container,
                    )
                    return False
                for index, nested_value in enumerate(value):
                    stack.append((nested_value, f"{value_location}[{index}]", depth + 1))

        return True

    def _bounded_structure_text(self, obj: Any) -> str:
        """Return a bounded lowercase text view for architecture heuristics."""
        fragments: list[str] = []
        total_chars = 0
        stack: list[tuple[Any, int]] = [(obj, 0)]
        visited_nodes = 0

        while stack and total_chars < self.max_bounded_text_chars:
            value, depth = stack.pop()
            visited_nodes += 1
            if visited_nodes > self.max_structure_nodes or depth > self.max_recursion_depth:
                break

            if isinstance(value, dict):
                for key, nested_value in value.items():
                    key_text = str(key)
                    remaining = self.max_bounded_text_chars - total_chars
                    if remaining <= 0:
                        break
                    fragments.append(key_text[:remaining])
                    total_chars += min(len(key_text), remaining)
                    stack.append((nested_value, depth + 1))
            elif isinstance(value, list | tuple):
                for nested_value in value:
                    stack.append((nested_value, depth + 1))
            elif isinstance(value, str):
                remaining = self.max_bounded_text_chars - total_chars
                fragments.append(value[:remaining])
                total_chars += min(len(value), remaining)

        return " ".join(fragments).lower()

    def _new_content_traversal_state(self, *, max_nodes: int | None = None) -> dict[str, Any]:
        return {
            "nodes": 0,
            "max_nodes": self.max_structure_nodes if max_nodes is None else max_nodes,
            "node_budget_reported": False,
        }

    def _analyze_content(
        self,
        value: Any,
        location: str,
        result: ScanResult,
        depth: int = 0,
        traversal_state: dict[str, Any] | None = None,
        check_string_jax_transform: bool = True,
    ) -> None:
        """Recursively analyze msgpack content for security threats and anomalies."""
        if traversal_state is None:
            traversal_state = self._new_content_traversal_state()
        traversal_state["nodes"] += 1
        if traversal_state["nodes"] > traversal_state["max_nodes"]:
            if not traversal_state["node_budget_reported"]:
                self._add_structure_budget_check(
                    result,
                    location=location,
                    budget="node_count",
                    observed=traversal_state["nodes"],
                    maximum=traversal_state["max_nodes"],
                )
                traversal_state["node_budget_reported"] = True
            return

        if depth > self.max_recursion_depth:
            mark_inconclusive_scan_result(result, self.RECURSION_LIMIT_INCONCLUSIVE_REASON)
            result.add_check(
                name="Recursion Depth Check",
                passed=False,
                message=f"Maximum recursion depth exceeded: {depth}",
                severity=IssueSeverity.INFO,
                location=_redact_evidence_location(location),
                details={
                    "depth": depth,
                    "max_allowed": self.max_recursion_depth,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self.RECURSION_LIMIT_INCONCLUSIVE_REASON,
                },
                rule_code="S902",
            )
            return

        if isinstance(value, bytes | bytearray):
            size = len(value)
            if size > self.max_blob_bytes:
                result.add_check(
                    name="Binary Blob Size Check",
                    passed=False,
                    message=f"Suspiciously large binary blob: {size:,} bytes",
                    severity=IssueSeverity.INFO,
                    location=_redact_evidence_location(location),
                    details={"size": size, "max_allowed": self.max_blob_bytes},
                    rule_code="S902",
                )

            # Try to decode as text to check for embedded code
            try:
                decoded = value.decode("utf-8", errors="ignore")
                if check_string_jax_transform:
                    self._check_jax_transform("", decoded, location, result)
                if len(decoded) > 50 or _is_text_like_short_binary(value):
                    self._check_suspicious_strings(
                        decoded,
                        f"{location}[decoded_binary]",
                        result,
                    )
            except Exception:  # pragma: no cover - encoding edge cases
                pass

        elif isinstance(value, str):
            if check_string_jax_transform:
                self._check_jax_transform("", value, location, result)

            # Check for suspicious string patterns
            self._check_suspicious_strings(value, location, result)

            # Check for very long strings that might be attacks
            if len(value) > 100000:  # 100KB string
                result.add_check(
                    name="String Length Check",
                    passed=False,
                    message=f"Extremely long string found: {len(value):,} characters",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=_redact_evidence_location(location),
                    details={"length": len(value), "threshold": 100000},
                )

        elif isinstance(value, dict):
            self._check_jax_array_metadata(value, location, result)

            if len(value) > self.max_items_per_container:
                self._add_structure_budget_check(
                    result,
                    location=location,
                    budget="dict_items",
                    observed=len(value),
                    maximum=self.max_items_per_container,
                )
                result.add_check(
                    name="Dictionary Size Check",
                    passed=False,
                    message=f"Dictionary with excessive items: {len(value):,}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=_redact_evidence_location(location),
                    details={
                        "item_count": len(value),
                        "max_allowed": self.max_items_per_container,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self.STRUCTURE_BUDGET_INCONCLUSIVE_REASON,
                    },
                )

            for index, (k, v) in enumerate(value.items()):
                if index >= self.max_items_per_container:
                    break
                key_text = _text_for_security_matching(k)
                key_str = key_text if key_text is not None else _stringify_evidence_fragment(k)
                safe_key_str = _stringify_safe_evidence_fragment(k)
                key_location = _join_evidence_path(location, k)
                self._check_jax_transform(
                    key_str,
                    v if isinstance(v, str) else "",
                    key_location,
                    result,
                )
                self._check_suspicious_keys(key_str, v, key_location, result)

                # Check if key itself contains suspicious patterns
                self._check_suspicious_strings(
                    key_str,
                    f"{location}[key:{safe_key_str}]",
                    result,
                    evidence_value=safe_key_str,
                )

                self._analyze_content(
                    v,
                    key_location,
                    result,
                    depth + 1,
                    traversal_state,
                    check_string_jax_transform=not isinstance(v, str),
                )

        elif isinstance(value, list | tuple):
            if len(value) > self.max_items_per_container:
                self._add_structure_budget_check(
                    result,
                    location=location,
                    budget="sequence_items",
                    observed=len(value),
                    maximum=self.max_items_per_container,
                )
                result.add_check(
                    name="Array Size Check",
                    passed=False,
                    message=f"Array with excessive items: {len(value):,}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=_redact_evidence_location(location),
                    details={
                        "item_count": len(value),
                        "max_allowed": self.max_items_per_container,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self.STRUCTURE_BUDGET_INCONCLUSIVE_REASON,
                    },
                )

            for i, v in enumerate(value):
                if i >= self.max_items_per_container:
                    break
                self._analyze_content(v, f"{location}[{i}]", result, depth + 1, traversal_state)

        elif isinstance(value, int | float):
            # Check for suspicious numerical values that might indicate attacks
            if isinstance(value, int) and abs(value) > 2**63:
                result.add_check(
                    name="Integer Value Range Check",
                    passed=False,
                    message=f"Extremely large integer value: {value}",
                    severity=IssueSeverity.INFO,
                    location=_redact_evidence_location(location),
                    details={"value": value},
                    rule_code="S902",
                )

    def _analyze_ml_structure(self, obj: Any, result: ScanResult) -> dict[str, Any]:
        """
        Analyze the mathematical and structural properties to determine if this looks like a legitimate ML model.
        Returns analysis results with confidence scores based on actual model characteristics, not naming.
        """
        analysis: dict[str, Any] = {
            "is_ml_model": False,
            "confidence": 0.0,
            "evidence": [],
            "tensor_count": 0,
            "weight_matrices": [],
            "suspicious_patterns": [],
        }

        if isinstance(obj, _FlaxStreamSummary):
            analysis["tensor_count"] = obj.tensor_count
            if obj.tensor_count == 0:
                analysis["suspicious_patterns"].append("No numerical data found - not a typical ML model")
                return analysis
            if obj.large_tensor_count == 0:
                analysis["suspicious_patterns"].append("No substantial weight matrices found")
                return analysis

            if obj.compatible_tensor_count:
                analysis["evidence"].append(
                    f"Found {obj.compatible_tensor_count} tensors with ML-compatible dimensions"
                )
                analysis["weight_matrices"] = obj.compatible_tensor_samples
                analysis["confidence"] += 0.4

            layer_evidence = len(obj.layer_keywords)
            if layer_evidence >= 2:
                analysis["evidence"].append(f"Found hierarchical layer structure ({layer_evidence} layer indicators)")
                analysis["confidence"] += 0.5

            analysis["evidence"].extend(obj.embedding_evidence)
            if obj.embedding_tensor_count:
                analysis["confidence"] += 0.3

            if obj.suspicious_tensor_count > obj.tensor_count * 0.5:
                analysis["confidence"] *= 0.5

            if analysis["confidence"] >= 0.7:
                analysis["is_ml_model"] = True
                analysis["evidence"].append(
                    "High confidence this is a legitimate ML model based on structural analysis"
                )
            elif analysis["confidence"] > 0.4:
                analysis["evidence"].append("Moderate confidence this could be an ML model")
            else:
                analysis["suspicious_patterns"].append("Low confidence in ML model structure - may be malicious data")
            return analysis

        if not isinstance(obj, dict):
            return analysis

        # Recursively collect all numerical arrays that could be tensors
        def collect_tensors(data: Any, path: str = "") -> list[dict[str, Any]]:
            tensors: list[dict[str, Any]] = []
            if isinstance(data, dict):
                for key, value in data.items():
                    tensors.extend(collect_tensors(value, _join_evidence_path(path, key)))
            elif isinstance(data, list | tuple):
                for i, value in enumerate(data):
                    tensors.extend(collect_tensors(value, f"{path}[{i}]"))
            elif isinstance(data, bytes | bytearray) and len(data) >= 16 and (len(data) % 4 == 0 or len(data) % 8 == 0):
                # Check if binary data could be a serialized tensor
                tensors.append(
                    {
                        "path": _redact_evidence_location(path),
                        "size": len(data),
                        "type": "binary_blob",
                        "potential_elements": len(data) // 4,  # Assume float32
                    }
                )
            return tensors

        tensors = collect_tensors(obj)
        analysis["tensor_count"] = len(tensors)

        if len(tensors) == 0:
            analysis["suspicious_patterns"].append("No numerical data found - not a typical ML model")
            return analysis

        # Analyze tensor size patterns
        large_tensors = [t for t in tensors if t["size"] > 1024]  # > 1KB
        if not large_tensors:
            analysis["suspicious_patterns"].append("No substantial weight matrices found")
            return analysis

        # Check for common ML model patterns in tensor sizes
        common_ml_sizes: list[dict[str, Any]] = []
        for tensor in large_tensors:
            size = tensor["size"]
            # Check if size could represent common ML architectures
            elements = size // 4  # Assume float32

            # Look for typical ML matrix dimensions (powers of 2, common vocab sizes, etc.)
            potential_shapes: list[tuple[int, int]] = []
            for dim1 in [64, 128, 256, 512, 768, 1024, 1536, 2048, 4096, 8192]:
                if elements % dim1 == 0:
                    dim2 = elements // dim1
                    if 1 <= dim2 <= 100000:  # Reasonable range for ML dimensions
                        potential_shapes.append((dim1, dim2))

            if potential_shapes:
                common_ml_sizes.append(
                    {
                        "tensor": tensor,
                        "potential_shapes": potential_shapes[:5],  # Limit output
                    }
                )

        if common_ml_sizes:
            analysis["evidence"].append(f"Found {len(common_ml_sizes)} tensors with ML-compatible dimensions")
            analysis["weight_matrices"] = common_ml_sizes
            analysis["confidence"] += 0.4

        # Check for hierarchical structure (multiple layers)
        layer_evidence = 0
        layer_keywords = ["layer", "block", "attention", "ffn", "mlp", "linear", "conv"]
        obj_text_lower = self._bounded_structure_text(obj)

        for keyword in layer_keywords:
            if keyword in obj_text_lower:
                layer_evidence += 1

        if layer_evidence >= 2:
            analysis["evidence"].append(f"Found hierarchical layer structure ({layer_evidence} layer indicators)")
            analysis["confidence"] += 0.5

        # Check for embedding-like structures (large matrices typical of word embeddings)
        embedding_evidence = 0
        for tensor in large_tensors:
            size = tensor["size"]
            elements = size // 4

            # Common embedding sizes: vocab_size x embedding_dim
            # Common vocab sizes: 30522 (BERT), 50257 (GPT-2), 32000 (T5)
            common_vocab_sizes = [30522, 50257, 32000, 28996, 51200]
            common_embed_dims = [128, 256, 384, 512, 768, 1024, 1536, 2048]

            for vocab_size in common_vocab_sizes:
                for embed_dim in common_embed_dims:
                    if abs(elements - (vocab_size * embed_dim)) < (vocab_size * embed_dim * 0.1):  # 10% tolerance
                        embedding_evidence += 1
                        analysis["evidence"].append(f"Found embedding-like matrix: ~{vocab_size}x{embed_dim}")
                        break

        if embedding_evidence > 0:
            analysis["confidence"] += 0.3

        # Penalize suspicious patterns
        suspicious_data = 0
        for tensor in tensors:
            # Check for non-ML-like data patterns
            if tensor["size"] < 100:  # Very small tensors are suspicious for model weights
                suspicious_data += 1
            elif tensor["size"] > 500 * 1024 * 1024:  # Extremely large (>500MB) single tensors
                analysis["suspicious_patterns"].append(
                    f"Extremely large single tensor: {tensor['size'] // 1024 // 1024}MB"
                )
                suspicious_data += 1

        if suspicious_data > len(tensors) * 0.5:  # More than 50% suspicious
            analysis["confidence"] *= 0.5

        # Final confidence calculation
        if analysis["confidence"] >= 0.7:
            analysis["is_ml_model"] = True
            analysis["evidence"].append("High confidence this is a legitimate ML model based on structural analysis")
        elif analysis["confidence"] > 0.4:
            analysis["evidence"].append("Moderate confidence this could be an ML model")
        else:
            analysis["suspicious_patterns"].append("Low confidence in ML model structure - may be malicious data")

        return analysis

    def _validate_flax_structure(
        self,
        obj: Any,
        result: ScanResult,
        *,
        ml_analysis: dict[str, Any] | None = None,
    ) -> None:
        """Validate that the msgpack structure looks like a legitimate Flax checkpoint using structural analysis."""
        is_stream_summary = isinstance(obj, _FlaxStreamSummary)
        top_level_type = obj.top_level_type if is_stream_summary else type(obj).__name__
        if (is_stream_summary and obj.top_level_type != "dict") or (
            not is_stream_summary and not isinstance(obj, dict)
        ):
            result.add_check(
                name="Flax Structure Validation",
                passed=False,
                message=f"Unexpected top-level type: {top_level_type} (expected dict)",
                rule_code="S903",
                severity=IssueSeverity.WARNING,
                location="root",
                details={"actual_type": top_level_type, "expected_type": "dict"},
            )
            return

        # Check for standard Flax checkpoint patterns first
        expected_keys = {"params", "state", "opt_state", "model_state", "step", "epoch"}
        found_keys = obj.top_level_string_keys if is_stream_summary else set(obj.keys())
        displayed_found_keys = (
            obj.top_level_keys if is_stream_summary else [_redact_evidence_key(key) for key in list(found_keys)[:20]]
        )

        # Also check for common transformer model patterns (BERT, GPT, T5, etc.)
        transformer_keys = {"embeddings", "encoder", "decoder", "pooler", "lm_head", "transformer", "model"}
        # Common HuggingFace model name keys that wrap transformer substructure
        model_name_keys = {
            "bert",
            "roberta",
            "distilbert",
            "albert",
            "electra",
            "xlm",
            "gpt2",
            "gpt_neo",
            "gpt_neox",
            "gptj",
            "opt",
            "llama",
            "t5",
            "bart",
            "pegasus",
            "mbart",
            "blenderbot",
            "vit",
            "clip",
            "whisper",
            "wav2vec2",
            "flax_model",
            "classifier",
            "qa_outputs",
            "lm_head",
            "score",
        }
        has_transformer_keys = any(key in found_keys for key in transformer_keys)
        if is_stream_summary:
            has_transformer_keys = has_transformer_keys or obj.has_nested_transformer_keys

        # Check if any top-level key contains transformer sub-keys (nested model structure)
        if not has_transformer_keys and not is_stream_summary:
            for key in found_keys:
                value = obj.get(key)
                if isinstance(value, dict):
                    sub_keys = set(value.keys())
                    if sub_keys & transformer_keys:
                        has_transformer_keys = True
                        break
                    # Also check if the top-level key is a known model name.
                    # Only check string keys — msgpack allows int/bytes keys which
                    # are never valid model names and would cause crashes on .lower().
                    if not isinstance(key, str):
                        continue
                    key_lower = key.lower()
                    # Use exact match only to avoid false positives from substring
                    # matching (e.g. "opt" matching "optional", "t5" matching "t500").
                    if key_lower in model_name_keys:
                        has_transformer_keys = True
                        break

        has_standard_flax_keys = any(key in found_keys for key in expected_keys)

        if has_standard_flax_keys:
            # This looks like a standard Flax checkpoint
            result.add_check(
                name="Flax Checkpoint Format Detection",
                passed=True,
                message="Standard Flax checkpoint format detected",
                location="root",
                details={
                    "found_standard_keys": [k for k in expected_keys if k in found_keys],
                    "model_type": "standard_flax",
                },
                rule_code=None,  # Passing check
            )
            return

        # Check if this is a transformer model (BERT, GPT, T5, etc.)
        if has_transformer_keys:
            # This looks like a transformer model checkpoint
            result.add_check(
                name="Model Format Detection",
                passed=True,
                message="Transformer model format detected (BERT/GPT/T5 style)",
                location="root",
                details={
                    "found_transformer_keys": [k for k in transformer_keys if k in found_keys],
                    "model_type": "transformer_model",
                    "all_keys": displayed_found_keys,
                },
                rule_code=None,  # Passing check
            )
            return

        # If no standard keys, perform deep structural analysis
        if ml_analysis is None:
            ml_analysis = self._analyze_ml_structure(obj, result)

        if ml_analysis["is_ml_model"]:
            # High confidence legitimate ML model based on structural analysis
            result.add_check(
                name="ML Model Detection",
                passed=True,
                message=f"Converted ML model detected (confidence: {ml_analysis['confidence']:.2f})",
                location="root",
                details={
                    "analysis": ml_analysis,
                    "model_type": "converted_ml_model",
                    "structural_evidence": ml_analysis["evidence"],
                },
                rule_code=None,  # Passing check
            )
        elif ml_analysis["confidence"] > 0.4:
            # Moderate confidence - flag for review but don't alarm
            result.add_check(
                name="ML Model Detection",
                passed=True,
                message=f"Possible ML model with moderate confidence ({ml_analysis['confidence']:.2f})",
                location="root",
                details={
                    "analysis": ml_analysis,
                    "model_type": "possible_ml_model",
                    "recommendation": "Manual review recommended",
                },
                rule_code=None,  # Passing check
            )
        else:
            # Low confidence - this is suspicious
            result.add_check(
                name="ML Model Pattern Validation",
                passed=False,
                message="Suspicious data structure - does not match known ML model patterns",
                severity=IssueSeverity.INFO,
                location="root",
                details={
                    "analysis": ml_analysis,
                    "found_keys": displayed_found_keys,
                    "expected_any_of": list(expected_keys),
                    "model_type": "suspicious",
                    "suspicious_patterns": ml_analysis["suspicious_patterns"],
                },
                rule_code="S903",
            )

        # Always check for truly suspicious top-level keys regardless of ML confidence
        dangerous_keys = {
            "__class__",
            "__module__",
            "__reduce__",
            "__getstate__",
            "__setstate__",
            "__dict__",
            "__code__",
            "__globals__",
            "__builtins__",
            "__import__",
        }

        suspicious_top_level = {
            key_text
            for key in found_keys
            if (key_text := _text_for_security_matching(key)) is not None and key_text in dangerous_keys
        }
        if suspicious_top_level:
            result.add_check(
                name="Top-Level Key Security Check",
                passed=False,
                message=f"Dangerous top-level keys detected: {sorted(suspicious_top_level)}",
                severity=IssueSeverity.CRITICAL,
                location="root",
                details={"dangerous_keys": sorted(suspicious_top_level)},
                rule_code="S902",
            )

    def _msgpack_unpacker_kwargs(self) -> dict[str, Any]:
        return {
            "raw": False,
            "strict_map_key": False,
            "max_buffer_size": self.max_msgpack_decode_bytes,
            "max_str_len": self.max_msgpack_decode_bytes,
            "max_bin_len": self.max_msgpack_decode_bytes,
            "max_array_len": self.max_items_per_container,
            "max_map_len": self.max_items_per_container,
        }

    def _msgpack_stream_read_size(self) -> int:
        """Leave decoder-buffer headroom for an object split across filesystem reads."""
        return min(self.chunk_size, max(self.max_msgpack_decode_bytes // 2, 1))

    def _msgpack_event_unpacker_kwargs(self) -> dict[str, Any]:
        """Allow container headers through; the event walker enforces their budgets."""
        kwargs = self._msgpack_unpacker_kwargs()
        kwargs["max_array_len"] = 2**32 - 1
        kwargs["max_map_len"] = 2**32 - 1
        return kwargs

    def _record_stream_text(self, value: str, summary: _FlaxStreamSummary) -> None:
        remaining = self.max_bounded_text_chars - summary.bounded_text_chars
        if remaining <= 0:
            return
        visible = value[:remaining].lower()
        summary.bounded_text_chars += len(visible)

        for patterns in self.jax_patterns.values():
            summary.architecture_hints.update(pattern for pattern in patterns if pattern in visible)
        summary.layer_keywords.update(
            keyword for keyword in ("layer", "block", "attention", "ffn", "mlp", "linear", "conv") if keyword in visible
        )
        if any(indicator in visible for indicator in ("opt_state", "optimizer", "adam", "sgd", "learning_rate")):
            summary.has_optimizer_state = True

    @staticmethod
    def _is_tensor_like_binary_size(size: int) -> bool:
        return size >= 16 and (size % 4 == 0 or size % 8 == 0)

    def _add_binary_blob_size_check(self, result: ScanResult, location: str, size: int) -> None:
        if size <= self.max_blob_bytes:
            return
        result.add_check(
            name="Binary Blob Size Check",
            passed=False,
            message=f"Suspiciously large binary blob: {size:,} bytes",
            severity=IssueSeverity.INFO,
            location=_redact_evidence_location(location),
            details={"size": size, "max_allowed": self.max_blob_bytes},
            rule_code="S902",
        )

    def _add_binary_pattern_incomplete_check(
        self,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        *,
        location: str,
        binary_size: int,
        sampled_bytes: int,
        message: str,
    ) -> None:
        summary.analysis_complete = False
        self._add_incomplete_check(
            result,
            reason=self.BINARY_PATTERN_INCONCLUSIVE_REASON,
            name="Flax MessagePack Binary Pattern Coverage",
            message=message,
            location=location,
            details={
                "binary_size": binary_size,
                "sampled_bytes": sampled_bytes,
                "stream_text_chunk_bytes": _STREAM_TEXT_CHUNK_BYTES,
            },
        )

    def _record_stream_tensor_size(self, size: int, location: str, summary: _FlaxStreamSummary) -> None:
        if size >= 16 and size % 4 == 0:
            summary.parameter_count += size // 4
        if not self._is_tensor_like_binary_size(size):
            return

        summary.tensor_count += 1
        if size < 100 or size > 500 * 1024 * 1024:
            summary.suspicious_tensor_count += 1
        if size <= 1024:
            return

        summary.large_tensor_count += 1
        elements = size // 4
        potential_shapes: list[tuple[int, int]] = []
        for dim1 in (64, 128, 256, 512, 768, 1024, 1536, 2048, 4096, 8192):
            if elements % dim1 == 0:
                dim2 = elements // dim1
                if 1 <= dim2 <= 100000:
                    potential_shapes.append((dim1, dim2))
        if potential_shapes:
            summary.compatible_tensor_count += 1
            if len(summary.compatible_tensor_samples) < _MAX_STREAM_TENSOR_SAMPLES:
                summary.compatible_tensor_samples.append(
                    {
                        "tensor": {
                            "path": _redact_evidence_location(location),
                            "size": size,
                            "type": "binary_blob",
                            "potential_elements": elements,
                        },
                        "potential_shapes": potential_shapes[:5],
                    }
                )

        for vocab_size in (30522, 50257, 32000, 28996, 51200):
            matched = False
            for embed_dim in (128, 256, 384, 512, 768, 1024, 1536, 2048):
                expected_elements = vocab_size * embed_dim
                if abs(elements - expected_elements) < expected_elements * 0.1:
                    summary.embedding_tensor_count += 1
                    if len(summary.embedding_evidence) < _MAX_STREAM_TENSOR_SAMPLES:
                        summary.embedding_evidence.append(f"Found embedding-like matrix: ~{vocab_size}x{embed_dim}")
                    matched = True
                    break
            if matched:
                break

    def _record_stream_tensor(self, value: bytes | bytearray, location: str, summary: _FlaxStreamSummary) -> None:
        size = len(value)
        self._record_stream_tensor_size(size, location, summary)

    def _analyze_streamed_text_chunks(
        self,
        chunks: Iterable[str],
        location: str,
        result: ScanResult,
        *,
        full_length: int,
        finding_location: str,
        coverage_details: dict[str, Any],
        check_jax_transform: bool,
        jax_location: str | None = None,
        evidence_sample: Any | None = None,
    ) -> None:
        """Analyze decoded text with bounded regex windows and conservative coverage checks."""
        raw_tail = ""
        normalized_tail = ""
        previous_chunk_ended_with_whitespace = False
        decoded_chars = 0
        matched_patterns: dict[str, tuple[str, str]] = {}
        matched_transforms: dict[str, str] = {}
        unresolved_pattern_candidates: set[str] = set()
        seen_pattern_anchors: dict[str, set[str]] = {}

        def inspect_windows(raw_window: str, normalized_window: str) -> None:
            raw_window_lower = raw_window.lower()
            if check_jax_transform:
                for transform in _DANGEROUS_JAX_TRANSFORMS:
                    if transform not in matched_transforms and transform in raw_window_lower:
                        matched_transforms[transform] = raw_window
            for pattern, compiled_pattern, lowered_pattern in self._compiled_suspicious_patterns:
                if pattern in self._stream_unsafe_pattern_anchors:
                    anchors = self._stream_unsafe_pattern_anchors[pattern]
                    anchor_matchers = self._stream_unsafe_anchor_matchers[pattern]
                    if anchors is None:
                        unresolved_pattern_candidates.add(pattern)
                        window_has_all_anchors = True
                    else:
                        seen_anchors = seen_pattern_anchors.setdefault(pattern, set())
                        assert anchor_matchers is not None
                        window_anchors = {
                            anchor
                            for anchor, matcher in anchor_matchers
                            if matcher.search(normalized_window) is not None
                        }
                        seen_anchors.update(window_anchors)
                        window_has_all_anchors = len(window_anchors) == len(anchors)
                        if len(seen_anchors) == len(anchors):
                            unresolved_pattern_candidates.add(pattern)

                    if (
                        pattern == _UNBOUNDED_GETATTR_PATTERN
                        and pattern not in matched_patterns
                        and window_has_all_anchors
                    ):
                        match_sample: str | None = None
                        if _contains_suspicious_getattr(raw_window):
                            match_sample = raw_window
                        elif _contains_suspicious_getattr(normalized_window):
                            match_sample = normalized_window
                        if match_sample is not None:
                            matched_patterns[pattern] = (lowered_pattern, match_sample)
                    continue

                if pattern in matched_patterns:
                    continue
                match_sample = None
                if compiled_pattern.search(raw_window):
                    match_sample = raw_window
                elif "\\s" in pattern and compiled_pattern.search(normalized_window):
                    match_sample = normalized_window
                if match_sample is not None:
                    matched_patterns[pattern] = (lowered_pattern, match_sample)

        for chunk in chunks:
            decoded_chars += len(chunk)
            normalized_chunk = _WHITESPACE_RUN_PATTERN.sub(" ", chunk)
            if previous_chunk_ended_with_whitespace and normalized_chunk.startswith(" "):
                normalized_chunk = normalized_chunk[1:]
            if chunk:
                previous_chunk_ended_with_whitespace = chunk[-1].isspace()

            raw_window = raw_tail + chunk
            normalized_window = normalized_tail + normalized_chunk
            inspect_windows(raw_window, normalized_window)
            raw_tail = raw_window[-_STREAM_TEXT_OVERLAP_CHARS:]
            normalized_tail = normalized_window[-_STREAM_TEXT_OVERLAP_CHARS:]

        for transform, context in matched_transforms.items():
            self._add_jax_transform_check(transform, context, jax_location or location, result)
        for pattern, (lowered_pattern, sample) in matched_patterns.items():
            self._add_suspicious_string_check(
                pattern,
                lowered_pattern,
                sample if evidence_sample is None else evidence_sample,
                decoded_chars,
                finding_location,
                result,
            )

        unresolved_patterns = sorted(unresolved_pattern_candidates - set(matched_patterns))
        existing_reasons = result.metadata.get("scan_outcome_reasons", [])
        if unresolved_patterns and self.BINARY_PATTERN_INCONCLUSIVE_REASON not in existing_reasons:
            self._add_incomplete_check(
                result,
                reason=self.BINARY_PATTERN_INCONCLUSIVE_REASON,
                name="Flax MessagePack Binary Pattern Coverage",
                message="Large text contained an unresolved pattern beyond the streaming overlap",
                location=location,
                details={
                    "pattern": unresolved_patterns[0],
                    "patterns": unresolved_patterns,
                    "full_length": full_length,
                    "stream_overlap_chars": _STREAM_TEXT_OVERLAP_CHARS,
                    **coverage_details,
                },
            )

    def _analyze_large_text(
        self,
        value: str,
        location: str,
        result: ScanResult,
        *,
        check_jax_transform: bool,
        jax_location: str | None = None,
    ) -> None:
        chunks = (
            value[offset : offset + _STREAM_TEXT_CHUNK_BYTES]
            for offset in range(0, len(value), _STREAM_TEXT_CHUNK_BYTES)
        )
        self._analyze_streamed_text_chunks(
            chunks,
            location,
            result,
            full_length=len(value),
            finding_location=location,
            coverage_details={"text_length": len(value)},
            check_jax_transform=check_jax_transform,
            jax_location=jax_location,
        )

    def _analyze_large_binary_text(self, value: bytes | bytearray, location: str, result: ScanResult) -> None:
        raw_value = memoryview(value)

        def decoded_chunks() -> Iterable[str]:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            for offset in range(0, len(raw_value), _STREAM_TEXT_CHUNK_BYTES):
                yield decoder.decode(raw_value[offset : offset + _STREAM_TEXT_CHUNK_BYTES], final=False)
            final_chunk = decoder.decode(b"", final=True)
            if final_chunk:
                yield final_chunk

        self._analyze_streamed_text_chunks(
            decoded_chunks(),
            location,
            result,
            full_length=len(value),
            finding_location=f"{location}[decoded_binary]",
            coverage_details={"binary_size": len(value)},
            check_jax_transform=True,
        )

    def _analyze_stream_scalar(
        self,
        value: Any,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        *,
        check_string_jax_transform: bool = True,
    ) -> None:
        if HAS_MSGPACK and isinstance(value, msgpack.ExtType):
            self._analyze_stream_scalar(
                value.data,
                f"{location}[1]",
                result,
                summary,
                check_string_jax_transform=check_string_jax_transform,
            )
            return

        if isinstance(value, bytes | bytearray):
            size = len(value)
            self._add_binary_blob_size_check(result, location, size)
            if size > _STREAM_TEXT_CHUNK_BYTES:
                self._analyze_large_binary_text(value, location, result)
            else:
                decoded = bytes(value).decode("utf-8", errors="replace")
                if check_string_jax_transform:
                    self._check_jax_transform("", decoded, location, result)
                if len(decoded) > 50 or _is_text_like_short_binary(value):
                    self._check_suspicious_strings(decoded, f"{location}[decoded_binary]", result)
            self._record_stream_tensor(value, location, summary)
            return

        if isinstance(value, str):
            if len(value) > _STREAM_TEXT_CHUNK_BYTES:
                self._analyze_large_text(
                    value,
                    location,
                    result,
                    check_jax_transform=check_string_jax_transform,
                )
            else:
                if check_string_jax_transform:
                    self._check_jax_transform("", value, location, result)
                self._check_suspicious_strings(value, location, result)
            if len(value) > 100000:
                result.add_check(
                    name="String Length Check",
                    passed=False,
                    message=f"Extremely long string found: {len(value):,} characters",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=_redact_evidence_location(location),
                    details={"length": len(value), "threshold": 100000},
                )
            self._record_stream_text(value, summary)
            return

        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2**63:
            result.add_check(
                name="Integer Value Range Check",
                passed=False,
                message=f"Extremely large integer value: {value}",
                severity=IssueSeverity.INFO,
                location=_redact_evidence_location(location),
                details={"value": value},
                rule_code="S902",
            )

    def _analyze_streamed_string_scalar(
        self,
        chunks: Iterable[str],
        length: int,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        *,
        check_string_jax_transform: bool = True,
    ) -> None:
        def recorded_chunks() -> Iterable[str]:
            for chunk in chunks:
                self._check_timeout()
                self._record_stream_text(chunk, summary)
                yield chunk

        self._analyze_streamed_text_chunks(
            recorded_chunks(),
            location,
            result,
            full_length=length,
            finding_location=location,
            coverage_details={"text_length": length},
            check_jax_transform=check_string_jax_transform,
        )
        if length > 100000:
            result.add_check(
                name="String Length Check",
                passed=False,
                message=f"Extremely long string found: {length:,} characters",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=_redact_evidence_location(location),
                details={"length": length, "threshold": 100000},
            )

    def _analyze_streamed_binary_sample(
        self,
        sample: bytes,
        length: int,
        location: str,
        result: ScanResult,
    ) -> None:
        if not sample or not _is_text_like_short_binary(sample):
            return
        decoded = sample.decode("utf-8", errors="replace")
        self._check_jax_transform("", decoded, location, result)
        self._check_suspicious_strings(decoded, f"{location}[decoded_binary]", result)

    def _analyze_streamed_binary_chunks(
        self,
        first_chunk: bytes,
        cursor: _MsgpackStreamCursor,
        remaining: int,
        length: int,
        location: str,
        result: ScanResult,
    ) -> None:
        if not first_chunk and remaining == 0:
            return

        if _is_text_like_short_binary(first_chunk) or self._binary_stream_requires_full_scan:
            self._analyze_streamed_binary_text_chunks(first_chunk, cursor, remaining, length, location, result)
            return

        self._analyze_streamed_binary_anchor_chunks(first_chunk, cursor, remaining, length, location, result)

    def _analyze_streamed_binary_text_chunks(
        self,
        first_chunk: bytes,
        cursor: _MsgpackStreamCursor,
        remaining: int,
        length: int,
        location: str,
        result: ScanResult,
    ) -> None:
        def decoded_chunks() -> Iterable[str]:
            nonlocal remaining
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            decoded = decoder.decode(first_chunk, final=False)
            if decoded:
                yield decoded
            while remaining > 0:
                raw_chunk = cursor._read_exact(min(remaining, _STREAM_TEXT_CHUNK_BYTES))
                remaining -= len(raw_chunk)
                self._check_timeout()
                decoded = decoder.decode(raw_chunk, final=False)
                if decoded:
                    yield decoded
            final_chunk = decoder.decode(b"", final=True)
            if final_chunk:
                yield final_chunk

        self._analyze_streamed_text_chunks(
            decoded_chunks(),
            location,
            result,
            full_length=length,
            finding_location=f"{location}[decoded_binary]",
            coverage_details={"binary_size": length},
            check_jax_transform=True,
        )

    def _analyze_streamed_binary_anchor_chunks(
        self,
        first_chunk: bytes,
        cursor: _MsgpackStreamCursor,
        remaining: int,
        length: int,
        location: str,
        result: ScanResult,
    ) -> None:
        matched_patterns: dict[str, tuple[str, str]] = {}
        matched_transforms: dict[str, str] = {}
        unresolved_pattern_candidates: set[str] = set()
        seen_pattern_anchors: dict[str, set[str]] = {}
        track_split_getattr_pattern = any(
            pattern == _UNBOUNDED_GETATTR_PATTERN for _, pattern, _, _ in self._binary_stream_pattern_matchers
        )
        saw_getattr_call_candidate = False
        saw_getattr_dunder_candidate = False
        raw_tail = b""

        def inspect_window(raw_bytes: bytes) -> None:
            nonlocal saw_getattr_call_candidate, saw_getattr_dunder_candidate
            raw_window_lower = raw_bytes.lower()
            transform_candidates = [
                transform for anchor, transform in self._binary_stream_transform_matchers if anchor in raw_window_lower
            ]
            pattern_candidates = [
                (pattern, compiled_pattern, lowered_pattern)
                for anchor, pattern, compiled_pattern, lowered_pattern in self._binary_stream_pattern_matchers
                if pattern not in self._stream_unsafe_pattern_anchors
                and pattern not in matched_patterns
                and anchor in raw_window_lower
            ]
            unsafe_pattern_candidates = []
            for pattern, compiled_pattern, lowered_pattern in self._compiled_suspicious_patterns:
                if pattern not in self._stream_unsafe_pattern_anchors or pattern in matched_patterns:
                    continue
                anchors = self._stream_unsafe_pattern_anchors[pattern]
                if anchors is None or any(anchor.lower().encode("utf-8") in raw_window_lower for anchor in anchors):
                    unsafe_pattern_candidates.append((pattern, compiled_pattern, lowered_pattern))
            inspect_split_getattr_candidate = (
                track_split_getattr_pattern
                and _UNBOUNDED_GETATTR_PATTERN not in matched_patterns
                and (b"getattr" in raw_window_lower or (saw_getattr_call_candidate and b"__" in raw_window_lower))
            )
            if (
                not transform_candidates
                and not pattern_candidates
                and not unsafe_pattern_candidates
                and not inspect_split_getattr_candidate
            ):
                return

            raw_window = raw_bytes.decode("utf-8", errors="replace")
            normalized_window = _WHITESPACE_RUN_PATTERN.sub(" ", raw_window)
            if inspect_split_getattr_candidate:
                previously_saw_getattr_call = saw_getattr_call_candidate
                if _contains_getattr_call_anchor(raw_window) or _contains_getattr_call_anchor(normalized_window):
                    saw_getattr_call_candidate = True
                if previously_saw_getattr_call and (
                    _contains_quoted_dunder_attribute_after_comma(raw_window)
                    or _contains_quoted_dunder_attribute_after_comma(normalized_window)
                ):
                    saw_getattr_dunder_candidate = True
            for transform in transform_candidates:
                if transform not in matched_transforms:
                    matched_transforms[transform] = raw_window

            for pattern, _compiled_pattern, lowered_pattern in unsafe_pattern_candidates:
                if pattern == _UNBOUNDED_GETATTR_PATTERN:
                    match_sample: str | None = None
                    if _contains_suspicious_getattr(raw_window):
                        match_sample = raw_window
                    elif _contains_suspicious_getattr(normalized_window):
                        match_sample = normalized_window
                    if match_sample is not None:
                        matched_patterns[pattern] = (lowered_pattern, match_sample)
                    continue

                anchors = self._stream_unsafe_pattern_anchors[pattern]
                if anchors is None:
                    unresolved_pattern_candidates.add(pattern)
                    continue

                anchor_matchers = self._stream_unsafe_anchor_matchers[pattern]
                assert anchor_matchers is not None
                seen_anchors = seen_pattern_anchors.setdefault(pattern, set())
                window_anchors = {
                    anchor for anchor, matcher in anchor_matchers if matcher.search(normalized_window) is not None
                }
                seen_anchors.update(window_anchors)
                if len(seen_anchors) == len(anchors):
                    unresolved_pattern_candidates.add(pattern)

            for pattern, compiled_pattern, lowered_pattern in pattern_candidates:
                match_sample = None
                if compiled_pattern.search(raw_window):
                    match_sample = raw_window
                elif "\\s" in pattern and compiled_pattern.search(normalized_window):
                    match_sample = normalized_window
                if match_sample is not None:
                    matched_patterns[pattern] = (lowered_pattern, match_sample)

        chunk = first_chunk
        while True:
            inspect_window(raw_tail + chunk)
            raw_tail = (raw_tail + chunk)[-_STREAM_TEXT_OVERLAP_CHARS:]
            if remaining <= 0:
                break
            chunk = cursor._read_exact(min(remaining, _STREAM_TEXT_CHUNK_BYTES))
            remaining -= len(chunk)
            self._check_timeout()

        for transform, context in matched_transforms.items():
            self._add_jax_transform_check(transform, context, location, result)
        for pattern, (lowered_pattern, sample) in matched_patterns.items():
            self._add_suspicious_string_check(
                pattern,
                lowered_pattern,
                sample,
                length,
                f"{location}[decoded_binary]",
                result,
            )

        if saw_getattr_call_candidate and saw_getattr_dunder_candidate:
            unresolved_pattern_candidates.add(_UNBOUNDED_GETATTR_PATTERN)
        unresolved_patterns = sorted(unresolved_pattern_candidates - set(matched_patterns))
        existing_reasons = result.metadata.get("scan_outcome_reasons", [])
        if unresolved_patterns and self.BINARY_PATTERN_INCONCLUSIVE_REASON not in existing_reasons:
            self._add_incomplete_check(
                result,
                reason=self.BINARY_PATTERN_INCONCLUSIVE_REASON,
                name="Flax MessagePack Binary Pattern Coverage",
                message="Large binary payload contained an unresolved pattern beyond the streaming overlap",
                location=location,
                details={
                    "pattern": unresolved_patterns[0],
                    "patterns": unresolved_patterns,
                    "binary_size": length,
                    "stream_overlap_chars": _STREAM_TEXT_OVERLAP_CHARS,
                },
            )

    def _read_stream_metadata_int(self, cursor: _MsgpackStreamCursor) -> int:
        marker = cursor.read_marker()
        if marker <= 0x7F:
            return marker
        if marker >= 0xE0:
            return marker - 256
        if marker == 0xCC:
            return cursor.read_uint(1)
        if marker == 0xCD:
            return cursor.read_uint(2)
        if marker == 0xCE:
            return cursor.read_uint(4)
        if marker == 0xCF:
            return cursor.read_uint(8)
        if marker == 0xD0:
            return cursor.read_int(1)
        if marker == 0xD1:
            return cursor.read_int(2)
        if marker == 0xD2:
            return cursor.read_int(4)
        if marker == 0xD3:
            return cursor.read_int(8)
        raise _MsgpackStreamFormatError(f"expected integer metadata, found marker 0x{marker:02x}")

    def _read_stream_metadata_string(self, cursor: _MsgpackStreamCursor) -> str:
        marker = cursor.read_marker()
        if 0xA0 <= marker <= 0xBF:
            length = marker & 0x1F
        elif marker == 0xD9:
            length = cursor.read_uint(1)
        elif marker == 0xDA:
            length = cursor.read_uint(2)
        elif marker == 0xDB:
            length = cursor.read_uint(4)
        else:
            raise _MsgpackStreamFormatError(f"expected string metadata, found marker 0x{marker:02x}")
        if length > self.max_stream_key_length:
            raise _MsgpackStreamFormatError("string metadata exceeds max_msgpack_key_length")
        return cursor._read_exact(length).decode("utf-8")

    @staticmethod
    def _read_stream_binary_header(cursor: _MsgpackStreamCursor) -> int:
        marker = cursor.read_marker()
        if marker == 0xC4:
            return cursor.read_uint(1)
        if marker == 0xC5:
            return cursor.read_uint(2)
        if marker == 0xC6:
            return cursor.read_uint(4)
        raise _MsgpackStreamFormatError(f"expected binary tensor payload, found marker 0x{marker:02x}")

    @staticmethod
    def _flax_ndarray_dtype_item_size(dtype: str) -> int:
        normalized = dtype.strip().lower()
        if normalized.startswith("numpy."):
            normalized = normalized.removeprefix("numpy.")
        if len(normalized) > 1 and normalized[0] in "<>|=":
            normalized = normalized[1:]
        item_size = _FLAX_NDARRAY_DTYPE_ITEM_SIZES.get(normalized)
        if item_size is None:
            raise _MsgpackStreamFormatError(f"unsupported Flax ndarray dtype metadata: {dtype!r}")
        return item_size

    def _validate_flax_ndarray_payload_length(
        self,
        shape_values: list[int],
        dtype: str,
        data_length: int,
    ) -> None:
        item_size = self._flax_ndarray_dtype_item_size(dtype)
        if data_length % item_size != 0:
            raise _MsgpackStreamFormatError("Flax ndarray tensor byte length is not aligned to dtype item size")

        has_zero_dimension = False
        for index, dimension in enumerate(shape_values):
            if dimension < 0:
                raise _MsgpackStreamFormatError(f"Flax ndarray shape dimension {index} is negative")
            if dimension == 0:
                has_zero_dimension = True
        if has_zero_dimension:
            if data_length != 0:
                raise _MsgpackStreamFormatError("Flax ndarray shape and dtype do not match declared tensor byte length")
            return

        max_elements = data_length // item_size
        element_count = 1
        for dimension in shape_values:
            if element_count > max_elements // dimension:
                raise _MsgpackStreamFormatError("Flax ndarray shape and dtype exceed declared tensor byte length")
            element_count *= dimension

        if element_count != max_elements:
            raise _MsgpackStreamFormatError("Flax ndarray shape and dtype do not match declared tensor byte length")

    def _check_stream_shape_values(self, shape_values: list[int], location: str, result: ScanResult) -> None:
        shape_summary = _StreamSequenceSummary(
            item_count=len(shape_values),
            evidence_values=shape_values[:_MAX_STREAM_SEQUENCE_EVIDENCE],
            evidence_complete=len(shape_values) <= _MAX_STREAM_SEQUENCE_EVIDENCE,
        )
        for index, value in enumerate(shape_values):
            if value < 0 and shape_summary.negative_dimension is None:
                shape_summary.negative_dimension = (index, value)
            elif value > 10**9 and shape_summary.oversized_dimension is None:
                shape_summary.oversized_dimension = (index, value)
        self._check_stream_shape_metadata(shape_summary, location, result)

    def _consume_large_binary_scalar(
        self,
        cursor: _MsgpackStreamCursor,
        length: int,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        state: _StreamTraversalState,
        *,
        path: str,
    ) -> _StreamValue:
        self._add_binary_blob_size_check(result, location, length)
        is_tensor_like = self._is_tensor_like_binary_size(length)
        if is_tensor_like:
            self._record_stream_tensor_size(length, location, summary)
        else:
            summary.analysis_complete = False
            self._report_stream_decode_limit(
                state,
                result,
                path,
                f"binary payload length {length} exceeds max_msgpack_decode_bytes({self.max_msgpack_decode_bytes})",
            )

        sample_size = min(length, _STREAM_TEXT_CHUNK_BYTES)
        sample = cursor._read_exact(sample_size)
        remaining = length - sample_size
        self._check_timeout()
        if _is_text_like_short_binary(sample):
            self._analyze_streamed_binary_chunks(sample, cursor, remaining, length, location, result)
        else:
            if is_tensor_like:
                self._add_binary_pattern_incomplete_check(
                    result,
                    summary,
                    location=location,
                    binary_size=length,
                    sampled_bytes=sample_size,
                    message="Tensor-like binary payload was not text-scanned after a bounded probe",
                )
            cursor.skip(remaining)
            self._check_timeout()
        return _StreamValue("bytes", value=None)

    def _consume_flax_ndarray_ext_scalar(
        self,
        cursor: _MsgpackStreamCursor,
        length: int,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        *,
        path: str,
    ) -> _StreamValue:
        body_start = cursor.tell()
        body_end = body_start + length
        field_count = cursor.read_array_header()
        if field_count != 3:
            raise _MsgpackStreamFormatError("unexpected Flax ndarray extension field count")

        shape_count = cursor.read_array_header()
        if shape_count > 32:
            raise _MsgpackStreamFormatError("Flax ndarray extension shape rank exceeds metadata limit")
        shape_values = []
        for _ in range(shape_count):
            shape_values.append(self._read_stream_metadata_int(cursor))
            self._check_timeout()
        self._check_stream_shape_values(shape_values, location, result)

        dtype = self._read_stream_metadata_string(cursor)
        self._analyze_stream_scalar(dtype, f"{location}[1]", result, summary)

        data_length = self._read_stream_binary_header(cursor)
        if cursor.tell() + data_length > body_end:
            raise OutOfData
        self._validate_flax_ndarray_payload_length(shape_values, dtype, data_length)

        value_location = f"{location}[2]"
        self._record_stream_tensor_size(data_length, value_location, summary)
        self._check_timeout()
        cursor.skip(data_length)
        self._check_timeout()

        if cursor.tell() != body_end:
            raise _MsgpackStreamFormatError("Flax ndarray extension contains trailing bytes after tensor payload")
        return _StreamValue("ExtType", value=None)

    def _read_stream_string_scalar(
        self,
        cursor: _MsgpackStreamCursor,
        length: int,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        *,
        analyze_scalar: bool,
    ) -> _StreamValue:
        if not analyze_scalar:
            raw_value = cursor._read_exact(length)
            return _StreamValue("str", value=raw_value.decode("utf-8"))

        if length > self.max_msgpack_decode_bytes:
            self._analyze_streamed_string_scalar(
                cursor.iter_utf8_chunks(length),
                length,
                location,
                result,
                summary,
            )
            return _StreamValue("str", value=None)

        raw_value = cursor._read_exact(length)
        value = raw_value.decode("utf-8")
        self._analyze_stream_scalar(value, location, result, summary)
        return _StreamValue("str", value=value)

    def _read_stream_binary_scalar(
        self,
        cursor: _MsgpackStreamCursor,
        length: int,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        state: _StreamTraversalState,
        *,
        path: str,
        analyze_scalar: bool,
    ) -> _StreamValue:
        if not analyze_scalar:
            return _StreamValue("bytes", value=cursor._read_exact(length))

        if length > self.max_msgpack_decode_bytes:
            return self._consume_large_binary_scalar(cursor, length, location, result, summary, state, path=path)

        value = cursor._read_exact(length)
        self._analyze_stream_scalar(value, location, result, summary)
        return _StreamValue("bytes", value=value)

    def _read_stream_ext_scalar(
        self,
        cursor: _MsgpackStreamCursor,
        length: int,
        code: int,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        state: _StreamTraversalState,
        *,
        path: str,
        analyze_scalar: bool,
    ) -> _StreamValue:
        value_location = f"{location}[1]"
        if not analyze_scalar:
            data = cursor._read_exact(length)
            if HAS_MSGPACK and 0 <= code <= 127:
                return _StreamValue("ExtType", value=msgpack.ExtType(code, data))
            return _StreamValue("ExtType", value=data)

        if code == 1:
            return self._consume_flax_ndarray_ext_scalar(cursor, length, location, result, summary, path=path)

        if length > self.max_msgpack_decode_bytes:
            self._consume_large_binary_scalar(cursor, length, value_location, result, summary, state, path=path)
            return _StreamValue("ExtType", value=None)

        data = cursor._read_exact(length)
        value = msgpack.ExtType(code, data) if HAS_MSGPACK and 0 <= code <= 127 else data
        self._analyze_stream_scalar(value, location, result, summary)
        return _StreamValue("ExtType", value=value)

    def _read_stream_scalar_value(
        self,
        cursor: _MsgpackStreamCursor,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        state: _StreamTraversalState,
        *,
        path: str,
        location: str,
        analyze_scalar: bool,
    ) -> _StreamValue:
        marker = cursor.read_marker()
        if marker <= 0x7F:
            value: Any = marker
        elif marker >= 0xE0:
            value = marker - 256
        elif 0xA0 <= marker <= 0xBF:
            return self._read_stream_string_scalar(
                cursor,
                marker & 0x1F,
                location,
                result,
                summary,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC0:
            value = None
        elif marker == 0xC2:
            value = False
        elif marker == 0xC3:
            value = True
        elif marker == 0xC4:
            return self._read_stream_binary_scalar(
                cursor,
                cursor.read_uint(1),
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC5:
            return self._read_stream_binary_scalar(
                cursor,
                cursor.read_uint(2),
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC6:
            return self._read_stream_binary_scalar(
                cursor,
                cursor.read_uint(4),
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC7:
            length = cursor.read_uint(1)
            code = cursor.read_int(1)
            return self._read_stream_ext_scalar(
                cursor,
                length,
                code,
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC8:
            length = cursor.read_uint(2)
            code = cursor.read_int(1)
            return self._read_stream_ext_scalar(
                cursor,
                length,
                code,
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC9:
            length = cursor.read_uint(4)
            code = cursor.read_int(1)
            return self._read_stream_ext_scalar(
                cursor,
                length,
                code,
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xCA:
            value = struct.unpack(">f", cursor._read_exact(4))[0]
        elif marker == 0xCB:
            value = struct.unpack(">d", cursor._read_exact(8))[0]
        elif marker == 0xCC:
            value = cursor.read_uint(1)
        elif marker == 0xCD:
            value = cursor.read_uint(2)
        elif marker == 0xCE:
            value = cursor.read_uint(4)
        elif marker == 0xCF:
            value = cursor.read_uint(8)
        elif marker == 0xD0:
            value = cursor.read_int(1)
        elif marker == 0xD1:
            value = cursor.read_int(2)
        elif marker == 0xD2:
            value = cursor.read_int(4)
        elif marker == 0xD3:
            value = cursor.read_int(8)
        elif marker in {0xD4, 0xD5, 0xD6, 0xD7, 0xD8}:
            length = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}[marker]
            code = cursor.read_int(1)
            return self._read_stream_ext_scalar(
                cursor,
                length,
                code,
                location,
                result,
                summary,
                state,
                path=path,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xD9:
            return self._read_stream_string_scalar(
                cursor,
                cursor.read_uint(1),
                location,
                result,
                summary,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xDA:
            return self._read_stream_string_scalar(
                cursor,
                cursor.read_uint(2),
                location,
                result,
                summary,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xDB:
            return self._read_stream_string_scalar(
                cursor,
                cursor.read_uint(4),
                location,
                result,
                summary,
                analyze_scalar=analyze_scalar,
            )
        elif marker == 0xC1:
            raise _MsgpackStreamFormatError("reserved MessagePack marker 0xc1")
        else:
            raise _MsgpackStreamFormatError(f"unexpected MessagePack scalar marker 0x{marker:02x}")

        if analyze_scalar:
            self._analyze_stream_scalar(value, location, result, summary)
        type_name = "NoneType" if value is None else type(value).__name__
        return _StreamValue(type_name, value=value)

    def _analyze_stream_key(
        self,
        key: Any,
        location: str,
        result: ScanResult,
        summary: _FlaxStreamSummary,
    ) -> tuple[str, str]:
        key_str = _stringify_evidence_fragment(key)
        safe_key_str = _stringify_safe_evidence_fragment(key)
        location_key = _redact_evidence_location(key)
        key_value_location = f"{location}/{location_key}" if location else location_key
        key_evidence_location = f"{location}[key:{location_key}]"
        if len(key_str) > _STREAM_TEXT_CHUNK_BYTES:
            self._analyze_large_text(
                key_str,
                key_evidence_location,
                result,
                check_jax_transform=True,
                jax_location=key_value_location,
            )
        else:
            self._check_jax_transform(key_str, "", key_value_location, result)
            self._check_suspicious_strings(
                key_str,
                key_evidence_location,
                result,
                evidence_value=safe_key_str,
            )
        self._record_stream_text(key_str, summary)
        layer_words = ("layer", "block", "level")
        if len(key_str) <= _STREAM_TEXT_CHUNK_BYTES:
            has_layer_word = any(layer_word in key_str.lower() for layer_word in layer_words)
        else:
            has_layer_word = any(
                layer_word in key_str[offset : offset + _STREAM_TEXT_CHUNK_BYTES].lower()
                for offset in range(0, len(key_str), _STREAM_TEXT_CHUNK_BYTES)
                for layer_word in layer_words
            )
        if has_layer_word:
            summary.layer_count += 1
        return key_str, location_key

    @staticmethod
    def _stream_key_digest_identity(kind: str, value: bytes) -> tuple[Any, ...]:
        digest = hashlib.blake2b(value, digest_size=16).hexdigest()
        return (kind, len(value), digest)

    def _stream_key_identity(self, key: Any) -> tuple[tuple[Any, ...], int]:
        if HAS_MSGPACK and isinstance(key, msgpack.ExtType):
            return (self._stream_key_digest_identity(f"ext:{key.code}", key.data), len(key.data))
        if isinstance(key, bytes | bytearray):
            raw_key = bytes(key)
            return (self._stream_key_digest_identity("bin", raw_key), len(raw_key))
        if isinstance(key, str):
            raw_key = key.encode("utf-8", errors="surrogatepass")
            return (self._stream_key_digest_identity("str", raw_key), len(raw_key))
        if key is None or isinstance(key, bool | int | float):
            identity = (type(key).__name__, repr(key))
            return (identity, len(identity[1]))
        fallback_key = _stringify_evidence_fragment(key)
        return ((type(key).__name__, fallback_key), len(fallback_key))

    @staticmethod
    def _add_duplicate_map_key_check(result: ScanResult, key: Any, location: str) -> None:
        result.add_check(
            name="MessagePack Duplicate Key Check",
            passed=False,
            message="Duplicate MessagePack map key detected",
            severity=IssueSeverity.INFO,
            location=_redact_evidence_location(location),
            details={"key": _redact_evidence_key(key)},
            rule_code="S902",
        )

    def _add_duplicate_key_tracking_budget_check(
        self,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        *,
        location: str,
        tracked_key_bytes: int,
        next_key_bytes: int,
        seen_key_count: int,
    ) -> None:
        summary.analysis_complete = False
        self._add_incomplete_check(
            result,
            reason=self.DUPLICATE_KEY_TRACKING_INCONCLUSIVE_REASON,
            name="MessagePack Duplicate Key Tracking Budget",
            message="Duplicate-key tracking exceeded bounded aggregate key budget",
            location=location,
            details={
                "tracked_key_bytes": tracked_key_bytes,
                "next_key_bytes": next_key_bytes,
                "seen_key_count": seen_key_count,
                "max_msgpack_duplicate_key_tracking_bytes": self.max_duplicate_key_tracking_bytes,
            },
        )

    @staticmethod
    def _is_msgpack_limit_error(error: Exception) -> bool:
        if type(error).__name__ == "BufferFull":
            return True
        message = str(error).lower()
        return "exceeds max_" in message or "max_buffer_size" in message or "recursion" in message

    def _add_msgpack_decode_limit_check(self, result: ScanResult, path: str, error: Exception) -> None:
        error_message = _redact_evidence_sample(error)
        self._add_incomplete_check(
            result,
            reason=self.DECODE_LIMIT_INCONCLUSIVE_REASON,
            name="Msgpack Decode Budget",
            message="Flax MessagePack decode exceeded configured size or container limits",
            location=path,
            details={
                "error": error_message,
                "error_type": type(error).__name__,
                "max_msgpack_decode_bytes": self.max_msgpack_decode_bytes,
                "max_items_per_container": self.max_items_per_container,
                "max_msgpack_key_length": self.max_stream_key_length,
            },
        )
        result.finish(success=False)

    def _add_msgpack_parse_failure_check(self, result: ScanResult, path: str, error: Exception) -> None:
        error_message = _redact_evidence_sample(error)
        result.add_check(
            name="Msgpack Parse Check",
            passed=False,
            message=f"Failed to parse msgpack data: {error_message}",
            severity=IssueSeverity.WARNING,
            location=path,
            details={"parse_error": error_message},
            rule_code="S902",
        )
        result.finish(success=False)

    def _add_msgpack_truncated_stream_check(
        self,
        result: ScanResult,
        path: str,
        *,
        stream_offset: int,
        stream_size: int,
    ) -> None:
        parse_error = "incomplete trailing msgpack object"
        self._add_incomplete_check(
            result,
            reason=self.TRUNCATED_STREAM_INCONCLUSIVE_REASON,
            name="Msgpack Parse Check",
            message=f"Failed to parse msgpack data: {parse_error}",
            location=path,
            details={
                "parse_error": parse_error,
                "stream_offset": stream_offset,
                "stream_size": stream_size,
            },
        )
        result.finish(success=False)

    def _add_msgpack_stream_object_limit_check(self, result: ScanResult, path: str, parsed_object_count: int) -> None:
        result.add_check(
            name="Msgpack Stream Object Limit",
            passed=False,
            message=(
                "Msgpack stream has unvalidated trailing data after the configured object limit "
                f"({self.max_msgpack_stream_objects})"
            ),
            severity=IssueSeverity.WARNING,
            location=path,
            details={
                "max_msgpack_stream_objects": self.max_msgpack_stream_objects,
                "parsed_object_count": parsed_object_count,
            },
            rule_code="S902",
        )
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = "msgpack_stream_object_limit_exceeded"
        result.finish(success=False)

    @staticmethod
    def _is_msgpack_out_of_data(error: Exception) -> bool:
        return type(error).__name__ == "OutOfData"

    def _report_stream_decode_limit(
        self,
        state: _StreamTraversalState,
        result: ScanResult,
        path: str,
        message: str,
    ) -> None:
        if state.decode_limit_reported:
            return
        state.decode_limit_reported = True
        self._add_msgpack_decode_limit_check(result, path, ValueError(message))

    def _read_stream_value(
        self,
        cursor: _MsgpackStreamCursor,
        result: ScanResult,
        summary: _FlaxStreamSummary,
        state: _StreamTraversalState,
        *,
        path: str,
        location: str,
        depth: int,
        analyze_scalar: bool = True,
        top_level: bool = False,
        count_node: bool = True,
        capture_sequence: bool = False,
    ) -> _StreamValue:
        if state.node_budget_reported:
            summary.analysis_complete = False
            raise _StreamCoverageStopped
        if count_node:
            state.nodes += 1
        if count_node and state.nodes > state.max_nodes:
            summary.analysis_complete = False
            if not state.node_budget_reported:
                self._add_structure_budget_check(
                    result,
                    location=location,
                    budget="node_count",
                    observed=state.nodes,
                    maximum=state.max_nodes,
                )
                state.node_budget_reported = True
            raise _StreamCoverageStopped

        if depth > self.max_recursion_depth:
            summary.analysis_complete = False
            if not state.recursion_limit_reported:
                self._add_incomplete_check(
                    result,
                    reason=self.RECURSION_LIMIT_INCONCLUSIVE_REASON,
                    name="Flax MessagePack Preanalysis Depth Limit",
                    message=f"Maximum preanalysis recursion depth exceeded: {depth}",
                    location=location,
                    details={"depth": depth, "max_allowed": self.max_recursion_depth},
                )
                self._add_incomplete_check(
                    result,
                    reason=self.RECURSION_LIMIT_INCONCLUSIVE_REASON,
                    name="Recursion Depth Check",
                    message=f"Maximum recursion depth exceeded: {depth}",
                    location=location,
                    details={"depth": depth, "max_allowed": self.max_recursion_depth},
                )
                state.recursion_limit_reported = True
            raise _StreamCoverageStopped

        marker = cursor.peek_marker()
        if marker is not None and (0x80 <= marker <= 0x8F or marker in {0xDE, 0xDF}):
            map_length = cursor.read_map_header()
            if top_level:
                summary.top_level_key_count = map_length
            direct_string_keys: set[str] = set()
            seen_keys: set[tuple[Any, ...]] = set()
            tracked_key_bytes = 0
            duplicate_key_reports = 0
            has_jax_array = False
            visible_items = min(map_length, self.max_items_per_container)
            if map_length > self.max_items_per_container:
                summary.analysis_complete = False
                self._report_stream_decode_limit(
                    state,
                    result,
                    path,
                    f"map length {map_length} exceeds max_map_len({self.max_items_per_container})",
                )

            transformer_keys = {"embeddings", "encoder", "decoder", "pooler", "lm_head", "transformer", "model"}
            model_name_keys = {
                "bert",
                "roberta",
                "distilbert",
                "albert",
                "electra",
                "xlm",
                "gpt2",
                "gpt_neo",
                "gpt_neox",
                "gptj",
                "opt",
                "llama",
                "t5",
                "bart",
                "pegasus",
                "mbart",
                "blenderbot",
                "vit",
                "clip",
                "whisper",
                "wav2vec2",
                "flax_model",
                "classifier",
                "qa_outputs",
                "lm_head",
                "score",
            }

            for index in range(visible_items):
                self._check_timeout()
                declared_key_length = cursor.peek_declared_data_bytes()
                if declared_key_length is not None and declared_key_length > self.max_stream_key_length:
                    summary.analysis_complete = False
                    self._report_stream_decode_limit(
                        state,
                        result,
                        path,
                        "map key length "
                        f"{declared_key_length} exceeds max_msgpack_key_length({self.max_stream_key_length})",
                    )
                    raise _StreamCoverageStopped
                key_value = self._read_stream_value(
                    cursor,
                    result,
                    summary,
                    state,
                    path=path,
                    location=f"{location}[key:{index}]",
                    depth=depth + 1,
                    analyze_scalar=False,
                    count_node=False,
                )
                key = key_value.value
                if key_value.is_container or key_value.type_name == "skipped":
                    key = f"<{key_value.type_name}_key>"
                key_length: int | None = None
                if HAS_MSGPACK and isinstance(key, msgpack.ExtType):
                    key_length = len(key.data)
                elif isinstance(key, str | bytes | bytearray):
                    key_length = len(key)
                if key_length is not None and key_length > self.max_stream_key_length:
                    summary.analysis_complete = False
                    self._report_stream_decode_limit(
                        state,
                        result,
                        path,
                        f"map key length {key_length} exceeds max_msgpack_key_length({self.max_stream_key_length})",
                    )
                    raise _StreamCoverageStopped
                key_str, safe_key_str = self._analyze_stream_key(key, location, result, summary)
                key_identity, key_identity_bytes = self._stream_key_identity(key)
                if tracked_key_bytes + key_identity_bytes > self.max_duplicate_key_tracking_bytes:
                    self._add_duplicate_key_tracking_budget_check(
                        result,
                        summary,
                        location=location,
                        tracked_key_bytes=tracked_key_bytes,
                        next_key_bytes=key_identity_bytes,
                        seen_key_count=len(seen_keys),
                    )
                    raise _StreamCoverageStopped
                if key_identity in seen_keys and duplicate_key_reports < 16:
                    duplicate_key_reports += 1
                    self._add_duplicate_map_key_check(result, key, location)
                seen_keys.add(key_identity)
                tracked_key_bytes += key_identity_bytes
                key_text = _text_for_security_matching(key)
                key_location = f"{location}/{safe_key_str}" if location else safe_key_str
                if key_text is not None and key_text in transformer_keys:
                    direct_string_keys.add(key_text)
                if top_level:
                    if len(summary.top_level_keys) < 50:
                        summary.top_level_keys.append(_redact_evidence_key(key))
                    if key_text is not None and len(key_text) <= 128:
                        summary.top_level_string_keys.add(key_text)
                        if key_text.startswith("__orbax"):
                            summary.orbax_format = True

                value = self._read_stream_value(
                    cursor,
                    result,
                    summary,
                    state,
                    path=path,
                    location=key_location,
                    depth=depth + 1,
                    count_node=True,
                    capture_sequence=key_text == "shape",
                )
                self._check_suspicious_keys(key_str, value.value, key_location, result)

                if key_text == "__jax_array__":
                    has_jax_array = True

                if (
                    top_level
                    and value.type_name == "dict"
                    and key_text is not None
                    and (value.direct_string_keys & transformer_keys or key_text.lower() in model_name_keys)
                ):
                    summary.has_nested_transformer_keys = True

            if map_length > visible_items:
                raise _StreamCoverageStopped

            if has_jax_array:
                self._check_jax_array_metadata({"__jax_array__": True}, location, result)
            return _StreamValue("dict", direct_string_keys=direct_string_keys)

        if marker is not None and (0x90 <= marker <= 0x9F or marker in {0xDC, 0xDD}):
            array_length = cursor.read_array_header()
            visible_items = min(array_length, self.max_items_per_container)
            if array_length > self.max_items_per_container:
                summary.analysis_complete = False
                self._report_stream_decode_limit(
                    state,
                    result,
                    path,
                    f"array length {array_length} exceeds max_array_len({self.max_items_per_container})",
                )
            sequence_summary = _StreamSequenceSummary(item_count=array_length) if capture_sequence else None
            for index in range(visible_items):
                self._check_timeout()
                value = self._read_stream_value(
                    cursor,
                    result,
                    summary,
                    state,
                    path=path,
                    location=f"{location}[{index}]",
                    depth=depth + 1,
                    count_node=True,
                )
                if sequence_summary is None:
                    continue

                if isinstance(value.value, int) and not isinstance(value.value, bool):
                    if value.value < 0 and sequence_summary.negative_dimension is None:
                        sequence_summary.negative_dimension = (index, value.value)
                    elif value.value > 10**9 and sequence_summary.oversized_dimension is None:
                        sequence_summary.oversized_dimension = (index, value.value)

                if len(sequence_summary.evidence_values) >= _MAX_STREAM_SEQUENCE_EVIDENCE or (
                    value.is_container
                    or value.type_name == "skipped"
                    or (isinstance(value.value, str | bytes | bytearray) and len(value.value) > 4096)
                    or (HAS_MSGPACK and isinstance(value.value, msgpack.ExtType))
                ):
                    sequence_summary.evidence_complete = False
                else:
                    sequence_summary.evidence_values.append(value.value)
            if sequence_summary is not None:
                shape_location = location.rsplit("/", 1)[0] if "/" in location else location
                self._check_stream_shape_metadata(sequence_summary, shape_location, result)
            if array_length > visible_items:
                raise _StreamCoverageStopped
            captured_values = None
            if (
                sequence_summary is not None
                and sequence_summary.evidence_complete
                and len(sequence_summary.evidence_values) == sequence_summary.item_count
            ):
                captured_values = sequence_summary.evidence_values
            return _StreamValue("list", value=captured_values, sequence_summary=sequence_summary)

        return self._read_stream_scalar_value(
            cursor,
            result,
            summary,
            state,
            path=path,
            location=location,
            analyze_scalar=analyze_scalar,
        )

    def _add_msgpack_stream_integrity_check_from_types(
        self,
        object_types: list[str],
        result: ScanResult,
        path: str,
    ) -> None:
        if len(object_types) <= 1:
            return
        trailing_objects_are_container_like = all(object_type in {"dict", "list"} for object_type in object_types[1:])
        result.add_check(
            name="Msgpack Stream Integrity Check",
            passed=False,
            message="Extra trailing data found after msgpack content",
            severity=(IssueSeverity.INFO if trailing_objects_are_container_like else IssueSeverity.WARNING),
            location=path,
            details={
                "has_trailing_data": True,
                "trailing_object_count": len(object_types) - 1,
                "trailing_object_types": object_types[1:9],
                "trailing_objects_are_container_like": trailing_objects_are_container_like,
            },
            rule_code="S902",
        )

    def _scan_msgpack_stream_from_path(self, path: str, result: ScanResult) -> _FlaxStreamSummary | None:
        """Walk MessagePack tokens without materializing container objects."""
        primary_summary = _FlaxStreamSummary()
        object_types: list[str] = []
        primary_state = _StreamTraversalState(max_nodes=self.max_structure_nodes)
        trailing_state = _StreamTraversalState(max_nodes=self.max_structure_nodes)
        try:
            with open(path, "rb") as source:
                stream_size = os.fstat(source.fileno()).st_size
                cursor = _MsgpackStreamCursor(source, stream_size)
                while True:
                    self._check_timeout()
                    previous_offset = cursor.tell()
                    if len(object_types) >= self.max_msgpack_stream_objects:
                        if previous_offset == stream_size:
                            break
                        marker = cursor.peek_marker()
                        required_header_bytes = 1 if marker is None else _msgpack_marker_header_bytes(marker)
                        remaining_bytes = stream_size - previous_offset
                        marker_prefix = cursor._peek_bytes(required_header_bytes)
                        declared_data_bytes = (
                            None if marker is None else _msgpack_declared_data_bytes(marker, marker_prefix)
                        )
                        scalar_is_truncated = (
                            declared_data_bytes is not None
                            and remaining_bytes < required_header_bytes + declared_data_bytes
                        )
                        if (
                            marker is None
                            or marker == 0xC1
                            or remaining_bytes < required_header_bytes
                            or scalar_is_truncated
                        ):
                            self._add_msgpack_truncated_stream_check(
                                result,
                                path,
                                stream_offset=previous_offset,
                                stream_size=stream_size,
                            )
                            return None
                        self._add_msgpack_stream_object_limit_check(result, path, len(object_types))
                        return None

                    object_index = len(object_types)
                    summary = primary_summary if object_index == 0 else _FlaxStreamSummary()
                    state = primary_state if object_index == 0 else trailing_state
                    location = "root" if object_index == 0 else f"root[msgpack_object_{object_index}]"
                    try:
                        value = self._read_stream_value(
                            cursor,
                            result,
                            summary,
                            state,
                            path=path,
                            location=location,
                            depth=0,
                            top_level=True,
                        )
                    except Exception as error:
                        if self._is_msgpack_out_of_data(error):
                            current_offset = cursor.tell()
                            if current_offset == previous_offset and previous_offset == stream_size:
                                break
                            self._add_msgpack_truncated_stream_check(
                                result,
                                path,
                                stream_offset=current_offset,
                                stream_size=stream_size,
                            )
                            return None
                        raise
                    object_types.append(value.type_name)
                    if object_index == 0:
                        primary_summary.top_level_type = value.type_name
        except TimeoutError:
            raise
        except _StreamCoverageStopped:
            result.finish(success=False)
            return None
        except Exception as error:
            if self._is_msgpack_limit_error(error):
                self._add_msgpack_decode_limit_check(result, path, error)
            else:
                self._add_msgpack_parse_failure_check(result, path, error)
            return None

        if not object_types:
            self._add_msgpack_parse_failure_check(result, path, ValueError("no decodable objects"))
            return None

        if len(object_types) > 1:
            result.metadata["msgpack_object_count"] = len(object_types)
        result.metadata["msgpack_stream_analyzed_nodes"] = min(primary_state.nodes, primary_state.max_nodes) + min(
            trailing_state.nodes, trailing_state.max_nodes
        )
        result.metadata["msgpack_stream_node_budget"] = primary_state.max_nodes + trailing_state.max_nodes
        self._add_msgpack_stream_integrity_check_from_types(object_types, result, path)
        return primary_summary

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        self._start_scan_timer()

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)
        self._check_timeout()

        self.current_file_path = path

        if has_inconclusive_renamed_flax_msgpack_routing(path):
            mark_inconclusive_scan_result(result, "flax_msgpack_routing_incomplete")
            result.add_check(
                name="MessagePack Routing Analysis Incomplete",
                passed=False,
                message="Flax MessagePack analysis incomplete because bounded routing inspection could not complete",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "flax_msgpack_routing_incomplete",
                },
                rule_code="S902",
            )
            result.bytes_scanned = file_size
            result.finish(success=False)
            return result

        if not HAS_MSGPACK:
            result.add_check(
                name="msgpack Library Check",
                passed=False,
                message="msgpack library not installed - cannot analyze Flax checkpoints",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"required_package": "msgpack"},
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        try:
            self.current_file_path = path

            summary = self._scan_msgpack_stream_from_path(path, result)
            if summary is None:
                return result

            # Record metadata
            result.metadata["top_level_type"] = summary.top_level_type
            if summary.top_level_type == "dict":
                result.metadata["top_level_keys"] = summary.top_level_keys
                result.metadata["key_count"] = summary.top_level_key_count

            if summary.analysis_complete:
                ml_analysis = self._analyze_ml_structure(summary, result)
                self._extract_jax_metadata(summary, result, ml_analysis=ml_analysis)
                self._validate_flax_structure(summary, result, ml_analysis=ml_analysis)

            result.bytes_scanned = file_size
        except TimeoutError:
            raise
        except MemoryError:
            result.add_check(
                name="File Size Safety Check",
                passed=False,
                message="File too large to process safely - potential memory exhaustion attack",
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S902",
            )
            result.finish(success=False)
            return result
        except Exception as e:
            error_message = _redact_evidence_sample(e)
            result.add_check(
                name="Flax Msgpack Processing",
                passed=False,
                message=f"Unexpected error processing Flax msgpack file: {error_message}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error_type": type(e).__name__, "error_message": error_message},
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        result.finish(
            success=not result.has_errors and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        )
        return result
