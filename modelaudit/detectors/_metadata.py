"""Bounded, non-executing ownership checks for model metadata strings."""

import pickletools
import re
from dataclasses import dataclass, field
from io import BytesIO

from modelaudit.utils.file.detection import (
    _ONNX_MODEL_FIELD_WIRE_TYPES,
    _looks_like_onnx_graph_proto_stream,
    _read_proto_varint,
    _skip_proto_value,
)

_MAX_PICKLE_BYTES = 10 * 1024 * 1024
_MAX_PICKLE_OPS = 100_000
_MAX_METADATA_VALUE_BYTES = 64 * 1024
_METADATA_KEYS = frozenset({"docs", "documentation", "license", "licence", "readme"})
_ONNX_METADATA_KEYS = _METADATA_KEYS | {"repository", "source", "url"}
_STRING_HEADERS = {"BINUNICODE": 5, "SHORT_BINUNICODE": 2, "BINUNICODE8": 9, "BINSTRING": 5, "SHORT_BINSTRING": 2}


@dataclass(eq=False)
class _PickleValue:
    kind: str = "opaque"
    text: str | None = None
    span: tuple[int, int] | None = None
    children: list["_PickleValue"] = field(default_factory=list)
    metadata: bool = False
    escaped: bool = False


def _escape(value: _PickleValue) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if not current.escaped:
            current.escaped = True
            pending.extend(current.children)


def _add_items(target: _PickleValue, values: list[_PickleValue]) -> None:
    target.children.extend(values)
    if target.escaped or target.kind not in {"dict", "list", "tuple", "set", "frozenset"}:
        for value in values:
            _escape(value)
    elif target.kind == "dict":
        if len(values) % 2:
            raise ValueError("Incomplete dictionary entry")
        for key, value in zip(values[::2], values[1::2], strict=True):
            _escape(key)
            key_name = key.text.casefold() if key.text is not None else None
            if key_name in _METADATA_KEYS and value.kind == "string":
                value.metadata = True
            elif key_name != "metadata" or value.kind not in {"dict", "list", "tuple"}:
                _escape(value)
    else:
        for value in values:
            if value.kind == "string":
                _escape(value)


def _pickle_metadata(data: bytes) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    if len(data) > _MAX_PICKLE_BYTES:
        return [], []
    stack: list[_PickleValue] = []
    memo: dict[int, _PickleValue] = {}
    strings: list[_PickleValue] = []
    mark = _PickleValue("mark")
    stream = BytesIO(data)
    frame_end: int | None = None

    def take(count: int) -> list[_PickleValue]:
        if count > len(stack):
            raise ValueError("Incomplete pickle stack")
        if not count:
            return []
        values = stack[-count:]
        del stack[-count:]
        return values

    def take_mark() -> list[_PickleValue]:
        index = len(stack) - 1
        while index >= 0 and stack[index] is not mark:
            index -= 1
        if index < 0:
            raise ValueError("Missing pickle mark")
        values = stack[index + 1 :]
        del stack[index:]
        return values

    try:
        for count, (opcode, arg, position) in enumerate(pickletools.genops(stream)):
            if count >= _MAX_PICKLE_OPS or position is None:
                return [], []
            name = opcode.name
            end = stream.tell()
            if frame_end == position:
                frame_end = None
            if frame_end is not None and end > frame_end:
                return [], []
            if name == "FRAME":
                if not isinstance(arg, int) or frame_end is not None or end + arg > len(data):
                    return [], []
                frame_end = end + arg
            elif name == "PROTO":
                if not isinstance(arg, int) or arg > 5:
                    return [], []
            elif name == "STOP":
                if end != len(data) or len(stack) != 1:
                    return [], []
                return (
                    [value.span for value in strings if value.span is not None],
                    [
                        value.span
                        for value in strings
                        if value.span is not None and value.metadata and not value.escaped
                    ],
                )
            elif isinstance(arg, str) and name in {*_STRING_HEADERS, "UNICODE", "STRING"}:
                if name in _STRING_HEADERS:
                    span = position + _STRING_HEADERS[name], end
                elif name == "UNICODE":
                    span = position + 1, end - 1
                else:
                    span = position + 2, end - 2
                value = _PickleValue("string", arg, span)
                strings.append(value)
                stack.append(value)
            elif name == "MARK":
                stack.append(mark)
            elif name == "MEMOIZE":
                memo[len(memo)] = stack[-1]
            elif name in {"PUT", "BINPUT", "LONG_BINPUT"}:
                if not isinstance(arg, int) or arg < 0:
                    return [], []
                memo[arg] = stack[-1]
            elif name in {"GET", "BINGET", "LONG_BINGET"}:
                if not isinstance(arg, int) or arg < 0:
                    return [], []
                stack.append(memo[arg])
            elif name == "DUP":
                stack.append(stack[-1])
            elif name in {"EMPTY_DICT", "EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_SET"}:
                stack.append(_PickleValue(name.removeprefix("EMPTY_").lower()))
            elif name in {"DICT", "LIST", "TUPLE", "FROZENSET", "TUPLE1", "TUPLE2", "TUPLE3"}:
                values = take(int(name[-1])) if name[-1].isdigit() else take_mark()
                target = _PickleValue("tuple" if name.startswith("TUPLE") else name.lower())
                _add_items(target, values)
                stack.append(target)
            elif name in {"SETITEM", "SETITEMS", "APPEND", "APPENDS", "ADDITEMS"}:
                values = take(2 if name == "SETITEM" else 1) if name in {"SETITEM", "APPEND"} else take_mark()
                expected = "dict" if name.startswith("SETITEM") else "set" if name == "ADDITEMS" else "list"
                if stack[-1].kind not in {expected, "opaque"}:
                    return [], []
                _add_items(stack[-1], values)
            else:
                if pickletools.markobject in opcode.stack_before:
                    consumed = take_mark()
                    consumed.extend(take(opcode.stack_before.index(pickletools.markobject)))
                else:
                    consumed = take(len(opcode.stack_before))
                # Calls, BUILD, persistent IDs and discarded objects provide no passive ownership proof.
                for value in consumed:
                    _escape(value)
                stack.extend(_PickleValue() for _ in opcode.stack_after)
    except (ValueError, IndexError, KeyError, UnicodeError, OverflowError):
        # Incomplete or invalid serialization cannot prove passive ownership.
        return [], []
    return [], []


def _proto_fields(data: bytes, start: int, end: int, budget: list[int]) -> list[tuple[int, int, int, int]]:
    fields = []
    while start < end:
        budget[0] -= 1
        tag = _read_proto_varint(data, start, end)
        if budget[0] < 0 or tag is None or tag[0] >> 3 == 0:
            raise ValueError("Invalid or oversized protobuf metadata")
        field_number, wire, value_start = tag[0] >> 3, tag[0] & 7, tag[1]
        next_offset = _skip_proto_value(data, value_start, wire, end)
        if next_offset is None:
            raise ValueError("Incomplete protobuf field")
        if wire == 2:
            length = _read_proto_varint(data, value_start, end)
            if length is None:
                raise ValueError("Missing protobuf length")
            value_start = length[1]
        fields.append((field_number, wire, value_start, next_offset))
        start = next_offset
    return fields


def _onnx_metadata(data: bytes) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    strings: list[tuple[int, int]] = []
    metadata: list[tuple[int, int]] = []
    has_ir_version = has_graph = False
    metadata_bytes = 0
    budget = [10_000]
    try:
        for number, wire, start, end in _proto_fields(data, 0, len(data), budget):
            if _ONNX_MODEL_FIELD_WIRE_TYPES.get(number, wire) != wire:
                return [], []
            if number == 1:
                version = _read_proto_varint(data, start, end)
                has_ir_version = version is not None and 0 < version[0] <= 1000
            elif number == 7:
                _proto_fields(data, start, end, budget)
                stream = BytesIO(data)
                stream.seek(start)
                if _looks_like_onnx_graph_proto_stream(stream, end, budget) is not True:
                    return [], []
                has_graph = True
            elif number == 14:
                metadata_bytes += end - start
                if metadata_bytes > _MAX_PICKLE_BYTES:
                    return [], []
                fields = _proto_fields(data, start, end, budget)
                if len(fields) != 2 or {(field, kind) for field, kind, _, _ in fields} != {(1, 2), (2, 2)}:
                    continue
                key_field, value_field = sorted(fields)
                if key_field[3] - key_field[2] > 128:
                    continue
                key = data[key_field[2] : key_field[3]].decode("utf-8").strip().casefold()
                span = value_field[2], value_field[3]
                strings.append(span)
                if span[1] - span[0] <= _MAX_METADATA_VALUE_BYTES and (
                    key in _ONNX_METADATA_KEYS or re.fullmatch(r"url_\d+", key)
                ):
                    data[span[0] : span[1]].decode("utf-8")
                    metadata.append(span)
    except (ValueError, UnicodeError):
        return [], []
    return (strings, metadata) if has_ir_version and has_graph else ([], [])


def metadata_string_spans(data: bytes) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Return literal boundaries and proven metadata values; uncertainty preserves detections."""
    strings, metadata = _pickle_metadata(data)
    if not strings:
        strings, metadata = _onnx_metadata(data)
    return sorted(strings), sorted(span for span in metadata if span[1] - span[0] <= _MAX_METADATA_VALUE_BYTES)
