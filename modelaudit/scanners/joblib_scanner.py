"""Scanner for Joblib serialized model files (.joblib)."""

from __future__ import annotations

import builtins
import bz2
import io
import lzma
import math
import os
import pickle
import pickletools
import struct
import zlib
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from importlib.metadata import version as distribution_version
from typing import Any, ClassVar, cast

import numpy as np
from modelaudit_picklescan.call_graph import import_only_reference_is_proven_trusted

from ..detectors.cve_patterns import analyze_cve_patterns, enhance_scan_result_with_cve
from ..scanner_results import ACTIONABLE_FAILED_CHECKS_METADATA_KEY, mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, embedded_pickle_scanner
from ..utils.file.detection import read_magic_bytes
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, Check, CheckStatus, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner

_MAX_JOBLIB_DTYPE_SPEC_CHARS = 256
_MAX_JOBLIB_DTYPE_DEPTH = 16
_MAX_JOBLIB_DTYPE_FIELDS = 1024
_MAX_JOBLIB_DTYPE_VALIDATION_WORK = 65536
_MAX_JOBLIB_CONTROL_OPCODES = 1000000
_MAX_JOBLIB_ARRAY_DIMENSIONS = 64
_NUMPY_DTYPE_HAS_OBJECT_FLAG = 1
_JOBLIB_COMPRESSED_PREFIXES = (b"x", b"\x1f\x8b", b"]\x00", b"\xfd7zXZ")
_JOBLIB_NUMPY_ARRAY_WRAPPER_MODULE = "joblib.numpy_pickle"
_JOBLIB_NUMPY_ARRAY_WRAPPER_NAME = "NumpyArrayWrapper"
_JOBLIB_NUMPY_ARRAY_WRAPPER_REFERENCE = f"{_JOBLIB_NUMPY_ARRAY_WRAPPER_MODULE}.{_JOBLIB_NUMPY_ARRAY_WRAPPER_NAME}"
_VALIDATED_JOBLIB_NUMPY_ARRAY_CONTROL_REFERENCES = frozenset(
    {
        _JOBLIB_NUMPY_ARRAY_WRAPPER_REFERENCE,
        "numpy.dtype",
        "numpy.ndarray",
        "numpy.matrix",
        "numpy.memmap",
    }
)


@dataclass(frozen=True)
class _JoblibPickleGlobal:
    module: str
    name: str
    occurrence_id: int | None = field(default=None, compare=False)


_JOBLIB_NUMPY_ARRAY_SUBCLASSES = {
    _JoblibPickleGlobal("numpy", "ndarray"),
    _JoblibPickleGlobal("numpy", "matrix"),
    _JoblibPickleGlobal("numpy", "memmap"),
}
_TRUNCATED_RAW_PICKLE_SIGNAL_OPCODES = frozenset(
    {
        "EXT1",
        "EXT2",
        "EXT4",
        "GLOBAL",
        "INST",
        "NEWOBJ",
        "NEWOBJ_EX",
        "PERSID",
        "BINPERSID",
        "STACK_GLOBAL",
    }
)
_PICKLE_OPCODE_BY_BYTE = {ord(opcode.code): opcode for opcode in pickletools.opcodes}
_PICKLE_TWO_LINE_ARGUMENT_OPCODES = frozenset({"GLOBAL", "INST"})
_PICKLE_LENGTH_PREFIX_BYTES = {-2: 1, -3: 4, -4: 4, -5: 8}


def _next_pickle_opcode_offset(data: bytes, offset: int, opcode: Any) -> int | None:
    argument = opcode.arg
    if argument is None:
        return offset + 1

    argument_size = argument.n
    if argument_size >= 0:
        next_offset = offset + 1 + argument_size
        return next_offset if next_offset <= len(data) else None
    if argument_size == -1:
        next_offset = offset + 1
        line_count = 2 if opcode.name in _PICKLE_TWO_LINE_ARGUMENT_OPCODES else 1
        for _ in range(line_count):
            newline = data.find(b"\n", next_offset)
            if newline < 0:
                return None
            next_offset = newline + 1
        return next_offset

    prefix_size = _PICKLE_LENGTH_PREFIX_BYTES.get(argument_size)
    if prefix_size is None:
        return None
    prefix_start = offset + 1
    payload_start = prefix_start + prefix_size
    if payload_start > len(data):
        return None
    payload_size = int.from_bytes(data[prefix_start:payload_start], "little")
    if payload_size > len(data) - payload_start:
        return None
    return payload_start + payload_size


def _apply_pickle_stack_effect(stack: list[bool], opcode: Any) -> bool:
    before = [item.name for item in opcode.stack_before]
    if "stackslice" in before:
        required_before_mark = before.index("mark")
        try:
            mark_index = len(stack) - 1 - stack[::-1].index(True)
        except ValueError:
            return False
        if mark_index < required_before_mark:
            return False
        del stack[mark_index - required_before_mark :]
    else:
        required = len(before)
        if required > len(stack):
            return False
        if required:
            del stack[-required:]
    stack.extend(item.name == "mark" for item in opcode.stack_after)
    return True


@dataclass
class _JoblibPickleObject:
    reference: object
    args: object
    state: object = None
    constructor_opcode: str = "UNKNOWN"
    reduction_id: int | None = None


@dataclass
class _JoblibDtypeValidationContext:
    remaining_work: int = _MAX_JOBLIB_DTYPE_VALIDATION_WORK
    dtype_cache: dict[int, tuple[_JoblibPickleObject, np.dtype[Any]]] = field(default_factory=dict)
    dtype_in_progress: list[_JoblibPickleObject] = field(default_factory=list)
    metadata_cache: dict[int, tuple[object, bool]] = field(default_factory=dict)
    metadata_in_progress: list[object] = field(default_factory=list)
    validated_codec_encode_reduction_ids: set[int] = field(default_factory=set)
    validated_codec_encode_global_ids: set[int] = field(default_factory=set)
    validated_numpy_dtype_global_ids: set[int] = field(default_factory=set)

    def consume(self, amount: int = 1) -> None:
        if amount > self.remaining_work:
            raise pickle.UnpicklingError("NumpyArrayWrapper dtype validation is too complex")
        self.remaining_work -= amount

    def clear_caches(self) -> None:
        self.dtype_cache.clear()
        self.metadata_cache.clear()


@dataclass(frozen=True)
class _SanitizedJoblibPayload:
    payload: bytes
    raw_array_count: int
    has_only_validated_codec_encodes: bool
    validated_control_occurrences: dict[str, frozenset[int]]


def _is_safe_dtype_metadata(
    value: object,
    *,
    depth: int,
    context: _JoblibDtypeValidationContext | None = None,
) -> bool:
    """Accept the bounded primitive metadata used by datetime and timedelta dtypes."""
    if context is None:
        context = _JoblibDtypeValidationContext()
    if depth > _MAX_JOBLIB_DTYPE_DEPTH:
        return False
    context.consume()
    if value is None or type(value) in {bool, int, str, bytes}:
        return True
    if isinstance(value, _JoblibPickleObject):
        reference = value.reference
        if not isinstance(reference, _JoblibPickleGlobal):
            return False
        is_safe_codec_encode = (
            reference == _JoblibPickleGlobal("_codecs", "encode")
            and value.state is None
            and isinstance(value.args, tuple)
            and len(value.args) == 2
            and isinstance(value.args[0], str)
            and len(value.args[0]) <= _MAX_JOBLIB_DTYPE_SPEC_CHARS
            and value.args[1] == "latin1"
        )
        if is_safe_codec_encode and value.reduction_id is not None:
            context.validated_codec_encode_reduction_ids.add(value.reduction_id)
            if reference.occurrence_id is not None:
                context.validated_codec_encode_global_ids.add(reference.occurrence_id)
        return is_safe_codec_encode
    items: tuple[object, ...]
    if isinstance(value, (tuple, list, set, frozenset)):
        if len(value) > _MAX_JOBLIB_DTYPE_FIELDS:
            return False
        items = tuple(value)
    elif isinstance(value, dict):
        if len(value) > _MAX_JOBLIB_DTYPE_FIELDS:
            return False
        items = tuple(item for entry in value.items() for item in entry)
    else:
        return False

    object_id = id(value)
    cached_metadata = context.metadata_cache.get(object_id)
    if cached_metadata is not None and cached_metadata[0] is value:
        return cached_metadata[1]
    if any(item is value for item in context.metadata_in_progress):
        return False

    context.consume(len(items))
    context.metadata_in_progress.append(value)
    try:
        result = all(
            _is_safe_dtype_metadata(
                item,
                depth=depth + 1,
                context=context,
            )
            for item in items
        )
    finally:
        context.metadata_in_progress.pop()
    context.metadata_cache[object_id] = (value, result)
    return result


def _validated_numpy_dtype(
    dtype_object: object,
    *,
    depth: int = 0,
    context: _JoblibDtypeValidationContext | None = None,
) -> np.dtype[Any]:
    """Reconstruct only the non-object dtype facts needed to size raw array data."""
    if context is None:
        context = _JoblibDtypeValidationContext()
    if depth > _MAX_JOBLIB_DTYPE_DEPTH:
        raise pickle.UnpicklingError("NumpyArrayWrapper dtype nesting is too deep")
    if (
        not isinstance(dtype_object, _JoblibPickleObject)
        or dtype_object.reference != _JoblibPickleGlobal("numpy", "dtype")
        or not isinstance(dtype_object.args, tuple)
        or not 1 <= len(dtype_object.args) <= 3
        or not all(type(argument) is bool for argument in dtype_object.args[1:])
    ):
        raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype")
    dtype_reference = dtype_object.reference

    object_id = id(dtype_object)
    cached_dtype = context.dtype_cache.get(object_id)
    if cached_dtype is not None and cached_dtype[0] is dtype_object:
        return cached_dtype[1]
    if any(item is dtype_object for item in context.dtype_in_progress):
        raise pickle.UnpicklingError("Recursive NumpyArrayWrapper dtype")
    context.consume()
    context.dtype_in_progress.append(dtype_object)

    try:
        dtype_spec = dtype_object.args[0]
        if not isinstance(dtype_spec, str) or len(dtype_spec) > _MAX_JOBLIB_DTYPE_SPEC_CHARS:
            raise pickle.UnpicklingError("Unsupported NumpyArrayWrapper dtype specification")
        try:
            dtype = np.dtype(dtype_spec)
        except (TypeError, ValueError) as exc:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype specification") from exc
        if dtype.hasobject:
            raise pickle.UnpicklingError("Object arrays require nested pickle analysis")
        state = dtype_object.state
        if state is None:
            if dtype_reference.occurrence_id is not None:
                context.validated_numpy_dtype_global_ids.add(dtype_reference.occurrence_id)
            context.dtype_cache[object_id] = (dtype_object, dtype)
            return dtype
        if not isinstance(state, tuple) or len(state) not in {8, 9}:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype state")

        version, byteorder, subarray, names, fields, itemsize, alignment, flags = state[:8]
        if type(version) is not int or not 0 <= version <= 4:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype version")
        if byteorder not in {"<", ">", "|", "="}:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype byte order")
        if type(itemsize) is not int or itemsize not in {-1, dtype.itemsize}:
            raise pickle.UnpicklingError("Inconsistent NumpyArrayWrapper dtype item size")
        if type(alignment) is not int or alignment < -1:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype alignment")
        if type(flags) is not int or flags < 0 or flags & _NUMPY_DTYPE_HAS_OBJECT_FLAG:
            raise pickle.UnpicklingError("Object arrays require nested pickle analysis")

        if subarray is not None:
            if (
                not isinstance(subarray, tuple)
                or len(subarray) != 2
                or not isinstance(subarray[1], tuple)
                or not 1 <= len(subarray[1]) <= _MAX_JOBLIB_ARRAY_DIMENSIONS
                or not all(type(dimension) is int and dimension > 0 for dimension in subarray[1])
            ):
                raise pickle.UnpicklingError("Invalid NumpyArrayWrapper subarray dtype")
            context.consume(len(subarray[1]))
            base_dtype = _validated_numpy_dtype(
                subarray[0],
                depth=depth + 1,
                context=context,
            )
            subarray_items = math.prod(subarray[1])
            if subarray_items > dtype.itemsize or base_dtype.itemsize * subarray_items != dtype.itemsize:
                raise pickle.UnpicklingError("Inconsistent NumpyArrayWrapper subarray dtype")

        if names is None or fields is None:
            if names is not None or fields is not None:
                raise pickle.UnpicklingError("Incomplete NumpyArrayWrapper structured dtype")
        else:
            if (
                not isinstance(names, tuple)
                or not isinstance(fields, dict)
                or len(names) > _MAX_JOBLIB_DTYPE_FIELDS
                or len(fields) > _MAX_JOBLIB_DTYPE_FIELDS * 2
                or not all(isinstance(name, str) for name in names)
                or not all(name in fields for name in names)
            ):
                raise pickle.UnpicklingError("Invalid NumpyArrayWrapper structured dtype")
            context.consume(len(names) + len(fields))
            for field_name, field in fields.items():
                if (
                    not isinstance(field_name, str)
                    or not isinstance(field, tuple)
                    or len(field) not in {2, 3}
                    or type(field[1]) is not int
                    or field[1] < 0
                    or (len(field) == 3 and field[2] is not None and not isinstance(field[2], str))
                ):
                    raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype field")
                field_dtype = _validated_numpy_dtype(
                    field[0],
                    depth=depth + 1,
                    context=context,
                )
                if field[1] > dtype.itemsize or field_dtype.itemsize > dtype.itemsize - field[1]:
                    raise pickle.UnpicklingError("NumpyArrayWrapper dtype field exceeds its item size")

        if len(state) == 9 and not _is_safe_dtype_metadata(
            state[8],
            depth=depth + 1,
            context=context,
        ):
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper dtype metadata")
        if dtype_reference.occurrence_id is not None:
            context.validated_numpy_dtype_global_ids.add(dtype_reference.occurrence_id)
        context.dtype_cache[object_id] = (dtype_object, dtype)
        return dtype
    finally:
        context.dtype_in_progress.pop()


class _SafeJoblibUnpickler(pickle._Unpickler):  # type: ignore[attr-defined]
    """Parse Joblib pickle control data without importing or invoking globals."""

    dispatch: ClassVar[dict[int, Callable[[Any], None]]] = pickle._Unpickler.dispatch.copy()  # type: ignore[attr-defined]

    def __init__(self, stream: io.BytesIO):
        super().__init__(stream)
        self._stream = stream
        self.raw_array_spans: list[tuple[int, int]] = []
        self.codec_encode_reduction_ids: set[int] = set()
        self.codec_encode_global_ids: set[int] = set()
        self.global_ids_by_reference: dict[str, list[int]] = {}
        self.validated_numpy_array_control_global_ids: set[int] = set()
        self.dtype_validation_context = _JoblibDtypeValidationContext()
        self._global_count = 0
        self._reduction_count = 0
        self._remaining_control_opcodes = _MAX_JOBLIB_CONTROL_OPCODES

    def load(self) -> object:
        """Parse one pickle while bounding control-stream materialization."""
        if not hasattr(self, "_file_read"):
            raise pickle.UnpicklingError(f"{self.__class__.__name__}.__init__() was not called")
        self._unframer = pickle._Unframer(self._file_read, self._file_readline)  # type: ignore[attr-defined]
        self.read = self._unframer.read
        self.readinto = self._unframer.readinto
        self.readline = self._unframer.readline
        self.metastack: list[list[object]] = []
        self.stack: list[object] = []
        self.append = self.stack.append
        self.proto = 0
        try:
            while True:
                if self._remaining_control_opcodes <= 0:
                    raise pickle.UnpicklingError("Joblib pickle control stream is too complex")
                self._remaining_control_opcodes -= 1
                key = self.read(1)
                if not key:
                    raise EOFError
                self.dispatch[key[0]](self)
        except pickle._Stop as stop:  # type: ignore[attr-defined]
            return stop.value

    def find_class(self, module: str, name: str) -> _JoblibPickleGlobal:
        self._global_count += 1
        reference = _JoblibPickleGlobal(module, name, self._global_count)
        self.global_ids_by_reference.setdefault(f"{module}.{name}", []).append(self._global_count)
        if reference == _JoblibPickleGlobal("_codecs", "encode"):
            self.codec_encode_global_ids.add(self._global_count)
        return reference

    @property
    def _pickle_stack(self) -> list[object]:
        return self.stack

    @property
    def _pickle_unframer(self) -> Any:
        return self._unframer  # type: ignore[attr-defined,no-any-return]

    def _pickle_append(self, value: object) -> None:
        self.append(value)  # type: ignore[attr-defined]

    def _pickle_pop_mark(self) -> list[object]:
        return cast(list[object], self.pop_mark())  # type: ignore[attr-defined]

    def _remaining_pickle_bytes(self) -> int:
        frame = self._pickle_unframer.current_frame
        if frame is not None:
            return len(frame.getbuffer()) - frame.tell()
        return len(self._stream.getbuffer()) - self._stream.tell()

    def load_bytearray8(self) -> None:
        """Consume protocol-5 bytearrays without allocating their declared size."""
        (size,) = struct.unpack("<Q", self.read(8))
        if size > self._remaining_pickle_bytes():
            raise pickle.UnpicklingError("Truncated Joblib BYTEARRAY8 payload")
        remaining = size
        while remaining:
            chunk_size = min(remaining, 64 * 1024)
            if len(self.read(chunk_size)) != chunk_size:
                raise pickle.UnpicklingError("Truncated Joblib BYTEARRAY8 payload")
            remaining -= chunk_size
        self._pickle_append(bytearray())

    def load_reduce(self) -> None:
        args = self._pickle_stack.pop()
        reference = self._pickle_stack.pop()
        self._reduction_count += 1
        instance = _JoblibPickleObject(
            reference,
            args,
            constructor_opcode="REDUCE",
            reduction_id=self._reduction_count,
        )
        if reference == _JoblibPickleGlobal("_codecs", "encode"):
            self.codec_encode_reduction_ids.add(self._reduction_count)
        self._pickle_append(instance)

    def load_newobj(self) -> None:
        args = self._pickle_stack.pop()
        reference = self._pickle_stack.pop()
        self._pickle_append(_JoblibPickleObject(reference, args, constructor_opcode="NEWOBJ"))

    def load_newobj_ex(self) -> None:
        kwargs = self._pickle_stack.pop()
        args = self._pickle_stack.pop()
        reference = self._pickle_stack.pop()
        self._pickle_append(_JoblibPickleObject(reference, (args, kwargs), constructor_opcode="NEWOBJ_EX"))

    def load_build(self) -> None:
        state = self._pickle_stack.pop()
        instance = self._pickle_stack[-1]
        if not isinstance(instance, _JoblibPickleObject):
            raise pickle.UnpicklingError("Unsupported Joblib BUILD target")
        self.dtype_validation_context.clear_caches()
        instance.state = state
        if instance.reference == _JoblibPickleGlobal("joblib.numpy_pickle", "NumpyArrayWrapper"):
            self._skip_numpy_array_payload(instance, state)

    def load_inst(self) -> None:
        readline = cast(Callable[[], bytes], self.readline)  # type: ignore[attr-defined]
        module = readline()[:-1].decode("ascii")
        name = readline()[:-1].decode("ascii")
        self._pickle_append(
            _JoblibPickleObject(
                _JoblibPickleGlobal(module, name),
                tuple(self._pickle_pop_mark()),
                constructor_opcode="INST",
            )
        )

    def load_obj(self) -> None:
        args = self._pickle_pop_mark()
        reference = args.pop(0)
        self._pickle_append(_JoblibPickleObject(reference, tuple(args), constructor_opcode="OBJ"))

    def load_unsupported_reference(self) -> None:
        raise pickle.UnpicklingError("Unsupported persistent or extension reference")

    def _skip_numpy_array_payload(self, instance: _JoblibPickleObject, state: object) -> None:
        if instance.constructor_opcode != "NEWOBJ" or instance.args != ():
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper construction")
        if not isinstance(state, dict):
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper state")

        required_keys = {"subclass", "shape", "order", "dtype", "allow_mmap"}
        allowed_keys = required_keys | {"numpy_array_alignment_bytes"}
        state_keys = set(state)
        if state_keys != required_keys and state_keys != allowed_keys:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper state fields")
        subclass = state.get("subclass")
        if subclass not in _JOBLIB_NUMPY_ARRAY_SUBCLASSES:
            raise pickle.UnpicklingError("Unsupported NumpyArrayWrapper subclass")
        if state.get("order") not in {"C", "F"} or type(state.get("allow_mmap")) is not bool:
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper read options")

        shape = state.get("shape")
        if (
            not isinstance(shape, tuple)
            or len(shape) > _MAX_JOBLIB_ARRAY_DIMENSIONS
            or not all(type(dimension) is int and dimension >= 0 for dimension in shape)
        ):
            raise pickle.UnpicklingError("Invalid NumpyArrayWrapper shape")
        dtype = _validated_numpy_dtype(
            state.get("dtype"),
            context=self.dtype_validation_context,
        )

        frame = self._pickle_unframer.current_frame
        if frame is not None:
            if frame.read(1):
                raise pickle.UnpicklingError("NumpyArrayWrapper BUILD did not end the pickle frame")
            self._pickle_unframer.current_frame = None

        raw_start = self._stream.tell()
        alignment = state.get("numpy_array_alignment_bytes")
        if alignment is not None:
            if type(alignment) is not int or not 1 <= alignment <= 255:
                raise pickle.UnpicklingError("Invalid NumpyArrayWrapper alignment")
            padding_byte = self._stream.read(1)
            if len(padding_byte) != 1:
                raise pickle.UnpicklingError("Missing NumpyArrayWrapper alignment byte")
            padding_length = padding_byte[0]
            expected_padding = alignment - ((raw_start + 1) % alignment)
            if padding_length != expected_padding or self._stream.read(padding_length) != b"\xff" * padding_length:
                raise pickle.UnpicklingError("Invalid NumpyArrayWrapper alignment padding")

        remaining_bytes = len(self._stream.getbuffer()) - self._stream.tell()
        item_count = 1
        for dimension in shape:
            if dimension and item_count > remaining_bytes // dimension:
                raise pickle.UnpicklingError("NumpyArrayWrapper shape exceeds the remaining payload")
            item_count *= dimension
        if dtype.itemsize and item_count > remaining_bytes // dtype.itemsize:
            raise pickle.UnpicklingError("NumpyArrayWrapper data exceeds the remaining payload")
        raw_size = item_count * dtype.itemsize
        self._stream.seek(raw_size, io.SEEK_CUR)
        self.raw_array_spans.append((raw_start, self._stream.tell()))
        if isinstance(subclass, _JoblibPickleGlobal) and subclass.occurrence_id is not None:
            self.validated_numpy_array_control_global_ids.add(subclass.occurrence_id)
        wrapper_reference = cast(_JoblibPickleGlobal, instance.reference)
        if wrapper_reference.occurrence_id is not None:
            self.validated_numpy_array_control_global_ids.add(wrapper_reference.occurrence_id)
        self.validated_numpy_array_control_global_ids.update(
            self.dtype_validation_context.validated_numpy_dtype_global_ids
        )

    def validated_control_occurrences(self) -> dict[str, frozenset[int]]:
        occurrences: dict[str, frozenset[int]] = {}
        for import_reference, global_ids in self.global_ids_by_reference.items():
            validated = {
                occurrence
                for occurrence, global_id in enumerate(global_ids, start=1)
                if global_id in self.validated_numpy_array_control_global_ids
            }
            if validated:
                occurrences[import_reference] = frozenset(validated)
        return occurrences


_SafeJoblibUnpickler.dispatch[pickle.REDUCE[0]] = _SafeJoblibUnpickler.load_reduce
_SafeJoblibUnpickler.dispatch[pickle.BYTEARRAY8[0]] = _SafeJoblibUnpickler.load_bytearray8
_SafeJoblibUnpickler.dispatch[pickle.NEWOBJ[0]] = _SafeJoblibUnpickler.load_newobj
_SafeJoblibUnpickler.dispatch[pickle.NEWOBJ_EX[0]] = _SafeJoblibUnpickler.load_newobj_ex
_SafeJoblibUnpickler.dispatch[pickle.BUILD[0]] = _SafeJoblibUnpickler.load_build
_SafeJoblibUnpickler.dispatch[pickle.INST[0]] = _SafeJoblibUnpickler.load_inst
_SafeJoblibUnpickler.dispatch[pickle.OBJ[0]] = _SafeJoblibUnpickler.load_obj
_SafeJoblibUnpickler.dispatch[pickle.PERSID[0]] = _SafeJoblibUnpickler.load_unsupported_reference
_SafeJoblibUnpickler.dispatch[pickle.BINPERSID[0]] = _SafeJoblibUnpickler.load_unsupported_reference
_SafeJoblibUnpickler.dispatch[pickle.EXT1[0]] = _SafeJoblibUnpickler.load_unsupported_reference
_SafeJoblibUnpickler.dispatch[pickle.EXT2[0]] = _SafeJoblibUnpickler.load_unsupported_reference
_SafeJoblibUnpickler.dispatch[pickle.EXT4[0]] = _SafeJoblibUnpickler.load_unsupported_reference


def _pickle_without_joblib_numpy_array_data(payload: bytes) -> _SanitizedJoblibPayload | None:
    """Remove only raw ndarray spans proven by static NumpyArrayWrapper state."""
    if b"NumpyArrayWrapper" not in payload:
        return None

    stream = io.BytesIO(payload)
    parser = _SafeJoblibUnpickler(stream)
    try:
        parser.load()
    except Exception:
        return None

    frame = parser._pickle_unframer.current_frame
    if (frame is not None and frame.read(1)) or stream.tell() != len(payload) or not parser.raw_array_spans:
        return None

    sanitized = bytearray()
    cursor = 0
    for start, end in parser.raw_array_spans:
        if start < cursor or end < start or end > len(payload):
            return None
        sanitized.extend(payload[cursor:start])
        cursor = end
    sanitized.extend(payload[cursor:])
    has_only_validated_codec_encodes = (
        bool(parser.codec_encode_global_ids)
        and parser.codec_encode_global_ids == parser.dtype_validation_context.validated_codec_encode_global_ids
        and parser.codec_encode_reduction_ids == parser.dtype_validation_context.validated_codec_encode_reduction_ids
    )
    return _SanitizedJoblibPayload(
        payload=bytes(sanitized),
        raw_array_count=len(parser.raw_array_spans),
        has_only_validated_codec_encodes=has_only_validated_codec_encodes,
        validated_control_occurrences=parser.validated_control_occurrences(),
    )


class JoblibScanner(BaseScanner):
    """Scanner for joblib serialized files."""

    name = "joblib"
    description = "Scans joblib files by decompressing and analyzing embedded pickle"
    supported_extensions: ClassVar[list[str]] = [".joblib"]

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize Joblib scanning limits and the embedded Pickle scanner."""
        super().__init__(config)
        self.pickle_scanner, self.scanner_selection = embedded_pickle_scanner(self.config, PickleScanner)
        # Security limits
        self.max_decompression_ratio = self.config.get("max_decompression_ratio", 100.0)
        has_explicit_read_budget = "max_file_read_size" in self.config
        configured_file_size = self.config.get("max_file_size")
        public_file_size_budget = (
            configured_file_size
            if not isinstance(configured_file_size, bool)
            and isinstance(configured_file_size, int)
            and configured_file_size > 0
            else None
        )
        decompressed_read_budget = (
            self.max_file_read_size if self.max_file_read_size > 0 else self.default_max_file_read_size
        )
        if not has_explicit_read_budget and public_file_size_budget is not None:
            decompressed_read_budget = public_file_size_budget
        configured_decompressed_size = self._normalize_positive_int_config(
            self.config.get("max_decompressed_size", decompressed_read_budget),
            decompressed_read_budget,
        )
        self.max_decompressed_size = configured_decompressed_size
        if has_explicit_read_budget and self.max_file_read_size > 0:
            self.max_decompressed_size = min(self.max_decompressed_size, self.max_file_read_size)
        elif not has_explicit_read_budget and public_file_size_budget is not None:
            self.max_decompressed_size = min(self.max_decompressed_size, public_file_size_budget)
        elif configured_file_size != 0 and self.max_file_read_size > 0:
            self.max_decompressed_size = min(self.max_decompressed_size, self.max_file_read_size)
        self.chunk_size = self.config.get("chunk_size", 8192)  # 8KB chunks

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Return True for existing `.joblib` files."""
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        return ext == ".joblib"

    def _read_file_safely(self, path: str) -> bytes:
        """Read file in chunks using the base class helper."""
        return super()._read_file_safely(path)

    def _max_decompressed_output_bytes(self, compressed_size: int) -> int:
        """Compute the effective decompression output cap for one compressed payload."""
        max_by_ratio = self.max_decompressed_size
        if compressed_size > 0:
            max_by_ratio = int(self.max_decompression_ratio * compressed_size)
        return min(self.max_decompressed_size, max_by_ratio)

    def _check_decompressed_size(self, decompressed_size: int) -> None:
        """Fail when the decompressed payload exceeds the absolute size limit."""
        if decompressed_size > self.max_decompressed_size:
            raise ValueError(
                f"Decompressed size too large: {decompressed_size} bytes (max: {self.max_decompressed_size})",
            )

    def _check_decompression_ratio(self, decompressed_size: int, compressed_size: int) -> None:
        """Fail when decompression expands beyond the configured ratio limit."""
        if compressed_size <= 0:
            return

        ratio = decompressed_size / compressed_size
        if ratio > self.max_decompression_ratio:
            raise ValueError(
                f"Suspicious compression ratio: {ratio:.1f}x (max: {self.max_decompression_ratio}x) - "
                f"possible compression bomb"
            )

    def _decompress_with_limited_output(self, decompressor: Any, data: bytes) -> bytes:
        """Decompress one stream while enforcing absolute-size and ratio budgets."""
        compressed_size = len(data)
        max_output_bytes = self._max_decompressed_output_bytes(compressed_size)
        output_limit = max_output_bytes + 1

        decompressed = bytearray(decompressor.decompress(data, output_limit))
        if len(decompressed) > output_limit:
            raise ValueError("Internal decompression limit exceeded")

        self._check_decompressed_size(len(decompressed))
        self._check_decompression_ratio(len(decompressed), compressed_size)

        if len(decompressed) == output_limit:
            raise ValueError(
                f"Decompressed size too large: {len(decompressed)} bytes (max: {max_output_bytes})",
            )

        remaining_output_budget = output_limit - len(decompressed)
        if remaining_output_budget > 0 and hasattr(decompressor, "flush"):
            decompressed.extend(decompressor.flush(remaining_output_budget))
            self._check_decompressed_size(len(decompressed))
            self._check_decompression_ratio(len(decompressed), compressed_size)
            if len(decompressed) > output_limit:
                raise ValueError(
                    f"Decompressed size too large: {len(decompressed)} bytes (max: {max_output_bytes})",
                )

        if getattr(decompressor, "unused_data", b""):
            raise ValueError("Trailing data found after compressed joblib stream")

        if not getattr(decompressor, "eof", True):
            raise ValueError("Incomplete compressed joblib stream")

        return bytes(decompressed)

    def _safe_decompress(self, data: bytes) -> bytes:
        """Safely decompress data with bomb protection"""
        codec_attempts: list[tuple[str, Callable[[], Any]]] = [
            ("zlib", zlib.decompressobj),
            ("gzip", lambda: zlib.decompressobj(zlib.MAX_WBITS | 16)),
            ("bz2", bz2.BZ2Decompressor),
            ("lzma", lzma.LZMADecompressor),
        ]
        decode_errors: list[str] = []

        for codec_name, decompressor_factory in codec_attempts:
            try:
                return self._decompress_with_limited_output(decompressor_factory(), data)
            except (OSError, EOFError, lzma.LZMAError, zlib.error) as exc:
                decode_errors.append(f"{codec_name}: {exc}")

        raise ValueError(
            "Unable to decompress joblib file: " + "; ".join(decode_errors or ["no supported decoder matched"]),
        )

    def _scan_pickle_payload(self, payload: bytes, result: ScanResult, context: str) -> None:
        """Analyze a raw or decompressed pickle payload with CVE and opcode checks."""
        sanitized = _pickle_without_joblib_numpy_array_data(payload)
        scan_payload = sanitized.payload if sanitized is not None else payload
        raw_array_count = sanitized.raw_array_count if sanitized is not None else 0
        has_only_validated_codec_encodes = (
            sanitized.has_only_validated_codec_encodes if sanitized is not None else False
        )
        validated_control_occurrences = sanitized.validated_control_occurrences if sanitized is not None else {}
        self._detect_cve_patterns(scan_payload, result, context)
        self._scan_for_joblib_specific_threats(scan_payload, result, context)

        if self.pickle_scanner is None:
            add_scanner_selection_skip_check(
                result,
                context,
                "pickle",
                self.scanner_selection,
                context="embedded joblib pickle analysis",
            )
            result.bytes_scanned = len(payload)
            return

        with io.BytesIO(scan_payload) as file_like:
            sub_result = self.pickle_scanner.scan_stream(
                file_like,
                len(scan_payload),
                source=context,
            )
        result.merge(sub_result)
        if has_only_validated_codec_encodes:
            self._remove_validated_dtype_codec_findings(result)
        if raw_array_count and self._numpy_array_wrapper_origin_is_trusted():
            self._remove_validated_numpy_array_wrapper_findings(result, validated_control_occurrences)
        result.metadata.pop("trusted_incomplete_tail", None)
        result.metadata.pop("trusted_incomplete_tail_reason", None)
        has_security_findings = any(
            issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues
        ) or any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        )
        if (
            raw_array_count
            and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
            and not has_security_findings
        ):
            result.trust_merged_child_failures()
            result.metadata["trusted_incomplete_tail"] = True
            result.metadata["trusted_incomplete_tail_reason"] = "joblib_numpy_array_payload"
            result.metadata["joblib_numpy_array_payload_count"] = raw_array_count
            if result.metadata.get("pickle_verdict") in {"suspicious", "unknown"}:
                result.metadata["pickle_verdict"] = "clean"
        else:
            self._downgrade_embedded_pickle_parse_errors(result)
        result.bytes_scanned = len(payload)

    @staticmethod
    def _remove_validated_dtype_codec_findings(result: ScanResult) -> None:
        def is_validated_dtype_codec_finding(finding: Any) -> bool:
            return (
                finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
                and finding.details.get("associated_global") == "_codecs.encode"
            )

        result.issues = [issue for issue in result.issues if not is_validated_dtype_codec_finding(issue)]
        result.checks = [check for check in result.checks if not is_validated_dtype_codec_finding(check)]

    @staticmethod
    def _numpy_array_wrapper_origin_is_trusted() -> bool:
        try:
            return import_only_reference_is_proven_trusted(
                _JOBLIB_NUMPY_ARRAY_WRAPPER_MODULE,
                _JOBLIB_NUMPY_ARRAY_WRAPPER_NAME,
            )
        except Exception:
            return False

    @staticmethod
    def _private_actionable_failed_check_entry(check: Check) -> dict[str, str] | None:
        if check.status != CheckStatus.FAILED or check.rule_code is None:
            return None
        return {
            "name": check.name,
            "rule_code": check.rule_code,
        }

    @staticmethod
    def _remove_private_actionable_failed_check_entries(
        result: ScanResult,
        entries_to_remove: list[dict[str, str]],
    ) -> None:
        private_failed_checks = result._private_metadata.get(ACTIONABLE_FAILED_CHECKS_METADATA_KEY)
        if not entries_to_remove or not isinstance(private_failed_checks, list):
            return

        unmatched_entries = list(entries_to_remove)
        filtered_entries: list[Any] = []
        for entry in private_failed_checks:
            if isinstance(entry, dict):
                matched_index = next(
                    (
                        index
                        for index, candidate in enumerate(unmatched_entries)
                        if entry.get("name") == candidate["name"] and entry.get("rule_code") == candidate["rule_code"]
                    ),
                    None,
                )
                if matched_index is not None:
                    del unmatched_entries[matched_index]
                    continue
            filtered_entries.append(entry)

        if filtered_entries:
            result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY] = filtered_entries
        else:
            result._private_metadata.pop(ACTIONABLE_FAILED_CHECKS_METADATA_KEY, None)

    @staticmethod
    def _remove_validated_numpy_array_wrapper_findings(
        result: ScanResult,
        validated_control_occurrences: dict[str, frozenset[int]],
    ) -> None:
        def validated_candidate_reference(finding: Any) -> str | None:
            details = getattr(finding, "details", {})
            if not isinstance(details, dict):
                return None
            import_reference = details.get("import_reference")
            if import_reference not in _VALIDATED_JOBLIB_NUMPY_ARRAY_CONTROL_REFERENCES:
                return None
            if (
                getattr(finding, "rule_code", None) == "NON_ALLOWLISTED_GLOBAL"
                or details.get("notice_code") == "call_graph_source_unavailable"
            ):
                return str(import_reference)
            return None

        def reference_origin_is_trusted(finding: Any) -> bool:
            details = getattr(finding, "details", {})
            if not isinstance(details, dict):
                return False
            module = details.get("module")
            name = details.get("name")
            if not isinstance(module, str) or not isinstance(name, str):
                return False
            try:
                return import_only_reference_is_proven_trusted(module, name)
            except Exception:
                return False

        def reference_dict_origin_is_trusted(reference: dict[str, Any]) -> bool:
            module = reference.get("module")
            name = reference.get("name")
            if not isinstance(module, str) or not isinstance(name, str):
                return False
            try:
                return import_only_reference_is_proven_trusted(module, name)
            except Exception:
                return False

        def finding_position(finding: Any) -> int:
            details = getattr(finding, "details", {})
            position = details.get("position") if isinstance(details, dict) else None
            return position if type(position) is int else 1 << 62

        def reference_position(reference: dict[str, Any]) -> int:
            position = reference.get("position")
            return position if type(position) is int else 1 << 62

        def origin_review_references_are_validated() -> bool:
            import_references = result.metadata.get("import_references")
            if not isinstance(import_references, list | tuple):
                return False
            origin_review_references = [
                reference
                for reference in import_references
                if isinstance(reference, dict)
                and reference.get("requires_origin_verification") is True
                and reference.get("import_reference") in _VALIDATED_JOBLIB_NUMPY_ARRAY_CONTROL_REFERENCES
            ]
            if not origin_review_references:
                return False

            seen_occurrences: dict[str, int] = {}
            seen_positions: dict[str, int] = {}
            for reference in sorted(origin_review_references, key=reference_position):
                import_reference = str(reference.get("import_reference"))
                position = reference_position(reference)
                if seen_positions.get(import_reference) != position:
                    seen_occurrences[import_reference] = seen_occurrences.get(import_reference, 0) + 1
                seen_positions[import_reference] = position
                occurrence = seen_occurrences[import_reference]
                if occurrence not in validated_control_occurrences.get(
                    import_reference, frozenset()
                ) or not reference_dict_origin_is_trusted(reference):
                    return False
            return True

        candidates: list[tuple[int, int, str, Any]] = []
        for sequence, finding in enumerate((*result.issues, *result.checks)):
            import_reference = validated_candidate_reference(finding)
            if import_reference is not None:
                candidates.append((finding_position(finding), sequence, import_reference, finding))

        validated_finding_ids: set[int] = set()
        seen_occurrences: dict[str, int] = {}
        seen_positions: dict[str, int] = {}
        for _position, _sequence, import_reference, finding in sorted(candidates):
            if seen_positions.get(import_reference) != _position:
                seen_occurrences[import_reference] = seen_occurrences.get(import_reference, 0) + 1
            seen_positions[import_reference] = _position
            occurrence = seen_occurrences[import_reference]
            if occurrence in validated_control_occurrences.get(
                import_reference, frozenset()
            ) and reference_origin_is_trusted(finding):
                validated_finding_ids.add(builtins.id(finding))

        origin_review_validated = origin_review_references_are_validated()
        if origin_review_validated:
            for _position, _sequence, _import_reference, finding in candidates:
                details = getattr(finding, "details", {})
                if (
                    isinstance(details, dict)
                    and details.get("notice_code") == "call_graph_source_unavailable"
                    and reference_origin_is_trusted(finding)
                ):
                    validated_finding_ids.add(builtins.id(finding))

        removed = bool(validated_finding_ids) or origin_review_validated
        if not removed:
            return

        removed_private_entries = [
            entry
            for check in result.checks
            if builtins.id(check) in validated_finding_ids
            for entry in [JoblibScanner._private_actionable_failed_check_entry(check)]
            if entry is not None
        ]
        result.issues = [issue for issue in result.issues if builtins.id(issue) not in validated_finding_ids]
        result.checks = [check for check in result.checks if builtins.id(check) not in validated_finding_ids]
        JoblibScanner._remove_private_actionable_failed_check_entries(result, removed_private_entries)
        has_security_findings = any(
            issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues
        ) or any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        )
        if has_security_findings or result.metadata.get("scan_outcome_reasons") != ["pickle_analysis_incomplete"]:
            return

        for key in ("analysis_incomplete", "scan_outcome", "scan_outcome_message", "scan_outcome_reasons"):
            result.metadata.pop(key, None)
        if result.metadata.get("pickle_report_status") == "inconclusive":
            result.metadata["pickle_report_status"] = "complete"
        if result.metadata.get("pickle_verdict") in {"suspicious", "unknown"}:
            result.metadata["pickle_verdict"] = "clean"

    @staticmethod
    def _downgrade_embedded_pickle_parse_errors(result: ScanResult) -> None:
        for issue in result.issues:
            if issue.rule_code == "S901" and issue.details.get("category") == "parse_error":
                issue.severity = IssueSeverity.INFO
        for check in result.checks:
            if check.rule_code == "S901" and check.details.get("category") == "parse_error":
                check.severity = IssueSeverity.INFO

    def _looks_like_raw_pickle_payload(self, data: bytes) -> bool:
        """Return True when `.joblib` bytes should be scanned directly as pickle."""
        if len(data) >= 2 and data[0] == 0x80:
            return data[1] <= 5

        parsed_security_opcode = False
        stack: list[bool] = []
        offset = 0
        for opcode_count in range(1, 17):
            if offset >= len(data):
                return parsed_security_opcode
            opcode = _PICKLE_OPCODE_BY_BYTE.get(data[offset])
            if opcode is None:
                return parsed_security_opcode
            next_offset = _next_pickle_opcode_offset(data, offset, opcode)
            if next_offset is None:
                return parsed_security_opcode
            if opcode.name == "STOP":
                return opcode_count > 1 and bool(stack) and not stack[-1]
            if not _apply_pickle_stack_effect(stack, opcode):
                return parsed_security_opcode
            parsed_security_opcode = parsed_security_opcode or (opcode.name in _TRUNCATED_RAW_PICKLE_SIGNAL_OPCODES)
            if opcode_count >= 16:
                return True
            offset = next_offset

        return False

    @staticmethod
    def _looks_like_compressed_joblib_payload(data: bytes) -> bool:
        """Recognize the compression prefixes emitted by Joblib's bundled codecs."""
        if data.startswith(_JOBLIB_COMPRESSED_PREFIXES):
            return True
        return len(data) >= 4 and data.startswith(b"BZh") and data[3:4] in b"123456789"

    def _record_joblib_operational_error(self, result: ScanResult, reason: str) -> None:
        """Mark a Joblib scan as operationally incomplete for CLI exit-code aggregation."""
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = reason

    def _detect_cve_patterns(self, data: bytes, result: ScanResult, context: str) -> None:
        """Detect CVE-specific patterns in joblib file data."""
        # Convert bytes to string for pattern analysis (ignore decode errors)
        try:
            content_str = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            content_str = ""

        # Analyze for CVE patterns
        cve_attributions = analyze_cve_patterns(content_str, data)

        if cve_attributions:
            # Add CVE information to result
            enhance_scan_result_with_cve(result, [content_str], data)

            # Add specific checks for each CVE found
            for attr in cve_attributions:
                severity = IssueSeverity.CRITICAL if attr.severity == "CRITICAL" else IssueSeverity.WARNING

                result.add_check(
                    name=f"CVE Detection: {attr.cve_id}",
                    passed=False,
                    message=f"Detected {attr.cve_id}: {attr.description}",
                    severity=severity,
                    location=f"{context}",
                    details={
                        "cve_id": attr.cve_id,
                        "cvss": attr.cvss,
                        "cwe": attr.cwe,
                        "affected_versions": attr.affected_versions,
                        "confidence": attr.confidence,
                        "patterns_matched": attr.patterns_matched,
                        "remediation": attr.remediation,
                    },
                    why=f"This file contains patterns associated with {attr.cve_id}, "
                    f"a {attr.severity.lower()} vulnerability affecting {attr.affected_versions}. "
                    f"Remediation: {attr.remediation}",
                )

    def _scan_for_joblib_specific_threats(self, data: bytes, result: ScanResult, context: str) -> None:
        """Scan for joblib-specific security threats beyond general pickle issues."""
        # CVE-2024-34997 specific detection
        numpy_wrapper_patterns = [
            b"NumpyArrayWrapper",
            b"read_array",
            b"numpy_pickle",
        ]

        found_numpy_patterns = []
        for pattern in numpy_wrapper_patterns:
            if pattern in data:
                found_numpy_patterns.append(pattern.decode("utf-8", errors="ignore"))

        if found_numpy_patterns and b"pickle.load" in data:
            result.add_check(
                name="CVE-2024-34997 Risk Detection",
                passed=False,
                message="Detected NumpyArrayWrapper with pickle.load - potential CVE-2024-34997 exploitation",
                severity=IssueSeverity.WARNING,
                location=context,
                details={
                    "cve": "CVE-2024-34997",
                    "patterns": found_numpy_patterns,
                    "risk": "NumpyArrayWrapper deserialization vulnerability",
                },
                why="NumpyArrayWrapper.read_array() combined with pickle.load() can be exploited "
                "for arbitrary code execution if the data source is untrusted.",
            )

        # Check for sklearn model loading patterns with dangerous operations
        if b"sklearn" in data and b"joblib.load" in data:
            dangerous_combos = [
                (b"os.system", "system command execution"),
                (b"subprocess", "process spawning"),
                (b"eval", "code evaluation"),
                (b"exec", "code execution"),
            ]

            for pattern, description in dangerous_combos:
                if pattern in data:
                    result.add_check(
                        name="CVE-2020-13092 Risk Detection",
                        passed=False,
                        message=f"Detected sklearn/joblib.load with {description} - "
                        f"potential CVE-2020-13092 exploitation",
                        severity=IssueSeverity.CRITICAL,
                        location=context,
                        details={
                            "cve": "CVE-2020-13092",
                            "sklearn_pattern": "sklearn + joblib.load",
                            "dangerous_pattern": pattern.decode("utf-8", errors="ignore"),
                            "risk": "scikit-learn deserialization vulnerability",
                        },
                        why=f"scikit-learn models loaded via joblib.load() with {description} "
                        f"can execute arbitrary code during deserialization.",
                    )

    def scan(self, path: str) -> ScanResult:
        """Scan one Joblib file as direct pickle, compressed pickle, or zip-backed content."""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path
            magic = read_magic_bytes(path, 4)
            data = self._read_file_safely(path)

            if magic.startswith(b"PK"):
                # Treat as zip archive
                from .zip_scanner import ZipScanner

                zip_scanner = ZipScanner(self.config)
                sub_result = zip_scanner.scan(path)
                result.merge(sub_result)
                result.bytes_scanned = sub_result.bytes_scanned
                result.metadata.update(sub_result.metadata)
                result.finish(success=sub_result.success)
                return result

            if not self._looks_like_compressed_joblib_payload(data) and self._looks_like_raw_pickle_payload(data):
                self._scan_pickle_payload(data, result, path)
            else:
                # Try safe decompression
                try:
                    decompressed = self._safe_decompress(data)
                    # Record successful decompression check
                    compressed_size = len(data)
                    decompressed_size = len(decompressed)
                    if compressed_size > 0:
                        ratio = decompressed_size / compressed_size
                        result.add_check(
                            name="Compression Bomb Detection",
                            passed=True,
                            message=f"Compression ratio ({ratio:.1f}x) is within safe limits",
                            location=path,
                            details={
                                "compressed_size": compressed_size,
                                "decompressed_size": decompressed_size,
                                "ratio": ratio,
                                "max_ratio": self.max_decompression_ratio,
                            },
                            rule_code=None,  # Passing check
                        )
                except ValueError as e:
                    # Size/ratio limit errors are informational - may indicate large legitimate models
                    # Compression bombs are DoS concerns, not RCE vectors
                    result.add_check(
                        name="Compression Bomb Detection",
                        passed=False,
                        message=str(e),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"security_check": "compression_bomb_detection"},
                        rule_code="S902",
                    )
                    self._record_joblib_operational_error(result, "joblib_wrapper_decode_failed")
                    result.finish(success=False)
                    return result
                except Exception as e:
                    result.add_check(
                        name="Joblib Decompression",
                        passed=False,
                        message=f"Error decompressing joblib file: {e}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "exception": str(e),
                            "exception_type": type(e).__name__,
                        },
                        rule_code="S902",
                    )
                    self._record_joblib_operational_error(result, "joblib_decompression_failed")
                    result.finish(success=False)
                    return result
                self._scan_pickle_payload(decompressed, result, f"{path} (decompressed)")
        except OSError as e:
            mark_inconclusive_scan_result(result, "joblib_read_failed")
            result.add_check(
                name="Joblib File Read",
                passed=False,
                message=f"Unable to read joblib file for analysis: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "joblib_read_failed",
                },
                rule_code="S902",
            )
            self._record_joblib_operational_error(result, "joblib_read_failed")
            result.finish(success=False)
            return result
        except Exception as e:  # pragma: no cover
            result.add_check(
                name="Joblib File Scan",
                passed=False,
                message=f"Error scanning joblib file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            self._record_joblib_operational_error(result, "joblib_scan_failed")
            result.finish(success=False)
            return result

        has_security_findings = any(
            issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues
        )
        has_trusted_incomplete_tail = result.metadata.get("trusted_incomplete_tail") is True
        if (
            result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            and not has_security_findings
            and not has_trusted_incomplete_tail
        ):
            result.finish(success=False)
        else:
            result.finish(success=not result.has_errors)
        return result

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract joblib metadata."""
        metadata = super().extract_metadata(file_path)

        with suppress(Exception):
            metadata["joblib_version"] = distribution_version("joblib")

        metadata["deserialization_skipped"] = True
        metadata["reason"] = "Unsafe in-process joblib deserialization is disabled for metadata extraction"
        if self.config.get("allow_metadata_deserialization"):
            metadata["allow_metadata_deserialization_ignored"] = True

        return metadata
