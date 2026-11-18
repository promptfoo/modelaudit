"""Bounded corroboration of ambiguous pickle evidence in validated tensor storage."""

import codecs
import io
import pickletools
import re
from collections.abc import Callable

# pickletools describes fixed-size arguments and length-prefixed fields for every protocol.
# STOP ends one stream. Invalid bytes cannot connect two otherwise independent fragments.
_INVALID = -8
_ARGUMENT_WIDTH = [_INVALID] * 256
for _opcode in pickletools.opcodes:
    _ARGUMENT_WIDTH[ord(_opcode.code)] = _opcode.arg.n if _opcode.arg is not None else 0
_LENGTH_WIDTH = {-2: 1, -3: 4, -4: 4, -5: 8}
_TEXT_RUN = re.compile(rb"[A-Za-z0-9_+./=\\]{24}")
_NUMBER = re.compile(rb"[+\-0-9.eELa-fA-Fx]*")
_MAX_LINE_CHECK = 256
_MAX_OPCODE_RUN = 16
_MAX_WITNESS_BYTES = 8192
_MAX_WITNESSES = 64

_ENDS_AT_STOP = 1
_HAS_INVOCATION = 2
_HAS_EXTENSION = 4
_HAS_STACK_GLOBAL = 8
_HAS_PERSISTENT_ID = 16
_HAS_INST = 32


def _text_operand(data: bytes, start: int, end: int, *, ascii_only: bool = False) -> str:
    if start >= end:
        return ""
    # A long printable operand can corroborate a stream even when its full
    # name exceeds the inspection budget. Allow a split UTF-8 character at the cut.
    limit = min(start + _MAX_LINE_CHECK, end)
    try:
        if limit == end or ascii_only:
            text = data[start:limit].decode("ascii" if ascii_only else "utf-8")
        else:
            text = codecs.utf_8_decode(data[start:limit], "strict", False)[0]
    except UnicodeDecodeError:
        return ""
    return text if text.isprintable() else ""


def _balanced_stream(data: bytes, offset: int) -> bool | None:
    """Check stack and memo use through STOP, without resolving or calling any globals."""
    sample = data[offset : offset + _MAX_WITNESS_BYTES]
    stream = io.BytesIO(sample)
    try:
        pickletools.dis(stream, out=io.StringIO())
    except (ValueError, UnicodeError, OverflowError) as exc:
        # Unpickling returns the top value even if lower stack entries remain.
        if str(exc).startswith("stack not empty after STOP"):
            return True
        if stream.tell() == len(sample) and offset + len(sample) < len(data):
            return None
        return False
    return True


def _has_named_stack_global(data: bytes, offset: int) -> bool:
    # STACK_GLOBAL may resolve a module before a later opcode fails. Look for
    # decoded name operands in this stream, never names elsewhere in the tensor.
    named_operands = 0
    try:
        for opcode, arg, _ in pickletools.genops(data[offset : offset + _MAX_WITNESS_BYTES]):
            if opcode.name == "STACK_GLOBAL":
                return named_operands >= 2
            if (isinstance(arg, str) and arg.isprintable() and any(c.isalpha() or c == "_" for c in arg)) or (
                opcode.name in {"DUP", "GET", "BINGET", "LONG_BINGET"} and named_operands
            ):
                named_operands += 1
    except (ValueError, UnicodeError, OverflowError):
        # Random tensor bytes often stop decoding before reaching STACK_GLOBAL.
        pass
    return False


def storage_pickle_evidence(
    data: bytes,
    *,
    candidate_bytes: bytes,
    candidate_limit: int,
    check_timeout: Callable[[], bool],
) -> str | None:
    """Return the reason to retain the original inconclusive verdict, if any.

    This is a corroboration pass over an already ambiguous member. Every possible
    byte offset is an entry point. Suffixes share instruction boundaries, so a
    long memo chain or overlapping prefixes cannot cause quadratic reparsing.
    """
    if _TEXT_RUN.search(data):
        return "text_or_encoded_payload"
    # Preserve regions dense enough to exhaust the primary probe's candidate limit.
    # Overlap by two windows so the decision is independent of block boundaries.
    discard = bytes(value for value in range(256) if value not in candidate_bytes)
    for start in range(0, len(data), candidate_limit):
        window = data[start : start + 3 * candidate_limit]
        if len(window.translate(None, discard)) >= candidate_limit:
            return "dense_pickle_candidates"

    size = len(data)
    runs = bytearray(size + 1)
    effects = bytearray(size + 1)
    newline = following_newline = next_control = size
    witnesses = 0
    for offset in range(size - 1, -1, -1):
        if offset % 65536 == 0:
            check_timeout()
        op = data[offset]
        if op == 10:
            following_newline, newline = newline, offset
            next_control = offset
            continue
        # next_control bounds line operands without repeatedly searching long binary suffixes.
        line_is_text = newline == next_control and newline < size
        if op < 32 or op == 127:
            next_control = offset
        width = _ARGUMENT_WIDTH[op]
        if width == _INVALID:
            continue
        if op == ord("."):
            runs[offset] = 1
            effects[offset] = _ENDS_AT_STOP
            continue

        start = offset + 1
        operand = start
        if width >= 0:
            end = start + width
            if end > size:
                continue
            if op == 0x80 and data[start] > 5:
                continue
            if op == 0x95 and int.from_bytes(data[start:end], "little") > size - end:
                continue
        elif width == -1:
            if not line_is_text:
                continue
            end = newline + 1
            if op in b"ci":
                if following_newline == size:
                    continue
                module = _text_operand(data, start, newline, ascii_only=op == ord("i"))
                name = _text_operand(data, newline + 1, following_newline, ascii_only=op == ord("i"))
                if not module or not name:
                    continue
                if all(any(c == "_" or c.isalpha() for c in part) for part in (module, name)):
                    return "named_pickle_reference"
                end = following_newline + 1
            elif op in b"ILFpg":
                if newline - start > _MAX_LINE_CHECK or not _NUMBER.fullmatch(data, start, newline):
                    continue
            elif (op == ord("P") and not _text_operand(data, start, newline, ascii_only=True)) or (
                op == ord("S")
                and (newline - start < 2 or data[start] not in b"\"'" or data[newline - 1] != data[start])
            ):
                continue
        else:
            operand = start + _LENGTH_WIDTH[width]
            if operand > size:
                continue
            length = data[start] if width == -2 else int.from_bytes(data[start:operand], "little")
            end = operand + length
            if end > size:
                continue

        count = 1 + runs[end]
        if count >= _MAX_OPCODE_RUN:
            return "coherent_opcode_sequence"
        state = effects[end]
        if op in b"Rbo\x81\x92":
            state |= _HAS_INVOCATION
        elif op in b"\x82\x83\x84":
            state |= _HAS_EXTENSION
        elif op == 0x93:
            state |= _HAS_STACK_GLOBAL
        elif op in b"PQ":
            state |= _HAS_PERSISTENT_ID
        elif op == ord("i"):
            state |= _HAS_INST
        runs[offset] = count
        effects[offset] = state

        if op == ord("P") and state & _ENDS_AT_STOP and start < newline:
            return "persistent_id_stream"
        if op == ord("(") and state & _HAS_INST:
            return "inst_with_mark"
        string_start = op in b"SVUTX\x8c\x8d"
        if string_start and state & _HAS_STACK_GLOBAL and _text_operand(data, operand, end if width != -1 else newline):
            if witnesses >= _MAX_WITNESSES:
                return "pickle_witness_budget_exhausted"
            witnesses += 1
            if _has_named_stack_global(data, offset):
                return "stack_global_operands"
        if not state & _ENDS_AT_STOP:
            continue
        if op == 0x80:
            candidate = state & (_HAS_EXTENSION | _HAS_STACK_GLOBAL | _HAS_PERSISTENT_ID)
        elif op in b"\x82\x83\x84":
            candidate = state & _HAS_INVOCATION
        elif string_start:
            candidate = state & _HAS_STACK_GLOBAL
        else:
            continue
        if candidate:
            if witnesses >= _MAX_WITNESSES:
                return "pickle_witness_budget_exhausted"
            witnesses += 1
            balanced = _balanced_stream(data, offset)
            if balanced is None:
                return "pickle_witness_read_limit"
            if balanced:
                return "structured_pickle_stream"
    return None
