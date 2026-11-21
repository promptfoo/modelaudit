"""Recognize plain protocol-2 PyTorch tensor and optimizer state without unpickling it."""

import pickletools
import re
from collections.abc import Callable, Iterator, Mapping

_INTEGER = {"BININT", "BININT1", "BININT2"}
_SCALAR = _INTEGER | {"BINUNICODE", "NONE", "NEWFALSE", "NEWTRUE", "BINFLOAT"}
_REBUILD = ("GLOBAL", "torch._utils _rebuild_tensor_v2")
_Token = tuple[str, object]


def _tokens(data: bytes, check_timeout: Callable[[], bool]) -> Iterator[_Token]:
    # Only names and strings may be reused. In particular, a storage, hooks
    # object or argument tuple must not escape its tensor expression via GET.
    memo: dict[int, _Token] = {}
    token: _Token = ("", None)
    for count, (op, arg, pos) in enumerate(pickletools.genops(data)):
        if count % 1024 == 0:
            check_timeout()
        if op.name in {"BINPUT", "LONG_BINPUT"}:
            if arg != len(memo) or token[0] in {"PROTO", "MARK"}:
                raise ValueError
            memo[arg] = token
            continue
        if op.name in {"BINGET", "LONG_BINGET"}:
            if not isinstance(arg, int):
                raise ValueError
            token = memo[arg]
            if token[0] not in {"GLOBAL", "BINUNICODE"}:
                raise ValueError
        else:
            if op.name == "GLOBAL" and (
                not isinstance(arg, str) or not data.startswith(b"c" + arg.replace(" ", "\n").encode() + b"\n", pos)
            ):
                raise ValueError
            if op.name == "STOP" and pos != len(data) - 1:
                raise ValueError
            token = (op.name, arg)
        yield token


def _integer(token: _Token) -> int:
    op, value = token
    if op not in _INTEGER or not isinstance(value, int) or value < 0:
        raise ValueError
    return value


def _dimensions(tokens: Iterator[_Token]) -> list[int]:
    dims: list[int] = []
    token = next(tokens)
    while token[0] in _INTEGER and len(dims) < 3:
        dims.append(_integer(token))
        token = next(tokens)
    if token[0] != ("EMPTY_TUPLE", "TUPLE1", "TUPLE2", "TUPLE3")[len(dims)]:
        raise ValueError
    return dims


def _tensor(tokens: Iterator[_Token], sizes: Mapping[str, int]) -> bool:
    # The only consumer of BINPERSID is _rebuild_tensor_v2. No custom hooks,
    # storage classes, device tags or out-of-bounds views qualify.
    if (
        next(tokens)[0] != "MARK"
        or next(tokens)[0] != "MARK"
        or next(tokens) != ("BINUNICODE", "storage")
        or next(tokens) != ("GLOBAL", "torch FloatStorage")
    ):
        return False
    key_op, key = next(tokens)
    loc_op, location = next(tokens)
    size = _integer(next(tokens))
    if (
        key_op != "BINUNICODE"
        or not isinstance(key, str)
        or sizes.get(key) != size * 4
        or loc_op != "BINUNICODE"
        or not isinstance(location, str)
        or not re.fullmatch(r"cpu|cuda:[0-9]+", location)
        or next(tokens)[0] != "TUPLE"
        or next(tokens)[0] != "BINPERSID"
    ):
        return False
    offset = _integer(next(tokens))
    dims, strides = _dimensions(tokens), _dimensions(tokens)
    if len(dims) != len(strides) or offset >= size or 0 in dims:
        return False
    if offset + sum((d - 1) * s for d, s in zip(dims, strides, strict=True)) >= size:
        return False
    return (
        next(tokens)[0] in {"NEWFALSE", "NEWTRUE"}
        and next(tokens) == ("GLOBAL", "collections OrderedDict")
        and next(tokens)[0] == "EMPTY_TUPLE"
        and next(tokens)[0] == "REDUCE"
        and next(tokens)[0] == "TUPLE"
        and next(tokens)[0] == "REDUCE"
    )


def uses_only_raw_tensors(data: bytes, sizes: Mapping[str, int], check_timeout: Callable[[], bool]) -> bool:
    """Only called after bounded, complete PID/size validation of the same data.pkl."""
    # Outside a tensor expression accept only literal containers and scalars.
    # Unknown instructions, malformed stacks and additional streams fail closed.
    if not data.startswith(b"\x80\x02"):
        return False
    tokens = _tokens(data, check_timeout)
    stack: list[str] = []
    marks: list[int] = []
    found_tensor = False
    try:
        next(tokens)  # PROTO 2
        for token in tokens:
            op = token[0]
            if token == _REBUILD:
                if not _tensor(tokens, sizes):
                    return False
                found_tensor = True
                stack.append("tensor")
            elif op in _SCALAR or op in {"EMPTY_LIST", "EMPTY_DICT", "EMPTY_TUPLE"}:
                stack.append(op)
            elif op in {"TUPLE1", "TUPLE2", "TUPLE3"}:
                n = int(op[-1])
                if len(stack) - (marks[-1] if marks else 0) < n:
                    return False
                del stack[-n:]
                stack.append("tuple")
            elif op == "MARK":
                marks.append(len(stack))
            elif op in {"SETITEMS", "APPENDS"}:
                start = marks.pop()
                if start <= (marks[-1] if marks else 0):
                    return False
                if op == "SETITEMS":
                    if stack[start - 1] != "EMPTY_DICT" or (len(stack) - start) % 2:
                        return False
                    if any(k not in _INTEGER and k != "BINUNICODE" for k in stack[start::2]):
                        return False
                elif stack[start - 1] != "EMPTY_LIST":
                    return False
                del stack[start:]
            elif op == "STOP":
                return found_tensor and not marks and len(stack) == 1
            else:
                return False
    except (ValueError, KeyError, IndexError, StopIteration, UnicodeError, OverflowError):
        return False
    return False
