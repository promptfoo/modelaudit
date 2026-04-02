"""Opcode-level pickle analysis for the standalone package."""

from __future__ import annotations

import base64
import binascii
import pickletools
import re
import time
from dataclasses import dataclass
from io import BytesIO
from typing import Any, BinaryIO, cast

from ..options import ScanOptions
from ..report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity

_MARK = object()
_DANGEROUS_WILDCARD_MODULES = frozenset(
    {
        "__builtin__",
        "__builtins__",
        "builtins",
        "cloudpickle",
        "ctypes",
        "dill._dill",
        "importlib",
        "marshal",
        "nt",
        "os",
        "pickle",
        "posix",
        "runpy",
        "socket",
        "ssl",
        "subprocess",
        "sys",
        "urllib",
    }
)
_DANGEROUS_GLOBALS = {
    "collections": frozenset({"eval"}),
    "operator": frozenset({"attrgetter", "itemgetter", "methodcaller"}),
    "_operator": frozenset({"attrgetter", "itemgetter", "methodcaller"}),
    "dill": frozenset({"load", "loads"}),
    "pkgutil": frozenset({"resolve_name"}),
    "types": frozenset({"CodeType", "FunctionType"}),
    "torch.serialization": frozenset({"load"}),
}
_WARNING_GLOBALS = {
    "functools": frozenset({"partial", "partialmethod"}),
}
_BUILTIN_DANGEROUS_NAMES = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "eval",
        "exec",
        "getattr",
        "open",
        "setattr",
    }
)
_REDUCE_OPCODES = frozenset({"REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST", "BUILD"})
_STACK_GLOBAL_STRING_OPCODES = frozenset(
    {
        "BINSTRING",
        "BINUNICODE",
        "BINUNICODE8",
        "SHORT_BINSTRING",
        "SHORT_BINUNICODE",
        "STRING",
        "UNICODE",
    }
)
_MEMO_WRITE_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_MEMO_READ_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
_SUSPICIOUS_STRING_PATTERNS = frozenset(
    {
        "__import__(",
        "eval(",
        "exec(",
        "os.system",
        "subprocess.",
    }
)
_NESTED_PICKLE_SCAN_LIMIT_BYTES = 2 * 1024 * 1024
_MAX_BASE64_NESTED_PICKLE_CHARS = ((_NESTED_PICKLE_SCAN_LIMIT_BYTES + 2) // 3) * 4
_MAX_HEX_NESTED_PICKLE_CHARS = _NESTED_PICKLE_SCAN_LIMIT_BYTES * 2
_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_HEX_CANDIDATE_RE = re.compile(r"(?:\\x)?[0-9a-fA-F]+")


@dataclass(frozen=True, slots=True)
class _GlobalRef:
    module: str
    name: str
    position: int
    malformed: bool = False

    @property
    def symbol(self) -> str:
        return f"{self.module}.{self.name}"


class _OpcodeBudgetExceeded(Exception):
    """Raised when opcode analysis reaches the configured opcode limit."""


class _ScanTimeout(Exception):
    """Raised when opcode analysis exceeds the configured timeout."""


class _StreamReadError(Exception):
    """Raised when the source stream fails during incremental parsing."""

    def __init__(self, source_error: Exception) -> None:
        super().__init__(str(source_error))
        self.source_error = source_error


class _BoundedPickleStream:
    """Incrementally read pickle bytes while enforcing an optional byte limit."""

    def __init__(self, stream: BinaryIO, byte_limit: int | None) -> None:
        self._stream = stream
        self._byte_limit = byte_limit
        self._prefetched = bytearray()
        self._position = 0
        self.short_read = False

    def tell(self) -> int:
        return self._position

    def has_remaining_bytes(self) -> bool:
        if self._byte_limit is not None and self._position >= self._byte_limit:
            return False
        if self._prefetched:
            return True

        chunk = self._read_once(1)
        if not chunk:
            if self._byte_limit is not None and self._position < self._byte_limit:
                self.short_read = True
            return False
        self._prefetched.extend(chunk)
        return True

    def read(self, size: int | None = -1) -> bytes:
        read_size = self._bounded_size(size)
        if read_size == 0:
            return b""

        if read_size is None:
            prefetched = self._consume_prefetched()
            chunk = self._read_once(None)
            payload = prefetched + chunk
            self._position += len(payload)
            return payload

        chunks: list[bytes] = []
        prefetched = self._consume_prefetched(read_size)
        if prefetched:
            chunks.append(prefetched)
        bytes_read = len(prefetched)
        while bytes_read < read_size:
            chunk = self._read_once(read_size - bytes_read)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)

        self._position += bytes_read
        self._mark_short_read_if_needed(bytes_read, expected_bytes=read_size)
        return b"".join(chunks)

    def readline(self, size: int | None = -1) -> bytes:
        read_size = self._bounded_size(size)
        if read_size == 0:
            return b""

        prefix = self._consume_prefetched_line(read_size)
        if prefix.endswith(b"\n") or (read_size is not None and len(prefix) >= read_size):
            self._position += len(prefix)
            return prefix

        suffix_size = None if read_size is None else read_size - len(prefix)
        suffix = self._readline_once(suffix_size)
        chunk = prefix + suffix
        chunk_len = len(chunk)
        if self._byte_limit is not None and self._position + chunk_len < self._byte_limit and not chunk.endswith(b"\n"):
            self.short_read = True
        self._position += chunk_len
        return chunk

    def _bounded_size(self, requested_size: int | None) -> int | None:
        if requested_size is not None and requested_size < 0:
            requested_size = None
        if self._byte_limit is None:
            return requested_size

        remaining = max(self._byte_limit - self._position, 0)
        if requested_size is None or requested_size < 0:
            return remaining
        return min(requested_size, remaining)

    def _read_once(self, size: int | None) -> bytes:
        try:
            return self._stream.read() if size is None else self._stream.read(size)
        except (OSError, ValueError) as error:
            raise _StreamReadError(error) from error

    def _readline_once(self, size: int | None) -> bytes:
        try:
            return self._stream.readline() if size is None else self._stream.readline(size)
        except (OSError, ValueError) as error:
            raise _StreamReadError(error) from error

    def _mark_short_read_if_needed(self, bytes_read: int, *, expected_bytes: int) -> None:
        if self._byte_limit is None:
            return
        if bytes_read < expected_bytes and self._position < self._byte_limit:
            self.short_read = True

    def _consume_prefetched(self, size: int | None = None) -> bytes:
        if not self._prefetched:
            return b""

        if size is None or size >= len(self._prefetched):
            chunk = bytes(self._prefetched)
            self._prefetched.clear()
            return chunk

        chunk = bytes(self._prefetched[:size])
        del self._prefetched[:size]
        return chunk

    def _consume_prefetched_line(self, size: int | None = None) -> bytes:
        if not self._prefetched:
            return b""

        limit = len(self._prefetched) if size is None else min(size, len(self._prefetched))
        newline_index = self._prefetched.find(b"\n", 0, limit)
        end = newline_index + 1 if newline_index >= 0 else limit
        chunk = bytes(self._prefetched[:end])
        del self._prefetched[:end]
        return chunk


def scan_pickle_payload(
    payload: bytes,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
) -> PickleReport:
    """Scan pickle bytes and return a standalone report."""

    bytes_total = len(payload) if bytes_total is None else bytes_total
    return scan_pickle_stream(
        BytesIO(payload),
        source=source,
        options=options,
        bytes_total=bytes_total,
        position_offset=position_offset,
    )


def scan_pickle_stream(
    stream: BinaryIO,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
) -> PickleReport:
    """Scan pickle bytes directly from a binary stream and return a standalone report."""

    started_at = time.monotonic()
    scan = _ScanState(
        source=source,
        stream=_BoundedPickleStream(stream, bytes_total),
        options=options,
        bytes_total=bytes_total,
        position_offset=position_offset,
    )
    scan.run()
    return scan.to_report(duration_s=time.monotonic() - started_at)


class _ScanState:
    def __init__(
        self,
        *,
        source: str,
        stream: _BoundedPickleStream,
        options: ScanOptions,
        bytes_total: int | None,
        position_offset: int,
    ) -> None:
        self.source = source
        self.stream = stream
        self.options = options
        self.bytes_total = bytes_total
        self.position_offset = position_offset
        self.deadline = time.monotonic() + options.timeout_s
        self.stack: list[Any] = []
        self.memo: dict[int | str, Any] = {}
        self.next_memo_index = 0
        self.findings: list[Finding] = []
        self.notices: list[Notice] = []
        self.errors: list[ScanError] = []
        self.metadata: dict[str, Any] = {}
        self.global_references: list[dict[str, Any]] = []
        self.opcode_count = 0
        self.global_count = 0
        self.bytes_scanned = 0
        self.first_pickle_end_pos: int | None = None
        self.status = ScanStatus.COMPLETE
        self.verdict = SafetyVerdict.CLEAN
        self._seen_finding_keys: set[tuple[str, str | None, str | None]] = set()
        self._seen_global_reference_keys: set[tuple[str, str, int, str]] = set()

    def run(self) -> None:
        if self.bytes_total == 0:
            self._record_empty_input_error()
            self._finalize_common_metadata()
            return

        try:
            if not self._has_remaining_stream_bytes():
                if not self._record_short_read_if_needed():
                    self._record_empty_input_error()
                self._finalize_common_metadata()
                self._finalize_verdict()
                return

            while self._has_remaining_stream_bytes():
                stream_start = self.stream.tell()
                parsed_opcode = False

                for opcode, arg, pos in pickletools.genops(cast(BinaryIO, self.stream)):
                    parsed_opcode = True
                    self._check_limits()

                    stream_position = int(pos or 0)
                    position = self.position_offset + stream_position
                    self.bytes_scanned = max(self.bytes_scanned, self.stream.tell(), stream_position + 1)
                    self.opcode_count += 1
                    self._handle_opcode(opcode.name, arg, position)

                    if opcode.name == "STOP":
                        if self.first_pickle_end_pos is None:
                            self.first_pickle_end_pos = self.position_offset + self.stream.tell()
                        self.stack.clear()
                        self.memo.clear()
                        self.next_memo_index = 0
                        break

                if not parsed_opcode:
                    if self._record_short_read_if_needed():
                        break
                    if stream_start == 0 and self.opcode_count == 0 and not self.findings:
                        self._record_empty_input_error()
                    break

                if self.stream.tell() <= stream_start:
                    break
        except _OpcodeBudgetExceeded:
            self.status = ScanStatus.INCONCLUSIVE
            self.notices.append(
                Notice(
                    message=f"Opcode analysis stopped after reaching max_opcodes={self.options.max_opcodes}",
                    severity=Severity.INFO,
                    location=self.source,
                    code="opcode_budget",
                    details={
                        "opcode_count": self.opcode_count,
                        "max_opcodes": self.options.max_opcodes,
                        "analysis_incomplete": True,
                    },
                )
            )
            self._scan_post_budget_tail(self.stream.tell())
        except _ScanTimeout:
            self.status = ScanStatus.INCONCLUSIVE
            self.notices.append(
                Notice(
                    message=f"Opcode analysis timed out after {self.options.timeout_s:.3f} seconds",
                    severity=Severity.INFO,
                    location=self.source,
                    code="timeout",
                    details={
                        "opcode_count": self.opcode_count,
                        "timeout_s": self.options.timeout_s,
                        "analysis_incomplete": True,
                    },
                )
            )
        except _StreamReadError as error:
            self.status = ScanStatus.ERROR
            self.errors.append(
                ScanError(
                    message=f"Could not read pickle stream: {error.source_error!s}",
                    category="io_error",
                    location=self.source,
                    exception_type=type(error.source_error).__name__,
                    details={"opcode_count": self.opcode_count},
                )
            )
        except Exception as error:
            if self._record_short_read_if_needed():
                self._finalize_common_metadata()
                self._finalize_verdict()
                return

            if self.opcode_count == 0 and not self.findings:
                self.status = ScanStatus.ERROR
                self.errors.append(
                    ScanError(
                        message=f"Could not parse pickle stream: {error!s}",
                        category="parse_error",
                        location=f"{self.source} (pos {self.position_offset + self.stream.tell()})",
                        exception_type=type(error).__name__,
                        details={"opcode_count": self.opcode_count},
                    )
                )
            else:
                self.status = ScanStatus.INCONCLUSIVE
                self.notices.append(
                    Notice(
                        message=f"Pickle parsing stopped before the stream was fully consumed: {type(error).__name__}",
                        severity=Severity.INFO,
                        location=f"{self.source} (pos {self.position_offset + self.stream.tell()})",
                        code="parse_incomplete",
                        details={
                            "opcode_count": self.opcode_count,
                            "exception": str(error),
                            "exception_type": type(error).__name__,
                            "analysis_incomplete": True,
                        },
                    )
                )

        if self.status == ScanStatus.COMPLETE:
            self._record_short_read_if_needed()

        self._finalize_common_metadata()
        self._coalesce_redundant_global_findings()
        self._finalize_verdict()

    def _has_remaining_stream_bytes(self) -> bool:
        return self.stream.has_remaining_bytes()

    def _record_empty_input_error(self) -> None:
        self.status = ScanStatus.ERROR
        self.verdict = SafetyVerdict.UNKNOWN
        self.metadata["opcode_count"] = self.opcode_count
        self.metadata["globals_count"] = self.global_count
        self.errors.append(
            ScanError(
                message="Input is empty and does not contain a pickle stream",
                category="empty_input",
                location=self.source,
            )
        )

    def _record_short_read_if_needed(self) -> bool:
        if self.bytes_total is None or not self.stream.short_read or self.stream.tell() >= self.bytes_total:
            return False

        self.status = ScanStatus.ERROR
        self.bytes_scanned = max(self.bytes_scanned, self.stream.tell())
        self.errors.append(
            ScanError(
                message=(
                    "Could not read requested pickle stream size: "
                    f"expected {self.bytes_total} bytes, got {self.stream.tell()}"
                ),
                category="short_read",
                location=self.source,
                details={
                    "expected_size": self.bytes_total,
                    "bytes_read": self.stream.tell(),
                    "position_offset": self.position_offset,
                },
            )
        )
        return True

    def _finalize_common_metadata(self) -> None:
        self.metadata["opcode_count"] = self.opcode_count
        self.metadata["globals_count"] = self.global_count
        self.metadata["import_references"] = self.global_references
        if self.first_pickle_end_pos is not None:
            self.metadata["first_pickle_end_pos"] = self.first_pickle_end_pos

    def to_report(self, *, duration_s: float) -> PickleReport:
        raw_scan_complete = self.status == ScanStatus.COMPLETE and (
            self.bytes_total is None or self.bytes_scanned >= self.bytes_total
        )
        opcode_scan_complete = self.status == ScanStatus.COMPLETE

        return PickleReport(
            source=self.source,
            status=self.status,
            verdict=self.verdict,
            findings=tuple(self.findings),
            notices=tuple(self.notices),
            errors=tuple(self.errors),
            coverage=CoverageSummary(
                bytes_scanned=self.bytes_scanned,
                bytes_total=self.bytes_total,
                opcode_count=self.opcode_count,
                raw_scan_complete=raw_scan_complete,
                opcode_scan_complete=opcode_scan_complete,
            ),
            metadata=self.metadata,
            duration_s=duration_s,
        )

    def _check_limits(self) -> None:
        if self.opcode_count >= self.options.max_opcodes:
            raise _OpcodeBudgetExceeded()
        if time.monotonic() > self.deadline:
            raise _ScanTimeout()

    def _handle_opcode(self, op_name: str, arg: Any, position: int) -> None:
        if op_name == "PROTO":
            self.metadata.setdefault("protocols", []).append(int(arg))
            return

        if op_name in _STACK_GLOBAL_STRING_OPCODES:
            value = _coerce_text_value(arg)
            self.stack.append(value)
            self._scan_string_literal(value, op_name=op_name, position=position)
            self._scan_encoded_nested_pickle_literal(value, position=position)
            return

        if op_name == "NONE":
            self.stack.append(None)
            return

        if op_name in {"NEWTRUE", "NEWFALSE"}:
            self.stack.append(op_name == "NEWTRUE")
            return

        if op_name in {"BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "INT"}:
            self.stack.append(arg)
            return

        if op_name in {"BINBYTES", "BINBYTES8", "SHORT_BINBYTES", "BYTEARRAY8"}:
            bytes_value = bytes(arg)
            self.stack.append(bytes_value)
            self._scan_raw_nested_pickle_bytes(bytes_value, position=position)
            return

        if op_name == "MARK":
            self.stack.append(_MARK)
            return

        if op_name == "POP":
            if self.stack:
                self.stack.pop()
            return

        if op_name == "POP_MARK":
            self._pop_to_mark()
            return

        if op_name in {"EMPTY_TUPLE", "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET"}:
            self.stack.append(())
            return

        if op_name in {"TUPLE", "LIST", "DICT", "SET", "FROZENSET"}:
            self.stack.append(tuple(self._pop_to_mark()))
            return

        if op_name == "TUPLE1":
            self._collapse_top_n(1)
            return

        if op_name == "TUPLE2":
            self._collapse_top_n(2)
            return

        if op_name == "TUPLE3":
            self._collapse_top_n(3)
            return

        if op_name in _MEMO_WRITE_OPCODES:
            if self.stack:
                self.memo[arg] = self.stack[-1]
            return

        if op_name == "MEMOIZE":
            if self.stack:
                self.memo[self.next_memo_index] = self.stack[-1]
                self.next_memo_index += 1
            return

        if op_name in _MEMO_READ_OPCODES:
            self.stack.append(self.memo.get(arg, _GlobalRef("__unknown__", f"memo_{arg}", position, malformed=True)))
            return

        if op_name == "GLOBAL":
            module, _, name = str(arg).partition(" ")
            ref = _GlobalRef(module=module, name=name, position=position)
            self.stack.append(ref)
            self._record_global_ref(ref, op_name=op_name)
            return

        if op_name == "STACK_GLOBAL":
            name_value = self.stack.pop() if self.stack else None
            module_value = self.stack.pop() if self.stack else None
            ref = self._resolve_stack_global(module_value, name_value, position)
            self.stack.append(ref)
            self._record_global_ref(ref, op_name=op_name)
            return

        if op_name in {"EXT1", "EXT2", "EXT4"}:
            ref = _GlobalRef(module="copyreg.extension", name=f"code_{arg}", position=position, malformed=True)
            self.stack.append(ref)
            self._add_finding(
                Finding(
                    message=f"Encountered {op_name} extension reference {ref.name}; extension resolution is opaque",
                    severity=Severity.WARNING,
                    location=f"{self.source} (pos {position})",
                    rule_code="EXTENSION_REF",
                    details={"opcode": op_name, "extension_code": arg, "symbol": ref.symbol},
                    why=(
                        "Pickle extension opcodes resolve through a process-global registry "
                        "and can obscure call targets."
                    ),
                )
            )
            return

        if op_name in _REDUCE_OPCODES:
            callable_ref = self._consume_callable_opcode(op_name, arg, position)
            if callable_ref is None:
                return

            global_severity = _global_severity(callable_ref.module, callable_ref.name)
            if global_severity is not None:
                self._add_finding(
                    Finding(
                        message=f"Found {op_name} opcode invoking dangerous global: {callable_ref.symbol}",
                        severity=global_severity,
                        location=f"{self.source} (pos {position})",
                        rule_code="DANGEROUS_CALL",
                        details={
                            "opcode": op_name,
                            "module": callable_ref.module,
                            "name": callable_ref.name,
                            "import_reference": callable_ref.symbol,
                            "global_position": callable_ref.position,
                        },
                        why="This pickle opcode can invoke attacker-controlled callables during deserialization.",
                    )
                )
            return

    def _pop_to_mark(self) -> list[Any]:
        values: list[Any] = []
        while self.stack:
            item = self.stack.pop()
            if item is _MARK:
                break
            values.append(item)
        values.reverse()
        return values

    def _collapse_top_n(self, count: int) -> None:
        if len(self.stack) < count:
            self.stack.append(())
            return
        values = [self.stack.pop() for _ in range(count)]
        values.reverse()
        self.stack.append(tuple(values))

    def _consume_callable_opcode(self, op_name: str, arg: Any, position: int) -> _GlobalRef | None:
        callable_value: Any = None
        if op_name in {"REDUCE", "NEWOBJ"}:
            callable_value = self._consume_top_operands(2)
        elif op_name == "NEWOBJ_EX":
            callable_value = self._consume_top_operands(3)
        elif op_name in {"OBJ", "INST"}:
            values = self._pop_to_mark()
            callable_value = values[0] if values else None
            if op_name == "INST":
                module, _, name = str(arg).partition(" ")
                callable_value = _GlobalRef(module=module, name=name, position=position)
                self._record_global_ref(callable_value, op_name=op_name)
            self.stack.append(())
        elif op_name == "BUILD":
            callable_value = self._consume_top_operands(2)

        if isinstance(callable_value, _GlobalRef) and not callable_value.malformed:
            return callable_value
        return None

    def _consume_top_operands(self, operand_count: int) -> Any:
        if len(self.stack) < operand_count:
            self.stack.clear()
            self.stack.append(())
            return None
        values = [self.stack.pop() for _ in range(operand_count)]
        values.reverse()
        self.stack.append(())
        return values[0]

    def _resolve_stack_global(self, module_value: Any, name_value: Any, position: int) -> _GlobalRef:
        module = self._resolve_global_operand(module_value)
        name = self._resolve_global_operand(name_value)

        if module is None or name is None:
            malformed = _GlobalRef(
                module=module or "__unknown__",
                name=name or "__unknown__",
                position=position,
                malformed=True,
            )
            self._add_finding(
                Finding(
                    message="Malformed STACK_GLOBAL operands prevent reliable callable resolution",
                    severity=Severity.CRITICAL,
                    location=f"{self.source} (pos {position})",
                    rule_code="MALFORMED_STACK_GLOBAL",
                    details={
                        "module_operand": _operand_preview(module_value),
                        "name_operand": _operand_preview(name_value),
                    },
                    why=(
                        "Malformed STACK_GLOBAL operands can be used to bypass scanners "
                        "that assume string-only operands."
                    ),
                )
            )
            return malformed

        return _GlobalRef(module=module, name=name, position=position)

    @staticmethod
    def _resolve_global_operand(value: Any) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, _GlobalRef) and not value.malformed:
            return value.symbol
        return None

    def _scan_string_literal(self, value: str, *, op_name: str, position: int) -> None:
        normalized = value.lower()
        for matched_pattern in sorted(_SUSPICIOUS_STRING_PATTERNS):
            if matched_pattern not in normalized:
                continue

            self._add_finding(
                Finding(
                    message=f"Suspicious string literal contains code execution pattern: {matched_pattern}",
                    severity=Severity.WARNING,
                    location=f"{self.source} (pos {position})",
                    rule_code="SUSPICIOUS_STRING",
                    details={
                        "opcode": op_name,
                        "pattern": matched_pattern,
                    },
                    why=(
                        "Suspicious code-like strings embedded in pickle payloads can be used by "
                        "downstream loaders or helper code during deserialization workflows."
                    ),
                )
            )

    def _scan_raw_nested_pickle_bytes(self, value: bytes, *, position: int) -> None:
        if not _looks_like_pickle_payload(value):
            return

        self._add_finding(
            Finding(
                message="Nested pickle payload detected",
                severity=Severity.CRITICAL,
                location=f"{self.source} (pos {position})",
                rule_code="S213",
                details={
                    "encoding": "raw",
                    "payload_size": len(value),
                },
                why=(
                    "This pickle contains another serialized pickle payload inside a byte field. "
                    "Nested payloads can hide code execution paths from shallow scanners."
                ),
            )
        )

    def _scan_encoded_nested_pickle_literal(self, value: str, *, position: int) -> None:
        for encoding, decoded in _decode_possible_encoded_pickle(value):
            self._add_finding(
                Finding(
                    message="Encoded pickle payload detected",
                    severity=Severity.CRITICAL,
                    location=f"{self.source} (pos {position})",
                    rule_code="S601" if encoding == "base64" else "S602",
                    details={
                        "encoding": encoding,
                        "payload_size": len(decoded),
                    },
                    why=(
                        "Encoded nested pickle payloads can hide deserialization gadgets "
                        "inside apparently inert metadata strings."
                    ),
                )
            )

    def _record_global_ref(self, ref: _GlobalRef, *, op_name: str) -> None:
        if ref.malformed:
            return

        self.global_count += 1
        global_severity = _global_severity(ref.module, ref.name)
        is_dangerous = global_severity is not None
        reference_key = (ref.symbol, op_name, ref.position, "dangerous" if is_dangerous else "observed")
        if reference_key not in self._seen_global_reference_keys:
            self._seen_global_reference_keys.add(reference_key)
            self.global_references.append(
                {
                    "import_reference": ref.symbol,
                    "module": ref.module,
                    "name": ref.name,
                    "opcode": op_name,
                    "position": ref.position,
                    "is_dangerous": is_dangerous,
                }
            )

        if global_severity is not None:
            self._add_finding(
                Finding(
                    message=f"Found dangerous global reference: {ref.symbol}",
                    severity=global_severity,
                    location=f"{self.source} (pos {ref.position})",
                    rule_code="DANGEROUS_GLOBAL",
                    details={
                        "opcode": op_name,
                        "module": ref.module,
                        "name": ref.name,
                        "import_reference": ref.symbol,
                    },
                    why="Dangerous globals can execute code or access sensitive system resources when unpickled.",
                )
            )
            return

        if ref.module == "__main__":
            self._add_finding(
                Finding(
                    message=f"Found non-allowlisted __main__ global reference: {ref.symbol}",
                    severity=Severity.WARNING,
                    location=f"{self.source} (pos {ref.position})",
                    rule_code="S203",
                    details={
                        "opcode": op_name,
                        "module": ref.module,
                        "name": ref.name,
                        "import_reference": ref.symbol,
                    },
                    why=(
                        "Pickles that instantiate classes from __main__ depend on arbitrary "
                        "application code and deserve manual review before loading."
                    ),
                )
            )

    def _add_finding(self, finding: Finding) -> None:
        key = (finding.message, finding.location, finding.rule_code)
        if key in self._seen_finding_keys:
            return
        self._seen_finding_keys.add(key)
        self.findings.append(finding)

    def _coalesce_redundant_global_findings(self) -> None:
        called_global_keys = {
            (
                finding.details.get("import_reference"),
                finding.details.get("global_position"),
            )
            for finding in self.findings
            if finding.rule_code == "DANGEROUS_CALL"
            and isinstance(finding.details.get("import_reference"), str)
            and isinstance(finding.details.get("global_position"), int)
        }
        if not called_global_keys:
            return

        self.findings = [
            finding
            for finding in self.findings
            if not (
                finding.rule_code == "DANGEROUS_GLOBAL"
                and (
                    finding.details.get("import_reference"),
                    _location_position(finding.location),
                )
                in called_global_keys
            )
        ]
        self._seen_finding_keys = {(finding.message, finding.location, finding.rule_code) for finding in self.findings}

    def _scan_post_budget_tail(self, stream_offset: int) -> None:
        if self.options.post_budget_scan_bytes <= 0:
            return

        try:
            tail = self.stream.read(self.options.post_budget_scan_bytes)
        except _StreamReadError as error:
            self.status = ScanStatus.ERROR
            self.errors.append(
                ScanError(
                    message=f"Could not read pickle stream tail: {error.source_error!s}",
                    category="io_error",
                    location=self.source,
                    exception_type=type(error.source_error).__name__,
                    details={
                        "opcode_count": self.opcode_count,
                        "post_budget_stream_offset": stream_offset,
                    },
                )
            )
            return

        self.bytes_scanned = max(self.bytes_scanned, stream_offset + len(tail))
        for needle in (b"os\nsystem", b"posix\nsystem", b"subprocess\nPopen", b"builtins\neval", b"__builtin__\neval"):
            offset = tail.find(needle)
            if offset >= 0:
                self._add_finding(
                    Finding(
                        message="Dangerous global-like byte pattern found beyond opcode budget",
                        severity=Severity.WARNING,
                        location=f"{self.source} (pos {self.position_offset + stream_offset + offset})",
                        rule_code="POST_BUDGET_GLOBAL",
                        details={"pattern": needle.decode("ascii", errors="replace")},
                        why=(
                            "Opcode analysis stopped early, but a byte-level tail scan still "
                            "found suspicious global references."
                        ),
                    )
                )

    def _finalize_verdict(self) -> None:
        if any(finding.severity == Severity.CRITICAL for finding in self.findings):
            self.verdict = SafetyVerdict.MALICIOUS
            return
        if any(finding.severity == Severity.WARNING for finding in self.findings):
            self.verdict = SafetyVerdict.SUSPICIOUS
            return
        if self.status == ScanStatus.COMPLETE:
            self.verdict = SafetyVerdict.CLEAN
            return
        self.verdict = SafetyVerdict.UNKNOWN


def _global_severity(module: str, name: str) -> Severity | None:
    warning_names = _WARNING_GLOBALS.get(module)
    if warning_names is not None and name in warning_names:
        return Severity.WARNING

    if module in _DANGEROUS_WILDCARD_MODULES:
        if module in {"builtins", "__builtin__", "__builtins__"}:
            return Severity.CRITICAL if name in _BUILTIN_DANGEROUS_NAMES else None
        return Severity.CRITICAL

    top_level_module = module.split(".", 1)[0]
    if top_level_module in _DANGEROUS_WILDCARD_MODULES and top_level_module not in {
        "builtins",
        "__builtin__",
        "__builtins__",
    }:
        return Severity.CRITICAL

    blocked_names = _DANGEROUS_GLOBALS.get(module)
    if blocked_names is not None and name in blocked_names:
        return Severity.CRITICAL
    return None


def _coerce_text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _decode_possible_encoded_pickle(value: str) -> list[tuple[str, bytes]]:
    stripped = value.strip()
    if len(stripped) < 16:
        return []

    decoded_values: list[tuple[str, bytes]] = []

    if _BASE64_CANDIDATE_RE.fullmatch(stripped):
        bounded = stripped[:_MAX_BASE64_NESTED_PICKLE_CHARS]
        padded = bounded + ("=" * (-len(bounded) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if _looks_like_pickle_payload(decoded):
            decoded_values.append(("base64", decoded))

    hex_candidate = stripped[: _MAX_HEX_NESTED_PICKLE_CHARS * 2].replace("\\x", "")
    if (
        len(hex_candidate) >= 16
        and len(hex_candidate) % 2 == 0
        and _HEX_CANDIDATE_RE.fullmatch(hex_candidate)
        and not re.fullmatch(r"(.)\1*", hex_candidate)
    ):
        bounded_hex_candidate = hex_candidate[:_MAX_HEX_NESTED_PICKLE_CHARS]
        try:
            decoded = binascii.unhexlify(bounded_hex_candidate)
        except (binascii.Error, ValueError):
            decoded = b""
        if _looks_like_pickle_payload(decoded):
            decoded_values.append(("hex", decoded))

    return decoded_values


def _looks_like_pickle_payload(value: bytes) -> bool:
    if len(value) < 2 or len(value) > _NESTED_PICKLE_SCAN_LIMIT_BYTES:
        return False
    if not (value[:1] == b"\x80" or value[:1] in {b"(", b"c", b"d", b"l", b"i", b"I", b"S", b"V", b"q", b"t", b"u"}):
        return False

    try:
        for opcode, _arg, _pos in pickletools.genops(BytesIO(value)):
            if opcode.name == "STOP":
                return True
    except Exception:
        return False
    return False


def _location_position(location: str | None) -> int | None:
    if not location:
        return None
    match = re.search(r"\(pos (\d+)\)$", location)
    return int(match.group(1)) if match is not None else None


def _operand_preview(value: Any) -> str:
    if isinstance(value, _GlobalRef):
        return f"_GlobalRef({value.symbol})"
    if isinstance(value, bytes):
        return f"bytes(len={len(value)})"
    if value is _MARK:
        return "MARK"
    return f"{type(value).__name__}:{value!r}"
