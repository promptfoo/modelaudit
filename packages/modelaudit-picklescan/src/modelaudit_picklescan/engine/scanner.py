"""Opcode-level pickle analysis for the standalone package."""

from __future__ import annotations

import pickletools
import re
import time
from io import BytesIO
from typing import Any, BinaryIO, cast

from ..options import ScanOptions
from ..report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity
from .nested import (
    _decode_possible_encoded_pickle,
    _detect_oversized_encoded_pickle_prefixes,
    _has_pickle_prefix,
    _looks_like_pickle_payload,
)
from .policy import _GlobalRef, global_severity, suspicious_string_matches
from .stream import _BoundedPickleStream, _StreamReadError

_MARK = object()
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
_BASE64_LITERAL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_LITERAL_CHARS = frozenset("0123456789abcdefABCDEF")
_ENCODED_LITERAL_PROBE_CHARS = 64


class _OpcodeBudgetExceeded(Exception):
    """Raised when opcode analysis reaches the configured opcode limit."""

    def __init__(self, stream_offset: int, tail_prefix: bytes = b"") -> None:
        super().__init__("opcode budget exceeded")
        self.stream_offset = stream_offset
        self.tail_prefix = tail_prefix


class _ScanTimeout(Exception):
    """Raised when opcode analysis exceeds the configured timeout."""


def scan_pickle_payload(
    payload: bytes,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
    nested_depth: int = 0,
    deadline: float | None = None,
) -> PickleReport:
    """Scan pickle bytes and return a standalone report."""

    bytes_total = len(payload) if bytes_total is None else bytes_total
    return scan_pickle_stream(
        BytesIO(payload),
        source=source,
        options=options,
        bytes_total=bytes_total,
        position_offset=position_offset,
        nested_depth=nested_depth,
        deadline=deadline,
    )


def scan_pickle_stream(
    stream: BinaryIO,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
    nested_depth: int = 0,
    deadline: float | None = None,
) -> PickleReport:
    """Scan pickle bytes directly from a binary stream and return a standalone report."""

    started_at = time.monotonic()
    scan = _ScanState(
        source=source,
        stream=_BoundedPickleStream(stream, bytes_total),
        options=options,
        bytes_total=bytes_total,
        position_offset=position_offset,
        nested_depth=nested_depth,
        deadline=deadline,
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
        nested_depth: int,
        deadline: float | None,
    ) -> None:
        self.source = source
        self.stream = stream
        self.options = options
        self.bytes_total = bytes_total
        self.position_offset = position_offset
        self.nested_depth = nested_depth
        self.deadline = deadline if deadline is not None else time.monotonic() + options.timeout_s
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
        self._seen_notice_keys: set[tuple[str | None, str | None, str]] = set()
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
                    stream_position = int(pos or 0)
                    self._check_limits(opcode.name, arg, stream_position)
                    parsed_opcode = True

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
        except _OpcodeBudgetExceeded as error:
            self.status = ScanStatus.INCONCLUSIVE
            self._add_notice(
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
            self._scan_post_budget_tail(error.stream_offset, tail_prefix=error.tail_prefix)
        except _ScanTimeout:
            self.status = ScanStatus.INCONCLUSIVE
            self._add_notice(
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
                self._add_notice(
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

    def _check_limits(self, op_name: str, arg: Any, stream_offset: int) -> None:
        if self.opcode_count >= self.options.max_opcodes:
            raise _OpcodeBudgetExceeded(stream_offset, _post_budget_opcode_prefix(op_name, arg, self.stack))
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

            global_severity = global_severity_for_ref(callable_ref)
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
        return None

    def _scan_string_literal(self, value: str, *, op_name: str, position: int) -> None:
        for window in self._bounded_string_windows(value, op_name=op_name, position=position):
            for matched_pattern in suspicious_string_matches(window):
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
        if len(value) > self.options.max_nested_pickle_bytes:
            if _has_pickle_prefix(value):
                self._add_nested_payload_finding(
                    encoding="raw",
                    payload_size=len(value),
                    position=position,
                    analysis_incomplete=True,
                )
            return

        if not _looks_like_pickle_payload(value, max_bytes=self.options.max_nested_pickle_bytes):
            return

        self._add_nested_payload_finding(encoding="raw", payload_size=len(value), position=position)
        self._surface_nested_pickle_findings(value, encoding="raw", position=position)

    def _add_nested_payload_finding(
        self,
        *,
        encoding: str,
        payload_size: int,
        position: int,
        analysis_incomplete: bool = False,
    ) -> None:
        self._add_finding(
            Finding(
                message=(
                    "Nested pickle payload detected"
                    if not analysis_incomplete
                    else "Nested pickle payload exceeds deep-scan byte limit"
                ),
                severity=Severity.CRITICAL,
                location=f"{self.source} (pos {position})",
                rule_code="S213",
                details={
                    "encoding": encoding,
                    "payload_size": payload_size,
                    "max_nested_pickle_bytes": self.options.max_nested_pickle_bytes,
                    "analysis_incomplete": analysis_incomplete,
                },
                why=(
                    "This pickle contains another serialized pickle payload inside a byte field. "
                    "Nested payloads can hide code execution paths from shallow scanners."
                ),
            )
        )

    def _scan_encoded_nested_pickle_literal(self, value: str, *, position: int) -> None:
        values: tuple[str, ...] = (value,)
        if len(value) > self.options.max_string_literal_scan_chars:
            self._record_literal_scan_truncated(
                literal_type="string",
                literal_length=len(value),
                op_name="encoded_nested_pickle",
                position=position,
            )
            values = self._bounded_encoded_nested_windows(value)

        for candidate in values:
            decoded_payload_found = False
            for encoding, decoded in _decode_possible_encoded_pickle(
                candidate,
                max_nested_pickle_bytes=self.options.max_nested_pickle_bytes,
            ):
                decoded_payload_found = True
                self._add_encoded_nested_payload_finding(
                    encoding=encoding,
                    payload_size=len(decoded),
                    position=position,
                )
                self._surface_nested_pickle_findings(decoded, encoding=encoding, position=position)
            if decoded_payload_found:
                continue

            for encoding, payload_size in _detect_oversized_encoded_pickle_prefixes(
                candidate,
                max_nested_pickle_bytes=self.options.max_nested_pickle_bytes,
            ):
                self._add_encoded_nested_payload_finding(
                    encoding=encoding,
                    payload_size=payload_size,
                    position=position,
                    analysis_incomplete=True,
                )
                self._record_encoded_nested_payload_truncated(
                    encoding=encoding,
                    payload_size=payload_size,
                    position=position,
                )

    def _add_encoded_nested_payload_finding(
        self,
        *,
        encoding: str,
        payload_size: int,
        position: int,
        analysis_incomplete: bool = False,
    ) -> None:
        rule_code = "S601" if encoding == "base64" else "S602"
        details: dict[str, Any] = {
            "encoding": encoding,
            "payload_size": payload_size,
        }
        if analysis_incomplete:
            details["max_nested_pickle_bytes"] = self.options.max_nested_pickle_bytes
            details["analysis_incomplete"] = True

        self._add_finding(
            Finding(
                message=(
                    "Encoded pickle payload detected"
                    if not analysis_incomplete
                    else "Encoded pickle payload exceeds deep-scan byte limit"
                ),
                severity=Severity.CRITICAL,
                location=f"{self.source} (pos {position})",
                rule_code=rule_code,
                details=details,
                why=(
                    "Encoded nested pickle payloads can hide deserialization gadgets "
                    "inside apparently inert metadata strings."
                ),
            )
        )

    def _record_encoded_nested_payload_truncated(
        self,
        *,
        encoding: str,
        payload_size: int,
        position: int,
    ) -> None:
        if self.status == ScanStatus.COMPLETE:
            self.status = ScanStatus.INCONCLUSIVE
        self._add_notice(
            Notice(
                message="Encoded pickle payload exceeds configured deep-scan byte limit",
                severity=Severity.INFO,
                location=f"{self.source} (pos {position})",
                code="encoded_nested_payload_truncated",
                details={
                    "encoding": encoding,
                    "payload_size": payload_size,
                    "max_nested_pickle_bytes": self.options.max_nested_pickle_bytes,
                    "analysis_incomplete": True,
                },
            )
        )

    def _record_global_ref(self, ref: _GlobalRef, *, op_name: str) -> None:
        if ref.malformed:
            return

        self.global_count += 1
        global_severity = global_severity_for_ref(ref)
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

    def _add_notice(self, notice: Notice) -> None:
        key = (notice.code, notice.location, notice.message)
        if key in self._seen_notice_keys:
            return
        self._seen_notice_keys.add(key)
        self.notices.append(notice)

    def _bounded_string_windows(self, value: str, *, op_name: str, position: int) -> tuple[str, ...]:
        max_chars = self.options.max_string_literal_scan_chars
        if max_chars <= 0:
            if value:
                self._record_literal_scan_truncated(
                    literal_type="string",
                    literal_length=len(value),
                    op_name=op_name,
                    position=position,
                )
            return ()
        if len(value) <= max_chars:
            return (value,)

        self._record_literal_scan_truncated(
            literal_type="string",
            literal_length=len(value),
            op_name=op_name,
            position=position,
        )
        prefix_chars = max_chars // 2
        suffix_chars = max_chars - prefix_chars
        return (value[:prefix_chars], value[-suffix_chars:] if suffix_chars else "")

    def _record_literal_scan_truncated(
        self,
        *,
        literal_type: str,
        literal_length: int,
        op_name: str,
        position: int,
    ) -> None:
        if self.status == ScanStatus.COMPLETE:
            self.status = ScanStatus.INCONCLUSIVE
        self._add_notice(
            Notice(
                message=f"{literal_type.capitalize()} literal scan truncated at configured limit",
                severity=Severity.INFO,
                location=f"{self.source} (pos {position})",
                code="literal_scan_truncated",
                details={
                    "opcode": op_name,
                    "literal_type": literal_type,
                    "literal_length": literal_length,
                    "max_string_literal_scan_chars": self.options.max_string_literal_scan_chars,
                    "analysis_incomplete": True,
                },
            )
        )

    def _bounded_encoded_nested_windows(self, value: str) -> tuple[str, ...]:
        max_chars = _encoded_nested_window_char_limit(value, self.options.max_nested_pickle_bytes)
        if len(value) <= max_chars:
            return (value,)

        prefix = value[:max_chars]
        suffix = value[-max_chars:]
        if prefix == suffix:
            return (prefix,)
        return (prefix, suffix)

    def _surface_nested_pickle_findings(self, payload: bytes, *, encoding: str, position: int) -> None:
        if self.nested_depth >= self.options.max_nested_depth:
            return

        nested_source = f"{self.source} (nested {encoding} pickle at pos {position})"
        nested_report = scan_pickle_payload(
            payload,
            source=nested_source,
            options=self.options,
            nested_depth=self.nested_depth + 1,
            deadline=self.deadline,
        )
        for nested_finding in nested_report.findings:
            nested_finding_details = nested_finding.to_dict()["details"]
            self._add_finding(
                Finding(
                    message=f"Nested pickle finding: {nested_finding.message}",
                    severity=nested_finding.severity,
                    location=nested_finding.location,
                    rule_code=nested_finding.rule_code,
                    details={
                        "nested_encoding": encoding,
                        "nested_source": nested_source,
                        "nested_rule_code": nested_finding.rule_code,
                        "nested_details": nested_finding_details,
                    },
                    why=nested_finding.why,
                )
            )

        if nested_report.status != ScanStatus.COMPLETE:
            if self.status == ScanStatus.COMPLETE:
                self.status = ScanStatus.INCONCLUSIVE
            self._add_notice(
                Notice(
                    message="Nested pickle analysis did not complete",
                    severity=Severity.INFO,
                    location=nested_source,
                    code="nested_pickle_incomplete",
                    details={
                        "nested_encoding": encoding,
                        "nested_status": nested_report.status.value,
                        "nested_errors": [error.to_dict() for error in nested_report.errors],
                        "nested_notices": [notice.to_dict() for notice in nested_report.notices],
                        "analysis_incomplete": True,
                    },
                )
            )

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

    def _scan_post_budget_tail(self, stream_offset: int, *, tail_prefix: bytes = b"") -> None:
        if self.options.post_budget_scan_bytes <= 0:
            return

        try:
            read_size = max(self.options.post_budget_scan_bytes - len(tail_prefix), 0)
            tail = tail_prefix + self.stream.read(read_size)
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
        for needle in (
            b"nt\nsystem",
            b"os\nsystem",
            b"posix\nsystem",
            b"subprocess\nPopen",
            b"builtins\neval",
            b"__builtin__\neval",
        ):
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


def global_severity_for_ref(ref: _GlobalRef) -> Severity | None:
    return global_severity(ref.module, ref.name)


def _encoded_nested_window_char_limit(value: str, max_nested_pickle_bytes: int) -> int:
    max_base64_chars = ((max_nested_pickle_bytes + 2) // 3) * 4
    max_plain_hex_chars = max_nested_pickle_bytes * 2
    max_escaped_hex_chars = max_nested_pickle_bytes * 4
    probe = _encoded_literal_probe(value)
    if "\\x" in probe:
        return max(16, max_escaped_hex_chars)
    if _chars_are_in_alphabet(probe, _HEX_LITERAL_CHARS):
        return max(16, max_plain_hex_chars)
    if _chars_are_in_alphabet(probe, _BASE64_LITERAL_CHARS):
        return max(16, max_base64_chars)
    return 16


def _encoded_literal_probe(value: str) -> str:
    stripped = value.strip()
    max_probe_chars = _ENCODED_LITERAL_PROBE_CHARS * 2
    if len(stripped) <= max_probe_chars:
        return stripped
    return stripped[:_ENCODED_LITERAL_PROBE_CHARS] + stripped[-_ENCODED_LITERAL_PROBE_CHARS:]


def _chars_are_in_alphabet(value: str, alphabet: frozenset[str]) -> bool:
    return bool(value) and all(char in alphabet for char in value)


def _post_budget_opcode_prefix(op_name: str, arg: Any, stack: list[Any]) -> bytes:
    """Reconstruct simple text opcode bytes already consumed at the budget boundary."""
    if op_name == "STACK_GLOBAL" and len(stack) >= 2:
        module, name = stack[-2], stack[-1]
        if isinstance(module, str) and isinstance(name, str):
            return module.encode("utf-8", errors="ignore") + b"\n" + name.encode("utf-8", errors="ignore")

    if op_name not in {"GLOBAL", "INST"}:
        return b""

    module, _, name = str(arg).partition(" ")
    if not module or not name:
        return b""
    opcode_byte = b"c" if op_name == "GLOBAL" else b"i"
    return opcode_byte + module.encode("utf-8", errors="ignore") + b"\n" + name.encode("utf-8", errors="ignore") + b"\n"


def _coerce_text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


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
