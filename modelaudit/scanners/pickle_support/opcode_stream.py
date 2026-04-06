"""Pickle opcode stream parsing and scan-outcome helpers."""

import io
import os
import pickletools
import reprlib
import time
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Literal, TypedDict

from ..base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult, logger

_RESYNC_BUDGET = 8192  # Max bytes to scan forward when resyncing after an unknown opcode
_STACK_GLOBAL_OPERAND_PREVIEW_MAX = 128
_STACK_GLOBAL_BINARY_PREVIEW_BYTES = 8
_STACK_GLOBAL_OPERAND_PREVIEWER = reprlib.Repr()
_STACK_GLOBAL_OPERAND_PREVIEWER.maxstring = _STACK_GLOBAL_OPERAND_PREVIEW_MAX
_STACK_GLOBAL_OPERAND_PREVIEWER.maxother = _STACK_GLOBAL_OPERAND_PREVIEW_MAX
_STACK_GLOBAL_OPERAND_PREVIEWER.maxlist = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxtuple = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxset = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxfrozenset = 4
_STACK_GLOBAL_OPERAND_PREVIEWER.maxdict = 4
_RAW_PATTERN_SCAN_LIMIT_BYTES = 10 * 1024 * 1024
_NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES = 64 * 1024
_NESTED_PICKLE_VALIDATION_WINDOW_BYTES = 8 * 1024
_POST_BUDGET_GLOBAL_SCAN_LIMIT_BYTES = 100 * 1024 * 1024
_POST_BUDGET_GLOBAL_CONTEXT_BYTES = 4096
_POST_BUDGET_GLOBAL_MEMO_LIMIT_ENTRIES = 4096
_POST_BUDGET_GLOBAL_MAX_REFERENCE_FINDINGS = 4096
_POST_BUDGET_GLOBAL_DEADLINE_CHECK_INTERVAL_BYTES = 4096
_POST_BUDGET_EXPANSION_SCAN_LIMIT_BYTES = 8 * 1024 * 1024
_POST_BUDGET_OPCODE_SCAN_LIMIT_OPCODES = 500_000
_MEMO_WRITE_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"})
_MEMO_READ_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
_EXPANSION_EVENT_WINDOW = 6
_EXPANSION_GROWTH_BUILDERS = frozenset({"TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "LIST", "APPENDS", "APPEND"})
_EXPANSION_DUP_COUNT_THRESHOLD = 128
_EXPANSION_DUP_DENSITY_THRESHOLD = 0.10
_EXPANSION_GET_PUT_RATIO_THRESHOLD = 32.0
_EXPANSION_GET_PUT_MIN_READS = 128
_EXPANSION_MEMO_GROWTH_MIN_WRITES = 64
_EXPANSION_MEMO_GROWTH_STEPS_THRESHOLD = 32
_EXPANSION_RATIO_SUPPORTING_DUP_THRESHOLD = 64
_EXPANSION_RATIO_SUPPORTING_GROWTH_THRESHOLD = 16
_EXPANSION_TRIGGER_LABELS = {
    "suspicious_get_put_ratio": "high memo GET/PUT ratio",
    "excessive_dup_usage": "dense DUP usage",
    "memo_growth_chain": "iterative memo growth chain",
}
_BINARY_PICKLE_PROTOCOLS = frozenset({2, 3, 4, 5})
_PICKLE_OPCODE_BYTES = frozenset(ord(op.code) for op in pickletools.opcodes)
_TEXT_PICKLE_RESYNC_START_BYTES = frozenset(
    {
        ord("("),
        ord("."),
        ord("0"),
        ord("N"),
        ord("]"),
        ord("c"),
        ord("i"),
    }
)
_TEXT_PICKLE_RESYNC_IMPORT_OPCODES = frozenset({ord("c"), ord("i")})
_TEXT_PICKLE_RESYNC_NAME_SCAN_BYTES = 128 * 1024
_TEXT_PICKLE_RESYNC_STRUCTURE_PROBE_OPCODES = 20
_TEXT_PICKLE_RESYNC_NON_STRUCTURAL_OPCODES = frozenset({"GLOBAL", "INST", "MARK"})
_RESYNC_FAST_FORWARD_PROBE_BYTES = 64 * 1024
_RESYNC_FAST_FORWARD_TAIL_BYTES = max(
    _NESTED_PICKLE_VALIDATION_WINDOW_BYTES,
    (2 * _TEXT_PICKLE_RESYNC_NAME_SCAN_BYTES) + 2,
)
_CASE_SENSITIVE_IMPORT_SEGMENTS: frozenset[str] = frozenset({"PIL", "Cython"})


StackGlobalOperandKind = Literal["string", "missing_memo", "unknown", "non_string"]
MalformedStackGlobalReason = Literal["insufficient_context", "missing_memo", "mixed_or_non_string"]


class MalformedStackGlobalDetails(TypedDict):
    module_kind: StackGlobalOperandKind
    module: str
    function_kind: StackGlobalOperandKind
    function: str
    reason: MalformedStackGlobalReason


class _GenopsBudgetExceeded(Exception):
    """Signal that opcode iteration stopped due to an explicit resource budget."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _NestedPickleMatch:
    offset: int
    sample_size: int
    searched_bytes: int


@dataclass(frozen=True)
class _ResolvedImportRef:
    module: str
    function: str
    origin_index: int
    origin_is_ext: bool = False


@dataclass(frozen=True)
class _MutationTargetRef:
    kind: Literal["dict", "object"]
    callable_ref: tuple[str, str] | None = None


@dataclass
class _ExpansionHeuristicStreamState:
    stream_id: int
    opcode_count: int = 0
    memo_reads: int = 0
    memo_writes: int = 0
    dup_count: int = 0
    memo_growth_steps: int = 0
    max_memo_index: int = -1
    next_memo_index: int = 0
    last_written_index: int | None = None
    last_position: int = 0
    event_window: list[tuple[str, int | str]] = field(default_factory=list)


@dataclass(frozen=True)
class _ExpansionHeuristicFinding:
    stream_id: int
    position: int
    opcode_count: int
    memo_reads: int
    memo_writes: int
    get_put_ratio: float
    dup_count: int
    dup_density: float
    memo_growth_steps: int
    memo_slots_used: int
    triggers: tuple[str, ...]


@dataclass
class _PrimaryRefFinding:
    check_index: int
    issue_index: int


@dataclass
class _PickleOpcodeAnalysis:
    opcodes: list[tuple[Any, Any, int | None]] = field(default_factory=list)
    globals_found: set[tuple[str, str, str]] = field(default_factory=set)
    sequence_results: list[Any] = field(default_factory=list)
    stack_global_refs: dict[int, tuple[str, str]] = field(default_factory=dict)
    callable_refs: dict[int, tuple[str, str]] = field(default_factory=dict)
    callable_origin_refs: dict[int, int] = field(default_factory=dict)
    callable_origin_is_ext: dict[int, bool] = field(default_factory=dict)
    malformed_stack_globals: dict[int, MalformedStackGlobalDetails] = field(default_factory=dict)
    mutation_target_refs: dict[int, _MutationTargetRef] = field(default_factory=dict)
    executed_import_origins: set[int] = field(default_factory=set)
    executed_ref_keys: set[tuple[str, str]] = field(default_factory=set)
    max_analyzed_end_offset: int = 0
    max_analyzed_offset: int = -1
    first_pickle_end_pos: int | None = None
    opcode_count: int = 0
    max_stack_depth: int = 0
    stack_depth_warnings: list[dict[str, int | str]] = field(default_factory=list)
    extreme_stack_depth_event: dict[str, int | str] | None = None
    opcode_budget_exceeded: bool = False
    timeout_exceeded: bool = False
    error: Exception | None = None


_SEVERITY_PRIORITY = {
    IssueSeverity.DEBUG: 0,
    IssueSeverity.INFO: 1,
    IssueSeverity.WARNING: 2,
    IssueSeverity.CRITICAL: 3,
}


def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
    """Mark a scan result as inconclusive when analysis could not complete."""
    existing_reasons = result.metadata.get("scan_outcome_reasons")
    reasons = existing_reasons if isinstance(existing_reasons, list) else []

    if reason not in reasons:
        reasons.append(reason)

    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    result.metadata["scan_outcome_reasons"] = reasons
    result.metadata["analysis_incomplete"] = True


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    """Return True when the result includes WARNING/CRITICAL findings."""
    return any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def _finish_with_inconclusive_contract(
    result: ScanResult,
    *,
    default_success: bool,
    allow_security_findings_override: bool = False,
) -> None:
    """Finalize success so inconclusive/no-finding scans fail closed."""
    has_security_findings = _scan_result_has_security_findings(result)
    if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME and not has_security_findings:
        result.finish(success=False)
        return

    result.finish(success=default_success or (allow_security_findings_override and has_security_findings))


def _format_stack_global_string_preview(value: str) -> str:
    """Return a bounded preview for malformed STACK_GLOBAL string operands."""
    preview = _STACK_GLOBAL_OPERAND_PREVIEWER.repr(value)
    if len(preview) >= 2 and preview[0] == preview[-1] and preview[0] in {"'", '"'}:
        preview = preview[1:-1]
    return preview


def _format_stack_global_operand_preview(value: Any) -> str:
    """Return a bounded diagnostic preview for malformed STACK_GLOBAL operands."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        value_len = value.nbytes if isinstance(value, memoryview) else len(value)
        prefix_bytes = bytes(value[:_STACK_GLOBAL_BINARY_PREVIEW_BYTES])
        suffix = "..." if value_len > _STACK_GLOBAL_BINARY_PREVIEW_BYTES else ""
        return f"{type(value).__name__}(len={value_len}, hex=0x{prefix_bytes.hex()}{suffix})"

    preview = _STACK_GLOBAL_OPERAND_PREVIEWER.repr(value)
    if len(preview) > _STACK_GLOBAL_OPERAND_PREVIEW_MAX:
        preview = preview[:_STACK_GLOBAL_OPERAND_PREVIEW_MAX] + "...<truncated>"

    preview_value_len: int | None
    try:
        preview_value_len = len(value)
    except Exception:
        preview_value_len = None

    length_suffix = f" (len={preview_value_len})" if preview_value_len is not None else ""
    return f"{type(value).__name__}:{preview}{length_suffix}"


def _scan_structural_tamper_findings(file_data: bytes) -> list[dict[str, Any]]:
    """Detect structurally suspicious pickle stream patterns."""
    findings: list[dict[str, Any]] = []
    if not file_data:
        return findings

    offset = 0
    max_separator_skip = 256

    while offset < len(file_data):
        stream = file_data[offset:]
        bio = io.BytesIO(stream)
        stream_opcode_count = 0
        stream_had_stop = False
        seen_proto_version: int | None = None

        try:
            for opcode, arg, pos in pickletools.genops(bio):
                stream_opcode_count += 1
                opcode_pos = int(pos) if pos is not None else 0
                absolute_pos = offset + opcode_pos

                if opcode.name == "PROTO":
                    if stream_opcode_count > 1:
                        findings.append(
                            {
                                "kind": "misplaced_proto",
                                "stream_offset": offset,
                                "position": absolute_pos,
                                "protocol": arg,
                            }
                        )

                    if seen_proto_version is not None:
                        findings.append(
                            {
                                "kind": "duplicate_proto",
                                "stream_offset": offset,
                                "position": absolute_pos,
                                "protocol": arg,
                                "previous_protocol": seen_proto_version,
                            }
                        )
                    seen_proto_version = int(arg) if isinstance(arg, int) else None

                if opcode.name == "STOP":
                    stream_had_stop = True
                    offset = absolute_pos + 1
                    break
        except ValueError:
            probe_start = min(offset + 1, len(file_data))
            probe_end = min(offset + _RESYNC_BUDGET, len(file_data))
            next_offset = -1
            for idx in range(probe_start, probe_end - 1):
                if file_data[idx] == 0x80 and file_data[idx + 1] in (2, 3, 4, 5):
                    next_offset = idx
                    break

            if next_offset >= 0:
                offset = next_offset
                continue
            break
        except Exception:
            break

        if stream_had_stop:
            skipped = 0
            while offset < len(file_data) and skipped < max_separator_skip:
                if file_data[offset] == 0x80 and offset + 1 < len(file_data) and file_data[offset + 1] in (2, 3, 4, 5):
                    break
                offset += 1
                skipped += 1
            if skipped >= max_separator_skip and offset < len(file_data):
                break
            continue

        offset += 1

    return findings


def _is_plausible_python_module(name: str) -> bool:
    """Check whether *name* looks like a real Python module/package path."""
    if not name:
        return False

    if " " in name or "\t" in name:
        return False

    segments = name.split(".")
    if not segments or any(s == "" or not s.isascii() or not s.isidentifier() for s in segments):
        return False

    return all(
        any(char.islower() for char in seg)
        or seg in _CASE_SENSITIVE_IMPORT_SEGMENTS
        or (seg.isupper() and seg.isalpha())
        for seg in segments
    )


def _looks_like_pickle(data: bytes) -> bool:
    """Check if the given bytes resemble a pickle payload with robust validation."""
    if not data or len(data) < 2:
        return False

    first_byte = data[0]
    if first_byte == 0x80:
        if len(data) < 2:
            return False
        protocol = data[1]
        if protocol not in (2, 3, 4, 5):
            return False
    elif first_byte not in (
        ord("("),
        ord("]"),
        ord("}"),
        ord("c"),
        ord("i"),
        ord("l"),
        ord("d"),
        ord("t"),
        ord("p"),
        ord("g"),
        ord("I"),
        ord("L"),
        ord("F"),
        ord("S"),
        ord("U"),
        ord("N"),
        ord("V"),
        ord("M"),
    ):
        return False

    try:
        stream = io.BytesIO(data)
        valid_opcodes = 0
        has_non_mark_structure = False

        for opcode_count, (opcode, _arg, _pos) in enumerate(pickletools.genops(stream), 1):
            if opcode.name in {
                "BINPUT",
                "EMPTY_LIST",
                "GLOBAL",
                "INST",
                "MARK",
                "NONE",
                "POP",
                "STOP",
                "TUPLE",
                "LIST",
                "DICT",
                "SETITEM",
                "BUILD",
                "REDUCE",
            }:
                valid_opcodes += 1
            if opcode.name not in {"GLOBAL", "INST", "MARK"}:
                has_non_mark_structure = True

            if (
                opcode.name == "STOP"
                and has_non_mark_structure
                and (valid_opcodes >= 2 or data[0] not in {ord("("), ord("c"), ord("i")})
            ):
                return True

            if opcode_count >= 3 and valid_opcodes >= 2 and has_non_mark_structure:
                return True

            if opcode_count > 20:
                break
    except Exception as e:
        logger.debug("Error analyzing pickle structure: %s", e)
        return False

    return False


def _find_next_resync_stream_candidate_offset(search_window: bytes) -> int:
    """Return the next likely pickle stream start in a probe window, or -1 if absent."""
    for candidate in range(len(search_window)):
        first_byte = search_window[candidate]

        if first_byte == 0x80:
            if (
                candidate + 1 < len(search_window)
                and search_window[candidate + 1] in _BINARY_PICKLE_PROTOCOLS
                and (candidate + 2 >= len(search_window) or search_window[candidate + 2] in _PICKLE_OPCODE_BYTES)
            ):
                return candidate
            continue

        if first_byte not in _TEXT_PICKLE_RESYNC_START_BYTES:
            continue

        if first_byte in _TEXT_PICKLE_RESYNC_IMPORT_OPCODES:
            module_end = search_window.find(
                b"\n",
                candidate + 1,
                min(len(search_window), candidate + 1 + _TEXT_PICKLE_RESYNC_NAME_SCAN_BYTES),
            )
            if module_end == -1:
                continue

            function_end = search_window.find(
                b"\n",
                module_end + 1,
                min(len(search_window), module_end + 1 + _TEXT_PICKLE_RESYNC_NAME_SCAN_BYTES),
            )
            if function_end == -1:
                continue

            try:
                module_name = search_window[candidate + 1 : module_end].decode("utf-8")
                function_name = search_window[module_end + 1 : function_end].decode("utf-8")
            except UnicodeDecodeError:
                continue

            if (
                _is_plausible_python_module(module_name)
                and all(part.isidentifier() for part in function_name.split("."))
                and _looks_like_pickle(search_window[candidate:])
            ):
                return candidate
            continue

        if _looks_like_pickle(search_window[candidate:]):
            return candidate

    return -1


def _genops_with_fallback(
    file_obj: BinaryIO,
    *,
    multi_stream: bool = False,
    max_items: int | None = None,
    deadline: float | None = None,
) -> Any:
    """Wrapper around pickletools.genops that handles protocol mismatches."""
    _MAX_RESYNC_BYTES = 256
    resync_skipped = 0
    parsed_any_stream = False
    yielded_items = 0

    def _check_budget(*, pending_items: int = 0) -> None:
        if max_items is not None and (yielded_items + pending_items) >= max_items:
            raise _GenopsBudgetExceeded("max_items")
        if deadline is not None and time.time() > deadline:
            raise _GenopsBudgetExceeded("deadline")

    while True:
        stream_start = file_obj.tell()
        had_opcodes = False
        stream_error = False

        if not parsed_any_stream:
            try:
                op_iter = pickletools.genops(file_obj)
                while True:
                    _check_budget()
                    try:
                        item = next(op_iter)
                    except StopIteration:
                        break
                    had_opcodes = True
                    yield item
                    yielded_items += 1
            except ValueError as e:
                error_str = str(e).lower()
                is_unknown_opcode = "opcode" in error_str and "unknown" in error_str
                is_decode_or_text_error = (
                    isinstance(e, UnicodeDecodeError)
                    or "unicode" in error_str
                    or "codec can't decode" in error_str
                    or "no newline found" in error_str
                )

                if is_unknown_opcode or is_decode_or_text_error:
                    if had_opcodes:
                        logger.info(
                            "Pickle stream parsing interrupted after partial opcode extraction; "
                            "continuing with partial security analysis"
                        )
                        stream_error = True
                    elif is_unknown_opcode:
                        logger.info(
                            f"Protocol mismatch in pickle (joblib may use protocol 5 opcodes in protocol 4 files): {e}"
                        )
                    else:
                        raise
                else:
                    raise
        else:
            buffered: list[Any] = []
            needs_text_structure_probe = False
            has_text_structure = False
            try:
                current_byte = file_obj.read(1)
                file_obj.seek(stream_start, 0)
                needs_text_structure_probe = bool(current_byte and current_byte[0] in _TEXT_PICKLE_RESYNC_START_BYTES)

                op_iter = pickletools.genops(file_obj)
                while True:
                    _check_budget(pending_items=len(buffered))
                    try:
                        item = next(op_iter)
                    except StopIteration:
                        break
                    had_opcodes = True
                    buffered.append(item)

                    if needs_text_structure_probe and not has_text_structure:
                        opcode_name = item[0].name
                        has_text_structure = opcode_name not in _TEXT_PICKLE_RESYNC_NON_STRUCTURAL_OPCODES
                        if not has_text_structure and len(buffered) >= _TEXT_PICKLE_RESYNC_STRUCTURE_PROBE_OPCODES:
                            buffered.clear()
                            stream_error = True
                            break
            except ValueError:
                stream_error = True

            if needs_text_structure_probe and not has_text_structure:
                buffered.clear()
                stream_error = True

            if stream_error and had_opcodes:
                if multi_stream:
                    continue
                return

            if not stream_error:
                for buffered_item in buffered:
                    _check_budget()
                    yield buffered_item
                    yielded_items += 1

        if stream_error and had_opcodes:
            if multi_stream:
                parsed_any_stream = True
                continue
            return

        if not multi_stream:
            return

        if had_opcodes and not stream_error:
            parsed_any_stream = True

        if not had_opcodes:
            file_obj.seek(stream_start, 0)
            if not file_obj.read(1):
                return
            resync_skipped += 1
            if resync_skipped >= _MAX_RESYNC_BYTES:
                previous_tail = b""
                while True:
                    _check_budget()
                    probe_start = file_obj.tell()
                    probe = file_obj.read(_RESYNC_FAST_FORWARD_PROBE_BYTES)
                    if not probe:
                        return
                    search_window = previous_tail + probe
                    candidate = _find_next_resync_stream_candidate_offset(search_window)
                    if candidate >= 0:
                        file_obj.seek(probe_start - len(previous_tail) + candidate, 0)
                        resync_skipped = 0
                        break
                    previous_tail = search_window[-_RESYNC_FAST_FORWARD_TAIL_BYTES:]
            continue

        resync_skipped = 0
        next_byte = file_obj.read(1)
        if not next_byte:
            return
        file_obj.seek(-1, 1)


def _compute_pickle_length(path: str) -> int:
    """Compute the exact length of pickle data by finding the STOP opcode position."""
    try:
        with open(path, "rb") as f:
            for opcode, _arg, pos in pickletools.genops(f):
                if opcode.name == "STOP" and pos is not None:
                    return pos + 1
        return os.path.getsize(path)
    except Exception:
        file_size = os.path.getsize(path)
        return min(file_size // 2, 64)


def _find_nested_pickle_match(data: bytes | bytearray) -> _NestedPickleMatch | None:
    """Find a nested pickle within a bounded search window."""
    data_bytes = bytes(data)
    if len(data_bytes) < 2:
        return None

    search_limit = min(len(data_bytes), _NESTED_PICKLE_HEADER_SEARCH_LIMIT_BYTES)
    validation_limit = min(len(data_bytes), _NESTED_PICKLE_VALIDATION_WINDOW_BYTES)

    if _looks_like_pickle(data_bytes[:validation_limit]):
        return _NestedPickleMatch(
            offset=0,
            sample_size=validation_limit,
            searched_bytes=search_limit,
        )

    if search_limit < 3:
        return None

    cursor = 0
    max_header_start = search_limit - 3

    while cursor <= max_header_start:
        header_offset = data_bytes.find(b"\x80", cursor, max_header_start + 1)
        if header_offset == -1:
            break
        cursor = header_offset + 1

        protocol = data_bytes[header_offset + 1]
        next_opcode = data_bytes[header_offset + 2]
        if protocol not in _BINARY_PICKLE_PROTOCOLS or next_opcode not in _PICKLE_OPCODE_BYTES:
            continue

        sample_end = min(len(data_bytes), header_offset + _NESTED_PICKLE_VALIDATION_WINDOW_BYTES)
        if _looks_like_pickle(data_bytes[header_offset:sample_end]):
            return _NestedPickleMatch(
                offset=header_offset,
                sample_size=sample_end - header_offset,
                searched_bytes=search_limit,
            )

    return None


def _decode_string_to_bytes(s: str) -> list[tuple[str, bytes]]:
    """Attempt to decode a string from common encodings with stricter validation."""
    import base64
    import binascii
    import re

    candidates: list[tuple[str, bytes]] = []

    try:
        if (
            16 <= len(s) <= 10000
            and len(s) % 4 == 0
            and re.fullmatch(r"[A-Za-z0-9+/]+=*", s)
            and s.count("=") <= 2
            and not s.replace("=", "").endswith("=")
        ):
            decoded = base64.b64decode(s)
            if len(decoded) >= 8:
                candidates.append(("base64", decoded))
    except Exception as e:
        logger.debug("Failed to decode potential base64 string: %s", e)

    try:
        hex_str = s
        if "\\x" in s:
            hex_str = s.replace("\\x", "")
        if (
            16 <= len(hex_str) <= 5000
            and len(hex_str) % 2 == 0
            and re.fullmatch(r"[0-9a-fA-F]+", hex_str)
            and not re.match(r"^(.)\1*$", hex_str)
        ):
            decoded = binascii.unhexlify(hex_str)
            if len(decoded) >= 8:
                candidates.append(("hex", decoded))
    except Exception as e:
        logger.debug("Failed to decode potential hex string: %s", e)

    return candidates


def _is_short_period_repetition(s: str, max_period: int = 16) -> bool:
    """Return True for strings made by repeating a short token like ``ABCD1234``."""
    if len(s) < max_period * 2:
        return False
    if len(s) > 10 * 1024 * 1024:
        return False

    for period in range(2, min(max_period, len(s) // 2) + 1):
        if len(s) % period == 0:
            unit = s[:period]
            if all(s[i : i + period] == unit for i in range(0, len(s), period)):
                return True

    return False


def _should_ignore_opcode_sequence(opcodes: list[tuple], ml_context: dict[str, Any]) -> bool:
    """Return whether opcode-sequence analysis should be skipped."""
    del opcodes, ml_context
    return False


def _get_context_aware_severity(
    base_severity: IssueSeverity,
    ml_context: dict[str, Any],
    issue_type: str = "",
) -> IssueSeverity:
    """Return base severity without ML-confidence downgrading."""
    del ml_context, issue_type
    return base_severity


def _severity_priority(severity: IssueSeverity | None) -> int:
    """Return an ordering key for failed-check severity comparisons."""
    if severity is None:
        return -1
    return _SEVERITY_PRIORITY.get(severity, -1)
