"""Adversarial pickle corpus checked against CPython execution semantics."""

from __future__ import annotations

import builtins
import dataclasses
import gc
import json
import logging
import pickle
import shlex
import shutil
import site
import statistics
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, ScanOptions, ScanStatus, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE, _with_call_graph_findings
from modelaudit_picklescan.call_graph import (
    _call_graph_entrypoints,
    _calls_for_function,
    _find_sink_path,
    find_dangerous_call_graphs,
    has_unanalyzed_call_graph_import_references,
)

pytestmark = pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None,
    reason="Rust picklescan extension is not built",
)

OperandBuilder = Callable[[bytes], bytes]
MemoOpcodeBuilder = Callable[[int], bytes]


def _runtime_before(version: tuple[int, int]) -> bool:
    return sys.version_info < version


@dataclass(frozen=True)
class AdversarialCase:
    name: str
    payload: bytes
    options: ScanOptions | None = None


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _binunicode(data: bytes) -> bytes:
    return b"X" + len(data).to_bytes(4, "little") + data


def _encoded_probe_limit_decoy_literal() -> str:
    decoys = "".join(f"gAR9Lg==-decoy-{index}|" for index in range(64))
    return f"{decoys}Y29zCnN5c3RlbQopUi4={'A' * 65}"


def _text_operand(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return _short_binunicode(data)
    return _binunicode(data)


def _bytes_operand(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"C" + bytes([len(data)]) + data
    return b"B" + len(data).to_bytes(4, "little") + data


def _int_operand(value: int) -> bytes:
    if 0 <= value <= 0xFF:
        return b"K" + bytes([value])
    if -0x80000000 <= value <= 0x7FFFFFFF:
        return b"J" + value.to_bytes(4, "little", signed=True)
    raise ValueError("test pickle helper only supports BININT1/BININT operands")


def _binunicode8(data: bytes) -> bytes:
    return b"\x8d" + len(data).to_bytes(8, "little") + data


def _unicode(data: bytes) -> bytes:
    return b"V" + data + b"\n"


def _string(data: bytes) -> bytes:
    return b"S" + repr(data.decode("ascii")).encode("ascii") + b"\n"


def _short_binstring(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINSTRING helper accepts at most 255 bytes")
    return b"U" + bytes([len(data)]) + data


def _binstring(data: bytes) -> bytes:
    return b"T" + len(data).to_bytes(4, "little") + data


TEXT_OPERANDS: dict[str, OperandBuilder] = {
    "short-binunicode": _short_binunicode,
    "binunicode": _binunicode,
    "binunicode8": _binunicode8,
    "unicode": _unicode,
    "string": _string,
    "short-binstring": _short_binstring,
    "binstring": _binstring,
}

STACK_NEUTRAL_GAPS = {
    "empty": b"",
    "dup-pop": b"20",
    "mark-popmark": b"(0",
    "none-pop": b"N0",
    "empty-tuple-pop": b")0",
    "binint1-pop": b"K\x010",
}

MEMO_WRITES: dict[str, MemoOpcodeBuilder] = {
    "memoize": lambda index: b"\x94",
    "binput": lambda index: b"q" + bytes([index]),
    "long-binput": lambda index: b"r" + index.to_bytes(4, "little"),
    "put": lambda index: b"p" + str(index).encode("ascii") + b"\n",
}

MEMO_READS: dict[str, MemoOpcodeBuilder] = {
    "binget": lambda index: b"h" + bytes([index]),
    "long-binget": lambda index: b"j" + index.to_bytes(4, "little"),
    "get": lambda index: b"g" + str(index).encode("ascii") + b"\n",
}


def _encoded_nested_probe_limit_payload() -> bytes:
    decoys = "".join(f"gAR9Lg==-decoy-{index}|" for index in range(64))
    literal = f"{decoys}Y29zCnN5c3RlbQopUi4{'A' * 65}".encode()
    return b"\x80\x04" + _binunicode(literal) + b"."


def _stack_global_call(
    module_operand: bytes, name_operand: bytes, gap_after_module: bytes, gap_after_name: bytes
) -> bytes:
    return b"\x80\x04" + module_operand + gap_after_module + name_operand + gap_after_name + b"\x93)R."


def _memoized_stack_global_call(
    write_name: str,
    read_name: str,
    gap_label: str,
    gap: bytes,
    *,
    post_budget: bool,
) -> AdversarialCase:
    write = MEMO_WRITES[write_name]
    read = MEMO_READS[read_name]
    module_index = 0 if write_name == "memoize" else 5
    name_index = 1 if write_name == "memoize" else 6
    payload = (
        _short_binunicode(b"subprocess")
        + write(module_index)
        + gap
        + _short_binunicode(b"run")
        + write(name_index)
        + gap
        + read(module_index)
        + gap
        + read(name_index)
        + gap
        + b"\x93)R."
    )
    if post_budget:
        return AdversarialCase(
            f"post-budget-tail-local-{write_name}-{read_name}-{gap_label}",
            b"\x80\x04\x88" + payload,
            ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
        )
    return AdversarialCase(f"memo-{write_name}-{read_name}-{gap_label}", b"\x80\x04" + payload)


def _pre_memoized_post_budget_call(gap_after_module_read: bytes, gap_after_name_read: bytes) -> bytes:
    prefix = b"\x80\x04" + _short_binunicode(b"subprocess") + b"\x94" + _short_binunicode(b"run") + b"\x94"
    return prefix + (b"\x880" * 4) + b"h\x00" + gap_after_module_read + b"h\x01" + gap_after_name_read + b"\x93)R."


def _build_adversarial_cases() -> list[AdversarialCase]:
    cases: list[AdversarialCase] = []

    for module_label, module_operand_builder in TEXT_OPERANDS.items():
        for name_label, name_operand_builder in TEXT_OPERANDS.items():
            module_operand = module_operand_builder(b"subprocess")
            name_operand = name_operand_builder(b"run")
            cases.append(
                AdversarialCase(
                    f"operand-encoding-{module_label}-{name_label}",
                    _stack_global_call(module_operand, name_operand, b"", b""),
                )
            )
            cases.append(
                AdversarialCase(
                    f"post-budget-operand-encoding-{module_label}-{name_label}",
                    b"\x80\x04\x88" + module_operand + name_operand + b"\x93)R.",
                    ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
                )
            )

    for module_gap_label, module_gap in STACK_NEUTRAL_GAPS.items():
        for name_gap_label, name_gap in STACK_NEUTRAL_GAPS.items():
            cases.append(
                AdversarialCase(
                    f"inline-gap-{module_gap_label}-{name_gap_label}",
                    _stack_global_call(
                        _short_binunicode(b"subprocess"),
                        _short_binunicode(b"run"),
                        module_gap,
                        name_gap,
                    ),
                )
            )
            cases.append(
                AdversarialCase(
                    f"post-budget-prememo-gap-{module_gap_label}-{name_gap_label}",
                    _pre_memoized_post_budget_call(module_gap, name_gap),
                    ScanOptions(max_opcodes=7, post_budget_scan_bytes=4096),
                )
            )

    for write_name in MEMO_WRITES:
        for read_name in MEMO_READS:
            for gap_label, gap in STACK_NEUTRAL_GAPS.items():
                cases.append(
                    _memoized_stack_global_call(
                        write_name,
                        read_name,
                        gap_label,
                        gap,
                        post_budget=False,
                    )
                )
                cases.append(
                    _memoized_stack_global_call(
                        write_name,
                        read_name,
                        gap_label,
                        gap,
                        post_budget=True,
                    )
                )

    cases.extend(
        [
            AdversarialCase("global-reduce", b"csubprocess\nrun\n)R."),
            AdversarialCase(
                "post-budget-global-reduce",
                b"\x80\x04\x88csubprocess\nrun\n)R.",
                ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
            ),
            AdversarialCase("inst", b"(isubprocess\nrun\n."),
            AdversarialCase(
                "post-budget-inst",
                b"\x80\x04\x88(isubprocess\nrun\n.",
                ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
            ),
            AdversarialCase(
                "obj-stack-global",
                b"\x80\x04(" + _short_binunicode(b"subprocess") + _short_binunicode(b"run") + b"\x93o.",
            ),
            AdversarialCase(
                "post-budget-obj-stack-global",
                b"\x80\x04\x88(" + _short_binunicode(b"subprocess") + _short_binunicode(b"run") + b"\x93o.",
                ScanOptions(max_opcodes=2, post_budget_scan_bytes=4096),
            ),
            AdversarialCase(
                "invalid-tuple-wrapped-operands",
                b"\x80\x04" + _short_binunicode(b"subprocess") + _short_binunicode(b"run") + b"\x86\x93)R.",
            ),
            AdversarialCase(
                "invalid-reversed-operands",
                b"\x80\x04" + _short_binunicode(b"run") + _short_binunicode(b"subprocess") + b"\x93)R.",
            ),
            AdversarialCase(
                "invalid-bytes-operands",
                b"\x80\x04" + b"C\x0asubprocess" + b"C\x03run" + b"\x93)R.",
            ),
            AdversarialCase(
                "invalid-mark-between-operands",
                b"\x80\x04" + _short_binunicode(b"subprocess") + b"(" + _short_binunicode(b"run") + b"\x93)R.",
            ),
            AdversarialCase(
                "invalid-popped-name",
                b"\x80\x04" + _short_binunicode(b"subprocess") + _short_binunicode(b"run") + b"0\x93)R.",
            ),
        ]
    )

    return cases


ADVERSARIAL_CASES = _build_adversarial_cases()


def _module_available(module_name: str) -> bool:
    try:
        return find_spec(module_name) is not None
    except ModuleNotFoundError:
        return False


def _module_global_available(module_name: str, name: str) -> bool:
    try:
        module = import_module(module_name)
    except Exception:
        return False
    return hasattr(module, name)


def _calls_subprocess_run_under_cpython(payload: bytes, monkeypatch: pytest.MonkeyPatch) -> bool:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def sentinel(*args: object, **kwargs: object) -> str:
        calls.append((args, kwargs))
        return "oracle-called"

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", sentinel)
        try:
            result = pickle.loads(payload)
        except Exception:
            return False

    return result == "oracle-called" and bool(calls)


def _has_critical_subprocess_run_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "subprocess"
        and finding.details.get("name") == "run"
        for finding in report.findings
    )


def _has_critical_atexit_register_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "atexit"
        and finding.details.get("name") == "register"
        for finding in report.findings
    )


def _has_critical_mailcap_findmatch_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "mailcap"
        and finding.details.get("name") == "findmatch"
        for finding in report.findings
    )


def _has_critical_builtins_map_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "builtins"
        and finding.details.get("name") == "map"
        for finding in report.findings
    )


def _has_critical_builtins_filter_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "builtins"
        and finding.details.get("name") == "filter"
        for finding in report.findings
    )


def _has_critical_builtins_hasattr_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "builtins"
        and finding.details.get("name") == "hasattr"
        for finding in report.findings
    )


def _has_suspicious_magic_method_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.WARNING
        and finding.rule_code == "SUSPICIOUS_STRING"
        and finding.details.get("pattern") == "magic method"
        for finding in report.findings
    )


def _has_dynamic_type_callable_attribute_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.WARNING
        and finding.rule_code == "DYNAMIC_TYPE_CALLABLE_ATTRIBUTE"
        and finding.details.get("callable_import_reference") == "pathlib.Path.touch"
        for finding in report.findings
    )


def _has_dynamic_type_unknown_key_overflow_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.WARNING
        and finding.rule_code == "DYNAMIC_TYPE_CALLABLE_ATTRIBUTE"
        and finding.details.get("tracked_dynamic_key_value_overflow") is True
        for finding in report.findings
    )


def _has_critical_global_finding(report: PickleReport, module: str, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


def _has_critical_call_graph_limit_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH_LIMIT"
        and finding.details.get("analysis_incomplete") is True
        for finding in report.findings
    )


def _has_encoded_nested_probe_limit_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "S601"
        and finding.details.get("encoding") == "base64"
        and finding.details.get("analysis_incomplete") is True
        and finding.details.get("max_nested_payload_probes") == 64
        for finding in report.findings
    )


def _has_critical_call_graph_file_write_finding(
    report: PickleReport,
    opener_module: str,
    opener_name: str,
    writer_module: str,
    writer_name: str,
) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH_FILE_WRITE"
        and finding.details.get("opener_module") == opener_module
        and finding.details.get("opener_name") == opener_name
        and finding.details.get("module") == writer_module
        and finding.details.get("name") == writer_name
        and finding.details.get("open_sink") == "builtins.open"
        and str(finding.details.get("write_sink", "")).endswith(".write")
        for finding in report.findings
    )


def _has_critical_builtins_staticmethod_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "builtins"
        and finding.details.get("name") == "staticmethod"
        for finding in report.findings
    )


def _has_critical_builtins_property_get_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "builtins"
        and finding.details.get("name") == "property.__get__"
        for finding in report.findings
    )


def _has_critical_builtins_classmethod_get_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "builtins"
        and finding.details.get("name") == "classmethod.__get__"
        for finding in report.findings
    )


def _has_critical_private_functools_partial_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "_functools"
        and finding.details.get("name") == "partial"
        for finding in report.findings
    )


def _has_critical_private_functools_reduce_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "_functools"
        and finding.details.get("name") == "reduce"
        for finding in report.findings
    )


def _has_critical_functools_wrapper_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "functools"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_logging_filterer_filter_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "logging"
        and finding.details.get("name") == "Filterer.filter"
        for finding in report.findings
    )


def _has_critical_inspect_getmembers_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "inspect"
        and finding.details.get("name") == "getmembers"
        for finding in report.findings
    )


def _has_critical_itertools_accumulate_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "accumulate"
        for finding in report.findings
    )


def _has_critical_itertools_dropwhile_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "dropwhile"
        for finding in report.findings
    )


def _has_critical_itertools_filterfalse_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "filterfalse"
        for finding in report.findings
    )


def _has_critical_itertools_groupby_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "groupby"
        for finding in report.findings
    )


def _has_critical_itertools_starmap_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "starmap"
        for finding in report.findings
    )


def _has_critical_itertools_takewhile_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "takewhile"
        for finding in report.findings
    )


def _has_critical_dataclasses_create_fn_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "dataclasses"
        and finding.details.get("name") == "_create_fn"
        for finding in report.findings
    )


def _has_critical_setuptools_distutils_spawn_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "setuptools._distutils.spawn"
        and finding.details.get("name") == "spawn"
        for finding in report.findings
    )


def _has_critical_site_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "site"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_unittest_loader_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "unittest.loader"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_pipes_template_copy_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "pipes"
        and finding.details.get("name") == "Template.copy"
        for finding in report.findings
    )


def _has_critical_operator_call_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "operator"
        and finding.details.get("name") == "call"
        for finding in report.findings
    )


def _has_critical_operator_setitem_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL"
        and finding.details.get("module") == "operator"
        and finding.details.get("name") == "setitem"
        for finding in report.findings
    )


def _has_critical_typing_eval_type_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "typing"
        and finding.details.get("name") == "_eval_type"
        for finding in report.findings
    )


def _has_critical_typing_get_type_hints_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "typing"
        and finding.details.get("name") == "get_type_hints"
        for finding in report.findings
    )


def _has_critical_weakref_finalize_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "weakref"
        and finding.details.get("name") == "finalize"
        for finding in report.findings
    )


def _has_critical_sched_scheduler_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "sched"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_contextlib_exitstack_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "contextlib"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_contextvars_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "contextvars"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_types_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "types"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_unittest_mock_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "unittest.mock"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _has_critical_concurrent_futures_finding(report: PickleReport, name: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "concurrent.futures"
        and finding.details.get("name") == name
        for finding in report.findings
    )


def _atexit_register_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"atexit"), _short_binunicode(b"register"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"\x86R."]
    return b"".join(parts)


def _weakref_finalize_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"weakref"), _short_binunicode(b"finalize"), b"\x93"]
    parts += [_short_binunicode(b"collections"), _short_binunicode(b"UserList"), b"\x93)R"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"\x87R."]
    return b"".join(parts)


def _sched_scheduler_run_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"sched"), _short_binunicode(b"scheduler"), b"\x93)R\x94"]
    parts += [_short_binunicode(b"sched"), _short_binunicode(b"scheduler.enter"), b"\x93("]
    parts += [b"h\x00", b"K\x00", b"K\x00"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"\x85", b"tR0"]
    parts += [_short_binunicode(b"sched"), _short_binunicode(b"scheduler.run"), b"\x93h\x00\x85R."]
    return b"".join(parts)


def _contextlib_exitstack_close_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"contextlib"), _short_binunicode(b"ExitStack"), b"\x93)R\x94"]
    parts += [_short_binunicode(b"contextlib"), _short_binunicode(b"ExitStack.callback"), b"\x93("]
    parts += [b"h\x00"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"tR0"]
    parts += [_short_binunicode(b"contextlib"), _short_binunicode(b"ExitStack.close"), b"\x93h\x00\x85R."]
    return b"".join(parts)


def _contextlib_exitstack_enter_context_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}"]
    parts += [_text_operand("__enter__"), _short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93s"]
    parts += [_text_operand("__exit__"), _short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93s"]
    parts += [b"tR\x940"]
    parts += [_short_binunicode(b"contextlib"), _short_binunicode(b"ExitStack"), b"\x93)R\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"contextlib"), _short_binunicode(b"ExitStack.enter_context"), b"\x93"]
        parts += [b"h\x01h\x02\x86R"]
    else:
        parts += [b"h\x02"]
    parts += [b"."]
    return b"".join(parts)


def _contextvars_context_run_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"contextvars"), _short_binunicode(b"Context"), b"\x93)R\x940"]
    parts += [_short_binunicode(b"contextvars"), _short_binunicode(b"Context.run"), b"\x93("]
    parts += [b"h\x00"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"tR."]
    return b"".join(parts)


def _types_methodtype_bound_method_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in marker.parts)
    parts += [b"tR\x940"]
    parts += [_short_binunicode(b"types"), _short_binunicode(b"MethodType"), b"\x93("]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"h\x00", b"tR"]
    if include_call:
        parts += [b")R"]
    parts += [b"."]
    return b"".join(parts)


def _types_dynamicclassattribute_get_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"types"), _short_binunicode(b"DynamicClassAttribute"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R\x94"]
    if include_call:
        parts += [_short_binunicode(b"types"), _short_binunicode(b"DynamicClassAttribute.__get__"), b"\x93"]
        parts += [b"h\x00"]
        parts += [
            _short_binunicode(b"pathlib"),
            _short_binunicode(type(marker).__name__.encode()),
            b"\x93(",
        ]
        parts.extend(_text_operand(part) for part in marker.parts)
        parts += [b"tR", b"\x86R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _functools_cached_property_get_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"types"), _short_binunicode(b"new_class"), b"\x93"]
    parts += [_text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85\x86R\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    parts += [_short_binunicode(b"functools"), _short_binunicode(b"cached_property"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R\x940"]
    parts += [_short_binunicode(b"functools"), _short_binunicode(b"cached_property.__set_name__"), b"\x93"]
    parts += [b"(", b"h\x02", b"h\x00", _text_operand("x"), b"tR0"]
    if include_call:
        parts += [_short_binunicode(b"functools"), _short_binunicode(b"cached_property.__get__"), b"\x93"]
        parts += [b"(", b"h\x02", b"h\x01", b"h\x00", b"tR"]
    else:
        parts += [b"h\x02"]
    parts += [b"."]
    return b"".join(parts)


def _functools_cmp_to_key_operator_lt_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"functools"), _short_binunicode(b"cmp_to_key"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_text"), b"\x93"]
    parts += [b"\x85R\x940"]
    parts += [b"h\x00"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in marker.parts)
    parts += [b"tR", b"\x85R\x940"]
    parts += [b"h\x00", _text_operand("x"), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(b"lt"), b"\x93"]
        parts += [b"h\x01h\x02\x86R"]
    else:
        parts += [b"h\x01h\x02\x86"]
    parts += [b"."]
    return b"".join(parts)


def _logging_filterer_filter_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Filterer"), b"\x93"]
    parts += [b")R\x940"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Filterer.addFilter"), b"\x93"]
    parts += [b"(", b"h\x00", _short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93", b"tR0"]
    if include_call:
        parts += [
            _short_binunicode(b"pathlib"),
            _short_binunicode(type(marker).__name__.encode()),
            b"\x93(",
        ]
        parts.extend(_text_operand(part) for part in marker.parts)
        parts += [b"tR", b"\x940"]
        parts += [_short_binunicode(b"logging"), _short_binunicode(b"Filterer.filter"), b"\x93"]
        parts += [b"(", b"h\x00", b"h\x01", b"tR"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _tuple_payload_operands(operands: list[bytes]) -> bytes:
    if not operands:
        return b")"
    if len(operands) == 1:
        return operands[0] + b"\x85"
    if len(operands) == 2:
        return operands[0] + operands[1] + b"\x86"
    if len(operands) == 3:
        return operands[0] + operands[1] + operands[2] + b"\x87"
    return b"(" + b"".join(operands) + b"t"


def _list_payload_operands(operands: list[bytes]) -> bytes:
    return b"(" + b"".join(operands) + b"l"


def _global_operand(module: str, name: str) -> bytes:
    return _short_binunicode(module.encode()) + _short_binunicode(name.encode()) + b"\x93"


def _legacy_global_operand(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def _dict_setitem(key: str, value: bytes) -> bytes:
    return _text_operand(key) + value + b"s"


def _log_record_payload(message: str, args: bytes = b")") -> list[bytes]:
    return [
        _short_binunicode(b"logging"),
        _short_binunicode(b"LogRecord"),
        b"\x93",
        b"(",
        _text_operand("picklescan"),
        b"K\x14",
        _text_operand("model.pkl"),
        b"K\x01",
        _text_operand(message),
        args,
        b"N",
        b"tR\x94",
    ]


def _logging_file_handler_payload(
    marker: Path,
    *,
    handler_module: str,
    handler_name: str,
    handler_args: list[bytes],
    driver_module: str,
    driver_name: str,
    message: str,
    include_emit: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [
        _short_binunicode(handler_module.encode()),
        _short_binunicode(handler_name.encode()),
        b"\x93",
    ]
    parts += [_tuple_payload_operands([_text_operand(str(marker)), *handler_args]), b"R\x94"]
    if not include_emit:
        parts += [b"h\x00", b"."]
        return b"".join(parts)

    parts += _log_record_payload(message)
    parts += [
        _short_binunicode(driver_module.encode()),
        _short_binunicode(driver_name.encode()),
        b"\x93",
    ]
    parts += [b"h\x00h\x01\x86R0"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Handler.close"), b"\x93"]
    parts += [b"h\x00\x85R."]
    return b"".join(parts)


def _logging_file_handler_pth_payload(pth_path: Path, marker: Path) -> bytes:
    pth_args = _tuple_payload_operands(
        [
            _text_operand("im"),
            _text_operand("port pathlib;pathlib.Path("),
            _text_operand(repr(str(marker))),
            _text_operand(").write_text('owned-by-logging-pth')"),
        ]
    )
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"FileHandler"), b"\x93"]
    parts += [_tuple_payload_operands([_text_operand(str(pth_path)), _text_operand("w")]), b"R\x94"]
    parts += _log_record_payload("%s%s%s%s", pth_args)
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Handler.handle"), b"\x93"]
    parts += [b"h\x00h\x01\x86R0"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Handler.close"), b"\x93"]
    parts += [b"h\x00\x85R."]
    return b"".join(parts)


def _logging_stream_handler_pth_payload(
    pth_path: Path,
    marker: Path,
    *,
    include_emit: bool,
    emit_global: str,
) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-logging-stream')\n",
    ]
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"argparse"), _short_binunicode(b"FileType"), b"\x93"]
    parts += [_text_operand("w"), b"\x85R\x94"]
    parts += [b"h\x00", _text_operand(str(pth_path)), b"\x85R\x94"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"StreamHandler"), b"\x93"]
    parts += [b"h\x01\x85R\x94"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"getLogger"), b"\x93"]
    parts += [b")R\x94"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Logger.setLevel"), b"\x93"]
    parts += [b"h\x03K\x00\x86R0"]
    parts += [_short_binunicode(b"logging"), _short_binunicode(b"Logger.addHandler"), b"\x93"]
    parts += [b"h\x03h\x02\x86R0"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93"]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_emit:
        parts += [_short_binunicode(b"logging"), _short_binunicode(emit_global.encode()), b"\x93"]
        if emit_global.startswith("Logger."):
            parts += [b"h\x03h\x04\x86R"]
        else:
            parts += [b"h\x04\x85R"]
    else:
        parts += [b"h\x03"]
    parts += [b"."]
    return b"".join(parts)


def _restore_root_logger(root_logger: logging.Logger, handlers: list[logging.Handler], level: int) -> None:
    for handler in list(root_logger.handlers):
        if handler not in handlers:
            root_logger.removeHandler(handler)
            handler.close()
    root_logger.handlers[:] = handlers
    root_logger.setLevel(level)


def _numpy_savetxt_pth_payload(pth_path: Path, marker: Path, *, writer_module: str, include_write: bool) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-numpy-savetxt')",
    ]
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93"]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_write:
        parts += [_short_binunicode(writer_module.encode()), _short_binunicode(b"savetxt"), b"\x93"]
        parts += [_text_operand(str(pth_path)), b"]h\x00a", _text_operand("%s"), b"\x87R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _dotenv_set_key_pth_payload(pth_path: Path, marker: Path, *, writer_module: str, include_write: bool) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-dotenv')#",
    ]
    parts = [b"\x80\x04"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_write:
        parts += [_global_operand(writer_module, "set_key")]
        parts += [_tuple_payload_operands([_text_operand(str(pth_path)), b"h\x00", _text_operand("x")]), b"R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _click_open_file_echo_pth_payload(pth_path: Path, marker: Path, *, click_module: str, include_write: bool) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-click')",
    ]
    parts = [b"\x80\x04"]
    if include_write:
        parts += [_global_operand(click_module, "open_file")]
        parts += [_tuple_payload_operands([_text_operand(str(pth_path)), _text_operand("w")]), b"R\x94"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_write:
        parts += [_global_operand(click_module, "echo")]
        parts += [b"h\x01h\x00\x86R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _click_lazy_file_echo_pth_payload(pth_path: Path, marker: Path, *, include_write: bool) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-click-lazyfile')",
    ]
    parts = [b"\x80\x04"]
    if include_write:
        parts += [_global_operand("click.utils", "LazyFile")]
        parts += [_tuple_payload_operands([_text_operand(str(pth_path)), _text_operand("w")]), b"R\x94"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_write:
        parts += [_global_operand("click", "echo")]
        parts += [b"h\x01h\x00\x86R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _io_fileio_pth_payload(pth_path: Path, _marker: Path, *, include_write: bool) -> tuple[bytes, bytes]:
    expected_text = (
        "import os,pathlib;pathlib.Path(os.environ['MODELAUDIT_PICKLESCAN_MARKER']).write_text('owned-by-io-fileio')\n"
    )
    expected_line = expected_text.encode()
    fragments = ["im"]
    fragments.extend(expected_text[offset : offset + 24] for offset in range(2, len(expected_text), 24))
    parts = [b"\x80\x04"]
    if include_write:
        parts += [_global_operand("io", "FileIO")]
        parts += [_tuple_payload_operands([_text_operand(str(pth_path)), _text_operand("w")]), b"R\x94"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x940"]
    joined_ref = b"h\x01" if include_write else b"h\x00"
    parts += [_global_operand("builtins", "str.encode")]
    parts += [joined_ref + b"\x85R"]
    if include_write:
        parts += [b"\x940"]
        parts += [_global_operand("io", "FileIO.write")]
        parts += [b"h\x00h\x02\x86R00"]
        parts += [_global_operand("io", "FileIO.close")]
        parts += [b"h\x00\x85R"]
    parts += [b"."]
    return b"".join(parts), expected_line


def _builtin_dict_get_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-dict-get')"
    code_fragments = [code[offset : offset + 18] for offset in range(0, len(code), 18)]
    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_global_operand("builtins", "__dict__"), b"\x940"]
        parts += [_global_operand("builtins", "str.join")]
        parts += [_text_operand(""), _tuple_payload_operands([_text_operand("ev"), _text_operand("al")])]
        parts += [b"\x86R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x00h\x01\x86R\x940"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in code_fragments])]
    parts += [b"\x86R"]
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _module_dict_builtins_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-fragmented-module-builtins')"
    code_fragments = [code[offset : offset + 18] for offset in range(0, len(code), 18)]
    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_global_operand("sysconfig", "__dict__"), b"\x940"]
        parts += [_global_operand("builtins", "str.join")]
        parts += [
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in ["_", "_", "builtins", "_", "_"]]),
        ]
        parts += [b"\x86R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x00h\x01\x86R\x940"]
        parts += [_global_operand("builtins", "str.join")]
        parts += [_text_operand(""), _tuple_payload_operands([_text_operand("ev"), _text_operand("al")])]
        parts += [b"\x86R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x02h\x03\x86R\x940"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in code_fragments])]
    parts += [b"\x86R"]
    if include_lookup:
        parts += [b"\x940h\x04h\x05\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _string_formatter_get_field_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-formatter-get-field')"
    code_fragments = [code[offset : offset + 19] for offset in range(0, len(code), 19)]
    field_fragments = [
        "0.",
        "_",
        "_",
        "globals",
        "_",
        "_",
        "[",
        "_",
        "_",
        "builtins",
        "_",
        "_",
        "][",
        "ev",
        "al",
        "]",
    ]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_global_operand("string", "Formatter"), b")R\x940"]
        parts += [_global_operand("string", "Formatter.get_field"), b"(", b"h\x00"]
        parts += join_fragments(field_fragments)
        parts += [_tuple_payload_operands([_global_operand("statistics", "mean")]), b"}tR\x940"]
        parts += [_global_operand("operator", "getitem"), b"h\x01K\x00\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _unittest_mock_get_target_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-mock-get-target')"
    code_fragments = [code[offset : offset + 18] for offset in range(0, len(code), 18)]
    target_fragments = ["builtins:ev", "al", ".x"]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_global_operand("unittest.mock", "_get_target")]
        parts += join_fragments(target_fragments)
        parts += [b"\x85R\x940"]
        parts += [_global_operand("operator", "getitem"), b"h\x00K\x00\x86R\x940"]
        parts += [b"h\x01)R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _static_member_descriptor_builtins_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-descriptor-static')"
    code_fragments = [code[offset : offset + 18] for offset in range(0, len(code), 18)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_global_operand("inspect", "getattr_static")]
        parts += [_global_operand("statistics", "mean")]
        parts += join_fragments(["_", "_", "builtins", "_", "_"])
        parts += [b"\x86R\x940"]
        parts += [_global_operand("types", "MemberDescriptorType.__get__")]
        parts += [b"h\x00", _global_operand("statistics", "mean"), b"\x86R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x01"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _wrapper_descriptor_getattribute_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-wrapper-descriptor')"
    code_fragments = [code[offset : offset + 18] for offset in range(0, len(code), 18)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_global_operand("inspect", "getattr_static")]
        parts += [_global_operand("statistics", "mean")]
        parts += join_fragments(["_", "_", "getattribute", "_", "_"])
        parts += [b"\x86R\x940"]
        parts += [_global_operand("types", "WrapperDescriptorType.__get__")]
        parts += [b"h\x00", _global_operand("statistics", "mean"), b"\x86R\x940"]
        parts += [b"h\x01"]
        parts += join_fragments(["_", "_", "builtins", "_", "_"])
        parts += [b"\x85R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x02"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x03h\x04\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _legacy_bound_getattribute_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-bound-function-getattribute')"
    code_fragments = [code[offset : offset + 19] for offset in range(0, len(code), 19)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_legacy_global_operand("statistics", "mean.__getattribute__")]
        parts += join_fragments(["_", "_", "builtins", "_", "_"])
        parts += [b"\x85R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x00"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x01h\x02\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _subclasses_popen_payload(marker: Path, *, include_call: bool) -> tuple[bytes, int]:
    popen_class: object = subprocess.Popen
    popen_index = next(index for index, cls in enumerate(object.__subclasses__()) if cls is popen_class)
    code = f"open({str(marker)!r},'w').write('owned-by-subclasses-popen')"
    code_fragments = [code[offset : offset + 3] for offset in range(0, len(code), 3)]

    def join_fragments(fragments: list[str]) -> bytes:
        return b"".join(
            [
                _global_operand("builtins", "str.join"),
                _text_operand(""),
                _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
                b"\x86R",
            ]
        )

    command = _tuple_payload_operands(
        [
            _text_operand(sys.executable),
            _text_operand("-c"),
            join_fragments(code_fragments),
        ]
    )
    parts = [b"\x80\x04"]
    if include_call:
        parts += [_legacy_global_operand("builtins", "object.__subclasses__"), b")R\x940"]
        parts += [_legacy_global_operand("operator", "getitem"), b"h\x00", _int_operand(popen_index), b"\x86R\x940"]
        parts += [b"h\x01", command, b"\x85R"]
    else:
        parts += [command]
    parts += [b"."]
    return b"".join(parts), popen_index


def _gc_referents_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str, int]:
    referent_index = next(
        index for index, referent in enumerate(gc.get_referents(statistics.mean)) if referent is builtins.__dict__
    )
    code = f"open({str(marker)!r},'w').write('owned-by-gc-referents')"
    code_fragments = [code[offset : offset + 3] for offset in range(0, len(code), 3)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_legacy_global_operand("gc", "get_referents")]
        parts += [_global_operand("statistics", "mean")]
        parts += [b"\x85R\x940"]
        parts += [_legacy_global_operand("operator", "getitem")]
        parts += [b"h\x00", _int_operand(referent_index), b"\x86R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x01"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code, referent_index


def _frame_builtins_descriptor_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-frame-f-builtins')"
    code_fragments = [code[offset : offset + 3] for offset in range(0, len(code), 3)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_legacy_global_operand("inspect", "currentframe"), b")R\x940"]
        parts += [_legacy_global_operand("types", "FrameType.f_builtins.__get__")]
        parts += [b"h\x00\x85R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x01"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _frame_builtins_call_suffix_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-call-suffix')"
    code_fragments = [code[offset : offset + 3] for offset in range(0, len(code), 3)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_legacy_global_operand("inspect", "currentframe.__call__"), b")R\x940"]
        parts += [_legacy_global_operand("types", "FrameType.f_builtins.__get__.__call__")]
        parts += [b"h\x00\x85R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x01"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _frame_builtins_get_self_alias_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-get-self')"
    code_fragments = [code[offset : offset + 3] for offset in range(0, len(code), 3)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_legacy_global_operand("inspect", "currentframe.__get__.__self__"), b")R\x940"]
        parts += [_legacy_global_operand("types", "FrameType.f_builtins.__get__.__self__.__get__")]
        parts += [b"h\x00\x85R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x01"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _frame_builtins_repr_self_alias_eval_payload(marker: Path, *, include_lookup: bool) -> tuple[bytes, str]:
    code = f"open({str(marker)!r},'w').write('owned-by-repr-self')"
    code_fragments = [code[offset : offset + 3] for offset in range(0, len(code), 3)]

    def join_fragments(fragments: list[str]) -> list[bytes]:
        return [
            _global_operand("builtins", "str.join"),
            _text_operand(""),
            _tuple_payload_operands([_text_operand(fragment) for fragment in fragments]),
            b"\x86R",
        ]

    parts = [b"\x80\x04"]
    if include_lookup:
        parts += [_legacy_global_operand("inspect", "currentframe.__repr__.__self__"), b")R\x940"]
        parts += [_legacy_global_operand("types", "FrameType.f_builtins.__get__.__repr__.__self__")]
        parts += [b"h\x00\x85R\x940"]
        parts += [_global_operand("builtins", "dict.get")]
        parts += [b"h\x01"]
        parts += join_fragments(["ev", "al"])
        parts += [b"\x86R\x940"]
    parts += join_fragments(code_fragments)
    if include_lookup:
        parts += [b"\x940h\x02h\x03\x85R"]
    parts += [b"."]
    return b"".join(parts), code


def _site_os_system_payload(command: str, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    if include_call:
        parts += [_global_operand("site", "os.system")]
        parts += [_tuple_payload_operands([_text_operand(command)]), b"R"]
    else:
        parts += [_tuple_payload_operands([_text_operand(command)])]
    parts += [b"."]
    return b"".join(parts)


def _posixpath_site_dict_pth_payload(
    pth_path: Path, marker: Path, site_dir: Path, *, include_write: bool
) -> tuple[bytes, str]:
    expected_line = f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-posixpath-site-dict')\n"
    fragments = ["im"]
    fragments.extend(expected_line[offset : offset + 24] for offset in range(2, len(expected_line), 24))
    parts = [b"\x80\x04"]
    if include_write:
        parts += [_global_operand("pathlib", "PosixPath")]
        parts += [_tuple_payload_operands([_text_operand(str(pth_path))]), b"R\x94"]
    parts += [_global_operand("builtins", "str.join")]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_write:
        parts += [b"0"]
        parts += [_global_operand("pathlib", "PosixPath.write_text")]
        parts += [b"h\x00h\x01\x86R0"]
        parts += [_global_operand("site", "__dict__.get"), b"\x94"]
        parts += [_global_operand("builtins", "str.join")]
        parts += [_text_operand(""), _tuple_payload_operands([_text_operand("add"), _text_operand("sitedir")])]
        parts += [b"\x86R\x94"]
        parts += [b"h\x02h\x03\x85R\x94"]
        parts += [b"h\x04", _text_operand(str(site_dir)), b"\x85R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts), expected_line


def _dotenv_run_command_payload(command: list[str], *, include_call: bool) -> bytes:
    command_list = _list_payload_operands([_text_operand(part) for part in command])
    parts = [b"\x80\x04"]
    if include_call:
        parts += [_global_operand("dotenv.cli", "run_command"), command_list, b"}", b"\x86R"]
    else:
        parts += [command_list, b"}", b"\x86"]
    parts += [b"."]
    return b"".join(parts)


def _numpy_wrapfunc_localpath_sysexec_payload(command: str, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    if include_call:
        parts += [_global_operand("numpy._core.fromnumeric", "_wrapfunc"), b"("]
    parts += [_global_operand("_pytest._py.path", "LocalPath")]
    parts += [_tuple_payload_operands([_text_operand("/bin/sh")]), b"R"]
    if include_call:
        parts += [_text_operand("sysexec"), _text_operand("-c"), _text_operand(command), b"tR"]
    parts += [b"."]
    return b"".join(parts)


def _scipy_rv_continuous_setstate_payload(marker: Path) -> bytes:
    parse_arg_template = (
        f"open({str(marker)!r},'w').write('owned-by-scipy-setstate-exec')\n"
        "def _parse_args(*args):\n    return (), 0, 1\n"
        "def _parse_args_stats(*args):\n    return (), 0, 1\n"
        "def _parse_args_rvs(*args):\n    return (), 0, 1, None\n"
    )
    state = b"".join(
        [
            b"}",
            _dict_setitem("_parse_arg_template", _text_operand(parse_arg_template)),
            _dict_setitem("numargs", _int_operand(0)),
            _dict_setitem("moment_type", _int_operand(0)),
        ]
    )
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("scipy.stats._distn_infrastructure", "rv_continuous"),
            b")\x81",
            state,
            b"b.",
        ]
    )


def _scipy_norm_gen_setstate_payload(marker: Path) -> bytes:
    parse_arg_template = (
        f"open({str(marker)!r},'w').write('owned-by-scipy-cross-module-setstate')\n"
        "def _parse_args(*args):\n    return (), 0, 1\n"
        "def _parse_args_stats(*args):\n    return (), 0, 1\n"
        "def _parse_args_rvs(*args):\n    return (), 0, 1, None\n"
    )
    state = b"".join(
        [
            b"}",
            _dict_setitem("_parse_arg_template", _text_operand(parse_arg_template)),
            _dict_setitem("numargs", _int_operand(0)),
            _dict_setitem("moment_type", _int_operand(0)),
        ]
    )
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("scipy.stats._continuous_distns", "norm_gen"),
            b")\x81",
            state,
            b"b.",
        ]
    )


def _scipy_stats_norm_singleton_setstate_payload(marker: Path) -> bytes:
    parse_arg_template = (
        f"open({str(marker)!r},'w').write('owned-by-scipy-stats-norm-singleton')\n"
        "def _parse_args(*args):\n    return (), 0, 1\n"
        "def _parse_args_stats(*args):\n    return (), 0, 1\n"
        "def _parse_args_rvs(*args):\n    return (), 0, 1, None\n"
    )
    state = b"".join(
        [
            b"}",
            _dict_setitem("_parse_arg_template", _text_operand(parse_arg_template)),
        ]
    )
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("scipy.stats", "norm"),
            state,
            b"b.",
        ]
    )


def _fsspec_registry_poisoning_payload(marker: Path, cache_dir: Path) -> bytes:
    def join_fragments(fragments: list[str]) -> bytes:
        return b"".join(
            [
                _global_operand("builtins", "str.join"),
                _tuple_payload_operands(
                    [
                        _text_operand(""),
                        _list_payload_operands([_text_operand(fragment) for fragment in fragments]),
                    ]
                ),
                b"R",
            ]
        )

    registry_value = b"}" + _dict_setitem("class", join_fragments(["sub", "process", ".P", "open"]))
    command = f"printf fsspec-registry-owned > {shlex.quote(str(marker))}"
    target_options = b"}" + _dict_setitem(
        "args",
        _list_payload_operands(
            [
                _text_operand("/bin/sh"),
                _text_operand("-c"),
                _text_operand(command),
            ]
        ),
    )
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("fsspec.registry", "known_implementations"),
            _dict_setitem("pwn197", registry_value),
            b"0",
            _global_operand("fsspec.implementations.cached", "WholeFileCacheFileSystem"),
            _tuple_payload_operands(
                [
                    _text_operand("pwn197"),
                    _text_operand(str(cache_dir)),
                    _int_operand(10),
                    b"\x89",
                    b"\x89",
                    target_options,
                ]
            ),
            b"R.",
        ]
    )


def _pydantic_dynamic_imports_payload(marker: Path) -> bytes:
    def join_fragments(fragments: list[str]) -> bytes:
        return b"".join(
            [
                _global_operand("builtins", "str.join"),
                _tuple_payload_operands(
                    [
                        _text_operand(""),
                        _list_payload_operands([_text_operand(fragment) for fragment in fragments]),
                    ]
                ),
                b"R",
            ]
        )

    command = f"printf pydantic-dynamic-import-owned > {shlex.quote(str(marker))}"
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("pydantic", "_dynamic_imports"),
            _dict_setitem(
                "Popen", _tuple_payload_operands([_text_operand("pydantic"), join_fragments(["sub", "process"])])
            ),
            b"0",
            _global_operand("pydantic", "Popen"),
            _tuple_payload_operands(
                [
                    _list_payload_operands(
                        [
                            _text_operand("/bin/sh"),
                            _text_operand("-c"),
                            _text_operand(command),
                        ]
                    )
                ]
            ),
            b"R.",
        ]
    )


def _pydantic_dotted_getattr_alias_payload(marker: Path) -> bytes:
    command = f"printf pydantic-dotted-os-alias-owned > {shlex.quote(str(marker))}"
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("pydantic", "_dynamic_imports"),
            _dict_setitem("_os", _tuple_payload_operands([_text_operand("pydantic"), _text_operand("random")])),
            b"0",
            _global_operand("pydantic", "_os.system"),
            _tuple_payload_operands([_text_operand(command)]),
            b"R.",
        ]
    )


def _random_os_alias_prefix_payload(marker: Path) -> bytes:
    command = f"printf random-os-alias-owned > {shlex.quote(str(marker))}"
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("random", "_os.system"),
            _tuple_payload_operands([_text_operand(command)]),
            b"R.",
        ]
    )


def _call_graph_poisoned_random_os_alias_prefix_payload(marker: Path, *, poison_after: bool = False) -> bytes:
    command = f"printf call-graph-poison-owned > {shlex.quote(str(marker))}"
    poison = [
        _global_operand("xml.sax.saxutils", "escape"),
        b"0",
    ]
    rce_call = [
        _global_operand("random", "_os.system"),
        _tuple_payload_operands([_text_operand(command)]),
        b"R",
    ]
    if poison_after:
        return b"".join([b"\x80\x04", *rce_call, b"0", *poison, b"N."])
    return b"".join([b"\x80\x04", *poison, *rce_call, b"."])


def _import_reference_limit_random_os_alias_prefix_payload(marker: Path, *, filler_count: int) -> bytes:
    command = f"printf import-ref-limit-owned > {shlex.quote(str(marker))}"
    parts = [b"\x80\x04"]
    for _ in range(filler_count):
        parts += [
            _global_operand("collections", "Counter"),
            b"0",
        ]
    parts += [
        _global_operand("random", "_os.system"),
        _tuple_payload_operands([_text_operand(command)]),
        b"R.",
    ]
    return b"".join(parts)


def _pkgutil_iter_importers_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("builtins", "list"),
            _global_operand("pkgutil", "iter_importers"),
            _text_operand("evilpkg.submodule"),
            b"\x85R\x85R.",
        ]
    )


def _pyyaml_unsafe_document(marker: Path, marker_content: str) -> str:
    source_tail = f"port pathlib\npathlib.Path({str(marker)!r}).write_text({marker_content!r})"
    return (
        "!!python/object/apply:builtins.exec\n"
        "- !!python/object/apply:operator.add\n"
        "  - im\n"
        f"  - {json.dumps(source_tail)}\n"
    )


def _pyyaml_unsafe_load_payload(
    document: str,
    *,
    load_name: str,
    loader_module: str | None,
    loader_name: str | None,
    force_iteration: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    if force_iteration:
        parts += [_global_operand("builtins", "tuple")]
    parts += [_global_operand("yaml", load_name), _text_operand(document)]
    if loader_module is None or loader_name is None:
        parts += [b"\x85R"]
    else:
        parts += [_global_operand(loader_module, loader_name), b"\x86R"]
    if force_iteration:
        parts += [b"\x85R"]
    parts += [b"."]
    return b"".join(parts)


def _codecs_open_write_payload(marker: Path, *, include_write: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"codecs"), _short_binunicode(b"open"), b"\x93"]
    parts += [_text_operand(str(marker)), _text_operand("w"), _text_operand("utf-8"), b"\x87R\x94"]
    if include_write:
        parts += [_short_binunicode(b"codecs"), _short_binunicode(b"StreamReaderWriter.write"), b"\x93"]
        parts += [b"h\x00", _text_operand("owned-by-codecs-open"), b"\x86R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _codecs_open_pth_payload(pth_path: Path, marker: Path) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-codecs-pth')\n",
    ]
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"codecs"), _short_binunicode(b"open"), b"\x93"]
    parts += [_text_operand(str(pth_path)), _text_operand("w"), _text_operand("utf-8"), b"\x87R\x94"]
    for fragment in fragments[:-1]:
        parts += [_short_binunicode(b"codecs"), _short_binunicode(b"StreamReaderWriter.write"), b"\x93"]
        parts += [b"h\x00", _text_operand(fragment), b"\x86R0"]
    parts += [_short_binunicode(b"codecs"), _short_binunicode(b"StreamReaderWriter.write"), b"\x93"]
    parts += [b"h\x00", _text_operand(fragments[-1]), b"\x86R."]
    return b"".join(parts)


def _csv_tempfile_pth_payload(
    target_dir: Path,
    marker: Path,
    *,
    include_write: bool,
    writer_method: str,
) -> bytes:
    fragments = [
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        ").write_text('owned-by-csv-tempfile')\n",
    ]
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"tempfile"), _short_binunicode(b"NamedTemporaryFile"), b"\x93"]
    parts += [
        b"(",
        _text_operand("w"),
        b"J\xff\xff\xff\xff",
        b"N",
        _text_operand(""),
        _text_operand(".pth"),
        _text_operand("ma_csv_"),
        _text_operand(str(target_dir)),
        b"\x89",
        b"tR\x94",
    ]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93"]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("CsvPthDialect"), b")", b"}"]
    parts += [
        _dict_setitem("delimiter", _text_operand(",")),
        _dict_setitem("quotechar", _text_operand('"')),
        _dict_setitem("lineterminator", b"h\x01"),
        _dict_setitem("quoting", b"K\x03"),
        _dict_setitem("doublequote", b"\x88"),
        _dict_setitem("skipinitialspace", b"\x89"),
        _dict_setitem("escapechar", _text_operand("\\")),
        _dict_setitem("strict", b"\x89"),
        b"tR\x94",
    ]
    parts += [_short_binunicode(b"csv"), _short_binunicode(b"DictWriter"), b"\x93"]
    parts += [b"(", b"h\x00", b")", _text_operand(""), _text_operand("raise"), b"h\x02", b"tR\x94"]
    if include_write:
        parts += [_short_binunicode(b"csv"), _short_binunicode(writer_method.encode()), b"\x93"]
        if writer_method == "DictWriter.writerow":
            parts += [b"h\x03", b"}", b"\x86R0"]
        elif writer_method == "DictWriter.writerows":
            parts += [b"h\x03", b"]}a", b"\x86R0"]
        else:
            raise ValueError(f"unexpected CSV writer method: {writer_method}")
    parts += [_short_binunicode(b"tempfile"), _short_binunicode(b"_TemporaryFileWrapper.close"), b"\x93"]
    parts += [b"h\x00\x85R."]
    return b"".join(parts)


def _mailbox_singlefile_pth_payload(
    pth_path: Path,
    marker: Path,
    *,
    mailbox_class: str,
    method_owner: str,
    marker_content: str,
    include_add: bool,
) -> bytes:
    fragments = [
        "Subject: x\n\n",
        "im",
        "port pathlib;pathlib.Path(",
        repr(str(marker)),
        f").write_text({marker_content!r})\n",
    ]
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"mailbox"), _short_binunicode(mailbox_class.encode()), b"\x93"]
    parts += [_text_operand(str(pth_path)), b"\x85R\x94"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93"]
    parts += [_text_operand(""), _tuple_payload_operands([_text_operand(fragment) for fragment in fragments])]
    parts += [b"\x86R\x94"]
    if include_add:
        parts += [_short_binunicode(b"mailbox"), _short_binunicode(f"{method_owner}.add".encode()), b"\x93"]
        parts += [b"h\x00h\x01\x86R0"]
    parts += [_short_binunicode(b"mailbox"), _short_binunicode(f"{method_owner}.flush".encode()), b"\x93"]
    parts += [b"h\x00\x85R0"]
    parts += [_short_binunicode(b"mailbox"), _short_binunicode(f"{method_owner}.close".encode()), b"\x93"]
    parts += [b"h\x00\x85R."]
    return b"".join(parts)


def _tkinter_tcl_control_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode(b"_tkinter"),
            _short_binunicode(b"create"),
            b"\x93",
            _tkinter_tcl_create_args(),
            b"R.",
        ]
    )


def _tkinter_tcl_create_args() -> bytes:
    return _tuple_payload_operands(
        [
            b"N",
            _text_operand(""),
            _text_operand("Tk"),
            b"\x89",
            b"\x88",
            b"\x89",
            b"\x89",
            b"N",
        ]
    )


def _tkinter_tcl_eval_payload(marker: Path) -> bytes:
    script = f"exec /bin/sh -c {{printf owned-by-tcl-eval > {marker}}}"
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode(b"_tkinter"),
            _short_binunicode(b"create"),
            b"\x93",
            _tkinter_tcl_create_args(),
            b"R\x94",
            _short_binunicode(b"_tkinter"),
            _short_binunicode(b"TkappType.eval"),
            b"\x93h\x00",
            _text_operand(script),
            b"\x86R.",
        ]
    )


def _tkinter_tcl_call_payload(marker: Path) -> bytes:
    command = f"printf owned-by-tcl-call > {marker}"
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode(b"_tkinter"),
            _short_binunicode(b"create"),
            b"\x93",
            _tkinter_tcl_create_args(),
            b"R\x94",
            _short_binunicode(b"_tkinter"),
            _short_binunicode(b"TkappType.call"),
            b"\x93",
            _tuple_payload_operands(
                [
                    b"h\x00",
                    _text_operand("exec"),
                    _text_operand("/bin/sh"),
                    _text_operand("-c"),
                    _text_operand(command),
                ]
            ),
            b"R.",
        ]
    )


def _subinterpreters_control_payload() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode(b"_xxsubinterpreters"),
            _short_binunicode(b"create"),
            b"\x93)R.",
        ]
    )


def _subinterpreters_run_string_payload(marker: Path) -> bytes:
    source = f"open({str(marker)!r}, 'w').write('owned-by-subinterp')"
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode(b"_xxsubinterpreters"),
            _short_binunicode(b"create"),
            b"\x93)R\x94",
            _short_binunicode(b"_xxsubinterpreters"),
            _short_binunicode(b"run_string"),
            b"\x93h\x00",
            _text_operand(source),
            b"\x86R.",
        ]
    )


def _inspect_getmembers_property_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("x")]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"property"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R", b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"inspect"), _short_binunicode(b"getmembers"), b"\x93"]
        parts += [b"h\x01\x85R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_hasattr_property_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("x")]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"property"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R", b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"builtins"), _short_binunicode(b"hasattr"), b"\x93"]
        parts += [b"h\x01", _text_operand("x"), b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _noop_del(_: object) -> None:
    return None


def _dynamic_dunder_name_payload(method_stem: str) -> bytes:
    parts = [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93"]
    parts += [b"(", _text_operand(""), b"("]
    parts += [_text_operand("__"), _text_operand(method_stem), _text_operand("__")]
    parts += [b"t", b"tR"]
    return b"".join(parts)


def _untracked_str_add_payload(left: str, right: str) -> bytes:
    parts = [_short_binunicode(b"builtins"), _short_binunicode(b"str.__add__"), b"\x93"]
    parts += [_text_operand(left), _text_operand(right), b"\x86R"]
    return b"".join(parts)


def _builtins_type_del_finalizer_payload(marker: Path, *, drop_instance: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__del__")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_dynamic_del_finalizer_payload(marker: Path, *, drop_instance: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _dynamic_dunder_name_payload("del")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_dynamic_del_finalizer_overflow_payload(marker: Path, *, drop_instance: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}"]
    for index in range(16):
        parts += [_untracked_str_add_payload("pad", str(index)), _int_operand(0), b"s"]
    parts += [_untracked_str_add_payload("__de", "l__")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_new_dynamic_del_finalizer_payload(
    marker: Path,
    *,
    drop_instance: bool,
    type_value_name: bytes = b"type",
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type.__new__"), b"\x93"]
    parts += [b"("]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(type_value_name), b"\x93"]
    parts += [_text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _dynamic_dunder_name_payload("del")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_call_dynamic_del_finalizer_payload(
    marker: Path,
    *,
    drop_instance: bool,
    type_value_name: bytes = b"type",
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type.__call__"), b"\x93"]
    parts += [b"("]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(type_value_name), b"\x93"]
    parts += [_text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _dynamic_dunder_name_payload("del")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_dict_constructor_dynamic_del_finalizer_payload(marker: Path, *, drop_instance: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85"]
    pair = _tuple_payload_operands(
        [
            _dynamic_dunder_name_payload("del"),
            _short_binunicode(b"pathlib") + _short_binunicode(b"Path.touch") + b"\x93",
        ]
    )
    pair_iterable = _tuple_payload_operands([pair])
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"dict"), b"\x93"]
    parts += [_tuple_payload_operands([pair_iterable]), b"R"]
    parts += [b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_mutated_namespace_dynamic_del_finalizer_payload(
    marker: Path,
    *,
    drop_instance: bool,
    mutator_module: bytes,
    mutator_name: bytes,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"}\x940"]
    parts += [_short_binunicode(mutator_module), _short_binunicode(mutator_name), b"\x93"]
    parts += [
        b"h\x00",
        _dynamic_dunder_name_payload("del"),
        _short_binunicode(b"pathlib"),
        _short_binunicode(b"Path.touch"),
        b"\x93",
        b"\x87R0",
    ]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"h\x00", b"tR\x94"]
    parts += [b"0", b"h\x01", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_update_mutated_namespace_dynamic_del_finalizer_payload(
    marker: Path,
    *,
    drop_instance: bool,
    mutator_module: bytes,
    mutator_name: bytes,
    tracked_source: bool = False,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"}\x940"]
    pair = _tuple_payload_operands(
        [
            _dynamic_dunder_name_payload("del"),
            _short_binunicode(b"pathlib") + _short_binunicode(b"Path.touch") + b"\x93",
        ]
    )
    pair_iterable = _tuple_payload_operands([pair])
    if tracked_source:
        source_dict = (
            b"}\x94"
            + _dynamic_dunder_name_payload("del")
            + _short_binunicode(b"pathlib")
            + _short_binunicode(b"Path.touch")
            + b"\x93s"
        )
    else:
        source_dict = (
            _short_binunicode(b"builtins")
            + _short_binunicode(b"dict")
            + b"\x93"
            + _tuple_payload_operands([pair_iterable])
            + b"R"
        )
    parts += [_short_binunicode(mutator_module), _short_binunicode(mutator_name), b"\x93"]
    parts += [b"h\x00", source_dict, b"\x86R0"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"h\x00", b"tR\x94"]
    class_memo_get = b"h\x02" if tracked_source else b"h\x01"
    parts += [b"0", class_memo_get, _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_dict_copy_mutated_namespace_dynamic_del_finalizer_payload(
    marker: Path,
    *,
    drop_instance: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"}\x940"]
    parts += [_short_binunicode(b"operator"), _short_binunicode(b"setitem"), b"\x93"]
    parts += [
        b"h\x00",
        _dynamic_dunder_name_payload("del"),
        _short_binunicode(b"pathlib"),
        _short_binunicode(b"Path.touch"),
        b"\x93",
        b"\x87R0",
    ]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"dict"), b"\x93"]
    parts += [b"h\x00", b"\x85R", b"tR\x940"]
    parts += [b"h\x01", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_dup_alias_mutated_namespace_dynamic_del_finalizer_payload(
    marker: Path,
    *,
    drop_instance: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"}2"]
    parts += [_dynamic_dunder_name_payload("del")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s0\x940"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"h\x00", b"tR\x940"]
    parts += [b"h\x01", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_object_class_dynamic_del_finalizer_payload(marker: Path, *, drop_instance: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"object.__class__"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _dynamic_dunder_name_payload("del")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_setattr_dynamic_del_finalizer_payload(marker: Path, *, drop_instance: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", b"tR\x940"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type.__setattr__"), b"\x93"]
    parts += [b"("]
    parts += [b"h\x00", _dynamic_dunder_name_payload("del")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"tR0"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R"]
    if drop_instance:
        parts += [b"0N"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_eq_comparison_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__eq__")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(b"eq"), b"\x93"]
        parts += [b"h\x01", b"M" + (0o666).to_bytes(2, "little"), b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_ordering_comparison_payload(
    marker: Path,
    *,
    method_name: str,
    operator_name: str,
    include_call: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(operator_name.encode()), b"\x93"]
        parts += [b"h\x01", b"M" + (0o666).to_bytes(2, "little"), b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_item_protocol_payload(
    marker: Path,
    *,
    method_name: str,
    operator_name: str,
    include_call: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(operator_name.encode()), b"\x93"]
        parts += [b"h\x01", b"M" + (0o666).to_bytes(2, "little"), b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_binary_operator_payload(
    marker: Path,
    *,
    method_name: str,
    operator_name: str,
    include_call: bool,
    reverse_operands: bool = False,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(operator_name.encode()), b"\x93"]
        mode_arg = b"M" + (0o666).to_bytes(2, "little")
        if reverse_operands:
            parts += [mode_arg, b"h\x01", b"\x86R"]
        else:
            parts += [b"h\x01", mode_arg, b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_unary_operator_payload(
    marker: Path,
    *,
    method_name: str,
    operator_name: str,
    include_call: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(operator_name.encode()), b"\x93"]
        parts += [b"h\x01", b"\x85R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_iteration_protocol_payload(
    marker: Path,
    *,
    method_name: str,
    builtin_name: str,
    include_call: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"builtins"), _short_binunicode(builtin_name.encode()), b"\x93"]
        parts += [b"h\x01", b"\x85R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_rounding_protocol_payload(
    marker: Path,
    *,
    method_name: str,
    module_name: str,
    helper_name: str,
    include_call: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(module_name.encode()), _short_binunicode(helper_name.encode()), b"\x93"]
        parts += [b"h\x01", b"\x85R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_presentation_protocol_payload(
    marker: Path,
    *,
    method_name: str,
    base_module: str,
    base_name: str,
    callable_module: str,
    callable_name: str,
    helper_module: str,
    helper_name: str,
    helper_arg: str | None,
    include_call: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedValue")]
    parts += [_short_binunicode(base_module.encode()), _short_binunicode(base_name.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand(method_name)]
    parts += [_short_binunicode(callable_module.encode()), _short_binunicode(callable_name.encode()), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(helper_module.encode()), _short_binunicode(helper_name.encode()), b"\x93"]
        parts += [b"h\x01"]
        if helper_arg is None:
            parts += [b"\x85R"]
        else:
            parts += [_text_operand(helper_arg), b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_fspath_protocol_payload(
    marker: Path,
    *,
    include_write: bool,
) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("PathLikeString")]
    parts += [_short_binunicode(b"collections"), _short_binunicode(b"UserString"), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__fspath__")]
    parts += [_short_binunicode(b"collections"), _short_binunicode(b"UserString.encode"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_write:
        parts += [_short_binunicode(b"io"), _short_binunicode(b"open"), b"\x93"]
        parts += [b"h\x01", _text_operand("w"), b"\x86R\x940"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.write"), b"\x93"]
        parts += [b"h\x02", _text_operand("owned-by-fspath"), b"\x86R0"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.close"), b"\x93"]
        parts += [b"h\x02", b"\x85R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _path_instance_payload(marker: Path) -> list[bytes]:
    return [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93",
        _text_operand(str(marker)),
        b"\x85R\x94",
    ]


def _direct_file_write_sink_payload(marker: Path, *, sink_name: str, include_write: bool) -> bytes:
    parts = [b"\x80\x04"]
    if not include_write:
        parts += _path_instance_payload(marker)
        parts += [b"h\x00"]
        parts += [b"."]
        return b"".join(parts)

    if sink_name == "path_write_text":
        parts += _path_instance_payload(marker)
        parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_text"), b"\x93"]
        parts += [b"h\x00", _text_operand("owned-by-path-write-text"), b"\x86R"]
    elif sink_name == "path_write_bytes":
        parts += _path_instance_payload(marker)
        parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_bytes"), b"\x93"]
        parts += [b"h\x00", _bytes_operand(b"owned-by-path-write-bytes"), b"\x86R"]
    elif sink_name == "path_open":
        parts += _path_instance_payload(marker)
        parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.open"), b"\x93"]
        parts += [b"h\x00", _text_operand("w"), b"\x86R\x940"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.write"), b"\x93"]
        parts += [b"h\x01", _text_operand("owned-by-path-open"), b"\x86R0"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.close"), b"\x93"]
        parts += [b"h\x01", b"\x85R"]
    elif sink_name == "io_open":
        parts += [_short_binunicode(b"io"), _short_binunicode(b"open"), b"\x93"]
        parts += [_text_operand(str(marker)), _text_operand("w"), b"\x86R\x940"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.write"), b"\x93"]
        parts += [b"h\x00", _text_operand("owned-by-io-open"), b"\x86R0"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.close"), b"\x93"]
        parts += [b"h\x00", b"\x85R"]
    elif sink_name == "_io_open":
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"open"), b"\x93"]
        parts += [_text_operand(str(marker)), _text_operand("w"), b"\x86R\x940"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.write"), b"\x93"]
        parts += [b"h\x00", _text_operand("owned-by-_io-open"), b"\x86R0"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"TextIOWrapper.close"), b"\x93"]
        parts += [b"h\x00", b"\x85R"]
    elif sink_name == "fileio":
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"FileIO"), b"\x93"]
        parts += [_text_operand(str(marker)), _text_operand("w"), b"\x86R\x940"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"FileIO.write"), b"\x93"]
        parts += [b"h\x00", _bytes_operand(b"owned-by-fileio"), b"\x86R0"]
        parts += [_short_binunicode(b"_io"), _short_binunicode(b"FileIO.close"), b"\x93"]
        parts += [b"h\x00", b"\x85R"]
    else:
        raise ValueError(f"unexpected direct file sink: {sink_name}")

    parts += [b"."]
    return b"".join(parts)


def _builtins_type_descriptor_set_name_payload(marker: Path, *, include_owner_class: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DescriptorPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__set_name__")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("Meta")]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__index__")]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"object.__sizeof__"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    if include_owner_class:
        parts += [b"h\x02", b"(", _text_operand("Owner"), b")", b"}", _text_operand("x"), b"h\x01", b"s", b"tR"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_contains_membership_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__contains__")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(b"contains"), b"\x93"]
        parts += [b"h\x01", b"M" + (0o666).to_bytes(2, "little"), b"\x86R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_type_setitem_assignment_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [b"(", _text_operand("DerivedPath")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(type(marker).__name__.encode()), b"\x93"]
    parts += [b"\x85", b"}", _text_operand("__setitem__")]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"s", b"tR\x940"]
    parts += [b"h\x00", _text_operand(str(marker)), b"\x85R\x940"]
    if include_call:
        parts += [_short_binunicode(b"operator"), _short_binunicode(b"setitem"), b"\x93"]
        parts += [b"h\x01", b"M" + (0o666).to_bytes(2, "little"), b"\x88", b"\x87R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_staticmethod_descriptor_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"staticmethod"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R\x940"]
    if include_call:
        parts += [b"h\x00"]
        parts += [
            _short_binunicode(b"pathlib"),
            _short_binunicode(type(marker).__name__.encode()),
            b"\x93(",
        ]
        parts.extend(_text_operand(part) for part in marker.parts)
        parts += [b"tR", b"\x85R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_property_get_descriptor_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"property"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R\x94"]
    if include_call:
        parts += [_short_binunicode(b"builtins"), _short_binunicode(b"property.__get__"), b"\x93"]
        parts += [b"h\x00"]
        parts += [
            _short_binunicode(b"pathlib"),
            _short_binunicode(type(marker).__name__.encode()),
            b"\x93(",
        ]
        parts.extend(_text_operand(part) for part in marker.parts)
        parts += [b"tR", b"\x86R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _builtins_classmethod_get_descriptor_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"classmethod"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R\x94"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"classmethod.__get__"), b"\x93"]
    parts += [b"(", b"h\x00", b"N"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in marker.parts)
    parts += [b"tR", b"tR\x94"]
    if include_call:
        parts += [b"h\x01)R"]
    else:
        parts += [b"h\x01"]
    parts += [b"."]
    return b"".join(parts)


def _private_functools_partial_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"_functools"), _short_binunicode(b"partial"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in marker.parts)
    parts += [b"tR", b"\x86R\x940"]
    if include_call:
        parts += [b"h\x00)R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _private_functools_reduce_payload(marker: Path, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"_functools"), _short_binunicode(b"reduce"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]", b"M\xb6\x01", b"a"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in marker.parts)
    parts += [b"tR", b"\x87"]
    if include_call:
        parts += [b"R"]
    parts += [b"."]
    return b"".join(parts)


def _functools_callable_wrapper_payload(marker: Path, factory_name: bytes, *, include_call: bool) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"functools"), _short_binunicode(factory_name), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x85R\x94"]
    if include_call:
        parts += [b"h\x00"]
        parts += [
            _short_binunicode(b"pathlib"),
            _short_binunicode(type(marker).__name__.encode()),
            b"\x93(",
        ]
        parts.extend(_text_operand(part) for part in marker.parts)
        parts += [b"tR", b"\x85R"]
    else:
        parts += [b"h\x00"]
    parts += [b"."]
    return b"".join(parts)


def _unittest_mock_side_effect_payload(marker: Path, class_name: bytes = b"Mock") -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"unittest.mock"), _short_binunicode(class_name), b"\x93("]
    parts += [b"N"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"tR\x94h\x00"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"\x85R."]
    return b"".join(parts)


def _threadpool_executor_submit_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"concurrent.futures"), _short_binunicode(b"ThreadPoolExecutor"), b"\x93)R\x94"]
    parts += [_short_binunicode(b"concurrent.futures"), _short_binunicode(b"ThreadPoolExecutor.submit"), b"\x93("]
    parts += [b"h\x00"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"tR0"]
    parts += [
        _short_binunicode(b"concurrent.futures"),
        _short_binunicode(b"ThreadPoolExecutor.shutdown"),
        b"\x93h\x00\x85R.",
    ]
    return b"".join(parts)


def _processpool_executor_submit_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"concurrent.futures"), _short_binunicode(b"ProcessPoolExecutor"), b"\x93)R\x94"]
    parts += [_short_binunicode(b"concurrent.futures"), _short_binunicode(b"ProcessPoolExecutor.submit"), b"\x93("]
    parts += [b"h\x00"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"tR0"]
    parts += [
        _short_binunicode(b"concurrent.futures"),
        _short_binunicode(b"ProcessPoolExecutor.shutdown"),
        b"\x93h\x00\x85R.",
    ]
    return b"".join(parts)


def _site_addsitedir_pth_payload(pth_path: Path, marker: Path, *, include_addsitedir: bool) -> bytes:
    content_fragments = [
        "im",
        "port pathlib; pathlib.Path(",
        repr(str(marker)),
        ").touch()\n",
    ]

    parts = [b"\x80\x04"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(pth_path).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in pth_path.parts)
    parts += [b"tR\x940"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93("]
    parts += [_short_binunicode(b""), b"("]
    parts.extend(_text_operand(fragment) for fragment in content_fragments)
    parts += [b"ttR\x940"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_text"), b"\x93("]
    parts += [b"h\x00", b"h\x01", b"tR"]
    if include_addsitedir:
        parts += [b"0", _short_binunicode(b"site"), _short_binunicode(b"addsitedir"), b"\x93"]
        parts += [_text_operand(str(pth_path.parent)), b"\x85R"]
    parts += [b"."]
    return b"".join(parts)


def _unittest_loader_discover_payload(
    module_path: Path,
    marker: Path,
    *,
    include_discover: bool,
) -> bytes:
    content_fragments = [
        "im",
        "port pathlib; pathlib.Path(",
        repr(str(marker)),
        ").touch()\n",
    ]

    parts = [b"\x80\x04"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(module_path).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in module_path.parts)
    parts += [b"tR\x940"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93("]
    parts += [_short_binunicode(b""), b"("]
    parts.extend(_text_operand(fragment) for fragment in content_fragments)
    parts += [b"ttR\x940"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_text"), b"\x93("]
    parts += [b"h\x00", b"h\x01", b"tR"]
    if include_discover:
        parts += [
            b"0",
            _short_binunicode(b"unittest.loader"),
            _short_binunicode(b"TestLoader"),
            b"\x93)R\x940",
        ]
        parts += [
            _short_binunicode(b"unittest.loader"),
            _short_binunicode(b"TestLoader.discover"),
            b"\x93(",
        ]
        parts += [b"h\x02", _text_operand(str(module_path.parent)), _text_operand(module_path.name), b"tR"]
    parts += [b"."]
    return b"".join(parts)


def _unittest_mock_patch_start_payload(
    module_path: Path,
    marker: Path,
    *,
    include_start: bool,
) -> bytes:
    content_fragments = [
        "im",
        "port pathlib; pathlib.Path(",
        repr(str(marker)),
        ").touch()\nsomeattr = 1\n",
    ]

    parts = [b"\x80\x04"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(module_path).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_text_operand(part) for part in module_path.parts)
    parts += [b"tR\x940"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"str.join"), b"\x93("]
    parts += [_short_binunicode(b""), b"("]
    parts.extend(_text_operand(fragment) for fragment in content_fragments)
    parts += [b"ttR\x940"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_text"), b"\x93("]
    parts += [b"h\x00", b"h\x01", b"tR"]
    if include_start:
        target = f"{module_path.stem}.someattr"
        parts += [b"0", _short_binunicode(b"unittest.mock"), _short_binunicode(b"patch"), b"\x93("]
        parts += [_text_operand(target), b"K\x02", b"tR\x940"]
        parts += [_short_binunicode(b"unittest.mock"), _short_binunicode(b"_patch.start"), b"\x93h\x02\x85R"]
    parts += [b"."]
    return b"".join(parts)


def _typing_eval_type_forward_ref_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"typing"), _short_binunicode(b"_eval_type"), b"\x93"]
    parts += [_short_binunicode(b"typing"), _short_binunicode(b"ForwardRef"), b"\x93"]
    parts += [_short_binunicode(b"f(p) or int"), b"\x85R"]
    parts += [b"}"]
    parts += [_short_binunicode(b"f"), _short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93s"]
    parts += [
        _short_binunicode(b"p"),
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRs"]
    parts += [_short_binunicode(b"int"), _short_binunicode(b"builtins"), _short_binunicode(b"int"), b"\x93s"]
    parts += [b"N\x87R."]
    return b"".join(parts)


def _typing_get_type_hints_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"typing"), _short_binunicode(b"get_type_hints"), b"\x93"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"type"), b"\x93"]
    parts += [_short_binunicode(b"C"), b")"]
    parts += [
        b"}",
        _short_binunicode(b"__annotations__"),
        b"}",
        _short_binunicode(b"x"),
        _short_binunicode(b"f(p) or int"),
        b"s",
        b"s",
        b"\x87R",
    ]
    parts += [b"}"]
    parts += [_short_binunicode(b"f"), _short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93s"]
    parts += [
        _short_binunicode(b"p"),
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRs"]
    parts += [_short_binunicode(b"int"), _short_binunicode(b"builtins"), _short_binunicode(b"int"), b"\x93s"]
    parts += [b"N\x87R."]
    return b"".join(parts)


def _operator_call_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"operator"), _short_binunicode(b"call"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"\x86R."]
    return b"".join(parts)


def _builtins_map_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"map"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa", b"\x86R", b"\x85R."]
    return b"".join(parts)


def _builtins_filter_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"filter"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa", b"\x86R", b"\x85R."]
    return b"".join(parts)


def _itertools_accumulate_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"itertools"), _short_binunicode(b"accumulate"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa", _short_binunicode(b"x"), b"a"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.write_text"), b"\x93"]
    parts += [b"\x86R", b"\x85R."]
    return b"".join(parts)


def _itertools_dropwhile_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"itertools"), _short_binunicode(b"dropwhile"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa", b"\x86R", b"\x85R."]
    return b"".join(parts)


def _itertools_filterfalse_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"itertools"), _short_binunicode(b"filterfalse"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa", b"\x86R", b"\x85R."]
    return b"".join(parts)


def _itertools_groupby_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"itertools"), _short_binunicode(b"groupby"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"\x86R", b"\x85R."]
    return b"".join(parts)


def _itertools_starmap_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"itertools"), _short_binunicode(b"starmap"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tR", b"\x85", b"a", b"\x86R", b"\x85R."]
    return b"".join(parts)


def _itertools_takewhile_tuple_payload(marker: Path) -> bytes:
    parts = [b"\x80\x04"]
    parts += [_short_binunicode(b"builtins"), _short_binunicode(b"tuple"), b"\x93"]
    parts += [_short_binunicode(b"itertools"), _short_binunicode(b"takewhile"), b"\x93"]
    parts += [_short_binunicode(b"pathlib"), _short_binunicode(b"Path.touch"), b"\x93"]
    parts += [b"]"]
    parts += [
        _short_binunicode(b"pathlib"),
        _short_binunicode(type(marker).__name__.encode()),
        b"\x93(",
    ]
    parts.extend(_short_binunicode(part.encode()) for part in marker.parts)
    parts += [b"tRa", b"\x86R", b"\x85R."]
    return b"".join(parts)


def test_adversarial_oracle_corpus_is_large_enough() -> None:
    assert len(ADVERSARIAL_CASES) >= 300


@pytest.mark.parametrize("case", ADVERSARIAL_CASES, ids=lambda case: case.name)
def test_scan_bytes_matches_cpython_oracle_for_adversarial_stack_global(
    case: AdversarialCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reaches_subprocess_run = _calls_subprocess_run_under_cpython(case.payload, monkeypatch)

    report = scan_bytes(case.payload, source=f"{case.name}.pkl", options=case.options)
    scanner_reports_subprocess_run = _has_critical_subprocess_run_finding(report)

    if reaches_subprocess_run:
        assert report.verdict == SafetyVerdict.MALICIOUS
        assert scanner_reports_subprocess_run, case.name
    else:
        assert not scanner_reports_subprocess_run, case.name


@pytest.mark.skipif(sys.platform == "win32", reason="mailcap test command proof uses POSIX shell")
def test_scan_bytes_blocks_mailcap_findmatch_test_command_rce(tmp_path: Path) -> None:
    if find_spec("mailcap") is None:
        pytest.skip("mailcap was removed in Python 3.13")

    import mailcap

    marker = tmp_path / "mailcap_findmatch_rce_marker"
    safe_input = tmp_path / "safe_input"

    class MailcapFindmatchRce:
        def __reduce__(self) -> tuple[object, tuple[object, ...]]:
            caps = {
                "text/plain": [
                    {
                        "view": "cat %s",
                        "test": f"touch {shlex.quote(str(marker))}",
                    }
                ]
            }
            return (mailcap.findmatch, (caps, "text/plain", "view", str(safe_input), []))

    payload = pickle.dumps(MailcapFindmatchRce(), protocol=4)

    report = scan_bytes(payload, source="mailcap-findmatch-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_mailcap_findmatch_finding(report)

    assert not marker.exists()
    pickle.loads(payload)
    assert marker.exists()


def test_scan_bytes_blocks_atexit_register_exit_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "atexit_register_exit_callback_rce_marker"
    payload = _atexit_register_payload(marker)

    report = scan_bytes(payload, source="atexit-register-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_atexit_register_finding(report)

    assert not marker.exists()
    subprocess.run(
        [
            sys.executable,
            "-c",
            f"import pickle; pickle.loads(bytes.fromhex({payload.hex()!r}))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert marker.exists()


def test_scan_bytes_blocks_weakref_finalize_reclaim_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "weakref_finalize_reclaim_callback_rce_marker"
    payload = _weakref_finalize_payload(marker)

    report = scan_bytes(payload, source="weakref-finalize-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_weakref_finalize_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert type(result).__module__ == "weakref"
    assert type(result).__name__ == "finalize"
    assert not result.alive
    assert marker.exists()


def test_scan_bytes_blocks_sched_scheduler_queued_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "sched_scheduler_queued_callback_rce_marker"
    payload = _sched_scheduler_run_payload(marker)

    report = scan_bytes(payload, source="sched-scheduler-run-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_sched_scheduler_finding(report, "scheduler.enter")
    assert _has_critical_sched_scheduler_finding(report, "scheduler.run")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_contextlib_exitstack_cleanup_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "contextlib_exitstack_cleanup_callback_rce_marker"
    payload = _contextlib_exitstack_close_payload(marker)

    report = scan_bytes(payload, source="contextlib-exitstack-close-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_contextlib_exitstack_finding(report, "ExitStack.callback")
    assert _has_critical_contextlib_exitstack_finding(report, "ExitStack.close")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_contextlib_exitstack_enter_context_dunder_enter_rce(tmp_path: Path) -> None:
    marker = tmp_path / "contextlib_exitstack_enter_context_dunder_enter_rce_marker"
    control_payload = _contextlib_exitstack_enter_context_payload(marker, include_call=False)
    payload = _contextlib_exitstack_enter_context_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="contextlib-exitstack-enter-context-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="contextlib-exitstack-enter-context-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_suspicious_magic_method_finding(report)
    assert _has_critical_contextlib_exitstack_finding(report, "ExitStack.enter_context")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_contextvars_context_run_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "contextvars_context_run_callback_rce_marker"
    payload = _contextvars_context_run_payload(marker)

    report = scan_bytes(payload, source="contextvars-context-run-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_contextvars_finding(report, "Context.run")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_types_methodtype_bound_method_rce(tmp_path: Path) -> None:
    marker = tmp_path / "types_methodtype_bound_method_rce_marker"
    control_payload = _types_methodtype_bound_method_payload(marker, include_call=False)
    payload = _types_methodtype_bound_method_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="types-methodtype-bound-method-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_types_finding(control_report, "MethodType")

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "method"
    assert not marker.exists()

    report = scan_bytes(payload, source="types-methodtype-bound-method-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_types_finding(report, "MethodType")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_types_dynamicclassattribute_get_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "types_dynamicclassattribute_get_descriptor_rce_marker"
    control_payload = _types_dynamicclassattribute_get_payload(marker, include_call=False)
    payload = _types_dynamicclassattribute_get_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="types-dynamicclassattribute-get-control.pkl")
    assert control_report.verdict in {SafetyVerdict.CLEAN, SafetyVerdict.UNKNOWN}
    if control_report.verdict == SafetyVerdict.UNKNOWN:
        assert control_report.status == ScanStatus.INCONCLUSIVE
        assert control_report.findings == ()
        assert control_report.metadata.get("analysis_incomplete") is True

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DynamicClassAttribute"
    assert not marker.exists()

    report = scan_bytes(payload, source="types-dynamicclassattribute-get-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_types_finding(report, "DynamicClassAttribute.__get__")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_functools_cached_property_get_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "functools_cached_property_get_descriptor_rce_marker"
    control_payload = _functools_cached_property_get_payload(marker, include_call=False)
    payload = _functools_cached_property_get_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="functools-cached-property-get-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "cached_property"
    assert control_result.attrname == "x"
    assert not marker.exists()

    report = scan_bytes(payload, source="functools-cached-property-get-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_functools_wrapper_finding(report, "cached_property.__get__")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_functools_cmp_to_key_comparison_rce(tmp_path: Path) -> None:
    marker = tmp_path / "functools_cmp_to_key_comparison_rce_marker"
    control_payload = _functools_cmp_to_key_operator_lt_payload(marker, include_call=False)
    payload = _functools_cmp_to_key_operator_lt_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="functools-cmp-to-key-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_functools_wrapper_finding(control_report, "cmp_to_key")

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert isinstance(control_result, tuple)
    assert len(control_result) == 2
    assert not marker.exists()

    report = scan_bytes(payload, source="functools-cmp-to-key-operator-lt-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_functools_wrapper_finding(report, "cmp_to_key")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is False
    assert marker.read_text() == "x"


def test_scan_bytes_blocks_logging_filterer_filter_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "logging_filterer_filter_callback_rce_marker"
    control_payload = _logging_filterer_filter_payload(marker, include_call=False)
    payload = _logging_filterer_filter_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="logging-filterer-filter-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "Filterer"
    assert len(control_result.filters) == 1
    assert not marker.exists()

    report = scan_bytes(payload, source="logging-filterer-filter-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_logging_filterer_filter_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is False
    assert marker.exists()


@pytest.mark.parametrize(
    (
        "sink_name",
        "handler_module",
        "handler_name",
        "handler_args",
        "driver_module",
        "driver_name",
        "expected_globals",
    ),
    [
        (
            "filehandler_file_emit",
            "logging",
            "FileHandler",
            [_text_operand("w")],
            "logging",
            "FileHandler.emit",
            [("logging", "FileHandler"), ("logging", "FileHandler.emit")],
        ),
        (
            "filehandler_stream_emit",
            "logging",
            "FileHandler",
            [_text_operand("w")],
            "logging",
            "StreamHandler.emit",
            [("logging", "FileHandler"), ("logging", "StreamHandler.emit")],
        ),
        (
            "filehandler_handler_handle",
            "logging",
            "FileHandler",
            [_text_operand("w")],
            "logging",
            "Handler.handle",
            [("logging", "FileHandler"), ("logging", "Handler.handle")],
        ),
        (
            "watched_stream_emit",
            "logging.handlers",
            "WatchedFileHandler",
            [_text_operand("w")],
            "logging",
            "StreamHandler.emit",
            [("logging.handlers", "WatchedFileHandler"), ("logging", "StreamHandler.emit")],
        ),
        (
            "rotating_stream_emit",
            "logging.handlers",
            "RotatingFileHandler",
            [_text_operand("w")],
            "logging",
            "StreamHandler.emit",
            [("logging.handlers", "RotatingFileHandler"), ("logging", "StreamHandler.emit")],
        ),
        (
            "timed_stream_emit",
            "logging.handlers",
            "TimedRotatingFileHandler",
            [],
            "logging",
            "StreamHandler.emit",
            [("logging.handlers", "TimedRotatingFileHandler"), ("logging", "StreamHandler.emit")],
        ),
    ],
)
def test_scan_bytes_blocks_logging_file_handler_writes(
    tmp_path: Path,
    sink_name: str,
    handler_module: str,
    handler_name: str,
    handler_args: list[bytes],
    driver_module: str,
    driver_name: str,
    expected_globals: list[tuple[str, str]],
) -> None:
    marker = tmp_path / f"logging_{sink_name}_rce_marker"
    message = f"owned-by-{sink_name}"
    control_payload = _logging_file_handler_payload(
        marker,
        handler_module=handler_module,
        handler_name=handler_name,
        handler_args=handler_args,
        driver_module=driver_module,
        driver_name=driver_name,
        message=message,
        include_emit=False,
    )
    payload = _logging_file_handler_payload(
        marker,
        handler_module=handler_module,
        handler_name=handler_name,
        handler_args=handler_args,
        driver_module=driver_module,
        driver_name=driver_name,
        message=message,
        include_emit=True,
    )

    control_report = scan_bytes(control_payload, source=f"logging-file-handler-{sink_name}-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(control_report, handler_module, handler_name)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    try:
        assert type(control_result).__name__ == handler_name
        assert marker.read_text() == ""
    finally:
        control_result.close()
    marker.unlink()

    report = scan_bytes(payload, source=f"logging-file-handler-{sink_name}-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    for module, name in expected_globals:
        assert _has_critical_global_finding(report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.read_text() == f"{message}\n"


def test_scan_bytes_blocks_logging_file_handler_fragmented_pth_rce(tmp_path: Path) -> None:
    pth_path = tmp_path / "logging_filehandler_exec.pth"
    marker = tmp_path / "logging_filehandler_pth_rce_marker"
    payload = _logging_file_handler_pth_payload(pth_path, marker)
    original_sys_path = list(sys.path)

    try:
        report = scan_bytes(payload, source="logging-file-handler-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "logging", "FileHandler")
        assert _has_critical_global_finding(report, "logging", "Handler.handle")

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_text() == (
            f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-logging-pth')\n"
        )
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-logging-pth"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.parametrize(
    ("emit_global", "expected_emit_global"),
    [
        ("Logger.warning", "Logger.warning"),
        ("warning", "warning"),
    ],
)
def test_scan_bytes_blocks_logging_stream_handler_fragmented_pth_rce(
    tmp_path: Path,
    emit_global: str,
    expected_emit_global: str,
) -> None:
    pth_path = tmp_path / f"logging_stream_{emit_global.replace('.', '_')}.pth"
    marker = tmp_path / f"logging_stream_{emit_global.replace('.', '_')}_marker"
    control_payload = _logging_stream_handler_pth_payload(
        pth_path,
        marker,
        include_emit=False,
        emit_global=emit_global,
    )
    payload = _logging_stream_handler_pth_payload(
        pth_path,
        marker,
        include_emit=True,
        emit_global=emit_global,
    )
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    original_sys_path = list(sys.path)

    try:
        control_report = scan_bytes(control_payload, source=f"logging-stream-{emit_global}-control.pkl")
        assert control_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(control_report, "argparse", "FileType")
        assert _has_critical_global_finding(control_report, "logging", "StreamHandler")
        assert _has_critical_global_finding(control_report, "logging", "Logger.addHandler")

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result is root_logger
        _restore_root_logger(root_logger, original_handlers, original_level)
        assert pth_path.read_text() == ""
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path
        pth_path.unlink()

        report = scan_bytes(payload, source=f"logging-stream-{emit_global}-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "argparse", "FileType")
        assert _has_critical_global_finding(report, "logging", "StreamHandler")
        assert _has_critical_global_finding(report, "logging", "Logger.addHandler")
        assert _has_critical_global_finding(report, "logging", expected_emit_global)

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        _restore_root_logger(root_logger, original_handlers, original_level)
        assert pth_path.read_text() == (
            f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-logging-stream')\n\n"
        )
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-logging-stream"
    finally:
        _restore_root_logger(root_logger, original_handlers, original_level)
        sys.path[:] = original_sys_path


@pytest.mark.skipif(not _module_available("numpy"), reason="numpy is unavailable")
@pytest.mark.parametrize(
    "writer_module",
    [
        "numpy",
        pytest.param(
            "numpy.lib._npyio_impl",
            marks=pytest.mark.skipif(
                not _module_available("numpy.lib._npyio_impl"),
                reason="numpy.lib._npyio_impl is unavailable",
            ),
        ),
    ],
)
def test_scan_bytes_blocks_numpy_savetxt_fragmented_pth_rce(tmp_path: Path, writer_module: str) -> None:
    case_name = writer_module.replace(".", "_")
    pth_path = tmp_path / f"{case_name}_savetxt_exec.pth"
    marker = tmp_path / f"{case_name}_savetxt_marker"
    control_payload = _numpy_savetxt_pth_payload(
        pth_path,
        marker,
        writer_module=writer_module,
        include_write=False,
    )
    payload = _numpy_savetxt_pth_payload(
        pth_path,
        marker,
        writer_module=writer_module,
        include_write=True,
    )
    original_sys_path = list(sys.path)

    try:
        control_report = scan_bytes(control_payload, source=f"numpy-savetxt-{case_name}-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result == f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-numpy-savetxt')"
        assert not pth_path.exists()
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path

        report = scan_bytes(payload, source=f"numpy-savetxt-{case_name}-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, writer_module, "savetxt")

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_text() == (
            f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-numpy-savetxt')\n"
        )
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-numpy-savetxt"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.skipif(not _module_available("dotenv"), reason="python-dotenv is unavailable")
@pytest.mark.parametrize(
    "writer_module",
    [
        "dotenv",
        "dotenv.main",
        pytest.param(
            "dotenv.cli",
            marks=pytest.mark.skipif(not _module_available("dotenv.cli"), reason="dotenv.cli is unavailable"),
        ),
    ],
)
def test_scan_bytes_blocks_dotenv_set_key_fragmented_pth_rce(tmp_path: Path, writer_module: str) -> None:
    case_name = writer_module.replace(".", "_")
    pth_path = tmp_path / f"{case_name}_set_key_exec.pth"
    marker = tmp_path / f"{case_name}_set_key_marker"
    control_payload = _dotenv_set_key_pth_payload(
        pth_path,
        marker,
        writer_module=writer_module,
        include_write=False,
    )
    payload = _dotenv_set_key_pth_payload(
        pth_path,
        marker,
        writer_module=writer_module,
        include_write=True,
    )
    original_sys_path = list(sys.path)
    expected_line = f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-dotenv')#"

    try:
        control_report = scan_bytes(control_payload, source=f"dotenv-set-key-{case_name}-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result == expected_line
        assert not pth_path.exists()
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path

        report = scan_bytes(payload, source=f"dotenv-set-key-{case_name}-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, writer_module, "set_key")

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result == (True, expected_line, "x")
        assert pth_path.read_text() == f"{expected_line}='x'\n"
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-dotenv"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.skipif(not _module_available("click"), reason="Click is unavailable")
@pytest.mark.parametrize(
    "click_module",
    [
        "click",
        pytest.param(
            "click.utils",
            marks=pytest.mark.skipif(not _module_available("click.utils"), reason="click.utils is unavailable"),
        ),
    ],
)
def test_scan_bytes_blocks_click_open_file_echo_fragmented_pth_rce(tmp_path: Path, click_module: str) -> None:
    case_name = click_module.replace(".", "_")
    pth_path = tmp_path / f"{case_name}_echo_exec.pth"
    marker = tmp_path / f"{case_name}_echo_marker"
    control_payload = _click_open_file_echo_pth_payload(
        pth_path,
        marker,
        click_module=click_module,
        include_write=False,
    )
    payload = _click_open_file_echo_pth_payload(
        pth_path,
        marker,
        click_module=click_module,
        include_write=True,
    )
    original_sys_path = list(sys.path)
    expected_line = f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-click')"

    try:
        control_report = scan_bytes(control_payload, source=f"click-echo-{case_name}-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result == expected_line
        assert not pth_path.exists()
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path

        report = scan_bytes(payload, source=f"click-echo-{case_name}-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_call_graph_file_write_finding(
            report,
            click_module,
            "open_file",
            click_module,
            "echo",
        )

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_text() == f"{expected_line}\n"
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-click"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.skipif(not _module_available("click.utils"), reason="click.utils is unavailable")
def test_scan_bytes_blocks_click_lazy_file_echo_fragmented_pth_rce(tmp_path: Path) -> None:
    pth_path = tmp_path / "click_lazy_file_echo_exec.pth"
    marker = tmp_path / "click_lazy_file_echo_marker"
    control_payload = _click_lazy_file_echo_pth_payload(pth_path, marker, include_write=False)
    payload = _click_lazy_file_echo_pth_payload(pth_path, marker, include_write=True)
    original_sys_path = list(sys.path)
    expected_line = f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-click-lazyfile')"

    try:
        control_report = scan_bytes(control_payload, source="click-lazy-file-echo-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result == expected_line
        assert not pth_path.exists()
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path

        report = scan_bytes(payload, source="click-lazy-file-echo-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_call_graph_file_write_finding(
            report,
            "click.utils",
            "LazyFile",
            "click",
            "echo",
        )

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_text() == f"{expected_line}\n"
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-click-lazyfile"
    finally:
        sys.path[:] = original_sys_path


def test_scan_bytes_blocks_io_fileio_fragmented_pth_rce(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pth_path = tmp_path / "io_fileio_exec.pth"
    marker = tmp_path / "io_fileio_marker"
    control_payload, expected_line = _io_fileio_pth_payload(pth_path, marker, include_write=False)
    payload, _ = _io_fileio_pth_payload(pth_path, marker, include_write=True)
    original_sys_path = list(sys.path)
    monkeypatch.setenv("MODELAUDIT_PICKLESCAN_MARKER", str(marker))

    try:
        control_report = scan_bytes(control_payload, source="io-fileio-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result == expected_line
        assert not pth_path.exists()
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path

        report = scan_bytes(payload, source="io-fileio-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "io", "FileIO")
        assert _has_critical_global_finding(report, "io", "FileIO.write")

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_bytes() == expected_line
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-io-fileio"
    finally:
        sys.path[:] = original_sys_path


def test_scan_bytes_blocks_builtin_dict_lookup_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtin_dict_get_eval_marker"
    control_payload, expected_code = _builtin_dict_get_eval_payload(marker, include_lookup=False)
    payload, _ = _builtin_dict_get_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="builtin-dict-get-eval-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="builtin-dict-get-eval-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "builtins", "__dict__")

    direct_lookup = b"\x80\x04" + _global_operand("builtins", "__dict__.get") + b"."
    direct_report = scan_bytes(direct_lookup, source="builtin-dict-get-bound-method.pkl")
    assert direct_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(direct_report, "builtins", "__dict__.get")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-dict-get")
    assert marker.read_text() == "owned-by-dict-get"


def test_scan_bytes_blocks_module_dict_fragmented_builtins_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "fragmented_module_builtins_marker"
    control_payload, expected_code = _module_dict_builtins_eval_payload(marker, include_lookup=False)
    payload, _ = _module_dict_builtins_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="module-dict-builtins-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="module-dict-builtins-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "sysconfig", "__dict__")

    direct_payload = b"\x80\x04" + _global_operand("sysconfig", "__builtins__") + b"."
    direct_report = scan_bytes(direct_payload, source="module-builtins-direct.pkl")
    assert direct_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(direct_report, "sysconfig", "__builtins__")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-fragmented-module-builtins")
    assert marker.read_text() == "owned-by-fragmented-module-builtins"


def test_scan_bytes_blocks_string_formatter_get_field_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "formatter_get_field_eval_marker"
    control_payload, expected_code = _string_formatter_get_field_eval_payload(marker, include_lookup=False)
    payload, _ = _string_formatter_get_field_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="formatter-get-field-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="formatter-get-field-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "string", "Formatter.get_field")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-formatter-get-field")
    assert marker.read_text() == "owned-by-formatter-get-field"


def test_scan_bytes_blocks_unittest_mock_get_target_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "mock_get_target_eval_marker"
    control_payload, expected_code = _unittest_mock_get_target_eval_payload(marker, include_lookup=False)
    payload, _ = _unittest_mock_get_target_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="mock-get-target-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="mock-get-target-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "unittest.mock", "_get_target")

    direct_payload = b"\x80\x04" + _global_operand("unittest.mock", "_get_target") + b"."
    direct_report = scan_bytes(direct_payload, source="mock-get-target-direct.pkl")
    assert direct_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(direct_report, "unittest.mock", "_get_target")

    if _runtime_before((3, 11)):
        return

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-mock-get-target")
    assert marker.read_text() == "owned-by-mock-get-target"


def test_scan_bytes_blocks_static_member_descriptor_builtins_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "static_member_descriptor_eval_marker"
    control_payload, expected_code = _static_member_descriptor_builtins_eval_payload(marker, include_lookup=False)
    payload, _ = _static_member_descriptor_builtins_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="static-member-descriptor-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="static-member-descriptor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "types", "MemberDescriptorType.__get__")

    for name in ["MemberDescriptorType.__get__", "GetSetDescriptorType.__get__"]:
        direct_payload = b"\x80\x04" + _global_operand("types", name) + b"."
        direct_report = scan_bytes(direct_payload, source=f"types-{name}-direct.pkl")
        assert direct_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(direct_report, "types", name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-descriptor-static")
    assert marker.read_text() == "owned-by-descriptor-static"


def test_scan_bytes_blocks_wrapper_descriptor_getattribute_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "wrapper_descriptor_eval_marker"
    control_payload, expected_code = _wrapper_descriptor_getattribute_eval_payload(marker, include_lookup=False)
    payload, _ = _wrapper_descriptor_getattribute_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="wrapper-descriptor-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="wrapper-descriptor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "types", "WrapperDescriptorType.__get__")

    for name in [
        "ClassMethodDescriptorType.__get__",
        "MethodDescriptorType.__get__",
        "WrapperDescriptorType.__get__",
    ]:
        direct_payload = b"\x80\x04" + _global_operand("types", name) + b"."
        direct_report = scan_bytes(direct_payload, source=f"types-{name}-direct.pkl")
        assert direct_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(direct_report, "types", name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-wrapper-descriptor")
    assert marker.read_text() == "owned-by-wrapper-descriptor"


def test_scan_bytes_blocks_legacy_global_bound_getattribute_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "legacy_bound_getattribute_eval_marker"
    control_payload, expected_code = _legacy_bound_getattribute_eval_payload(marker, include_lookup=False)
    payload, _ = _legacy_bound_getattribute_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="legacy-bound-getattribute-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="legacy-bound-getattribute-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "statistics", "mean.__getattribute__")

    for module, name in [
        ("statistics", "__getattribute__"),
        ("builtins", "object.__getattribute__"),
        ("statistics", "mean.__globals__"),
    ]:
        direct_payload = b"\x80\x04" + _legacy_global_operand(module, name) + b"."
        direct_report = scan_bytes(direct_payload, source=f"{module}-{name}-legacy-direct.pkl")
        assert direct_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(direct_report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-bound-function-getattribute")
    assert marker.read_text() == "owned-by-bound-function-getattribute"


def test_scan_bytes_blocks_object_subclasses_popen_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "object_subclasses_popen_marker"
    control_payload, _ = _subclasses_popen_payload(marker, include_call=False)
    payload, popen_index = _subclasses_popen_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="object-subclasses-popen-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result[0] == sys.executable
    assert control_result[1] == "-c"
    assert "owned-by-subclasses-popen" in control_result[2]
    assert not marker.exists()

    report = scan_bytes(payload, source="object-subclasses-popen-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "builtins", "object.__subclasses__")

    for global_payload in [
        _legacy_global_operand("builtins", "object.__subclasses__"),
        _global_operand("builtins", "object.__subclasses__"),
        _legacy_global_operand("collections", "Counter.__subclasses__"),
    ]:
        direct_report = scan_bytes(b"\x80\x04" + global_payload + b".", source="object-subclasses-direct.pkl")
        assert direct_report.verdict == SafetyVerdict.MALICIOUS

    assert not marker.exists()
    result = pickle.loads(payload)
    assert isinstance(result, subprocess.Popen)
    popen_class: object = subprocess.Popen
    assert object.__subclasses__()[popen_index] is popen_class
    assert result.wait(timeout=5) == 0
    assert marker.read_text() == "owned-by-subclasses-popen"


def test_scan_bytes_blocks_gc_referents_builtin_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "gc_referents_eval_marker"
    control_payload, expected_code, _ = _gc_referents_eval_payload(marker, include_lookup=False)
    payload, _, referent_index = _gc_referents_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="gc-referents-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="gc-referents-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "gc", "get_referents")

    for name in ["get_objects", "get_referents", "get_referrers"]:
        for global_payload in [_legacy_global_operand("gc", name), _global_operand("gc", name)]:
            direct_report = scan_bytes(b"\x80\x04" + global_payload + b".", source=f"gc-{name}-direct.pkl")
            assert direct_report.verdict == SafetyVerdict.MALICIOUS
            assert _has_critical_global_finding(direct_report, "gc", name)

    assert gc.get_referents(statistics.mean)[referent_index] is builtins.__dict__
    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-gc-referents")
    assert marker.read_text() == "owned-by-gc-referents"


def test_scan_bytes_blocks_frame_builtins_descriptor_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "frame_builtins_descriptor_eval_marker"
    control_payload, expected_code = _frame_builtins_descriptor_eval_payload(marker, include_lookup=False)
    payload, _ = _frame_builtins_descriptor_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="frame-builtins-descriptor-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="frame-builtins-descriptor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "inspect", "currentframe")
    assert _has_critical_global_finding(report, "types", "FrameType.f_builtins.__get__")

    for module, name in [
        ("inspect", "currentframe"),
        ("types", "FrameType.f_builtins.__get__"),
        ("types", "FrameType.f_globals.__get__"),
        ("types", "FrameType.f_locals.__get__"),
    ]:
        for global_payload in [_legacy_global_operand(module, name), _global_operand(module, name)]:
            direct_report = scan_bytes(b"\x80\x04" + global_payload + b".", source=f"{module}-{name}-direct.pkl")
            assert direct_report.verdict == SafetyVerdict.MALICIOUS
            assert _has_critical_global_finding(direct_report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-frame-f-builtins")
    assert marker.read_text() == "owned-by-frame-f-builtins"


def test_scan_bytes_blocks_callable_suffix_frame_builtins_descriptor_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "frame_builtins_call_suffix_eval_marker"
    control_payload, expected_code = _frame_builtins_call_suffix_eval_payload(marker, include_lookup=False)
    payload, _ = _frame_builtins_call_suffix_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="frame-builtins-call-suffix-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="frame-builtins-call-suffix-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "inspect", "currentframe.__call__")
    assert _has_critical_global_finding(report, "types", "FrameType.f_builtins.__get__.__call__")

    for module, name in [
        ("inspect", "currentframe.__call__"),
        ("inspect", "currentframe.__call__.__call__"),
        ("types", "FrameType.f_builtins.__get__.__call__"),
        ("types", "FrameType.f_builtins.__get__.__call__.__call__"),
        ("types", "FrameType.f_globals.__get__.__call__"),
        ("types", "FrameType.f_locals.__get__.__call__"),
    ]:
        for global_payload in [_legacy_global_operand(module, name), _global_operand(module, name)]:
            direct_report = scan_bytes(
                b"\x80\x04" + global_payload + b".",
                source=f"{module}-{name}-call-suffix-direct.pkl",
            )
            assert direct_report.verdict == SafetyVerdict.MALICIOUS
            assert _has_critical_global_finding(direct_report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-call-suffix")
    assert marker.read_text() == "owned-by-call-suffix"


def test_scan_bytes_blocks_get_self_alias_frame_builtins_descriptor_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "frame_builtins_get_self_alias_eval_marker"
    control_payload, expected_code = _frame_builtins_get_self_alias_eval_payload(marker, include_lookup=False)
    payload, _ = _frame_builtins_get_self_alias_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="frame-builtins-get-self-alias-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="frame-builtins-get-self-alias-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "inspect", "currentframe.__get__.__self__")
    assert _has_critical_global_finding(report, "types", "FrameType.f_builtins.__get__.__self__.__get__")

    for module, name in [
        ("inspect", "currentframe.__get__"),
        ("inspect", "currentframe.__get__.__self__"),
        ("inspect", "currentframe.__get__.__self__.__call__"),
        ("types", "FrameType.f_builtins.__get__.__self__"),
        ("types", "FrameType.f_builtins.__get__.__self__.__get__"),
        ("types", "FrameType.f_builtins.__get__.__self__.__get__.__call__"),
        ("types", "FrameType.f_globals.__get__.__self__"),
        ("types", "FrameType.f_globals.__get__.__self__.__get__"),
        ("types", "FrameType.f_locals.__get__.__self__"),
        ("types", "FrameType.f_locals.__get__.__self__.__get__"),
    ]:
        for global_payload in [_legacy_global_operand(module, name), _global_operand(module, name)]:
            direct_report = scan_bytes(
                b"\x80\x04" + global_payload + b".",
                source=f"{module}-{name}-get-self-alias-direct.pkl",
            )
            assert direct_report.verdict == SafetyVerdict.MALICIOUS
            assert _has_critical_global_finding(direct_report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-get-self")
    assert marker.read_text() == "owned-by-get-self"


def test_scan_bytes_blocks_repr_self_alias_frame_builtins_descriptor_eval_recovery_rce(tmp_path: Path) -> None:
    marker = tmp_path / "frame_builtins_repr_self_alias_eval_marker"
    control_payload, expected_code = _frame_builtins_repr_self_alias_eval_payload(marker, include_lookup=False)
    payload, _ = _frame_builtins_repr_self_alias_eval_payload(marker, include_lookup=True)

    control_report = scan_bytes(control_payload, source="frame-builtins-repr-self-alias-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == expected_code
    assert not marker.exists()

    report = scan_bytes(payload, source="frame-builtins-repr-self-alias-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "inspect", "currentframe.__repr__.__self__")
    assert _has_critical_global_finding(report, "types", "FrameType.f_builtins.__get__.__repr__.__self__")

    for module, name in [
        ("inspect", "currentframe.__repr__"),
        ("inspect", "currentframe.__repr__.__self__"),
        ("inspect", "currentframe.__str__.__self__"),
        ("inspect", "currentframe.__reduce__.__self__"),
        ("types", "FrameType.f_builtins.__get__.__repr__"),
        ("types", "FrameType.f_builtins.__get__.__repr__.__self__"),
        ("types", "FrameType.f_builtins.__get__.__str__.__self__"),
        ("types", "FrameType.f_globals.__get__.__repr__.__self__"),
        ("types", "FrameType.f_locals.__get__.__repr__.__self__"),
    ]:
        for global_payload in [_legacy_global_operand(module, name), _global_operand(module, name)]:
            direct_report = scan_bytes(
                b"\x80\x04" + global_payload + b".",
                source=f"{module}-{name}-repr-self-alias-direct.pkl",
            )
            assert direct_report.verdict == SafetyVerdict.MALICIOUS
            assert _has_critical_global_finding(direct_report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == len("owned-by-repr-self")
    assert marker.read_text() == "owned-by-repr-self"


@pytest.mark.skipif(sys.platform == "win32", reason="os.system proof uses POSIX shell redirection")
def test_scan_bytes_blocks_dotted_global_os_system_alias_rce(tmp_path: Path) -> None:
    marker = tmp_path / "site_os_system_marker"
    command = f"printf owned-by-site-os-system > {shlex.quote(str(marker))}"
    control_payload = _site_os_system_payload(command, include_call=False)
    payload = _site_os_system_payload(command, include_call=True)

    control_report = scan_bytes(control_payload, source="site-os-system-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == (command,)
    assert not marker.exists()

    report = scan_bytes(payload, source="site-os-system-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "site", "os.system")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == 0
    assert marker.read_text() == "owned-by-site-os-system"


@pytest.mark.skipif(sys.platform == "win32", reason="PosixPath proof is POSIX-specific")
def test_scan_bytes_blocks_posixpath_writer_and_site_dict_lookup_pth_rce(tmp_path: Path) -> None:
    pth_path = tmp_path / "posixpath_site_dict_exec.pth"
    marker = tmp_path / "posixpath_site_dict_marker"
    control_payload, expected_line = _posixpath_site_dict_pth_payload(
        pth_path,
        marker,
        tmp_path,
        include_write=False,
    )
    payload, _ = _posixpath_site_dict_pth_payload(
        pth_path,
        marker,
        tmp_path,
        include_write=True,
    )
    original_sys_path = list(sys.path)

    try:
        control_report = scan_bytes(control_payload, source="posixpath-site-dict-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result == expected_line
        assert not pth_path.exists()
        assert not marker.exists()

        report = scan_bytes(payload, source="posixpath-site-dict-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "pathlib", "PosixPath.write_text")
        assert _has_critical_global_finding(report, "site", "__dict__.get")

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_text() == expected_line
        assert marker.read_text() == "owned-by-posixpath-site-dict"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.skipif(sys.platform == "win32", reason="dotenv.cli.run_command uses POSIX os.execvpe in this proof")
@pytest.mark.skipif(not _module_available("dotenv.cli"), reason="dotenv.cli is unavailable")
def test_scan_bytes_blocks_dotenv_run_command_rce(tmp_path: Path) -> None:
    marker = tmp_path / "dotenv_run_command_marker"
    command = [
        "/bin/sh",
        "-c",
        f"printf owned-by-dotenv-run-command > {shlex.quote(str(marker))}",
    ]
    control_payload = _dotenv_run_command_payload(command, include_call=False)
    payload = _dotenv_run_command_payload(command, include_call=True)

    control_report = scan_bytes(control_payload, source="dotenv-run-command-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == (command, {})
    assert not marker.exists()

    report = scan_bytes(payload, source="dotenv-run-command-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "dotenv.cli",
        "run_command",
        "os.execvpe",
    ) or _has_critical_call_graph_finding(
        report,
        "dotenv.cli",
        "run_command",
        "subprocess.Popen",
    )

    assert not marker.exists()
    child_code = f"import pickle; pickle.loads({payload!r})"
    result = subprocess.run(
        [sys.executable, "-c", child_code],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    assert marker.read_text() == "owned-by-dotenv-run-command"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
@pytest.mark.skipif(not _module_available("numpy._core.fromnumeric"), reason="NumPy fromnumeric is unavailable")
@pytest.mark.skipif(not _module_available("_pytest._py.path"), reason="pytest LocalPath is unavailable")
def test_scan_bytes_blocks_numpy_wrapfunc_controlled_getattr_rce(tmp_path: Path) -> None:
    marker = tmp_path / "numpy_wrapfunc_getattr_marker"
    command = f"printf owned-by-numpy-wrapfunc-localpath > {shlex.quote(str(marker))}"
    control_payload = _numpy_wrapfunc_localpath_sysexec_payload(command, include_call=False)
    payload = _numpy_wrapfunc_localpath_sysexec_payload(command, include_call=True)

    control_report = scan_bytes(control_payload, source="numpy-wrapfunc-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert str(control_result) == "/bin/sh"
    assert not marker.exists()

    assert _find_sink_path("numpy._core.fromnumeric._wrapfunc") == (
        "numpy._core.fromnumeric._wrapfunc",
        "builtins.getattr.__call__",
    )

    report = scan_bytes(payload, source="numpy-wrapfunc-localpath-sysexec-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "numpy._core.fromnumeric",
        "_wrapfunc",
        "builtins.getattr.__call__",
    )

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == ""
    assert marker.read_text() == "owned-by-numpy-wrapfunc-localpath"


@pytest.mark.skipif(not _module_available("scipy.stats._distn_infrastructure"), reason="SciPy stats is unavailable")
def test_scan_bytes_blocks_scipy_rv_continuous_setstate_rce(tmp_path: Path) -> None:
    marker = tmp_path / "scipy_rv_continuous_setstate_marker"
    payload = _scipy_rv_continuous_setstate_payload(marker)

    assert _call_graph_entrypoints("scipy.stats._distn_infrastructure.rv_continuous")[:1] == (
        "scipy.stats._distn_infrastructure.rv_continuous.__setstate__",
    )
    assert _find_sink_path("scipy.stats._distn_infrastructure.rv_continuous.__setstate__") == (
        "scipy.stats._distn_infrastructure.rv_continuous.__setstate__",
        "scipy.stats._distn_infrastructure.rv_continuous._attach_methods",
        "scipy.stats._distn_infrastructure.rv_continuous._attach_argparser_methods",
        "builtins.exec",
    )

    report = scan_bytes(payload, source="scipy-rv-continuous-setstate-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "scipy.stats._distn_infrastructure",
        "rv_continuous",
        "builtins.exec",
    )

    assert not marker.exists()
    result = pickle.loads(payload)
    assert type(result).__name__ == "rv_continuous"
    assert marker.read_text() == "owned-by-scipy-setstate-exec"


@pytest.mark.skipif(not _module_available("scipy.stats._continuous_distns"), reason="SciPy stats is unavailable")
def test_scan_bytes_blocks_scipy_norm_gen_cross_module_setstate_rce(tmp_path: Path) -> None:
    marker = tmp_path / "scipy_norm_gen_cross_module_setstate_marker"
    payload = _scipy_norm_gen_setstate_payload(marker)

    assert _call_graph_entrypoints("scipy.stats._continuous_distns.norm_gen")[:1] == (
        "scipy.stats._continuous_distns.norm_gen.__setstate__",
    )
    assert _find_sink_path("scipy.stats._continuous_distns.norm_gen.__setstate__") == (
        "scipy.stats._continuous_distns.norm_gen.__setstate__",
        "scipy.stats._continuous_distns.norm_gen._attach_methods",
        "scipy.stats._continuous_distns.norm_gen._attach_argparser_methods",
        "builtins.exec",
    )

    report = scan_bytes(payload, source="scipy-norm-gen-cross-module-setstate-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "scipy.stats._continuous_distns",
        "norm_gen",
        "builtins.exec",
    )

    assert not marker.exists()
    result = pickle.loads(payload)
    assert type(result).__name__ == "norm_gen"
    assert marker.read_text() == "owned-by-scipy-cross-module-setstate"


@pytest.mark.skipif(not _module_available("scipy.stats"), reason="SciPy stats is unavailable")
def test_scan_bytes_blocks_scipy_stats_norm_star_reexported_singleton_setstate_rce(tmp_path: Path) -> None:
    marker = tmp_path / "scipy_stats_norm_singleton_setstate_marker"
    payload = _scipy_stats_norm_singleton_setstate_payload(marker)

    assert _call_graph_entrypoints("scipy.stats.norm")[:1] == ("scipy.stats._continuous_distns.norm_gen.__setstate__",)
    assert _find_sink_path("scipy.stats._continuous_distns.norm_gen.__setstate__") == (
        "scipy.stats._continuous_distns.norm_gen.__setstate__",
        "scipy.stats._continuous_distns.norm_gen._attach_methods",
        "scipy.stats._continuous_distns.norm_gen._attach_argparser_methods",
        "builtins.exec",
    )

    report = scan_bytes(payload, source="scipy-stats-norm-star-reexported-singleton-setstate-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "scipy.stats",
        "norm",
        "builtins.exec",
    )

    assert not marker.exists()
    result = subprocess.run(
        [sys.executable, "-c", f"import pickle; pickle.loads(bytes.fromhex({payload.hex()!r}))"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert marker.read_text() == "owned-by-scipy-stats-norm-singleton"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
@pytest.mark.skipif(not _module_available("fsspec.implementations.cached"), reason="fsspec cached FS is unavailable")
def test_scan_bytes_blocks_fsspec_registry_poisoning_inherited_constructor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "fsspec_registry_poisoning_marker"
    cache_dir = tmp_path / "cache"
    payload = _fsspec_registry_poisoning_payload(marker, cache_dir)
    class_ref = "fsspec.implementations.cached.WholeFileCacheFileSystem"

    assert _call_graph_entrypoints(class_ref) == (
        f"{class_ref}.__getattribute__",
        f"{class_ref}.__init__",
    )
    assert _find_sink_path(f"{class_ref}.__init__") == (
        f"{class_ref}.__init__",
        "fsspec.filesystem",
        "fsspec.registry.get_filesystem_class",
        "fsspec.registry._import_class",
        "importlib.import_module",
    )

    report = scan_bytes(payload, source="fsspec-registry-poisoning-inherited-constructor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "fsspec.implementations.cached",
        "WholeFileCacheFileSystem",
        "importlib.import_module",
    )

    assert not marker.exists()
    child_code = """
import pickle
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
try:
    pickle.loads(payload)
except Exception:
    pass
for _ in range(100):
    if marker.exists():
        break
    time.sleep(0.02)
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "fsspec-registry-owned"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
@pytest.mark.skipif(not _module_available("pydantic"), reason="pydantic is unavailable")
def test_scan_bytes_blocks_pydantic_dynamic_imports_module_getattr_rce(tmp_path: Path) -> None:
    marker = tmp_path / "pydantic_dynamic_imports_marker"
    payload = _pydantic_dynamic_imports_payload(marker)

    assert _call_graph_entrypoints("pydantic._dynamic_imports") == ()
    assert _call_graph_entrypoints("pydantic.Popen") == ("pydantic.__getattr__",)
    assert _find_sink_path("pydantic.Popen") == (
        "pydantic.Popen",
        "importlib.import_module",
    )

    report = scan_bytes(payload, source="pydantic-dynamic-imports-module-getattr-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "pydantic",
        "Popen",
        "importlib.import_module",
    )

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
process = pickle.loads(payload)
process.wait(timeout=5)
if process.returncode != 0:
    raise SystemExit(process.returncode)
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "pydantic-dynamic-import-owned"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
@pytest.mark.skipif(not _module_available("pydantic"), reason="pydantic is unavailable")
def test_scan_bytes_blocks_pydantic_dotted_getattr_alias_rce(tmp_path: Path) -> None:
    marker = tmp_path / "pydantic_dotted_getattr_alias_marker"
    payload = _pydantic_dotted_getattr_alias_payload(marker)

    assert _call_graph_entrypoints("pydantic._dynamic_imports") == ()
    assert _call_graph_entrypoints("pydantic._os.system") == ("pydantic.__getattr__",)
    assert _find_sink_path("pydantic._os.system") == (
        "pydantic._os.system",
        "importlib.import_module",
    )

    report = scan_bytes(payload, source="pydantic-dotted-getattr-alias-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "pydantic",
        "_os.system",
        "importlib.import_module",
    )

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
result = pickle.loads(payload)
if result != 0:
    raise SystemExit(result)
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "pydantic-dotted-os-alias-owned"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_random_os_import_alias_prefix_rce(tmp_path: Path) -> None:
    marker = tmp_path / "random_os_alias_prefix_marker"
    payload = _random_os_alias_prefix_payload(marker)

    assert _call_graph_entrypoints("random._os") == ()
    assert _call_graph_entrypoints("random._os.system") == ("os.system",)
    assert _find_sink_path("random._os.system") == ("random._os.system", "os.system")
    assert _find_sink_path("os.system") == ("os.system",)

    report = scan_bytes(payload, source="random-os-alias-prefix-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "random", "_os.system", "os.system")

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
result = pickle.loads(payload)
if result != 0:
    raise SystemExit(result)
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "random-os-alias-owned"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_import_reference_limit_padding_rce(tmp_path: Path) -> None:
    marker = tmp_path / "import_reference_limit_padding_marker"
    control_payload = _import_reference_limit_random_os_alias_prefix_payload(marker, filler_count=31)
    payload = _import_reference_limit_random_os_alias_prefix_payload(marker, filler_count=32)

    control_report = scan_bytes(control_payload, source="import-reference-limit-control.pkl")
    report = scan_bytes(payload, source="import-reference-limit-padding-rce.pkl")

    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(control_report, "random", "_os.system", "os.system")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "random", "_os.system", "os.system")
    assert has_unanalyzed_call_graph_import_references(report.metadata["import_references"]) is False
    assert any(
        finding.module == "random" and finding.name == "_os.system" and finding.sink == "os.system"
        for finding in find_dangerous_call_graphs(report.metadata["import_references"])
    )

    assert has_unanalyzed_call_graph_import_references(
        tuple({"module": "unique", "name": f"ref_{index}"} for index in range(33))
    )

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
result = pickle.loads(payload)
if result != 0:
    raise SystemExit(result)
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "import-ref-limit-owned"


def test_call_graph_import_reference_limit_fails_closed() -> None:
    report = PickleReport(
        source="unique-import-reference-limit.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={"import_references": tuple({"module": "unique", "name": f"ref_{index}"} for index in range(33))},
    )

    updated = _with_call_graph_findings(report)

    assert updated.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_limit_finding(updated)


def test_scan_bytes_fails_closed_when_encoded_nested_probe_cap_is_exhausted() -> None:
    report = scan_bytes(
        _encoded_nested_probe_limit_payload(),
        source="encoded-nested-probe-cap.pkl",
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_encoded_nested_probe_limit_finding(report)
    assert any(notice.code == "nested_probe_limit" for notice in report.notices)


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_call_graph_exception_poisoning_rce(tmp_path: Path) -> None:
    marker = tmp_path / "call_graph_exception_poisoning_marker"
    payload = _call_graph_poisoned_random_os_alias_prefix_payload(marker)
    poison_after_payload = _call_graph_poisoned_random_os_alias_prefix_payload(marker, poison_after=True)

    findings = find_dangerous_call_graphs(
        (
            {"module": "xml.sax.saxutils", "name": "escape"},
            {"module": "random", "name": "_os.system"},
        )
    )
    assert any(
        finding.module == "random" and finding.name == "_os.system" and finding.sink == "os.system"
        for finding in findings
    )

    report = scan_bytes(payload, source="call-graph-exception-poisoning-before-rce.pkl")
    poison_after_report = scan_bytes(
        poison_after_payload,
        source="call-graph-exception-poisoning-after-rce.pkl",
    )

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "random", "_os.system", "os.system")
    assert poison_after_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(poison_after_report, "random", "_os.system", "os.system")

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

marker = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
result = pickle.loads(payload)
if result != 0:
    raise SystemExit(result)
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "call-graph-poison-owned"


def test_scan_bytes_blocks_pkgutil_iter_importers_import_side_effect_rce(tmp_path: Path) -> None:
    marker = tmp_path / "pkgutil_iter_importers_marker"
    package_dir = tmp_path / "evilpkg"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('pkgutil-iter-importers-owned')\n",
        encoding="utf-8",
    )
    payload = _pkgutil_iter_importers_payload()

    calls = _calls_for_function("pkgutil.iter_importers") or ()
    assert "importlib.import_module" in calls
    assert "importlib.machinery.import_module" not in calls
    assert _find_sink_path("pkgutil.iter_importers") == (
        "pkgutil.iter_importers",
        "importlib.import_module",
    )

    report = scan_bytes(payload, source="pkgutil-iter-importers-import-side-effect-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "pkgutil",
        "iter_importers",
        "importlib.import_module",
    )

    assert not marker.exists()
    child_code = """
import pickle
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
marker = Path(sys.argv[2])
payload = bytes.fromhex(sys.argv[3])
result = pickle.loads(payload)
if not isinstance(result, list):
    raise SystemExit(f"expected list result, got {type(result).__name__}")
if not marker.exists():
    raise SystemExit("marker was not written")
"""
    result = subprocess.run(
        [sys.executable, "-c", child_code, str(tmp_path), str(marker), payload.hex()],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "pkgutil-iter-importers-owned"


@pytest.mark.skipif(not _module_available("yaml"), reason="PyYAML is unavailable")
@pytest.mark.parametrize(
    (
        "case_name",
        "load_name",
        "loader_module",
        "loader_name",
        "force_iteration",
        "expected_globals",
    ),
    [
        ("unsafe-load", "unsafe_load", None, None, False, [("yaml", "unsafe_load")]),
        ("load-loader", "load", "yaml", "Loader", False, [("yaml", "load"), ("yaml", "Loader")]),
        (
            "load-unsafe-loader",
            "load",
            "yaml",
            "UnsafeLoader",
            False,
            [("yaml", "load"), ("yaml", "UnsafeLoader")],
        ),
        ("load-c-loader", "load", "yaml", "CLoader", False, [("yaml", "load"), ("yaml", "CLoader")]),
        (
            "load-c-unsafe-loader",
            "load",
            "yaml",
            "CUnsafeLoader",
            False,
            [("yaml", "load"), ("yaml", "CUnsafeLoader")],
        ),
        (
            "load-loader-module",
            "load",
            "yaml.loader",
            "Loader",
            False,
            [("yaml", "load"), ("yaml.loader", "Loader")],
        ),
        (
            "load-cyaml-loader",
            "load",
            "yaml.cyaml",
            "CLoader",
            False,
            [("yaml", "load"), ("yaml.cyaml", "CLoader")],
        ),
        (
            "load-cyaml-unsafe-loader",
            "load",
            "yaml.cyaml",
            "CUnsafeLoader",
            False,
            [("yaml", "load"), ("yaml.cyaml", "CUnsafeLoader")],
        ),
        ("unsafe-load-all", "unsafe_load_all", None, None, True, [("yaml", "unsafe_load_all")]),
        (
            "load-all-loader",
            "load_all",
            "yaml",
            "Loader",
            True,
            [("yaml", "load_all"), ("yaml", "Loader")],
        ),
        (
            "load-all-c-unsafe-loader",
            "load_all",
            "yaml",
            "CUnsafeLoader",
            True,
            [("yaml", "load_all"), ("yaml", "CUnsafeLoader")],
        ),
    ],
)
def test_scan_bytes_blocks_pyyaml_unsafe_loader_rce(
    tmp_path: Path,
    case_name: str,
    load_name: str,
    loader_module: str | None,
    loader_name: str | None,
    force_iteration: bool,
    expected_globals: list[tuple[str, str]],
) -> None:
    if (
        loader_module is not None
        and loader_name is not None
        and not _module_global_available(loader_module, loader_name)
    ):
        pytest.skip(f"{loader_module}.{loader_name} is unavailable")

    marker = tmp_path / f"{case_name}_marker"
    marker_content = f"owned-by-pyyaml-{case_name}"
    document = _pyyaml_unsafe_document(marker, marker_content)
    control_payload = b"\x80\x04" + _text_operand(document) + b"."
    payload = _pyyaml_unsafe_load_payload(
        document,
        load_name=load_name,
        loader_module=loader_module,
        loader_name=loader_name,
        force_iteration=force_iteration,
    )

    control_report = scan_bytes(control_payload, source=f"pyyaml-{case_name}-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == document
    assert not marker.exists()

    report = scan_bytes(payload, source=f"pyyaml-{case_name}-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    for module, name in expected_globals:
        assert _has_critical_global_finding(report, module, name)

    assert not marker.exists()
    result = pickle.loads(payload)
    if force_iteration:
        assert result == (None,)
    else:
        assert result is None
    assert marker.read_text() == marker_content


def test_scan_bytes_blocks_codecs_open_write_rce(tmp_path: Path) -> None:
    marker = tmp_path / "codecs_open_write_rce_marker"
    control_payload = _codecs_open_write_payload(marker, include_write=False)
    payload = _codecs_open_write_payload(marker, include_write=True)

    control_report = scan_bytes(control_payload, source="codecs-open-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(control_report, "codecs", "open")

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    try:
        assert type(control_result).__name__ == "StreamReaderWriter"
        assert marker.read_text() == ""
    finally:
        control_result.close()
    marker.unlink()

    report = scan_bytes(payload, source="codecs-open-write-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "codecs", "open")
    assert _has_critical_global_finding(report, "codecs", "StreamReaderWriter.write")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.read_text() == "owned-by-codecs-open"


def test_scan_bytes_blocks_codecs_open_fragmented_pth_rce(tmp_path: Path) -> None:
    pth_path = tmp_path / "codecs_open_exec.pth"
    marker = tmp_path / "codecs_open_pth_rce_marker"
    payload = _codecs_open_pth_payload(pth_path, marker)
    original_sys_path = list(sys.path)

    try:
        report = scan_bytes(payload, source="codecs-open-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "codecs", "open")
        assert _has_critical_global_finding(report, "codecs", "StreamReaderWriter.write")

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.read_text() == (
            f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-codecs-pth')\n"
        )
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-codecs-pth"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.parametrize("writer_method", ["DictWriter.writerow", "DictWriter.writerows"])
def test_scan_bytes_blocks_csv_tempfile_fragmented_pth_rce(tmp_path: Path, writer_method: str) -> None:
    marker = tmp_path / f"csv_tempfile_{writer_method.rsplit('.', maxsplit=1)[-1]}_pth_rce_marker"
    control_payload = _csv_tempfile_pth_payload(
        tmp_path,
        marker,
        include_write=False,
        writer_method=writer_method,
    )
    payload = _csv_tempfile_pth_payload(
        tmp_path,
        marker,
        include_write=True,
        writer_method=writer_method,
    )
    original_sys_path = list(sys.path)

    try:
        control_report = scan_bytes(control_payload, source=f"csv-tempfile-{writer_method}-control.pkl")
        assert control_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(control_report, "tempfile", "NamedTemporaryFile")

        assert not list(tmp_path.glob("ma_csv_*.pth"))
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result is None
        control_pths = list(tmp_path.glob("ma_csv_*.pth"))
        assert len(control_pths) == 1
        assert control_pths[0].read_text() == ""
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path
        control_pths[0].unlink()

        report = scan_bytes(payload, source=f"csv-tempfile-{writer_method}-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "tempfile", "NamedTemporaryFile")
        assert _has_critical_global_finding(report, "csv", writer_method)

        assert not list(tmp_path.glob("ma_csv_*.pth"))
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        pths = list(tmp_path.glob("ma_csv_*.pth"))
        assert len(pths) == 1
        assert pths[0].read_text() == (
            f"import pathlib;pathlib.Path({str(marker)!r}).write_text('owned-by-csv-tempfile')\n"
        )
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == "owned-by-csv-tempfile"
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.parametrize(
    ("case_name", "mailbox_class", "method_owner", "marker_content", "expected_global"),
    [
        ("mbox", "mbox", "mbox", "owned-by-mailbox-mbox", "mbox.add"),
        ("mmdf", "MMDF", "MMDF", "owned-by-mailbox-mmdf", "MMDF.add"),
        ("babyl", "Babyl", "Babyl", "owned-by-mailbox-babyl", "Babyl.add"),
        (
            "singlefile-base",
            "mbox",
            "_singlefileMailbox",
            "owned-by-mailbox-base",
            "_singlefileMailbox.add",
        ),
    ],
)
def test_scan_bytes_blocks_mailbox_singlefile_pth_writes(
    tmp_path: Path,
    case_name: str,
    mailbox_class: str,
    method_owner: str,
    marker_content: str,
    expected_global: str,
) -> None:
    pth_path = tmp_path / f"mailbox_{case_name}_exec.pth"
    marker = tmp_path / f"mailbox_{case_name}_pth_rce_marker"
    control_payload = _mailbox_singlefile_pth_payload(
        pth_path,
        marker,
        mailbox_class=mailbox_class,
        method_owner=method_owner,
        marker_content=marker_content,
        include_add=False,
    )
    payload = _mailbox_singlefile_pth_payload(
        pth_path,
        marker,
        mailbox_class=mailbox_class,
        method_owner=method_owner,
        marker_content=marker_content,
        include_add=True,
    )
    original_sys_path = list(sys.path)

    try:
        control_report = scan_bytes(control_payload, source=f"mailbox-{case_name}-control.pkl")
        assert control_report.verdict == SafetyVerdict.CLEAN

        assert not pth_path.exists()
        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert control_result is None
        assert pth_path.read_text() == ""
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert not marker.exists()
        sys.path[:] = original_sys_path
        pth_path.unlink()

        report = scan_bytes(payload, source=f"mailbox-{case_name}-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(report, "mailbox", expected_global)

        assert not pth_path.exists()
        assert not marker.exists()
        result = pickle.loads(payload)
        assert result is None
        assert pth_path.exists()
        assert f"import pathlib;pathlib.Path({str(marker)!r}).write_text({marker_content!r})\n" in pth_path.read_text()
        assert not marker.exists()

        site.addsitedir(str(tmp_path))
        assert marker.read_text() == marker_content
    finally:
        sys.path[:] = original_sys_path


@pytest.mark.skipif(find_spec("_tkinter") is None, reason="_tkinter is unavailable")
@pytest.mark.skipif(sys.platform == "win32", reason="Tcl process execution proof uses /bin/sh")
@pytest.mark.parametrize(
    ("method_name", "payload_builder", "marker_content"),
    [
        ("TkappType.eval", _tkinter_tcl_eval_payload, "owned-by-tcl-eval"),
        ("TkappType.call", _tkinter_tcl_call_payload, "owned-by-tcl-call"),
    ],
)
def test_scan_bytes_blocks_tkinter_tcl_process_execution(
    tmp_path: Path,
    method_name: str,
    payload_builder: Callable[[Path], bytes],
    marker_content: str,
) -> None:
    control_payload = _tkinter_tcl_control_payload()
    control_report = scan_bytes(control_payload, source="tkinter-tcl-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "tkapp"

    marker = tmp_path / f"tkinter_tcl_{method_name.rsplit('.', 1)[1]}_marker"
    payload = payload_builder(marker)
    report = scan_bytes(payload, source=f"tkinter-tcl-{method_name}.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "_tkinter", method_name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == ""
    assert marker.read_text() == marker_content


@pytest.mark.skipif(find_spec("_xxsubinterpreters") is None, reason="_xxsubinterpreters is unavailable")
def test_scan_bytes_blocks_subinterpreters_run_string_rce(tmp_path: Path) -> None:
    control_payload = _subinterpreters_control_payload()
    control_report = scan_bytes(control_payload, source="subinterpreters-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert any(
        finding.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and finding.details.get("import_reference") == "_xxsubinterpreters.create"
        for finding in control_report.findings
    )

    marker = tmp_path / "subinterpreters_run_string_marker"
    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "InterpreterID"
    assert not marker.exists()

    payload = _subinterpreters_run_string_payload(marker)
    report = scan_bytes(payload, source="subinterpreters-run-string-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_global_finding(report, "_xxsubinterpreters", "run_string")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.read_text() == "owned-by-subinterp"


def test_scan_bytes_blocks_inspect_getmembers_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "inspect_getmembers_descriptor_rce_marker"
    control_payload = _inspect_getmembers_property_payload(marker, include_call=False)
    payload = _inspect_getmembers_property_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="inspect-getmembers-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="inspect-getmembers-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_inspect_getmembers_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert ("x", None) in result
    assert marker.exists()


def test_scan_bytes_blocks_builtins_hasattr_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_hasattr_descriptor_rce_marker"
    control_payload = _builtins_hasattr_property_payload(marker, include_call=False)
    payload = _builtins_hasattr_property_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-hasattr-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-hasattr-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_hasattr_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is True
    assert marker.exists()


def test_scan_bytes_blocks_builtins_type_del_finalizer_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_del_finalizer_rce_marker"
    control_payload = _builtins_type_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_type_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(control_payload, source="builtins-type-del-finalizer-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-del-finalizer-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_builtins_type_dynamic_del_finalizer_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_dynamic_del_finalizer_rce_marker"
    control_payload = _builtins_type_dynamic_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_type_dynamic_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(
        control_payload,
        source="builtins-type-dynamic-del-finalizer-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-dynamic-del-finalizer-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_fails_closed_on_dynamic_type_unknown_key_overflow(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_dynamic_del_overflow_marker"
    control_payload = _builtins_type_dynamic_del_finalizer_overflow_payload(marker, drop_instance=False)
    payload = _builtins_type_dynamic_del_finalizer_overflow_payload(marker, drop_instance=True)

    control_report = scan_bytes(
        control_payload,
        source="builtins-type-dynamic-del-overflow-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_unknown_key_overflow_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-dynamic-del-overflow-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_unknown_key_overflow_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_type_new_dynamic_del_finalizer_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_new_dynamic_del_finalizer_rce_marker"
    control_payload = _builtins_type_new_dynamic_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_type_new_dynamic_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(
        control_payload,
        source="builtins-type-new-dynamic-del-finalizer-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-new-dynamic-del-finalizer-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_type_call_dynamic_del_finalizer_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_call_dynamic_del_finalizer_rce_marker"
    control_payload = _builtins_type_call_dynamic_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_type_call_dynamic_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(
        control_payload,
        source="builtins-type-call-dynamic-del-finalizer-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-call-dynamic-del-finalizer-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_dict_constructor_dynamic_type_namespace_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_dict_constructor_dynamic_del_marker"
    control_payload = _builtins_type_dict_constructor_dynamic_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_type_dict_constructor_dynamic_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(
        control_payload,
        source="builtins-type-dict-constructor-dynamic-del-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_unknown_key_overflow_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-dict-constructor-dynamic-del-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_unknown_key_overflow_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("mutator_module", "mutator_name"),
    [
        (b"operator", b"setitem"),
        (b"builtins", b"dict.__setitem__"),
        (b"builtins", b"dict.setdefault"),
    ],
)
def test_scan_bytes_blocks_mutated_dynamic_type_namespace_rce(
    tmp_path: Path,
    mutator_module: bytes,
    mutator_name: bytes,
) -> None:
    marker = tmp_path / f"{mutator_module.decode()}_{mutator_name.decode().replace('.', '_')}_dynamic_del_marker"
    control_payload = _builtins_type_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=False,
        mutator_module=mutator_module,
        mutator_name=mutator_name,
    )
    payload = _builtins_type_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=True,
        mutator_module=mutator_module,
        mutator_name=mutator_name,
    )

    control_report = scan_bytes(
        control_payload,
        source=f"{mutator_module.decode()}-{mutator_name.decode()}-dynamic-del-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(
        payload,
        source=f"{mutator_module.decode()}-{mutator_name.decode()}-dynamic-del-rce.pkl",
    )

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("mutator_module", "mutator_name"),
    [
        (b"builtins", b"dict.__init__"),
        (b"builtins", b"dict.update"),
        (b"builtins", b"dict.__ior__"),
        (b"operator", b"ior"),
    ],
)
def test_scan_bytes_blocks_update_mutated_dynamic_type_namespace_rce(
    tmp_path: Path,
    mutator_module: bytes,
    mutator_name: bytes,
) -> None:
    marker = tmp_path / f"{mutator_module.decode()}_{mutator_name.decode().replace('.', '_')}_dynamic_del_marker"
    control_payload = _builtins_type_update_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=False,
        mutator_module=mutator_module,
        mutator_name=mutator_name,
        tracked_source=True,
    )
    payload = _builtins_type_update_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=True,
        mutator_module=mutator_module,
        mutator_name=mutator_name,
        tracked_source=True,
    )

    control_report = scan_bytes(
        control_payload,
        source=f"{mutator_module.decode()}-{mutator_name.decode()}-dynamic-del-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(
        payload,
        source=f"{mutator_module.decode()}-{mutator_name.decode()}-dynamic-del-rce.pkl",
    )

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("mutator_module", "mutator_name"),
    [
        (b"builtins", b"dict.__init__"),
        (b"builtins", b"dict.update"),
        (b"builtins", b"dict.__ior__"),
        (b"operator", b"ior"),
    ],
)
def test_scan_bytes_fails_closed_on_untracked_update_mutated_dynamic_type_namespace_rce(
    tmp_path: Path,
    mutator_module: bytes,
    mutator_name: bytes,
) -> None:
    marker = tmp_path / f"{mutator_module.decode()}_{mutator_name.decode().replace('.', '_')}_untracked_update"
    control_payload = _builtins_type_update_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=False,
        mutator_module=mutator_module,
        mutator_name=mutator_name,
    )
    payload = _builtins_type_update_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=True,
        mutator_module=mutator_module,
        mutator_name=mutator_name,
    )

    control_report = scan_bytes(
        control_payload,
        source=f"{mutator_module.decode()}-{mutator_name.decode()}-untracked-update-control.pkl",
    )
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_unknown_key_overflow_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(
        payload,
        source=f"{mutator_module.decode()}-{mutator_name.decode()}-untracked-update-rce.pkl",
    )

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_unknown_key_overflow_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_dict_copy_of_mutated_dynamic_type_namespace_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_dict_copy_mutated_dynamic_del_marker"
    control_payload = _builtins_type_dict_copy_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=False,
    )
    payload = _builtins_type_dict_copy_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=True,
    )

    control_report = scan_bytes(control_payload, source="builtins-type-dict-copy-dynamic-del-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-dict-copy-dynamic-del-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_dup_alias_mutated_dynamic_type_namespace_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_dup_alias_mutated_dynamic_del_marker"
    control_payload = _builtins_type_dup_alias_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=False,
    )
    payload = _builtins_type_dup_alias_mutated_namespace_dynamic_del_finalizer_payload(
        marker,
        drop_instance=True,
    )

    control_report = scan_bytes(control_payload, source="builtins-type-dup-alias-dynamic-del-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-dup-alias-dynamic-del-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_object_class_type_constructor_alias_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_object_class_type_constructor_alias_marker"
    control_payload = _builtins_object_class_dynamic_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_object_class_dynamic_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(control_payload, source="builtins-object-class-type-constructor-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-object-class-type-constructor-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_type_setattr_dynamic_del_finalizer_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_setattr_dynamic_del_finalizer_marker"
    control_payload = _builtins_type_setattr_dynamic_del_finalizer_payload(marker, drop_instance=False)
    payload = _builtins_type_setattr_dynamic_del_finalizer_payload(marker, drop_instance=True)

    control_report = scan_bytes(control_payload, source="builtins-type-setattr-dynamic-del-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source="builtins-type-setattr-dynamic-del-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("constructor_name", "payload_factory"),
    [
        ("type.__new__", _builtins_type_new_dynamic_del_finalizer_payload),
        ("type.__call__", _builtins_type_call_dynamic_del_finalizer_payload),
    ],
)
def test_scan_bytes_blocks_type_constructor_type_class_alias_rce(
    tmp_path: Path,
    constructor_name: str,
    payload_factory: Callable[..., bytes],
) -> None:
    marker = tmp_path / f"builtins_{constructor_name.replace('.', '_')}_type_class_alias_marker"
    control_payload = payload_factory(marker, drop_instance=False, type_value_name=b"type.__class__")
    payload = payload_factory(marker, drop_instance=True, type_value_name=b"type.__class__")

    control_report = scan_bytes(control_payload, source=f"builtins-{constructor_name}-type-class-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()
    type(control_result).__del__ = _noop_del

    report = scan_bytes(payload, source=f"builtins-{constructor_name}-type-class-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_dynamic_type_callable_attribute_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_builtins_type_eq_comparison_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_eq_comparison_rce_marker"
    control_payload = _builtins_type_eq_comparison_payload(marker, include_call=False)
    payload = _builtins_type_eq_comparison_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-type-eq-comparison-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-type-eq-comparison-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "operator_name"),
    [
        ("__neg__", "neg"),
        ("__pos__", "pos"),
        ("__abs__", "abs"),
        ("__invert__", "invert"),
    ],
)
def test_scan_bytes_blocks_builtins_type_unary_operator_rce(
    tmp_path: Path,
    method_name: str,
    operator_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{operator_name}_unary_operator_rce_marker"
    control_payload = _builtins_type_unary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=False,
    )
    payload = _builtins_type_unary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{operator_name}-unary-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{operator_name}-unary-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "builtin_name", "raises_type_error"),
    [
        ("__next__", "next", False),
        ("__reversed__", "reversed", False),
        ("__anext__", "anext", False),
        ("__iter__", "iter", True),
        ("__aiter__", "aiter", True),
    ],
)
def test_scan_bytes_blocks_builtins_type_iteration_protocol_rce(
    tmp_path: Path,
    method_name: str,
    builtin_name: str,
    raises_type_error: bool,
) -> None:
    marker = tmp_path / f"builtins_type_{builtin_name}_iteration_protocol_rce_marker"
    control_payload = _builtins_type_iteration_protocol_payload(
        marker,
        method_name=method_name,
        builtin_name=builtin_name,
        include_call=False,
    )
    payload = _builtins_type_iteration_protocol_payload(
        marker,
        method_name=method_name,
        builtin_name=builtin_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{builtin_name}-iteration-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{builtin_name}-iteration-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    if raises_type_error:
        with pytest.raises(TypeError):
            pickle.loads(payload)
    else:
        result = pickle.loads(payload)
        assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "module_name", "helper_name"),
    [
        ("__round__", "builtins", "round"),
        ("__floor__", "math", "floor"),
        ("__ceil__", "math", "ceil"),
        ("__trunc__", "math", "trunc"),
    ],
)
def test_scan_bytes_blocks_builtins_type_rounding_protocol_rce(
    tmp_path: Path,
    method_name: str,
    module_name: str,
    helper_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{helper_name}_rounding_protocol_rce_marker"
    control_payload = _builtins_type_rounding_protocol_payload(
        marker,
        method_name=method_name,
        module_name=module_name,
        helper_name=helper_name,
        include_call=False,
    )
    payload = _builtins_type_rounding_protocol_payload(
        marker,
        method_name=method_name,
        module_name=module_name,
        helper_name=helper_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{helper_name}-rounding-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{helper_name}-rounding-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    (
        "method_name",
        "base_module",
        "base_name",
        "callable_module",
        "callable_name",
        "helper_module",
        "helper_name",
        "helper_arg",
        "runtime_effect",
    ),
    [
        ("__repr__", "builtins", "str", "pathlib", "Path.touch", "builtins", "repr", None, "touch"),
        ("__str__", "builtins", "str", "pathlib", "Path.touch", "builtins", "str", None, "touch"),
        ("__bytes__", "builtins", "str", "pathlib", "Path.touch", "builtins", "bytes", None, "touch"),
        ("__hash__", "builtins", "str", "pathlib", "Path.touch", "builtins", "hash", None, "touch"),
        ("__len__", "builtins", "str", "pathlib", "Path.touch", "builtins", "len", None, "touch"),
        ("__bool__", "builtins", "str", "pathlib", "Path.touch", "builtins", "bool", None, "touch"),
        (
            "__length_hint__",
            "pathlib",
            "{path_class}",
            "pathlib",
            "Path.touch",
            "operator",
            "length_hint",
            None,
            "touch",
        ),
        (
            "__format__",
            "builtins",
            "str",
            "pathlib",
            "Path.symlink_to",
            "builtins",
            "format",
            "target-value",
            "symlink",
        ),
    ],
)
def test_scan_bytes_blocks_builtins_type_presentation_protocol_rce(
    tmp_path: Path,
    method_name: str,
    base_module: str,
    base_name: str,
    callable_module: str,
    callable_name: str,
    helper_module: str,
    helper_name: str,
    helper_arg: str | None,
    runtime_effect: str,
) -> None:
    marker = tmp_path / f"builtins_type_{helper_name}_presentation_protocol_rce_marker"
    resolved_base_name = type(marker).__name__ if base_name == "{path_class}" else base_name
    control_payload = _builtins_type_presentation_protocol_payload(
        marker,
        method_name=method_name,
        base_module=base_module,
        base_name=resolved_base_name,
        callable_module=callable_module,
        callable_name=callable_name,
        helper_module=helper_module,
        helper_name=helper_name,
        helper_arg=helper_arg,
        include_call=False,
    )
    payload = _builtins_type_presentation_protocol_payload(
        marker,
        method_name=method_name,
        base_module=base_module,
        base_name=resolved_base_name,
        callable_module=callable_module,
        callable_name=callable_name,
        helper_module=helper_module,
        helper_name=helper_name,
        helper_arg=helper_arg,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{helper_name}-presentation-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    assert not marker.is_symlink()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedValue"
    assert not marker.exists()
    assert not marker.is_symlink()

    report = scan_bytes(payload, source=f"builtins-type-{helper_name}-presentation-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    if _runtime_before((3, 11)):
        return

    assert not marker.exists()
    assert not marker.is_symlink()
    with pytest.raises(TypeError):
        pickle.loads(payload)

    if runtime_effect == "touch":
        assert marker.exists()
        assert not marker.is_symlink()
    elif runtime_effect == "symlink":
        assert marker.is_symlink()
        assert marker.readlink() == Path(helper_arg or "")
    else:
        raise AssertionError(f"unexpected runtime effect: {runtime_effect}")


def test_scan_bytes_blocks_builtins_type_fspath_protocol_file_write_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_fspath_protocol_rce_marker"
    control_payload = _builtins_type_fspath_protocol_payload(marker, include_write=False)
    payload = _builtins_type_fspath_protocol_payload(marker, include_write=True)

    control_report = scan_bytes(control_payload, source="builtins-type-fspath-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "PathLikeString"
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-type-fspath-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_suspicious_magic_method_finding(report)
    assert _has_critical_global_finding(report, "io", "open")
    assert _has_critical_global_finding(report, "_io", "TextIOWrapper.write")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.read_text() == "owned-by-fspath"


@pytest.mark.parametrize(
    ("sink_name", "expected_content", "expected_globals"),
    [
        (
            "path_write_text",
            b"owned-by-path-write-text",
            [("pathlib", "Path.write_text")],
        ),
        (
            "path_write_bytes",
            b"owned-by-path-write-bytes",
            [("pathlib", "Path.write_bytes")],
        ),
        (
            "path_open",
            b"owned-by-path-open",
            [("pathlib", "Path.open"), ("_io", "TextIOWrapper.write")],
        ),
        (
            "io_open",
            b"owned-by-io-open",
            [("io", "open"), ("_io", "TextIOWrapper.write")],
        ),
        (
            "_io_open",
            b"owned-by-_io-open",
            [("_io", "open"), ("_io", "TextIOWrapper.write")],
        ),
        (
            "fileio",
            b"owned-by-fileio",
            [("_io", "FileIO"), ("_io", "FileIO.write")],
        ),
    ],
)
def test_scan_bytes_blocks_direct_file_write_sinks(
    tmp_path: Path,
    sink_name: str,
    expected_content: bytes,
    expected_globals: list[tuple[str, str]],
) -> None:
    marker = tmp_path / f"direct_file_write_{sink_name}_rce_marker"
    control_payload = _direct_file_write_sink_payload(marker, sink_name=sink_name, include_write=False)
    payload = _direct_file_write_sink_payload(marker, sink_name=sink_name, include_write=True)

    control_report = scan_bytes(control_payload, source=f"direct-file-write-{sink_name}-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == type(marker).__name__
    assert not marker.exists()

    report = scan_bytes(payload, source=f"direct-file-write-{sink_name}-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    for module, name in expected_globals:
        assert _has_critical_global_finding(report, module, name)

    assert not marker.exists()
    pickle.loads(payload)
    assert marker.read_bytes() == expected_content


def test_scan_bytes_blocks_builtins_type_descriptor_set_name_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_descriptor_set_name_rce_marker"
    control_payload = _builtins_type_descriptor_set_name_payload(marker, include_owner_class=False)
    payload = _builtins_type_descriptor_set_name_payload(marker, include_owner_class=True)

    control_report = scan_bytes(control_payload, source="builtins-type-descriptor-set-name-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DescriptorPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-type-descriptor-set-name-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert type(result).__name__ == "Meta"
    assert result.__name__ == "Owner"
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "operator_name"),
    [
        ("__add__", "add"),
        ("__sub__", "sub"),
        ("__mul__", "mul"),
        ("__matmul__", "matmul"),
        ("__truediv__", "truediv"),
        ("__mod__", "mod"),
        ("__pow__", "pow"),
        ("__lshift__", "lshift"),
        ("__rshift__", "rshift"),
        ("__and__", "and_"),
        ("__xor__", "xor"),
        ("__or__", "or_"),
    ],
)
def test_scan_bytes_blocks_builtins_type_binary_operator_rce(
    tmp_path: Path,
    method_name: str,
    operator_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{operator_name}_binary_operator_rce_marker"
    control_payload = _builtins_type_binary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=False,
    )
    payload = _builtins_type_binary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{operator_name}-binary-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{operator_name}-binary-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "operator_name"),
    [
        ("__radd__", "add"),
        ("__rsub__", "sub"),
        ("__rmul__", "mul"),
        ("__rmatmul__", "matmul"),
        ("__rtruediv__", "truediv"),
        ("__rmod__", "mod"),
        ("__rpow__", "pow"),
        ("__rlshift__", "lshift"),
        ("__rrshift__", "rshift"),
        ("__rand__", "and_"),
        ("__rxor__", "xor"),
        ("__ror__", "or_"),
    ],
)
def test_scan_bytes_blocks_builtins_type_reflected_binary_operator_rce(
    tmp_path: Path,
    method_name: str,
    operator_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{operator_name}_reflected_operator_rce_marker"
    control_payload = _builtins_type_binary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=False,
        reverse_operands=True,
    )
    payload = _builtins_type_binary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=True,
        reverse_operands=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{operator_name}-reflected-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{operator_name}-reflected-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "operator_name"),
    [
        ("__iadd__", "iadd"),
        ("__isub__", "isub"),
        ("__imul__", "imul"),
        ("__imatmul__", "imatmul"),
        ("__itruediv__", "itruediv"),
        ("__imod__", "imod"),
        ("__ipow__", "ipow"),
        ("__ilshift__", "ilshift"),
        ("__irshift__", "irshift"),
        ("__iand__", "iand"),
        ("__ixor__", "ixor"),
        ("__ior__", "ior"),
    ],
)
def test_scan_bytes_blocks_builtins_type_inplace_binary_operator_rce(
    tmp_path: Path,
    method_name: str,
    operator_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{operator_name}_inplace_operator_rce_marker"
    control_payload = _builtins_type_binary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=False,
    )
    payload = _builtins_type_binary_operator_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{operator_name}-inplace-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{operator_name}-inplace-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "operator_name"),
    [
        ("__lt__", "lt"),
        ("__le__", "le"),
        ("__gt__", "gt"),
        ("__ge__", "ge"),
        ("__ne__", "ne"),
    ],
)
def test_scan_bytes_blocks_builtins_type_ordering_comparison_rce(
    tmp_path: Path,
    method_name: str,
    operator_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{operator_name}_ordering_comparison_rce_marker"
    control_payload = _builtins_type_ordering_comparison_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=False,
    )
    payload = _builtins_type_ordering_comparison_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{operator_name}-comparison-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{operator_name}-comparison-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize(
    ("method_name", "operator_name"),
    [
        ("__getitem__", "getitem"),
        ("__delitem__", "delitem"),
    ],
)
def test_scan_bytes_blocks_builtins_type_item_protocol_rce(
    tmp_path: Path,
    method_name: str,
    operator_name: str,
) -> None:
    marker = tmp_path / f"builtins_type_{operator_name}_item_protocol_rce_marker"
    control_payload = _builtins_type_item_protocol_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=False,
    )
    payload = _builtins_type_item_protocol_payload(
        marker,
        method_name=method_name,
        operator_name=operator_name,
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"builtins-type-{operator_name}-item-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"builtins-type-{operator_name}-item-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_builtins_type_contains_membership_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_contains_membership_rce_marker"
    control_payload = _builtins_type_contains_membership_payload(marker, include_call=False)
    payload = _builtins_type_contains_membership_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-type-contains-membership-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-type-contains-membership-rce.pkl")

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is False
    assert marker.exists()


def test_scan_bytes_blocks_builtins_type_setitem_assignment_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_type_setitem_assignment_rce_marker"
    control_payload = _builtins_type_setitem_assignment_payload(marker, include_call=False)
    payload = _builtins_type_setitem_assignment_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-type-setitem-assignment-control.pkl")
    assert control_report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "DerivedPath"
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-type-setitem-assignment-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_operator_setitem_finding(report)
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_encoded_nested_probe_limit_fails_closed_after_decoys() -> None:
    literal = _encoded_probe_limit_decoy_literal()
    payload = b"\x80\x04" + _binunicode(literal.encode()) + b"."

    report = scan_bytes(
        payload,
        source="encoded-nested-probe-limit.pkl",
        options=ScanOptions(max_nested_pickle_bytes=16),
    )

    assert report.status == ScanStatus.INCONCLUSIVE
    assert report.verdict == SafetyVerdict.MALICIOUS
    finding = next(finding for finding in report.findings if finding.rule_code == "S601")
    assert finding.severity == Severity.CRITICAL
    assert finding.details["encoding"] == "base64"
    assert finding.details["max_nested_payload_probes"] == 64
    assert finding.details["analysis_incomplete"] is True
    assert any(notice.code == "nested_probe_limit" for notice in report.notices)


def test_scan_bytes_blocks_builtins_staticmethod_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_staticmethod_descriptor_rce_marker"
    control_payload = _builtins_staticmethod_descriptor_payload(marker, include_call=False)
    payload = _builtins_staticmethod_descriptor_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-staticmethod-descriptor-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_staticmethod_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert isinstance(control_result, staticmethod)
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-staticmethod-descriptor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_staticmethod_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_builtins_property_get_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_property_get_descriptor_rce_marker"
    control_payload = _builtins_property_get_descriptor_payload(marker, include_call=False)
    payload = _builtins_property_get_descriptor_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-property-get-descriptor-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert isinstance(control_result, property)
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-property-get-descriptor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_property_get_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_builtins_classmethod_get_descriptor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_classmethod_get_descriptor_rce_marker"
    control_payload = _builtins_classmethod_get_descriptor_payload(marker, include_call=False)
    payload = _builtins_classmethod_get_descriptor_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="builtins-classmethod-get-descriptor-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_classmethod_get_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__name__ == "method"
    assert control_result.__self__ == marker
    assert not marker.exists()

    report = scan_bytes(payload, source="builtins-classmethod-get-descriptor-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_classmethod_get_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_private_functools_partial_rce(tmp_path: Path) -> None:
    marker = tmp_path / "private_functools_partial_rce_marker"
    control_payload = _private_functools_partial_payload(marker, include_call=False)
    payload = _private_functools_partial_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="private-functools-partial-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_private_functools_partial_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert type(control_result).__module__ == "functools"
    assert type(control_result).__name__ == "partial"
    assert not marker.exists()

    report = scan_bytes(payload, source="private-functools-partial-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_private_functools_partial_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_private_functools_reduce_rce(tmp_path: Path) -> None:
    marker = tmp_path / "private_functools_reduce_rce_marker"
    control_payload = _private_functools_reduce_payload(marker, include_call=False)
    payload = _private_functools_reduce_payload(marker, include_call=True)

    control_report = scan_bytes(control_payload, source="private-functools-reduce-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_private_functools_reduce_finding(control_report)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert isinstance(control_result, tuple)
    assert len(control_result) == 3
    assert not marker.exists()

    report = scan_bytes(payload, source="private-functools-reduce-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_private_functools_reduce_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


@pytest.mark.parametrize("factory_name", ["cache", "lru_cache", "singledispatch"])
def test_scan_bytes_blocks_functools_callable_wrapper_rce(tmp_path: Path, factory_name: str) -> None:
    marker = tmp_path / f"functools_{factory_name}_callable_wrapper_rce_marker"
    control_payload = _functools_callable_wrapper_payload(
        marker,
        factory_name.encode(),
        include_call=False,
    )
    payload = _functools_callable_wrapper_payload(
        marker,
        factory_name.encode(),
        include_call=True,
    )

    control_report = scan_bytes(control_payload, source=f"functools-{factory_name}-wrapper-control.pkl")
    assert control_report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_functools_wrapper_finding(control_report, factory_name)

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert callable(control_result)
    assert not marker.exists()

    report = scan_bytes(payload, source=f"functools-{factory_name}-wrapper-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_functools_wrapper_finding(report, factory_name)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_unittest_mock_side_effect_rce(tmp_path: Path) -> None:
    marker = tmp_path / "unittest_mock_side_effect_rce_marker"
    payload = _unittest_mock_side_effect_payload(marker)

    report = scan_bytes(payload, source="unittest-mock-side-effect-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_unittest_mock_finding(report, "Mock")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_threadpool_executor_submitted_callback_rce(tmp_path: Path) -> None:
    marker = tmp_path / "threadpool_executor_submitted_callback_rce_marker"
    payload = _threadpool_executor_submit_payload(marker)

    report = scan_bytes(payload, source="threadpool-executor-submit-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_concurrent_futures_finding(report, "ThreadPoolExecutor.submit")
    assert _has_critical_concurrent_futures_finding(report, "ThreadPoolExecutor.shutdown")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_processpool_executor_submitted_callback_rce(tmp_path: Path) -> None:
    try:
        import concurrent.futures

        executor = concurrent.futures.ProcessPoolExecutor(max_workers=1)
    except (OSError, PermissionError) as exc:
        pytest.skip(f"ProcessPoolExecutor is unavailable: {exc}")
    else:
        executor.shutdown(wait=True, cancel_futures=True)

    marker = tmp_path / "processpool_executor_submitted_callback_rce_marker"
    payload = _processpool_executor_submit_payload(marker)

    report = scan_bytes(payload, source="processpool-executor-submit-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_concurrent_futures_finding(report, "ProcessPoolExecutor.submit")
    assert _has_critical_concurrent_futures_finding(report, "ProcessPoolExecutor.shutdown")

    script_path = tmp_path / "run_processpool_payload.py"
    script_path.write_text(
        "import pickle\n"
        f"PAYLOAD = bytes.fromhex({payload.hex()!r})\n"
        "if __name__ == '__main__':\n"
        "    assert pickle.loads(PAYLOAD) is None\n"
    )

    assert not marker.exists()
    subprocess.run(
        [sys.executable, str(script_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert marker.exists()


def test_scan_bytes_blocks_site_addsitedir_pth_execution_rce(tmp_path: Path) -> None:
    marker = tmp_path / "site_addsitedir_pth_execution_rce_marker"
    pth_path = tmp_path / "site_addsitedir_exec.pth"
    control_payload = _site_addsitedir_pth_payload(
        pth_path,
        marker,
        include_addsitedir=False,
    )
    payload = _site_addsitedir_pth_payload(pth_path, marker, include_addsitedir=True)
    original_sys_path = list(sys.path)

    try:
        control_report = scan_bytes(control_payload, source="site-addsitedir-pth-control.pkl")
        assert control_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(control_report, "pathlib", "Path.write_text")

        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert isinstance(control_result, int)
        assert pth_path.exists()
        assert not marker.exists()

        pth_path.unlink()

        report = scan_bytes(payload, source="site-addsitedir-pth-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_site_finding(report, "addsitedir")

        result = pickle.loads(payload)
        assert result is None
        assert marker.exists()
    finally:
        sys.path[:] = original_sys_path


def test_scan_bytes_blocks_unittest_loader_discover_import_execution_rce(tmp_path: Path) -> None:
    marker = tmp_path / "unittest_loader_discover_import_execution_rce_marker"
    module_path = tmp_path / "ma_unittest_loader_discover_exec.py"
    module_name = module_path.stem
    control_payload = _unittest_loader_discover_payload(
        module_path,
        marker,
        include_discover=False,
    )
    payload = _unittest_loader_discover_payload(module_path, marker, include_discover=True)
    original_sys_path = list(sys.path)

    try:
        sys.modules.pop(module_name, None)
        control_report = scan_bytes(control_payload, source="unittest-loader-discover-control.pkl")
        assert control_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(control_report, "pathlib", "Path.write_text")

        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert isinstance(control_result, int)
        assert module_path.exists()
        assert not marker.exists()

        module_path.unlink()
        sys.modules.pop(module_name, None)

        report = scan_bytes(payload, source="unittest-loader-discover-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_unittest_loader_finding(report, "TestLoader.discover")

        result = pickle.loads(payload)
        assert type(result).__module__ == "unittest.suite"
        assert type(result).__name__ == "TestSuite"
        assert marker.exists()
    finally:
        sys.path[:] = original_sys_path
        sys.modules.pop(module_name, None)


def test_scan_bytes_blocks_unittest_mock_patch_start_import_execution_rce(tmp_path: Path) -> None:
    marker = tmp_path / "unittest_mock_patch_start_import_execution_rce_marker"
    module_path = tmp_path / "ma_unittest_mock_patch_exec.py"
    module_name = module_path.stem
    control_payload = _unittest_mock_patch_start_payload(
        module_path,
        marker,
        include_start=False,
    )
    payload = _unittest_mock_patch_start_payload(module_path, marker, include_start=True)
    original_sys_path = list(sys.path)

    try:
        sys.path.insert(0, str(tmp_path))
        sys.modules.pop(module_name, None)
        control_report = scan_bytes(control_payload, source="unittest-mock-patch-start-control.pkl")
        assert control_report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_global_finding(control_report, "pathlib", "Path.write_text")

        assert not marker.exists()
        control_result = pickle.loads(control_payload)
        assert isinstance(control_result, int)
        assert module_path.exists()
        assert not marker.exists()

        module_path.unlink()
        sys.modules.pop(module_name, None)

        report = scan_bytes(payload, source="unittest-mock-patch-start-rce.pkl")

        assert report.verdict == SafetyVerdict.MALICIOUS
        assert _has_critical_unittest_mock_finding(report, "patch")
        assert _has_critical_unittest_mock_finding(report, "_patch.start")

        result = pickle.loads(payload)
        assert result == 2
        assert marker.exists()
    finally:
        sys.path[:] = original_sys_path
        sys.modules.pop(module_name, None)

        import unittest.mock as mock

        mock.patch.stopall()


def test_scan_bytes_blocks_dataclasses_create_fn_default_arg_rce(tmp_path: Path) -> None:
    if "_create_fn" not in dataclasses.__dict__:
        pytest.skip("dataclasses._create_fn is unavailable")

    marker = tmp_path / "dataclasses_create_fn_rce_marker"

    class DataclassesCreateFnRce:
        def __reduce__(self) -> tuple[object, tuple[object, ...]]:
            create_fn = dataclasses.__dict__["_create_fn"]
            return (
                create_fn,
                (
                    "x",
                    [f"a=open({str(marker)!r}, 'w').write('x')"],
                    ["return int"],
                ),
            )

    payload = pickle.dumps(DataclassesCreateFnRce(), protocol=4)

    report = scan_bytes(payload, source="dataclasses-create-fn-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_dataclasses_create_fn_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result.__name__ == "x"
    assert marker.read_text() == "x"


@pytest.mark.skipif(sys.platform == "win32", reason="pipes.Template proof uses POSIX shell and /dev/null")
def test_scan_bytes_blocks_pipes_template_copy_pipeline_rce(tmp_path: Path) -> None:
    try:
        import pipes
    except Exception as error:
        pytest.skip(f"pipes is unavailable: {error!s}")

    marker = tmp_path / "pipes_template_copy_rce_marker"
    output = tmp_path / "pipes_template_copy_output"

    class PipesTemplateCopyRce:
        def __reduce__(self) -> tuple[object, tuple[object, ...]]:
            template = pipes.Template()
            template.append(f"touch {shlex.quote(str(marker))}; cat $IN > $OUT", "ff")
            return (pipes.Template.copy, (template, "/dev/null", str(output)))

    payload = pickle.dumps(PipesTemplateCopyRce(), protocol=4)

    report = scan_bytes(payload, source="pipes-template-copy-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_pipes_template_copy_finding(report)

    assert not marker.exists()
    pickle.loads(payload)
    assert marker.exists()
    assert output.exists()


def test_scan_bytes_blocks_operator_call_public_alias_rce(tmp_path: Path) -> None:
    marker = tmp_path / "operator_call_rce_marker"
    payload = _operator_call_payload(marker)

    report = scan_bytes(payload, source="operator-call-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_operator_call_finding(report)

    import operator

    if not hasattr(operator, "call"):
        return

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


def test_scan_bytes_blocks_builtins_map_forced_iteration_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_map_tuple_rce_marker"
    payload = _builtins_map_tuple_payload(marker)

    report = scan_bytes(payload, source="builtins-map-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_map_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == (None,)
    assert marker.exists()


def test_scan_bytes_blocks_builtins_filter_forced_iteration_rce(tmp_path: Path) -> None:
    marker = tmp_path / "builtins_filter_tuple_rce_marker"
    payload = _builtins_filter_tuple_payload(marker)

    report = scan_bytes(payload, source="builtins-filter-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_builtins_filter_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == ()
    assert marker.exists()


def test_scan_bytes_blocks_itertools_accumulate_binary_function_rce(tmp_path: Path) -> None:
    marker = tmp_path / "itertools_accumulate_tuple_rce_marker"
    payload = _itertools_accumulate_tuple_payload(marker)

    report = scan_bytes(payload, source="itertools-accumulate-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_itertools_accumulate_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == (marker, 1)
    assert marker.read_text() == "x"


def test_scan_bytes_blocks_itertools_dropwhile_forced_iteration_rce(tmp_path: Path) -> None:
    marker = tmp_path / "itertools_dropwhile_tuple_rce_marker"
    payload = _itertools_dropwhile_tuple_payload(marker)

    report = scan_bytes(payload, source="itertools-dropwhile-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_itertools_dropwhile_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == (marker,)
    assert marker.exists()


def test_scan_bytes_blocks_itertools_filterfalse_forced_iteration_rce(tmp_path: Path) -> None:
    marker = tmp_path / "itertools_filterfalse_tuple_rce_marker"
    payload = _itertools_filterfalse_tuple_payload(marker)

    report = scan_bytes(payload, source="itertools-filterfalse-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_itertools_filterfalse_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == (marker,)
    assert marker.exists()


def test_scan_bytes_blocks_itertools_groupby_key_function_rce(tmp_path: Path) -> None:
    marker = tmp_path / "itertools_groupby_tuple_rce_marker"
    payload = _itertools_groupby_tuple_payload(marker)

    report = scan_bytes(payload, source="itertools-groupby-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_itertools_groupby_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert len(result) == 1
    group_key, group_iter = result[0]
    assert group_key is None
    assert type(group_iter).__name__ == "_grouper"
    assert marker.exists()


def test_scan_bytes_blocks_itertools_starmap_forced_iteration_rce(tmp_path: Path) -> None:
    marker = tmp_path / "itertools_starmap_tuple_rce_marker"
    payload = _itertools_starmap_tuple_payload(marker)

    report = scan_bytes(payload, source="itertools-starmap-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_itertools_starmap_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == (None,)
    assert marker.exists()


def test_scan_bytes_blocks_itertools_takewhile_forced_iteration_rce(tmp_path: Path) -> None:
    marker = tmp_path / "itertools_takewhile_tuple_rce_marker"
    payload = _itertools_takewhile_tuple_payload(marker)

    report = scan_bytes(payload, source="itertools-takewhile-tuple-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_itertools_takewhile_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == ()
    assert marker.exists()


def test_scan_bytes_blocks_typing_eval_type_forward_ref_rce(tmp_path: Path) -> None:
    marker = tmp_path / "typing_eval_type_forward_ref_rce_marker"
    payload = _typing_eval_type_forward_ref_payload(marker)

    report = scan_bytes(payload, source="typing-eval-type-forward-ref-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_typing_eval_type_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is int
    assert marker.exists()


def test_scan_bytes_blocks_typing_get_type_hints_annotation_rce(tmp_path: Path) -> None:
    marker = tmp_path / "typing_get_type_hints_rce_marker"
    payload = _typing_get_type_hints_payload(marker)

    report = scan_bytes(payload, source="typing-get-type-hints-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_typing_get_type_hints_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == {"x": int}
    assert marker.exists()


def test_scan_bytes_blocks_setuptools_distutils_spawn_rce(tmp_path: Path) -> None:
    try:
        import setuptools._distutils.spawn as dist_spawn
    except Exception as error:
        pytest.skip(f"setuptools._distutils.spawn is unavailable: {error!s}")

    touch_path = shutil.which("touch")
    if touch_path is None:
        pytest.skip("touch command is unavailable")

    marker = tmp_path / "setuptools_distutils_spawn_rce_marker"

    class SetuptoolsDistutilsSpawnRce:
        def __reduce__(self) -> tuple[object, tuple[object, ...]]:
            return (dist_spawn.spawn, ([touch_path, str(marker)],))

    payload = pickle.dumps(SetuptoolsDistutilsSpawnRce(), protocol=4)

    report = scan_bytes(payload, source="setuptools-distutils-spawn-rce.pkl")

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_setuptools_distutils_spawn_finding(report)

    assert not marker.exists()
    pickle.loads(payload)
    assert marker.exists()
