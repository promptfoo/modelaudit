"""Adversarial pickle corpus checked against CPython execution semantics."""

from __future__ import annotations

import dataclasses
import pickle
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, ScanOptions, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE

pytestmark = pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None,
    reason="Rust picklescan extension is not built",
)

OperandBuilder = Callable[[bytes], bytes]
MemoOpcodeBuilder = Callable[[int], bytes]


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


def _text_operand(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return _short_binunicode(data)
    return _binunicode(data)


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
    assert control_report.verdict == SafetyVerdict.CLEAN

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

    assert report.verdict == SafetyVerdict.SUSPICIOUS
    assert _has_suspicious_magic_method_finding(report)

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result is None
    assert marker.exists()


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
        assert control_report.verdict == SafetyVerdict.CLEAN

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
        assert control_report.verdict == SafetyVerdict.CLEAN

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
        assert control_report.verdict == SafetyVerdict.CLEAN

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
