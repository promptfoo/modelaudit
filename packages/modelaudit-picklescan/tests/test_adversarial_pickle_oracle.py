"""Adversarial pickle corpus checked against CPython execution semantics."""

from __future__ import annotations

import dataclasses
import pickle
import shlex
import shutil
import subprocess
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


def _has_critical_itertools_dropwhile_finding(report: PickleReport) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.details.get("module") == "itertools"
        and finding.details.get("name") == "dropwhile"
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
