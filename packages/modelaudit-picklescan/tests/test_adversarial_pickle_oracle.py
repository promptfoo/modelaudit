"""Adversarial pickle corpus checked against CPython execution semantics."""

from __future__ import annotations

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
