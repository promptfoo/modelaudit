"""Focused call-graph regressions for six.moves compatibility aliases."""

from __future__ import annotations

import pickle
import shlex
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import _call_graph_entrypoints, _find_sink_path, _trusted_module_origin_kind


def _has_module(module: str) -> bool:
    try:
        return find_spec(module) is not None
    except ModuleNotFoundError:
        return False


pytestmark = [
    pytest.mark.skipif(
        not _has_module(_RUST_EXTENSION_MODULE),
        reason="Rust picklescan extension is not built",
    ),
    pytest.mark.skipif(
        not _has_module("six"),
        reason="six is unavailable",
    ),
]


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


def _global_operand(module: str, name: str) -> bytes:
    return _text_operand(module) + _text_operand(name) + b"\x93"


def _tuple_payload_operands(operands: list[bytes]) -> bytes:
    return b"(" + b"".join(operands) + b"t"


def _six_moves_getoutput_payload(module: str, name: str, marker: Path) -> tuple[bytes, str]:
    marker_content = "owned-by-six-moves-getoutput"
    command = f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}"
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand(module, name),
            _tuple_payload_operands([_text_operand(command)]),
            b"R.",
        ]
    )
    return payload, marker_content


def _int_list_operand(values: bytes) -> bytes:
    return b"](" + b"".join(b"K" + bytes([value]) for value in values) + b"e"


def _constructed_bytes_operand(values: bytes) -> bytes:
    return b"".join(
        [
            _global_operand("builtins", "bytes"),
            _tuple_payload_operands([_int_list_operand(values)]),
            b"R",
        ]
    )


def _posix_system_payload(command: str) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("posix", "system"),
            _tuple_payload_operands([_text_operand(command)]),
            b"R.",
        ]
    )


def _six_moves_cpickle_loads_payload(module: str, name: str, marker: Path) -> tuple[bytes, bytes, str]:
    marker_content = "owned-by-six-cpickle-int-list"
    command = f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}"
    inner_payload = _posix_system_payload(command)
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand(module, name),
            _tuple_payload_operands([_constructed_bytes_operand(inner_payload)]),
            b"R.",
        ]
    )
    return payload, inner_payload, marker_content


def _six_moves_builtins_eval_payload(module: str, name: str, marker: Path) -> tuple[bytes, str]:
    marker_content = "owned-by-six-moves-builtins-eval"
    expression = f"open({str(marker)!r}, 'w').write({marker_content!r})"
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand(module, name),
            _tuple_payload_operands([_text_operand(expression)]),
            b"R.",
        ]
    )
    return payload, marker_content


def _control_payload(command: str) -> bytes:
    return b"\x80\x04" + _text_operand(command) + b"."


def _constructed_bytes_control_payload(values: bytes) -> bytes:
    return b"\x80\x04" + _constructed_bytes_operand(values) + b"."


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


def _assert_pickle_payload_executes_in_subprocess(
    payload: bytes,
    marker: Path,
    marker_content: str,
    tmp_path: Path,
    *,
    expected_result: object,
) -> None:
    payload_path = tmp_path / "payload.pkl"
    payload_path.write_bytes(payload)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import pathlib, pickle, sys; "
                "result = pickle.loads(pathlib.Path(sys.argv[1]).read_bytes()); "
                "print(repr(result))"
            ),
            str(payload_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == repr(expected_result)
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    "reference",
    [
        "six.moves.getoutput",
        "botocore.vendored.six.moves.getoutput",
    ],
)
def test_call_graph_resolves_six_moves_getoutput_alias(reference: str) -> None:
    assert _call_graph_entrypoints(reference) == ("subprocess.getoutput",)

    path = _find_sink_path(reference)
    assert path is not None
    assert path[-2:] == ("subprocess.getstatusoutput", "subprocess.check_output")


@pytest.mark.parametrize(
    ("reference", "sink"),
    [
        ("six.moves.cPickle.load", "pickle.load"),
        ("six.moves.cPickle.loads", "pickle.loads"),
        ("botocore.vendored.six.moves.cPickle.load", "pickle.load"),
        ("botocore.vendored.six.moves.cPickle.loads", "pickle.loads"),
    ],
)
def test_call_graph_resolves_six_moves_cpickle_aliases(reference: str, sink: str) -> None:
    assert _call_graph_entrypoints(reference) == (sink,)

    path = _find_sink_path(reference)
    assert path is not None
    assert path[-1] == sink


@pytest.mark.parametrize(
    ("reference", "sink"),
    [
        ("six.moves.builtins.__import__", "builtins.__import__"),
        ("six.moves.builtins.compile", "builtins.compile"),
        ("six.moves.builtins.eval", "builtins.eval"),
        ("six.moves.builtins.exec", "builtins.exec"),
        ("botocore.vendored.six.moves.builtins.__import__", "builtins.__import__"),
        ("botocore.vendored.six.moves.builtins.compile", "builtins.compile"),
        ("botocore.vendored.six.moves.builtins.eval", "builtins.eval"),
        ("botocore.vendored.six.moves.builtins.exec", "builtins.exec"),
    ],
)
def test_call_graph_resolves_six_moves_builtins_dangerous_aliases(reference: str, sink: str) -> None:
    assert _call_graph_entrypoints(reference) == (sink,)

    path = _find_sink_path(reference)
    assert path is not None
    assert path[-1] == sink


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("six.moves", "getoutput"),
        ("six", "moves.getoutput"),
        ("botocore.vendored.six.moves", "getoutput"),
        ("botocore.vendored.six", "moves.getoutput"),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_six_moves_getoutput_rce(module: str, name: str, tmp_path: Path) -> None:
    marker = tmp_path / f"{module.replace('.', '_')}_{name.replace('.', '_')}_rce_marker"
    payload, marker_content = _six_moves_getoutput_payload(module, name, marker)
    command = f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}"
    control_payload = _control_payload(command)

    control_report = scan_bytes(control_payload, source="six-moves-getoutput-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    assert pickle.loads(control_payload) == command
    assert not marker.exists()

    report = scan_bytes(payload, source="six-moves-getoutput-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module, name, "subprocess.check_output")

    if module.startswith("botocore.") and not _has_module("botocore.vendored.six"):
        return

    assert not marker.exists()
    assert pickle.loads(payload) == ""
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("six.moves.cPickle", "loads"),
        ("six.moves", "cPickle.loads"),
        ("botocore.vendored.six.moves.cPickle", "loads"),
        ("botocore.vendored.six.moves", "cPickle.loads"),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_six_moves_cpickle_loads_constructed_bytes_rce(
    module: str,
    name: str,
    tmp_path: Path,
) -> None:
    marker = tmp_path / f"{module.replace('.', '_')}_{name.replace('.', '_')}_rce_marker"
    payload, inner_payload, marker_content = _six_moves_cpickle_loads_payload(module, name, marker)
    control_payload = _constructed_bytes_control_payload(inner_payload)

    control_report = scan_bytes(control_payload, source="six-moves-cpickle-loads-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    assert pickle.loads(control_payload) == inner_payload
    assert not marker.exists()

    report = scan_bytes(payload, source="six-moves-cpickle-loads-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module, name, "pickle.loads")

    if module.startswith("botocore.") and not _has_module("botocore.vendored.six"):
        return

    assert not marker.exists()
    assert pickle.loads(payload) == 0
    assert marker.read_text() == marker_content


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("six.moves.builtins", "eval"),
        ("botocore.vendored.six.moves.builtins", "eval"),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_six_moves_builtins_eval_rce(module: str, name: str, tmp_path: Path) -> None:
    marker = tmp_path / f"{module.replace('.', '_')}_{name.replace('.', '_')}_rce_marker"
    payload, marker_content = _six_moves_builtins_eval_payload(module, name, marker)
    expression = f"open({str(marker)!r}, 'w').write({marker_content!r})"
    control_payload = _control_payload(expression)

    control_report = scan_bytes(control_payload, source="six-moves-builtins-eval-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    assert pickle.loads(control_payload) == expression
    assert not marker.exists()

    report = scan_bytes(payload, source="six-moves-builtins-eval-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, module, name, "builtins.eval")

    if module.startswith("botocore.") and not _has_module("botocore.vendored.six"):
        return

    assert not marker.exists()
    _assert_pickle_payload_executes_in_subprocess(
        payload,
        marker,
        marker_content,
        tmp_path,
        expected_result=len(marker_content),
    )
    _trusted_module_origin_kind.cache_clear()
    assert _trusted_module_origin_kind("builtins") == "stdlib"
