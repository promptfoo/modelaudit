"""Focused call-graph regressions for six.moves compatibility aliases."""

from __future__ import annotations

import pickle
import shlex
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import _call_graph_entrypoints, _find_sink_path

pytestmark = [
    pytest.mark.skipif(
        find_spec(_RUST_EXTENSION_MODULE) is None,
        reason="Rust picklescan extension is not built",
    ),
    pytest.mark.skipif(
        find_spec("six") is None,
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


def _control_payload(command: str) -> bytes:
    return b"\x80\x04" + _text_operand(command) + b"."


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


def test_call_graph_resolves_six_moves_getoutput_alias() -> None:
    assert _call_graph_entrypoints("six.moves.getoutput") == ("subprocess.getoutput",)

    path = _find_sink_path("six.moves.getoutput")
    assert path is not None
    assert path[-2:] == ("subprocess.getstatusoutput", "subprocess.check_output")


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("six.moves", "getoutput"),
        ("six", "moves.getoutput"),
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

    assert not marker.exists()
    assert pickle.loads(payload) == ""
    assert marker.read_text() == marker_content
