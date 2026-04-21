"""Focused call-graph regressions for tkinter Tcl dispatch surfaces."""

from __future__ import annotations

import pickle
import shlex
import sys
from collections.abc import Callable
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import _find_sink_path

pytestmark = pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None,
    reason="Rust picklescan extension is not built",
)


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


def _shell_command(marker: Path, marker_content: str) -> str:
    return f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}"


def _command_tuple(command: str) -> bytes:
    return _tuple_payload_operands(
        [
            _text_operand("exec"),
            _text_operand("/bin/sh"),
            _text_operand("-c"),
            _text_operand(command),
        ]
    )


def _tkinter_misc_unbind_payload(marker: Path, *, include_call: bool) -> tuple[bytes, str]:
    marker_content = "owned-by-tkinter-misc-unbind"
    command = _shell_command(marker, marker_content)
    command_tuple = _command_tuple(command)
    if not include_call:
        return b"\x80\x04" + command_tuple + b".", marker_content

    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("tkinter", "Tcl"),
            b")R\x94",
            _global_operand("tkinter", "Misc._unbind"),
            _tuple_payload_operands([b"h\x00", command_tuple]),
            b"R.",
        ]
    )
    return payload, marker_content


def _tkinter_misc_getconfigure_payload(marker: Path, *, include_call: bool) -> tuple[bytes, str]:
    marker_content = "owned-by-tkinter-misc-getconfigure"
    command = _shell_command(marker, marker_content)
    if not include_call:
        return b"\x80\x04" + _command_tuple(command) + b".", marker_content

    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("tkinter", "Tcl"),
            b")R\x94",
            _global_operand("tkinter", "Misc._getconfigure"),
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
    return payload, marker_content


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


def test_call_graph_marks_parameter_controlled_tcl_dispatchers() -> None:
    unbind_path = _find_sink_path("tkinter.Misc._unbind")
    if unbind_path is not None:
        assert unbind_path == ("tkinter.Misc._unbind", "tkinter.Misc.tk.call")
    getconfigure_path = _find_sink_path("tkinter.Misc._getconfigure")
    if getconfigure_path is None and find_spec("_tkinter") is None:
        pytest.skip("tkinter runtime/source is unavailable")
    assert getconfigure_path == (
        "tkinter.Misc._getconfigure",
        "tkinter.Misc.tk.call",
    )
    assert _find_sink_path("tkinter.Misc._getconfigure1") == (
        "tkinter.Misc._getconfigure1",
        "tkinter.Misc.tk.call",
    )


def test_call_graph_ignores_fixed_tk_widget_dispatchers() -> None:
    assert _find_sink_path("tkinter.Misc._configure") is None
    assert _find_sink_path("tkinter.Misc.grid_bbox") is None
    assert _find_sink_path("tkinter.Canvas.delete") is None


@pytest.mark.skipif(find_spec("_tkinter") is None, reason="_tkinter is unavailable")
@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell redirection")
@pytest.mark.parametrize(
    ("method_name", "payload_builder", "expected_result"),
    [
        ("Misc._unbind", _tkinter_misc_unbind_payload, None),
        ("Misc._getconfigure", _tkinter_misc_getconfigure_payload, {}),
    ],
)
def test_scan_bytes_blocks_tkinter_misc_tcl_dispatch_rce(
    tmp_path: Path,
    method_name: str,
    payload_builder: Callable[..., tuple[bytes, str]],
    expected_result: object,
) -> None:
    marker = tmp_path / f"tkinter_{method_name.rsplit('.', 1)[1]}_rce_marker"
    control_payload, _ = payload_builder(marker, include_call=False)
    payload, marker_content = payload_builder(marker, include_call=True)

    control_report = scan_bytes(control_payload, source=f"tkinter-{method_name}-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert isinstance(control_result, tuple)
    assert control_result[0] == "exec"
    assert not marker.exists()

    report = scan_bytes(payload, source=f"tkinter-{method_name}-rce.pkl")

    if method_name == "Misc._unbind" and _find_sink_path("tkinter.Misc._unbind") is None:
        return

    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "tkinter", method_name, "tkinter.Misc.tk.call")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == expected_result
    assert marker.read_text() == marker_content
