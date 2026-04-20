"""Focused call-graph regressions for function-local import aliases."""

from __future__ import annotations

import pickle
import shlex
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest

from modelaudit_picklescan import PickleReport, SafetyVerdict, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import _calls_for_function, _find_sink_path

pytestmark = [
    pytest.mark.skipif(
        find_spec(_RUST_EXTENSION_MODULE) is None,
        reason="Rust picklescan extension is not built",
    ),
    pytest.mark.skipif(
        find_spec("_pytest._py.path") is None,
        reason="_pytest._py.path is unavailable",
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


def _shell_command(marker: Path, marker_content: str) -> str:
    return f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}"


def _pytest_localpath_payload(executable: str) -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _global_operand("_pytest._py.path", "LocalPath"),
            _tuple_payload_operands([_text_operand(executable)]),
            b"R.",
        ]
    )


def _pytest_localpath_sysexec_payload(marker: Path) -> tuple[bytes, str]:
    marker_content = "owned-by-pytest-localpath-sysexec"
    command = _shell_command(marker, marker_content)
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("_pytest._py.path", "LocalPath"),
            _tuple_payload_operands([_text_operand("/bin/sh")]),
            b"R\x94",
            _global_operand("_pytest._py.path", "LocalPath.sysexec"),
            _tuple_payload_operands([b"h\x00", _text_operand("-c"), _text_operand(command)]),
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


def test_call_graph_resolves_function_local_import_aliases() -> None:
    assert "subprocess.Popen" in (_calls_for_function("_pytest._py.path.LocalPath.sysexec") or ())
    assert _find_sink_path("_pytest._py.path.LocalPath.sysexec") == (
        "_pytest._py.path.LocalPath.sysexec",
        "subprocess.Popen",
    )


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell redirection")
def test_scan_bytes_blocks_pytest_localpath_sysexec_rce(tmp_path: Path) -> None:
    marker = tmp_path / "pytest_localpath_sysexec_rce_marker"
    control_payload = _pytest_localpath_payload("/bin/sh")
    payload, marker_content = _pytest_localpath_sysexec_payload(marker)

    control_report = scan_bytes(control_payload, source="pytest-localpath-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert str(control_result) == "/bin/sh"
    assert not marker.exists()

    report = scan_bytes(payload, source="pytest-localpath-sysexec-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "_pytest._py.path",
        "LocalPath.sysexec",
        "subprocess.Popen",
    )

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == ""
    assert marker.read_text() == marker_content
