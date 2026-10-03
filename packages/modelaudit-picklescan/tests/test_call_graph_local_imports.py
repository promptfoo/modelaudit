"""Focused call-graph regressions for function-local import aliases."""

from __future__ import annotations

import pickle
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest
from pickle_test_helpers import (
    _global_operand,
    _has_critical_call_graph_finding,
    _shell_command,
    _text_operand,
    _tuple_payload_operands,
)

from modelaudit_picklescan import SafetyVerdict, scan_bytes
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
