"""Focused call-graph regressions for execnet gateway process dispatch."""

from __future__ import annotations

import pickle
import shlex
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest
from pickle_test_helpers import (
    _global_operand,
    _has_critical_call_graph_finding,
    _text_operand,
    _tuple_payload_operands,
)

from modelaudit_picklescan import SafetyVerdict, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import _call_graph_entrypoints, _find_sink_path

pytestmark = [
    pytest.mark.skipif(
        find_spec(_RUST_EXTENSION_MODULE) is None,
        reason="Rust picklescan extension is not built",
    ),
    pytest.mark.skipif(
        find_spec("execnet") is None,
        reason="execnet is unavailable",
    ),
]


def _execnet_spec(marker: Path, marker_content: str) -> str:
    command = f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))} #"
    return f"popen//python=/bin/sh -c {shlex.quote(command)}"


def _execnet_control_payload(spec: str) -> bytes:
    return b"\x80\x04" + _text_operand(spec) + b"."


def _execnet_makegateway_payload(marker: Path) -> tuple[bytes, str, str]:
    marker_content = "owned-by-execnet-makegateway"
    spec = _execnet_spec(marker, marker_content)
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("execnet", "makegateway"),
            _tuple_payload_operands([_text_operand(spec)]),
            b"R.",
        ]
    )
    return payload, marker_content, spec


def test_call_graph_resolves_execnet_bound_method_process_dispatch() -> None:
    assert _call_graph_entrypoints("execnet.makegateway") == ("execnet.multi.Group.makegateway",)

    path = _find_sink_path("execnet.makegateway")
    assert path is not None
    assert path[-3:] == (
        "execnet.gateway_io.create_io",
        "execnet.gateway_io.Popen2IOMaster.__init__",
        "execmodel.subprocess.Popen",
    )


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_execnet_makegateway_rce(tmp_path: Path) -> None:
    marker = tmp_path / "execnet_makegateway_rce_marker"
    payload, marker_content, spec = _execnet_makegateway_payload(marker)
    control_payload = _execnet_control_payload(spec)

    control_report = scan_bytes(control_payload, source="execnet-makegateway-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == spec
    assert not marker.exists()

    report = scan_bytes(payload, source="execnet-makegateway-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "execnet",
        "makegateway",
        "execmodel.subprocess.Popen",
    )

    assert not marker.exists()
    assert marker_content in spec
