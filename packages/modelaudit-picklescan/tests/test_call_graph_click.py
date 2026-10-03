"""Focused call-graph regressions for function-local class instance aliases."""

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
from modelaudit_picklescan.call_graph import _calls_for_function, _find_sink_path

pytestmark = [
    pytest.mark.skipif(
        find_spec(_RUST_EXTENSION_MODULE) is None,
        reason="Rust picklescan extension is not built",
    ),
    pytest.mark.skipif(
        find_spec("click") is None,
        reason="click is unavailable",
    ),
]


def _click_editor(marker: Path, marker_content: str) -> str:
    command = f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))} #"
    return f"/bin/sh -c {shlex.quote(command)}"


def _click_edit_control_payload(editor: str) -> bytes:
    return b"\x80\x04" + _text_operand(editor) + b"."


def _click_edit_payload(marker: Path) -> tuple[bytes, str, str]:
    marker_content = "owned-by-click-edit"
    editor = _click_editor(marker, marker_content)
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("click", "edit"),
            _tuple_payload_operands(
                [
                    _text_operand("seed"),
                    _text_operand(editor),
                    b"N",
                    b"\x89",
                ]
            ),
            b"R.",
        ]
    )
    return payload, marker_content, editor


def test_call_graph_resolves_function_local_class_instance_aliases() -> None:
    calls = _calls_for_function("click.edit")
    assert calls is not None
    assert "click._termui_impl.Editor.edit" in calls

    path = _find_sink_path("click.edit")
    assert path is not None
    assert path[-3:] == (
        "click._termui_impl.Editor.edit",
        "click._termui_impl.Editor.edit_files",
        "subprocess.Popen",
    )


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell redirection")
def test_scan_bytes_blocks_click_edit_editor_rce(tmp_path: Path) -> None:
    marker = tmp_path / "click_edit_rce_marker"
    payload, marker_content, editor = _click_edit_payload(marker)
    control_payload = _click_edit_control_payload(editor)

    control_report = scan_bytes(control_payload, source="click-edit-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    control_result = pickle.loads(control_payload)
    assert control_result == editor
    assert not marker.exists()

    report = scan_bytes(payload, source="click-edit-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(report, "click", "edit", "subprocess.Popen")

    assert not marker.exists()
    result = pickle.loads(payload)
    assert isinstance(result, str)
    assert result.startswith("seed")
    assert marker.read_text() == marker_content
