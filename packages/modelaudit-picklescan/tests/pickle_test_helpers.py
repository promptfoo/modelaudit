"""Shared pickle encoders and finding assertions for standalone package tests."""

import shlex
from importlib.util import find_spec
from pathlib import Path

from framework_fixtures import (
    _short_binunicode,
)

from modelaudit_picklescan import PickleReport, Severity, call_graph


def _has_critical_call_graph_finding(report: PickleReport, module: str, name: str, sink: str) -> bool:
    return any(
        finding.severity == Severity.CRITICAL
        and finding.rule_code == "DANGEROUS_CALL_GRAPH"
        and finding.details.get("module") == module
        and finding.details.get("name") == name
        and finding.details.get("sink") == sink
        for finding in report.findings
    )


def _text_operand(value: str) -> bytes:
    data = value.encode()
    if len(data) <= 0xFF:
        return _short_binunicode(data)
    return _binunicode(data)


def _binunicode(data: bytes) -> bytes:
    return b"X" + len(data).to_bytes(4, "little") + data


def _global_operand(module: str, name: str) -> bytes:
    return _text_operand(module) + _text_operand(name) + b"\x93"


def _tuple_payload_operands(operands: list[bytes]) -> bytes:
    return b"(" + b"".join(operands) + b"t"


def _proto0_string_literal(value: bytes) -> bytes:
    literal = value.decode("latin-1").encode("unicode_escape").replace(b"'", b"\\'")
    return b"S'" + literal + b"'\n."


def _binunicode8(data: bytes) -> bytes:
    return b"\x8d" + len(data).to_bytes(8, "little") + data


def _clear_call_graph_caches() -> None:
    for function in call_graph._SOURCE_SENSITIVE_CACHED_FUNCTIONS:
        function.cache_clear()


def _shell_command(marker: Path, marker_content: str) -> str:
    return f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}"


def _bytes_operand(data: bytes) -> bytes:
    if len(data) <= 0xFF:
        return b"C" + bytes([len(data)]) + data
    return b"B" + len(data).to_bytes(4, "little") + data


def _has_module(module: str) -> bool:
    try:
        return find_spec(module) is not None
    except ModuleNotFoundError:
        return False
