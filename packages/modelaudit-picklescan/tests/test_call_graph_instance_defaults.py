"""Call-graph regressions for constructor-default instance aliases."""

from __future__ import annotations

import pickle
import shlex
import subprocess
import sys
import time
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
        find_spec("botocore") is None,
        reason="botocore is unavailable",
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


def _botocore_process_provider_operand() -> bytes:
    return b"".join(
        [
            _global_operand("botocore.credentials", "ProcessProvider"),
            _tuple_payload_operands(
                [
                    _text_operand("default"),
                    _global_operand("builtins", "dict"),
                ]
            ),
            b"R",
        ]
    )


def _botocore_process_provider_control_payload() -> bytes:
    return b"\x80\x04" + _botocore_process_provider_operand() + b"."


def _botocore_process_provider_rce_payload(marker: Path) -> tuple[bytes, str]:
    marker_content = "owned-by-botocore-process-provider"
    credential_json = '{"Version":1,"AccessKeyId":"A","SecretAccessKey":"S","AccountId":"1"}'
    script = (
        f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}; printf '%s' {shlex.quote(credential_json)}"
    )
    credential_process = f"/bin/sh -c {shlex.quote(script)}"
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("botocore.credentials", "ProcessProvider._retrieve_credentials_using"),
            _tuple_payload_operands(
                [
                    _botocore_process_provider_operand(),
                    _text_operand(credential_process),
                ]
            ),
            b"R.",
        ]
    )
    return payload, marker_content


def _aiobotocore_process_provider_operand() -> bytes:
    return b"".join(
        [
            _global_operand("aiobotocore.credentials", "AioProcessProvider"),
            _tuple_payload_operands(
                [
                    _text_operand("default"),
                    _global_operand("builtins", "dict"),
                ]
            ),
            b"R",
        ]
    )


def _aiobotocore_process_provider_control_payload() -> bytes:
    return b"\x80\x04" + _aiobotocore_process_provider_operand() + b"."


def _aiobotocore_anyio_backend_rce_payload(marker: Path) -> tuple[bytes, str]:
    marker_content = "owned-by-aiobotocore-anyio"
    credential_json = '{"Version":1,"AccessKeyId":"A","SecretAccessKey":"S","AccountId":"1"}'
    script = (
        f"printf {shlex.quote(marker_content)} > {shlex.quote(str(marker))}; printf '%s' {shlex.quote(credential_json)}"
    )
    credential_process = f"/bin/sh -c {shlex.quote(script)}"
    payload = b"".join(
        [
            b"\x80\x04",
            _global_operand("anyio._backends._asyncio", "AsyncIOBackend.run"),
            _tuple_payload_operands(
                [
                    _global_operand("aiobotocore.credentials", "AioProcessProvider._retrieve_credentials_using"),
                    _tuple_payload_operands(
                        [
                            _aiobotocore_process_provider_operand(),
                            _text_operand(credential_process),
                        ]
                    ),
                    b"}",
                    b"}",
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


def test_call_graph_resolves_constructor_default_instance_aliases() -> None:
    calls = _calls_for_function("botocore.credentials.ProcessProvider._retrieve_credentials_using")
    assert calls is not None
    assert "botocore.credentials.ProcessProvider._popen" in calls

    path = _find_sink_path("botocore.credentials.ProcessProvider._retrieve_credentials_using")
    assert path is not None
    assert path[-1] == "subprocess.Popen"


@pytest.mark.skipif(find_spec("aiobotocore") is None, reason="aiobotocore is unavailable")
def test_call_graph_resolves_super_forwarded_constructor_default_instance_aliases() -> None:
    calls = _calls_for_function("aiobotocore.credentials.AioProcessProvider._retrieve_credentials_using")
    assert calls is not None
    assert "aiobotocore.credentials.AioProcessProvider._popen" in calls

    path = _find_sink_path("aiobotocore.credentials.AioProcessProvider._retrieve_credentials_using")
    assert path is not None
    assert path[-1] == "asyncio.create_subprocess_exec"


@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_botocore_process_provider_rce(tmp_path: Path) -> None:
    marker = tmp_path / "botocore_process_provider_rce_marker"
    control_payload = _botocore_process_provider_control_payload()
    payload, marker_content = _botocore_process_provider_rce_payload(marker)

    control_report = scan_bytes(control_payload, source="botocore-process-provider-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    pickle.loads(control_payload)
    assert not marker.exists()

    report = scan_bytes(payload, source="botocore-process-provider-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "botocore.credentials",
        "ProcessProvider._retrieve_credentials_using",
        "subprocess.Popen",
    )

    assert not marker.exists()
    result = pickle.loads(payload)
    assert result == {
        "access_key": "A",
        "secret_key": "S",
        "token": None,
        "expiry_time": None,
        "account_id": "1",
    }
    assert marker.read_text() == marker_content


@pytest.mark.skipif(find_spec("aiobotocore") is None, reason="aiobotocore is unavailable")
@pytest.mark.skipif(find_spec("anyio") is None, reason="anyio is unavailable")
@pytest.mark.skipif(sys.platform == "win32", reason="proof uses POSIX shell")
def test_scan_bytes_blocks_aiobotocore_anyio_backend_rce(tmp_path: Path) -> None:
    marker = tmp_path / "aiobotocore_anyio_backend_rce_marker"
    control_payload = _aiobotocore_process_provider_control_payload()
    payload, marker_content = _aiobotocore_anyio_backend_rce_payload(marker)

    control_report = scan_bytes(control_payload, source="aiobotocore-process-provider-control.pkl")
    assert control_report.verdict == SafetyVerdict.CLEAN

    assert not marker.exists()
    pickle.loads(control_payload)
    assert not marker.exists()

    report = scan_bytes(payload, source="aiobotocore-anyio-backend-rce.pkl")
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert _has_critical_call_graph_finding(
        report,
        "aiobotocore.credentials",
        "AioProcessProvider._retrieve_credentials_using",
        "asyncio.create_subprocess_exec",
    )

    assert not marker.exists()
    proof = subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"import pickle; pickle.loads({payload!r})",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 30
        while not marker.exists() and time.monotonic() < deadline:
            assert proof.poll() is None
            time.sleep(0.1)
        assert marker.read_text() == marker_content
    finally:
        if proof.poll() is None:
            proof.terminate()
            try:
                proof.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proof.kill()
                proof.wait(timeout=5)
