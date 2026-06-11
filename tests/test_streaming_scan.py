"""Tests for streaming scan-and-delete functionality."""

import hashlib
import logging
import os
import pickle
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest

from modelaudit.core import (
    _complete_validated_shard_family_sources,
    _reconcile_cross_directory_shard_coverage,
    _snapshot_validated_shard_target,
    determine_exit_code,
    scan_file,
    scan_model_directory_or_file,
    scan_model_streaming,
)
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.models import FileMetadataModel, LicenseInfoModel, create_initial_audit_result
from modelaudit.scanners import safetensors_scanner
from modelaudit.scanners.base import Issue, IssueSeverity, ScanResult
from modelaudit.utils.file.detection import SAFETENSORS_ROUTING_HEADER_PARSE_BYTES
from modelaudit.utils.helpers.file_iterator import iterate_files_streaming
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash
from tests.helpers import write_mock_pytorch_zip_metadata


class _StreamingMaliciousPicklePayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("__import__('os').system('echo modelaudit-stream-test')",))


def _create_streaming_pytorch_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        write_mock_pytorch_zip_metadata(archive)
        for member_name, payload in members.items():
            archive.writestr(member_name, payload)
    return path


def _streaming_member_record(metadata: dict[str, Any], path_segments: list[str]) -> dict[str, Any]:
    member_hashes = metadata.get("member_file_hashes")
    assert isinstance(member_hashes, dict)
    records = [
        record
        for record in member_hashes.values()
        if isinstance(record, dict) and record.get("path_segments") == path_segments
    ]
    assert len(records) == 1
    return records[0]


@pytest.fixture
def temp_test_files() -> Iterator[list[Path]]:
    """Create temporary test files for streaming."""
    files: list[Path] = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write(f"Test content {i}")
            files.append(Path(tmp.name))
    yield files
    # Cleanup
    for file_path in files:
        if file_path.exists():
            file_path.unlink()


def create_mock_scan_result(bytes_scanned: int = 1024, with_critical_issue: bool = False) -> ScanResult:
    """Create a mock ScanResult for testing."""
    result = ScanResult(scanner_name="test_scanner")
    result.bytes_scanned = bytes_scanned
    result.success = True
    if with_critical_issue:
        result.add_issue("Detected malicious behavior", severity=IssueSeverity.CRITICAL, location="test.pkl")
    return result


def create_mock_location_scan_result(
    resolved_path: Path,
    *,
    issue_suffix: str = ":payload",
    check_suffix: str = " (weights)",
) -> ScanResult:
    """Create a mock result whose locations are anchored to the resolved target."""
    result = ScanResult(scanner_name="test_scanner")
    result.bytes_scanned = 128
    result.add_check(
        name="Suspicious Payload",
        passed=False,
        message="Detected malicious behavior",
        severity=IssueSeverity.CRITICAL,
        location=f"{resolved_path}{issue_suffix}",
    )
    result.add_check(
        name="Layout Inspection",
        passed=True,
        message="Model structure inspected",
        location=f"{resolved_path}{check_suffix}",
    )
    result.finish(success=True)
    return result


def test_scan_model_directory_or_file_streaming_path() -> None:
    """Ensure stream:// paths route to streaming analysis."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 123
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

        args, kwargs = mock_scanner.call_args
        assert args[0] == "/model.pkl"
        assert "config" in kwargs
        mock_stream.assert_called_once_with(stream_url, dummy_scanner)
        assert result.files_scanned == 1
        assert result.bytes_scanned == 123
    assert determine_exit_code(result) == 0


def test_scan_model_directory_or_file_streaming_path_enforces_max_file_size() -> None:
    """The configured file limit must cap the actual remote stream read."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, False)) as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()) as mock_scanner,
    ):
        scan_model_directory_or_file(f"stream://{stream_url}", max_file_size=4096)

    mock_stream.assert_called_once_with(stream_url, mock_scanner.return_value, max_bytes=4096)


def test_scan_model_directory_or_file_encoded_signed_query_preserves_routing() -> None:
    """Encoded signed queries must not hide the model suffix from scanner routing."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl%3FX-Amz-Signature%3Ddeadbeef%26token%3Dsecret-token"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)) as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()) as mock_scanner,
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    assert mock_scanner.call_args.args[0] == "/model.pkl"
    mock_stream.assert_called_once_with(stream_url, mock_scanner.return_value)
    serialized = result.model_dump_json(exclude_none=True)
    assert "deadbeef" not in serialized
    assert "secret-token" not in serialized


def test_scan_model_directory_or_file_mixed_case_streaming_path() -> None:
    """URI scheme casing must not bypass streaming routing."""
    stream_url = "S3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        scan_model_directory_or_file(f"STREAM://{stream_url}")

    mock_stream.assert_called_once_with(stream_url, dummy_scanner)


def test_scan_model_directory_or_file_incomplete_streaming_path_returns_exit_code_2() -> None:
    """Incomplete stream:// analysis without findings should be explicit and fail closed."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, False)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    metadata = result.file_metadata[stream_url].model_dump()
    assert metadata["scan_outcome"] == "inconclusive"
    assert metadata["analysis_incomplete"] is True
    assert "streaming_analysis_incomplete" in metadata["scan_outcome_reasons"]
    assert "failed closed" in metadata["scan_outcome_message"]
    assert any(
        issue.message == "Streaming analysis incomplete - full scanner coverage was not available"
        for issue in result.issues
    )
    assert result.has_errors is False
    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_directory_or_file_partial_streaming_security_finding_returns_exit_code_1() -> None:
    """Security findings should outrank partial stream:// analysis metadata."""
    stream_url = "s3://bucket/model.pkl"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.add_issue(
        "Dangerous payload found in streamed prefix",
        severity=IssueSeverity.CRITICAL,
        location=stream_url,
    )
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, False)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    metadata = result.file_metadata[stream_url].model_dump()
    assert metadata["scan_outcome"] == "inconclusive"
    assert result.success is True
    assert determine_exit_code(result) == 1


def test_streaming_signed_url_is_redacted_from_results_and_sarif() -> None:
    """stream:// scans must preserve raw scanner input but redact persisted output."""
    stream_url = (
        "https://bucket.s3.amazonaws.com/model.pkl?"
        "X-Amz-Credential=AKIASECRET&X-Amz-Signature=deadbeef&token=secret-token"
    )
    safe_url = "https://bucket.s3.amazonaws.com/model.pkl"
    related_url = (
        "https://collector.example/upload?"
        "visible=yes&token=secondary-secret&password=password-secret&opaque=unknown-secret"
    )
    parsed_credentials = {
        "Authorization": "Bearer nested-auth-secret",
        "client_secret": "nested-client-secret",
        "access%252525255Ftoken": "deeply-encoded-token-secret",
        "tokenizer": "sentencepiece",
    }
    fragment_url = "https://collector.example/callback#access_token=fragment-secret"
    legacy_signed_url = (
        "https://bucket.s3.amazonaws.com/related.pkl?"
        "AWSAccessKeyId=AKIARELATED&Expires=123456&Signature=related-signature"
    )
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata.update(
        {
            "source_url": stream_url,
            "related_url": related_url,
            "fragment_url": fragment_url,
            "path_url": Path(related_url),
            "license_info": [LicenseInfoModel(url=related_url)],
            "source_set": {stream_url, related_url},
            "source_bytes": stream_url.encode(),
            "legacy_signed_url": legacy_signed_url,
            "parsed_query": parsed_credentials,
            "nested_model": Issue(message=stream_url, details={"source_bytes": stream_url.encode()}),
        }
    )
    scan_result.add_issue(
        f"Dangerous payload from {stream_url}",
        severity=IssueSeverity.CRITICAL,
        location=f"{stream_url}:payload",
        details={
            "source": stream_url,
            "nested": [stream_url],
            stream_url: {"source": stream_url},
            "related_url": related_url,
            "fragment_url": fragment_url,
            "path_url": Path(related_url),
            "license_info": [LicenseInfoModel(url=related_url)],
            "source_set": {stream_url, related_url},
            "source_bytes": stream_url.encode(),
            "legacy_signed_url": legacy_signed_url,
            "parsed_query": parsed_credentials,
            "nested_model": Issue(message=stream_url, details={"source_bytes": stream_url.encode()}),
        },
    )
    scan_result.add_check(
        name=f"Streaming Payload {stream_url}",
        passed=False,
        message=f"Checked {stream_url}",
        severity=IssueSeverity.CRITICAL,
        location=f"{stream_url} (header)",
        details={
            "source": stream_url,
            stream_url: {"source": stream_url},
            "parsed_query": parsed_credentials,
        },
        why=f"Matched {stream_url}",
    )
    cast(Any, scan_result.issues[0]).source_index = {stream_url: stream_url}
    cast(Any, scan_result.checks[0]).source_index = {stream_url: stream_url}
    cast(Any, scan_result.issues[0]).parsed_query = parsed_credentials
    cast(Any, scan_result.checks[0]).parsed_query = parsed_credentials
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    mock_stream.assert_called_once_with(stream_url, dummy_scanner)
    json_text = result.model_dump_json(exclude_none=True)
    sarif_text = format_sarif_output(result, [f"stream://{stream_url}"])

    for leaked in (
        "AKIASECRET",
        "deadbeef",
        "secret-token",
        "secondary-secret",
        "password-secret",
        "unknown-secret",
        "fragment-secret",
        "AKIARELATED",
        "related-signature",
        "X-Amz-Signature",
        "nested-auth-secret",
        "nested-client-secret",
        "deeply-encoded-token-secret",
    ):
        assert leaked not in json_text
        assert leaked not in sarif_text
    assert "sentencepiece" in json_text
    assert "sentencepiece" in sarif_text
    assert stream_url not in json_text
    assert stream_url not in sarif_text
    assert safe_url in json_text
    assert safe_url in sarif_text
    assert "visible=yes" in json_text
    assert "visible=yes" in sarif_text
    assert "token=<redacted>" in sarif_text
    assert "opaque=<redacted>" in json_text
    assert "opaque=<redacted>" in sarif_text
    assert "https://collector.example/upload<redacted>" not in sarif_text
    assert safe_url in result.file_metadata
    assert all(asset.path != stream_url for asset in result.assets)


def test_streaming_safe_source_still_redacts_related_signed_urls() -> None:
    """Stream record sanitization should not depend on the source URL needing redaction."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl"
    related_url = "https://collector.example/upload?visible=yes&token=secondary-secret&password=password-secret"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata.update({"related_url": related_url})
    scan_result.add_issue(
        f"Related signed URL {related_url}",
        severity=IssueSeverity.WARNING,
        location=stream_url,
        details={"related_url": related_url},
    )
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file") as mock_stream,
        patch("modelaudit.scanners.get_scanner_for_file") as mock_scanner,
    ):
        dummy_scanner = object()
        mock_scanner.return_value = dummy_scanner
        mock_stream.return_value = (scan_result, True)

        result = scan_model_directory_or_file(f"stream://{stream_url}")

    mock_stream.assert_called_once_with(stream_url, dummy_scanner)
    json_text = result.model_dump_json(exclude_none=True)
    assert "secondary-secret" not in json_text
    assert "password-secret" not in json_text
    assert "token=<redacted>" in json_text
    assert "visible=yes" in json_text


def test_streaming_transformed_and_escaped_credentials_are_redacted() -> None:
    """Scanner-normalized source diagnostics must not bypass reporting redaction."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl"
    opaque_url = "https://collector.example/callback?OPAQUE-QUERY-SECRET#OPAQUE-FRAGMENT-SECRET"
    escaped_url = r"https:\/\/collector.example\/callback\u003ftoken\u003dENCODED-STREAM-SECRET"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata.update(
        {
            "normalized_query": "token=TRANSFORMED-STREAM-SECRET",
            "opaque_url": opaque_url,
            "escaped_url": escaped_url,
            "authorization_header": "Authorization: Bearer HEADER-STREAM-SECRET",
        }
    )
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    sarif_text = format_sarif_output(result, [f"stream://{stream_url}"])
    for secret in (
        "TRANSFORMED-STREAM-SECRET",
        "OPAQUE-QUERY-SECRET",
        "OPAQUE-FRAGMENT-SECRET",
        "ENCODED-STREAM-SECRET",
        "HEADER-STREAM-SECRET",
    ):
        assert secret not in json_text
        assert secret not in sarif_text
    assert "token=<redacted>" in json_text
    assert "https://collector.example/callback" in json_text


def test_streaming_related_url_safe_key_cannot_hide_encoded_nested_credentials() -> None:
    """Scanner metadata must redact nested credentials hidden under an allowlisted key."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl"
    related_url = "https://collector.example/upload?lang=en%26token%3Dsecondary-secret"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.bytes_scanned = 128
    scan_result.metadata["related_url"] = related_url
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    sarif_text = format_sarif_output(result, [f"stream://{stream_url}"])
    assert "secondary-secret" not in json_text
    assert "secondary-secret" not in sarif_text
    assert "lang=<redacted>" in json_text


def test_streaming_invalid_utf8_metadata_is_replaced_before_reporting() -> None:
    """Opaque binary metadata must not retain signed URLs or break JSON output."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?token=secret-token"
    scan_result = ScanResult(scanner_name="streaming")
    scan_result.metadata["opaque_blob"] = b"\xff" + stream_url.encode()
    scan_result.finish(success=True)

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(scan_result, True)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert "<binary data>" in json_text
    assert "secret-token" not in json_text


def test_streaming_malformed_port_error_is_redacted() -> None:
    """Malformed stream URLs should produce a safe operational result, not escape error handling."""
    stream_url = "https://user:password@example.com:notaport/model.pkl?token=secret-token"

    result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert determine_exit_code(result) == 2
    assert "stream://<cloud URL redacted>" in json_text
    assert "password" not in json_text
    assert "secret-token" not in json_text


def test_streaming_signed_url_no_scanner_error_is_redacted() -> None:
    """stream:// scanner-routing failures must not persist signed URL material."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"

    with patch("modelaudit.scanners.get_scanner_for_file", return_value=None) as mock_scanner:
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    mock_scanner.assert_called_once()
    json_text = result.model_dump_json(exclude_none=True)
    assert "deadbeef" not in json_text
    assert "secret-token" not in json_text
    assert "X-Amz-Signature" not in json_text
    assert "stream://https://bucket.s3.amazonaws.com/model.pkl" in json_text
    assert all(asset.path != f"stream://{stream_url}" for asset in result.assets)
    assert determine_exit_code(result) == 2


def test_streaming_signed_url_analysis_none_error_is_redacted() -> None:
    """stream:// analysis failures must not persist signed URL material."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"

    with (
        patch("modelaudit.core.stream_analyze_file", return_value=(None, False)),
        patch("modelaudit.scanners.get_scanner_for_file", return_value=object()),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert "deadbeef" not in json_text
    assert "secret-token" not in json_text
    assert "X-Amz-Signature" not in json_text
    assert "stream://https://bucket.s3.amazonaws.com/model.pkl" in json_text
    assert all(asset.path != f"stream://{stream_url}" for asset in result.assets)
    assert determine_exit_code(result) == 2


def test_streaming_signed_url_routing_exception_log_is_redacted(caplog: pytest.LogCaptureFixture) -> None:
    """stream:// routing exceptions must not leak signed URLs through tracebacks."""
    stream_url = "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef&token=secret-token"

    with (
        caplog.at_level(logging.ERROR, logger="modelaudit.core"),
        patch(
            "modelaudit.scanners.get_scanner_for_file",
            side_effect=RuntimeError(f"route failed for {stream_url}"),
        ),
    ):
        result = scan_model_directory_or_file(f"stream://{stream_url}")

    assert determine_exit_code(result) == 2
    assert "https://bucket.s3.amazonaws.com/model.pkl" in caplog.text
    assert "deadbeef" not in caplog.text
    assert "secret-token" not in caplog.text
    assert "X-Amz-Signature" not in caplog.text


def test_streaming_signed_url_with_invalid_port_fails_closed() -> None:
    """Malformed URL authorities must not make the reporting sanitizer raise or leak."""
    stream_url = "https://example.com:not-a-port/model.pkl?token=secret-token"

    result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert determine_exit_code(result) == 2
    assert "secret-token" not in json_text
    assert "token=" not in json_text
    assert "<cloud URL redacted>" in json_text


def test_streaming_signed_url_without_inner_scheme_fails_closed() -> None:
    """Malformed stream identifiers must not persist their raw query in error assets."""
    stream_url = "bucket/model.pkl?session=secret-token"

    result = scan_model_directory_or_file(f"stream://{stream_url}")

    json_text = result.model_dump_json(exclude_none=True)
    assert determine_exit_code(result) == 2
    assert "secret-token" not in json_text
    assert "session=" not in json_text
    assert "stream://<cloud URL redacted>" in json_text


def test_scan_model_streaming_basic(temp_test_files: list[Path]) -> None:
    """Test basic streaming scan functionality."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        """Generator that yields (path, is_last) tuples."""
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        # Mock scan_file to return scan results
        mock_scan.side_effect = [create_mock_scan_result(bytes_scanned=100) for _ in temp_test_files]

        # Run streaming scan (don't delete for this test)
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # Verify results
        assert result.bytes_scanned == 300  # 3 files * 100 bytes
        assert result.files_scanned == 3
        assert result.has_errors is False
        assert result.content_hash is not None
        assert len(result.content_hash) == 64  # SHA256 hex string


@pytest.mark.parametrize("delete_after_scan", [False, True])
def test_scan_model_streaming_reconciles_cross_directory_shard_coverage(
    delete_after_scan: bool,
) -> None:
    """A complete streamed family should not fail merely because each shard has its own directory."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 4):
            staging_root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_dir = staging_root / "huggingface" / "models--org--repo" / "snapshots" / "revision"
            shard_dir.mkdir(parents=True)
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=delete_after_scan,
            shard_family_group="trusted-stream:model-a",
            cache_enabled=False,
        )

        assert result.files_scanned == 3
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)
        assert all(
            "missing_model_shards" not in metadata.model_dump().get("scan_outcome_reasons", [])
            for metadata in result.file_metadata.values()
        )
        assert all(
            "scan_outcome_message" not in metadata.model_dump(exclude_none=True)
            for metadata in result.file_metadata.values()
        )


def test_scan_model_streaming_preserves_max_total_size_failure_after_shard_reconciliation() -> None:
    """Completing a shard family must not erase an independent aggregate size failure."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard_path)

        max_total_size = sum(shard.stat().st_size for shard in shards) - 1
        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            max_total_size=max_total_size,
            shard_family_group="trusted-stream:model-a",
            cache_enabled=False,
        )

        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)
        assert any(issue.details.get("max_total_size") == max_total_size for issue in result.issues)
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_scan_model_streaming_preserves_malicious_cross_directory_shard_findings() -> None:
    """Coverage reconciliation must not suppress a malicious finding from a complete family."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = (
        b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    )
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 4):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00003.safetensors"
            header = malicious_header if shard_index == 2 else safe_header
            tensor_data = b"\x00" if shard_index == 2 else b""
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header + tensor_data)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:model-a",
            cache_enabled=False,
        )

        assert result.files_scanned == 3
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(result) == 1
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert not any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)


def test_streaming_shard_alias_aba_cannot_hide_malicious_content() -> None:
    """Scanning must stay bound to the shard target selected before inspection."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = (
        b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    )
    with ExitStack() as stack:
        shards: list[Path] = []
        swaps: dict[str, tuple[Path, Path, Path]] = {}
        for shard_index in range(1, 3):
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            malicious = root / "malicious.safetensors"
            safe = root / "safe.safetensors"
            malicious.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header + b"\0")
            safe.write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
            alias = root / f"model-{shard_index:05d}-of-00002.safetensors"
            alias.symlink_to(malicious.name)
            shards.append(alias)
            swaps[str(alias)] = (alias, malicious, safe)

        real_scan_file = scan_file

        def swap_during_scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            entry = swaps.get(path)
            if entry is None:
                return real_scan_file(path, config=config)
            alias, _malicious, safe = entry
            alias.unlink()
            alias.symlink_to(safe.name)
            try:
                return real_scan_file(path, config=config)
            finally:
                alias.unlink()
                alias.symlink_to("malicious.safetensors")

        with patch("modelaudit.core.scan_file", side_effect=swap_during_scan):
            result = scan_model_streaming(
                file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert all(shard.resolve().name == "malicious.safetensors" for shard in shards)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(result) == 1


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir() and not Path("/dev/fd").is_dir(),
    reason="descriptor-relative scan paths are unavailable",
)
def test_streaming_shard_staging_directory_aba_cannot_hide_malicious_content() -> None:
    """Replacing the staging pathname cannot redirect a descriptor-bound shard scan."""
    safe_header = b'{"__metadata__":{"format":"pt"}}'
    malicious_header = (
        b'{"tensor":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"__metadata__":{"api_key":"SECRET_METADATA_TOKEN"}}'
    )
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 3):
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard = root / f"model-{shard_index:05d}-of-00002.safetensors"
            shard.write_bytes(struct.pack("<Q", len(malicious_header)) + malicious_header + b"\0")
            shards.append(shard)

        real_scan_file = scan_file

        def exchange_staging_directory(path: str, config: dict[str, Any] | None = None) -> ScanResult:
            scan_path = Path(path)
            if not path.startswith(("/proc/self/fd/", "/dev/fd/")):
                return real_scan_file(path, config=config)
            staging_directory = Path(os.readlink(scan_path.parent))
            preserved_directory = staging_directory.with_name(f"{staging_directory.name}.preserved")
            staging_directory.rename(preserved_directory)
            staging_directory.mkdir(mode=0o700)
            benign_path = staging_directory / scan_path.name
            benign_path.write_bytes(struct.pack("<Q", len(safe_header)) + safe_header)
            try:
                return real_scan_file(path, config=config)
            finally:
                shutil.rmtree(staging_directory)
                preserved_directory.rename(staging_directory)

        with patch("modelaudit.core.scan_file", side_effect=exchange_staging_directory):
            result = scan_model_streaming(
                file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert all(b"SECRET_METADATA_TOKEN" in shard.read_bytes() for shard in shards)
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(result) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor pinning does not require hard links")
def test_streaming_shard_scan_does_not_require_hard_link_support() -> None:
    """Descriptor-bound shard scans must work on filesystems without hard links."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with ExitStack() as stack:
        shards: list[Path] = []
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard)

        with patch("modelaudit.utils.file.handlers.os.link", side_effect=OSError("hard links unavailable")):
            result = scan_model_streaming(
                file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert result.success is True
        assert result.has_errors is False
        assert determine_exit_code(result) == 0
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses open-handle hard-link pinning")
def test_streaming_shard_pin_failure_is_explicit_operational_error() -> None:
    """Platforms without descriptor paths must report the pin failure explicitly."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as shard_directory:
        shard = Path(shard_directory) / "model-00001-of-00002.safetensors"
        shard.write_bytes(struct.pack("<Q", len(header)) + header)

        with patch("modelaudit.utils.file.handlers._descriptor_path_for_open_file", return_value=None):
            result = scan_model_streaming(
                file_generator=iter([(shard, True)]),
                timeout=30,
                delete_after_scan=False,
                shard_family_group="trusted-stream:test",
                cache_enabled=False,
            )

        assert result.success is False
        assert result.has_errors is True
        assert determine_exit_code(result) == 2
        assert any(check.details.get("scan_outcome_reason") == "shard_pin_unavailable" for check in result.checks)
        assert not any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)


def test_scan_model_streaming_does_not_reconcile_distinct_remote_model_directories() -> None:
    """One remote stream must not combine complementary shards from distinct logical parents."""
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as staging_directory:
        staging_root = Path(staging_directory)
        shards: list[Path] = []
        for shard_index, model_id in ((1, "model-a"), (2, "model-b")):
            shard_dir = staging_root / model_id
            shard_dir.mkdir()
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            header = f'{{"__metadata__":{{"format":"pt","model_id":"{model_id}"}}}}'.encode()
            shard_path.write_bytes(struct.pack("<Q", len(header)) + header)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:remote-repo",
            cache_enabled=False,
        )

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)


def test_scan_model_streaming_keeps_hf_snapshot_symlink_families_separate(
    requires_symlinks: None,
) -> None:
    """Logical model directories must not merge through one shared HF blobs parent."""
    header = b'{"__metadata__":{"format":"pt"}}'
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as staging_directory:
        staging_root = Path(staging_directory)
        blobs_dir = staging_root / "huggingface" / "models--org--repo" / "blobs"
        blobs_dir.mkdir(parents=True)
        shards: list[Path] = []
        for shard_index, model_id in ((1, "model-a"), (2, "model-b")):
            blob_path = blobs_dir / f"blob-{shard_index}"
            blob_path.write_bytes(struct.pack("<Q", len(header)) + header)
            logical_dir = staging_root / "snapshots" / model_id
            logical_dir.mkdir(parents=True)
            shard_path = logical_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.symlink_to(blob_path)
            shards.append(shard_path)

        result = scan_model_streaming(
            file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
            timeout=30,
            delete_after_scan=False,
            shard_family_group="trusted-stream:remote-repo",
            cache_enabled=False,
        )

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)
        assert any(issue.details.get("scan_outcome_reason") == "missing_model_shards" for issue in result.issues)


def test_stream_staging_family_groups_are_scoped_to_nested_logical_parent() -> None:
    """Nested trusted staging paths must not combine unrelated remote model directories."""
    with tempfile.TemporaryDirectory(prefix="modelaudit_stream_") as staging_directory:
        staging_root = Path(staging_directory)
        snapshots = []
        for shard_index, model_id in ((1, "model-a"), (2, "model-b")):
            shard_dir = staging_root / "remote" / model_id
            shard_dir.mkdir(parents=True)
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            snapshots.append(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:remote-repo",
                    family_group_policy="stream_staging",
                )
            )

    family_groups = [next(iter(snapshot.values())).get("family_group") for snapshot in snapshots]
    assert all(isinstance(family_group, str) for family_group in family_groups)
    assert family_groups[0] != family_groups[1]


def test_stream_staging_family_group_rejects_nested_prefix_lookalike(tmp_path: Path) -> None:
    """A prefixed directory outside the direct temp root must not gain trusted grouping."""
    shard_dir = tmp_path / "modelaudit_stream_untrusted" / "remote" / "model-a"
    shard_dir.mkdir(parents=True)
    shard_path = shard_dir / "model-00001-of-00002.safetensors"
    shard_path.write_bytes(b"shard")

    snapshot = _snapshot_validated_shard_target(
        str(shard_path),
        family_group="attacker-controlled",
        family_group_policy="stream_staging",
    )

    assert snapshot
    assert "family_group" not in next(iter(snapshot.values()))


def test_stream_staging_family_group_rejects_plain_persistent_root(tmp_path: Path) -> None:
    """A caller-provided path must not act as a trusted persistent stream root."""
    shard_path = tmp_path / "model-00001-of-00002.safetensors"
    shard_path.write_bytes(b"shard")

    snapshot = _snapshot_validated_shard_target(
        str(shard_path),
        family_group="attacker-controlled",
        family_group_policy="stream_staging",
        trusted_root_marker=tmp_path,
    )

    assert snapshot
    assert "family_group" not in next(iter(snapshot.values()))


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes are required")
def test_stream_staging_family_group_rejects_publicly_writable_temp_root(tmp_path: Path) -> None:
    """A forgeable temp prefix must not authorize a publicly mutable shard family."""
    shard_dir = Path(tempfile.gettempdir()) / f"modelaudit_stream_public_{uuid.uuid4().hex}"
    shard_dir.mkdir(mode=0o777)
    shard_dir.chmod(0o777)
    try:
        shard_path = shard_dir / "model-00001-of-00002.safetensors"
        shard_path.write_bytes(b"shard")

        snapshot = _snapshot_validated_shard_target(
            str(shard_path),
            family_group="attacker-controlled",
            family_group_policy="stream_staging",
        )

        assert snapshot
        assert "family_group" not in next(iter(snapshot.values()))
    finally:
        shutil.rmtree(shard_dir)


def test_cross_directory_shard_reconciliation_bounds_untrusted_expected_total() -> None:
    """An attacker-controlled shard count must not allocate the declared range."""
    script = "\n".join(
        (
            "from modelaudit.core import _complete_validated_shard_family_sources",
            "total = '9' * 100",
            "source = f'/tmp/part-1/model-00001-of-{total}.safetensors'",
            "targets = {source: {'resolved_path': '/tmp/one', 'device': 1, 'inode': 1}}",
            "assert _complete_validated_shard_family_sources(targets) == set()",
        )
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0, completed.stderr


def test_cross_directory_shard_reconciliation_distinguishes_reused_inode_generations() -> None:
    """Sequential streamed files may legitimately reuse an inode after deletion."""
    shard_one = "/tmp/part-1/model-00001-of-00002.safetensors"
    shard_two = "/tmp/part-2/model-00002-of-00002.safetensors"
    targets: dict[str, dict[str, int | str]] = {
        shard_one: {
            "resolved_path": "/tmp/part-1/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 100,
            "ctime_ns": 100,
            "nlink": 1,
            "family_group": "stream-staging:test",
        },
        shard_two: {
            "resolved_path": "/tmp/part-2/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 200,
            "ctime_ns": 200,
            "nlink": 1,
            "family_group": "stream-staging:test",
        },
    }

    expected_sources = {
        os.path.normcase(os.path.normpath(os.path.abspath(shard_one))),
        os.path.normcase(os.path.normpath(os.path.abspath(shard_two))),
    }
    assert _complete_validated_shard_family_sources(targets) == expected_sources


def test_cross_directory_shard_reconciliation_rejects_sequential_hardlinks() -> None:
    """Deleting one hardlink must not make its peer look like a reused inode generation."""
    shard_one = "/tmp/part-1/model-00001-of-00002.safetensors"
    shard_two = "/tmp/part-2/model-00002-of-00002.safetensors"
    targets: dict[str, dict[str, int | str]] = {
        shard_one: {
            "resolved_path": "/tmp/part-1/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 100,
            "ctime_ns": 100,
            "nlink": 2,
            "family_group": "stream-staging:test",
        },
        shard_two: {
            "resolved_path": "/tmp/part-2/target",
            "device": 1,
            "inode": 7,
            "size": 10,
            "mtime_ns": 100,
            "ctime_ns": 200,
            "nlink": 1,
            "family_group": "stream-staging:test",
        },
    }

    assert _complete_validated_shard_family_sources(targets) == set()


def test_cross_directory_shard_reconciliation_updates_stale_scalar_reason() -> None:
    """Removing one reason must leave scalar outcome metadata aligned with the remaining reason."""
    with ExitStack() as stack:
        shards: list[Path] = []
        validated_targets = {}
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            shards.append(shard_path)
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )

        result = create_initial_audit_result()
        result.success = False
        for shard in shards:
            result.file_metadata[str(shard)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards", "shard_scan_error"],
            )

        assert _reconcile_cross_directory_shard_coverage(result, validated_targets) is True
        assert result.success is False
        for metadata_model in result.file_metadata.values():
            metadata = metadata_model.model_dump()
            assert metadata["scan_outcome_reasons"] == ["shard_scan_error"]
            assert metadata["scan_outcome_reason"] == "shard_scan_error"
            assert metadata["analysis_incomplete"] is True
            assert metadata["scan_outcome"] == "inconclusive"


def test_cross_directory_shard_reconciliation_preserves_secondary_coverage_failure() -> None:
    """Disproving missing peers must retain another incomplete-coverage explanation."""
    with ExitStack() as stack:
        shards: list[Path] = []
        validated_targets = {}
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            shards.append(shard_path)
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )

        source_result = ScanResult(scanner_name="safetensors")
        source_result.add_check(
            name="Sharded Model Coverage Check",
            passed=False,
            message="Missing 1 expected model shard(s); scan coverage is incomplete.",
            severity=IssueSeverity.INFO,
            location=str(shards[0]),
            details={
                "missing_shard_count": 1,
                "unreadable_shard_count": 1,
                "unreadable_shards": [str(shards[0].with_name("unreadable.safetensors"))],
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "missing_model_shards",
                "scan_outcome_reasons": ["missing_model_shards", "unreadable_model_shards"],
                "scan_outcome_message": "Missing model shards prevented complete analysis.",
            },
        )
        result = create_initial_audit_result()
        result.success = False
        result.checks = list(source_result.checks)
        result.issues = list(source_result.issues)
        for shard in shards:
            result.file_metadata[str(shard)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards", "unreadable_model_shards"],
            )

        assert _reconcile_cross_directory_shard_coverage(result, validated_targets) is True
        assert result.success is False
        assert len(result.checks) == 1
        assert result.checks[0].details["scan_outcome_reason"] == "unreadable_model_shards"
        assert result.checks[0].details["scan_outcome_reasons"] == ["unreadable_model_shards"]
        assert "scan_outcome_message" not in result.checks[0].details
        assert "Unable to read 1 model shard(s)" in result.checks[0].message
        assert len(result.issues) == 1
        assert result.issues[0].details["scan_outcome_reason"] == "unreadable_model_shards"
        assert result.issues[0].details["scan_outcome_reasons"] == ["unreadable_model_shards"]
        assert "scan_outcome_message" not in result.issues[0].details
        assert "Unable to read 1 model shard(s)" in result.issues[0].message


def test_cross_directory_shard_reconciliation_clears_stale_outcome_message() -> None:
    """Removing the final inconclusive reason must remove its stale explanation."""
    with ExitStack() as stack:
        shards: list[Path] = []
        validated_targets = {}
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            shards.append(shard_path)
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )

        result = create_initial_audit_result()
        result.success = False
        for shard in shards:
            result.file_metadata[str(shard)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
                scan_outcome_message="Scan analysis incomplete; failed closed because full coverage was not available.",
            )

        assert _reconcile_cross_directory_shard_coverage(result, validated_targets) is True
        assert result.success is True
        for metadata_model in result.file_metadata.values():
            metadata = metadata_model.model_dump(exclude_none=True)
            assert "analysis_incomplete" not in metadata
            assert "scan_outcome" not in metadata
            assert "scan_outcome_reason" not in metadata
            assert "scan_outcome_reasons" not in metadata
            assert "scan_outcome_message" not in metadata


def test_cross_directory_shard_reconciliation_clears_stale_operational_error_state() -> None:
    """A disproven missing-shard failure must not leave the aggregate at exit code 2."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
                missing_shard_errors_only=True,
            )
            is True
        )
        assert result.has_errors is False
        assert result.success is True
        assert determine_exit_code(result) == 0


def test_cross_directory_shard_reconciliation_preserves_retained_aggregate_failure() -> None:
    """A retained incomplete-analysis issue must keep the aggregate at exit code 2."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )
        result.issues.append(
            Issue(
                message="Total scan size limit exceeded",
                severity=IssueSeverity.INFO,
                details={"max_total_size": 1, "analysis_incomplete": True},
            )
        )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
                missing_shard_errors_only=True,
            )
            is True
        )
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_cross_directory_shard_reconciliation_preserves_unattributed_runtime_failure() -> None:
    """Caller provenance must preserve a runtime failure without durable result evidence."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 2
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
            )
            is True
        )
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_cross_directory_shard_reconciliation_preserves_independent_operational_error() -> None:
    """Clearing a shard gap must retain an unrelated explicit operational failure."""
    with ExitStack() as stack:
        validated_targets = {}
        result = create_initial_audit_result()
        result.files_scanned = 3
        result.has_errors = True
        result.success = False
        for shard_index in range(1, 3):
            shard_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="modelaudit_stream_")))
            shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
            shard_path.write_bytes(b"shard")
            validated_targets.update(
                _snapshot_validated_shard_target(
                    str(shard_path),
                    family_group="trusted-stream:model-a",
                    family_group_policy="stream_staging",
                )
            )
            result.file_metadata[str(shard_path)] = FileMetadataModel(
                analysis_incomplete=True,
                scan_outcome="inconclusive",
                scan_outcome_reason="missing_model_shards",
                scan_outcome_reasons=["missing_model_shards"],
            )
        result.file_metadata["failed-download"] = FileMetadataModel(
            operational_error=True,
            operational_error_reason="download_failed",
        )

        assert (
            _reconcile_cross_directory_shard_coverage(
                result,
                validated_targets,
                missing_shard_errors_only=True,
            )
            is True
        )
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2


def test_scan_model_streaming_does_not_reconcile_duplicate_shard_targets(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Two shard indices resolving to one target must remain incomplete."""
    header = b'{"__metadata__":{"format":"pt"}}'
    shared_target = tmp_path / "shared-target"
    shared_target.write_bytes(struct.pack("<Q", len(header)) + header)
    shards: list[Path] = []
    for shard_index in range(1, 3):
        shard_dir = tmp_path / f"part-{shard_index}"
        shard_dir.mkdir()
        shard_path = shard_dir / f"model-{shard_index:05d}-of-00002.safetensors"
        shard_path.symlink_to(shared_target)
        shards.append(shard_path)

    result = scan_model_streaming(
        file_generator=iter((shard, index == len(shards) - 1) for index, shard in enumerate(shards)),
        timeout=30,
        delete_after_scan=False,
        shard_family_group="trusted-stream:model-a",
        cache_enabled=False,
    )

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(check.details.get("scan_outcome_reason") == "missing_model_shards" for check in result.checks)


def test_scan_model_streaming_skips_non_model_files(tmp_path: Path) -> None:
    """Streaming directory scans should honor the normal skip_file_types policy."""
    ignored_file = tmp_path / "notes.log"
    ignored_file.write_text("debug output")
    model_file = tmp_path / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100)

        result = scan_model_streaming(
            file_generator=iter([(ignored_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=True,
        )

    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(model_file)
    assert mock_scan.call_args.kwargs["config"]["skip_file_types"] is True
    assert result.files_scanned == 1


def test_scan_model_streaming_preserves_license_metadata_when_skipped(tmp_path: Path) -> None:
    """Skipped license files should still populate file metadata in streaming mode."""
    license_file = tmp_path / "license.txt"
    license_file.write_text("MIT License\nCopyright 2026 Example")

    with patch("modelaudit.core.scan_file") as mock_scan:
        result = scan_model_streaming(
            file_generator=iter([(license_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=True,
        )

    mock_scan.assert_not_called()
    assert result.files_scanned == 0
    assert str(license_file) in result.file_metadata
    metadata = result.file_metadata[str(license_file)].model_dump()
    assert "license_info" in metadata
    assert "copyright_notices" in metadata


def test_scan_model_streaming_skip_file_types_preserves_malicious_findings(tmp_path: Path) -> None:
    """Prefiltering should skip non-model files without dropping model security findings."""
    ignored_file = tmp_path / "notes.log"
    ignored_file.write_text("debug output")
    model_file = tmp_path / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100, with_critical_issue=True)

        result = scan_model_streaming(
            file_generator=iter([(ignored_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=True,
        )

    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(model_file)
    assert result.files_scanned == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_keeps_non_model_files_when_skip_disabled(tmp_path: Path) -> None:
    """The skip_file_types flag should remain opt-out for streaming scans."""
    ignored_file = tmp_path / "notes.log"
    ignored_file.write_text("debug output")
    model_file = tmp_path / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100)

        result = scan_model_streaming(
            file_generator=iter([(ignored_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            skip_file_types=False,
        )

    assert [call.args[0] for call in mock_scan.call_args_list] == [str(ignored_file), str(model_file)]
    assert result.files_scanned == 2


def test_scan_model_streaming_skips_huggingface_cache_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming scans should skip HF bookkeeping metadata like regular scans."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    snapshots_dir = hf_home / "hub" / "models--test-model" / "snapshots" / "abc123"
    snapshots_dir.mkdir(parents=True)

    metadata_file = snapshots_dir / "config.json.metadata"
    metadata_file.write_text("{}")
    model_file = snapshots_dir / "model.pkl"
    with model_file.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100)

        result = scan_model_streaming(
            file_generator=iter([(metadata_file, False), (model_file, True)]),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(snapshots_dir),
            cache_enabled=False,
        )

    mock_scan.assert_called_once()
    assert mock_scan.call_args.args[0] == str(model_file)
    assert result.files_scanned == 1


def test_scan_model_streaming_scans_local_file_named_main(tmp_path: Path) -> None:
    """A local payload named like an HF ref must still be scanned in streaming mode."""
    payload = tmp_path / "main"
    payload.write_bytes(b"\x80\x02cos\nsystem\n.")

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert any(issue.severity == IssueSeverity.CRITICAL and "system" in issue.message for issue in result.issues)
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_symlink_outside_directory_matches_normal_scan(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Local streaming scans should reject symlinks that escape the requested directory."""
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with (base_dir / "safe.pkl").open("wb") as f:
        pickle.dump({"data": "safe"}, f)
    with (outside_dir / "secret.pkl").open("wb") as f:
        pickle.dump({"data": "secret"}, f)

    symlink_path = base_dir / "link.pkl"
    symlink_path.symlink_to(outside_dir / "secret.pkl")

    normal_result = scan_model_directory_or_file(str(base_dir), cache_enabled=False)
    streaming_result = scan_model_streaming(
        file_generator=iterate_files_streaming(base_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(base_dir),
        cache_enabled=False,
    )

    normal_traversal_issues = [i for i in normal_result.issues if "path traversal" in i.message.lower()]
    streaming_traversal_issues = [i for i in streaming_result.issues if "path traversal" in i.message.lower()]

    assert len(normal_traversal_issues) == 1
    assert len(streaming_traversal_issues) == 1
    assert normal_traversal_issues[0].location == str(symlink_path)
    assert streaming_traversal_issues[0].location == str(symlink_path)
    assert streaming_traversal_issues[0].severity == IssueSeverity.CRITICAL
    assert normal_result.files_scanned == 1
    assert streaming_result.files_scanned == 1


def test_scan_model_streaming_symlink_outside_directory_without_safe_files_returns_security_exit_code(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Traversal findings should keep the security exit code even when no files were scanned."""
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with (outside_dir / "secret.pkl").open("wb") as f:
        pickle.dump({"data": "secret"}, f)

    symlink_path = base_dir / "link.pkl"
    symlink_path.symlink_to(outside_dir / "secret.pkl")

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(base_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(base_dir),
        cache_enabled=False,
    )

    traversal_issues = [issue for issue in result.issues if "path traversal" in issue.message.lower()]

    assert result.files_scanned == 0
    assert result.has_errors is False
    assert len(traversal_issues) == 1
    assert traversal_issues[0].location == str(symlink_path)
    assert traversal_issues[0].severity == IssueSeverity.CRITICAL
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_hf_cache_symlink_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Local streaming scans should preserve HuggingFace cache symlink handling."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)

    blob_path = blobs_dir / "blob123"
    with blob_path.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    model_link = snapshots_dir / "model.pkl"
    os.symlink(os.path.relpath(blob_path, model_link.parent), model_link)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshots_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshots_dir),
        cache_enabled=False,
    )

    path_traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
    assert result.files_scanned == 1
    assert len(path_traversal_issues) == 0


def test_scan_model_streaming_hf_home_cache_symlink_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """Custom HF_HOME cache roots should preserve symlink handling in streaming scans."""
    monkeypatch.setenv("HF_HOME", str(tmp_path / "custom-hf-home"))
    cache_dir = tmp_path / "custom-hf-home" / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)

    blob_path = blobs_dir / "blob123"
    with blob_path.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    model_link = snapshots_dir / "model.pkl"
    os.symlink(os.path.relpath(blob_path, model_link.parent), model_link)

    result = scan_model_streaming(
        file_generator=iterate_files_streaming(snapshots_dir),
        timeout=30,
        delete_after_scan=False,
        scan_root=str(snapshots_dir),
        cache_enabled=False,
    )

    path_traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
    assert result.files_scanned == 1
    assert len(path_traversal_issues) == 0


def test_scan_model_streaming_symlink_reports_source_path_consistently(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    """Streaming scans should report source paths even when scanning a resolved symlink target."""
    base_dir = tmp_path / "base"
    nested_dir = base_dir / "nested"
    nested_dir.mkdir(parents=True)

    resolved_target = nested_dir / "model.pkl"
    with resolved_target.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    source_link = base_dir / "link.pkl"
    source_link.symlink_to(resolved_target.relative_to(source_link.parent))

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_location_scan_result(resolved_target)

        result = scan_model_streaming(
            file_generator=iter([(source_link, True)]),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(base_dir),
            cache_enabled=False,
        )

    assert mock_scan.call_args[0][0] == str(resolved_target)
    assert result.files_scanned == 1
    assert result.assets[0].path == str(source_link)
    assert result.assets[0].size == resolved_target.stat().st_size

    metadata = result.file_metadata[str(source_link)].model_dump()
    assert metadata["source_path"] == str(source_link)
    assert metadata["resolved_path"] == str(resolved_target)

    assert result.issues[0].location == f"{source_link}:payload"
    check_locations = {check.name: check.location for check in result.checks}
    assert check_locations["Suspicious Payload"] == f"{source_link}:payload"
    assert check_locations["Layout Inspection"] == f"{source_link} (weights)"


def test_scan_model_streaming_hf_cache_symlink_reports_snapshot_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    """HuggingFace cache symlinks should keep snapshot paths in streamed results."""
    hf_home = tmp_path / ".cache" / "huggingface"
    monkeypatch.setenv("HF_HOME", str(hf_home))
    cache_dir = hf_home / "hub" / "models--test-model"
    snapshots_dir = cache_dir / "snapshots" / "abc123"
    blobs_dir = cache_dir / "blobs"
    snapshots_dir.mkdir(parents=True)
    blobs_dir.mkdir(parents=True)

    blob_path = blobs_dir / "blob123"
    with blob_path.open("wb") as f:
        pickle.dump({"data": "safe"}, f)

    model_link = snapshots_dir / "model.pkl"
    os.symlink(os.path.relpath(blob_path, model_link.parent), model_link)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = create_mock_location_scan_result(blob_path, issue_suffix="", check_suffix=":tensor")

        result = scan_model_streaming(
            file_generator=iterate_files_streaming(snapshots_dir),
            timeout=30,
            delete_after_scan=False,
            scan_root=str(snapshots_dir),
            cache_enabled=False,
        )

    assert mock_scan.call_args[0][0] == str(blob_path)
    assert result.files_scanned == 1
    assert result.assets[0].path == str(model_link)

    metadata = result.file_metadata[str(model_link)].model_dump()
    assert metadata["source_path"] == str(model_link)
    assert metadata["resolved_path"] == str(blob_path)

    assert result.issues[0].location == str(model_link)
    check_locations = {check.name: check.location for check in result.checks}
    assert check_locations["Suspicious Payload"] == str(model_link)
    assert check_locations["Layout Inspection"] == f"{model_link}:tensor"


def test_scan_model_streaming_with_deletion(temp_test_files: list[Path]) -> None:
    """Test that files are deleted after scanning in streaming mode."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [create_mock_scan_result(bytes_scanned=100) for _ in temp_test_files]

        # Verify files exist before scan
        for f in temp_test_files:
            assert f.exists()

        # Run streaming scan with deletion
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=True,
        )

        # Verify files were deleted
        for f in temp_test_files:
            assert not f.exists()

    # Verify scan completed
    assert result.files_scanned == 3
    assert result.content_hash is not None


def test_scan_model_streaming_critical_findings_do_not_set_operational_errors(
    temp_test_files: list[Path],
) -> None:
    """Security findings in streaming mode should still return the security exit code."""

    def file_generator():
        yield (temp_test_files[0], True)

    finding = ScanResult(scanner_name="test_scanner")
    finding.bytes_scanned = 1024
    finding.success = True
    finding.add_issue(
        "Detected malicious payload",
        severity=IssueSeverity.CRITICAL,
        location=str(temp_test_files[0]),
    )

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.return_value = finding

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    assert result.files_scanned == 1
    assert len(result.issues) == 1
    assert result.issues[0].message == "Detected malicious payload"
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].location == str(temp_test_files[0])
    assert result.has_errors is False
    assert result.success is True
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_informational_failed_scan_does_not_set_operational_errors(
    temp_test_files: list[Path],
) -> None:
    """Informational failed scans should not override security findings with exit code 2."""

    def file_generator():
        yield (temp_test_files[0], False)
        yield (temp_test_files[1], True)

    info_result = ScanResult(scanner_name="numpy")
    info_result.add_issue(
        "Object-dtype payload contains trailing bytes after the embedded pickle stream",
        severity=IssueSeverity.INFO,
        location="trailing.npy",
    )
    info_result.finish(success=False)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [info_result, create_mock_scan_result(with_critical_issue=True)]

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    assert result.files_scanned == 2
    assert result.success is True
    assert result.has_errors is False
    assert determine_exit_code(result) == 1


def test_scan_model_streaming_bare_failed_scan_fails_closed(
    temp_test_files: list[Path],
) -> None:
    """Streaming dict aggregation should preserve bare failed-scan inconclusive metadata."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield (temp_test_files[0], True)

    info_result = ScanResult(scanner_name="numpy")
    info_result.add_issue(
        "Object-dtype payload contains trailing bytes after the embedded pickle stream",
        severity=IssueSeverity.INFO,
        location=str(temp_test_files[0]),
    )
    info_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=info_result):
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    metadata = result.file_metadata[str(temp_test_files[0])]
    assert metadata["scan_outcome"] == "inconclusive"
    assert "scanner_reported_unsuccessful_without_outcome" in metadata["scan_outcome_reasons"]
    assert result.has_errors is False
    assert result.success is False
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_operational_info_failure_sets_exit_code_2(
    temp_test_files: list[Path],
) -> None:
    """Informational coverage failures must still fail closed when flagged as operational."""

    def file_generator():
        yield (temp_test_files[0], True)

    info_result = ScanResult(scanner_name="pickle")
    info_result.add_check(
        name="Large File Coverage Check",
        passed=False,
        message=(
            "Error scanning file: scanner pickle does not support bounded large-file analysis "
            "for this file size; aborting to avoid partial coverage."
        ),
        severity=IssueSeverity.INFO,
        location=str(temp_test_files[0]),
    )
    info_result.metadata["operational_error"] = True
    info_result.metadata["operational_error_reason"] = "unsupported_bounded_large_file_analysis"
    info_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=info_result):
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

    assert result.files_scanned == 1
    assert result.success is False
    assert result.has_errors is True
    assert determine_exit_code(result) == 2


def test_scan_model_streaming_oversized_renamed_safetensors_fails_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "weights.jpg"
    header_len = SAFETENSORS_ROUTING_HEADER_PARSE_BYTES + 1
    with payload.open("wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(b"{")
        handle.truncate(8 + header_len + 1)

    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("streaming bounded SafeTensors failure must not hash the artifact"),
    )
    monkeypatch.setattr(
        safetensors_scanner.SafeTensorsScanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("streaming bounded SafeTensors failure must not run scanner hashes"),
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert "safetensors" in result.scanner_names
    assert any(check.name == "Header Size Limit" for check in result.checks)


def test_scan_model_streaming_does_not_hash_files_over_max_file_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "oversized.pkl"
    payload.write_bytes(b"X" * 128)

    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("streaming oversized file must not be hashed before rejection"),
    )

    result = scan_model_streaming(
        file_generator=iter([(payload, True)]),
        timeout=30,
        delete_after_scan=False,
        max_file_size=64,
        cache_enabled=False,
    )

    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(issue.message.startswith("File too large to scan") for issue in result.issues)


def test_scan_model_streaming_fails_closed_after_max_total_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "oversized.pkl"
    payload.write_bytes(pickle.dumps({"safe": True}) + b"X" * 128)
    later = tmp_path / "later.pkl"
    later.write_bytes(pickle.dumps({"safe": "later"}))
    scan_result = ScanResult(scanner_name="bounded_test")
    scan_result.bytes_scanned = 128
    scan_result.finish(success=True)
    hashed_paths: list[Path] = []
    file_hash = "a" * 64

    def track_hash(path: Path) -> str:
        hashed_paths.append(path)
        return file_hash

    monkeypatch.setattr("modelaudit.utils.helpers.file_hash.compute_sha256_hash", track_hash)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: scan_result)

    result = scan_model_streaming(
        file_generator=iter([(payload, False), (later, True)]),
        timeout=30,
        delete_after_scan=False,
        max_total_size=64,
        cache_enabled=False,
    )

    assert hashed_paths == [payload]
    assert result.files_scanned == 1
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(issue.message.startswith("Total scan size limit exceeded") for issue in result.issues)
    assert result.content_hash is None


def test_scan_model_streaming_stops_hashing_at_max_total_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.pkl"
    first.write_bytes(b"A" * 32)
    second = tmp_path / "second.pkl"
    second.write_bytes(b"B" * 33)
    third = tmp_path / "third.pkl"
    third.write_bytes(b"C")
    hashed_paths: list[Path] = []
    first_hash = "a" * 64

    def track_hash(path: Path) -> str:
        hashed_paths.append(path)
        return first_hash

    monkeypatch.setattr("modelaudit.utils.helpers.file_hash.compute_sha256_hash", track_hash)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result(bytes_scanned=1))

    result = scan_model_streaming(
        file_generator=iter([(first, False), (second, False), (third, True)]),
        timeout=30,
        delete_after_scan=False,
        max_total_size=64,
        cache_enabled=False,
    )

    assert hashed_paths == [first, second]
    assert result.files_scanned == 3
    assert result.content_hash is None
    assert result.success is True


def test_scan_model_streaming_content_hash_deterministic():
    """Test that content hash is deterministic for same files."""
    # Create two files with same content
    files1 = []
    files2 = []

    for _i in range(2):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("Same content")
            files1.append(Path(tmp.name))

    for _i in range(2):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("Same content")
            files2.append(Path(tmp.name))

    try:

        def gen1():
            for i, f in enumerate(files1):
                yield (f, i == len(files1) - 1)

        def gen2():
            for i, f in enumerate(files2):
                yield (f, i == len(files2) - 1)

        with patch("modelaudit.core.scan_file") as mock_scan:
            mock_scan.side_effect = [create_mock_scan_result() for _ in files1 + files2]

            result1 = scan_model_streaming(file_generator=gen1(), timeout=30, delete_after_scan=False)
            result2 = scan_model_streaming(file_generator=gen2(), timeout=30, delete_after_scan=False)

            # Same content should produce same hash
            assert result1.content_hash == result2.content_hash

    finally:
        for file_path in files1 + files2:
            if file_path.exists():
                file_path.unlink()


def test_scan_model_streaming_keeps_member_hashes_separate_from_parent(tmp_path: Path) -> None:
    benign_payload = pickle.dumps({"safe": "stream"})
    malicious_payload = pickle.dumps(_StreamingMaliciousPicklePayload())
    model_path = _create_streaming_pytorch_zip(
        tmp_path / "streamed.pt",
        {
            "data.pkl": benign_payload,
            "evil.pkl": malicious_payload,
        },
    )
    outer_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    malicious_hash = hashlib.sha256(malicious_payload).hexdigest()

    result = scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )

    metadata = result.file_metadata[str(model_path)].model_dump(mode="json", exclude_none=True)
    assert result.content_hash == compute_aggregate_hash([outer_hash])
    assert metadata["file_hashes"]["sha256"] == outer_hash
    malicious_record = _streaming_member_record(metadata, ["evil.pkl"])
    assert malicious_record["file_hashes"]["sha256"] == malicious_hash
    assert malicious_record["file_hashes"]["sha256"] != outer_hash
    assert any(
        issue.location is not None
        and ":evil.pkl" in issue.location
        and issue.details.get("pickle_filename") == "evil.pkl"
        for issue in result.issues
    )


def test_scan_model_streaming_empty_generator():
    """Test streaming scan with empty file generator."""

    def empty_generator():
        return
        yield  # Make it a generator

    result = scan_model_streaming(
        file_generator=empty_generator(),
        timeout=30,
        delete_after_scan=True,
    )

    # Should complete without errors but with no results
    assert result.files_scanned == 0
    assert result.bytes_scanned == 0
    assert result.content_hash is None or result.content_hash == compute_aggregate_hash([])


def test_scan_model_streaming_timeout_closes_generator_and_deletes_yielded_file(tmp_path: Path) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    generator_closed = False
    clock_calls = 0

    def fake_time() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 1.0

    def file_generator() -> Iterator[tuple[Path, bool]]:
        nonlocal generator_closed
        try:
            yield (streamed_file, True)
        finally:
            generator_closed = True

    retained_generator = file_generator()
    with (
        patch("modelaudit.core.time.time", side_effect=fake_time),
        patch("modelaudit.core.scan_file") as mock_scan,
    ):
        result = scan_model_streaming(
            file_generator=retained_generator,
            timeout=0,
            delete_after_scan=True,
        )

    assert result.has_errors is True
    assert result.success is False
    assert generator_closed is True
    assert not streamed_file.exists()
    mock_scan.assert_not_called()


def test_scan_model_streaming_timeout_omits_successful_prefix_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.pkl"
    second = tmp_path / "second.pkl"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    now = [0.0]

    def file_generator() -> Iterator[tuple[Path, bool]]:
        yield first, False
        now[0] = 2.0
        yield second, True

    monkeypatch.setattr("modelaudit.core.time.time", lambda: now[0])
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result())

    result = scan_model_streaming(
        file_generator=file_generator(),
        timeout=1,
        delete_after_scan=False,
    )

    assert result.files_scanned == 1
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert result.content_hash is None


def test_scan_model_streaming_interruption_closes_generator_and_deletes_yielded_file(tmp_path: Path) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    generator_closed = False

    def file_generator() -> Iterator[tuple[Path, bool]]:
        nonlocal generator_closed
        try:
            yield (streamed_file, True)
        finally:
            generator_closed = True

    retained_generator = file_generator()
    with (
        patch("modelaudit.core.check_interrupted", side_effect=KeyboardInterrupt("interrupted")),
        pytest.raises(KeyboardInterrupt, match="interrupted"),
    ):
        scan_model_streaming(
            file_generator=retained_generator,
            delete_after_scan=True,
        )

    assert generator_closed is True
    assert not streamed_file.exists()


def test_scan_model_streaming_delete_failure_is_operational_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    original_unlink = Path.unlink

    def fail_streamed_unlink(path: Path, missing_ok: bool = False) -> None:
        if path == streamed_file:
            raise PermissionError("delete denied")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_streamed_unlink)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result())

    result = scan_model_streaming(
        file_generator=iter([(streamed_file, True)]),
        delete_after_scan=True,
    )

    assert streamed_file.exists()
    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.location == str(streamed_file)
        and issue.details.get("operational_error") is True
        and "delete denied" in issue.message
        for issue in result.issues
    )


def test_scan_model_streaming_accepts_generator_fallback_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")
    original_unlink = Path.unlink

    def file_generator() -> Iterator[tuple[Path, bool]]:
        try:
            yield streamed_file, True
        finally:
            original_unlink(streamed_file)

    def fail_streamed_unlink(path: Path, missing_ok: bool = False) -> None:
        if path == streamed_file:
            raise PermissionError("delete denied")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_streamed_unlink)
    monkeypatch.setattr("modelaudit.core.scan_file", lambda _path, **_kwargs: create_mock_scan_result())

    result = scan_model_streaming(
        file_generator=file_generator(),
        delete_after_scan=True,
    )

    assert not streamed_file.exists()
    assert result.has_errors is False
    assert result.success is True
    assert determine_exit_code(result) == 0
    assert not any("Failed to delete streamed source" in issue.message for issue in result.issues)


def test_scan_model_streaming_close_failure_is_operational_error(tmp_path: Path) -> None:
    streamed_file = tmp_path / "streamed.pkl"
    streamed_file.write_bytes(b"payload")

    class CloseFails(Iterator[tuple[Path, bool]]):
        def __init__(self) -> None:
            self.yielded = False

        def __next__(self) -> tuple[Path, bool]:
            if self.yielded:
                raise StopIteration
            self.yielded = True
            return streamed_file, True

        def close(self) -> None:
            raise OSError("close failed")

    with patch("modelaudit.core.scan_file", return_value=create_mock_scan_result()):
        result = scan_model_streaming(
            file_generator=CloseFails(),
            delete_after_scan=False,
        )

    assert result.has_errors is True
    assert result.success is False
    assert determine_exit_code(result) == 2
    assert any(
        issue.message == "Failed to close streaming file generator: close failed"
        and issue.details.get("operational_error") is True
        for issue in result.issues
    )


def test_scan_model_streaming_scan_error_handling(temp_test_files: list[Path]) -> None:
    """Test that scan errors are handled gracefully in streaming mode."""

    def file_generator():
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        # First file succeeds, second fails, third succeeds
        mock_scan.side_effect = [
            create_mock_scan_result(),
            Exception("Scan failed"),
            create_mock_scan_result(),
        ]

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # Should have errors flag set
        assert result.has_errors is True
        # Should have scanned 2 files (1st and 3rd)
        assert result.files_scanned == 2
        assert result.content_hash is None


@pytest.mark.slow
def test_scan_model_streaming_timeout():
    """Test that timeout is respected in streaming mode."""
    # Create multiple files to trigger timeout between scans
    temp_files = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(f"Test {i}")
            temp_files.append(Path(f.name))

    try:

        def slow_generator():
            for i, f in enumerate(temp_files):
                yield (f, i == len(temp_files) - 1)

        with patch("modelaudit.core.scan_file") as mock_scan:
            # Make each scan take 0.5 seconds (3 files = 1.5s total)
            def slow_scan(*args, **kwargs):
                time.sleep(0.5)
                return create_mock_scan_result()

            mock_scan.side_effect = slow_scan

            # Set timeout to 1 second (should complete 1-2 files, then timeout)
            result = scan_model_streaming(
                file_generator=slow_generator(),
                timeout=1,  # 1 second timeout
                delete_after_scan=False,
            )

            # Should timeout and have errors
            assert result.has_errors is True
            # Should have scanned at least 1 file but not all 3
            assert 1 <= result.files_scanned < 3

    finally:
        for file_path in temp_files:
            if file_path.exists():
                file_path.unlink()


def test_compute_aggregate_hash_empty_list():
    """Test aggregate hash computation with empty list."""
    result = compute_aggregate_hash([])
    # Should return hash of empty string
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert result == expected


def test_compute_aggregate_hash_single_hash():
    """Test aggregate hash computation with single hash."""
    file_hash = "a" * 64  # Mock SHA256 hash
    result = compute_aggregate_hash([file_hash])
    assert len(result) == 64
    assert result != file_hash  # Should be different (hash of hash)


def test_compute_aggregate_hash_multiple_hashes():
    """Test aggregate hash computation with multiple hashes."""
    hashes = [
        "a" * 64,
        "b" * 64,
        "c" * 64,
    ]
    result = compute_aggregate_hash(hashes)
    assert len(result) == 64


def test_compute_aggregate_hash_order_independence():
    """Test that aggregate hash is order-independent (sorted)."""
    hashes = ["aaa", "bbb", "ccc"]
    reversed_hashes = ["ccc", "bbb", "aaa"]

    result1 = compute_aggregate_hash(hashes)
    result2 = compute_aggregate_hash(reversed_hashes)

    # Should be the same (sorted internally)
    assert result1 == result2


def test_scan_model_streaming_progress_callback(temp_test_files: list[Path]) -> None:
    """Test that progress callback is called during streaming scan."""
    progress_calls: list[tuple[str, float]] = []

    def progress_callback(message: str, percentage: float) -> None:
        progress_calls.append((message, percentage))

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for i, file_path in enumerate(temp_test_files):
            yield (file_path, i == len(temp_test_files) - 1)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [create_mock_scan_result() for _ in temp_test_files]

        scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            progress_callback=progress_callback,
            delete_after_scan=False,
        )

        # Should have received progress updates
        assert len(progress_calls) > 0
        # Should have both hashing and scanning messages
        messages = [msg for msg, _ in progress_calls]
        assert any("Hashing" in msg for msg in messages)
        assert any("Scanning" in msg for msg in messages)


def test_scan_model_streaming_asset_creation(temp_test_files: list[Path]) -> None:
    """Test that assets are created during streaming scan."""

    def file_generator() -> Iterator[tuple[Path, bool]]:
        for i, file_path in enumerate(temp_test_files):
            yield (file_path, i == len(temp_test_files) - 1)

    with (
        patch("modelaudit.core.scan_file") as mock_scan,
        patch("modelaudit.utils.helpers.assets.asset_from_scan_result") as mock_asset,
    ):
        mock_scan.side_effect = [create_mock_scan_result() for _ in temp_test_files]

        # Mock asset creation
        mock_asset.return_value = {
            "path": "test",
            "type": "test",
            "size": 100,
        }

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # asset_from_scan_result should be called for each file
        assert result.success is True
        assert result.files_scanned == len(temp_test_files)
        assert mock_asset.call_count == 3
        assert result.assets
        assert all(asset.is_streamed is True for asset in result.assets)
