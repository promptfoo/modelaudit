"""Comprehensive tests for the GGUF scanner."""

import struct
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.rules import Severity
from modelaudit.scanners.base import DEFAULT_MAX_FILE_READ_SIZE, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.gguf_scanner import (
    GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON,
    GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON,
    GGUF_PARSE_INCONCLUSIVE_REASON,
    GGUF_STRUCTURE_INCONCLUSIVE_REASON,
    GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON,
    GgufScanner,
)
from tests.helpers import create_mock_gguf


def _write_minimal_gguf(path, n_kv=1, n_tensors=0, kv_key=b"test", kv_value=b"val"):
    """Create a minimal valid GGUF file for testing."""
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", n_tensors))  # tensor count
        f.write(struct.pack("<Q", n_kv))  # kv count

        # Metadata
        if n_kv > 0:
            f.write(struct.pack("<Q", len(kv_key)))  # key length
            f.write(kv_key)  # key
            f.write(struct.pack("<I", 8))  # value type (string)
            f.write(struct.pack("<Q", len(kv_value)))  # value length
            f.write(kv_value)  # value


def _write_comprehensive_gguf(path):
    """Create a comprehensive GGUF file with tensors for testing."""
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Metadata
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)

        # Tensor info
        name = b"weight"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))  # dimensions
        f.write(struct.pack("<Q", 8))  # dimension size
        f.write(struct.pack("<I", 0))  # f32 tensor type
        f.write(struct.pack("<Q", 0))  # tensor offset (relative to tensor data section start)

        # Align tensor data section to 32 bytes
        tensor_info_end = f.tell()
        pad_to_tensor_data = (32 - (tensor_info_end % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\0" * pad_to_tensor_data)

        # Tensor data (8 * 4 bytes for f32)
        f.write(b"\0" * 32)


def _write_ggml_file(path):
    """Create a basic GGML file for testing."""
    with open(path, "wb") as f:
        f.write(b"GGML")
        f.write(struct.pack("<I", 1))  # version
        f.write(b"\0" * 24)  # padding to minimum size


def _write_ggml_variant_file(path, magic):
    """Create a GGML variant file with custom magic."""
    with open(path, "wb") as f:
        f.write(magic)
        f.write(struct.pack("<I", 1))
        f.write(b"\0" * 24)


def _write_gguf_with_tensor_type(
    path: Path,
    tensor_type: int,
    *,
    tensor_name: bytes = b"unknown",
    dims: tuple[int, ...] = (8,),
    tensor_data_size: int = 32,
) -> None:
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))
        f.write(struct.pack("<Q", 0))

        f.write(struct.pack("<Q", len(tensor_name)))
        f.write(tensor_name)
        f.write(struct.pack("<I", len(dims)))
        for dimension in dims:
            f.write(struct.pack("<Q", dimension))
        f.write(struct.pack("<I", tensor_type))
        f.write(struct.pack("<Q", 0))

        pad_to_tensor_data = (32 - (f.tell() % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\0" * pad_to_tensor_data)
        f.write(b"\0" * tensor_data_size)


def _write_gguf_with_tensor_records(
    path: Path,
    records: list[tuple[bytes, int, tuple[int, ...], int]],
) -> None:
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", len(records)))
        f.write(struct.pack("<Q", 0))

        offset = 0
        for tensor_name, tensor_type, dims, tensor_data_size in records:
            f.write(struct.pack("<Q", len(tensor_name)))
            f.write(tensor_name)
            f.write(struct.pack("<I", len(dims)))
            for dimension in dims:
                f.write(struct.pack("<Q", dimension))
            f.write(struct.pack("<I", tensor_type))
            f.write(struct.pack("<Q", offset))
            offset += tensor_data_size

        pad_to_tensor_data = (32 - (f.tell() % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\0" * pad_to_tensor_data)

        for _tensor_name, _tensor_type, _dims, tensor_data_size in records:
            f.write(b"\0" * tensor_data_size)


def _write_gguf_string_metadata_entries(
    path: Path,
    entries: list[tuple[str, str]],
    *,
    declared_count: int | None = None,
) -> None:
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", declared_count if declared_count is not None else len(entries)))
        for key, value in entries:
            encoded_key = key.encode("utf-8")
            encoded_value = value.encode("utf-8")
            f.write(struct.pack("<Q", len(encoded_key)))
            f.write(encoded_key)
            f.write(struct.pack("<I", 8))
            f.write(struct.pack("<Q", len(encoded_value)))
            f.write(encoded_value)


def _write_gguf_raw_metadata_entries(
    path: Path,
    entries: list[tuple[str, int, bytes]],
    *,
    n_tensors: int = 0,
) -> None:
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", n_tensors))
        f.write(struct.pack("<Q", len(entries)))
        for key, value_type, value_bytes in entries:
            encoded_key = key.encode("utf-8")
            f.write(struct.pack("<Q", len(encoded_key)))
            f.write(encoded_key)
            f.write(struct.pack("<I", value_type))
            f.write(value_bytes)


def _encode_gguf_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def _encode_gguf_array(subtype: int, values: bytes, count: int) -> bytes:
    return struct.pack("<IQ", subtype, count) + values


def _single_file_metadata(aggregate: Any) -> Any:
    return next(iter(aggregate.file_metadata.values()))


def _assert_inconclusive_exit2(aggregate: Any, reason: str) -> None:
    metadata = _single_file_metadata(aggregate)
    assert aggregate.success is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in metadata.get("scan_outcome_reasons", [])
    assert determine_exit_code(aggregate) == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)


def _assert_no_warning_or_critical_issues(result: Any) -> None:
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def _assert_uncached_rerun_preserves_inconclusive_exit2(
    path: Path,
    cache_dir: Path,
    reason: str,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        _assert_inconclusive_exit2(first, reason)
        _assert_inconclusive_exit2(second, reason)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_gguf_scanner_can_handle_gguf(tmp_path):
    """Test that scanner can handle GGUF files."""
    path = tmp_path / "model.gguf"
    _write_minimal_gguf(path)
    assert GgufScanner.can_handle(str(path))


def test_gguf_scanner_can_handle_ggml(tmp_path):
    """Test that scanner can handle GGML files."""
    path = tmp_path / "model.ggml"
    _write_ggml_file(path)
    assert GgufScanner.can_handle(str(path))


def test_large_gguf_scans_metadata_without_default_full_file_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Large GGUF files should not trip a full-file read cap before header parsing."""
    path = tmp_path / "large.gguf"
    _write_minimal_gguf(path, n_kv=0, n_tensors=0)
    with path.open("ab") as handle:
        handle.truncate(DEFAULT_MAX_FILE_READ_SIZE + 4096)

    scanner = GgufScanner()
    monkeypatch.setattr(
        scanner,
        "calculate_file_hashes",
        lambda _path: {"md5": "0", "sha256": "0", "sha512": "0"},
    )

    result = scanner.scan(str(path))

    check_names = {check.name for check in result.checks}
    assert "File Size Limit" not in check_names
    assert result.success is True
    assert result.metadata["format"] == "gguf"
    assert result.metadata["file_size"] > DEFAULT_MAX_FILE_READ_SIZE


def test_gguf_scanner_can_handle_ggml_variants(tmp_path):
    """Scanner handles GGML variant magic codes."""
    for magic in [b"GGMF", b"GGJT"]:
        path = tmp_path / f"model_{magic.decode().lower()}.ggml"
        _write_ggml_variant_file(path, magic)
        assert GgufScanner.can_handle(str(path))


def test_gguf_scanner_rejects_invalid_files(tmp_path):
    """Test that scanner rejects invalid files."""
    path = tmp_path / "invalid.gguf"
    with open(path, "wb") as f:
        f.write(b"INVALID")
    assert not GgufScanner.can_handle(str(path))


def test_gguf_scanner_basic_scan(tmp_path):
    """Test basic GGUF scanning functionality."""
    path = tmp_path / "model.gguf"
    _write_minimal_gguf(path)
    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["format"] == "gguf"
    assert result.metadata["n_kv"] == 1
    assert result.metadata["n_tensors"] == 0


def test_gguf_scanner_delegates_malicious_chat_templates_to_jinja_analysis(tmp_path: Path) -> None:
    path = create_mock_gguf(
        tmp_path / "malicious.gguf",
        metadata={"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
    )

    result = GgufScanner().scan(str(path))

    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_gguf_scanner_delegates_named_chat_templates_to_jinja_analysis(tmp_path: Path) -> None:
    path = create_mock_gguf(
        tmp_path / "malicious-named-template.gguf",
        metadata={"tokenizer.chat_template.tool": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
    )

    result = GgufScanner().scan(str(path))

    assert any(
        check.name == "Jinja2 Template Injection Detection"
        and check.status == CheckStatus.FAILED
        and check.details["template_location"] == "tokenizer.chat_template.tool"
        for check in result.checks
    )


def test_gguf_scanner_keeps_benign_chat_templates_clean(tmp_path: Path) -> None:
    path = create_mock_gguf(
        tmp_path / "benign.gguf",
        metadata={
            "tokenizer.chat_template": "{% for message in messages %}{{ message['content'] }}{% endfor %}",
        },
    )

    result = GgufScanner().scan(str(path))

    assert any(check.name == "Jinja2 SSTI Analysis" and check.status == CheckStatus.PASSED for check in result.checks)
    assert not any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_gguf_scanner_keeps_benign_macro_chat_templates_clean(tmp_path: Path) -> None:
    path = create_mock_gguf(
        tmp_path / "benign-macro.gguf",
        metadata={
            "tokenizer.chat_template": "{% macro render(message) %}{{ message['content'] }}{% endmacro %}",
        },
    )

    result = GgufScanner().scan(str(path))

    assert any(check.name == "Jinja2 SSTI Analysis" and check.status == CheckStatus.PASSED for check in result.checks)
    assert not any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_gguf_scanner_detects_malicious_chat_template_hidden_by_duplicate_key(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-template.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [
            ("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}"),
            ("tokenizer.chat_template", "{{ message['content'] }}"),
        ],
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert any(check.name == "GGUF Duplicate Metadata Keys" for check in direct.checks)
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_gguf_scanner_duplicate_benign_chat_template_is_inconclusive_without_finding(tmp_path: Path) -> None:
    path = tmp_path / "benign-duplicate-template.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [
            ("tokenizer.chat_template", "{{ message['content'] }}"),
            ("tokenizer.chat_template", "{{ message['role'] }}"),
        ],
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
    _assert_inconclusive_exit2(aggregate, GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON)
    _assert_uncached_rerun_preserves_inconclusive_exit2(
        path,
        tmp_path / "duplicate-template-cache",
        GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON,
    )


def test_gguf_scanner_duplicate_benign_chat_template_ignores_s902_severity_override(tmp_path: Path) -> None:
    path = tmp_path / "benign-duplicate-template-severity-override.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [
            ("tokenizer.chat_template", "{{ message['content'] }}"),
            ("tokenizer.chat_template", "{{ message['role'] }}"),
        ],
    )

    set_config(ModelAuditConfig(severity={"S902": Severity.CRITICAL}))
    try:
        direct = GgufScanner().scan(str(path))
        aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)
    finally:
        reset_config()

    duplicate_checks = [check for check in direct.checks if check.name == "GGUF Duplicate Metadata Keys"]
    assert len(duplicate_checks) == 1
    assert duplicate_checks[0].severity == IssueSeverity.INFO
    assert duplicate_checks[0].rule_code is None
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
    assert all(issue.rule_code != "S902" for issue in direct.issues)
    _assert_inconclusive_exit2(aggregate, GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON)


def test_gguf_scanner_duplicate_and_key_limit_ignore_s902_severity_override(tmp_path: Path) -> None:
    path = tmp_path / "benign-duplicate-template-key-limit-severity-override.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [
            ("tokenizer.chat_template", "{{ message['content'] }}"),
            ("tokenizer.chat_template", "{{ message['role'] }}"),
        ],
        declared_count=3,
    )

    set_config(ModelAuditConfig(severity={"S902": Severity.CRITICAL}))
    try:
        direct = GgufScanner(config={"gguf_max_metadata_keys": 2}).scan(str(path))
        aggregate = scan_model_directory_or_file(
            str(path),
            cache_enabled=False,
            gguf_max_metadata_keys=2,
        )
    finally:
        reset_config()

    checks_by_name = {check.name: check for check in direct.checks}
    assert checks_by_name["GGUF Duplicate Metadata Keys"].rule_code is None
    assert checks_by_name["GGUF Duplicate Metadata Keys"].severity == IssueSeverity.INFO
    assert checks_by_name["GGUF Metadata Resource Limits"].rule_code is None
    assert checks_by_name["GGUF Metadata Resource Limits"].severity == IssueSeverity.INFO
    _assert_no_warning_or_critical_issues(direct)
    assert GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    _assert_inconclusive_exit2(aggregate, GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON)
    assert GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON in _single_file_metadata(aggregate)["scan_outcome_reasons"]


def test_gguf_scanner_scans_malicious_template_before_truncated_metadata(tmp_path: Path) -> None:
    path = tmp_path / "trailing-truncated-template.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")],
        declared_count=2,
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_PARSE_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_gguf_scanner_reports_duplicate_key_before_truncated_duplicate_value(tmp_path: Path) -> None:
    path = tmp_path / "truncated-duplicate-template.gguf"
    key = "tokenizer.chat_template"
    _write_gguf_string_metadata_entries(
        path,
        [(key, "{{ message['content'] }}")],
        declared_count=2,
    )
    with path.open("ab") as f:
        encoded_key = key.encode("utf-8")
        f.write(struct.pack("<Q", len(encoded_key)))
        f.write(encoded_key)

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert GGUF_PARSE_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert any(check.name == "GGUF Duplicate Metadata Keys" for check in direct.checks)
    _assert_inconclusive_exit2(aggregate, GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON)


def test_gguf_metadata_array_item_limit_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "bounded-array.gguf"
    _write_gguf_raw_metadata_entries(
        path,
        [("test.array", 9, _encode_gguf_array(0, b"\x01\x02", 2))],
    )

    direct = GgufScanner(config={"gguf_max_metadata_array_items": 1}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        gguf_max_metadata_array_items=1,
    )

    assert direct.success is False
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
    assert any(
        check.name == "GGUF Metadata Resource Limits"
        and check.details["max_metadata_array_items"] == 1
        and check.details["scan_outcome_reason"] == GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON
        for check in direct.checks
    )
    _assert_inconclusive_exit2(aggregate, GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON)
    _assert_uncached_rerun_preserves_inconclusive_exit2(
        path,
        tmp_path / "array-cache",
        GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON,
        gguf_max_metadata_array_items=1,
    )


def test_gguf_metadata_byte_limit_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "bounded-metadata-bytes.gguf"
    _write_gguf_raw_metadata_entries(
        path,
        [("test.string", 8, _encode_gguf_string("benign value"))],
    )

    direct = GgufScanner(config={"gguf_max_metadata_bytes": 8}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        gguf_max_metadata_bytes=8,
    )

    assert direct.success is False
    assert any(
        check.name == "GGUF Metadata Resource Limits" and check.details["max_metadata_bytes"] == 8
        for check in direct.checks
    )
    _assert_inconclusive_exit2(aggregate, GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON)


def test_gguf_metadata_limit_ignores_s902_severity_override(tmp_path: Path) -> None:
    path = tmp_path / "bounded-array-severity-override.gguf"
    _write_gguf_raw_metadata_entries(
        path,
        [("test.array", 9, _encode_gguf_array(0, b"\x01\x02", 2))],
    )

    set_config(ModelAuditConfig(severity={"S902": Severity.CRITICAL}))
    try:
        direct = GgufScanner(config={"gguf_max_metadata_array_items": 1}).scan(str(path))
        aggregate = scan_model_directory_or_file(
            str(path),
            cache_enabled=False,
            gguf_max_metadata_array_items=1,
        )
    finally:
        reset_config()

    limit_checks = [check for check in direct.checks if check.name == "GGUF Metadata Resource Limits"]
    assert len(limit_checks) == 1
    assert limit_checks[0].severity == IssueSeverity.INFO
    assert limit_checks[0].rule_code is None
    _assert_no_warning_or_critical_issues(direct)
    _assert_inconclusive_exit2(aggregate, GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON)


def test_gguf_extract_metadata_reports_bounded_partial_results(tmp_path: Path) -> None:
    path = tmp_path / "bounded-extracted-metadata.gguf"
    _write_gguf_raw_metadata_entries(
        path,
        [
            ("general.architecture", 8, _encode_gguf_string("llama")),
            ("test.array", 9, _encode_gguf_array(0, b"\x01\x02", 2)),
        ],
    )

    metadata = GgufScanner(config={"gguf_max_metadata_array_items": 1}).extract_metadata(str(path))

    assert metadata["architecture"] == "llama"
    assert metadata["metadata_count"] == 2
    assert "exceeds per-array limit 1" in metadata["error_reading_metadata"]


def test_gguf_total_metadata_array_item_limit_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "bounded-total-array-items.gguf"
    _write_gguf_raw_metadata_entries(
        path,
        [
            ("test.first", 9, _encode_gguf_array(0, b"\x01", 1)),
            ("test.second", 9, _encode_gguf_array(0, b"\x02", 1)),
        ],
    )

    direct = GgufScanner(config={"gguf_max_total_metadata_array_items": 1}).scan(str(path))

    assert direct.success is False
    assert any(
        check.name == "GGUF Metadata Resource Limits" and check.details["max_total_metadata_array_items"] == 1
        for check in direct.checks
    )
    assert GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]


def test_gguf_scanner_keeps_malicious_template_found_before_array_limit(tmp_path: Path) -> None:
    path = tmp_path / "template-before-array-limit.gguf"
    _write_gguf_raw_metadata_entries(
        path,
        [
            ("tokenizer.chat_template", 8, _encode_gguf_string("{{ ''.__class__.__mro__[1].__subclasses__() }}")),
            ("test.array", 9, _encode_gguf_array(0, b"\x01\x02", 2)),
        ],
    )

    direct = GgufScanner(config={"gguf_max_metadata_array_items": 1}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        gguf_max_metadata_array_items=1,
    )

    assert GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_gguf_scanner_keeps_malicious_template_found_before_key_count_limit(tmp_path: Path) -> None:
    path = tmp_path / "template-before-key-count-limit.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [("tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}")],
        declared_count=2,
    )

    direct = GgufScanner(config={"gguf_max_metadata_keys": 1}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        gguf_max_metadata_keys=1,
    )

    assert GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_gguf_nested_metadata_array_depth_limit_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "deep-array.gguf"
    leaf = _encode_gguf_array(0, b"\x01", 1)
    nested = _encode_gguf_array(9, _encode_gguf_array(9, leaf, 1), 1)
    _write_gguf_raw_metadata_entries(path, [("test.array", 9, nested)])

    direct = GgufScanner(config={"gguf_max_metadata_array_depth": 2}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        gguf_max_metadata_array_depth=2,
    )

    assert direct.success is False
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
    _assert_inconclusive_exit2(aggregate, GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON)


def test_gguf_tensor_information_byte_limit_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "bounded-tensor-info.gguf"
    _write_gguf_with_tensor_type(path, tensor_type=0)

    direct = GgufScanner(config={"gguf_max_tensor_info_bytes": 4}).scan(str(path))
    aggregate = scan_model_directory_or_file(
        str(path),
        cache_enabled=False,
        gguf_max_tensor_info_bytes=4,
    )

    assert direct.success is False
    assert any(
        check.name == "GGUF Tensor Resource Limits" and check.details["max_tensor_info_bytes"] == 4
        for check in direct.checks
    )
    _assert_inconclusive_exit2(aggregate, GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON)


def test_gguf_default_tensor_count_limit_blocks_compact_resource_exhaustion(tmp_path: Path) -> None:
    path = tmp_path / "too-many-compact-tensors.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", GgufScanner.DEFAULT_MAX_TENSORS + 1))
        f.write(struct.pack("<Q", 0))

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.success is False
    assert "tensors" not in direct.metadata
    assert any(
        check.name == "GGUF Tensor Resource Limits"
        and check.details["declared_tensors"] == GgufScanner.DEFAULT_MAX_TENSORS + 1
        for check in direct.checks
    )
    _assert_inconclusive_exit2(aggregate, GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON)


def test_gguf_tensor_metadata_summary_is_capped_without_skipping_validation(tmp_path: Path) -> None:
    path = tmp_path / "capped-tensor-summary.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 3))
        f.write(struct.pack("<Q", 0))

        for index in range(3):
            name = f"tensor{index}".encode()
            f.write(struct.pack("<Q", len(name)))
            f.write(name)
            f.write(struct.pack("<I", 1))
            f.write(struct.pack("<Q", 8))
            f.write(struct.pack("<I", 0))
            f.write(struct.pack("<Q", index * 32))

        pad_to_tensor_data = (32 - (f.tell() % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\0" * pad_to_tensor_data)
        f.write(b"\0" * 96)

    result = GgufScanner(config={"gguf_max_reported_tensors": 1}).scan(str(path))

    assert result.success
    assert result.metadata["tensors"] == [{"name": "tensor0", "type": 0, "dims": [8]}]
    assert result.metadata["tensor_count_reported"] == 1
    assert result.metadata["tensor_metadata_truncated"] is True
    assert result.metadata["max_reported_tensors"] == 1
    assert not any("size mismatch" in issue.message.lower() for issue in result.issues)


def test_gguf_streaming_tensor_parse_preserves_excessive_dimension_finding(tmp_path: Path) -> None:
    path = tmp_path / "excessive-dimensions-missing-data.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))
        f.write(struct.pack("<Q", 0))
        name = b"huge_rank"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1001))

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert any(
        check.name == "Tensor Dimension Validation" and check.severity == IssueSeverity.CRITICAL
        for check in direct.checks
    )
    assert any(check.name == "Tensor Data Section Bounds" for check in direct.checks)
    assert determine_exit_code(aggregate) == 1


def test_gguf_tensor_limit_ignores_s902_severity_override(tmp_path: Path) -> None:
    path = tmp_path / "bounded-tensor-info-severity-override.gguf"
    _write_gguf_with_tensor_type(path, tensor_type=0)

    set_config(ModelAuditConfig(severity={"S902": Severity.CRITICAL}))
    try:
        direct = GgufScanner(config={"gguf_max_tensor_info_bytes": 4}).scan(str(path))
        aggregate = scan_model_directory_or_file(
            str(path),
            cache_enabled=False,
            gguf_max_tensor_info_bytes=4,
        )
    finally:
        reset_config()

    limit_checks = [check for check in direct.checks if check.name == "GGUF Tensor Resource Limits"]
    assert len(limit_checks) == 1
    assert limit_checks[0].severity == IssueSeverity.INFO
    assert limit_checks[0].rule_code is None
    _assert_no_warning_or_critical_issues(direct)
    _assert_inconclusive_exit2(aggregate, GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON)


def test_gguf_scanner_fails_closed_on_oversized_chat_templates(tmp_path: Path) -> None:
    path = create_mock_gguf(
        tmp_path / "large-template.gguf",
        metadata={"tokenizer.chat_template": "{{ content }}" * 10000},
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Template Size Limit"
        and check.status == CheckStatus.FAILED
        and "analysis incomplete" in check.message.lower()
        and check.details["reason"] == "jinja2_template_size_limit_exceeded"
        for check in direct.checks
    )
    assert not any(check.name == "Jinja2 SSTI Analysis" for check in direct.checks)
    _assert_inconclusive_exit2(aggregate, "jinja2_template_size_limit_exceeded")


def test_gguf_scanner_propagates_jinja_sandbox_budget_inconclusive(tmp_path: Path) -> None:
    pytest.importorskip("jinja2.sandbox")
    path = create_mock_gguf(
        tmp_path / "sandbox-budget.gguf",
        metadata={"tokenizer.chat_template": "{{ 'A' * 1000000 }}"},
    )
    config = {
        "sandbox_render_max_output_chars": 16,
        "sandbox_render_timeout_seconds": 2,
    }

    direct = GgufScanner(config=config).scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), config={**config, "cache_scan_results": False})

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jinja2_sandbox_render_budget_exceeded" in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Template Sandbox Safety Probe"
        and check.status == CheckStatus.FAILED
        and check.details["template_location"].endswith(":tokenizer.chat_template")
        for check in direct.checks
    )
    _assert_inconclusive_exit2(aggregate, "jinja2_sandbox_render_budget_exceeded")


def test_gguf_scanner_preserves_duplicate_reason_with_oversized_chat_template(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-large-template.gguf"
    _write_gguf_string_metadata_entries(
        path,
        [
            ("tokenizer.chat_template", "{{ content }}" * 10000),
            ("tokenizer.chat_template", "{{ message['content'] }}"),
        ],
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    reasons = direct.metadata["scan_outcome_reasons"]
    assert GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON in reasons
    assert "jinja2_template_size_limit_exceeded" in reasons
    assert any(check.name == "Template Size Limit" and check.status == CheckStatus.FAILED for check in direct.checks)
    _assert_inconclusive_exit2(aggregate, GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON)
    assert "jinja2_template_size_limit_exceeded" in _single_file_metadata(aggregate)["scan_outcome_reasons"]


def test_gguf_oversized_chat_template_uncached_rerun_preserves_exit2(tmp_path: Path) -> None:
    path = create_mock_gguf(
        tmp_path / "large-template.gguf",
        metadata={"tokenizer.chat_template": "{{ content }}" * 10000},
    )

    _assert_uncached_rerun_preserves_inconclusive_exit2(
        path,
        tmp_path / "cache",
        "jinja2_template_size_limit_exceeded",
    )


def test_gguf_scanner_comprehensive_scan(tmp_path):
    """Test comprehensive GGUF scanning with tensors."""
    path = tmp_path / "model.gguf"
    _write_comprehensive_gguf(path)
    scanner = GgufScanner()
    result = scanner.scan(str(path))
    assert result.success
    assert result.metadata["n_tensors"] == 1
    assert len(result.metadata["tensors"]) == 1
    assert result.metadata["tensors"][0]["name"] == "weight"


def test_gguf_scanner_invalid_alignment_falls_back_to_default(tmp_path: Path) -> None:
    """Invalid alignment metadata should warn but still use the GGUF default."""
    path = tmp_path / "invalid_alignment.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 48))  # invalid: not a power of two

        name = b"weights8"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<Q", 8))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<Q", 0))

        pad_to_tensor_data = (32 - (f.tell() % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\0" * pad_to_tensor_data)
        f.write(b"\0" * 32)

    result = GgufScanner().scan(str(path))

    assert result.success
    assert len(result.metadata["tensors"]) == 1
    assert any(check.name == "GGUF Alignment Validation" and check.status.value == "failed" for check in result.checks)
    assert not any("size mismatch" in issue.message.lower() for issue in result.issues)


def test_gguf_scanner_large_kv_count(tmp_path: Path) -> None:
    """Test detection of suspiciously large KV counts."""
    path = tmp_path / "bad.gguf"
    _write_minimal_gguf(path, n_kv=2**31)
    result = GgufScanner().scan(str(path))
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "GGUF Metadata Resource Limits" and check.details["declared_metadata_keys"] == 2**31
        for check in result.checks
    )


def test_gguf_scanner_large_tensor_count(tmp_path: Path) -> None:
    """Test detection of suspiciously large tensor counts."""
    path = tmp_path / "bad.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 2**31))  # huge tensor count
        f.write(struct.pack("<Q", 0))  # kv count

    result = GgufScanner().scan(str(path))
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "GGUF Tensor Resource Limits" and check.details["declared_tensors"] == 2**31
        for check in result.checks
    )


def test_gguf_scanner_truncated_file(tmp_path: Path) -> None:
    """Test handling of truncated GGUF files."""
    path = tmp_path / "trunc.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", 5))  # Claims 5 KV pairs but file ends

    result = GgufScanner().scan(str(path))
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_gguf_truncated_metadata_returns_exit2(tmp_path: Path) -> None:
    path = tmp_path / "truncated_metadata.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", 5))

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path))
    metadata = next(iter(aggregate.file_metadata.values()))

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_PARSE_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert aggregate.success is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)


def test_gguf_truncated_metadata_uncached_rerun_preserves_exit2(
    tmp_path: Path,
) -> None:
    path = tmp_path / "truncated_metadata.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", 5))

    _assert_uncached_rerun_preserves_inconclusive_exit2(
        path,
        tmp_path / "cache",
        GGUF_PARSE_INCONCLUSIVE_REASON,
    )


def test_gguf_unknown_tensor_type_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "unknown_tensor_type.gguf"
    _write_gguf_with_tensor_type(path, tensor_type=999)

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path))

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_STRUCTURE_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    type_checks = [check for check in direct.checks if check.name == "Tensor Type Validation"]
    assert len(type_checks) == 1
    assert type_checks[0].status == CheckStatus.FAILED
    assert type_checks[0].details["tensor_type"] == 999
    assert type_checks[0].details["tensor_name"] == "unknown"
    assert any("unknown ggml type" in issue.message.lower() for issue in direct.issues)
    _assert_no_warning_or_critical_issues(direct)
    assert determine_exit_code(aggregate) == 2


def test_gguf_bf16_tensor_type_30_is_supported(tmp_path: Path) -> None:
    path = tmp_path / "bf16_tensor_type30.gguf"
    _write_gguf_with_tensor_type(
        path,
        tensor_type=30,
        tensor_name=b"bf16_weight",
        tensor_data_size=16,
    )

    result = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert result.success is True
    assert result.metadata["tensors"] == [{"name": "bf16_weight", "type": 30, "dims": [8]}]
    assert not any(check.name == "Tensor Type Validation" for check in result.checks)
    assert not any("unknown ggml type" in issue.message.lower() for issue in result.issues)
    assert not any(check.name == "Tensor Data Bounds Check" for check in result.checks)
    _assert_no_warning_or_critical_issues(result)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    ("tensor_type", "tensor_name", "tensor_data_size"),
    [
        (21, b"blk.0.ffn_down.weight.iq3_s", 110),
        (23, b"blk.0.ffn_up.weight.iq4_xs", 136),
    ],
)
def test_gguf_rank250_iq_tensor_types_are_supported(
    tmp_path: Path,
    tensor_type: int,
    tensor_name: bytes,
    tensor_data_size: int,
) -> None:
    path = tmp_path / f"rank250_type{tensor_type}.gguf"
    _write_gguf_with_tensor_type(
        path,
        tensor_type=tensor_type,
        tensor_name=tensor_name,
        dims=(256,),
        tensor_data_size=tensor_data_size,
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.success is True
    assert direct.metadata["tensors"] == [{"name": tensor_name.decode(), "type": tensor_type, "dims": [256]}]
    assert not any(check.name == "Tensor Type Validation" for check in direct.checks)
    assert not any("unknown ggml type" in issue.message.lower() for issue in direct.issues)
    assert not any(check.name == "Tensor Data Bounds Check" for check in direct.checks)
    _assert_no_warning_or_critical_issues(direct)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    ("tensor_type", "tensor_name", "expected_size"),
    [
        (21, b"iq3_s_truncated", 110),
        (23, b"iq4_xs_truncated", 136),
    ],
)
def test_gguf_rank250_iq_tensor_types_reach_bounds_validation(
    tmp_path: Path,
    tensor_type: int,
    tensor_name: bytes,
    expected_size: int,
) -> None:
    path = tmp_path / f"rank250_type{tensor_type}_truncated.gguf"
    _write_gguf_with_tensor_type(
        path,
        tensor_type=tensor_type,
        tensor_name=tensor_name,
        dims=(256,),
        tensor_data_size=expected_size - 1,
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert not any(check.name == "Tensor Type Validation" for check in direct.checks)
    bounds_checks = [check for check in direct.checks if check.name == "Tensor Data Bounds Check"]
    assert len(bounds_checks) == 1
    assert bounds_checks[0].status == CheckStatus.FAILED
    assert bounds_checks[0].details["tensor_name"] == tensor_name.decode()
    assert bounds_checks[0].details["expected"] == expected_size
    assert determine_exit_code(aggregate) == 1


def test_gguf_rank250_mixed_current_tensor_types_are_supported(tmp_path: Path) -> None:
    path = tmp_path / "rank250_current_types.gguf"
    _write_gguf_with_tensor_records(
        path,
        [
            (b"blk.0.attn_q.weight.iq3_s", 21, (256,), 110),
            (b"blk.0.attn_k.weight.iq4_xs", 23, (256,), 136),
            (b"blk.0.ffn_norm.weight.bf16", 30, (8,), 16),
        ],
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.success is True
    assert direct.metadata["tensors"] == [
        {"name": "blk.0.attn_q.weight.iq3_s", "type": 21, "dims": [256]},
        {"name": "blk.0.attn_k.weight.iq4_xs", "type": 23, "dims": [256]},
        {"name": "blk.0.ffn_norm.weight.bf16", "type": 30, "dims": [8]},
    ]
    assert not any(check.name == "Tensor Type Validation" for check in direct.checks)
    assert not any("unknown ggml type" in issue.message.lower() for issue in direct.issues)
    _assert_no_warning_or_critical_issues(direct)
    assert determine_exit_code(aggregate) == 0


def test_gguf_rank250_current_types_do_not_mask_unknown_future_type(tmp_path: Path) -> None:
    path = tmp_path / "rank250_current_plus_unknown.gguf"
    _write_gguf_with_tensor_records(
        path,
        [
            (b"blk.0.attn_q.weight.iq3_s", 21, (256,), 110),
            (b"blk.0.attn_k.weight.iq4_xs", 23, (256,), 136),
            (b"blk.0.ffn_norm.weight.bf16", 30, (8,), 16),
            (b"blk.0.future.weight", 999, (8,), 32),
        ],
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_STRUCTURE_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    type_checks = [check for check in direct.checks if check.name == "Tensor Type Validation"]
    assert len(type_checks) == 1
    assert type_checks[0].details["tensor_type"] == 999
    assert type_checks[0].details["tensor_name"] == "blk.0.future.weight"
    assert any("unknown ggml type 999" in issue.message.lower() for issue in direct.issues)
    _assert_no_warning_or_critical_issues(direct)
    assert determine_exit_code(aggregate) == 2


def test_gguf_bf16_truncated_tensor_data_reports_bounds_check(tmp_path: Path) -> None:
    path = tmp_path / "bf16_truncated_tensor_data.gguf"
    _write_gguf_with_tensor_type(
        path,
        tensor_type=30,
        tensor_name=b"bf16_truncated",
        tensor_data_size=8,
    )

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert not any(check.name == "Tensor Type Validation" for check in direct.checks)
    bounds_checks = [check for check in direct.checks if check.name == "Tensor Data Bounds Check"]
    assert len(bounds_checks) == 1
    assert bounds_checks[0].status == CheckStatus.FAILED
    assert bounds_checks[0].details["tensor_name"] == "bf16_truncated"
    assert bounds_checks[0].details["expected"] == 16
    assert determine_exit_code(aggregate) == 1


def test_gguf_truncated_tensor_dimensions_are_parse_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "truncated_tensor_dimensions.gguf"
    with path.open("wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))
        f.write(struct.pack("<Q", 0))
        name = b"truncated_dims"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 2))
        f.write(struct.pack("<Q", 8))

    direct = GgufScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_enabled=False)

    assert direct.success is False
    assert "tensors" not in direct.metadata
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert GGUF_PARSE_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    parse_checks = [check for check in direct.checks if check.name == "GGUF Tensor Parsing"]
    assert len(parse_checks) == 1
    assert parse_checks[0].status == CheckStatus.FAILED
    assert parse_checks[0].details["error_type"] in {"error", "ValueError"}
    _assert_no_warning_or_critical_issues(direct)
    _assert_inconclusive_exit2(aggregate, GGUF_PARSE_INCONCLUSIVE_REASON)


def test_gguf_unknown_tensor_type_uncached_rerun_preserves_exit2(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unknown_tensor_type.gguf"
    _write_gguf_with_tensor_type(path, tensor_type=999)

    _assert_uncached_rerun_preserves_inconclusive_exit2(
        path,
        tmp_path / "cache",
        GGUF_STRUCTURE_INCONCLUSIVE_REASON,
    )


def test_gguf_scanner_suspicious_key_paths(tmp_path):
    """Test detection of suspicious key names with path traversal."""
    path = tmp_path / "suspicious.gguf"
    _write_minimal_gguf(path, kv_key=b"../../../etc/passwd", kv_value=b"root")

    result = GgufScanner().scan(str(path))
    assert any("path traversal" in i.message.lower() for i in result.issues)


def test_gguf_scanner_suspicious_values(tmp_path):
    """Test detection of suspicious metadata values."""
    path = tmp_path / "suspicious.gguf"
    _write_minimal_gguf(path, kv_key=b"command", kv_value=b"rm -rf /")

    result = GgufScanner().scan(str(path))
    assert any("suspicious" in i.message.lower() for i in result.issues)


def test_gguf_scanner_string_length_security(tmp_path: Path) -> None:
    """Test security checks for string lengths."""
    path = tmp_path / "long_string.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count
        f.write(struct.pack("<Q", 2**31))  # extremely long key
        # File ends here, should trigger error

    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME


def test_ggml_scanner_basic(tmp_path):
    """Test basic GGML file scanning."""
    path = tmp_path / "model.ggml"
    _write_ggml_file(path)

    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["format"] == "ggml"
    assert result.metadata["version"] == 1


def test_ggml_variant_scanner_basic(tmp_path):
    """Ensure GGML variants are scanned correctly."""
    path = tmp_path / "model.ggmf"
    _write_ggml_variant_file(path, b"GGMF")
    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["format"] == "ggml"
    assert result.metadata.get("magic") == "GGMF"


def test_ggml_scanner_suspicious_version(tmp_path):
    """Test that GGML scanner handles unusual versions gracefully."""
    path = tmp_path / "unusual_version.ggml"
    with open(path, "wb") as f:
        f.write(b"GGML")
        f.write(struct.pack("<I", 99999))  # unusual but technically valid version
        f.write(b"\0" * 24)

    result = GgufScanner().scan(str(path))
    # Should parse successfully - version number is format validation, not a security issue
    assert result.success
    assert result.metadata["version"] == 99999


def test_ggml_scanner_truncated(tmp_path: Path) -> None:
    """Test handling of truncated GGML files."""
    path = tmp_path / "trunc.ggml"
    with open(path, "wb") as f:
        f.write(b"GGML")
        f.write(b"\0" * 10)  # Too short

    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME


def test_gguf_scanner_file_extensions(tmp_path):
    """Test that scanner handles different file extensions correctly."""
    # Test .gguf extension
    gguf_path = tmp_path / "model.gguf"
    _write_minimal_gguf(gguf_path)
    assert GgufScanner.can_handle(str(gguf_path))

    # Test .ggml extension
    ggml_path = tmp_path / "model.ggml"
    _write_ggml_file(ggml_path)
    assert GgufScanner.can_handle(str(ggml_path))

    # Test unsupported extension
    txt_path = tmp_path / "model.txt"
    with open(txt_path, "w") as f:
        f.write("not a model")
    assert not GgufScanner.can_handle(str(txt_path))


def test_gguf_scanner_metadata_types(tmp_path):
    """Test handling of different metadata value types."""
    path = tmp_path / "types.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 3))  # kv count

        # String value
        key1 = b"string_key"
        f.write(struct.pack("<Q", len(key1)))
        f.write(key1)
        f.write(struct.pack("<I", 8))  # STRING
        val1 = b"string_value"
        f.write(struct.pack("<Q", len(val1)))
        f.write(val1)

        # Int32 value
        key2 = b"int_key"
        f.write(struct.pack("<Q", len(key2)))
        f.write(key2)
        f.write(struct.pack("<I", 5))  # INT32
        f.write(struct.pack("<i", 42))

        # Float32 value
        key3 = b"float_key"
        f.write(struct.pack("<Q", len(key3)))
        f.write(key3)
        f.write(struct.pack("<I", 6))  # FLOAT32
        f.write(struct.pack("<f", 3.14))

    result = GgufScanner().scan(str(path))
    assert result.success
    assert "string_key" in result.metadata["metadata"]
    assert "int_key" in result.metadata["metadata"]
    assert "float_key" in result.metadata["metadata"]


def test_gguf_scanner_error_handling(tmp_path):
    """Test various error conditions."""
    scanner = GgufScanner()

    # Test non-existent file
    result = scanner.scan("non_existent_file.gguf")
    assert not result.success

    # Test directory instead of file
    dir_path = tmp_path / "not_a_file"
    dir_path.mkdir()
    result = scanner.scan(str(dir_path))
    assert not result.success


def test_gguf_scanner_invalid_tensor_dimensions(tmp_path: Path) -> None:
    """Test handling of tensors with invalid dimensions (regression test for dimension bug)."""
    path = tmp_path / "invalid_dims.gguf"
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 2))  # tensor count - two tensors to test both cases
        f.write(struct.pack("<Q", 1))  # kv count

        # Minimal metadata
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)

        # First tensor with invalid dimensions: [10, 0, 5] - has zero dimension
        name1 = b"tensor_with_zero"
        f.write(struct.pack("<Q", len(name1)))
        f.write(name1)
        f.write(struct.pack("<I", 3))  # 3 dimensions
        f.write(struct.pack("<Q", 10))  # first dimension
        f.write(struct.pack("<Q", 0))  # zero dimension (invalid!)
        f.write(struct.pack("<Q", 5))  # third dimension
        f.write(struct.pack("<I", 0))  # f32 tensor type
        offset1 = 100  # dummy offset
        f.write(struct.pack("<Q", offset1))

        # Second tensor with invalid dimensions: [10, -1, 5] - has negative dimension
        name2 = b"tensor_with_negative"
        f.write(struct.pack("<Q", len(name2)))
        f.write(name2)
        f.write(struct.pack("<I", 3))  # 3 dimensions
        f.write(struct.pack("<Q", 10))  # first dimension
        f.write(struct.pack("<q", -1))  # negative dimension (invalid!)
        f.write(struct.pack("<Q", 5))  # third dimension
        f.write(struct.pack("<I", 0))  # f32 tensor type
        offset2 = 200  # dummy offset
        f.write(struct.pack("<Q", offset2))

        # Align to 32 bytes for tensor data section
        pad2 = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad2)

        # Write dummy tensor data to reach the required file size
        # Need to write at least enough to cover offset2 + some data
        tensor_data_size = 300  # offset2 (200) + some extra
        f.write(b"\0" * tensor_data_size)

    result = GgufScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME

    # Should have warnings about both invalid dimensions
    warning_messages = [issue.message for issue in result.issues]

    # Check for zero dimension warning
    assert any("tensor_with_zero" in msg and "invalid dimension: 0" in msg for msg in warning_messages)

    # Check for negative dimension warning (the exact value depends on how it's interpreted)
    assert any("tensor_with_negative" in msg and "invalid dimension" in msg for msg in warning_messages)

    # Should have exactly 2 warnings (one for each invalid dimension)
    dimension_warnings = [msg for msg in warning_messages if "invalid dimension" in msg]
    assert len(dimension_warnings) == 2

    # Verify that tensors metadata is still populated (shows parsing continued)
    assert "tensors" in result.metadata
    assert len(result.metadata["tensors"]) == 2


def test_gguf_scanner_without_alignment_metadata(tmp_path):
    """Test GGUF files without general.alignment metadata (real-world case)."""
    path = tmp_path / "no_alignment.gguf"
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Metadata WITHOUT general.alignment (like real llama.cpp files)
        key = b"test.key"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 5))  # INT32
        f.write(struct.pack("<i", 42))

        # No padding - tensor info starts immediately
        # Tensor info
        name = b"weight"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))  # dimensions
        f.write(struct.pack("<Q", 8))  # dimension size
        f.write(struct.pack("<I", 0))  # f32 tensor type

        # Calculate tensor data offset (relative to tensor data section)
        # Tensor data section starts after this tensor info with default 32-byte alignment
        tensor_info_end = f.tell() + 8  # +8 for offset field we're about to write
        pad_to_tensor_data = (32 - (tensor_info_end % 32)) % 32
        offset = 0  # First tensor starts at offset 0 in tensor data section
        f.write(struct.pack("<Q", offset))

        # Add padding to align tensor data section
        if pad_to_tensor_data:
            f.write(b"\x00" * pad_to_tensor_data)

        # Tensor data (8 * 4 bytes for f32)
        f.write(b"\x00" * 32)

    result = GgufScanner().scan(str(path))
    assert result.success
    assert len(result.metadata["tensors"]) == 1
    assert not any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_gguf_scanner_tensor_size_validation(tmp_path):
    """Test that tensor size consistency checking works correctly."""
    path = tmp_path / "tensor_sizes.gguf"
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 2))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Metadata with alignment
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\x00" * pad)

        # Tensor 1: f32 tensor with 8 elements = 32 bytes
        name1 = b"tensor1"
        f.write(struct.pack("<Q", len(name1)))
        f.write(name1)
        f.write(struct.pack("<I", 1))  # dimensions
        f.write(struct.pack("<Q", 8))  # dimension size
        f.write(struct.pack("<I", 0))  # f32 tensor type
        f.write(struct.pack("<Q", 0))  # offset 0

        # Tensor 2: f32 tensor with 16 elements = 64 bytes
        name2 = b"tensor2"
        f.write(struct.pack("<Q", len(name2)))
        f.write(name2)
        f.write(struct.pack("<I", 1))  # dimensions
        f.write(struct.pack("<Q", 16))  # dimension size
        f.write(struct.pack("<I", 0))  # f32 tensor type
        # Offset 32 + 16 bytes padding = 48 (aligned to 32 bytes: next multiple of 32 after 32)
        f.write(struct.pack("<Q", 32))  # offset 32 (no padding needed as 32 is aligned)

        # Align tensor data section to 32 bytes
        tensor_info_end = f.tell()
        pad_to_tensor_data = (32 - (tensor_info_end % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\x00" * pad_to_tensor_data)

        # Tensor 1 data (32 bytes)
        f.write(b"\x00" * 32)

        # Tensor 2 data (64 bytes)
        f.write(b"\x00" * 64)

    result = GgufScanner().scan(str(path))
    assert result.success
    assert len(result.metadata["tensors"]) == 2
    # Should not have size mismatch warnings (within alignment tolerance)
    size_warnings = [i for i in result.issues if "size mismatch" in i.message.lower()]
    assert len(size_warnings) == 0


def test_gguf_scanner_tensor_bounds_detects_uint64_wrap(tmp_path: Path) -> None:
    """Tensor offsets must not wrap or point outside the file."""
    path = tmp_path / "tensor_bounds_wrap.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))
        f.write(struct.pack("<Q", 0))

        name = b"wrap_tensor"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<Q", 8))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<Q", 2**64 - 16))

        pad_to_tensor_data = (32 - (f.tell() % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\x00" * pad_to_tensor_data)
        f.write(b"\x00" * 32)

    result = GgufScanner().scan(str(path))

    bounds_checks = [check for check in result.checks if check.name == "Tensor Data Bounds Check"]
    assert len(bounds_checks) == 1
    assert bounds_checks[0].status.value == "failed"
    assert bounds_checks[0].details["offset_overflows_uint64"] is True
    assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)


def test_gguf_scanner_tensor_bounds_allows_exact_file_end(tmp_path: Path) -> None:
    """A tensor may end exactly at EOF when its offset and expected size fit."""
    path = tmp_path / "tensor_bounds_exact_end.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))
        f.write(struct.pack("<Q", 0))

        name = b"offset_tensor"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<Q", 8))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<Q", 32))

        pad_to_tensor_data = (32 - (f.tell() % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\x00" * pad_to_tensor_data)
        f.write(b"\x00" * 32)
        f.write(b"\x00" * 32)

    result = GgufScanner().scan(str(path))

    assert result.success
    assert not any(check.name == "Tensor Data Bounds Check" for check in result.checks)
    assert not any("size mismatch" in issue.message.lower() for issue in result.issues)


def test_gguf_scanner_last_tensor_size(tmp_path):
    """Test that the last tensor's size is calculated correctly using file size."""
    path = tmp_path / "last_tensor.gguf"
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Metadata with alignment
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\x00" * pad)

        # Tensor: f32 tensor with 128 elements = 512 bytes
        name = b"last_tensor"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))  # dimensions
        f.write(struct.pack("<Q", 128))  # dimension size
        f.write(struct.pack("<I", 0))  # f32 tensor type
        f.write(struct.pack("<Q", 0))  # offset 0

        # Align tensor data section to 32 bytes
        tensor_info_end = f.tell()
        pad_to_tensor_data = (32 - (tensor_info_end % 32)) % 32
        if pad_to_tensor_data:
            f.write(b"\x00" * pad_to_tensor_data)

        # Tensor data (512 bytes) - this is the last tensor, size should be calculated from file size
        f.write(b"\x00" * 512)

    result = GgufScanner().scan(str(path))
    assert result.success
    assert len(result.metadata["tensors"]) == 1
    # Should not have size mismatch warnings
    size_warnings = [i for i in result.issues if "size mismatch" in i.message.lower()]
    assert len(size_warnings) == 0
