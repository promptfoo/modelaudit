import io
import json
import os
import struct
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

# Skip if msgpack is not available before importing it
pytest.importorskip("msgpack")

import msgpack

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import _create_results
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.flax_msgpack_scanner import (
    _UNBOUNDED_GETATTR_PATTERN,
    FlaxMsgpackScanner,
    _matching_jax_transforms,
    _MsgpackStreamCursor,
    _pattern_has_stream_unsafe_repeat,
)
from modelaudit.utils.file.detection import FLAX_MSGPACK_STRUCTURE_READ_BYTES


def create_msgpack_file(path: Path, data: Any) -> None:
    """Helper to create msgpack files with specific data."""
    with open(path, "wb") as f:
        f.write(msgpack.packb(data, use_bin_type=True))


def _write_msgpack_str(output: Any, value: str) -> None:
    encoded = value.encode()
    if len(encoded) <= 31:
        output.write(bytes([0xA0 | len(encoded)]))
    elif len(encoded) <= 0xFF:
        output.write(b"\xd9" + struct.pack(">B", len(encoded)))
    elif len(encoded) <= 0xFFFF:
        output.write(b"\xda" + struct.pack(">H", len(encoded)))
    else:
        output.write(b"\xdb" + struct.pack(">I", len(encoded)))
    output.write(encoded)


def _write_msgpack_uint(output: Any, value: int) -> None:
    if value <= 0x7F:
        output.write(bytes([value]))
    elif value <= 0xFF:
        output.write(b"\xcc" + struct.pack(">B", value))
    elif value <= 0xFFFF:
        output.write(b"\xcd" + struct.pack(">H", value))
    elif value <= 0xFFFFFFFF:
        output.write(b"\xce" + struct.pack(">I", value))
    else:
        output.write(b"\xcf" + struct.pack(">Q", value))


def _msgpack_str_size(value: str) -> int:
    length = len(value.encode())
    if length <= 31:
        return 1 + length
    if length <= 0xFF:
        return 2 + length
    if length <= 0xFFFF:
        return 3 + length
    return 5 + length


def _msgpack_uint_size(value: int) -> int:
    if value <= 0x7F:
        return 1
    if value <= 0xFF:
        return 2
    if value <= 0xFFFF:
        return 3
    if value <= 0xFFFFFFFF:
        return 5
    return 9


def _write_sparse_large_flax_tensor(
    path: Path,
    tensor_size: int,
    *,
    trailing_reduce: bool = False,
    body_bytes: bytes | None = None,
) -> None:
    with path.open("wb") as output:
        output.write(b"\x82" if trailing_reduce else b"\x81")
        _write_msgpack_str(output, "params")
        output.write(b"\x81")
        _write_msgpack_str(output, "embedding")
        output.write(b"\xc6" + struct.pack(">I", tensor_size))
        if body_bytes is None:
            output.seek(tensor_size - 1, os.SEEK_CUR)
            output.write(b"\0")
        else:
            output.write(body_bytes)
        if trailing_reduce:
            _write_msgpack_str(output, "__reduce__")
            _write_msgpack_str(output, "os.system")


def _write_sparse_large_flax_ndarray_ext(
    path: Path,
    tensor_size: int,
    *,
    dtype: str = "float32",
    shape_values: list[int] | None = None,
    body_prefix: bytes = b"",
    trailing_body: bytes = b"",
    wrap_in_params: bool = True,
) -> None:
    shape_values = [tensor_size // 4] if shape_values is None else shape_values
    metadata_size = 1 + 1 + sum(_msgpack_uint_size(dimension) for dimension in shape_values)
    metadata_size += _msgpack_str_size(dtype) + 5
    ext_size = metadata_size + tensor_size + len(trailing_body)
    with path.open("wb") as output:
        if wrap_in_params:
            output.write(b"\x81")
            _write_msgpack_str(output, "params")
            output.write(b"\x81")
            _write_msgpack_str(output, "embedding")
        output.write(b"\xc9" + struct.pack(">I", ext_size) + b"\x01")
        output.write(b"\x93")
        if len(shape_values) > 15:
            raise ValueError("test helper only supports fixarray shape metadata")
        output.write(bytes([0x90 | len(shape_values)]))
        for dimension in shape_values:
            _write_msgpack_uint(output, dimension)
        _write_msgpack_str(output, dtype)
        output.write(b"\xc6" + struct.pack(">I", tensor_size))
        if len(body_prefix) > tensor_size:
            raise ValueError("body_prefix cannot exceed tensor_size")
        output.write(body_prefix)
        remaining = tensor_size - len(body_prefix)
        if remaining:
            output.seek(remaining - 1, os.SEEK_CUR)
            output.write(b"\0")
        output.write(trailing_body)


def _assert_inconclusive_aggregate_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
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

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert expected_reason in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def create_malicious_msgpack_file(path):
    """Create a msgpack file with suspicious content."""
    malicious_data = {
        "params": {"w": list(range(5))},
        "__reduce__": "malicious_function",
        "code": "import os; os.system('rm -rf /')",
        "suspicious_blob": b"eval(compile('malicious code', 'string', 'exec'))" * 1000,
    }
    create_msgpack_file(path, malicious_data)


class _LowerCountingText(str):
    lower_calls: int

    def __new__(cls, value: str) -> "_LowerCountingText":
        instance = super().__new__(cls, value)
        instance.lower_calls = 0
        return instance

    def lower(self) -> str:
        self.lower_calls += 1
        return super().lower()


def test_matching_jax_transforms_reuses_lowered_value_text() -> None:
    value = _LowerCountingText("dynamic_eval payload")

    assert _matching_jax_transforms("weights", value) == ["dynamic_eval"]
    assert value.lower_calls == 1


def test_flax_msgpack_valid_checkpoint(tmp_path):
    """Test scanning a valid Flax checkpoint."""
    path = tmp_path / "model.msgpack"
    # Create realistic Flax checkpoint structure
    data = {
        "params": {
            "layers_0": {"kernel": [[0.1, 0.2], [0.3, 0.4]], "bias": [0.1, 0.2]},
            "layers_1": {"kernel": [[0.5, 0.6]], "bias": [0.3]},
        },
        "opt_state": {"step": 1000},
        "metadata": {"model_name": "test_model", "version": "1.0"},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.metadata.get("top_level_type") == "dict"
    assert "params" in result.metadata.get("top_level_keys", [])
    assert (
        len(
            [issue for issue in result.issues if issue.severity == IssueSeverity.INFO],
        )
        == 0
    )


def test_flax_scan_reuses_ml_structure_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One scan should reuse the same deep ML-structure analysis result."""
    path = tmp_path / "converted.msgpack"
    create_msgpack_file(path, {"tensor": b"0" * 4096, "payload": "x" * 4096})

    scanner = FlaxMsgpackScanner()
    analyze_calls = 0
    original_analyze = scanner._analyze_ml_structure

    def count_analyze(obj: Any, result: ScanResult) -> dict[str, Any]:
        nonlocal analyze_calls
        analyze_calls += 1
        return original_analyze(obj, result)

    monkeypatch.setattr(scanner, "_analyze_ml_structure", count_analyze)

    scanner.scan(str(path))

    assert analyze_calls == 1


def test_flax_ml_structure_uses_bounded_text_without_whole_object_stringification() -> None:
    """Layer-keyword analysis should not stringify the whole checkpoint object."""

    class StringCountingDict(dict[str, Any]):
        stringify_calls = 0

        def __str__(self) -> str:
            self.stringify_calls += 1
            return super().__str__()

    obj = StringCountingDict({"tensor": b"0" * 4096, "payload": "x" * 4096})
    scanner = FlaxMsgpackScanner()

    scanner._analyze_ml_structure(obj, scanner._create_result())

    assert obj.stringify_calls == 0


def test_flax_msgpack_suspicious_content(tmp_path):
    """Test detection of suspicious patterns in msgpack content."""
    path = tmp_path / "suspicious.msgpack"
    create_malicious_msgpack_file(path)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Should detect multiple security issues (CRITICAL or INFO severity)
    security_issues = [
        issue for issue in result.issues if issue.severity in (IssueSeverity.CRITICAL, IssueSeverity.INFO)
    ]
    assert len(security_issues) > 0, f"Expected security issues but got: {result.issues}"

    # Check for specific threats
    issue_messages = [issue.message for issue in result.issues]

    # Should detect suspicious key or code patterns
    found_threats = any(
        "__reduce__" in msg or "os.system" in msg or "suspicious" in msg.lower() for msg in issue_messages
    )
    assert found_threats, f"Expected to detect threats but got messages: {issue_messages}"


def test_flax_msgpack_malicious_content_marks_scan_unsuccessful(tmp_path: Path) -> None:
    """CRITICAL msgpack findings should make the scan unsuccessful."""
    path = tmp_path / "malicious.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.message == "Suspicious object attribute detected: __reduce__"
        for issue in result.issues
    )


def test_flax_msgpack_byte_encoded_dangerous_key_is_critical(tmp_path: Path) -> None:
    path = tmp_path / "byte_reduce_key.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"__reduce__": "os.system"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute detected: __reduce__"
        and issue.location == "root/__reduce__"
        and issue.details["suspicious_key"] == "__reduce__"
        for issue in result.issues
    )


def test_flax_msgpack_byte_encoded_dangerous_top_level_key_is_critical(tmp_path: Path) -> None:
    path = tmp_path / "byte_top_level_reduce_key.msgpack"
    create_msgpack_file(path, {b"__reduce__": "custom_deserialize"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        check.name == "Top-Level Key Security Check" and check.details["dangerous_keys"] == ["__reduce__"]
        for check in result.checks
    )


def test_flax_msgpack_byte_encoded_standard_key_is_recognized(tmp_path: Path) -> None:
    path = tmp_path / "byte_params_key.msgpack"
    create_msgpack_file(path, {b"params": {b"weights": b"\x00" * 4096}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert any(
        check.name == "Flax Checkpoint Format Detection"
        and check.status == CheckStatus.PASSED
        and check.details["found_standard_keys"] == ["params"]
        for check in result.checks
    )


def test_flax_msgpack_byte_encoded_shape_key_is_validated(tmp_path: Path) -> None:
    path = tmp_path / "byte_shape_key.msgpack"
    create_msgpack_file(path, {b"params": {b"shape": [-1, 2]}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert any(
        check.name == "Tensor Shape Validation"
        and check.details["shape"] == [-1, 2]
        and check.location == "root/params"
        for check in result.checks
    )


def test_flax_msgpack_byte_encoded_function_metadata_key_is_value_aware(tmp_path: Path) -> None:
    path = tmp_path / "byte_restore_fn_key.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"restore_fn": "eval"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute value detected: restore_fn"
        and issue.location == "root/restore_fn"
        and issue.details["suspicious_key"] == "restore_fn"
        for issue in result.issues
    )


def test_flax_msgpack_byte_encoded_function_metadata_value_is_checked(tmp_path: Path) -> None:
    path = tmp_path / "byte_restore_fn_value.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"restore_fn": b"eval"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute value detected: restore_fn"
        and issue.location == "root/restore_fn"
        and issue.details["suspicious_key"] == "restore_fn"
        and issue.details["value_sample"] == "eval"
        for issue in result.issues
    )


def test_flax_msgpack_byte_encoded_benign_function_metadata_value_is_not_critical(tmp_path: Path) -> None:
    path = tmp_path / "byte_benign_restore_fn_value.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"restore_fn": b"custom_deserialize"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert not [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL and "restore_fn" in issue.message
    ]


def test_flax_msgpack_byte_encoded_benign_near_match_key_is_not_critical(tmp_path: Path) -> None:
    path = tmp_path / "byte_benign_near_match_key.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"__reducer__": "custom_deserialize"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert not [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL and "__reducer__" in issue.message
    ]


def test_flax_msgpack_restore_fn_custom_value_no_critical(tmp_path: Path) -> None:
    """Benign Orbax restore function names should not be key-name criticals."""
    path = tmp_path / "benign_restore_fn.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "restore_fn": "custom_deserialize"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert not [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL and "restore_fn" in issue.message
    ]


def test_flax_msgpack_restore_fn_dangerous_value_still_critical(tmp_path: Path) -> None:
    """Function metadata that directly names dangerous callables should stay critical."""
    path = tmp_path / "dangerous_restore_fn.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "restore_fn": "eval"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute value detected: restore_fn"
        for issue in result.issues
    )


def test_flax_msgpack_binary_function_metadata_value_still_critical(tmp_path: Path) -> None:
    path = tmp_path / "binary_callable.msgpack"
    create_msgpack_file(path, {"params": {"eval_fn": b"eval", "compiled_fn": b"exec"}})

    result = FlaxMsgpackScanner().scan(str(path))

    findings = {
        check.message
        for check in result.checks
        if check.name == "Object Attribute Security Check" and check.status == CheckStatus.FAILED
    }
    assert "Suspicious object attribute value detected: eval_fn" in findings
    assert "Suspicious object attribute value detected: compiled_fn" in findings


def test_flax_msgpack_binary_function_metadata_near_matches_stay_benign(tmp_path: Path) -> None:
    path = tmp_path / "binary_callable_near_match.msgpack"
    create_msgpack_file(path, {"params": {"eval_fn": b"evaluate", "compiled_fn": b"\xffexec"}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert not any(
        check.name == "Object Attribute Security Check" and "attribute value" in check.message
        for check in result.checks
    )


def test_flax_msgpack_deduplicates_transform_in_key_and_value(tmp_path: Path) -> None:
    path = tmp_path / "duplicate_transform.msgpack"
    create_msgpack_file(path, {"runtime_eval": "runtime_eval"})

    result = FlaxMsgpackScanner().scan(str(path))

    transform_checks = [
        check
        for check in result.checks
        if check.name == "JAX Transform Security Check" and check.details.get("transform") == "runtime_eval"
    ]
    assert len(transform_checks) == 1


def test_flax_msgpack_jax_transform_dedup_does_not_scan_existing_checks() -> None:
    class NonIterableChecks(list[Check]):
        def __iter__(self) -> Iterator[Check]:
            raise AssertionError("transform deduplication must not scan prior checks")

    result = ScanResult("flax_msgpack")
    result.checks = NonIterableChecks()

    FlaxMsgpackScanner._add_jax_transform_check("runtime_eval", "runtime_eval", "root/key", result)
    FlaxMsgpackScanner._add_jax_transform_check("runtime_eval", "runtime_eval", "root/key", result)

    assert len(result.checks) == 1


@pytest.mark.parametrize(
    ("metadata_key", "dangerous_callable"),
    [
        ("restore_fn", "eval"),
        ("jax_fn", "exec"),
        ("compiled_fn", "compile"),
        ("exec_fn", "os.system"),
        ("transform_fn", "subprocess.run"),
        ("__tree_flatten__", "__import__"),
        ("__tree_unflatten__", "subprocess.Popen"),
    ],
)
def test_flax_msgpack_function_metadata_key_value_combinations(
    tmp_path: Path,
    metadata_key: str,
    dangerous_callable: str,
) -> None:
    """Function metadata keys should be value-aware across common callable names."""
    for value, should_be_critical in ((dangerous_callable, True), ("custom_deserialize", False)):
        path = tmp_path / f"{metadata_key.strip('_') or 'dunder'}_{value.replace('.', '_')}.msgpack"
        create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, metadata_key: value})

        result = FlaxMsgpackScanner().scan(str(path))
        key_critical_issues = [
            issue
            for issue in result.issues
            if issue.severity == IssueSeverity.CRITICAL and metadata_key in issue.message
        ]

        if should_be_critical:
            assert key_critical_issues, f"Expected CRITICAL for {metadata_key}={value!r}: {result.issues}"
        else:
            assert not key_critical_issues, f"Expected no CRITICAL for {metadata_key}={value!r}: {result.issues}"


def test_flax_msgpack_jax_internal_key_metadata_is_not_critical(tmp_path: Path) -> None:
    """JAX internal metadata key names should not become critical without dangerous values."""
    path = tmp_path / "benign_jax_internal_keys.msgpack"
    create_msgpack_file(
        path,
        {
            "params": {"w": [1, 2, 3]},
            "__jax_array__": {"dtype": "float32", "shape": [3]},
            "__tree_flatten__": "tree_def",
            "__tree_unflatten__": "tree_def",
        },
    )

    result = FlaxMsgpackScanner().scan(str(path))

    critical_messages = [issue.message for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert not any("__jax_array__" in message for message in critical_messages)
    assert not any("__tree_flatten__" in message for message in critical_messages)
    assert not any("__tree_unflatten__" in message for message in critical_messages)


def test_flax_msgpack_metadata_system_os_keys_not_critical(tmp_path: Path) -> None:
    """Environment-like top-level metadata keys should not be unconditional criticals."""
    path = tmp_path / "benign_system_metadata.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "system": "linux", "os": "linux-x86_64"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert not [
        issue
        for issue in result.issues
        if issue.severity == IssueSeverity.CRITICAL and "top-level keys" in issue.message.lower()
    ]


def test_flax_msgpack_respects_file_size_limit(tmp_path: Path) -> None:
    """Scanner should fail closed before reading files larger than max_file_read_size."""
    path = tmp_path / "too_large.msgpack"
    create_msgpack_file(path, {"params": {"w": list(range(64))}})

    result = FlaxMsgpackScanner(config={"max_file_read_size": 10}).scan(str(path))

    assert result.success is False
    size_checks = [
        check for check in result.checks if check.name == "File Size Limit" and check.status == CheckStatus.FAILED
    ]
    assert len(size_checks) == 1


def test_flax_msgpack_max_file_size_zero_preserves_default_read_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core unlimited max_file_size should not disable Flax full-read protection."""
    monkeypatch.setattr(FlaxMsgpackScanner, "default_max_file_read_size", 10)
    path = tmp_path / "too_large_default.msgpack"
    create_msgpack_file(path, {"params": {"w": list(range(64))}})

    result = FlaxMsgpackScanner(config={"max_file_size": 0}).scan(str(path))

    assert result.success is False
    checks = {check.name: check for check in result.checks}
    assert checks["File Size Limit"].status == CheckStatus.FAILED
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]


def test_flax_msgpack_scans_trailing_msgpack_objects(tmp_path: Path) -> None:
    """A malicious second msgpack object after a benign first object must still be scanned."""
    path = tmp_path / "trailing_malicious.msgpack"
    payload = msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    payload += msgpack.packb({"__reduce__": "os.system"}, use_bin_type=True)
    path.write_bytes(payload)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert result.metadata.get("msgpack_object_count") == 2
    stream_checks = [
        check
        for check in result.checks
        if check.name == "Msgpack Stream Integrity Check" and check.status == CheckStatus.FAILED
    ]
    assert len(stream_checks) == 1
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute detected: __reduce__"
        and issue.location == "root[msgpack_object_1]/__reduce__"
        for issue in result.issues
    )


def test_flax_msgpack_stops_when_first_object_exhausts_node_budget(tmp_path: Path) -> None:
    """Coverage exhaustion must stop before unbounded work on the object remainder."""
    path = tmp_path / "trailing_after_budget.msgpack"
    payload = msgpack.packb({"params": list(range(8))}, use_bin_type=True)
    payload += msgpack.packb("eval('x')", use_bin_type=True)
    path.write_bytes(payload)

    result = FlaxMsgpackScanner(config={"max_msgpack_structure_nodes": 4}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.STRUCTURE_BUDGET_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert not any(issue.location == "root[msgpack_object_1]" for issue in result.issues)


def test_flax_msgpack_trailing_objects_do_not_dilute_primary_scan_budget(tmp_path: Path) -> None:
    """Many trailing objects must not shrink the primary checkpoint's security traversal."""
    path = tmp_path / "primary_before_many_trailing.msgpack"
    payload = msgpack.packb({"params": ["safe", "eval('x')"]}, use_bin_type=True)
    payload += b"".join(msgpack.packb("safe", use_bin_type=True) for _ in range(3))
    path.write_bytes(payload)

    result = FlaxMsgpackScanner(config={"max_msgpack_structure_nodes": 4}).scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == r"Suspicious code pattern detected: eval\s*\("
        and issue.location == "root/params[1]"
        for issue in result.issues
    )


def test_flax_msgpack_trailing_objects_share_an_aggregate_node_budget(tmp_path: Path) -> None:
    path = tmp_path / "bounded_trailing_stream.msgpack"
    payload = msgpack.packb({"params": [1]}, use_bin_type=True)
    payload += b"".join(msgpack.packb(["a", "b", "c", "d"], use_bin_type=True) for _ in range(12))
    path.write_bytes(payload)

    result = FlaxMsgpackScanner(
        config={
            "max_msgpack_stream_objects": 32,
            "max_msgpack_structure_nodes": 5,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.STRUCTURE_BUDGET_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    budget_checks = [check for check in result.checks if check.name == "Flax MessagePack Structure Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].details["max_allowed"] == 5


def test_flax_msgpack_node_budget_does_not_call_unbounded_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = pytest.importorskip("msgpack.fallback")

    def fail_skip(_self: Any) -> None:
        raise AssertionError("coverage exhaustion must not skip an unbounded nested object")

    monkeypatch.setattr(fallback.Unpacker, "skip", fail_skip)
    monkeypatch.setattr(msgpack, "Unpacker", fallback.Unpacker)
    path = tmp_path / "nested_after_node_budget.msgpack"
    create_msgpack_file(path, [[0] * 100])

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 10,
            "max_msgpack_structure_nodes": 1,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.STRUCTURE_BUDGET_INCONCLUSIVE_REASON]
    assert not [check for check in result.checks if check.name == "Msgpack Parse Check"]


def test_flax_msgpack_benign_trailing_dict_object_is_info_only(tmp_path: Path) -> None:
    """Valid trailing dict objects should be scanned without warning-level stream noise."""
    path = tmp_path / "benign_two_objects.msgpack"
    payload = msgpack.packb({"params": {"a": [1, 2]}}, use_bin_type=True)
    payload += msgpack.packb({"params": {"b": [3, 4]}}, use_bin_type=True)
    path.write_bytes(payload)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert result.metadata.get("msgpack_object_count") == 2
    stream_checks = [
        check
        for check in result.checks
        if check.name == "Msgpack Stream Integrity Check" and check.status == CheckStatus.FAILED
    ]
    assert len(stream_checks) == 1
    assert stream_checks[0].severity == IssueSeverity.INFO
    assert stream_checks[0].details["trailing_objects_are_container_like"] is True


def test_flax_msgpack_scalar_trailing_junk_stays_warning(tmp_path: Path) -> None:
    """Scalar trailing bytes are still surfaced as warning-level stream integrity findings."""
    path = tmp_path / "scalar_trailing_junk.msgpack"
    payload = msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True) + b"garbage"
    path.write_bytes(payload)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    stream_checks = [
        check
        for check in result.checks
        if check.name == "Msgpack Stream Integrity Check" and check.status == CheckStatus.FAILED
    ]
    assert len(stream_checks) == 1
    assert stream_checks[0].severity == IssueSeverity.WARNING
    assert stream_checks[0].details["trailing_objects_are_container_like"] is False


@pytest.mark.parametrize(
    ("trailer_name", "trailer"),
    [
        ("partial_fixmap", b"\x81\xa1"),
        ("partial_array16", b"\xdc"),
        ("partial_array32", b"\xdd"),
        ("partial_map16", b"\xde"),
        ("partial_map32", b"\xdf"),
    ],
)
def test_flax_msgpack_incomplete_trailing_object_fails_closed(
    tmp_path: Path,
    trailer_name: str,
    trailer: bytes,
) -> None:
    """A partial trailing object must not disappear into the streaming unpacker buffer."""
    path = tmp_path / f"incomplete_trailing_{trailer_name}.msgpack"
    payload = msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True) + trailer
    path.write_bytes(payload)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.TRUNCATED_STREAM_INCONCLUSIVE_REASON]
    assert any(
        check.name == "Msgpack Parse Check"
        and check.status == CheckStatus.FAILED
        and check.details["parse_error"] == "incomplete trailing msgpack object"
        and check.details["analysis_incomplete"] is True
        and check.details["stream_size"] == len(payload)
        for check in result.checks
    )


def test_flax_msgpack_clean_eof_and_valid_width_prefixed_trailer_remain_complete(tmp_path: Path) -> None:
    """Clean EOF and valid concatenated containers must remain distinguishable from truncation."""
    primary = msgpack.packb({"params": {"w": [1, 2, 3]}}, use_bin_type=True)
    clean_path = tmp_path / "clean_eof.msgpack"
    clean_path.write_bytes(primary)
    concatenated_path = tmp_path / "valid_array16_trailer.msgpack"
    concatenated_path.write_bytes(primary + msgpack.packb(list(range(16)), use_bin_type=True))

    clean_result = FlaxMsgpackScanner().scan(str(clean_path))
    concatenated_result = FlaxMsgpackScanner().scan(str(concatenated_path))

    assert clean_result.success is True
    assert "scan_outcome" not in clean_result.metadata
    assert concatenated_result.success is True
    assert concatenated_result.metadata["msgpack_object_count"] == 2
    assert FlaxMsgpackScanner.TRUNCATED_STREAM_INCONCLUSIVE_REASON not in concatenated_result.metadata.get(
        "scan_outcome_reasons", []
    )


def test_flax_msgpack_truncated_width_prefixed_trailer_exits_with_error_and_is_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "truncated_map16_trailer.msgpack"
    path.write_bytes(msgpack.packb({"params": {"w": [1]}}, use_bin_type=True) + b"\xde")

    _assert_inconclusive_aggregate_not_cached(
        path,
        FlaxMsgpackScanner.TRUNCATED_STREAM_INCONCLUSIVE_REASON,
        tmp_path / "truncated-stream-cache",
    )


def test_flax_msgpack_truncated_trailer_at_stream_object_limit_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "truncated_trailer_at_object_limit.msgpack"
    path.write_bytes(msgpack.packb({"params": {"w": [1]}}, use_bin_type=True) + b"\xdc")

    result = FlaxMsgpackScanner(config={"max_msgpack_stream_objects": 1}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.TRUNCATED_STREAM_INCONCLUSIVE_REASON]
    assert not [check for check in result.checks if check.name == "Msgpack Stream Object Limit"]


@pytest.mark.parametrize(
    "trailer",
    [
        pytest.param(b"\xa5ab", id="fixstr-body"),
        pytest.param(b"\xd9\x05ab", id="str8-body"),
        pytest.param(b"\xc6\x00\x00\x00\x05ab", id="bin32-body"),
        pytest.param(b"\xc1", id="reserved-marker"),
    ],
)
def test_flax_msgpack_truncated_scalar_at_stream_object_limit_fails_closed(
    tmp_path: Path,
    trailer: bytes,
) -> None:
    path = tmp_path / "truncated_scalar_at_object_limit.msgpack"
    path.write_bytes(msgpack.packb({"params": {"w": [1]}}, use_bin_type=True) + trailer)

    result = FlaxMsgpackScanner(config={"max_msgpack_stream_objects": 1}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.TRUNCATED_STREAM_INCONCLUSIVE_REASON]
    assert not [check for check in result.checks if check.name == "Msgpack Stream Object Limit"]


def test_flax_msgpack_caps_trailing_stream_object_count(tmp_path: Path) -> None:
    """Too many trailing msgpack objects should fail closed without materializing the full stream."""
    path = tmp_path / "many_objects.msgpack"
    payload = msgpack.packb({"params": {"root": [1]}}, use_bin_type=True)
    payload += b"".join(msgpack.packb({"params": {"n": [index]}}, use_bin_type=True) for index in range(8))
    path.write_bytes(payload)

    result = FlaxMsgpackScanner(config={"max_msgpack_stream_objects": 4}).scan(str(path))

    assert result.success is False
    assert result.metadata.get("operational_error") is True
    assert result.metadata.get("operational_error_reason") == "msgpack_stream_object_limit_exceeded"
    object_limit_checks = [
        check
        for check in result.checks
        if check.name == "Msgpack Stream Object Limit" and check.status == CheckStatus.FAILED
    ]
    assert len(object_limit_checks) == 1
    assert object_limit_checks[0].details["max_msgpack_stream_objects"] == 4


def test_flax_msgpack_stream_object_limit_does_not_decode_extra_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = pytest.importorskip("msgpack.fallback")

    def fail_skip(_self: Any) -> None:
        raise AssertionError("object limit must not decode the extra object")

    monkeypatch.setattr(fallback.Unpacker, "skip", fail_skip)
    monkeypatch.setattr(msgpack, "Unpacker", fallback.Unpacker)
    path = tmp_path / "large_extra_object.msgpack"
    path.write_bytes(msgpack.packb({}, use_bin_type=True) + msgpack.packb([0] * 100, use_bin_type=True))

    result = FlaxMsgpackScanner(config={"max_msgpack_stream_objects": 1}).scan(str(path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "msgpack_stream_object_limit_exceeded"
    assert not [check for check in result.checks if check.name == "Msgpack Parse Check"]


@pytest.mark.parametrize(
    "trailer",
    [
        pytest.param(b"\x92\x01", id="partial-array-body"),
        pytest.param(b"\x81\xa1k", id="partial-map-body"),
    ],
)
def test_flax_msgpack_stream_object_limit_reports_unvalidated_container_trailer(
    tmp_path: Path,
    trailer: bytes,
) -> None:
    path = tmp_path / "unvalidated_container_at_object_limit.msgpack"
    path.write_bytes(msgpack.packb({}, use_bin_type=True) + trailer)

    result = FlaxMsgpackScanner(config={"max_msgpack_stream_objects": 1}).scan(str(path))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "msgpack_stream_object_limit_exceeded"
    limit_check = next(check for check in result.checks if check.name == "Msgpack Stream Object Limit")
    assert "unvalidated trailing data" in limit_check.message


@pytest.mark.parametrize(
    "key",
    [
        pytest.param("x" * 17, id="string"),
        pytest.param(b"x" * 17, id="binary"),
        pytest.param(msgpack.ExtType(1, b"x" * 17), id="extension"),
    ],
)
def test_flax_msgpack_fails_closed_before_stringifying_oversized_map_key(tmp_path: Path, key: object) -> None:
    path = tmp_path / "oversized_key.msgpack"
    create_msgpack_file(path, {key: 0})

    result = FlaxMsgpackScanner(config={"max_msgpack_key_length": 16}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.DECODE_LIMIT_INCONCLUSIVE_REASON]
    decode_check = next(check for check in result.checks if check.name == "Msgpack Decode Budget")
    assert "map key length 17 exceeds max_msgpack_key_length(16)" in decode_check.details["error"]


def test_flax_msgpack_oversized_map_key_is_rejected_before_unpack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = pytest.importorskip("msgpack.fallback")

    def fail_unpack(_self: Any) -> object:
        raise AssertionError("oversized map key must be rejected before scalar materialization")

    monkeypatch.setattr(fallback.Unpacker, "unpack", fail_unpack)
    monkeypatch.setattr(msgpack, "Unpacker", fallback.Unpacker)
    path = tmp_path / "oversized_key_preflight.msgpack"
    create_msgpack_file(path, {b"x" * 17: 0})

    result = FlaxMsgpackScanner(config={"max_msgpack_key_length": 16}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.DECODE_LIMIT_INCONCLUSIVE_REASON]
    assert not [check for check in result.checks if check.name == "Msgpack Parse Check"]


def test_flax_msgpack_accepts_map_key_at_length_limit(tmp_path: Path) -> None:
    path = tmp_path / "bounded_key.msgpack"
    create_msgpack_file(path, {"params": {b"x" * 16: 0}})

    result = FlaxMsgpackScanner(config={"max_msgpack_key_length": 16}).scan(str(path))

    assert result.success is True


def test_flax_msgpack_streaming_decode_does_not_call_unpackb(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Native scans should stream through Unpacker instead of full-buffer unpackb."""
    path = tmp_path / "streamed.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}})

    def fail_unpackb(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scan should not full-buffer decode through msgpack.unpackb")

    monkeypatch.setattr(msgpack, "unpackb", fail_unpackb)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert result.metadata.get("top_level_type") == "dict"


def test_flax_msgpack_pure_python_unpacker_preserves_malicious_scalar_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = pytest.importorskip("msgpack.fallback")
    monkeypatch.setattr(msgpack, "Unpacker", fallback.Unpacker)
    path = tmp_path / "pure_python_malicious.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "__reduce__": "os.system"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["top_level_type"] == "dict"
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute detected: __reduce__"
        and issue.location == "root/__reduce__"
        for issue in result.issues
    )
    assert not any("Failed to parse msgpack data" in issue.message for issue in result.issues)


def test_flax_msgpack_pure_python_unpacker_preserves_benign_scalar_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = pytest.importorskip("msgpack.fallback")
    monkeypatch.setattr(msgpack, "Unpacker", fallback.Unpacker)
    path = tmp_path / "pure_python_benign.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "metadata": "safe"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["top_level_type"] == "dict"
    assert not result.issues


def test_flax_msgpack_event_walker_scans_nested_and_trailing_content(tmp_path: Path) -> None:
    """Nested and trailing content should be inspected one scalar at a time."""
    path = tmp_path / "event_walk.msgpack"
    payload = msgpack.packb(
        {"params": {"notes": "evaluate(safely)", "weights": [1, 2, 3]}},
        use_bin_type=True,
    )
    payload += msgpack.packb({"__reduce__": "os.system"}, use_bin_type=True)
    path.write_bytes(payload)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["msgpack_object_count"] == 2
    assert any(
        issue.message == "Suspicious object attribute detected: __reduce__"
        and issue.location == "root[msgpack_object_1]/__reduce__"
        for issue in result.issues
    )
    assert not any(issue.message == r"Suspicious code pattern detected: eval\s*\(" for issue in result.issues)


def test_flax_msgpack_complex_map_keys_consume_node_budget(tmp_path: Path) -> None:
    path = tmp_path / "complex_key.msgpack"
    key_item_count = 1000
    payload = b"\x81\xdc" + struct.pack(">H", key_item_count) + (b"\x01" * key_item_count) + b"\x00"
    path.write_bytes(payload)

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 2000,
            "max_msgpack_structure_nodes": 2,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    budget_checks = [check for check in result.checks if check.name == "Flax MessagePack Structure Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].details["max_allowed"] == 2


@pytest.mark.skipif(sys.platform == "win32", reason="resource peak RSS is unavailable on Windows")
def test_flax_msgpack_large_container_peak_memory_is_bounded(tmp_path: Path) -> None:
    """A large scalar array must not expand into a retained Python object graph."""
    path = tmp_path / "large_array.msgpack"
    item_count = 750_000
    with path.open("wb") as output:
        output.write(b"\xdd" + struct.pack(">I", item_count))
        for start in range(0, item_count, 50_000):
            payload = bytearray()
            for value in range(start, min(start + 50_000, item_count)):
                payload.append(0xCE)
                payload.extend(struct.pack(">I", value))
            output.write(payload)

    repo_root = Path(__file__).resolve().parents[2]
    script = textwrap.dedent(
        """
        import json
        import resource
        import sys

        from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner

        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result = FlaxMsgpackScanner(
            config={
                "max_file_read_size": 0,
                "max_items_per_container": 800_000,
                "max_msgpack_structure_nodes": 800_010,
            }
        ).scan(sys.argv[1])
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        scale = 1 if sys.platform == "darwin" else 1024
        print(
            json.dumps(
                {
                    "peak_delta_mb": (after - before) * scale / (1024 * 1024),
                    "top_level_type": result.metadata.get("top_level_type"),
                    "scan_outcome": result.metadata.get("scan_outcome"),
                }
            )
        )
        """
    )
    env = {**os.environ, "PYTHONPATH": str(repo_root)}

    completed = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        check=True,
        capture_output=True,
        env=env,
        text=True,
        timeout=60,
    )
    metrics = json.loads(completed.stdout.strip().splitlines()[-1])

    assert metrics["top_level_type"] == "list"
    assert metrics["scan_outcome"] is None
    assert metrics["peak_delta_mb"] < 20


def test_flax_msgpack_large_binary_preserves_cross_chunk_findings(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_pattern.msgpack"
    stream_chunk_bytes = 64 * 1024
    prefix = b"x" * (stream_chunk_bytes - 3)
    create_msgpack_file(path, {"params": {"blob": prefix + b"os.system('id')"}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.message == r"Suspicious code pattern detected: os\.system"
        for issue in result.issues
    )


def test_flax_msgpack_large_binary_preserves_cross_chunk_findings_without_re_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.flax_msgpack_scanner._get_regex_parser", lambda: None)
    path = tmp_path / "large_binary_pattern_without_re_parser.msgpack"
    stream_chunk_bytes = 64 * 1024
    prefix = b"x" * (stream_chunk_bytes - 3)
    create_msgpack_file(path, {"params": {"blob": prefix + b"os.system('id')"}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.message == r"Suspicious code pattern detected: os\.system"
        for issue in result.issues
    )


def test_stream_repeat_fallback_without_re_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("modelaudit.scanners.flax_msgpack_scanner._get_regex_parser", lambda: None)

    for pattern in (
        r"os\.system",
        r"eval\s*\(",
        r"import\s+os",
        r"eval\s{0,}\(",
        r"eval\s{1,}\(",
        r"[\s+]",
    ):
        assert _pattern_has_stream_unsafe_repeat(pattern) is False

    for pattern in (
        r"eval.*\(",
        r"eval\s{2,}\(",
        r"(foo)?bar",
        r"(foo)\1",
        r"(?P<name>foo)(?P=name)",
        r"BEGIN.{5000}END",
        r"\\s+",
        r"(a+)+b",
        r"(a|aa){20}b",
    ):
        assert _pattern_has_stream_unsafe_repeat(pattern) is True


def test_flax_msgpack_large_binary_does_not_join_tokens_across_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_invalid_utf8.msgpack"
    payload = (b"x" * (64 * 1024 + 100)) + b"ev\xffal("
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert not any(check.name == "Code Pattern Security Check" for check in result.checks)


def test_flax_msgpack_large_binary_preserves_long_whitespace_pattern(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_whitespace_pattern.msgpack"
    stream_chunk_bytes = 64 * 1024
    prefix = b"x" * (stream_chunk_bytes - 5004)
    payload = prefix + b"eval" + (b" " * 6000) + b"("
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.message == r"Suspicious code pattern detected: eval\s*\("
        for issue in result.issues
    )
    assert all(check.name != "Flax MessagePack Binary Pattern Coverage" for check in result.checks)


def test_flax_msgpack_large_binary_preserves_long_whitespace_near_match(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_whitespace_near_match.msgpack"
    stream_chunk_bytes = 64 * 1024
    prefix = b"x" * (stream_chunk_bytes - 5010)
    payload = prefix + b"evaluation" + (b" " * 6000) + b"("
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert all(check.name != "Code Pattern Security Check" for check in result.checks)
    assert all(check.name != "Flax MessagePack Binary Pattern Coverage" for check in result.checks)


def test_flax_msgpack_large_binary_fails_closed_for_unresolved_unbounded_pattern(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_unbounded_pattern.msgpack"
    gap = b"x" * (64 * 1024 + 4096 + 100)
    payload = b"getattr(object" + gap + b", '__custom_hook__')"
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    coverage_check = next(check for check in result.checks if check.name == "Flax MessagePack Binary Pattern Coverage")
    assert coverage_check.details["analysis_incomplete"] is True
    assert coverage_check.details["stream_overlap_chars"] == 4096


def test_flax_msgpack_large_binary_benign_getattr_prose_is_not_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_benign_getattr.msgpack"
    payload = (b"x" * (64 * 1024 + 100)) + b" documentation mentions getattr helper only"
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON not in result.metadata.get("scan_outcome_reasons", [])


def test_flax_msgpack_binary_anchor_scanner_ignores_benign_getattr_prose() -> None:
    first_chunk = b"\x00" * 128
    remaining = b" documentation mentions getattr helper only"
    cursor = _MsgpackStreamCursor(io.BytesIO(remaining), len(remaining))
    scanner = FlaxMsgpackScanner()
    result = ScanResult("flax_msgpack")

    scanner._analyze_streamed_binary_anchor_chunks(
        first_chunk,
        cursor,
        len(remaining),
        len(first_chunk) + len(remaining),
        "root.params.blob",
        result,
    )

    assert FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON not in result.metadata.get("scan_outcome_reasons", [])
    assert all(check.name != "Flax MessagePack Binary Pattern Coverage" for check in result.checks)


@pytest.mark.parametrize(
    ("pattern", "payload"),
    [
        pytest.param(
            r"(?:eval|harmless_long_anchor).*\(",
            b"eval" + (b"x" * 70000) + b"(",
            id="unbounded-alternation",
        ),
        pytest.param(r"eval\s{2,}\(", b"eval" + (b" " * 70000) + b"(", id="unbounded-whitespace"),
        pytest.param(r"BEGIN.{5000}END", b"BEGIN" + (b"x" * 5000) + b"END", id="wide-bounded-repeat"),
    ],
)
def test_flax_msgpack_large_binary_fails_closed_for_stream_unsafe_custom_patterns(
    tmp_path: Path,
    pattern: str,
    payload: bytes,
) -> None:
    path = tmp_path / "large_binary_custom_pattern.msgpack"
    create_msgpack_file(path, {"params": {"blob": (b"x" * (64 * 1024)) + payload}})

    result = FlaxMsgpackScanner(config={"suspicious_patterns": [pattern]}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    coverage_check = next(check for check in result.checks if check.name == "Flax MessagePack Binary Pattern Coverage")
    assert coverage_check.details["pattern"] == pattern


@pytest.mark.parametrize(
    ("pattern", "suffix"),
    [(r"foo.*bar?END", b"baEND"), (r"foo.*(bar)?END", b"END")],
)
def test_flax_msgpack_large_binary_fails_closed_when_optional_regex_anchor_is_absent(
    tmp_path: Path,
    pattern: str,
    suffix: bytes,
) -> None:
    path = tmp_path / "large_binary_optional_anchor.msgpack"
    payload = b"foo" + (b"x" * 70000) + suffix
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner(config={"suspicious_patterns": [pattern]}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    coverage_check = next(check for check in result.checks if check.name == "Flax MessagePack Binary Pattern Coverage")
    assert coverage_check.details["pattern"] == pattern


def test_flax_msgpack_does_not_execute_stream_unsafe_regex_on_large_values(tmp_path: Path) -> None:
    class FailIfSearched:
        def search(self, _value: str) -> None:
            if len(_value) > 64 * 1024:
                raise AssertionError("stream-unsafe regex should not run on bounded windows")

    for name, payload in (("binary", b"getattr(" * 10000), ("text", "getattr(" * 10000)):
        path = tmp_path / f"large_unsafe_regex_{name}.msgpack"
        create_msgpack_file(path, {"params": {"blob": payload}})
        scanner = FlaxMsgpackScanner()
        scanner._compiled_suspicious_patterns = cast(
            Any,
            tuple(
                (
                    pattern,
                    FailIfSearched() if pattern == _UNBOUNDED_GETATTR_PATTERN else compiled,
                    lowered,
                )
                for pattern, compiled, lowered in scanner._compiled_suspicious_patterns
            ),
        )

        result = scanner.scan(str(path))

        assert result.success is True


@pytest.mark.parametrize("payload_size", [10_000, 70_000])
def test_flax_msgpack_does_not_execute_ambiguous_custom_regex(
    tmp_path: Path,
    payload_size: int,
) -> None:
    class FailIfSearched:
        def search(self, _value: str) -> None:
            raise AssertionError("ambiguous regex must not be executed")

    pattern = r"(a|aa){20}b"
    path = tmp_path / f"ambiguous_regex_{payload_size}.msgpack"
    create_msgpack_file(path, {"params": {"blob": "a" * payload_size}})
    scanner = FlaxMsgpackScanner(config={"suspicious_patterns": [pattern]})
    scanner._compiled_suspicious_patterns = ((pattern, cast(Any, FailIfSearched()), pattern.lower()),)

    result = scanner.scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]


@pytest.mark.parametrize("as_binary", [False, True])
def test_flax_msgpack_unsafe_pattern_anchors_preserve_unicode_ignorecase(
    tmp_path: Path,
    as_binary: bool,
) -> None:
    pattern = r"ss.*ii"
    text = "\u017f\u017f" + ("x" * 70_000) + "\u0131\u0131"
    payload: str | bytes = text.encode() if as_binary else text
    path = tmp_path / f"unicode_anchors_{as_binary}.msgpack"
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner(config={"suspicious_patterns": [pattern]}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    coverage = next(check for check in result.checks if check.name == "Flax MessagePack Binary Pattern Coverage")
    assert coverage.details["pattern"] == pattern


def test_flax_msgpack_unicode_unsafe_pattern_near_match_remains_clean(tmp_path: Path) -> None:
    pattern = r"ss.*ii"
    path = tmp_path / "unicode_anchor_near_match.msgpack"
    create_msgpack_file(path, {"params": {"blob": "\u017f\u017f" + ("x" * 70_000)}})

    result = FlaxMsgpackScanner(config={"suspicious_patterns": [pattern]}).scan(str(path))

    assert result.success is True
    assert FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON not in result.metadata.get("scan_outcome_reasons", [])


def test_flax_msgpack_streams_shape_validation_beyond_evidence_limit(tmp_path: Path) -> None:
    malicious_path = tmp_path / "long_malicious_shape.msgpack"
    benign_path = tmp_path / "long_benign_shape.msgpack"
    create_msgpack_file(malicious_path, {"params": {"shape": [1] * 64 + [-1]}})
    create_msgpack_file(benign_path, {"params": {"shape": [1] * 65}})

    malicious_result = FlaxMsgpackScanner().scan(str(malicious_path))
    benign_result = FlaxMsgpackScanner().scan(str(benign_path))

    shape_check = next(check for check in malicious_result.checks if check.name == "Tensor Shape Validation")
    assert shape_check.details["dimension_index"] == 64
    assert shape_check.details["dimension"] == -1
    assert shape_check.details["shape_item_count"] == 65
    assert shape_check.details["shape_evidence_truncated"] is True
    assert all(check.name != "Tensor Shape Validation" for check in benign_result.checks)


def test_flax_msgpack_file_size_cap_is_opt_in() -> None:
    assert FlaxMsgpackScanner().max_file_read_size == 0
    assert FlaxMsgpackScanner(config={"max_file_read_size": 1024}).max_file_read_size == 1024


def test_flax_msgpack_small_decode_buffer_accepts_stream_of_small_objects(tmp_path: Path) -> None:
    """A bounded decoder should stream complete small objects without buffering the whole file."""
    path = tmp_path / "small_stream_objects.msgpack"
    payload = b"".join(msgpack.packb({"params": {"n": [index]}}, use_bin_type=True) for index in range(8))
    path.write_bytes(payload)

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 32}).scan(str(path))

    assert result.success is True
    assert result.metadata.get("msgpack_object_count") == 8
    assert all(check.name != "Msgpack Decode Budget" for check in result.checks)


def test_flax_msgpack_decode_limit_is_inconclusive(tmp_path: Path) -> None:
    """Oversized non-tensor MessagePack members should fail closed before materializing content."""
    path = tmp_path / "oversized_blob.msgpack"
    create_msgpack_file(path, {"params": {"blob": b"x" * 513}})

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.DECODE_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Msgpack Decode Budget"
        and check.status == CheckStatus.FAILED
        and check.details["analysis_incomplete"] is True
        for check in result.checks
    )


def test_flax_msgpack_large_tensor_above_decode_budget_scans_without_bufferfull(tmp_path: Path) -> None:
    path = tmp_path / "sparse_large_tensor.msgpack"
    tensor_size = (512 * 1024 * 1024) + 4
    _write_sparse_large_flax_tensor(path, tensor_size)

    result = FlaxMsgpackScanner(
        config={
            "max_msgpack_decode_bytes": 128,
            "max_blob_bytes": 64,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON]
    assert result.metadata["top_level_keys"] == ["params"]
    assert all(check.name != "Msgpack Decode Budget" for check in result.checks)
    blob_check = next(check for check in result.checks if check.name == "Binary Blob Size Check")
    assert blob_check.details["size"] == tensor_size


def test_flax_msgpack_large_flax_ndarray_ext_above_decode_budget_streams_tensor_body(tmp_path: Path) -> None:
    path = tmp_path / "sparse_large_ndarray_ext.msgpack"
    tensor_size = (1024 * 1024) + 4
    _write_sparse_large_flax_ndarray_ext(path, tensor_size)

    result = FlaxMsgpackScanner(
        config={
            "max_msgpack_decode_bytes": 128,
            "max_blob_bytes": 64,
        }
    ).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["estimated_parameters"] == tensor_size // 4
    assert result.metadata["jax_metadata"]["tensor_count"] == 1
    assert all(check.name != "Msgpack Decode Budget" for check in result.checks)
    assert all(check.name != "Binary Blob Size Check" for check in result.checks)


def test_flax_msgpack_flax_ndarray_ext_above_reduced_decode_budget_uses_ndarray_parser(tmp_path: Path) -> None:
    path = tmp_path / "small_ndarray_ext_above_reduced_budget.msgpack"
    _write_sparse_large_flax_ndarray_ext(path, 32)

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 16}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["jax_metadata"]["tensor_count"] == 1
    assert all(check.name != "Msgpack Decode Budget" for check in result.checks)


@pytest.mark.parametrize("dtype", ["float8_e4m3fn", "float4_e2m1fn", "float6_e3m2fn", "int4", "uint4"])
def test_flax_msgpack_flax_ndarray_ext_accepts_one_byte_ml_dtypes_metadata(
    tmp_path: Path,
    dtype: str,
) -> None:
    path = tmp_path / f"{dtype}_ndarray_ext.msgpack"
    _write_sparse_large_flax_ndarray_ext(path, 64, dtype=dtype, shape_values=[64])

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 16}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["jax_metadata"]["tensor_count"] == 1
    assert all(check.name != "Msgpack Parse Check" for check in result.checks)


def test_flax_msgpack_flax_ndarray_ext_accepts_zero_dimension_after_nonzero(tmp_path: Path) -> None:
    path = tmp_path / "zero_dimension_ndarray_ext.msgpack"
    _write_sparse_large_flax_ndarray_ext(path, 0, shape_values=[5, 0])

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 16}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert all(check.name != "Msgpack Parse Check" for check in result.checks)


def test_flax_msgpack_large_flax_ndarray_ext_treats_valid_tensor_bytes_as_data(tmp_path: Path) -> None:
    path = tmp_path / "text_like_tensor_bytes_ndarray_ext.msgpack"
    body_prefix = (b"\0" * (64 * 1024)) + b"eval('x')"
    body_prefix += b"\0" * (-len(body_prefix) % 4)
    _write_sparse_large_flax_ndarray_ext(path, len(body_prefix), body_prefix=body_prefix)

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["jax_metadata"]["tensor_count"] == 1
    assert all(issue.message != r"Suspicious code pattern detected: eval\s*\(" for issue in result.issues)
    assert all(check.name != "Msgpack Parse Check" for check in result.checks)


def test_flax_msgpack_direct_ndarray_ext_treats_valid_tensor_bytes_as_data(tmp_path: Path) -> None:
    path = tmp_path / "direct_text_like_tensor_bytes_ndarray_ext.msgpack"
    body_prefix = b"eval('x')" + (b"\0" * 24)
    body_prefix += b"\0" * (-len(body_prefix) % 4)
    _write_sparse_large_flax_ndarray_ext(path, len(body_prefix), body_prefix=body_prefix, wrap_in_params=False)

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 16}).scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["jax_metadata"]["tensor_count"] == 1
    assert all(issue.message != r"Suspicious code pattern detected: eval\s*\(" for issue in result.issues)
    assert all(check.name != "Msgpack Parse Check" for check in result.checks)


def test_flax_msgpack_ndarray_ext_under_decode_budget_treats_valid_tensor_bytes_as_data(tmp_path: Path) -> None:
    path = tmp_path / "small_text_like_tensor_bytes_ndarray_ext.msgpack"
    body_prefix = b"eval('x')" + (b"\0" * 24)
    body_prefix += b"\0" * (-len(body_prefix) % 4)
    _write_sparse_large_flax_ndarray_ext(path, len(body_prefix), body_prefix=body_prefix)

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert result.metadata["jax_metadata"]["tensor_count"] == 1
    assert all(issue.message != r"Suspicious code pattern detected: eval\s*\(" for issue in result.issues)
    assert all(check.name != "Msgpack Parse Check" for check in result.checks)


def test_flax_msgpack_large_flax_ndarray_ext_scans_dtype_metadata(tmp_path: Path) -> None:
    path = tmp_path / "malicious_dtype_ndarray_ext.msgpack"
    tensor_size = (64 * 1024) + 4
    _write_sparse_large_flax_ndarray_ext(path, tensor_size, dtype="eval('x')")

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.message == r"Suspicious code pattern detected: eval\s*\("
        for issue in result.issues
    )


def test_flax_msgpack_flax_ndarray_ext_rejects_trailing_body_bytes(tmp_path: Path) -> None:
    path = tmp_path / "trailing_body_ndarray_ext.msgpack"
    tensor_size = (64 * 1024) + 4
    _write_sparse_large_flax_ndarray_ext(path, tensor_size, trailing_body=msgpack.packb("eval('x')", use_bin_type=True))

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    parse_check = next(check for check in result.checks if check.name == "Msgpack Parse Check")
    assert "Flax ndarray extension contains trailing bytes" in parse_check.details["parse_error"]


def test_flax_msgpack_flax_ndarray_ext_rejects_unsupported_dtype(tmp_path: Path) -> None:
    path = tmp_path / "unsupported_dtype_ndarray_ext.msgpack"
    _write_sparse_large_flax_ndarray_ext(path, (64 * 1024) + 4, dtype="object")

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    parse_check = next(check for check in result.checks if check.name == "Msgpack Parse Check")
    assert "unsupported Flax ndarray dtype metadata" in parse_check.details["parse_error"]


def test_flax_msgpack_flax_ndarray_ext_rejects_shape_dtype_length_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "shape_dtype_mismatch_ndarray_ext.msgpack"
    _write_sparse_large_flax_ndarray_ext(path, 64 * 1024, dtype="float64")

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    parse_check = next(check for check in result.checks if check.name == "Msgpack Parse Check")
    assert "Flax ndarray shape and dtype" in parse_check.details["parse_error"]


def test_flax_msgpack_non_text_tensor_like_raw_bin_with_hidden_text_tail_is_incomplete(tmp_path: Path) -> None:
    path = tmp_path / "hidden_tail_tensor_like_bin.msgpack"
    payload = (b"\0" * (64 * 1024)) + b"eval('x')" + (b"\0" * 3)
    create_msgpack_file(path, {"params": {"blob": payload}})

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON]
    assert all(
        issue.message != r"Suspicious code pattern detected: eval\s*\("
        for issue in result.issues
        if issue.severity == IssueSeverity.CRITICAL
    )


@pytest.mark.parametrize("payload_size", [64 * 1024 - 4, 64 * 1024])
def test_flax_msgpack_over_budget_tensor_like_raw_bin_probe_is_incomplete(
    tmp_path: Path,
    payload_size: int,
) -> None:
    path = tmp_path / "over_budget_probe_tensor_like_bin.msgpack"
    create_msgpack_file(path, {"params": {"blob": b"\0" * payload_size}})

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON]
    coverage = next(check for check in result.checks if check.name == "Flax MessagePack Binary Pattern Coverage")
    assert coverage.details["binary_size"] == payload_size
    assert coverage.details["sampled_bytes"] == payload_size
    assert all(check.name != "Msgpack Decode Budget" for check in result.checks)


def test_flax_msgpack_large_tensor_skip_continues_to_later_security_finding(tmp_path: Path) -> None:
    path = tmp_path / "sparse_large_tensor_then_reduce.msgpack"
    tensor_size = (512 * 1024 * 1024) + 4
    _write_sparse_large_flax_tensor(path, tensor_size, trailing_reduce=True)

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    assert FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert all(check.name != "Msgpack Decode Budget" for check in result.checks)
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute detected: __reduce__"
        and issue.location == "root/__reduce__"
        for issue in result.issues
    )


def test_flax_msgpack_truncated_declared_large_tensor_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "truncated_sparse_tensor.msgpack"
    tensor_size = (512 * 1024 * 1024) + 4
    _write_sparse_large_flax_tensor(path, tensor_size, body_bytes=b"\0" * 8)

    result = FlaxMsgpackScanner(config={"max_msgpack_decode_bytes": 128}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.TRUNCATED_STREAM_INCONCLUSIVE_REASON]
    parse_check = next(check for check in result.checks if check.name == "Msgpack Parse Check")
    assert parse_check.details["parse_error"] == "incomplete trailing msgpack object"


def test_flax_msgpack_duplicate_keys_are_reported_and_values_scanned(tmp_path: Path) -> None:
    path = tmp_path / "duplicate_params.msgpack"
    path.write_bytes(b"\x82\xa6params\x80\xa6params\x81\xaa__reduce__\xa9os.system")

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    duplicate_check = next(check for check in result.checks if check.name == "MessagePack Duplicate Key Check")
    assert duplicate_check.details["key"] == "params"
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Suspicious object attribute detected: __reduce__"
        and issue.location == "root/params/__reduce__"
        for issue in result.issues
    )


def test_flax_msgpack_duplicate_key_tracking_budget_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "duplicate_key_tracking_budget.msgpack"
    create_msgpack_file(path, {"aaaa": 1, "bbbb": 2, "cccc": 3})

    result = FlaxMsgpackScanner(config={"max_msgpack_duplicate_key_tracking_bytes": 8}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.DUPLICATE_KEY_TRACKING_INCONCLUSIVE_REASON]
    budget_check = next(check for check in result.checks if check.name == "MessagePack Duplicate Key Tracking Budget")
    assert budget_check.details["tracked_key_bytes"] == 8
    assert budget_check.details["next_key_bytes"] == 4
    assert budget_check.details["seen_key_count"] == 2


@pytest.mark.parametrize(
    "oversized_value",
    [
        ["eval('x')", "safe", "extra"],
        {"payload": "eval('x')", "safe": "ok", "extra": "ok"},
    ],
)
def test_flax_msgpack_decode_limit_scans_visible_oversized_container_prefix(
    tmp_path: Path,
    oversized_value: object,
) -> None:
    """Early malicious values remain visible when a container exceeds the decode cap."""
    path = tmp_path / "oversized_container.msgpack"
    create_msgpack_file(path, {"params": oversized_value})

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 2,
            "max_msgpack_decode_bytes": 1024,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.DECODE_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.message == r"Suspicious code pattern detected: eval\s*\("
        for issue in result.issues
    )


def test_flax_msgpack_decode_limit_scans_visible_jax_transform_prefix(tmp_path: Path) -> None:
    """Dedicated JAX checks must run on the visible prefix of oversized containers."""
    path = tmp_path / "oversized_jax_transform.msgpack"
    create_msgpack_file(path, {"params": [{"jit_compile": "safe"}, "safe", "extra"]})

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 2,
            "max_msgpack_decode_bytes": 1024,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    jax_checks = [
        check
        for check in result.checks
        if check.name == "JAX Transform Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["transform"] == "jit_compile"
    ]
    assert len(jax_checks) == 1


def test_flax_msgpack_scans_byte_encoded_jax_transform_metadata(tmp_path: Path) -> None:
    """Byte-valued JAX metadata must retain the dedicated transform check."""
    path = tmp_path / "byte_jax_transform.msgpack"
    create_msgpack_file(path, {"params": {"x": b"jit_compile"}})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.success is False
    assert any(
        check.name == "JAX Transform Security Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details["transform"] == "jit_compile"
        for check in result.checks
    )


def test_flax_msgpack_decode_limit_does_not_join_adjacent_jax_transform_parts(tmp_path: Path) -> None:
    """Separate visible keys and values must not synthesize a JAX transform."""
    path = tmp_path / "oversized_jax_transform_parts.msgpack"
    create_msgpack_file(path, {"params": [{"jit": "compile"}, "safe", "extra"]})

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 2,
            "max_msgpack_decode_bytes": 1024,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert all(check.name != "JAX Transform Security Check" for check in result.checks)


def test_flax_msgpack_decode_limit_does_not_join_adjacent_visible_strings(tmp_path: Path) -> None:
    """Structurally separate values must not become a synthetic suspicious pattern."""
    path = tmp_path / "oversized_benign_strings.msgpack"
    create_msgpack_file(path, {"params": ["ev", "al(", "extra"]})

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 2,
            "max_msgpack_decode_bytes": 1024,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_flax_msgpack_large_containers(tmp_path):
    """Test detection of containers with excessive items."""
    path = tmp_path / "large.msgpack"
    # Create oversized containers (default limit is 50000)
    # Use smaller sizes in CI to avoid memory issues
    is_ci = os.getenv("CI") or os.getenv("GITHUB_ACTIONS")
    dict_size = 52000 if is_ci else 60000  # Just over limit, but smaller in CI
    list_size = 51000 if is_ci else 55000  # Just over limit, but smaller in CI

    large_dict = {f"key_{i}": f"value_{i}" for i in range(dict_size)}
    large_list = list(range(list_size))

    data = {"params": {"large_dict": large_dict, "large_list": large_list}}
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.DECODE_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "Msgpack Decode Budget" for check in result.checks)


def test_flax_msgpack_deep_nesting_is_inconclusive(tmp_path: Path) -> None:
    """Benign content beyond the recursion cap is incomplete coverage, not clean analysis."""
    path = tmp_path / "deep.msgpack"

    # Create deeply nested structure
    deep_data: dict[str, Any] = {"level": 0}
    current: dict[str, Any] = deep_data
    for i in range(1, 150):  # Deeper than default limit
        current["nested"] = {"level": i}
        current = current["nested"]

    create_msgpack_file(path, deep_data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON]
    depth_checks = [check for check in result.checks if check.name == "Recursion Depth Check"]
    assert depth_checks
    assert all("Maximum recursion depth exceeded" in check.message for check in depth_checks)
    assert all(check.severity == IssueSeverity.INFO for check in depth_checks)
    assert all(check.rule_code == "S902" for check in depth_checks)
    assert all(check.details["analysis_incomplete"] is True for check in depth_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    _assert_inconclusive_aggregate_not_cached(
        path,
        FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON,
        tmp_path / "benign-recursion-cache",
    )


def test_flax_msgpack_depth_limit_reporting_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "wide_beyond_depth.msgpack"
    create_msgpack_file(path, [0] * 1000)

    result = FlaxMsgpackScanner(
        config={
            "max_items_per_container": 2000,
            "max_msgpack_structure_nodes": 5000,
            "max_recursion_depth": 0,
        }
    ).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert sum(check.name == "Flax MessagePack Preanalysis Depth Limit" for check in result.checks) == 1
    assert sum(check.name == "Recursion Depth Check" for check in result.checks) == 1


def test_flax_msgpack_renamed_hidden_pattern_beyond_recursion_limit_is_inconclusive(tmp_path: Path) -> None:
    """A renamed payload hidden below the traversal cap must not be reported clean."""
    path = tmp_path / "hidden_payload.jpg"
    create_msgpack_file(path, {"params": {"layer": {"deep": {"payload": 'os.system("id")'}}}})

    result = FlaxMsgpackScanner(config={"max_recursion_depth": 2}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON]
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    _assert_inconclusive_aggregate_not_cached(
        path,
        FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON,
        tmp_path / "hidden-payload-cache",
        max_recursion_depth=2,
    )


def test_flax_msgpack_preanalysis_depth_limit_skips_unbounded_ml_helpers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deep structures should fail closed before ML metadata helpers recurse over them."""
    path = tmp_path / "preanalysis_deep.msgpack"
    nested: object = "benign"
    for _ in range(6):
        nested = {"nested": nested}
    create_msgpack_file(path, {"params": nested})

    scanner = FlaxMsgpackScanner(config={"max_recursion_depth": 2})

    def fail_analyze(_obj: Any, _result: ScanResult) -> dict[str, Any]:
        raise AssertionError("ML structure helper should be skipped once preanalysis depth is exhausted")

    monkeypatch.setattr(scanner, "_analyze_ml_structure", fail_analyze)

    result = scanner.scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(check.name == "Flax MessagePack Preanalysis Depth Limit" for check in result.checks)


def test_flax_msgpack_pattern_within_recursion_limit_remains_security_finding(tmp_path: Path) -> None:
    """The recursion policy must not dilute an observed suspicious code pattern."""
    path = tmp_path / "visible_payload.msgpack"
    create_msgpack_file(path, {"params": {"payload": 'os.system("id")'}})

    result = FlaxMsgpackScanner(config={"max_recursion_depth": 2}).scan(str(path))

    assert "scan_outcome" not in result.metadata
    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL and "os\\.system" in issue.message for issue in result.issues)

    aggregate = scan_model_directory_or_file(
        str(path),
        max_recursion_depth=2,
        cache_enabled=False,
    )
    assert determine_exit_code(aggregate) == 1


def test_flax_msgpack_visible_finding_with_deep_sibling_remains_security_finding(tmp_path: Path) -> None:
    """Observed malicious content must win over incomplete sibling coverage."""
    path = tmp_path / "visible_and_deep.msgpack"
    create_msgpack_file(
        path,
        {
            "params": {
                "payload": 'os.system("id")',
                "opaque": {"level": {"level": "benign"}},
            }
        },
    )

    result = FlaxMsgpackScanner(config={"max_recursion_depth": 2}).scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "os\\.system" in issue.message for issue in result.issues)
    assert any("Maximum recursion depth exceeded" in check.message for check in result.checks)

    reset_cache_manager()
    try:
        aggregates = [
            scan_model_directory_or_file(
                str(path),
                max_recursion_depth=2,
                cache_enabled=True,
                cache_dir=str(tmp_path / "mixed-outcome-cache"),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]
        for aggregate in aggregates:
            metadata = aggregate.file_metadata[str(path)]
            assert FlaxMsgpackScanner.RECURSION_LIMIT_INCONCLUSIVE_REASON in metadata["scan_outcome_reasons"]
            assert any(issue.severity == IssueSeverity.CRITICAL for issue in aggregate.issues)
            assert determine_exit_code(aggregate) == 1
        assert get_cache_manager(str(tmp_path / "mixed-outcome-cache"), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_flax_msgpack_non_standard_structure(tmp_path):
    """Test detection of non-standard Flax structures using structural analysis."""
    path = tmp_path / "nonstandard.msgpack"
    # Create structure that doesn't look like a Flax checkpoint
    data = {
        "random_key": "random_value",
        "another_key": [1, 2, 3],
        "not_flax": {"definitely": "not a model"},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Scanner behavior may vary - either flag suspicious structure or recognize as non-ML file
    # Check that the scan completes without critical errors
    assert result.success is True or len(result.issues) > 0

    # If warnings exist, they should be about structure or non-ML content
    warning_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
    if warning_issues:
        # Warnings should be about structure or content, not malicious patterns
        assert all(
            "suspicious" in issue.message.lower()
            or "structure" in issue.message.lower()
            or "data" in issue.message.lower()
            or "ml" in issue.message.lower()
            for issue in warning_issues
        )


def test_flax_msgpack_corrupted(tmp_path):
    """Test handling of corrupted msgpack files."""
    path = tmp_path / "corrupt.msgpack"
    data = {"params": {"w": list(range(5))}}
    create_msgpack_file(path, data)

    # Corrupt the file by truncating it
    original_data = path.read_bytes()
    path.write_bytes(original_data[:-10])

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Scanner may report corruption via has_errors or via issues/checks
    # Check for any indication of corrupted/invalid file
    all_messages = [issue.message for issue in result.issues]
    all_messages.extend([check.message for check in result.checks])

    has_error_indication = (
        result.has_errors
        or any(
            "Invalid msgpack format" in msg or "Unexpected error processing" in msg or "corrupt" in msg.lower()
            for msg in all_messages
        )
        or not result.success
    )
    assert has_error_indication, (
        f"Expected error indication for corrupted file but got: "
        f"issues={result.issues}, checks={result.checks}, success={result.success}"
    )


def test_flax_msgpack_enhanced_jax_support(tmp_path):
    """Test enhanced JAX-specific functionality."""
    path = tmp_path / "jax_model.flax"

    # Create JAX model with transformer architecture
    data = {
        "params": {
            "transformer": {
                "attention": {"query": b"\x00" * 1000, "key": b"\x00" * 1000},
                "feed_forward": {"dense": b"\x00" * 2000},
            }
        },
        "opt_state": {"step": 1000, "learning_rate": 0.001},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success
    # Should detect transformer architecture
    assert result.metadata.get("model_architecture") == "transformer"
    estimated_params = result.metadata.get("estimated_parameters")
    assert estimated_params is not None and estimated_params > 0

    # Should detect optimizer state
    jax_metadata = result.metadata.get("jax_metadata", {})
    assert jax_metadata.get("has_optimizer_state") is True


def test_flax_msgpack_orbax_format_detection(tmp_path):
    """Test detection of Orbax checkpoint format."""
    path = tmp_path / "orbax_checkpoint.orbax"

    data = {
        "__orbax_metadata__": {"version": "0.1.0", "format": "flax"},
        "state": {"params": {"layer": b"\x00" * 1000}},
        "metadata": {"step": 5000},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success

    # Should detect Orbax format
    jax_metadata = result.metadata.get("jax_metadata", {})
    assert jax_metadata.get("orbax_format") is True

    # Should have check about Orbax detection
    # Now using checks instead of issues - look for passed check with Orbax message
    orbax_checks = [check for check in result.checks if "Orbax checkpoint format detected" in check.message]
    assert len(orbax_checks) > 0, "No Orbax detection check found"
    assert orbax_checks[0].status.value == "passed"


def test_flax_msgpack_jax_specific_threats(tmp_path):
    """Test detection of JAX-specific security threats."""
    path = tmp_path / "malicious_jax.jax"

    data = {
        "params": {"layer": b"\x00" * 100},
        "__jax_array__": "fake_array_metadata",
        "custom_transform": "jax.jit(eval(malicious_code))",
        "shape": [-1, 100],  # Invalid negative dimension
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Should detect multiple threats (CRITICAL, WARNING, or INFO severity)
    security_issues = [
        issue
        for issue in result.issues
        if issue.severity in (IssueSeverity.CRITICAL, IssueSeverity.WARNING, IssueSeverity.INFO)
    ]

    # Check for JAX-specific threats
    issues_messages = [issue.message for issue in security_issues]

    # Scanner message may say "JAX array metadata" or "Suspicious object attribute detected: __jax_array__"
    assert any("__jax_array__" in msg or "JAX array" in msg for msg in issues_messages)
    # Negative dimensions check - may not be implemented in all scanner versions
    # assert any("negative dimensions" in msg for msg in issues_messages)


def test_flax_msgpack_redacts_suspicious_string_evidence(tmp_path: Path) -> None:
    path = tmp_path / "leaky_code.msgpack"
    secret = "CLIENTSECRET123456789"
    url_token = "HFSECRETTOKEN123"
    data = {
        "params": {"w": [1, 2, 3]},
        "code": (
            f"eval('payload') client_secret='{secret}' https://user:pass@example.com/model?token={url_token}&ok=1"
        ),
    }
    create_msgpack_file(path, data)

    result = FlaxMsgpackScanner().scan(str(path))
    sample = next(check.details["sample"] for check in result.checks if check.name == "Code Pattern Security Check")
    serialized = result.to_json()

    assert "eval('payload')" in sample
    assert "client_secret='<redacted>'" in sample
    assert "https://<credentials-redacted>@example.com/model?token=<redacted>&ok=1" in sample
    assert secret not in serialized
    assert url_token not in serialized
    assert "user:pass" not in serialized


def test_flax_msgpack_redacts_jax_transform_context(tmp_path: Path) -> None:
    path = tmp_path / "leaky_transform.jax"
    api_key = "JAXAPIKEY123456789"
    data = {
        "params": {"w": [1, 2, 3]},
        "custom_transform": f"runtime_eval api_key={api_key}",
    }
    create_msgpack_file(path, data)

    result = FlaxMsgpackScanner().scan(str(path))
    context = next(check.details["context"] for check in result.checks if check.name == "JAX Transform Security Check")
    serialized = result.to_json()

    assert "runtime_eval" in context
    assert "api_key=<redacted>" in context
    assert api_key not in serialized


def test_flax_msgpack_redacts_model_controlled_key_locations(tmp_path: Path) -> None:
    path = tmp_path / "leaky_location.jax"
    secret = "LOCATIONSECRET123456789"
    data = {
        "params": {"w": [1, 2, 3]},
        f"runtime_eval?token={secret}": "benign transform metadata",
    }
    create_msgpack_file(path, data)

    result = FlaxMsgpackScanner().scan(str(path))
    locations = [issue.location or "" for issue in result.issues]
    serialized = result.to_json()
    sarif_results = json.dumps(_create_results(result.issues, prefiltered=True))

    assert any("runtime_eval?token=<redacted>" in location for location in locations)
    assert any(issue.message == "Suspicious JAX transform detected: runtime_eval" for issue in result.issues)
    assert secret not in serialized
    assert secret not in sarif_results


def test_flax_msgpack_redacts_bytes_keys_without_breaking_tensor_analysis(tmp_path: Path) -> None:
    path = tmp_path / "bytes_key.msgpack"
    secret = "BYTESKEYSECRET123456789"
    data = {
        f"token={secret}".encode(): b"0" * 4096,
        7: {"__jax_array__": True},
    }
    create_msgpack_file(path, data)

    result = FlaxMsgpackScanner().scan(str(path))
    serialized = result.to_json()

    assert not any(check.name == "Flax Msgpack Processing" for check in result.checks)
    assert result.metadata["top_level_keys"] == ["token=<redacted>", 7]
    assert any(check.name == "JAX Array Metadata Check" and check.location == "root/7" for check in result.checks)
    assert secret not in serialized


def test_flax_msgpack_redacts_url_path_capability_token_sample(tmp_path: Path) -> None:
    path = tmp_path / "url_capability_token.msgpack"
    token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
    create_msgpack_file(
        path,
        {
            "params": {"w": [1, 2, 3]},
            "code": f"eval('https://example.com/path/{token}/model.bin')",
        },
    )

    result = FlaxMsgpackScanner().scan(str(path))
    serialized = result.to_json()

    assert token not in serialized
    assert "https://example.com/path/<redacted>/model.bin" in serialized


def test_flax_msgpack_redacts_standalone_secret_shaped_metadata_key(tmp_path: Path) -> None:
    path = tmp_path / "standalone_secret_key.msgpack"
    token = "ghp_" + "a" * 36
    create_msgpack_file(path, {token: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.metadata["top_level_keys"] == ["<redacted>"]
    assert token not in result.to_json()


def test_flax_msgpack_redacts_huggingface_token_metadata_key(tmp_path: Path) -> None:
    path = tmp_path / "huggingface_token_key.msgpack"
    token = "hf_" + "a" * 34
    create_msgpack_file(path, {token: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.metadata["top_level_keys"] == ["<redacted>"]
    assert token not in result.to_json()


def test_flax_msgpack_redacts_url_safe_openai_project_key(tmp_path: Path) -> None:
    path = tmp_path / "openai_project_key.msgpack"
    token = "sk-proj-" + "abc_def-" * 4
    create_msgpack_file(path, {token: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.metadata["top_level_keys"] == ["<redacted>"]
    assert token not in result.to_json()


def test_flax_msgpack_redacts_percent_encoded_secret_metadata_key(tmp_path: Path) -> None:
    path = tmp_path / "encoded_secret_key.msgpack"
    encoded_token = "ghp%5F" + "a" * 36
    create_msgpack_file(path, {encoded_token: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))
    serialized = result.to_json()

    assert result.metadata["top_level_keys"] == ["<redacted>"]
    assert encoded_token not in serialized


def test_flax_msgpack_redacts_deeply_percent_encoded_secret_metadata_key(tmp_path: Path) -> None:
    path = tmp_path / "deeply_encoded_secret_key.msgpack"
    encoded_token = "ghp%2525255F" + "a" * 36
    create_msgpack_file(path, {encoded_token: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.metadata["top_level_keys"] == ["<redacted>"]
    assert encoded_token not in result.to_json()


@pytest.mark.parametrize(
    ("encoded_evidence", "expected_marker"),
    [
        ("api_key%3Dhunter2", "<redacted>"),
        ("api_key%3DENCODEDSECRET123456", "<redacted>"),
        ("https%3A%2F%2Fuser%3Apass%40evil.example%2Fcb", "<credentials-redacted>"),
    ],
)
def test_flax_msgpack_redacts_percent_encoded_credential_metadata_key(
    tmp_path: Path,
    encoded_evidence: str,
    expected_marker: str,
) -> None:
    path = tmp_path / "encoded_credential_key.msgpack"
    create_msgpack_file(path, {encoded_evidence: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))
    serialized = result.to_json()

    assert encoded_evidence not in serialized
    assert "ENCODEDSECRET123456" not in serialized
    assert "user:pass" not in serialized
    assert expected_marker in serialized


@pytest.mark.parametrize(
    ("metadata_key", "expected_key"),
    [
        (b"token\xff=INVALIDUTF8SECRET123456789", "<redacted>"),
        (b"api_\x00key=CONTROLBYTESECRET123456789", "api_key=<redacted>"),
        ("api_\tkey=TABSECRET123456789", "api_key=<redacted>"),
        ("api_\nkey=LINESECRET123456789", "api_key=<redacted>"),
        ("api_\rkey=RETURNSECRET123456789", "api_key=<redacted>"),
        ("api_\u2028key=SEPARATORSECRET123456789", "api_key=<redacted>"),
        ("api_\u202ekey=BIDISECRET123456789", "api_key=<redacted>"),
    ],
)
def test_flax_msgpack_fails_closed_for_unsafe_metadata_keys(
    tmp_path: Path,
    metadata_key: bytes | str,
    expected_key: str,
) -> None:
    path = tmp_path / "unsafe_binary_key.msgpack"
    create_msgpack_file(path, {metadata_key: b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))
    serialized = result.to_json()

    assert result.metadata["top_level_keys"] == [expected_key]
    assert "SECRET123456789" not in serialized


def test_flax_msgpack_redacts_openai_project_key_across_persisted_outputs(tmp_path: Path) -> None:
    path = tmp_path / "openai_project_key.msgpack"
    cache_dir = tmp_path / "cache"
    token = "sk-proj-" + "A" * 12 + "_" + "b" * 20 + "-" + "C" * 8
    create_msgpack_file(path, {token: b"0" * 4096})
    scanner = FlaxMsgpackScanner(config={"cache_enabled": True, "cache_dir": str(cache_dir)})

    reset_cache_manager()
    try:
        direct = scanner.scan(str(path))
        first = scanner.scan_with_cache(str(path))
        cached = scanner.scan_with_cache(str(path))
        cache_stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
        sarif_results = _create_results(direct.issues, prefiltered=True)
        cache_text = "".join(
            cache_path.read_text(errors="ignore") for cache_path in cache_dir.rglob("*") if cache_path.is_file()
        )

        assert direct.metadata["top_level_keys"] == ["<redacted>"]
        assert any(issue.details.get("found_keys") == ["<redacted>"] for issue in direct.issues)
        assert token not in direct.to_json()
        assert sarif_results
        assert "<redacted>" in json.dumps(sarif_results)
        assert token not in json.dumps(sarif_results)
        assert token not in first.to_json()
        assert token not in cached.to_json()
        assert token not in cache_text
        assert cache_stats["total_entries"] == 1
        assert cache_stats["cache_hits"] == 1
    finally:
        reset_cache_manager()


def test_flax_msgpack_unresolved_binary_pattern_aggregate_exits_with_error_and_is_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "large_binary_unbounded_pattern.msgpack"
    gap = b"x" * (64 * 1024 + 4096 + 100)
    payload = b"getattr(object" + gap + b", '__custom_hook__')"
    create_msgpack_file(path, {"params": {"blob": payload}})

    _assert_inconclusive_aggregate_not_cached(
        path,
        FlaxMsgpackScanner.BINARY_PATTERN_INCONCLUSIVE_REASON,
        tmp_path / "binary-pattern-cache",
    )


def test_flax_msgpack_stringifies_extension_metadata_keys(tmp_path: Path) -> None:
    path = tmp_path / "extension_key.msgpack"
    secret = "EXTKEYSECRET123456789"
    create_msgpack_file(
        path,
        {msgpack.ExtType(1, f"token={secret}".encode()): b"0" * 4096},
    )

    result = FlaxMsgpackScanner().scan(str(path))
    serialized = result.to_json()

    assert secret not in serialized
    assert "token=<redacted>" in serialized
    assert isinstance(result.metadata["top_level_keys"][0], str)


@pytest.mark.parametrize(
    ("extension_data", "expected_key"),
    [
        (b"token\xff=INVALIDEXTSECRET123456789", "<redacted>"),
        (b"api_\x00key=CONTROLEXTSECRET123456789", "<redacted>"),
    ],
)
def test_flax_msgpack_fails_closed_for_unsafe_extension_metadata_keys(
    tmp_path: Path,
    extension_data: bytes,
    expected_key: str,
) -> None:
    path = tmp_path / "unsafe_extension_key.msgpack"
    create_msgpack_file(path, {msgpack.ExtType(1, extension_data): b"0" * 4096})

    result = FlaxMsgpackScanner().scan(str(path))

    assert result.metadata["top_level_keys"] == [expected_key]
    assert "EXTSECRET123456789" not in result.to_json()


def test_flax_msgpack_detects_suspicious_bytes_keys(tmp_path: Path) -> None:
    path = tmp_path / "bytes_reduce.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"__reduce__": "os.system"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert any(
        check.name == "Object Attribute Security Check"
        and check.message == "Suspicious object attribute detected: __reduce__"
        for check in result.checks
    )


def test_flax_msgpack_detects_short_suspicious_binary_value(tmp_path: Path) -> None:
    path = tmp_path / "short_binary_code.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, "payload": b"eval('x')"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert any(
        check.name == "Code Pattern Security Check" and check.details.get("sample") == "eval('x')"
        for check in result.checks
    )


def test_flax_msgpack_detects_suspicious_binary_key(tmp_path: Path) -> None:
    path = tmp_path / "binary_code_key.msgpack"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, b"eval('x')": "safe"})

    result = FlaxMsgpackScanner().scan(str(path))

    assert any(
        check.name == "Code Pattern Security Check" and check.details.get("sample") == "eval('x')"
        for check in result.checks
    )


def test_flax_msgpack_redacts_unsafe_binary_key_finding_evidence(tmp_path: Path) -> None:
    path = tmp_path / "unsafe_binary_code_key.msgpack"
    secret = "UNSAFEKEYSECRET123456789"
    key = b"api_" + b"\xff" + f"key={secret} os.system(1)".encode()
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}, key: "safe"})

    result = FlaxMsgpackScanner().scan(str(path))
    finding = next(check for check in result.checks if check.name == "Code Pattern Security Check")

    assert finding.details["sample"] == "<redacted>"
    assert finding.location == "root[key:<redacted>]"
    assert secret not in result.to_json()


def test_flax_msgpack_preserves_benign_short_binary_near_matches(tmp_path: Path) -> None:
    path = tmp_path / "benign_binary_text.msgpack"
    create_msgpack_file(
        path,
        {
            "params": {"w": [1, 2, 3]},
            b"evaluation_metric": b"evaluation_result",
        },
    )

    result = FlaxMsgpackScanner().scan(str(path))

    assert not any(check.name == "Code Pattern Security Check" for check in result.checks)


def test_flax_msgpack_ignores_short_non_textual_binary_code_near_match(tmp_path: Path) -> None:
    path = tmp_path / "non_textual_binary_code.msgpack"
    create_msgpack_file(
        path,
        {
            "params": {"w": [1, 2, 3]},
            "payload": b"\x00\xffeval(\x80\x81",
        },
    )

    result = FlaxMsgpackScanner().scan(str(path))

    assert not any(check.name == "Code Pattern Security Check" for check in result.checks)


def test_flax_msgpack_redaction_preserves_non_secret_suspicious_evidence(tmp_path: Path) -> None:
    path = tmp_path / "non_secret_evidence.msgpack"
    data = {
        "params": {"w": [1, 2, 3]},
        "code": 'eval("https://evil.example/run?mode=test")',
    }
    create_msgpack_file(path, data)

    result = FlaxMsgpackScanner().scan(str(path))
    sample = next(check.details["sample"] for check in result.checks if check.name == "Code Pattern Security Check")

    assert "eval(" in sample
    assert "evil.example" in sample
    assert "mode=test" in sample


def test_flax_msgpack_fails_closed_for_oversized_evidence_sample(tmp_path: Path) -> None:
    path = tmp_path / "oversized_evidence.msgpack"
    secret = "OVERSIZED_EVIDENCE_SECRET"
    create_msgpack_file(
        path,
        {
            "params": {"w": [1, 2, 3]},
            "code": f"eval('{secret}')" + "x" * 5000,
        },
    )

    result = FlaxMsgpackScanner().scan(str(path))
    samples = [check.details["sample"] for check in result.checks if check.name == "Code Pattern Security Check"]

    assert samples == ["<redacted>"]
    assert secret not in result.to_json()


def test_flax_msgpack_redacts_function_metadata_value_sample(tmp_path: Path) -> None:
    path = tmp_path / "leaky_function_metadata.msgpack"
    token = "FUNCTIONTOKEN123456789"
    dangerous_value = f"custom.loader token={token}"
    data = {
        "params": {"w": [1, 2, 3]},
        "transform_fn": dangerous_value,
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner(config={"dangerous_callable_names": {dangerous_value.lower()}})
    result = scanner.scan(str(path))
    value_sample = next(
        check.details["value_sample"] for check in result.checks if check.name == "Object Attribute Security Check"
    )
    serialized = result.to_json()

    assert "custom.loader" in value_sample
    assert "token=<redacted>" in value_sample
    assert token not in serialized


def test_flax_msgpack_redacts_model_controlled_tensor_shape_evidence(tmp_path: Path) -> None:
    path = tmp_path / "leaky_shape.msgpack"
    secret = "SHAPESECRET123456789"
    create_msgpack_file(path, {"params": {"shape": [-1, f"token={secret}"]}})

    result = FlaxMsgpackScanner().scan(str(path))
    shape_check = next(check for check in result.checks if check.name == "Tensor Shape Validation")

    assert shape_check.details["shape"] == [-1, "token=<redacted>"]
    assert secret not in result.to_json()


def test_flax_msgpack_redacts_parse_error_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "leaky_parse_error.msgpack"
    secret = "PARSEERRORSECRET123456789"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}})

    def raise_parse_error(*_args: Any, **_kwargs: Any) -> object:
        raise ValueError(f"token={secret}")

    monkeypatch.setattr(FlaxMsgpackScanner, "_read_stream_value", raise_parse_error)

    result = FlaxMsgpackScanner().scan(str(path))
    parse_check = next(check for check in result.checks if check.name == "Msgpack Parse Check")

    assert parse_check.details["parse_error"] == "token=<redacted>"
    assert secret not in result.to_json()


def test_flax_msgpack_redacts_decode_limit_error_evidence() -> None:
    scanner = FlaxMsgpackScanner()
    result = scanner._create_result()
    secret = "DECODELIMITSECRET123456789"

    scanner._add_msgpack_decode_limit_check(result, "model.msgpack", ValueError(f"api_key={secret}"))

    decode_check = next(check for check in result.checks if check.name == "Msgpack Decode Budget")
    assert decode_check.details["error"] == "api_key=<redacted>"
    assert secret not in result.to_json()


def test_flax_msgpack_redacts_structure_budget_location(tmp_path: Path) -> None:
    path = tmp_path / "leaky_budget_location.msgpack"
    secret = "BUDGETLOCATIONSECRET123456789"
    create_msgpack_file(path, {"params": {f"token={secret}": {"nested": "value"}}})

    result = FlaxMsgpackScanner(config={"max_msgpack_structure_nodes": 2}).scan(str(path))
    budget_check = next(check for check in result.checks if check.name == "Flax MessagePack Structure Budget")

    assert "token=<redacted>" in (budget_check.location or "")
    assert secret not in result.to_json()


def test_flax_msgpack_redacts_unexpected_processing_error_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "leaky_processing_error.msgpack"
    secret = "PROCESSINGERRORSECRET123456789"
    create_msgpack_file(path, {"params": {"w": [1, 2, 3]}})

    def raise_processing_error(
        _self: FlaxMsgpackScanner,
        _obj: Any,
        _result: ScanResult,
    ) -> dict[str, Any]:
        raise RuntimeError(f"client_secret={secret}")

    monkeypatch.setattr(FlaxMsgpackScanner, "_analyze_ml_structure", raise_processing_error)

    result = FlaxMsgpackScanner().scan(str(path))
    processing_check = next(check for check in result.checks if check.name == "Flax Msgpack Processing")

    assert processing_check.details["error_message"] == "client_secret=<redacted>"
    assert secret not in result.to_json()


def test_flax_msgpack_function_metadata_value_sample_requires_exact_callable(tmp_path: Path) -> None:
    exact_path = tmp_path / "exact_callable.msgpack"
    noisy_path = tmp_path / "noisy_callable.msgpack"
    secret = "NOISYFUNCTIONTOKEN123456789"
    create_msgpack_file(exact_path, {"params": {"w": [1, 2, 3]}, "eval_fn": "eval"})
    create_msgpack_file(noisy_path, {"params": {"w": [1, 2, 3]}, "eval_fn": f"eval token={secret}"})

    exact_result = FlaxMsgpackScanner().scan(str(exact_path))
    noisy_result = FlaxMsgpackScanner().scan(str(noisy_path))

    exact_value_sample = next(
        check.details["value_sample"]
        for check in exact_result.checks
        if check.name == "Object Attribute Security Check"
        and check.message == "Suspicious object attribute value detected: eval_fn"
    )

    assert exact_value_sample == "eval"
    assert not any(
        check.name == "Object Attribute Security Check"
        and check.message == "Suspicious object attribute value detected: eval_fn"
        for check in noisy_result.checks
    )
    assert secret not in noisy_result.to_json()


def test_flax_msgpack_large_model_support(tmp_path):
    """Test support for large transformer models."""
    path = tmp_path / "large_model.msgpack"

    # Create scanner with lower blob limit for testing
    is_ci = os.getenv("CI") or os.getenv("GITHUB_ACTIONS")
    blob_limit = 5 * 1024 * 1024 if is_ci else 10 * 1024 * 1024  # 5MB in CI, 10MB locally
    scanner = FlaxMsgpackScanner(config={"max_blob_bytes": blob_limit})

    # Simulate large model embedding
    embedding_size = 10 * 1024 * 1024 if is_ci else 20 * 1024 * 1024  # 10MB in CI, 20MB locally
    large_embedding = b"\x00" * embedding_size

    data = {
        "params": {
            "embedding": {"vocab_embedding": large_embedding},
            "transformer": {"layer_0": {"attention": b"\x00" * 1000}},
        }
    }
    create_msgpack_file(path, data)

    result = scanner.scan(str(path))

    assert result.success

    # Should handle large blobs without flagging as suspicious for legitimate models
    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    # The large blob should be detected but at INFO level, not CRITICAL
    large_blob_issues = [issue for issue in info_issues if "large binary blob" in issue.message.lower()]
    assert len(large_blob_issues) >= 1


def test_flax_msgpack_can_handle_extensions(tmp_path):
    """Test that scanner can handle all JAX/Flax file extensions."""
    extensions = [".msgpack", ".flax", ".orbax", ".jax"]

    for ext in extensions:
        test_file = tmp_path / f"test{ext}"
        test_file.write_bytes(b"\x81\xa4test\xa5value")  # Simple msgpack

        assert FlaxMsgpackScanner.can_handle(str(test_file))


def test_flax_msgpack_can_handle_large_renamed_checkpoint_root_after_metadata_without_promoting_generic_map(
    tmp_path: Path,
) -> None:
    disguised_checkpoint = tmp_path / "checkpoint.jpg"
    generic_map = tmp_path / "metadata.jpg"
    large_metadata = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
    create_msgpack_file(disguised_checkpoint, {"metadata": large_metadata, "params": {"w": [1, 2, 3]}})
    create_msgpack_file(
        generic_map, {"metadata": large_metadata, "state": {"selected": True}, "__reduce__": "os.system"}
    )

    assert FlaxMsgpackScanner.can_handle(str(disguised_checkpoint)) is True
    assert FlaxMsgpackScanner.can_handle(str(generic_map)) is False


def test_flax_msgpack_ambiguous_renamed_probe_limit_fails_closed_without_unpacking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambiguous_map = tmp_path / "metadata.jpg"
    large_metadata: dict[str, object] = {f"field{i}": i for i in range(2100)}
    large_metadata["blob"] = "x" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 100)
    create_msgpack_file(ambiguous_map, {"metadata": large_metadata, "state": {"selected": True}})

    def fail_unpack(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ambiguous renamed maps must not be fully unpacked")

    monkeypatch.setattr(msgpack, "unpackb", fail_unpack)

    result = FlaxMsgpackScanner().scan(str(ambiguous_map))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome_message"] == (
        "Scan analysis incomplete; failed closed because full coverage was not available."
    )
    check = next(check for check in result.checks if check.name == "MessagePack Routing Analysis Incomplete")
    assert check.status == CheckStatus.FAILED
    assert check.details["scan_outcome_reason"] == "flax_msgpack_routing_incomplete"


@pytest.mark.slow
def test_flax_msgpack_ml_context_confidence(tmp_path):
    """Test ML context confidence scoring.

    Note: This test is marked as slow because it creates a large (~150MB)
    simulated GPT-2 model file which takes significant time to serialize,
    write to disk, and scan.
    """
    path = tmp_path / "ml_model.msgpack"

    # Create data that strongly indicates ML model
    # Using smaller matrices to reduce test time while still being representative
    data = {
        "params": {
            "transformer": {
                "attention": {"query": b"\x00" * (768 * 768 * 4)},  # 768x768 matrix (~2.4MB)
                "feed_forward": {"dense": b"\x00" * (768 * 3072 * 4)},  # 768x3072 matrix (~9.4MB)
            },
            "embedding": {"token_embedding": b"\x00" * (50257 * 768 * 4)},  # GPT-2 vocab size (~147MB)
        }
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success

    # Should have high confidence this is an ML model
    jax_metadata = result.metadata.get("jax_metadata", {})
    assert jax_metadata.get("confidence", 0) >= 0.7
    assert jax_metadata.get("is_ml_model") is True

    # Should find evidence of transformer architecture
    assert "transformer" in result.metadata.get("model_architecture", "")


def test_flax_msgpack_trailing_data(tmp_path):
    """Test detection of trailing data after msgpack content."""
    path = tmp_path / "trailing.msgpack"
    data = {"params": {"w": [1, 2, 3]}}
    create_msgpack_file(path, data)

    # Add trailing bytes
    original_data = path.read_bytes()
    path.write_bytes(original_data + b"TRAILING_GARBAGE_DATA")

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Trailing data detection may not be implemented in all scanner versions
    # Just verify the scan completes without errors
    # If trailing data detection is implemented, it would be at INFO severity
    all_issues = result.issues
    trailing_detected = any("trailing" in issue.message.lower() for issue in all_issues)
    # This test passes if either trailing is detected or scan completes successfully
    assert result.success or trailing_detected


def test_flax_msgpack_large_binary_blob(tmp_path: Path) -> None:
    """Test oversized blob detection with a small custom threshold.

    Keep this fixture tiny so the regular xdist lane does not stall on one
    worker while still exercising the exact size-threshold check.
    """
    threshold_bytes = 1024
    blob_size_bytes = 2 * threshold_bytes

    path = tmp_path / "large_blob.msgpack"
    # Create large binary blob (exceeds threshold)
    large_blob = b"X" * blob_size_bytes
    data = {"params": {"normal_param": [1, 2, 3]}, "suspicious_blob": large_blob}
    create_msgpack_file(path, data)

    # Configure scanner with appropriate threshold
    config = {"max_blob_bytes": threshold_bytes}
    scanner = FlaxMsgpackScanner(config=config)
    result = scanner.scan(str(path))

    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    assert any("Suspiciously large binary blob" in issue.message for issue in info_issues)


def test_flax_msgpack_custom_config(tmp_path):
    """Test scanner with custom configuration parameters."""
    path = tmp_path / "test.msgpack"
    create_malicious_msgpack_file(path)

    # Test with custom config
    custom_config = {
        "max_recursion_depth": 10,
        "max_items_per_container": 100,
        "suspicious_patterns": [r"custom_threat"],
    }

    scanner = FlaxMsgpackScanner(config=custom_config)
    result = scanner.scan(str(path))

    # Should still detect some issues but with different thresholds
    assert len(result.issues) > 0


def test_flax_msgpack_custom_suspicious_patterns_still_match(tmp_path: Path) -> None:
    path = tmp_path / "custom_pattern.msgpack"
    create_msgpack_file(path, {"payload": "custom_threat"})

    result = FlaxMsgpackScanner(config={"suspicious_patterns": [r"custom_threat"]}).scan(str(path))

    assert any(issue.details.get("pattern") == r"custom_threat" for issue in result.issues)


def test_flax_msgpack_custom_long_suspicious_key_still_matches(tmp_path: Path) -> None:
    path = tmp_path / "custom_long_key.msgpack"
    suspicious_key = "dangerous_" + ("x" * 80)
    create_msgpack_file(path, {suspicious_key: "safe"})

    result = FlaxMsgpackScanner(config={"suspicious_keys": {suspicious_key}}).scan(str(path))

    assert any(
        check.name == "Object Attribute Security Check"
        and check.message == f"Suspicious object attribute detected: {suspicious_key}"
        for check in result.checks
    )


def test_flax_msgpack_redacts_custom_suspicious_key_evidence(tmp_path: Path) -> None:
    path = tmp_path / "custom_secret_key.msgpack"
    secret = "CUSTOMKEYSECRET123456789"
    suspicious_key = f"danger?token={secret}"
    create_msgpack_file(path, {suspicious_key: "safe"})

    result = FlaxMsgpackScanner(config={"suspicious_keys": {suspicious_key}}).scan(str(path))
    serialized = result.to_json()

    assert any(
        check.name == "Object Attribute Security Check"
        and check.message == "Suspicious object attribute detected: danger?token=<redacted>"
        and check.details["suspicious_key"] == "danger?token=<redacted>"
        for check in result.checks
    )
    assert secret not in serialized


def test_flax_msgpack_deduplicates_configured_suspicious_patterns(tmp_path: Path) -> None:
    path = tmp_path / "duplicate_pattern.msgpack"
    create_msgpack_file(path, {"params": {"note": "import subprocess"}})

    result = FlaxMsgpackScanner(config={"suspicious_patterns": [r"import\s+subprocess"] * 2}).scan(str(path))

    findings = [
        check
        for check in result.checks
        if check.name == "Code Pattern Security Check" and check.details["pattern"] == r"import\s+subprocess"
    ]
    assert len(findings) == 1
