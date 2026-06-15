import importlib.abc
import io
import sys
import zipfile
from collections.abc import Callable, Sequence
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np
import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.cache_policy import should_cache_scan_result
from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.rules import Severity
from modelaudit.scanner_results import ACTIONABLE_FAILED_CHECKS_METADATA_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.numpy_scanner import (
    NUMPY_HEADER_MAX_SIZE,
    NumPyScanner,
    _numpy_object_reconstruction_reference_is_trusted,
    _read_numpy_array_header,
)

_MALFORMED_NUMPY_RECONSTRUCT_PAYLOAD = b"cnumpy._core.multiarray\n_reconstruct\n(NtR."


def test_numpy_scanner_valid(tmp_path):
    arr = np.arange(10)
    path = tmp_path / "array.npy"
    np.save(path, arr)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.bytes_scanned == path.stat().st_size
    assert not any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_numpy_scanner_truncated(tmp_path):
    arr = np.arange(10)
    path = tmp_path / "bad.npy"
    np.save(path, arr)
    data = path.read_bytes()[:-5]
    path.write_bytes(data)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_numpy_format_module_unavailable_is_operational_not_critical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arr = np.arange(3)
    path = tmp_path / "array.npy"
    np.save(path, arr)

    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.NUMPY_FORMAT_AVAILABLE", False)

    result = NumPyScanner().scan(str(path))

    assert result.success is False
    assert result.has_errors is False
    assert result.has_warnings is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "numpy_format_module_unavailable"
    assert "numpy_format_module_unavailable" in result.metadata["scan_outcome_reasons"]

    check = next(check for check in result.checks if check.name == "NumPy Format Module Check")
    assert check.severity == IssueSeverity.INFO
    assert check.details["analysis_incomplete"] is True
    assert check.details["operational_error"] is True
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_numpy_read_failure_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable.npy"
    np.save(path, np.arange(3))

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated NumPy read failure")

    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.open", raise_os_error, raising=False)

    direct = NumPyScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "NumPy File Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Unable to read NumPy file" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["operational_error"] is True
    assert read_checks[0].details["operational_error_reason"] == "numpy_read_failed"
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata["operational_error"] is True
    assert direct.metadata["operational_error_reason"] == "numpy_read_failed"
    assert "numpy_read_failed" in direct.metadata["scan_outcome_reasons"]
    assert aggregate.file_metadata[str(path)]["operational_error_reason"] == "numpy_read_failed"
    assert any(
        check.name == "NumPy File Read" and "Unable to read NumPy file" in check.message for check in aggregate.checks
    )
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_numpy_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "permission-denied.npy"
    np.save(path, np.arange(3))

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = NumPyScanner().scan(str(path))
    aggregate = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert direct.metadata["scan_outcome_reasons"] == ["numpy_read_failed"]
    assert direct.metadata["operational_error_reason"] == "numpy_read_failed"
    assert aggregate.file_metadata[str(path)]["operational_error_reason"] == "numpy_read_failed"
    assert determine_exit_code(aggregate) == 2


def test_numpy_header_read_oserror_is_operational_not_header_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "header-read-failure.npy"
    np.save(path, np.arange(3))

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated NumPy header read failure")

    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner.fmt.read_array_header_1_0",
        raise_os_error,
    )

    result = NumPyScanner().scan(str(path))

    read_checks = [check for check in result.checks if check.name == "NumPy File Read"]
    assert len(read_checks) == 1
    assert not [check for check in result.checks if check.name == "NumPy Header Read"]
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].rule_code is None
    assert read_checks[0].details["exception_type"] == "OSError"
    assert read_checks[0].details["operational_error_reason"] == "numpy_read_failed"
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "numpy_read_failed"


def test_numpy_read_failure_ignores_s902_severity_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unreadable-with-severity-override.npy"
    np.save(path, np.arange(3))

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated NumPy read failure")

    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.open", raise_os_error, raising=False)
    config = ModelAuditConfig()
    config.severity = {"S902": Severity.CRITICAL}
    set_config(config)

    try:
        result = NumPyScanner().scan(str(path))
    finally:
        reset_config()

    read_checks = [check for check in result.checks if check.name == "NumPy File Read"]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].rule_code is None
    assert all(issue.severity == IssueSeverity.INFO for issue in result.issues)
    assert all(issue.rule_code != "S902" for issue in result.issues)
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME


class TestCVE20196446ObjectDtype:
    """Tests for CVE-2019-6446: NumPy allow_pickle RCE via object dtype."""

    def test_object_dtype_triggers_cve(self, tmp_path: Path) -> None:
        """Object dtype array should trigger informational CVE-2019-6446 attribution."""
        arr = np.array(["hello", "world"], dtype=object)
        path = tmp_path / "object_array.npy"
        np.save(path, arr, allow_pickle=True)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        failed_checks = [
            (check.name, check.message, check.details) for check in result.checks if check.status != CheckStatus.PASSED
        ]
        assert result.success is True, (
            f"Benign object-dtype scan was incomplete: metadata={result.metadata!r}; failed_checks={failed_checks!r}"
        )
        cve_checks = [c for c in result.checks if "CVE-2019-6446" in c.name or "CVE-2019-6446" in c.message]
        assert len(cve_checks) > 0, f"Should detect CVE-2019-6446. Checks: {[c.message for c in result.checks]}"
        assert cve_checks[0].severity == IssueSeverity.INFO
        assert cve_checks[0].details.get("cve_id") == "CVE-2019-6446"
        assert not any(c.name == "Data Type Safety Check" and c.status.value == "failed" for c in result.checks), (
            f"Object dtype should not be treated as a scan failure: {[c.message for c in result.checks]}"
        )
        assert not any(issue.severity == IssueSeverity.WARNING for issue in result.issues), (
            f"Benign object-dtype payloads should not emit warnings: {[i.message for i in result.issues]}"
        )

    def test_numeric_dtype_no_cve(self, tmp_path):
        """Numeric dtype arrays should not trigger CVE-2019-6446."""
        arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        path = tmp_path / "float_array.npy"
        np.save(path, arr)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2019-6446" in (c.name + c.message)]
        assert len(cve_checks) == 0, "Numeric dtype should not trigger CVE"

    def test_structured_numeric_dtype_no_cve(self, tmp_path):
        """Structured dtype with only numeric fields should not trigger CVE-2019-6446."""
        dt = np.dtype([("x", np.float32), ("y", np.int32)])
        arr = np.array([(1.0, 2), (3.0, 4)], dtype=dt)
        path = tmp_path / "structured.npy"
        np.save(path, arr)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2019-6446" in (c.name + c.message)]
        assert len(cve_checks) == 0, "Pure numeric structured dtype should not trigger CVE"

    def test_cve_details_fields(self, tmp_path):
        """CVE-2019-6446 check should include cvss, cwe, remediation."""
        arr = np.array([None, "test"], dtype=object)
        path = tmp_path / "obj.npy"
        np.save(path, arr, allow_pickle=True)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2019-6446"]
        assert len(cve_checks) > 0
        details = cve_checks[0].details
        assert details["cvss"] == 9.8
        assert details["cwe"] == "CWE-502"
        assert "remediation" in details

    def test_structured_with_object_field_triggers_cve(self, tmp_path):
        """Structured dtype with object fields should trigger CVE-2019-6446."""
        dt = np.dtype([("x", np.float32), ("obj", object)])
        arr = np.array([(1.0, {"nested": "payload"})], dtype=dt)
        path = tmp_path / "struct_with_obj.npy"
        np.save(path, arr, allow_pickle=True)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        assert result.success is True
        cve_checks = [c for c in result.checks if "CVE-2019-6446" in (c.name + c.message)]
        assert len(cve_checks) > 0, "Structured dtype with object field should trigger CVE"


class _ExecPayload:
    def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
        return (exec, ("print('owned')",))


def _write_metadata_marker(path: str) -> None:
    Path(path).write_text("executed", encoding="utf-8")


class _MetadataExecPayload:
    def __init__(self, marker_path: Path) -> None:
        self.marker_path = str(marker_path)

    def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
        return (_write_metadata_marker, (self.marker_path,))


class _SSLPayload:
    def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
        import ssl

        return (ssl.get_server_certificate, (("example.com", 443),))


def _failed_checks(result: ScanResult) -> list[Check]:
    return [c for c in result.checks if c.status.value == "failed"]


def _replace_npy_data_payload(path: Path, payload: bytes) -> None:
    with path.open("rb") as handle:
        version = np.lib.format.read_magic(handle)
        if version == (1, 0):
            np.lib.format.read_array_header_1_0(handle)
        elif version == (2, 0):
            np.lib.format.read_array_header_2_0(handle)
        else:
            np.lib.format.read_array_header_1_0(handle)
        payload_start = handle.tell()
    path.write_bytes(path.read_bytes()[:payload_start] + payload)


def _assert_no_trailing_pickle_parse_noise(result: ScanResult) -> None:
    parse_noise_terms = (
        "parse_incomplete",
        "pickle parsing failed before full scan completion",
        "pickle parsing stopped before the stream was fully consumed",
        "stream was fully consumed",
    )
    check_text = " ".join(f"{check.name} {check.message}" for check in result.checks).lower()
    issue_text = " ".join(issue.message for issue in result.issues).lower()
    reasons = result.metadata.get("scan_outcome_reasons", [])

    assert not any(term in check_text for term in parse_noise_terms)
    assert not any(term in issue_text for term in parse_noise_terms)
    assert isinstance(reasons, list)
    assert "parse_incomplete" not in reasons


def test_numpy_metadata_extraction_preserves_numeric_header_and_stats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "numeric.npy"
    np.save(path, np.array([1.0, 2.0, 3.0], dtype=np.float32), allow_pickle=False)

    def fail_load(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("metadata extraction must not reopen the path with numpy.load")

    monkeypatch.setattr(np, "load", fail_load)

    metadata = NumPyScanner().extract_metadata(str(path))

    assert metadata["array_shape"] == [3]
    assert metadata["array_dtype"] == "float32"
    assert metadata["array_size"] == 3
    assert metadata["contains_objects"] is False
    assert metadata["min_value"] == 1.0
    assert metadata["max_value"] == 3.0


def test_numpy_metadata_extraction_preserves_v3_unicode_field_names(tmp_path: Path) -> None:
    path = tmp_path / "unicode-fields.npy"
    array = np.zeros(1, dtype=[("\u03bc", np.int64)])
    with path.open("wb") as handle:
        np.lib.format.write_array(handle, array, version=(3, 0), allow_pickle=False)

    metadata = NumPyScanner().extract_metadata(str(path))

    assert metadata["array_dtype"] == "[('\u03bc', '<i8')]"
    assert metadata["contains_objects"] is False
    assert "extraction_error" not in metadata


@pytest.mark.parametrize(
    (("version", "length_size", "header_length")),
    [
        ((1, 0), 2, NUMPY_HEADER_MAX_SIZE + 1),
        ((2, 0), 4, NUMPY_HEADER_MAX_SIZE + 1),
        ((3, 0), 4, (NUMPY_HEADER_MAX_SIZE * 4) + 1),
    ],
)
def test_numpy_metadata_extraction_bounds_header_reads(
    tmp_path: Path,
    version: tuple[int, int],
    length_size: int,
    header_length: int,
) -> None:
    path = tmp_path / f"oversized-v{version[0]}-header.npy"
    path.write_bytes(
        b"\x93NUMPY" + bytes(version) + header_length.to_bytes(length_size, "little"),
    )

    metadata = NumPyScanner().extract_metadata(str(path))

    assert "NumPy header is too large" in metadata["extraction_error"]


def test_numpy_metadata_extraction_bounds_v3_decoded_header_characters(tmp_path: Path) -> None:
    path = tmp_path / "oversized-v3-decoded-header.npy"
    header = b" " * (NUMPY_HEADER_MAX_SIZE + 1)
    path.write_bytes(b"\x93NUMPY\x03\x00" + len(header).to_bytes(4, "little") + header)

    metadata = NumPyScanner().extract_metadata(str(path))

    assert "NumPy header is too large" in metadata["extraction_error"]
    assert "characters" in metadata["extraction_error"]


def test_numpy_v3_unicode_header_uses_decoded_character_limit(tmp_path: Path) -> None:
    path = tmp_path / "long-unicode-header.npy"
    field_name = "\u03bc" * 5_000
    array = np.zeros(1, dtype=[(field_name, np.int8)])
    with path.open("wb") as handle:
        np.lib.format.write_array(handle, array, version=(3, 0), allow_pickle=False)

    with path.open("rb") as handle:
        assert np.lib.format.read_magic(handle) == (3, 0)
        header_length = int.from_bytes(handle.read(4), "little")
        header_bytes = handle.read(header_length)
    assert len(header_bytes) > NUMPY_HEADER_MAX_SIZE
    assert len(header_bytes.decode("utf-8")) <= NUMPY_HEADER_MAX_SIZE

    result = NumPyScanner().scan(str(path))
    metadata = NumPyScanner().extract_metadata(str(path))

    assert result.success is True
    assert metadata["array_dtype"] == f"[('{field_name}', 'i1')]"
    assert "extraction_error" not in metadata


@pytest.mark.parametrize((("version", "length_size")), [((1, 0), 2), ((2, 0), 4), ((3, 0), 4)])
def test_numpy_scan_rejects_boolean_shape_dimensions(
    tmp_path: Path,
    version: tuple[int, int],
    length_size: int,
) -> None:
    path = tmp_path / f"boolean-shape-v{version[0]}.npy"
    header = repr({"descr": "<i8", "fortran_order": False, "shape": (False,)}).encode("ascii")
    path.write_bytes(b"\x93NUMPY" + bytes(version) + len(header).to_bytes(length_size, "little") + header)

    result = NumPyScanner().scan(str(path))

    assert result.success is False
    assert any(
        check.name == "NumPy Header Read" and "Boolean NumPy shape dimensions are invalid" in check.message
        for check in result.checks
    )


@pytest.mark.parametrize((("version", "length_size")), [((1, 0), 2), ((2, 0), 4), ((3, 0), 4)])
def test_numpy_metadata_extraction_rejects_negative_shape_dimensions(
    tmp_path: Path,
    version: tuple[int, int],
    length_size: int,
) -> None:
    path = tmp_path / f"negative-shape-v{version[0]}.npy"
    header = repr({"descr": "<i8", "fortran_order": False, "shape": (-1,)}).encode("ascii")
    path.write_bytes(
        b"\x93NUMPY" + bytes(version) + len(header).to_bytes(length_size, "little") + header + (b"A" * 1024),
    )

    metadata = NumPyScanner().extract_metadata(str(path))

    assert metadata["extraction_error"] == "Negative NumPy shape dimensions are invalid"


def test_numpy_scan_accepts_empty_integer_dimension(tmp_path: Path) -> None:
    path = tmp_path / "empty.npy"
    np.save(path, np.empty((0,), dtype=np.int64), allow_pickle=False)

    result = NumPyScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["shape"] == (0,)


def test_numpy_header_parser_does_not_rewind_the_untrusted_stream() -> None:
    class NoRewindBytesIO(io.BytesIO):
        def seek(self, offset: int, whence: int = 0) -> int:
            raise AssertionError(f"unexpected rewind: {offset}, {whence}")

    encoded_header = io.BytesIO()
    np.lib.format.write_array_header_2_0(
        encoded_header,
        {"descr": "<i8", "fortran_order": False, "shape": (1,)},
    )
    stream = NoRewindBytesIO(encoded_header.getvalue())
    assert np.lib.format.read_magic(stream) == (2, 0)

    shape, fortran_order, dtype = _read_numpy_array_header(stream, (2, 0))

    assert shape == (1,)
    assert fortran_order is False
    assert dtype == np.dtype("<i8")


def test_numpy_metadata_extraction_does_not_flag_fixed_width_strings_as_objects(tmp_path: Path) -> None:
    path = tmp_path / "strings.npy"
    np.save(path, np.array(["abc"], dtype="U3"), allow_pickle=False)

    metadata = NumPyScanner().extract_metadata(str(path))

    assert metadata["contains_objects"] is False
    assert metadata["contains_strings"] is True
    assert "security_note" not in metadata


def test_numpy_metadata_extraction_never_deserializes_object_arrays(tmp_path: Path) -> None:
    marker_path = tmp_path / "metadata-executed"
    path = tmp_path / "object.npy"
    np.save(path, np.array([_MetadataExecPayload(marker_path)], dtype=object), allow_pickle=True)

    metadata = NumPyScanner({"allow_metadata_deserialization": True}).extract_metadata(str(path))

    assert marker_path.exists() is False
    assert metadata["array_shape"] == [1]
    assert metadata["array_dtype"] == "object"
    assert metadata["contains_objects"] is True
    assert metadata["deserialization_skipped"] is True
    assert metadata["allow_metadata_deserialization_ignored"] is True
    assert "unsafe pickle deserialization" in metadata["reason"]
    assert "extraction_error" not in metadata


def test_numpy_metadata_extraction_never_deserializes_structured_object_fields(tmp_path: Path) -> None:
    marker_path = tmp_path / "structured-metadata-executed"
    path = tmp_path / "structured-object.npy"
    array = np.empty(1, dtype=[("value", np.int64), ("payload", object)])
    array["value"] = 1
    array["payload"][0] = _MetadataExecPayload(marker_path)
    np.save(path, array, allow_pickle=True)

    metadata = NumPyScanner({"allow_metadata_deserialization": True}).extract_metadata(str(path))

    assert marker_path.exists() is False
    assert metadata["array_shape"] == [1]
    assert metadata["contains_objects"] is True
    assert metadata["deserialization_skipped"] is True
    assert metadata["allow_metadata_deserialization_ignored"] is True
    assert "unsafe pickle deserialization" in metadata["reason"]
    assert "extraction_error" not in metadata


@pytest.mark.parametrize(
    (("dtype", "shape")),
    [
        (np.dtype("<i8"), (1,)),
        (np.dtype("S8"), (1,)),
        (np.dtype("<i8"), ((10 * 1024 * 1024 // 8) + 1,)),
    ],
)
def test_numpy_metadata_extraction_reports_truncated_fixed_width_payloads(
    tmp_path: Path,
    dtype: np.dtype[Any],
    shape: tuple[int, ...],
) -> None:
    path = tmp_path / "truncated.npy"
    with path.open("wb") as handle:
        np.lib.format.write_array_header_2_0(
            handle,
            {"descr": np.lib.format.dtype_to_descr(dtype), "fortran_order": False, "shape": shape},
        )

    metadata = NumPyScanner().extract_metadata(str(path))

    assert metadata["array_shape"] == list(shape)
    assert metadata["array_dtype"] == str(dtype)
    assert metadata["extraction_error"].startswith("NumPy array data is truncated:")
    assert "found 0" in metadata["extraction_error"]


def _inject_comment_token_into_npy_payload(path: Path) -> None:
    with path.open("rb") as handle:
        major, minor = np.lib.format.read_magic(handle)
        if (major, minor) == (1, 0):
            np.lib.format.read_array_header_1_0(handle)
        elif (major, minor) == (2, 0):
            np.lib.format.read_array_header_2_0(handle)
        else:
            read_array_header = getattr(np.lib.format, "_read_array_header", None)
            if read_array_header is None:
                raise AssertionError(f"Unsupported NumPy header version: {(major, minor)}")
            read_array_header(handle, version=(major, minor))
        data_offset = handle.tell()
        payload = handle.read()

    if len(payload) < 2 or payload[0] != 0x80:
        raise AssertionError(f"Unexpected pickle payload header: {payload[:4]!r}")

    protocol = payload[1]
    comment = b"# harmless note"
    if protocol >= 4:
        comment_op = b"\x8c" + bytes([len(comment)]) + comment
    else:
        comment_op = b"X" + len(comment).to_bytes(4, "little") + comment

    patched = payload[:2] + comment_op + b"0" + payload[2:]
    original = path.read_bytes()
    path.write_bytes(original[:data_offset] + patched)


def _inject_comment_token_into_npz_member(path: Path, member_name: str) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    member_path = path.parent / member_name
    member_path.write_bytes(members[member_name])
    _inject_comment_token_into_npy_payload(member_path)
    members[member_name] = member_path.read_bytes()
    member_path.unlink()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def test_object_dtype_numpy_recurses_into_pickle_exec(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object.npy"
    np.save(path, arr, allow_pickle=True)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.has_errors is True
    failed = _failed_checks(result)
    assert any("CVE-2019-6446" in (c.name + c.message) for c in failed)
    assert any("exec" in (c.message.lower()) for c in failed)
    assert any(
        issue.rule_code == "S104" and "S115" in issue.details.get("legacy_rule_aliases", []) for issue in result.issues
    )


def test_object_dtype_numpy_recurses_into_pickle_ssl(tmp_path: Path) -> None:
    arr = np.array([_SSLPayload()], dtype=object)
    path = tmp_path / "malicious_ssl_object.npy"
    np.save(path, arr, allow_pickle=True)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.has_errors is True
    failed = _failed_checks(result)
    assert any("CVE-2019-6446" in (c.name + c.message) for c in failed)
    assert any("ssl.get_server_certificate" in c.message for c in failed)


def test_numeric_npz_has_no_pickle_recursion_findings(tmp_path: Path) -> None:
    npz_path = tmp_path / "numeric_only.npz"
    np.savez(npz_path, a=np.arange(4), b=np.ones((2, 2), dtype=np.float32))

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    assert not any("CVE-2019-6446" in (c.name + c.message) for c in result.checks)
    assert not any("exec" in c.message.lower() for c in result.checks)
    assert not any(i.details.get("cve_id") == "CVE-2019-6446" for i in result.issues)
    assert not any("exec" in i.message.lower() for i in result.issues)


def test_object_npz_member_recurses_into_pickle_exec_with_member_context(tmp_path: Path) -> None:
    safe = np.array([1, 2, 3], dtype=np.int64)
    malicious = np.array([_ExecPayload()], dtype=object)
    npz_path = tmp_path / "mixed_object.npz"
    np.savez(npz_path, safe=safe, payload=malicious)

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    failed = _failed_checks(result)
    assert any("CVE-2019-6446" in (c.name + c.message) and "payload.npy" in str(c.location) for c in failed)
    assert any("exec" in i.message.lower() and i.details.get("zip_entry") == "payload.npy" for i in result.issues)


def test_object_dtype_numpy_comment_token_bypass_still_detected(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "comment_token.npy"
    np.save(path, arr, allow_pickle=True)
    _inject_comment_token_into_npy_payload(path)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    failed = _failed_checks(result)
    assert any("CVE-2019-6446" in (c.name + c.message) for c in failed)
    assert any("exec" in c.message.lower() for c in failed)


def test_object_npz_member_comment_token_bypass_still_detected(tmp_path: Path) -> None:
    npz_path = tmp_path / "comment_token.npz"
    np.savez(npz_path, payload=np.array([_ExecPayload()], dtype=object))
    _inject_comment_token_into_npz_member(npz_path, "payload.npy")

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    failed = _failed_checks(result)
    assert any("CVE-2019-6446" in (c.name + c.message) and "payload.npy" in str(c.location) for c in failed)
    assert any("exec" in i.message.lower() and i.details.get("zip_entry") == "payload.npy" for i in result.issues)


def test_benign_object_dtype_numpy_no_nested_critical(tmp_path: Path) -> None:
    arr = np.array([{"k": "v"}, [1, 2, 3]], dtype=object)
    path = tmp_path / "benign_object.npy"
    np.save(path, arr, allow_pickle=True)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.has_errors is False
    assert any("CVE-2019-6446" in (c.name + c.message) for c in result.checks)
    assert not any(i.severity == IssueSeverity.CRITICAL for i in result.issues if "CVE-2019-6446" not in i.message)


def test_object_dtype_numpy_preserves_untrusted_reconstruction_origin_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import modelaudit_picklescan.api as picklescan_api

    untrusted_references = {
        "numpy._core.multiarray._reconstruct",
        "numpy.core.multiarray._reconstruct",
        "numpy.dtype",
        "numpy.ndarray",
    }
    original_picklescan_trust = picklescan_api.import_only_reference_is_proven_trusted
    original_requires_origin_review = picklescan_api.import_only_module_requires_origin_review

    def trust_reference(module: str, name: str) -> bool:
        if f"{module}.{name}" in untrusted_references:
            return False
        return original_picklescan_trust(module, name)

    def requires_origin_review(module: str, name: str) -> bool:
        if f"{module}.{name}" in untrusted_references:
            return True
        return original_requires_origin_review(module, name)

    monkeypatch.setattr(picklescan_api, "import_only_reference_is_proven_trusted", trust_reference)
    monkeypatch.setattr(picklescan_api, "import_only_module_requires_origin_review", requires_origin_review)
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_reconstruction_reference_is_trusted",
        lambda module, name: False if f"{module}.{name}" in untrusted_references else trust_reference(module, name),
    )

    arr = np.array([{"k": "v"}, [1, 2, 3]], dtype=object)
    path = tmp_path / "untrusted_reconstruction.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert determine_exit_code(result) == 1
    assert any(
        item.rule_code == "NON_ALLOWLISTED_GLOBAL" and item.details.get("import_reference") in untrusted_references
        for item in result.issues
    )


def test_object_dtype_numpy_malformed_reconstruct_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "malformed_reconstruct.npy"
    np.save(path, np.array([None], dtype=object), allow_pickle=True)
    _replace_npy_data_payload(path, _MALFORMED_NUMPY_RECONSTRUCT_PAYLOAD)

    result = scan_model_directory_or_file(str(path), cache_scan_results=False)

    assert determine_exit_code(result) == 1
    assert any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("import_reference") == "numpy._core.multiarray._reconstruct"
        for issue in result.issues
    )


def test_numpy_object_reconstruction_trust_fails_closed_without_picklescan_owner_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.import_only_reference_is_proven_trusted", lambda *_: False)
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._picklescan_loaded_site_package_reference_owner_matches",
        None,
    )

    assert _numpy_object_reconstruction_reference_is_trusted("numpy", "dtype") is False


def test_numpy_object_reconstruction_trust_does_not_import_unloaded_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_module = "numpy.core.multiarray"
    target_name = "_reconstruct"
    target_reference = f"{target_module}.{target_name}"
    import_marker = tmp_path / "import-hook-fired"
    path = tmp_path / "shadowed_numpy_reconstruct.npy"
    np.save(path, np.array([{"k": "v"}], dtype=object), allow_pickle=True)

    class RecordingImportHook(importlib.abc.MetaPathFinder):
        def find_spec(
            self,
            fullname: str,
            path: Sequence[str] | None,
            target: ModuleType | None = None,
        ) -> ModuleSpec | None:
            del path, target
            if fullname == target_module:
                import_marker.write_text("imported", encoding="utf-8")
                raise AssertionError("trust fallback must not import after origin proof fails")
            return None

    def trust_reference(_module: str, _name: str) -> bool:
        return False

    def fake_embedded_scan(
        self: NumPyScanner,
        file_obj: Any,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        del self, payload_size
        result = ScanResult(scanner_name="pickle")
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="untrusted NumPy reconstruction",
            severity=IssueSeverity.WARNING,
            location=context_path,
            details={
                "import_reference": target_reference,
                "module": target_module,
                "name": target_name,
                "position": file_obj.tell(),
            },
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
        result.finish(success=False)
        return result

    monkeypatch.delitem(sys.modules, target_module, raising=False)
    monkeypatch.setattr(sys, "meta_path", [RecordingImportHook(), *sys.meta_path])
    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.import_only_reference_is_proven_trusted", trust_reference)
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_payload_has_safe_reconstruct_proof",
        lambda _payload: True,
    )
    monkeypatch.setattr(NumPyScanner, "_scan_embedded_pickle_payload", fake_embedded_scan)

    result = NumPyScanner().scan(str(path))

    assert import_marker.exists() is False
    assert result.success is False
    assert any(
        check.rule_code == "NON_ALLOWLISTED_GLOBAL" and check.details.get("import_reference") == target_reference
        for check in result.checks
    )


def test_numpy_object_reconstruction_trust_uses_loaded_numpy_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "loaded_numpy_dtype.npy"
    np.save(path, np.array([{"k": "v"}], dtype=object), allow_pickle=True)

    def trust_reference(_module: str, _name: str) -> bool:
        raise RuntimeError("forced primary trust failure")

    def fake_embedded_scan(
        self: NumPyScanner,
        file_obj: Any,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        del self, payload_size
        result = ScanResult(scanner_name="pickle")
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="trusted loaded dtype",
            severity=IssueSeverity.WARNING,
            location=context_path,
            details={
                "import_reference": "numpy.dtype",
                "module": "numpy",
                "name": "dtype",
                "position": file_obj.tell(),
            },
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
        result.finish(success=False)
        return result

    monkeypatch.setattr("modelaudit.scanners.numpy_scanner.import_only_reference_is_proven_trusted", trust_reference)
    monkeypatch.setattr(NumPyScanner, "_scan_embedded_pickle_payload", fake_embedded_scan)

    result = NumPyScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["embedded_pickle_scan_success"] is False
    assert not result.has_warnings
    assert not any(check.rule_code == "NON_ALLOWLISTED_GLOBAL" for check in result.checks)
    assert not any(issue.rule_code == "NON_ALLOWLISTED_GLOBAL" for issue in result.issues)


def test_numpy_object_dtype_benign_exit0(tmp_path: Path) -> None:
    arr = np.array([{"k": "v"}, [1, 2, 3]], dtype=object)
    path = tmp_path / "benign_object.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(str(path))

    assert determine_exit_code(result) == 0
    assert not any(issue.severity == IssueSeverity.WARNING for issue in result.issues)
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_numpy_object_dtype_benign_direct_scan_success_after_reconstruction_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arr = np.array([{"k": "v"}, [1, 2, 3]], dtype=object)
    path = tmp_path / "benign_object_direct.npy"
    np.save(path, arr, allow_pickle=True)

    def fake_embedded_scan(
        self: NumPyScanner,
        file_obj: Any,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        result = ScanResult(scanner_name="pickle")
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="validated reconstruct",
            severity=IssueSeverity.WARNING,
            location=context_path,
            details={
                "import_reference": "numpy._core.multiarray._reconstruct",
                "module": "numpy._core.multiarray",
                "name": "_reconstruct",
                "position": file_obj.tell(),
            },
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
        result.finish(success=False)
        return result

    monkeypatch.setattr(NumPyScanner, "_scan_embedded_pickle_payload", fake_embedded_scan)
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_reconstruction_reference_is_trusted",
        lambda _module, _name: True,
    )
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_payload_has_safe_reconstruct_proof",
        lambda _payload: True,
    )

    result = NumPyScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["embedded_pickle_scan_success"] is False
    assert not result.has_warnings
    assert not result.has_errors
    assert not any(check.rule_code == "NON_ALLOWLISTED_GLOBAL" for check in result.checks)
    assert not any(issue.rule_code == "NON_ALLOWLISTED_GLOBAL" for issue in result.issues)
    serialized_result = result.to_dict(include_private_metadata=True)
    private_metadata = serialized_result.get("_private_metadata", {})
    assert isinstance(private_metadata, dict)
    assert ACTIONABLE_FAILED_CHECKS_METADATA_KEY not in private_metadata
    assert should_cache_scan_result(serialized_result) is True


def test_numpy_object_dtype_direct_scan_preserves_retained_embedded_failure_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arr = np.array([{"k": "v"}], dtype=object)
    path = tmp_path / "malicious_object_direct.npy"
    np.save(path, arr, allow_pickle=True)

    def fake_embedded_scan(
        self: NumPyScanner,
        file_obj: Any,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        result = ScanResult(scanner_name="pickle")
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="validated reconstruct",
            severity=IssueSeverity.WARNING,
            location=context_path,
            details={
                "import_reference": "numpy._core.multiarray._reconstruct",
                "module": "numpy._core.multiarray",
                "name": "_reconstruct",
                "position": file_obj.tell(),
            },
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="dangerous reduce",
            severity=IssueSeverity.CRITICAL,
            location=context_path,
            details={
                "associated_global": "builtins.exec",
                "module": "builtins",
                "name": "exec",
                "position": file_obj.tell() + 1,
            },
            rule_code="S209",
        )
        result.finish(success=False)
        return result

    monkeypatch.setattr(NumPyScanner, "_scan_embedded_pickle_payload", fake_embedded_scan)
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_reconstruction_reference_is_trusted",
        lambda _module, _name: True,
    )
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_payload_has_safe_reconstruct_proof",
        lambda _payload: True,
    )

    result = NumPyScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["embedded_pickle_scan_success"] is False
    assert result.has_errors is True
    assert not any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("import_reference") == "numpy._core.multiarray._reconstruct"
        for issue in result.issues
    )
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_numpy_object_dtype_cleanup_keeps_untrusted_numpy_reconstruction_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = ScanResult("numpy")
    result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="untrusted dtype",
        severity=IssueSeverity.WARNING,
        details={"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": 209},
        rule_code="NON_ALLOWLISTED_GLOBAL",
    )

    def trust_reconstruction_origin(module: str, name: str) -> bool:
        return (module, name) != ("numpy", "dtype")

    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner.import_only_reference_is_proven_trusted",
        trust_reconstruction_origin,
    )
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._picklescan_loaded_site_package_reference_owner_matches",
        None,
    )

    NumPyScanner._remove_validated_numpy_object_reconstruction_findings(
        result,
        safe_numpy_reconstruct_payload=True,
    )

    assert [check.details.get("position") for check in result.checks] == [209]
    assert [issue.details.get("position") for issue in result.issues] == [209]


def test_numpy_object_dtype_cleanup_filters_matching_private_failed_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def add_validated_dtype_check(scan_result: ScanResult) -> None:
        scan_result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="validated dtype",
            severity=IssueSeverity.WARNING,
            details={"import_reference": "numpy.dtype", "module": "numpy", "name": "dtype", "position": 209},
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )

    benign_result = ScanResult("numpy")
    add_validated_dtype_check(benign_result)
    benign_result.checks[0].severity = IssueSeverity.INFO
    benign_result.issues[0].severity = IssueSeverity.INFO

    result = ScanResult("numpy")
    add_validated_dtype_check(result)
    result.add_check(
        name="Dangerous Embedded Code",
        passed=False,
        message="dangerous global",
        severity=IssueSeverity.CRITICAL,
        details={"import_reference": "builtins.exec", "module": "builtins", "name": "exec", "position": 212},
        rule_code="S101",
    )

    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_reconstruction_reference_is_trusted",
        lambda _module, _name: True,
    )

    NumPyScanner._remove_validated_numpy_object_reconstruction_findings(
        benign_result,
        safe_numpy_reconstruct_payload=True,
    )
    NumPyScanner._remove_validated_numpy_object_reconstruction_findings(
        result,
        safe_numpy_reconstruct_payload=True,
    )

    assert benign_result.checks == []
    assert benign_result.issues == []
    assert ACTIONABLE_FAILED_CHECKS_METADATA_KEY not in benign_result._private_metadata
    assert [(check.name, check.rule_code) for check in result.checks] == [("Dangerous Embedded Code", "S101")]
    assert [(issue.message, issue.rule_code) for issue in result.issues] == [("dangerous global", "S101")]
    assert result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY] == [
        {"name": "Dangerous Embedded Code", "rule_code": "S101", "severity": "critical"}
    ]


def test_numpy_object_dtype_direct_scan_preserves_info_downgraded_embedded_private_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arr = np.array([{"k": "v"}], dtype=object)
    path = tmp_path / "info_downgraded_private.npy"
    np.save(path, arr, allow_pickle=True)

    def fake_embedded_scan(
        self: NumPyScanner,
        file_obj: Any,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        result = ScanResult(scanner_name="pickle")
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="validated reconstruct",
            severity=IssueSeverity.WARNING,
            location=context_path,
            details={
                "import_reference": "numpy._core.multiarray._reconstruct",
                "module": "numpy._core.multiarray",
                "name": "_reconstruct",
                "position": file_obj.tell(),
            },
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
        result.add_check(
            name="Dangerous Embedded Code",
            passed=False,
            message="dangerous global",
            severity=IssueSeverity.CRITICAL,
            location=context_path,
            details={"import_reference": "builtins.exec", "module": "builtins", "name": "exec", "position": 212},
            rule_code="S101",
        )
        result.checks[-1].severity = IssueSeverity.INFO
        result.issues[-1].severity = IssueSeverity.INFO
        result.finish(success=True)
        return result

    monkeypatch.setattr(NumPyScanner, "_scan_embedded_pickle_payload", fake_embedded_scan)
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_reconstruction_reference_is_trusted",
        lambda _module, _name: True,
    )
    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_payload_has_safe_reconstruct_proof",
        lambda _payload: True,
    )

    result = NumPyScanner().scan(str(path))

    assert result.success is True
    assert not result.has_warnings
    assert result._private_metadata[ACTIONABLE_FAILED_CHECKS_METADATA_KEY] == [
        {"name": "Dangerous Embedded Code", "rule_code": "S101", "severity": "critical"}
    ]
    assert not should_cache_scan_result(result.to_dict(include_private_metadata=True))


def test_numpy_object_dtype_malicious_exit1(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(str(path))

    assert determine_exit_code(result) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    direct_result = NumPyScanner().scan(str(path))

    assert direct_result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct_result.issues)


def test_numpy_object_dtype_pickle_selection_skip_is_inconclusive(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object_numpy_only.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(
        str(path),
        scanners=["numpy"],
        cache_scan_results=False,
    )
    metadata = result.file_metadata[str(path)]
    reasons = metadata.get("scan_outcome_reasons", [])
    selection_checks = [
        check
        for check in result.checks
        if check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
    ]
    dtype_checks = [
        check
        for check in result.checks
        if check.name == "Data Type Safety Check" and check.details.get("handled_via") == "scanner_selection_skip"
    ]

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "numpy_object_embedded_pickle_scanner_selection_skip" in reasons
    assert "numpy_object_embedded_pickle_incomplete" in reasons
    assert selection_checks
    assert selection_checks[0].details["analysis_incomplete"] is True
    assert selection_checks[0].details["scan_outcome_reason"] == "numpy_object_embedded_pickle_scanner_selection_skip"
    assert dtype_checks
    assert dtype_checks[0].details["analysis_incomplete"] is True
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert not any("exec" in issue.message.lower() for issue in result.issues)


def test_numpy_object_dtype_pickle_exclusion_is_inconclusive_and_not_cached(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object_pickle_excluded.npy"
    cache_dir = tmp_path / "cache"
    np.save(path, arr, allow_pickle=True)

    reset_cache_manager()
    try:
        results = [
            scan_model_directory_or_file(
                str(path),
                exclude_scanners=["pickle"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]

        for result in results:
            metadata = result.file_metadata[str(path)]
            selection_check = next(
                check
                for check in result.checks
                if check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
            )

            assert result.success is False
            assert determine_exit_code(result) == 2
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "numpy_object_embedded_pickle_scanner_selection_skip" in metadata["scan_outcome_reasons"]
            assert "embedded NumPy object pickle analysis" in selection_check.message
            assert selection_check.details["analysis_incomplete"] is True
            assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
            assert not any("exec" in issue.message.lower() for issue in result.issues)

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_numpy_structured_object_field_pickle_selection_skip_is_inconclusive(tmp_path: Path) -> None:
    dtype = np.dtype([("payload", object), ("score", np.int64)])
    arr = np.array([(_ExecPayload(), 7)], dtype=dtype)
    path = tmp_path / "structured_object_numpy_only.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(
        str(path),
        scanners=["numpy"],
        cache_scan_results=False,
    )
    metadata = result.file_metadata[str(path)]
    reasons = metadata.get("scan_outcome_reasons", [])
    dtype_checks = [
        check
        for check in result.checks
        if check.name == "Data Type Safety Check" and check.details.get("handled_via") == "scanner_selection_skip"
    ]

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "numpy_object_embedded_pickle_scanner_selection_skip" in reasons
    assert "numpy_object_embedded_pickle_incomplete" in reasons
    assert dtype_checks
    assert dtype_checks[0].details["dtype_kind"] == "V"
    assert dtype_checks[0].details["analysis_incomplete"] is True
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert not any("exec" in issue.message.lower() for issue in result.issues)


def test_numpy_numeric_dtype_numpy_only_remains_conclusive(tmp_path: Path) -> None:
    path = tmp_path / "numeric_numpy_only.npy"
    np.save(path, np.arange(4))

    result = scan_model_directory_or_file(
        str(path),
        scanners=["numpy"],
        cache_scan_results=False,
    )
    metadata = result.file_metadata[str(path)]

    assert result.success is True
    assert determine_exit_code(result) == 0
    assert metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert not any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
        for check in result.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_numpy_object_dtype_pickle_selection_control_detects_exec(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object_numpy_and_pickle.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(
        str(path),
        scanners=["numpy", "pickle"],
        cache_scan_results=False,
    )
    metadata = result.file_metadata[str(path)]

    assert determine_exit_code(result) == 1
    assert metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        issue.rule_code == "S104"
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("associated_global") == "builtins.exec"
        for issue in result.issues
    )


def test_numpy_object_npz_pickle_selection_skip_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "malicious_object_numpy_only.npz"
    np.savez(path, payload=np.array([_ExecPayload()], dtype=object))

    result = scan_model_directory_or_file(
        str(path),
        scanners=["zip", "numpy"],
        cache_scan_results=False,
    )
    metadata = result.file_metadata[str(path)]
    reasons = metadata.get("scan_outcome_reasons", [])
    selection_checks = [
        check
        for check in result.checks
        if check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
    ]

    assert result.success is False
    assert determine_exit_code(result) == 2
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "zip_analysis_incomplete" in reasons
    assert selection_checks
    assert selection_checks[0].details["analysis_incomplete"] is True
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert not any("exec" in issue.message.lower() for issue in result.issues)


def test_benign_object_dtype_npz_no_nested_critical(tmp_path: Path) -> None:
    npz_path = tmp_path / "benign_object.npz"
    np.savez(npz_path, safe=np.array([{"x": 1}], dtype=object))

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    assert any("CVE-2019-6446" in (c.name + c.message) for c in result.checks)
    assert not any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_truncated_npy_fails_safely(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "truncated.npy"
    np.save(path, arr, allow_pickle=True)
    path.write_bytes(path.read_bytes()[:-8])

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.has_errors is True
    assert any("exec" in i.message.lower() and i.severity == IssueSeverity.CRITICAL for i in result.issues)
    assert any(
        i.severity in {IssueSeverity.INFO, IssueSeverity.WARNING}
        and (
            "corrupted pickle" in i.message.lower()
            or "pickle parsing stopped before the stream was fully consumed" in i.message.lower()
        )
        for i in result.issues
    ), f"Expected a non-critical corruption finding, got: {[i.message for i in result.issues]}"


def test_object_dtype_numpy_trailing_bytes_fail_integrity(tmp_path: Path) -> None:
    arr = np.array([{"k": "v"}], dtype=object)
    path = tmp_path / "trailing.npy"
    np.save(path, arr, allow_pickle=True)
    path.write_bytes(path.read_bytes() + b"TRAILINGJUNK")

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert "numpy_object_pickle_trailing_bytes" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    _assert_no_trailing_pickle_parse_noise(result)
    assert any(
        check.name == "File Integrity Check"
        and check.status.value == "failed"
        and "trailing bytes" in check.message.lower()
        for check in result.checks
    ), f"Expected trailing-byte integrity failure, got: {[c.message for c in result.checks]}"


def test_object_dtype_numpy_trailing_bytes_exit2_not_security_finding(tmp_path: Path) -> None:
    arr = np.array([{"k": "v"}], dtype=object)
    path = tmp_path / "trailing.npy"
    np.save(path, arr, allow_pickle=True)
    path.write_bytes(path.read_bytes() + b"TRAILINGJUNK")

    result = scan_model_directory_or_file(str(path))
    metadata = next(iter(result.file_metadata.values()))

    assert result.success is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "numpy_object_pickle_trailing_bytes" in metadata.get("scan_outcome_reasons", [])
    assert determine_exit_code(result) == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_object_dtype_numpy_trailing_bytes_malicious_exit1(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_trailing.npy"
    np.save(path, arr, allow_pickle=True)
    path.write_bytes(path.read_bytes() + b"TRAILINGJUNK")

    result = scan_model_directory_or_file(str(path))
    metadata = next(iter(result.file_metadata.values()))

    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(result) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_object_dtype_numpy_trailing_stream_keeps_unproven_reconstruct_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arr = np.array([{"k": "v"}], dtype=object)
    path = tmp_path / "safe_first_stream_unsafe_reconstruct_tail.npy"
    np.save(path, arr, allow_pickle=True)
    path.write_bytes(path.read_bytes() + b"TAIL")

    def payload_has_safe_reconstruct_proof(payload: bytes) -> bool:
        return not payload.endswith(b"TAIL")

    def fake_embedded_scan(
        self: NumPyScanner,
        file_obj: Any,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        result = ScanResult(scanner_name="pickle")
        result.metadata["first_pickle_end_pos"] = file_obj.tell() + 1
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message="unproven trailing reconstruct",
            severity=IssueSeverity.WARNING,
            location=context_path,
            details={
                "import_reference": "numpy._core.multiarray._reconstruct",
                "module": "numpy._core.multiarray",
                "name": "_reconstruct",
                "position": file_obj.tell() + 2,
            },
            rule_code="NON_ALLOWLISTED_GLOBAL",
        )
        result.finish(success=False)
        return result

    monkeypatch.setattr(
        "modelaudit.scanners.numpy_scanner._numpy_object_payload_has_safe_reconstruct_proof",
        payload_has_safe_reconstruct_proof,
    )
    monkeypatch.setattr(NumPyScanner, "_scan_embedded_pickle_payload", fake_embedded_scan)

    result = NumPyScanner().scan(str(path))

    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("import_reference") == "numpy._core.multiarray._reconstruct"
        for issue in result.issues
    )


def test_corrupted_npz_fails_safely(tmp_path: Path) -> None:
    npz_path = tmp_path / "corrupt.npz"
    npz_path.write_bytes(b"not-a-zip")

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    assert result.success is False
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)
