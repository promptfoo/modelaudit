import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from modelaudit.config import ModelAuditConfig, reset_config, set_config
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.rules import Severity
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.numpy_scanner import NumPyScanner


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

    def test_object_dtype_triggers_cve(self, tmp_path):
        """Object dtype array should trigger informational CVE-2019-6446 attribution."""
        arr = np.array(["hello", "world"], dtype=object)
        path = tmp_path / "object_array.npy"
        np.save(path, arr, allow_pickle=True)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        assert result.success is True
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


class _SSLPayload:
    def __reduce__(self) -> tuple[Callable[..., Any], tuple[Any, ...]]:
        import ssl

        return (ssl.get_server_certificate, (("example.com", 443),))


def _failed_checks(result: ScanResult) -> list[Check]:
    return [c for c in result.checks if c.status.value == "failed"]


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

    assert result.success is True
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

    assert result.success is True
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


def test_numpy_object_dtype_benign_exit0(tmp_path: Path) -> None:
    arr = np.array([{"k": "v"}, [1, 2, 3]], dtype=object)
    path = tmp_path / "benign_object.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(str(path))

    assert determine_exit_code(result) == 0
    assert not any(issue.severity == IssueSeverity.WARNING for issue in result.issues)
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_numpy_object_dtype_malicious_exit1(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object.npy"
    np.save(path, arr, allow_pickle=True)

    result = scan_model_directory_or_file(str(path))

    assert determine_exit_code(result) == 1
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


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


def test_corrupted_npz_fails_safely(tmp_path: Path) -> None:
    npz_path = tmp_path / "corrupt.npz"
    npz_path.write_bytes(b"not-a-zip")

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    assert result.success is False
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)
