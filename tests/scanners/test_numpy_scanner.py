from pathlib import Path

import numpy as np

from modelaudit.scanners.base import Check, IssueSeverity, ScanResult
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


class TestCVE20196446ObjectDtype:
    """Tests for CVE-2019-6446: NumPy allow_pickle RCE via object dtype."""

    def test_object_dtype_triggers_cve(self, tmp_path):
        """Object dtype array should trigger CVE-2019-6446 warning-level potential-RCE check."""
        arr = np.array(["hello", "world"], dtype=object)
        path = tmp_path / "object_array.npy"
        np.save(path, arr, allow_pickle=True)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2019-6446" in c.name or "CVE-2019-6446" in c.message]
        assert len(cve_checks) > 0, f"Should detect CVE-2019-6446. Checks: {[c.message for c in result.checks]}"
        assert cve_checks[0].severity == IssueSeverity.WARNING
        assert cve_checks[0].details.get("cve_id") == "CVE-2019-6446"

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

        cve_checks = [c for c in result.checks if "CVE-2019-6446" in (c.name + c.message)]
        assert len(cve_checks) > 0, "Structured dtype with object field should trigger CVE"


class _ExecPayload:
    def __reduce__(self):
        return (exec, ("print('owned')",))


class _SSLPayload:
    def __reduce__(self):
        import ssl

        return (ssl.get_server_certificate, (("example.com", 443),))


def _failed_checks(result: ScanResult) -> list[Check]:
    return [c for c in result.checks if c.status.value == "failed"]


def test_object_dtype_numpy_recurses_into_pickle_exec(tmp_path: Path) -> None:
    arr = np.array([_ExecPayload()], dtype=object)
    path = tmp_path / "malicious_object.npy"
    np.save(path, arr, allow_pickle=True)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    failed = _failed_checks(result)
    assert any("CVE-2019-6446" in (c.name + c.message) for c in failed)
    assert any("exec" in (c.message.lower()) for c in failed)


def test_object_dtype_numpy_recurses_into_pickle_ssl(tmp_path: Path) -> None:
    arr = np.array([_SSLPayload()], dtype=object)
    path = tmp_path / "malicious_ssl_object.npy"
    np.save(path, arr, allow_pickle=True)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

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


def test_benign_object_dtype_numpy_no_nested_critical(tmp_path: Path) -> None:
    arr = np.array([{"k": "v"}, [1, 2, 3]], dtype=object)
    path = tmp_path / "benign_object.npy"
    np.save(path, arr, allow_pickle=True)

    scanner = NumPyScanner()
    result = scanner.scan(str(path))

    assert any("CVE-2019-6446" in (c.name + c.message) for c in result.checks)
    assert not any(i.severity == IssueSeverity.CRITICAL for i in result.issues if "CVE-2019-6446" not in i.message)


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

    assert any(i.severity == IssueSeverity.INFO for i in result.issues)


def test_corrupted_npz_fails_safely(tmp_path: Path) -> None:
    npz_path = tmp_path / "corrupt.npz"
    npz_path.write_bytes(b"not-a-zip")

    from modelaudit.scanners.zip_scanner import ZipScanner

    result = ZipScanner().scan(str(npz_path))

    assert result.success is False
    assert any(i.severity == IssueSeverity.INFO for i in result.issues)
