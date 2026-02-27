import numpy as np

from modelaudit.scanners.base import IssueSeverity
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
        """Object dtype array should trigger CVE-2019-6446 CRITICAL check."""
        arr = np.array(["hello", "world"], dtype=object)
        path = tmp_path / "object_array.npy"
        np.save(path, arr, allow_pickle=True)

        scanner = NumPyScanner()
        result = scanner.scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2019-6446" in c.name or "CVE-2019-6446" in c.message]
        assert len(cve_checks) > 0, f"Should detect CVE-2019-6446. Checks: {[c.message for c in result.checks]}"
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
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
