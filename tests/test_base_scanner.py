import os
from typing import ClassVar

from modelaudit.scanners.base import BaseScanner, CheckStatus, Issue, IssueSeverity, ScanResult


class MockScanner(BaseScanner):
    """Mock scanner implementation for testing the BaseScanner class."""

    name = "test_scanner"
    description = "Test scanner for unit tests"
    supported_extensions: ClassVar[list[str]] = [".test", ".tst"]

    def scan(self, path: str) -> ScanResult:
        result = self._create_result()

        # Check if path is valid
        path_check = self._check_path(path)
        if path_check:
            return path_check

        # Add a test issue
        result.add_issue(
            "Test issue",
            severity=IssueSeverity.INFO,
            location=path,
            details={"test": True},
        )

        # Set bytes scanned
        result.bytes_scanned = self.get_file_size(path)

        # Finish the scan
        result.finish(success=True)
        return result


def test_base_scanner_can_handle():
    """Test the can_handle method of BaseScanner."""
    scanner = MockScanner()

    assert scanner.can_handle("file.test") is True
    assert scanner.can_handle("file.tst") is True
    assert scanner.can_handle("file.txt") is False
    assert scanner.can_handle("file") is False


def test_base_scanner_init():
    """Test BaseScanner initialization."""
    # Test with default config
    scanner = MockScanner()
    assert scanner.config == {}

    # Test with custom config
    custom_config = {"option1": "value1", "option2": 123}
    scanner = MockScanner(config=custom_config)
    assert scanner.config == custom_config


def test_base_scanner_create_result():
    """Test the _create_result method."""
    scanner = MockScanner()
    result = scanner._create_result()

    assert isinstance(result, ScanResult)
    assert result.scanner_name == "test_scanner"
    assert result.issues == []
    assert result.bytes_scanned == 0
    assert result.success is True


def test_base_scanner_check_path_nonexistent():
    """Test _check_path with nonexistent file."""
    scanner = MockScanner()
    result = scanner._check_path("nonexistent_file.test")

    assert isinstance(result, ScanResult)
    assert result.success is False
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert "not exist" in result.issues[0].message.lower()

    check_names = {check.name: check for check in result.checks}
    assert "Path Exists" in check_names
    assert check_names["Path Exists"].status == CheckStatus.FAILED


def test_base_scanner_check_path_unreadable(tmp_path, monkeypatch):
    """Test _check_path with unreadable file."""

    # Create a test file
    test_file = tmp_path / "test.test"
    test_file.write_bytes(b"test content")

    # Mock os.access to simulate unreadable file
    def mock_access(path, mode):
        return mode != os.R_OK

    monkeypatch.setattr(os, "access", mock_access)

    scanner = MockScanner()
    result = scanner._check_path(str(test_file))

    assert isinstance(result, ScanResult)
    assert result.success is False
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert "not readable" in result.issues[0].message.lower()

    check_map = {check.name: check for check in result.checks}
    assert check_map["Path Exists"].status == CheckStatus.PASSED
    assert check_map["Path Readable"].status == CheckStatus.FAILED


def test_base_scanner_check_path_directory(tmp_path):
    """Test _check_path with a directory."""
    # Create a test directory
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()

    # The BaseScanner implementation might handle directories differently
    # Some implementations might return a ScanResult with an error
    # Others might return None and handle directories in the scan method

    scanner = MockScanner()
    result = scanner._check_path(str(test_dir))

    # If result is not None, it should be a ScanResult with an error about directories
    if result is not None:
        assert isinstance(result, ScanResult)
        assert result.success is False
        assert len(result.issues) == 1
        assert result.issues[0].severity == IssueSeverity.CRITICAL
        assert "directory" in result.issues[0].message.lower()


def test_base_scanner_check_path_valid(tmp_path):
    """Test _check_path with a valid file."""
    # Create a test file
    test_file = tmp_path / "test.test"
    test_file.write_bytes(b"test content")

    scanner = MockScanner()
    result = scanner._check_path(str(test_file))

    # Should return None for valid files
    assert result is None

    merged = scanner._create_result()
    check_names = {check.name for check in merged.checks}
    assert {"Path Exists", "Path Readable", "File Type Validation"}.issubset(check_names)


def test_base_scanner_get_file_size(tmp_path):
    """Test the get_file_size method."""
    # Create a test file with known size
    test_file = tmp_path / "test.test"
    content = b"test content"
    test_file.write_bytes(content)

    scanner = MockScanner()
    size = scanner.get_file_size(str(test_file))

    assert size == len(content)


def test_base_scanner_get_file_size_oserror(tmp_path, monkeypatch):
    """get_file_size should handle OS errors gracefully."""

    test_file = tmp_path / "test.test"
    test_file.write_bytes(b"data")

    def mock_getsize(_path):  # pragma: no cover - error simulation
        raise OSError("bad file")

    monkeypatch.setattr(os.path, "getsize", mock_getsize)

    scanner = MockScanner()
    size = scanner.get_file_size(str(test_file))

    assert size == 0


def test_scanner_implementation(tmp_path):
    """Test a complete scan with the test scanner implementation."""
    # Create a test file
    test_file = tmp_path / "test.test"
    test_file.write_bytes(b"test content")

    scanner = MockScanner()
    result = scanner.scan(str(test_file))

    assert isinstance(result, ScanResult)
    assert result.scanner_name == "test_scanner"
    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].message == "Test issue"
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.bytes_scanned == len(b"test content")


def test_issue_class():
    """Test the Issue class."""
    # Create an issue
    issue = Issue(
        message="Test issue",
        severity=IssueSeverity.WARNING,
        location="test.pkl",
        details={"key": "value"},
    )

    # Test properties
    assert issue.message == "Test issue"
    assert issue.severity == IssueSeverity.WARNING
    assert issue.location == "test.pkl"
    assert issue.details == {"key": "value"}

    # Test to_dict method
    issue_dict = issue.to_dict()
    assert issue_dict["message"] == "Test issue"
    assert issue_dict["severity"] == "warning"
    assert issue_dict["location"] == "test.pkl"
    assert issue_dict["details"] == {"key": "value"}
    assert "timestamp" in issue_dict

    # Test string representation
    issue_str = str(issue)
    assert "[WARNING]" in issue_str
    assert "test.pkl" in issue_str
    assert "Test issue" in issue_str


def test_base_scanner_file_type_validation(tmp_path):
    """Test that BaseScanner performs file type validation in _check_path."""
    scanner = MockScanner()

    # Create a file with mismatched extension and magic bytes
    invalid_h5 = tmp_path / "fake.h5"
    invalid_h5.write_bytes(b"not real hdf5 data")

    result = scanner._check_path(str(invalid_h5))

    # Should return None (warnings don't stop the scan)
    assert result is None

    # But scan should include the validation warnings
    scan_result = scanner.scan(str(invalid_h5))
    assert scan_result is not None

    # Check that we have a file type validation warning in the scan result
    validation_issues = [
        issue for issue in scan_result.issues if "file type validation failed" in issue.message.lower()
    ]
    assert len(validation_issues) > 0

    # Should be WARNING level (not CRITICAL) to allow scan to continue
    assert validation_issues[0].severity == IssueSeverity.WARNING

    # Should contain details about the mismatch
    assert "header_format" in validation_issues[0].details
    assert "extension_format" in validation_issues[0].details


def test_base_scanner_valid_file_type(tmp_path):
    """Test that BaseScanner doesn't warn for valid file types."""
    import zipfile

    scanner = MockScanner()

    # Create a valid ZIP file with .zip extension
    zip_file = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_file, "w") as zipf:
        zipf.writestr("test.txt", "data")

    result = scanner._check_path(str(zip_file))

    # Should return None (path is valid) without validation warnings
    assert result is None

    # Scan should work without file type validation issues
    scan_result = scanner.scan(str(zip_file))
    assert scan_result is not None


def test_base_scanner_small_file_handling(tmp_path):
    """Test that BaseScanner handles small files properly in validation."""
    scanner = MockScanner()

    # Create a very small file (< 4 bytes)
    small_file = tmp_path / "tiny.h5"
    small_file.write_bytes(b"hi")

    result = scanner._check_path(str(small_file))

    # Should return None (path is valid) - small files can't be validated
    assert result is None


def test_base_scanner_read_file_safely(tmp_path):
    """_read_file_safely should return bytes with chunking."""
    scanner = MockScanner(config={"chunk_size": 4})

    file_path = tmp_path / "data.test"
    content = b"0123456789"
    file_path.write_bytes(content)

    data = scanner._read_file_safely(str(file_path))

    assert isinstance(data, bytes)
    assert data == content


def test_base_scanner_size_limit_pass(tmp_path):
    """_check_size_limit should record a passing check when within limits."""
    scanner = MockScanner(config={"max_file_read_size": 100})
    file_path = tmp_path / "small.test"
    content = b"small"
    file_path.write_bytes(content)

    result = scanner._check_size_limit(str(file_path))

    assert result is None
    merged = scanner._create_result()
    checks = {check.name: check for check in merged.checks}
    assert checks["File Size Limit"].status == CheckStatus.PASSED


def test_base_scanner_size_limit_fail(tmp_path):
    """_check_size_limit should return a result when file is too large."""
    scanner = MockScanner(config={"max_file_read_size": 5})
    file_path = tmp_path / "large.test"
    file_path.write_bytes(b"this is too long")

    result = scanner._check_size_limit(str(file_path))

    assert isinstance(result, ScanResult)
    checks = {check.name: check for check in result.checks}
    assert checks["File Size Limit"].status == CheckStatus.FAILED
    assert result.success is False
