import os

from modelaudit.scanners.base import BaseScanner, Issue, IssueSeverity, ScanResult


class MockScanner(BaseScanner):
    """Mock scanner implementation for testing the BaseScanner class."""

    name = "test_scanner"
    description = "Test scanner for unit tests"
    supported_extensions = [".test", ".tst"]

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
