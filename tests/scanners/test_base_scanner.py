import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

import pytest

from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.scanner_results import mark_inconclusive_scan_result
from modelaudit.scanners.base import (
    DEFAULT_READ_CHUNK_SIZE,
    INCONCLUSIVE_SCAN_OUTCOME,
    BaseScanner,
    CheckStatus,
    Issue,
    IssueSeverity,
    ScanResult,
    make_trusted_source_provenance,
)


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
        result._add_issue(
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


class TinyReadLimitScanner(MockScanner):
    """Mock scanner with a tiny default read cap for size-limit regression tests."""

    default_max_file_read_size: ClassVar[int] = 8


def _create_hf_cache_model_path(tmp_path: Path, model_id: str, *, cache_root: Path | None = None) -> Path:
    """Create a model file inside a HuggingFace cache-shaped layout."""
    namespace, repo = model_id.split("/", maxsplit=1)
    root = cache_root or (tmp_path / ".cache" / "huggingface" / "hub")
    model_path = root / f"models--{namespace}--{repo}" / "snapshots" / "abc123" / "model.test"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_bytes(b"test")
    return model_path


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


def test_base_scanner_calculate_file_hashes_spans_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hashing must be output-identical across the chunked read boundary."""
    content = (b"modelaudit-hash-payload" * 4096) + bytes(DEFAULT_READ_CHUNK_SIZE + 7)
    assert len(content) > DEFAULT_READ_CHUNK_SIZE

    test_file = tmp_path / "model.test"
    test_file.write_bytes(content)
    read_sizes: list[int] = []

    class RecordingReader:
        def __init__(self) -> None:
            self.offset = 0

        def __enter__(self) -> "RecordingReader":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            chunk = content[self.offset : self.offset + size]
            self.offset += len(chunk)
            return chunk

    def recording_open(*_args: Any, **_kwargs: Any) -> RecordingReader:
        return RecordingReader()

    monkeypatch.setattr("builtins.open", recording_open)

    hashes = MockScanner().calculate_file_hashes(str(test_file))

    assert read_sizes == [DEFAULT_READ_CHUNK_SIZE] * 3
    assert hashes["md5"] == hashlib.md5(content).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(content).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(content).hexdigest()


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
    # INFO severity creates passed checks, not issues
    assert len(result.issues) == 0
    assert len(result.checks) == 1
    assert result.checks[0].message == "Test issue"
    assert result.checks[0].severity == IssueSeverity.INFO
    assert result.checks[0].status == CheckStatus.PASSED
    assert result.bytes_scanned == len(b"test content")


def test_issue_class():
    """Test the Issue class."""
    # Create an issue
    issue = Issue(
        message="Test issue",
        severity=IssueSeverity.WARNING,
        location="test.pkl",
        details={"key": "value"},
        why=None,
        type=None,
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

    # Should be INFO level (informational - format mismatch not necessarily a security issue)
    assert validation_issues[0].severity == IssueSeverity.INFO

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


def test_base_scanner_size_limit_fail(tmp_path: Path) -> None:
    """_check_size_limit should return a result when file is too large."""
    scanner = MockScanner(config={"max_file_read_size": 5})
    file_path = tmp_path / "large.test"
    file_path.write_bytes(b"this is too long")

    result = scanner._check_size_limit(str(file_path))

    assert isinstance(result, ScanResult)
    checks = {check.name: check for check in result.checks}
    assert checks["File Size Limit"].status == CheckStatus.FAILED
    assert "File too large" in checks["File Size Limit"].message
    assert str(scanner.max_file_read_size) in checks["File Size Limit"].message
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]


def test_base_scanner_uses_bounded_default_read_limit() -> None:
    """Scanners should default to a bounded full-file read cap."""
    scanner = MockScanner()

    assert scanner.max_file_read_size == MockScanner.default_max_file_read_size


def test_base_scanner_default_read_limit_fails_closed(tmp_path: Path) -> None:
    """Default read caps should stop oversized files with an inconclusive result."""
    scanner = TinyReadLimitScanner()
    file_path = tmp_path / "large.test"
    file_path.write_bytes(b"this is too long")

    result = scanner._check_size_limit(str(file_path))

    assert isinstance(result, ScanResult)
    checks = {check.name: check for check in result.checks}
    assert checks["File Size Limit"].status == CheckStatus.FAILED
    assert "File too large" in checks["File Size Limit"].message
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["analysis_incomplete"] is True


def test_base_scanner_explicit_zero_read_limit_keeps_opt_out(tmp_path: Path) -> None:
    """Direct scanner config can still opt out of the read cap explicitly."""
    scanner = TinyReadLimitScanner(config={"max_file_read_size": 0})
    file_path = tmp_path / "large.test"
    file_path.write_bytes(b"this is too long")

    result = scanner._check_size_limit(str(file_path))

    assert result is None


def test_base_scanner_core_max_file_size_unlimited_keeps_default_read_cap() -> None:
    """Core-level unlimited max_file_size should not disable scanner read caps."""
    scanner = TinyReadLimitScanner(config={"max_file_size": 0})

    assert scanner.max_file_read_size == TinyReadLimitScanner.default_max_file_read_size


def test_base_scanner_core_max_file_size_unlimited_still_fails_closed(tmp_path: Path) -> None:
    """Default read caps should still apply when the core file-size limit is unlimited."""
    scanner = TinyReadLimitScanner(config={"max_file_size": 0})
    file_path = tmp_path / "large.test"
    file_path.write_bytes(b"this is too long")

    result = scanner._check_size_limit(str(file_path))

    assert isinstance(result, ScanResult)
    checks = {check.name: check for check in result.checks}
    assert checks["File Size Limit"].status == CheckStatus.FAILED
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]


def test_base_scanner_explicit_read_limit_overrides_core_file_size() -> None:
    """max_file_read_size remains the scanner-specific override when both caps are set."""
    scanner = TinyReadLimitScanner(config={"max_file_size": 0, "max_file_read_size": 4})

    assert scanner.max_file_read_size == 4


def test_base_scanner_positive_core_max_file_size_does_not_replace_read_cap() -> None:
    """Positive max_file_size remains the top-level scan cap, not a full-read cap alias."""
    scanner = TinyReadLimitScanner(config={"max_file_size": 4})

    assert scanner.max_file_read_size == TinyReadLimitScanner.default_max_file_read_size


def test_base_scanner_create_scan_result_after_preflight_merges_checks(tmp_path: Path) -> None:
    """The preflight template should merge deferred path/size checks into the scanner result."""
    scanner = MockScanner(config={"max_file_read_size": 100})
    file_path = tmp_path / "model.test"
    file_path.write_bytes(b"content")

    result = scanner._create_scan_result_after_preflight(str(file_path))

    assert result.success is True
    assert scanner.current_file_path == str(file_path)
    check_names = {check.name for check in result.checks}
    assert {"Path Exists", "Path Readable", "File Type Validation", "File Size Limit"}.issubset(check_names)
    assert result.metadata["file_size"] == len(b"content")


def test_base_scanner_create_scan_result_after_preflight_can_skip_size_gate(tmp_path: Path) -> None:
    """Scanners with custom size policies should be able to skip the shared size-limit gate."""
    scanner = MockScanner(config={"max_file_read_size": 1})
    file_path = tmp_path / "model.test"
    file_path.write_bytes(b"content")

    result = scanner._create_scan_result_after_preflight(str(file_path), check_size_limit=False)

    assert result.success is True
    check_names = {check.name for check in result.checks}
    assert "Path Exists" in check_names
    assert "Path Readable" in check_names
    assert "File Size Limit" not in check_names


def test_whitelist_downgrade_warning_to_info():
    """Test that whitelisted models have warnings downgraded to INFO."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add a warning issue
    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    # Should be downgraded to INFO
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "WARNING"


def test_whitelist_downgrade_critical_to_info():
    """Policy-grade critical findings remain eligible for trusted HF downgrades."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add a critical issue
    result = scanner._create_result()
    result._add_issue("Test critical", severity=IssueSeverity.CRITICAL)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "CRITICAL"


@pytest.mark.parametrize(
    "check_name",
    [
        "Command/Network Correlation Check",
        "RKNN Command and Network Indicator Correlation",
    ],
)
def test_whitelist_does_not_downgrade_critical_command_network_correlation(check_name: str) -> None:
    """Neutral command/network criticals must still fail whitelisted HF scans."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name=check_name,
        passed=False,
        message="Correlated command and process/network indicators detected",
        severity=IssueSeverity.CRITICAL,
        details={"same_fragment_correlation": True},
    )

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].details.get("whitelist_downgrade") is None
    assert len(result.checks) == 1
    assert result.checks[0].severity == IssueSeverity.CRITICAL
    assert result.checks[0].details.get("whitelist_downgrade") is None


@pytest.mark.parametrize(
    "check_name",
    [
        "Command/Network Correlation Check",
        "RKNN Command and Network Indicator Correlation",
    ],
)
def test_whitelist_downgrades_unconfirmed_command_network_correlation(check_name: str) -> None:
    """Display names alone must not turn unrelated model text into an active finding."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name=check_name,
        passed=False,
        message="Command and network indicators occur in unrelated model text",
        severity=IssueSeverity.CRITICAL,
        details={"same_fragment_correlation": False},
    )

    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.checks[0].severity == IssueSeverity.INFO


@pytest.mark.parametrize(
    "check_name",
    [
        "Blacklist Pattern Check",
        "Command Indicator Check",
        "CoreML Custom Layer Check",
        "CoreML Custom Model Class Check",
        "Embedded PE Detection",
        "External Library Reference Check",
        "Protobuf String Injection Check",
        "Python Operator Detection",
        "Serialized Expression Payload Detection",
        "Suspicious Layer Type Detection",
        "TorchServe Handler Static Analysis",
        "Torch7 Lua Execution Primitive Analysis",
    ],
)
def test_whitelist_does_not_downgrade_active_critical_checks(check_name: str) -> None:
    """Concrete active-payload criticals must still fail whitelisted HF scans."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name=check_name,
        passed=False,
        message="Concrete active execution or runtime-extension evidence detected",
        severity=IssueSeverity.CRITICAL,
    )

    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].details.get("whitelist_downgrade") is None
    assert result.checks[0].severity == IssueSeverity.CRITICAL


@pytest.mark.parametrize(
    "check_name",
    [
        "Blacklist Pattern Check",
        "Command Indicator Check",
        "Protobuf String Injection Check",
        "Serialized Expression Payload Detection",
        "Torch7 Lua Execution Primitive Analysis",
    ],
)
def test_whitelist_still_downgrades_warning_variants_of_active_check_names(check_name: str) -> None:
    """Documentation, operational, or uncorrelated warning variants stay whitelist eligible."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name=check_name,
        passed=False,
        message="Uncorrelated or documentation-context indicator detected",
        severity=IssueSeverity.WARNING,
    )

    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.checks[0].severity == IssueSeverity.INFO


def test_whitelist_still_downgrades_rknn_command_only_near_match() -> None:
    """The RKNN correlation exemption must not cover command-only indicators."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.rknn"),
        file_size=100,
        file_type=".rknn",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name="RKNN Command Indicator Detection",
        passed=False,
        message="Command execution indicators detected in RKNN metadata text",
        severity=IssueSeverity.WARNING,
    )

    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.checks[0].severity == IssueSeverity.INFO


def test_whitelist_still_downgrades_policy_grade_high_severity_url() -> None:
    """Trusted HF provenance may still suppress policy-grade URL findings."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    scanner.add_network_communication_findings(
        [
            {
                "type": "url",
                "message": "Suspicious URL detected: https://example.com/model",
                "severity": "HIGH",
            }
        ],
        result,
    )

    assert result.issues[0].rule_code == "S309"
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("original_severity") == "CRITICAL"


def test_whitelist_annotations_do_not_leak_through_reused_details() -> None:
    """Internal whitelist markers must not mutate caller-owned evidence."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )
    shared_details = {"source": "shared detector evidence"}

    result = scanner._create_result()
    result.add_check(
        name="Policy Finding",
        passed=False,
        message="Policy-grade anomaly detected",
        severity=IssueSeverity.WARNING,
        details=shared_details,
    )
    result.add_check(
        name="Command/Network Correlation Check",
        passed=False,
        message="Correlated command and process/network indicators detected",
        severity=IssueSeverity.CRITICAL,
        details=shared_details | {"same_fragment_correlation": True},
    )

    assert shared_details == {"source": "shared detector evidence"}
    result.metadata["analysis_incomplete"] = True
    result.finish(success=False)

    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[1].severity == IssueSeverity.CRITICAL
    assert result.checks[1].severity == IssueSeverity.CRITICAL
    assert result.issues[1].details.get("whitelist_downgrade_restored") is None


def test_relayed_whitelist_downgrade_can_be_restored_by_parent_metadata() -> None:
    """Composition must retain the provenance needed for fail-closed restoration."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    child = scanner._create_result()
    child.add_check(
        name="Policy Finding",
        passed=False,
        message="Policy-grade anomaly detected",
        severity=IssueSeverity.CRITICAL,
    )
    assert child.issues[0].severity == IssueSeverity.INFO

    parent = scanner._create_result()
    child_issue = child.issues[0]
    parent.add_check(
        name=child_issue.type or "Relayed Security Finding",
        passed=False,
        message=child_issue.message,
        severity=child_issue.severity,
        location=child_issue.location,
        details=child_issue.details,
        why=child_issue.why,
    )

    assert parent.issues[0].details.get("whitelist_downgrade") is True
    assert parent.issues[0].details.get("original_severity") == "CRITICAL"

    parent.metadata["analysis_incomplete"] = True
    parent.finish(success=False)

    assert parent.checks[0].severity == IssueSeverity.CRITICAL
    assert parent.issues[0].severity == IssueSeverity.CRITICAL
    assert parent.issues[0].details.get("whitelist_downgrade_restored") is True


def test_whitelist_no_downgrade_info():
    """Test that INFO severity is not affected by whitelist."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add an info issue
    result = scanner._create_result()
    result._add_issue("Test info", severity=IssueSeverity.INFO)

    # INFO severity creates passed checks, not issues
    assert len(result.issues) == 0
    assert len(result.checks) == 1
    assert result.checks[0].severity == IssueSeverity.INFO
    assert result.checks[0].status == CheckStatus.PASSED
    # INFO doesn't get downgraded (already informational)
    assert result.checks[0].details.get("whitelist_downgrade") is None


def test_whitelist_disabled():
    """Test that whitelist can be disabled via config."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner(config={"use_hf_whitelist": False})
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add a warning issue
    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    # Should NOT be downgraded because whitelist is disabled
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_staleness_recent_no_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Recent whitelist snapshots should not emit a staleness warning."""
    from modelaudit.scanners.base import _warn_if_whitelist_is_stale
    from modelaudit.whitelists import POPULAR_MODELS

    _warn_if_whitelist_is_stale.cache_clear()
    monkeypatch.setattr(
        "modelaudit.whitelists.WHITELIST_GENERATED_AT",
        datetime.now(timezone.utc).date().isoformat(),
    )

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result = scanner._create_result()
        result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert not any("HuggingFace whitelist is" in rec.message for rec in caplog.records)


def test_whitelist_staleness_warning_logged_for_stale_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stale whitelist snapshots should emit a warning when used."""
    from modelaudit.whitelists import POPULAR_MODELS

    stale_date = (datetime.now(timezone.utc).date() - timedelta(days=180)).isoformat()
    from modelaudit.scanners.base import _warn_if_whitelist_is_stale

    _warn_if_whitelist_is_stale.cache_clear()
    monkeypatch.setattr("modelaudit.whitelists.WHITELIST_GENERATED_AT", stale_date)

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result = scanner._create_result()
        result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert any("HuggingFace whitelist is 180 days old" in rec.message for rec in caplog.records)


def test_whitelist_staleness_warning_only_logs_once(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stale whitelist warning should only be logged once per scan session."""
    from modelaudit.whitelists import POPULAR_MODELS

    stale_date = (datetime.now(timezone.utc).date() - timedelta(days=180)).isoformat()
    from modelaudit.scanners.base import _warn_if_whitelist_is_stale

    _warn_if_whitelist_is_stale.cache_clear()
    monkeypatch.setattr("modelaudit.whitelists.WHITELIST_GENERATED_AT", stale_date)

    scanner_one = MockScanner()
    scanner_one.context = UnifiedMLContext(
        file_path=Path("/tmp/test-one.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    scanner_two = MockScanner()
    scanner_two.context = UnifiedMLContext(
        file_path=Path("/tmp/test-two.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result_one = scanner_one._create_result()
        result_one._add_issue("Test warning", severity=IssueSeverity.WARNING)

        result_two = scanner_two._create_result()
        result_two._add_issue("Another warning", severity=IssueSeverity.WARNING)

    warning_messages = [rec.message for rec in caplog.records if "HuggingFace whitelist is" in rec.message]
    assert len(warning_messages) == 1


def test_whitelist_staleness_unknown_model_no_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unknown models should not emit a stale whitelist warning."""
    stale_date = (datetime.now(timezone.utc).date() - timedelta(days=180)).isoformat()
    from modelaudit.scanners.base import _warn_if_whitelist_is_stale

    _warn_if_whitelist_is_stale.cache_clear()
    monkeypatch.setattr("modelaudit.whitelists.WHITELIST_GENERATED_AT", stale_date)

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id="unknown-author/unknown-model-12345",
        model_source="huggingface",
    )

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result = scanner._create_result()
        result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert not any("HuggingFace whitelist is" in rec.message for rec in caplog.records)


def test_whitelist_unknown_model():
    """Test that unknown models are not whitelisted."""
    scanner = MockScanner()
    # Create a context with an unknown model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id="unknown-author/unknown-model-12345",
        model_source="huggingface",
    )

    # Create a result and add a warning issue
    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    # Should NOT be downgraded
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_no_model_id():
    """Test that files without model ID are not whitelisted."""
    scanner = MockScanner()
    # Create a context without a model ID
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=None,
        model_source=None,
    )

    # Create a result and add a warning issue
    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    # Should NOT be downgraded
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_no_downgrade_local_spoofed_config(tmp_path: Path) -> None:
    """Local config metadata should not make files eligible for whitelist downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
    model_dir = tmp_path / "spoofed-model"
    model_dir.mkdir()
    model_path = model_dir / "model.test"
    model_path.write_bytes(b"test")
    (model_dir / "config.json").write_text(f'{{"_name_or_path": "{whitelisted_model}"}}')

    scanner = MockScanner()
    scanner._initialize_context(str(model_path))

    assert scanner.context is not None
    assert scanner.context.model_id == whitelisted_model
    assert scanner.context.model_source == "local"

    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_no_downgrade_hf_cache_path_without_explicit_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cache-shaped local paths alone should not qualify for whitelist downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
    monkeypatch.setenv("HF_HOME", str(tmp_path / ".cache" / "huggingface"))
    model_path = _create_hf_cache_model_path(tmp_path, whitelisted_model)

    scanner = MockScanner()
    scanner._initialize_context(str(model_path))

    assert scanner.context is not None
    assert scanner.context.model_id == whitelisted_model
    assert scanner.context.model_source == "huggingface_cache"

    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_downgrade_explicit_hf_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit upstream HuggingFace provenance should still permit downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
    monkeypatch.setenv("HF_HOME", str(tmp_path / ".cache" / "huggingface"))
    model_path = _create_hf_cache_model_path(tmp_path, whitelisted_model)

    scanner = MockScanner(
        config={
            "_trusted_source_provenance": make_trusted_source_provenance(
                whitelisted_model,
                "huggingface",
            ),
        }
    )
    scanner._initialize_context(str(model_path))

    assert scanner.context is not None
    assert scanner.context.model_id == whitelisted_model
    assert scanner.context.model_source == "huggingface"

    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "WARNING"


def test_whitelist_ignores_raw_config_provenance_override(tmp_path: Path) -> None:
    """Raw string config overrides must not be enough to trigger downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
    model_path = tmp_path / "plain-model.test"
    model_path.write_bytes(b"test")

    scanner = MockScanner(
        config={
            "_source_model_id": whitelisted_model,
            "_source_model_source": "huggingface",
        }
    )
    scanner._initialize_context(str(model_path))

    assert scanner.context is not None
    assert scanner.context.model_id is None
    assert scanner.context.model_source is None

    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_no_downgrade_spoofed_hf_cache_layout(tmp_path: Path) -> None:
    """HF lookalike paths outside the real cache root must not qualify for downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
    model_path = _create_hf_cache_model_path(
        tmp_path,
        whitelisted_model,
        cache_root=tmp_path / "project" / "huggingface" / "hub",
    )

    scanner = MockScanner()
    scanner._initialize_context(str(model_path))

    assert scanner.context is not None
    assert scanner.context.model_id is None
    assert scanner.context.model_source is None

    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_no_downgrade_non_whitelisted_hf_cache_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real HF cache paths should not downgrade findings for non-whitelisted models."""
    monkeypatch.setenv("HF_HOME", str(tmp_path / ".cache" / "huggingface"))
    model_path = _create_hf_cache_model_path(tmp_path, "unknown-author/unknown-model-12345")

    scanner = MockScanner()
    scanner._initialize_context(str(model_path))

    assert scanner.context is not None
    assert scanner.context.model_id == "unknown-author/unknown-model-12345"
    assert scanner.context.model_source == "huggingface_cache"

    result = scanner._create_result()
    result._add_issue("Test warning", severity=IssueSeverity.WARNING)

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.WARNING
    assert result.issues[0].details.get("whitelist_downgrade") is None


def test_whitelist_downgrade_critical_check() -> None:
    """Policy-grade critical checks remain eligible for trusted HF downgrades."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add a failed check (which creates both a Check and an Issue)
    result = scanner._create_result()
    result.add_check(
        name="Test Security Check",
        passed=False,
        message="High confidence model anomaly detected",
        severity=IssueSeverity.CRITICAL,
    )

    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "CRITICAL"

    assert len(result.checks) == 1
    assert result.checks[0].name == "Test Security Check"
    assert result.checks[0].status == CheckStatus.FAILED
    assert result.checks[0].severity == IssueSeverity.INFO
    assert result.checks[0].details.get("whitelist_downgrade") is True
    assert result.checks[0].details.get("original_severity") == "CRITICAL"


@pytest.mark.parametrize(
    ("name", "message", "rule_code", "details", "severity"),
    [
        ("Active Reducer", "Dangerous reducer invokes posix.system", "S201", {}, IssueSeverity.CRITICAL),
        (
            "RCE CVE",
            "Known vulnerable deserialization construct",
            None,
            {"cve_id": "CVE-2026-1234"},
            IssueSeverity.CRITICAL,
        ),
        (
            "Legacy CVE",
            "Detected CVE-2024-34997 pattern",
            None,
            {"cve": "CVE-2024-34997"},
            IssueSeverity.CRITICAL,
        ),
        ("Traversal", "Path traversal attempt detected", None, {}, IssueSeverity.CRITICAL),
        ("System Path", "Symlink target points to critical system path", "S408", {}, IssueSeverity.CRITICAL),
        ("Incomplete", "Archive scan inconclusive", None, {"analysis_incomplete": True}, IssueSeverity.WARNING),
        # S1xx active code-execution primitives. Messages are deliberately neutral
        # ("Suspicious code pattern detected: ...") so the rule code itself carries
        # the exemption rather than the keyword fallback. Mirrors the emission shape
        # used by `flax_msgpack_scanner._check_suspicious_strings`.
        ("os import", r"Suspicious code pattern detected: import\s+os", "S101", {}, IssueSeverity.CRITICAL),
        ("sys import", r"Suspicious code pattern detected: import\s+sys", "S102", {}, IssueSeverity.CRITICAL),
        (
            "subprocess import",
            r"Suspicious code pattern detected: subprocess\.",
            "S103",
            {},
            IssueSeverity.CRITICAL,
        ),
        ("eval pattern", r"Suspicious code pattern detected: \beval\s*\(", "S104", {}, IssueSeverity.CRITICAL),
        ("compile pattern", r"Suspicious code pattern detected: \bcompile\s*\(", "S105", {}, IssueSeverity.CRITICAL),
        ("__import__ pattern", "Suspicious code pattern detected: __import__", "S106", {}, IssueSeverity.CRITICAL),
        ("importlib", "Suspicious code pattern detected: importlib.import_module", "S107", {}, IssueSeverity.WARNING),
        ("runpy", "Suspicious code pattern detected: runpy.run_module", "S108", {}, IssueSeverity.CRITICAL),
        ("webbrowser", "Suspicious code pattern detected: webbrowser.open", "S109", {}, IssueSeverity.CRITICAL),
        ("ctypes", "Suspicious code pattern detected: ctypes.CDLL", "S110", {}, IssueSeverity.WARNING),
        ("pty", "Suspicious code pattern detected: pty.spawn", "S111", {}, IssueSeverity.CRITICAL),
        ("code", "Suspicious code pattern detected: code.InteractiveConsole", "S112", {}, IssueSeverity.CRITICAL),
        ("types", "Suspicious code pattern detected: types.FunctionType", "S113", {}, IssueSeverity.WARNING),
        ("ast", "Suspicious code pattern detected: ast.parse", "S114", {}, IssueSeverity.WARNING),
        ("builtins access", "Suspicious code pattern detected: __builtins__", "S115", {}, IssueSeverity.WARNING),
        # S3xx active network primitives at HIGH severity. Lower-severity HTTP/SMTP/DNS
        # codes are intentionally omitted so policy-grade findings remain downgradeable.
        ("socket usage", "Network primitive detected: socket call", "S301", {}, IssueSeverity.WARNING),
        ("ftplib usage", "Network primitive detected: ftplib session", "S304", {}, IssueSeverity.WARNING),
        ("telnetlib usage", "Network primitive detected: telnetlib session", "S305", {}, IssueSeverity.WARNING),
        ("exfiltration", "Potential outbound data transfer detected", "S310", {}, IssueSeverity.WARNING),
        # S5xx embedded executable / interpreter content (regression coverage so future
        # refactors of the exempt set do not silently drop them).
        ("Executable", "Executable file detected in archive", "S501", {}, IssueSeverity.WARNING),
        (
            "Executable Fragments",
            "Executable script fragments detected in CatBoost text-bearing sections",
            None,
            {},
            IssueSeverity.WARNING,
        ),
        ("PowerShell", "PowerShell content found in pickle tail", "S506", {}, IssueSeverity.WARNING),
        ("Embedded Python", "Python script embedded in tensor payload", "S507", {}, IssueSeverity.WARNING),
        ("WebAssembly", "WASM module found in model payload", "S509", {}, IssueSeverity.WARNING),
    ],
)
def test_whitelist_does_not_downgrade_active_or_incomplete_findings(
    name: str,
    message: str,
    rule_code: str | None,
    details: dict[str, object],
    severity: IssueSeverity,
) -> None:
    """Trusted provenance must not hide active payloads or incomplete coverage."""
    from modelaudit.whitelists import POPULAR_MODELS

    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name=name,
        passed=False,
        message=message,
        severity=severity,
        details=dict(details),
        rule_code=rule_code,
    )

    assert len(result.issues) == 1
    assert result.issues[0].severity == severity
    assert result.issues[0].details.get("whitelist_downgrade") is None
    assert len(result.checks) == 1
    assert result.checks[0].severity == severity
    assert result.checks[0].details.get("whitelist_downgrade") is None


@pytest.mark.parametrize(
    ("name", "message"),
    [
        # "executable" inside "ExecuTorch" must not exempt an unrelated informational note.
        ("ExecuTorch substring", "ExecuTorch tensor metadata observed"),
        # "rce" inside "enforce"/"source" must not exempt unrelated findings either.
        ("enforce substring", "Tensor enforce_layout flag observed"),
        ("source substring", "Source-tracked metadata observed"),
    ],
)
def test_whitelist_keyword_fallback_uses_word_boundaries(name: str, message: str) -> None:
    """Substring-only matches in unrelated words must not block whitelist downgrades."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name=name,
        passed=False,
        message=message,
        severity=IssueSeverity.WARNING,
    )

    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "WARNING"


def test_whitelist_does_not_downgrade_result_metadata_operational_errors() -> None:
    """Operational error metadata must preserve fail-closed severities."""
    from modelaudit.whitelists import POPULAR_MODELS

    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.joblib"),
        file_size=100,
        file_type=".joblib",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = "joblib_decompression_failed"
    result.add_check(
        name="Joblib Decompression",
        passed=False,
        message="Error decompressing joblib file",
        severity=IssueSeverity.CRITICAL,
    )

    assert result.issues[0].severity.value == "critical"
    assert result.issues[0].details.get("whitelist_downgrade") is None
    assert result.checks[0].severity == IssueSeverity.CRITICAL
    assert result.checks[0].details.get("whitelist_downgrade") is None


def test_whitelist_restores_downgrade_when_operational_metadata_set_after_check() -> None:
    """Late operational metadata should restore already-downgraded checks."""
    from modelaudit.whitelists import POPULAR_MODELS

    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.joblib"),
        file_size=100,
        file_type=".joblib",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name="Joblib Decompression",
        passed=False,
        message="Error decompressing joblib file",
        severity=IssueSeverity.CRITICAL,
    )
    assert result.issues[0].severity.value == "info"
    assert result.issues[0].details.get("whitelist_downgrade") is True

    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = "joblib_decompression_failed"
    result.finish(success=False)

    assert result.issues[0].severity.value == "critical"
    assert result.issues[0].details.get("whitelist_downgrade") is None
    assert result.issues[0].details.get("whitelist_downgrade_restored") is True
    assert result.checks[0].severity == IssueSeverity.CRITICAL
    assert result.checks[0].details.get("whitelist_downgrade") is None
    assert result.checks[0].details.get("whitelist_downgrade_restored") is True


def test_finish_recomputes_success_after_restoring_metadata_exempt_severity(tmp_path: Path) -> None:
    """Restored CRITICAL findings must make finished results unsuccessful."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=tmp_path / "test.joblib",
        file_size=100,
        file_type=".joblib",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name="Joblib Decompression",
        passed=False,
        message="Error decompressing joblib file",
        severity=IssueSeverity.CRITICAL,
    )
    assert result.issues[0].severity == IssueSeverity.INFO

    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = "joblib_decompression_failed"
    result.finish(success=True)

    assert result.issues[0].severity.value == "critical"
    assert result.checks[0].severity == IssueSeverity.CRITICAL
    assert result.success is False


def test_finished_result_refreshes_whitelist_restore_after_late_inconclusive_metadata(tmp_path: Path) -> None:
    """Post-finish inconclusive metadata should restore downgraded severities."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=tmp_path / "test.pkl",
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name="Late Coverage Check",
        passed=False,
        message="High confidence model anomaly detected",
        severity=IssueSeverity.CRITICAL,
    )
    result.finish(success=True)
    assert result.issues[0].severity.value == "info"
    assert result.success is True

    mark_inconclusive_scan_result(result, "streaming_analysis_incomplete")

    assert result.issues[0].severity.value == "critical"
    assert result.issues[0].details.get("whitelist_downgrade") is None
    assert result.issues[0].details.get("whitelist_downgrade_restored") is True
    assert result.checks[0].severity == IssueSeverity.CRITICAL
    assert result.success is False


def test_finish_remembers_pre_finish_metadata_restored_critical(tmp_path: Path) -> None:
    """Pre-finish metadata refreshes must still affect final success."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=tmp_path / "test.pkl",
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    result = scanner._create_result()
    result.add_check(
        name="Pre-Finish Coverage Check",
        passed=False,
        message="High confidence model anomaly detected",
        severity=IssueSeverity.CRITICAL,
    )
    assert result.issues[0].severity.value == "info"

    mark_inconclusive_scan_result(result, "streaming_analysis_incomplete")
    assert result.end_time is None
    assert result.issues[0].severity.value == "critical"

    result.finish(success=True)

    assert result.checks[0].severity == IssueSeverity.CRITICAL
    assert result.success is False


def test_whitelist_downgrade_check_warning():
    """Test that whitelisted models have warning checks downgraded to INFO."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add a failed check
    result = scanner._create_result()
    result.add_check(
        name="Test Suspicious Pattern",
        passed=False,
        message="Unusual pattern found",
        severity=IssueSeverity.WARNING,
    )

    # Verify the Issue was downgraded
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "WARNING"

    # Verify the Check exists and severity is also downgraded
    assert len(result.checks) == 1
    assert result.checks[0].name == "Test Suspicious Pattern"
    assert result.checks[0].status == CheckStatus.FAILED
    assert result.checks[0].severity == IssueSeverity.INFO
    assert result.checks[0].details.get("whitelist_downgrade") is True
    assert result.checks[0].details.get("original_severity") == "WARNING"


def test_whitelist_no_downgrade_passed_check():
    """Test that passed checks are not affected by whitelist."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    # Create a context with a whitelisted model
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Create a result and add a passed check
    result = scanner._create_result()
    result.add_check(
        name="Test Validation",
        passed=True,
        message="Validation successful",
    )

    # Passed checks don't create issues
    assert len(result.issues) == 0

    # Check should be marked as passed
    assert len(result.checks) == 1
    assert result.checks[0].status == CheckStatus.PASSED


def test_whitelist_apply_downgrade_helper_none_details():
    """Test _apply_whitelist_downgrade helper with None details."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    new_severity, new_details = scanner._apply_whitelist_downgrade(IssueSeverity.WARNING, None)

    assert new_severity == IssueSeverity.INFO
    assert new_details is not None
    assert new_details.get("whitelist_downgrade") is True
    assert new_details.get("original_severity") == "WARNING"


def test_whitelist_apply_downgrade_helper_keeps_exempt_critical_none_details() -> None:
    """Explicitly active critical checks must not be downgrade eligible."""
    from modelaudit.whitelists import POPULAR_MODELS

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )

    new_severity, new_details = scanner._apply_whitelist_downgrade(
        IssueSeverity.CRITICAL,
        {"same_fragment_correlation": True},
        check_name="Command/Network Correlation Check",
    )

    assert new_severity == IssueSeverity.CRITICAL
    assert new_details == {"same_fragment_correlation": True}


def test_whitelist_helper_preserves_detector_original_severity_evidence() -> None:
    """Generic detector evidence must not be treated as internal whitelist state."""
    scanner = MockScanner()
    original_details = {"original_severity": "upstream-high", "source": "nested scanner"}

    new_severity, new_details = scanner._apply_whitelist_downgrade(
        IssueSeverity.WARNING,
        original_details,
    )

    assert new_severity == IssueSeverity.WARNING
    assert new_details == original_details


def test_whitelist_apply_downgrade_helper_existing_details():
    """Test _apply_whitelist_downgrade helper with existing details."""
    from modelaudit.whitelists import POPULAR_MODELS

    # Get a model from the whitelist
    whitelisted_model = next(iter(POPULAR_MODELS))

    scanner = MockScanner()
    scanner.context = UnifiedMLContext(
        file_path=Path("/tmp/test.pkl"),
        file_size=100,
        file_type=".pkl",
        model_id=whitelisted_model,
        model_source="huggingface",
    )

    # Test with existing details
    existing_details = {"custom_field": "value"}
    new_severity, new_details = scanner._apply_whitelist_downgrade(IssueSeverity.WARNING, existing_details)

    assert new_severity == IssueSeverity.INFO
    assert new_details.get("whitelist_downgrade") is True
    assert new_details.get("original_severity") == "WARNING"
    assert new_details.get("custom_field") == "value"  # Original details preserved
    assert existing_details == {"custom_field": "value"}
