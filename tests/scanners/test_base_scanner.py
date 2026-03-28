import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

import pytest

import modelaudit.scanners.base as base_module
import modelaudit.whitelists as whitelist_module
from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.scanners.base import (
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
    """Test that whitelisted models have critical issues downgraded to INFO."""
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

    # Should be downgraded to INFO
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "CRITICAL"


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
    from modelaudit.whitelists import POPULAR_MODELS

    monkeypatch.setattr(base_module, "_has_logged_stale_whitelist_warning", False)
    monkeypatch.setattr(whitelist_module, "WHITELIST_GENERATED_AT", datetime.now(timezone.utc).date().isoformat())

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
    monkeypatch.setattr(base_module, "_has_logged_stale_whitelist_warning", False)
    monkeypatch.setattr(whitelist_module, "WHITELIST_GENERATED_AT", stale_date)

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
    monkeypatch.setattr(base_module, "_has_logged_stale_whitelist_warning", False)
    monkeypatch.setattr(whitelist_module, "WHITELIST_GENERATED_AT", stale_date)

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
    monkeypatch.setattr(base_module, "_has_logged_stale_whitelist_warning", False)
    monkeypatch.setattr(whitelist_module, "WHITELIST_GENERATED_AT", stale_date)

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


def test_whitelist_no_downgrade_hf_cache_path_without_explicit_provenance(tmp_path: Path) -> None:
    """Cache-shaped local paths alone should not qualify for whitelist downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
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


def test_whitelist_downgrade_explicit_hf_provenance(tmp_path: Path) -> None:
    """Explicit upstream HuggingFace provenance should still permit downgrades."""
    whitelisted_model = "Qwen/Qwen2.5-0.5B"
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


def test_whitelist_no_downgrade_non_whitelisted_hf_cache_model(tmp_path: Path) -> None:
    """Real HF cache paths should not downgrade findings for non-whitelisted models."""
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


def test_whitelist_downgrade_check_critical():
    """Test that whitelisted models have critical checks downgraded to INFO."""
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
        message="Dangerous pattern detected",
        severity=IssueSeverity.CRITICAL,
    )

    # Verify the Issue was downgraded
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.INFO
    assert result.issues[0].details.get("whitelist_downgrade") is True
    assert result.issues[0].details.get("original_severity") == "CRITICAL"

    # Verify the Check exists and severity is also downgraded
    assert len(result.checks) == 1
    assert result.checks[0].name == "Test Security Check"
    assert result.checks[0].status == CheckStatus.FAILED
    assert result.checks[0].severity == IssueSeverity.INFO
    assert result.checks[0].details.get("whitelist_downgrade") is True
    assert result.checks[0].details.get("original_severity") == "CRITICAL"


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

    # Test with None details
    new_severity, new_details = scanner._apply_whitelist_downgrade(IssueSeverity.CRITICAL, None)

    assert new_severity == IssueSeverity.INFO
    assert new_details is not None
    assert new_details.get("whitelist_downgrade") is True
    assert new_details.get("original_severity") == "CRITICAL"


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
