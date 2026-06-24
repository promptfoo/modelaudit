"""
Test suite for SevenZipScanner

Tests the 7-Zip archive scanning functionality including:
- Basic format detection and scanning
- Security issue detection in contained files
- Error handling for missing dependencies
- Path traversal protection
- Large archive handling
"""

import io
import os
import pickle
import struct
import tarfile
import tempfile
import zipfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.sevenzip_scanner import (
    HAS_PY7ZR,
    SevenZipScanner,
    _NestedMemberProbeResult,
    _RecursiveScanBudget,
)
from modelaudit.scanners.xgboost_scanner import XGBoostScanner
from modelaudit.utils.file.detection import PICKLE_ROUTING_INCONCLUSIVE_FORMAT

# Skip all tests if py7zr is not available for asset generation
pytest_plugins: list[str] = []


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


def _mock_scan_result(
    *,
    message: str | None = None,
    location: str = "extracted_file",
    scanner_name: str = "mock",
) -> ScanResult:
    result = ScanResult(scanner_name=scanner_name)
    if message is not None:
        result.add_check(
            name="Mock Nested Scan",
            passed=False,
            message=message,
            severity=IssueSeverity.CRITICAL,
            location=location,
            details={},
        )
    result.finish(success=True)
    return result


def _ubjson_key(key: bytes) -> bytes:
    return b"U" + bytes([len(key)]) + key


def _ubjson_string(value: bytes) -> bytes:
    return b"SL" + len(value).to_bytes(8, byteorder="big", signed=True) + value


def _xgboost_ubjson_probe(
    *, root_padding: int = 0, learner_padding: int = 0, learner_noop: bool = False, malicious: bool = False
) -> bytes:
    root_body = b""
    if root_padding:
        root_body += _ubjson_key(b"metadata") + _ubjson_string(b"x" * root_padding)
    learner_body = b""
    if learner_padding:
        learner_body += _ubjson_key(b"metadata") + _ubjson_string(b"x" * learner_padding)
    learner_body += _ubjson_key(b"learner_model_param") + b"{}"
    if malicious:
        learner_body += _ubjson_key(b"malicious_code") + _ubjson_string(b"system(cpu)")
    learner_value = (b"N" if learner_noop else b"") + b"{" + learner_body + b"}"
    return b"{" + root_body + _ubjson_key(b"learner") + learner_value + _ubjson_key(b"version") + b"[]" + b"}"


def _xgboost_ubjson_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    learner = b"{" + _ubjson_key(b"learner_model_param") + b"{}" + _ubjson_key(b"payload") + b"[$Z#L" + max_count + b"}"
    return b"{" + _ubjson_key(b"learner") + learner + _ubjson_key(b"version") + b"[]" + b"}"


def _xgboost_ubjson_uncounted_null_array_probe(item_count: int) -> bytes:
    learner = (
        b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + _ubjson_key(b"payload")
        + b"["
        + (b"Z" * item_count)
        + b"]}"
    )
    return b"{" + _ubjson_key(b"learner") + learner + b"}"


def _xgboost_ubjson_noop_before_counted_root_header_probe() -> bytes:
    return (
        b"{N#U\x02"
        + _ubjson_key(b"learner")
        + b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + b"}"
        + _ubjson_key(b"version")
        + b"[]"
    )


def _xgboost_ubjson_deep_before_counted_null_array_probe() -> bytes:
    max_count = ((1 << 63) - 1).to_bytes(8, byteorder="big", signed=True)
    nested = b"[" * 66 + b"Z" + b"]" * 66
    learner = (
        b"{"
        + _ubjson_key(b"learner_model_param")
        + b"{}"
        + _ubjson_key(b"nested")
        + nested
        + _ubjson_key(b"payload")
        + b"[$Z#L"
        + max_count
        + b"}"
    )
    return b"{" + _ubjson_key(b"learner") + learner + b"}"


class TestSevenZipScanner:
    """Test suite for SevenZipScanner functionality"""

    def test_header_probe_accepts_py7zr_close_hook(self, scanner: SevenZipScanner) -> None:
        """py7zr 1.1.3 closes factory products before callers inspect them."""

        class ClosingArchive:
            def extract(self, *, targets: list[str], factory: Any) -> None:
                probe = factory.create(targets[0])
                probe.write(b"pickle-prefix")
                probe.close()

            def reset(self) -> None:
                return None

        prefix = scanner._read_member_probe_prefix(ClosingArchive(), "model.dat", 16)

        assert prefix == b"pickle-prefix"

    @pytest.fixture
    def scanner(self):
        """Create a SevenZipScanner instance for testing"""
        return SevenZipScanner()

    @pytest.fixture
    def temp_7z_file(self):
        """Create a temporary file with .7z extension for testing"""
        with tempfile.NamedTemporaryFile(suffix=".7z", delete=False) as f:
            temp_path = f.name
        yield temp_path
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_scanner_metadata(self, scanner):
        """Test basic scanner metadata and properties"""
        assert scanner.name == "sevenzip"
        assert scanner.description == "Scans 7-Zip archives for malicious model files"
        assert scanner.supported_extensions == [".7z"]

    def test_can_handle_without_py7zr(self, temp_7z_file):
        """Test that can_handle returns False when py7zr is not available"""
        if HAS_PY7ZR:
            pytest.skip("py7zr is available, skipping unavailable test")

        assert not SevenZipScanner.can_handle(temp_7z_file)

    @patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", False)
    def test_can_handle_mocked_unavailable(self, temp_7z_file):
        """Test can_handle behavior when py7zr is mocked as unavailable"""
        assert not SevenZipScanner.can_handle(temp_7z_file)

    def test_can_handle_non_existent_file(self):
        """Test can_handle with non-existent file"""
        assert not SevenZipScanner.can_handle("/non/existent/file.7z")

    def test_can_handle_wrong_extension(self, temp_7z_file):
        """Test can_handle with wrong file extension"""
        # Rename to different extension
        wrong_ext = temp_7z_file.replace(".7z", ".zip")
        os.rename(temp_7z_file, wrong_ext)

        try:
            assert not SevenZipScanner.can_handle(wrong_ext)
        finally:
            if os.path.exists(wrong_ext):
                os.unlink(wrong_ext)

    def test_scan_without_py7zr(self, scanner, temp_7z_file):
        """Test scan behavior when py7zr is not available"""
        if HAS_PY7ZR:
            pytest.skip("py7zr is available, skipping unavailable test")

        result = scanner.scan(temp_7z_file)

        assert not result.success
        assert len(result.issues) == 1

        issue = result.issues[0]
        assert issue.severity == IssueSeverity.INFO
        assert "py7zr library not installed" in issue.message
        assert "pip install py7zr" in issue.message
        assert issue.details["analysis_incomplete"] is True
        assert issue.details["scan_outcome_reason"] == "sevenzip_analysis_incomplete"
        assert result.has_warnings is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["analysis_incomplete"] is True
        assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]

    @patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", False)
    def test_scan_mocked_unavailable(self, scanner: SevenZipScanner, temp_7z_file: str, tmp_path: Path) -> None:
        """Test scan behavior when py7zr is mocked as unavailable"""
        result = scanner.scan(temp_7z_file)

        assert not result.success
        assert len(result.issues) == 1

        issue = result.issues[0]
        assert issue.severity == IssueSeverity.INFO
        assert "py7zr library not installed" in issue.message
        assert issue.details["analysis_incomplete"] is True
        assert issue.details["scan_outcome_reason"] == "sevenzip_analysis_incomplete"
        assert result.has_warnings is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["analysis_incomplete"] is True
        assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]

        Path(temp_7z_file).write_bytes(SevenZipScanner._SEVENZIP_MAGIC + b"\0" * 26)
        _assert_inconclusive_aggregate_not_cached(
            Path(temp_7z_file),
            "sevenzip_analysis_incomplete",
            tmp_path / "missing-dependency-cache",
        )

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_can_handle_valid_7z_magic_bytes(self, temp_7z_file):
        """Test can_handle with valid 7z magic bytes"""
        # Write 7z magic bytes to file
        with open(temp_7z_file, "wb") as f:
            f.write(b"7z\xbc\xaf\x27\x1c")

        # Mock py7zr to avoid needing valid 7z structure
        with patch("py7zr.SevenZipFile"):
            assert SevenZipScanner.can_handle(temp_7z_file)

    def test_can_handle_invalid_magic_bytes(self, temp_7z_file):
        """Test can_handle with invalid magic bytes"""
        # Write invalid magic bytes
        with open(temp_7z_file, "wb") as f:
            f.write(b"not7z")

        assert not SevenZipScanner.can_handle(temp_7z_file)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_empty_archive(self, scanner, temp_7z_file):
        """Test scanning an empty 7z archive"""
        import py7zr  # type: ignore[import-untyped]

        # Create empty 7z archive
        with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
            pass  # Empty archive

        result = scanner.scan(temp_7z_file)

        assert result.success
        assert result.metadata["total_files"] == 0
        assert result.metadata["scannable_files"] == 0

        # Should have a check indicating no scannable files
        content_checks = [c for c in result.checks if "Content Check" in c.name]
        assert len(content_checks) > 0

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_safe_archive(self, scanner, temp_7z_file):
        """Test scanning a 7z archive with safe content"""
        import py7zr  # type: ignore[import-untyped]

        # Create safe pickle content
        safe_data = {"safe": True, "data": [1, 2, 3]}

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_pickle:
            pickle.dump(safe_data, temp_pickle)
            temp_pickle_path = temp_pickle.name

        try:
            # Create 7z archive with safe content
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(temp_pickle_path, "safe_model.pkl")

            with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
                result = scanner.scan(temp_7z_file)

                assert result.success
                assert result.metadata["total_files"] == 1
                assert result.metadata["scannable_files"] == 1
                mock_scan_file.assert_called_once()

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_malicious_archive(self, scanner: SevenZipScanner, temp_7z_file: str) -> None:
        """Test scanning a 7z archive with malicious content"""
        import py7zr  # type: ignore[import-untyped]

        # Create malicious pickle that would execute code if unpickled
        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('malicious code executed')",))

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_pickle:
            pickle.dump(MaliciousClass(), temp_pickle)
            temp_pickle_path = temp_pickle.name

        try:
            # Create 7z archive with malicious content
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(temp_pickle_path, "malicious_model.pkl")

            with patch(
                "modelaudit.core.scan_file",
                return_value=_mock_scan_result(message="Malicious eval detected"),
            ) as mock_scan_file:
                result = scanner.scan(temp_7z_file)

                assert result.success is False
                assert len(result.issues) > 0  # But issues are found
                assert any("eval" in getattr(issue, "message", "").lower() for issue in result.issues)
                mock_scan_file.assert_called_once()

                # Check that location was adjusted for archive context
                for issue in result.issues:
                    assert issue.location is not None
                    assert temp_7z_file in issue.location or "malicious_model.pkl" in issue.location

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_nested_7z_archive(self, scanner: SevenZipScanner, temp_7z_file: str) -> None:
        """Nested 7z archives should be scanned recursively."""
        import py7zr  # type: ignore[import-untyped]

        inner_7z_path = Path(temp_7z_file).with_name("nested_inner.7z")
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_pickle:
            pickle.dump({"safe": True}, temp_pickle)
            temp_pickle_path = temp_pickle.name

        try:
            with py7zr.SevenZipFile(inner_7z_path, "w") as archive:
                archive.write(temp_pickle_path, "nested_model.pkl")

            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(str(inner_7z_path), "nested.7z")

            with patch(
                "modelaudit.core.scan_file",
                return_value=_mock_scan_result(message="Nested pickle scanned", location="pickle_scan"),
            ) as mock_scan_file:
                result = scanner.scan(temp_7z_file)

            assert result.success is False
            mock_scan_file.assert_called_once()
            nested_issues = [issue for issue in result.issues if issue.message == "Nested pickle scanned"]
            assert len(nested_issues) == 1
            nested_location = nested_issues[0].location
            assert nested_location is not None
            assert f"{temp_7z_file}:nested.7z:nested_model.pkl" in nested_location

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)
            if inner_7z_path.exists():
                inner_7z_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_extensionless_nested_7z_archive(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Extensionless nested 7z archives should recurse based on file content."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self):
                import os as os_module

                return (os_module.system, ("echo extensionless_7z_nested",))

        inner_7z_path = Path(temp_7z_file).with_name("extensionless_inner.7z")
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_pickle:
            pickle.dump(MaliciousClass(), temp_pickle)
            temp_pickle_path = temp_pickle.name

        try:
            with py7zr.SevenZipFile(inner_7z_path, "w") as archive:
                archive.write(temp_pickle_path, "payload.pkl")

            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(str(inner_7z_path), "nested_archive")

            result = scanner.scan(temp_7z_file)

            system_symbols = {
                "os.system",
                f"{os.system.__module__}.system",
            }
            assert result.success is False
            nested_issues = [
                issue
                for issue in result.issues
                if issue.location
                and f"{temp_7z_file}:nested_archive:payload.pkl" in issue.location
                and any(symbol in issue.message.lower() for symbol in system_symbols)
            ]
            assert len(nested_issues) > 0
            assert any(issue.severity == IssueSeverity.CRITICAL for issue in nested_issues)

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)
            if inner_7z_path.exists():
                inner_7z_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_misnamed_nested_7z_archive(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
        tmp_path: Path,
    ) -> None:
        """Nested 7z archives should recurse even when the member has a misleading extension."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self):
                import os as os_module

                return (os_module.system, ("echo disguised_7z_nested",))

        inner_7z_path = tmp_path / "misnamed_inner.7z"
        temp_pickle_path = tmp_path / "payload.pkl"
        with temp_pickle_path.open("wb") as temp_pickle:
            pickle.dump(MaliciousClass(), temp_pickle)

        try:
            with py7zr.SevenZipFile(inner_7z_path, "w") as archive:
                archive.write(str(temp_pickle_path), "payload.pkl")

            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(str(inner_7z_path), "nested.jpg")

            result = scanner.scan(temp_7z_file)

            system_symbols = {
                "os.system",
                f"{os.system.__module__}.system",
            }
            nested_issues = [
                issue
                for issue in result.issues
                if issue.location
                and f"{temp_7z_file}:nested.jpg:payload.pkl" in issue.location
                and any(symbol in issue.message.lower() for symbol in system_symbols)
            ]
            assert result.success is False
            assert len(nested_issues) > 0
            assert any(issue.severity == IssueSeverity.CRITICAL for issue in nested_issues)

        finally:
            if temp_pickle_path.exists():
                temp_pickle_path.unlink()
            if inner_7z_path.exists():
                inner_7z_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_misnamed_nested_7z_archive_prioritizes_disguised_member_over_fillers(
        self,
        temp_7z_file: str,
        tmp_path: Path,
    ) -> None:
        """High-priority disguised members should still be probed ahead of low-value fillers."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self):
                import os as os_module

                return (os_module.system, ("echo disguised_7z_nested",))

        scanner = SevenZipScanner(config={"max_7z_extensionless_probes": 1})
        inner_7z_path = tmp_path / "misnamed_inner.7z"
        temp_pickle_path = tmp_path / "payload.pkl"
        with temp_pickle_path.open("wb") as temp_pickle:
            pickle.dump(MaliciousClass(), temp_pickle)

        try:
            with py7zr.SevenZipFile(inner_7z_path, "w") as archive:
                archive.write(str(temp_pickle_path), "payload.pkl")

            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                for index in range(10):
                    archive.writestr(b"filler", f"docs/{index}.txt.bak")
                archive.write(str(inner_7z_path), "nested.jpg")

            result = scanner.scan(temp_7z_file)

            system_symbols = {
                "os.system",
                f"{os.system.__module__}.system",
            }
            nested_issues = [
                issue
                for issue in result.issues
                if issue.location
                and f"{temp_7z_file}:nested.jpg:payload.pkl" in issue.location
                and any(symbol in issue.message.lower() for symbol in system_symbols)
            ]
            assert result.success is False
            assert len(nested_issues) > 0
            probe_limit_checks = [check for check in result.checks if check.name == "Nested Member Probe Limit"]
            assert len(probe_limit_checks) == 1
            assert probe_limit_checks[0].details["limit"] == 1

        finally:
            if temp_pickle_path.exists():
                temp_pickle_path.unlink()
            if inner_7z_path.exists():
                inner_7z_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_misnamed_nested_7z_archive_low_value_suffix_still_probed(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
        tmp_path: Path,
    ) -> None:
        """Low-value suffixes like .txt should still be eligible for header probing."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self):
                import os as os_module

                return (os_module.system, ("echo disguised_7z_low_value",))

        inner_7z_path = tmp_path / "misnamed_inner_low_value.7z"
        temp_pickle_path = tmp_path / "payload_low_value.pkl"
        with temp_pickle_path.open("wb") as temp_pickle:
            pickle.dump(MaliciousClass(), temp_pickle)

        try:
            with py7zr.SevenZipFile(inner_7z_path, "w") as archive:
                archive.write(str(temp_pickle_path), "payload.pkl")

            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(str(inner_7z_path), "nested.txt")

            result = scanner.scan(temp_7z_file)

            system_symbols = {
                "os.system",
                f"{os.system.__module__}.system",
            }
            nested_issues = [
                issue
                for issue in result.issues
                if issue.location
                and f"{temp_7z_file}:nested.txt:payload.pkl" in issue.location
                and any(symbol in issue.message.lower() for symbol in system_symbols)
            ]
            assert result.success is False
            assert len(nested_issues) > 0
            assert any(issue.severity == IssueSeverity.CRITICAL for issue in nested_issues)
        finally:
            if temp_pickle_path.exists():
                temp_pickle_path.unlink()
            if inner_7z_path.exists():
                inner_7z_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_safe_misnamed_nested_7z_archive_has_no_critical_findings(
        self,
        temp_7z_file: str,
        tmp_path: Path,
    ) -> None:
        """Benign nested archives should recurse without introducing critical findings."""
        import py7zr  # type: ignore[import-untyped]

        scanner = SevenZipScanner(config={"max_7z_extensionless_probes": 1})
        inner_7z_path = tmp_path / "safe_inner.7z"
        safe_payload_path = tmp_path / "payload.txt"
        safe_payload_path.write_text("safe nested content", encoding="utf-8")

        try:
            with py7zr.SevenZipFile(inner_7z_path, "w") as archive:
                archive.write(str(safe_payload_path), "payload.txt")

            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                for index in range(10):
                    archive.writestr(b"filler", f"docs/{index}.txt.bak")
                archive.write(str(inner_7z_path), "nested.jpg")

            result = scanner.scan(temp_7z_file)

            assert result.success is False
            assert result.metadata["scannable_files"] == 1
            assert not any(
                issue.location
                and f"{temp_7z_file}:nested.jpg" in issue.location
                and issue.severity == IssueSeverity.CRITICAL
                for issue in result.issues
            )
            probe_limit_checks = [check for check in result.checks if check.name == "Nested Member Probe Limit"]
            assert len(probe_limit_checks) == 1
            assert probe_limit_checks[0].details["limit"] == 1
        finally:
            if safe_payload_path.exists():
                safe_payload_path.unlink()
            if inner_7z_path.exists():
                inner_7z_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_max_depth_limit(self, temp_7z_file: str) -> None:
        """Nested 7z archives should enforce the configured maximum depth."""
        import py7zr  # type: ignore[import-untyped]

        archive_paths: list[Path] = []
        try:
            deepest_path = Path(temp_7z_file).with_name("depth_0.7z")
            with py7zr.SevenZipFile(deepest_path, "w") as archive:
                archive.writestr(b"payload", "payload.txt")
            archive_paths.append(deepest_path)

            for depth in range(1, 4):
                next_path = Path(temp_7z_file).with_name(f"depth_{depth}.7z")
                with py7zr.SevenZipFile(next_path, "w") as archive:
                    archive.write(str(archive_paths[-1]), f"nested_{depth}.7z")
                archive_paths.append(next_path)

            scanner = SevenZipScanner(config={"max_7z_depth": 2})
            result = scanner.scan(str(archive_paths[-1]))

            assert result.success is False
            depth_issues = [issue for issue in result.issues if "maximum 7z nesting depth" in issue.message.lower()]
            assert len(depth_issues) == 1
            assert depth_issues[0].severity == IssueSeverity.WARNING

        finally:
            for archive_path in archive_paths:
                if archive_path.exists():
                    archive_path.unlink()

    def test_scan_honors_incoming_shared_archive_depth(self, temp_7z_file: str) -> None:
        """Nested 7z scans must respect the shared archive depth passed by parent scanners."""
        scanner = SevenZipScanner(config={"max_7z_depth": 1, "_archive_depth": 1})

        with patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True):
            result = scanner.scan(temp_7z_file)

        depth_checks = [check for check in result.checks if check.name == "7z Depth Bomb Protection"]
        assert not result.success
        assert len(depth_checks) == 1
        assert depth_checks[0].status == CheckStatus.FAILED
        assert "maximum 7z nesting depth (1) exceeded" in depth_checks[0].message.lower()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_non_7z_member_is_not_reported_as_unsupported(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Extensionless non-7z members should not emit noisy unsupported-file checks."""
        import py7zr  # type: ignore[import-untyped]

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"plain text")
            temp_file_path = temp_file.name

        try:
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(temp_file_path, "README")

            result = scanner.scan(temp_7z_file)

            assert result.success
            unsupported_checks = [check for check in result.checks if check.name == "File Type Support: README"]
            assert len(unsupported_checks) == 0

        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    def test_identify_scannable_files(self, scanner):
        """Test identification of scannable files"""
        test_files = [
            "nested.7z",  # Scannable
            "nested_archive",  # Extensionless members are probed separately
            "model.pkl",  # Scannable
            "model.joblib",  # Scannable
            "weights.pt",  # Scannable
            "checkpoint.ckpt",  # Scannable
            "model.bin",  # Scannable
            "arrays.npz",  # Scannable
            "serve.mar",  # Scannable
            "bundle.tar.gz",  # Scannable
            "config.json",  # Scannable
            "readme.txt",  # Not scannable
            "image.png",  # Not scannable
            "data.csv",  # Not scannable
        ]

        scannable = scanner._identify_scannable_files(test_files)
        supported = scanner._supported_nested_core_extensions()
        expected_scannable = {
            name
            for name in test_files
            if any(extension in supported for extension in scanner._candidate_archive_extensions(name))
        }
        assert set(scannable) == expected_scannable
        assert "model.joblib" in scannable
        assert "readme.txt" not in scannable
        assert "image.png" not in scannable

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_nested_supported_formats_route_through_core(self, temp_7z_file: str, tmp_path: Path) -> None:
        """Supported nested members should be extracted and routed through core scanning."""
        import py7zr  # type: ignore[import-untyped]

        scanner = SevenZipScanner(config={"max_file_size": 1024})
        sources = {
            "model.joblib": b"joblib payload",
            "checkpoint.ckpt": b"checkpoint payload",
            "arrays.npz": b"npz payload",
            "serve.mar": b"mar payload",
        }

        for archive_name, payload in sources.items():
            (tmp_path / archive_name).write_bytes(payload)

        with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
            for archive_name in sources:
                archive.write(str(tmp_path / archive_name), archive_name)

        with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
            result = scanner.scan(temp_7z_file)

        assert result.success
        assert result.metadata["scannable_files"] == len(sources)
        assert {Path(call.args[0]).name for call in mock_scan_file.call_args_list} == set(sources)
        for call in mock_scan_file.call_args_list:
            nested_config = call.args[1]
            assert nested_config["max_file_size"] == 1024
            assert nested_config["_archive_depth"] == 1

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_malicious_joblib_in_7z_end_to_end(self, scanner: SevenZipScanner, temp_7z_file: str) -> None:
        """A malicious .joblib nested in .7z must produce the same critical findings as a top-level scan."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousJoblib:
            def __reduce__(self):
                import os as os_module

                return (os_module.system, ("echo nested_joblib_payload",))

        joblib_path = Path(temp_7z_file).with_name("payload.joblib")
        with joblib_path.open("wb") as handle:
            pickle.dump(MaliciousJoblib(), handle)

        try:
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(str(joblib_path), "payload.joblib")

            result = scanner.scan(temp_7z_file)

            system_symbols = {
                "os.system",
                f"{os.system.__module__}.system",
            }
            critical_issues = [
                issue
                for issue in result.issues
                if issue.severity == IssueSeverity.CRITICAL
                and issue.location
                and f"{temp_7z_file}:payload.joblib" in issue.location
            ]

            assert result.success is False
            assert result.metadata["scannable_files"] == 1
            assert critical_issues, (
                f"Expected critical findings for payload.joblib, got: {[i.message for i in result.issues]}"
            )
            assert any(
                any(symbol in issue.message.lower() for symbol in system_symbols) for issue in critical_issues
            ), f"Expected os/posix.system finding, got: {[issue.message for issue in critical_issues]}"
        finally:
            if joblib_path.exists():
                joblib_path.unlink()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_path_traversal_detection(self, scanner: SevenZipScanner, temp_7z_file: str) -> None:
        """Test detection of path traversal attempts in archive"""
        import py7zr  # type: ignore[import-untyped]

        # Create safe content but with dangerous path
        safe_data = {"safe": True}

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_pickle:
            pickle.dump(safe_data, temp_pickle)
            temp_pickle_path = temp_pickle.name

        try:
            # Create 7z archive with path traversal attempt
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(temp_pickle_path, "../../../dangerous.pkl")

            result = scanner.scan(temp_7z_file)

            # Should detect path traversal
            assert result.success is False
            traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
            assert len(traversal_issues) > 0

            issue = traversal_issues[0]
            assert issue.severity == IssueSeverity.CRITICAL
            assert issue.location is not None
            assert "dangerous.pkl" in issue.location

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)

    def test_unsafe_entries_are_excluded_from_extraction_targets(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Path traversal entries should be reported but never extracted."""
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file"),
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["../../../escape.pkl", "safe.pkl", "readme.txt"]
            mock_archive.getinfo.return_value = MagicMock(
                is_directory=False,
                is_symlink=False,
                uncompressed=16,
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert result.success is False
            assert result.metadata["total_files"] == 3
            assert result.metadata["unsafe_entries"] == 1
            assert result.metadata["scannable_files"] == 1
            extract_targets = [
                call.kwargs["targets"] for call in mock_archive.extract.call_args_list if "targets" in call.kwargs
            ]
            assert ["safe.pkl"] in extract_targets
            assert all("../../../escape.pkl" not in targets for targets in extract_targets)

    def test_nested_critical_scan_does_not_mark_7z_extraction_incomplete(self, tmp_path: Path) -> None:
        """A nested CRITICAL finding is complete analysis, not partial archive traversal."""
        extracted_path = tmp_path / "model.pkl"
        extracted_path.write_bytes(b"payload")
        archive_path = tmp_path / "model.7z"
        archive_result = ScanResult(scanner_name="sevenzip")

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            nested_result = ScanResult(scanner_name="test_nested")
            nested_result.add_check(
                name="Nested Critical Finding",
                passed=False,
                message="Nested member is malicious",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            nested_result.finish(success=False)
            return nested_result

        scanner = SevenZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan})
        scan_complete = scanner._scan_extracted_file(
            str(extracted_path),
            "model.pkl",
            str(archive_path),
            archive_result,
            depth=0,
            budget=_RecursiveScanBudget(),
        )

        assert scan_complete is True
        assert archive_result.has_errors is True
        assert "scan_outcome" not in archive_result.metadata
        assert archive_result.metadata.get("analysis_incomplete") is not True
        assert any(check.name == "Nested Critical Finding" for check in archive_result.checks)

    def test_oversized_entries_are_skipped_before_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Archive member sizes should be checked before extraction materializes files."""
        scanner.max_extract_size = 100

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file") as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["large_file.pkl", "safe.pkl"]
            mock_archive.getinfo.side_effect = lambda name: MagicMock(
                uncompressed=1000 if name == "large_file.pkl" else 10,
                is_symlink=False,
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert result.success is False
            large_file_issues = [i for i in result.issues if "too large" in i.message]
            assert len(large_file_issues) == 1
            assert large_file_issues[0].details["extracted_size"] == 1000
            mock_archive.extract.assert_called_once()
            assert mock_archive.extract.call_args.kwargs["targets"] == ["safe.pkl"]
            mock_scan_extracted_file.assert_called_once()

    def test_extensionless_non_7z_members_are_filtered_before_full_extraction(
        self,
        scanner: SevenZipScanner,
        tmp_path: Path,
    ) -> None:
        """Only header-confirmed extensionless members should reach the full extraction pass."""
        extensionless_members = [f"asset_{index:03d}" for index in range(3)]
        archive_path = tmp_path / "filter_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file") as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                targets = kwargs["targets"]
                if factory is None:
                    return

                for target in targets:
                    probe = factory.create(target)
                    header = scanner._SEVENZIP_MAGIC if target == "nested_archive" else b"not7z!"
                    probe.write(header)

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["safe.pkl", "nested_archive", *extensionless_members]
            mock_archive.getinfo.side_effect = lambda _name: MagicMock(
                uncompressed=16,
                is_directory=False,
                is_symlink=False,
            )
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            assert result.success
            probe_calls = mock_archive.extract.call_args_list[:-1]
            assert mock_archive.reset.call_count == len(probe_calls)
            assert mock_archive.extract.call_count == len(extensionless_members) + 2
            assert [call.kwargs["targets"][0] for call in probe_calls] == ["nested_archive", *extensionless_members]
            assert all("factory" in call.kwargs for call in probe_calls)
            assert mock_archive.extract.call_args_list[-1].kwargs["targets"] == ["safe.pkl", "nested_archive"]
            assert mock_scan_extracted_file.call_count == 2

    def test_max_entries_protection(self, scanner, temp_7z_file):
        """Test protection against archives with too many entries"""
        # Set a low limit for testing
        scanner.max_entries = 2

        # Mock py7zr to simulate large archive
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["file1.pkl", "file2.pkl", "file3.pkl"]  # 3 files > limit of 2
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert not result.success
            bomb_issues = [i for i in result.issues if "exceeding limit" in i.message]
            assert len(bomb_issues) > 0

            issue = bomb_issues[0]
            assert issue.severity == IssueSeverity.CRITICAL
            assert "zip_bomb" in str(issue.details)

    def test_max_entries_protection_uses_bounded_member_metadata(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Entry limits should fail closed without copying the complete 7z name table."""
        scanner.max_entries = 2

        class SizedMemberSource(list[object]):
            def __iter__(self) -> Generator[object, None, None]:
                raise AssertionError("oversized sized metadata should not be iterated")

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            mock_archive = MagicMock()
            mock_archive.files = SizedMemberSource([object(), object(), object(), object()])
            mock_archive.getnames.side_effect = AssertionError("getnames should not materialize all member names")
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        assert result.success is False
        mock_archive.getnames.assert_not_called()
        mock_archive.extract.assert_not_called()
        limit_check = next(check for check in result.checks if check.name == "Archive Entry Limit")
        assert limit_check.status == CheckStatus.FAILED
        assert limit_check.details["file_count"] == 4
        assert limit_check.details["limit"] == 2
        assert result.metadata["total_files"] == 4

    def test_bounded_member_metadata_stops_unsized_source_at_limit(self, scanner: SevenZipScanner) -> None:
        """Unsized member sources should consume at most one entry beyond the configured limit."""
        scanner.max_entries = 2
        observed: list[str] = []

        def members() -> Generator[str, None, None]:
            for name in ("one.pkl", "two.pkl", "three.pkl", "four.pkl"):
                observed.append(name)
                yield name

        archive = MagicMock()
        archive.files = members()

        names, count, exceeded = scanner._bounded_archive_file_names(archive)

        assert names == ["one.pkl", "two.pkl", "three.pkl"]
        assert count == 3
        assert exceeded is True
        assert observed == names

    def test_bounded_member_metadata_does_not_trust_underreported_length(self, scanner: SevenZipScanner) -> None:
        """Iteration must retain the entry bound even when metadata length is inconsistent."""
        scanner.max_entries = 2

        class UnderreportedMemberSource:
            def __len__(self) -> int:
                return 1

            def __iter__(self) -> Generator[str, None, None]:
                yield from ("one.pkl", "two.pkl", "three.pkl", "four.pkl")

        archive = MagicMock()
        archive.files = UnderreportedMemberSource()

        names, count, exceeded = scanner._bounded_archive_file_names(archive)

        assert names == ["one.pkl", "two.pkl", "three.pkl"]
        assert count == 3
        assert exceeded is True

    def test_real_py7zr_metadata_api_change_fails_closed(self, scanner: SevenZipScanner) -> None:
        """A future py7zr metadata rename must not fall back to eager name collection."""

        class MissingMetadataArchive:
            __module__ = "py7zr.compat"

            @staticmethod
            def getnames() -> list[str]:
                raise AssertionError("getnames must not materialize all member names")

        with pytest.raises(ValueError, match="did not expose a bounded member source"):
            scanner._bounded_archive_file_names(MissingMetadataArchive())

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_real_archive_entry_limit_does_not_call_getnames(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Supported py7zr archives expose sized metadata, so eager name collection is unnecessary."""
        import py7zr  # type: ignore[import-untyped]

        with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
            archive.writestr(b"one", "one.txt")
            archive.writestr(b"two", "two.txt")
            archive.writestr(b"three", "three.txt")

        scanner.max_entries = 2
        with patch.object(py7zr.SevenZipFile, "getnames", side_effect=AssertionError("getnames must not be called")):
            result = scanner.scan(temp_7z_file)

        assert result.success is False
        limit_check = next(check for check in result.checks if check.name == "Archive Entry Limit")
        assert limit_check.details["file_count"] == 3
        assert result.metadata["total_files"] == 3

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_with_mixed_content(self, scanner, temp_7z_file):
        """Test scanning archive with mixed scannable and non-scannable content"""
        import py7zr  # type: ignore[import-untyped]

        # Create multiple temporary files
        temp_files = []

        try:
            # Safe pickle file
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                pickle.dump({"safe": True}, f)
                temp_files.append((f.name, "model.pkl"))

            # Text file (not scannable)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("Just text")
                temp_files.append((f.name, "readme.txt"))

            # JSON config (scannable)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                f.write('{"config": true}')
                temp_files.append((f.name, "config.json"))

            # Create 7z archive
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                for temp_path, archive_name in temp_files:
                    archive.write(temp_path, archive_name)

            with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
                result = scanner.scan(temp_7z_file)

                assert result.success
                assert result.metadata["total_files"] == 3
                assert result.metadata["scannable_files"] == 2  # .pkl and .json files
                assert mock_scan_file.call_count == 2

        finally:
            for temp_path, _ in temp_files:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    def test_scan_invalid_7z_file(self, scanner, temp_7z_file):
        """Test scanning an invalid/corrupted 7z file"""
        # Write invalid content to 7z file
        with open(temp_7z_file, "wb") as f:
            f.write(b"invalid 7z content")

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            # Create a mock exception class
            class MockBad7zFile(Exception):
                pass

            mock_py7zr.Bad7zFile = MockBad7zFile
            mock_py7zr.SevenZipFile.side_effect = MockBad7zFile("Invalid 7z file")

            result = scanner.scan(temp_7z_file)

            assert not result.success
            format_checks = [c for c in result.checks if "Format Validation" in c.name]
            assert len(format_checks) > 0

            check = format_checks[0]
            assert check.status == CheckStatus.FAILED
            assert "Invalid 7z file format" in check.message

    def test_scan_with_extraction_error(self, scanner: SevenZipScanner, temp_7z_file: str) -> None:
        """Test behavior when file extraction fails"""
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["test.pkl"]
            mock_archive.getinfo.return_value = MagicMock(
                is_directory=False,
                is_symlink=False,
                uncompressed=16,
            )
            mock_archive.extract.side_effect = Exception("Extraction failed")
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            # Should handle extraction errors gracefully
            # With batch extraction, errors are caught at archive level
            assert result.success is False
            archive_checks = [c for c in result.checks if "Archive Extraction" in c.name]
            assert len(archive_checks) > 0

            check = archive_checks[0]
            assert check.status == CheckStatus.FAILED
            assert "Failed during archive extraction" in check.message

    def test_very_long_filename_in_archive_mocked_scannable_entry(self, scanner, temp_7z_file):
        """Mocked long-filename entries should remain scannable without raising."""
        long_name = "a" * 200 + ".pkl"  # 204-character entry name

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file"),
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = [long_name]
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            # Scan must complete without raising; the long-named file is scannable
            assert result.metadata["total_files"] == 1
            assert result.metadata["scannable_files"] == 1

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_very_long_filename_in_archive_real_extraction(self, scanner, temp_7z_file):
        """Real 7z extraction should handle long entry names end to end."""
        import py7zr  # type: ignore[import-untyped]

        long_name = "a" * 200 + ".pkl"
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as temp_pickle:
            pickle.dump({"safe": True}, temp_pickle)
            temp_pickle_path = temp_pickle.name

        try:
            with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
                archive.write(temp_pickle_path, long_name)

            with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
                result = scanner.scan(temp_7z_file)

            assert result.success
            assert result.metadata["total_files"] == 1
            assert result.metadata["scannable_files"] == 1
            mock_scan_file.assert_called_once()
            extracted_path = mock_scan_file.call_args.args[0]
            assert os.path.basename(extracted_path) == long_name
        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)

    def test_truncated_archive_handled_gracefully_mocked_bad7zfile(self, scanner, temp_7z_file):
        """A mocked Bad7zFile should be reported as a clear format failure."""
        with open(temp_7z_file, "wb") as f:
            # Write valid magic bytes but then truncated/garbage body
            f.write(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 10)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):

            class MockBad7zFile(Exception):
                pass

            mock_py7zr.Bad7zFile = MockBad7zFile
            mock_py7zr.SevenZipFile.side_effect = MockBad7zFile("Truncated archive")

            result = scanner.scan(temp_7z_file)

            assert not result.success
            format_checks = [c for c in result.checks if "Format Validation" in c.name]
            assert len(format_checks) > 0
            assert format_checks[0].status == CheckStatus.FAILED

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_truncated_archive_handled_gracefully_real_archive(self, scanner, temp_7z_file):
        """A genuinely truncated 7z archive should fail format validation without crashing."""
        import py7zr  # type: ignore[import-untyped]

        source_path = Path(temp_7z_file).with_suffix(".pkl")
        source_path.write_bytes(b"safe pickle content")

        with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
            archive.write(str(source_path), "payload.pkl")

        full_data = Path(temp_7z_file).read_bytes()
        Path(temp_7z_file).write_bytes(full_data[: len(full_data) // 2])

        result = scanner.scan(temp_7z_file)

        assert not result.success
        format_checks = [c for c in result.checks if c.name == "7z File Format Validation"]
        assert len(format_checks) == 1
        assert format_checks[0].status == CheckStatus.FAILED
        assert "invalid 7z file format" in format_checks[0].message.lower()

    def test_multiple_model_formats_identified(self, scanner):
        """Archives containing diverse model-format files scan all scannable entries."""
        entries = [
            "nested.7z",
            "model.pkl",
            "weights.pt",
            "model.onnx",
            "config.json",
            "tokenizer.bin",
            "readme.txt",  # not scannable
            "image.png",  # not scannable
        ]

        scannable = scanner._identify_scannable_files(entries)

        supported = scanner._supported_nested_core_extensions()
        expected = {
            name
            for name in entries
            if any(extension in supported for extension in scanner._candidate_archive_extensions(name))
        }
        assert set(scannable) == expected
        # Non-model files must be excluded
        assert "readme.txt" not in scannable
        assert "image.png" not in scannable


class TestSevenZipScannerConfiguration:
    """Test configuration options for SevenZipScanner"""

    @pytest.fixture
    def scanner(self):
        """Create a SevenZipScanner instance for testing"""
        return SevenZipScanner()

    @pytest.fixture
    def temp_7z_file(self):
        """Create a temporary file with .7z extension for testing"""
        with tempfile.NamedTemporaryFile(suffix=".7z", delete=False) as f:
            temp_path = f.name
        yield temp_path
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_default_configuration(self):
        """Test default scanner configuration"""
        scanner = SevenZipScanner()

        assert scanner.max_depth == 5
        assert scanner.max_entries == 10000
        assert scanner.max_extract_size == 1024 * 1024 * 1024  # 1GB

    def test_custom_configuration(self):
        """Test custom scanner configuration"""
        config = {
            "max_7z_depth": 3,
            "max_7z_entries": 5000,
            "max_7z_extract_size": 512 * 1024 * 1024,  # 512MB
        }
        scanner = SevenZipScanner(config)

        assert scanner.max_depth == 3
        assert scanner.max_entries == 5000
        assert scanner.max_extract_size == 512 * 1024 * 1024

    def test_invalid_configuration_values_fall_back_to_defaults(self) -> None:
        """Malformed 7z limit configs should not raise or disable safety limits."""
        scanner = SevenZipScanner(
            {
                "max_7z_depth": "bad",
                "max_7z_entries": "bad",
                "max_7z_extract_size": "bad",
                "max_7z_extensionless_probes": "bad",
                "max_7z_total_extract_size": "bad",
                "max_7z_cumulative_entries": "bad",
            }
        )

        assert scanner.max_depth == 5
        assert scanner.max_entries == 10000
        assert scanner.max_extract_size == 1024 * 1024 * 1024
        assert scanner.max_extensionless_probes == 100
        assert scanner.max_total_extract_size == 5 * 1024 * 1024 * 1024
        assert scanner.max_cumulative_entries == 50000

    def test_nested_scans_receive_scanner_config(self, temp_7z_file: str) -> None:
        """Nested file scans should preserve the parent scanner config."""
        config = {
            "max_7z_depth": 4,
            "max_7z_entries": 5000,
            "max_7z_extract_size": 2048,
            "max_file_size": 1024,
        }
        scanner = SevenZipScanner(config)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["safe.pkl"]
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16, is_symlink=False)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert result.success
            mock_scan_file.assert_called_once()
            assert mock_scan_file.call_args.args[1] == {
                **scanner.config,
                "_archive_depth": 1,
                "cache_enabled": False,
            }

    def test_large_extracted_file_handling(self, scanner: SevenZipScanner, temp_7z_file: str) -> None:
        """Test handling of files that are too large after extraction"""
        scanner.max_extract_size = 100  # Very small limit for testing

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["large_file.pkl"]
            mock_archive.getinfo.return_value = MagicMock(
                is_directory=False,
                is_symlink=False,
                uncompressed=1000,
            )
            mock_archive.extract = MagicMock()
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            # Mock os.path.isfile and os.path.getsize
            with (
                patch("os.path.isfile", return_value=True),
                patch("os.path.getsize", return_value=1000),  # Larger than limit
            ):
                result = scanner.scan(temp_7z_file)

                # Should warn about large file
                assert result.success is False
                large_file_issues = [i for i in result.issues if "too large" in i.message]
                assert len(large_file_issues) > 0


class TestSevenZipScannerHardening:
    """Red-team tests for security hardening introduced in the review."""

    @pytest.fixture
    def temp_7z_file(self) -> Generator[str, None, None]:
        """Create a temporary file with .7z extension for testing"""
        with tempfile.NamedTemporaryFile(suffix=".7z", delete=False) as f:
            temp_path = f.name
        yield temp_path
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def scanner(self) -> SevenZipScanner:
        return SevenZipScanner()

    @staticmethod
    def _write_pickle(path: Path, payload: Any) -> None:
        with path.open("wb") as handle:
            pickle.dump(payload, handle)

    @staticmethod
    def _write_7z_archive(archive_path: Path, members: list[tuple[Path, str]]) -> None:
        import py7zr  # type: ignore[import-untyped]

        with py7zr.SevenZipFile(archive_path, "w") as archive:
            for source_path, archive_name in members:
                archive.write(str(source_path), archive_name)

    # -- symlink protection ---------------------------------------------------

    def test_symlink_in_archive_is_blocked(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
        tmp_path: Path,
    ) -> None:
        """Symlinks extracted from 7z archives must be detected and blocked."""
        symlink_target = tmp_path / "outside" / "sensitive.pkl"
        symlink_target.parent.mkdir()
        symlink_target.write_bytes(b"secret")

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("os.path.islink") as mock_islink,
            patch("os.readlink", return_value=str(symlink_target)),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["safe.pkl"]
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16, is_symlink=False)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive
            mock_islink.return_value = True

            result = scanner.scan(temp_7z_file)

            assert result.success is False
            symlink_checks = [c for c in result.checks if "Symlink" in c.name]
            assert len(symlink_checks) == 1
            assert symlink_checks[0].status == CheckStatus.FAILED
            assert symlink_checks[0].severity == IssueSeverity.CRITICAL
            assert symlink_checks[0].details["symlink_target"] == str(symlink_target)

    def test_declared_symlink_member_is_blocked_before_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """7z symlink metadata must be rejected before py7zr materializes the member."""
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["link.pkl"]
            mock_archive.getinfo.return_value = MagicMock(
                is_directory=False,
                is_symlink=True,
                uncompressed=16,
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        symlink_checks = [c for c in result.checks if c.name == "7z Symlink Protection"]
        assert result.success is False
        assert len(symlink_checks) == 1
        assert symlink_checks[0].severity == IssueSeverity.CRITICAL
        assert symlink_checks[0].details["checked_before_extraction"] is True
        mock_archive.extract.assert_not_called()

    def test_extensionless_symlink_member_is_blocked_before_probe_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Probe extraction must also reject symlink metadata before py7zr materializes the member."""
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["model"]
            mock_archive.getinfo.return_value = MagicMock(
                is_directory=False,
                is_symlink=True,
                uncompressed=16,
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        symlink_checks = [c for c in result.checks if c.name == "7z Symlink Protection"]
        assert result.success is False
        assert len(symlink_checks) == 1
        assert symlink_checks[0].details["checked_before_extraction"] is True
        mock_archive.extract.assert_not_called()

    def test_named_security_symlink_reports_once(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Probe and extraction preflights should share one link finding per member."""
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["payload.py"]
            mock_archive.getinfo.return_value = MagicMock(
                is_directory=False,
                is_symlink=True,
                is_junction=False,
                uncompressed=16,
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        symlink_checks = [c for c in result.checks if c.name == "7z Symlink Protection"]
        assert result.success is False
        assert len(symlink_checks) == 1
        mock_archive.extract.assert_not_called()

    def test_duplicate_name_with_symlink_is_blocked_before_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Name-based py7zr extraction must not select a hidden duplicate symlink entry."""
        regular_member = MagicMock(
            filename="dup.pkl",
            is_directory=False,
            is_symlink=False,
            is_junction=False,
            uncompressed=16,
        )
        symlink_member = MagicMock(
            filename="dup.pkl",
            is_directory=False,
            is_symlink=True,
            is_junction=False,
            uncompressed=8,
        )

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.files = [regular_member, symlink_member]
            mock_archive.getnames.return_value = ["dup.pkl", "dup.pkl"]
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        duplicate_checks = [c for c in result.checks if c.name == "7z Duplicate Entry Protection"]
        assert result.success is False
        assert len(duplicate_checks) == 1
        mock_archive.extract.assert_not_called()

    @pytest.mark.parametrize(
        "member_names",
        [
            ["dup.pkl", "dup.pkl"],
            ["dup.pkl", "subdir/../dup.pkl"],
        ],
    )
    def test_ambiguous_duplicate_paths_have_no_safe_extraction_target(
        self,
        scanner: SevenZipScanner,
        member_names: list[str],
    ) -> None:
        """Every entry in a canonical-name collision must be excluded from extraction."""
        result = ScanResult(scanner_name="sevenzip")

        safe_entries = scanner._check_path_traversal(member_names, "archive.7z", result)

        assert safe_entries == []
        duplicate_checks = [c for c in result.checks if c.name == "7z Duplicate Entry Protection"]
        assert len(duplicate_checks) == 1

    def test_member_metadata_is_indexed_once(self, scanner: SevenZipScanner) -> None:
        """Repeated preflight lookups should not rescan the full archive metadata iterable."""

        class CountingMemberList:
            iterations = 0

            def __iter__(self) -> Generator[MagicMock, None, None]:
                self.iterations += 1
                yield MagicMock(filename="first.pkl", is_symlink=False, uncompressed=1)
                yield MagicMock(filename="second.pkl", is_symlink=False, uncompressed=2)

        archive = MagicMock()
        archive.files = CountingMemberList()

        assert scanner._get_archive_member_info(archive, "first.pkl") is not None
        assert scanner._get_archive_member_info(archive, "second.pkl") is not None
        assert archive.files.iterations == 1

    def test_junction_metadata_is_treated_as_symlink(self, scanner: SevenZipScanner) -> None:
        """Windows junctions are reparse-point links and must be blocked before extraction."""
        member_info = MagicMock(is_symlink=False, is_junction=True)

        assert scanner._preflight_member_symlink_state(member_info) == "symlink"

    @pytest.mark.parametrize(("is_symlink", "expected_state"), [(False, "regular"), (True, "symlink")])
    def test_legacy_internal_member_metadata_preserves_symlink_preflight(
        self,
        scanner: SevenZipScanner,
        is_symlink: bool,
        expected_state: str,
    ) -> None:
        """py7zr 0.20.x exposes symlink state on archive.files but not public FileInfo."""

        class LegacyPublicFileInfo:
            filename = "model.pkl"
            uncompressed = 16

        class LegacyArchiveMember:
            filename = "model.pkl"
            uncompressed = 16

            def __init__(self) -> None:
                self.is_symlink = is_symlink

        class LegacyArchiveFileList:
            def __iter__(self) -> Generator[LegacyArchiveMember, None, None]:
                yield LegacyArchiveMember()

        class LegacyArchive:
            def __init__(self) -> None:
                self.files = LegacyArchiveFileList()

            @staticmethod
            def list() -> list[LegacyPublicFileInfo]:
                return [LegacyPublicFileInfo()]

        archive = LegacyArchive()
        member_info = scanner._get_archive_member_info(archive, "model.pkl")

        assert scanner._preflight_member_symlink_state(member_info) == expected_state
        assert scanner._get_archive_member_size(archive, "model.pkl") == 16

    def test_missing_symlink_metadata_fails_closed_before_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Older py7zr metadata without symlink status must not be trusted for extraction."""

        class LegacyMemberInfo:
            is_directory = False
            uncompressed = 16

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["model.pkl"]
            mock_archive.getinfo.return_value = LegacyMemberInfo()
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        metadata_checks = [c for c in result.checks if c.name == "7z Member Metadata"]
        assert result.success is False
        assert len(metadata_checks) == 1
        assert metadata_checks[0].details["analysis_incomplete"] is True
        assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        mock_archive.extract.assert_not_called()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_real_symlink_member_is_blocked_before_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """End-to-end: symlink metadata in a real 7z archive must stop before extraction."""
        import py7zr  # type: ignore[import-untyped]

        symlink_target = tmp_path / "outside" / "target.pkl"
        symlink_target.parent.mkdir()
        self._write_pickle(symlink_target, {"secret": True})
        symlink_path = tmp_path / "link.pkl"
        symlink_path.symlink_to(symlink_target)

        with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
            archive.write(str(symlink_path), "model.pkl")

        with patch.object(py7zr.SevenZipFile, "extract", side_effect=AssertionError("extract should not run")):
            result = scanner.scan(temp_7z_file)

        symlink_issues = [c for c in result.checks if "Symlink" in c.name]
        assert result.success is False
        assert len(symlink_issues) == 1
        assert symlink_issues[0].severity == IssueSeverity.CRITICAL
        assert symlink_issues[0].details["checked_before_extraction"] is True

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_real_symlink_blocked_after_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """End-to-end: a symlink member must not be scanned."""
        import py7zr  # type: ignore[import-untyped]

        benign = tmp_path / "benign.pkl"
        self._write_pickle(benign, {"ok": True})
        symlink_target = tmp_path / "outside" / "target.pkl"
        symlink_target.parent.mkdir()
        self._write_pickle(symlink_target, {"secret": True})

        with py7zr.SevenZipFile(temp_7z_file, "w") as archive:
            archive.write(str(benign), "model.pkl")

        original_extract = py7zr.SevenZipFile.extract

        def patched_extract(self_archive: Any, path: str | None = None, **kw: Any) -> None:
            original_extract(self_archive, path=path, **kw)
            if path is None:
                return

            link_path = Path(path) / "model.pkl"
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink()
            link_path.symlink_to(symlink_target)

        with (
            patch.object(py7zr.SevenZipFile, "extract", patched_extract),
            patch("modelaudit.core.scan_file") as mock_scan_file,
        ):
            result = scanner.scan(temp_7z_file)

        assert result.success is False
        symlink_issues = [c for c in result.checks if "Symlink" in c.name]
        assert len(symlink_issues) == 1
        assert symlink_issues[0].severity == IssueSeverity.CRITICAL
        assert symlink_issues[0].details["symlink_target"] == str(symlink_target)
        mock_scan_file.assert_not_called()

    # -- extensionless probe cap ----------------------------------------------

    def test_extensionless_probe_limit_enforced(
        self,
        temp_7z_file: str,
    ) -> None:
        """Extensionless member probing must stop after the configured limit."""
        scanner = SevenZipScanner(config={"max_7z_extensionless_probes": 3})

        extensionless_members = [f"asset_{i:03d}" for i in range(10)]

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(
                scanner,
                "_probe_extensionless_members",
                return_value={name: _NestedMemberProbeResult(None) for name in extensionless_members[:3]},
            ) as mock_probe,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = extensionless_members
            mock_archive.getinfo.return_value = MagicMock(is_directory=False, is_symlink=False, uncompressed=16)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert result.success is False
            assert mock_probe.call_count == 1
            assert mock_probe.call_args.args[1] == extensionless_members[:3]
            limit_checks = [c for c in result.checks if "Probe Limit" in c.name]
            assert len(limit_checks) == 1
            assert limit_checks[0].status == CheckStatus.FAILED
            assert limit_checks[0].severity == IssueSeverity.INFO
            assert "remaining unsupported members were not inspected" in limit_checks[0].message
            assert limit_checks[0].details["analysis_incomplete"] is True
            assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_probe_limit_benign_archive_exits_inconclusive(
        self,
        tmp_path: Path,
    ) -> None:
        """A bounded probe window is incomplete coverage, not a security finding."""
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "benign_probe_limit.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.writestr(b"ordinary notes", "first_payload")
            archive.writestr(b"more ordinary notes", "second_payload")

        config = {"max_7z_extensionless_probes": 1}
        result = SevenZipScanner(config=config).scan(str(archive_path))
        _assert_inconclusive_aggregate_not_cached(
            archive_path,
            "sevenzip_analysis_incomplete",
            tmp_path / "benign-probe-limit-cache",
            max_7z_extensionless_probes=1,
        )

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any("remaining unsupported members were not inspected" in check.message for check in result.checks)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_probe_limit_hidden_payload_exits_inconclusive(
        self,
        tmp_path: Path,
    ) -> None:
        """An uninspected payload after the probe cap must not produce a clean or invented finding."""
        import py7zr  # type: ignore[import-untyped]

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                return (os.system, ("echo hidden_after_probe_cap",))

        archive_path = tmp_path / "hidden_probe_limit.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.writestr(b"ordinary notes", "first_payload")
            archive.writestr(pickle.dumps(DangerousPayload(), protocol=0), "second_payload")

        config = {"max_7z_extensionless_probes": 1}
        result = SevenZipScanner(config=config).scan(str(archive_path))
        _assert_inconclusive_aggregate_not_cached(
            archive_path,
            "sevenzip_analysis_incomplete",
            tmp_path / "hidden-probe-limit-cache",
            max_7z_extensionless_probes=1,
        )

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["scannable_files"] == 0
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_probe_limit_preserves_observed_security_finding(self, tmp_path: Path) -> None:
        """An inspected malicious member must stay a security finding despite later incomplete coverage."""
        import py7zr  # type: ignore[import-untyped]

        class DangerousPayload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                return (os.system, ("echo detected_before_probe_cap",))

        archive_path = tmp_path / "observed_probe_limit.7z"
        payload_path = tmp_path / "observed_payload"
        payload_path.write_bytes(pickle.dumps(DangerousPayload(), protocol=0))
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "first_payload")
            archive.writestr(b"ordinary notes", "second_payload")

        reset_cache_manager()
        try:
            aggregates = [
                scan_model_directory_or_file(
                    str(archive_path),
                    max_7z_extensionless_probes=1,
                    cache_enabled=True,
                    cache_dir=str(tmp_path / "observed-probe-limit-cache"),
                    min_cache_file_size=0,
                )
                for _ in range(2)
            ]
            for aggregate in aggregates:
                metadata = aggregate.file_metadata[str(archive_path)]
                assert "sevenzip_analysis_incomplete" in metadata["scan_outcome_reasons"]
                assert any(
                    issue.severity == IssueSeverity.CRITICAL
                    and issue.location
                    and f"{archive_path}:first_payload" in issue.location
                    and "system" in str(issue.message).lower()
                    for issue in aggregate.issues
                )
                assert determine_exit_code(aggregate) == 1
            assert (
                get_cache_manager(str(tmp_path / "observed-probe-limit-cache"), enabled=True).get_stats()[
                    "total_entries"
                ]
                == 0
            )
        finally:
            reset_cache_manager()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_probe_read_failure_is_inconclusive_and_not_cached(
        self,
        tmp_path: Path,
    ) -> None:
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "unreadable_probe.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.writestr(b"ordinary notes", "payload")

        with (
            patch.object(SevenZipScanner, "_probe_extensionless_members", side_effect=OSError("batch read failed")),
            patch.object(SevenZipScanner, "_member_probe_result", side_effect=OSError("member read failed")),
        ):
            result = SevenZipScanner().scan(str(archive_path))

            assert result.success is False
            assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
            failure_check = next(check for check in result.checks if check.name.startswith("Nested 7z Probe:"))
            assert failure_check.severity == IssueSeverity.INFO
            assert "Failed to inspect nested archive candidate" in failure_check.message
            assert failure_check.details["analysis_incomplete"] is True
            assert failure_check.details["scan_outcome_reason"] == "sevenzip_analysis_incomplete"

            _assert_inconclusive_aggregate_not_cached(
                archive_path,
                "sevenzip_analysis_incomplete",
                tmp_path / "probe-read-failure-cache",
            )

    def test_disguised_nested_zip_member_is_routed_for_scan(
        self,
        tmp_path: Path,
    ) -> None:
        """Disguised nested archives should become scannable via bounded header probes."""
        scanner = SevenZipScanner()
        archive_path = tmp_path / "mock.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(
                scanner,
                "_probe_extensionless_members",
                return_value={"payload.jpg": _NestedMemberProbeResult("zip")},
            ) as mock_probe,
            patch.object(scanner, "_extract_and_scan_files", return_value=True) as mock_extract,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["payload.jpg"]
            mock_archive.getinfo.return_value = MagicMock(is_directory=False, is_symlink=False, uncompressed=16)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            assert result.success
            assert mock_probe.call_args.args[1] == ["payload.jpg"]
            assert mock_extract.call_args.args[1] == ["payload.jpg"]
            assert result.metadata["scannable_files"] == 1

    def test_probe_confirmed_disguised_xgboost_member_is_retargeted_without_suffix(self, tmp_path: Path) -> None:
        extracted_path = tmp_path / "model.jpg"
        extracted_path.write_bytes(_xgboost_ubjson_probe())
        archive_result = ScanResult(scanner_name="sevenzip")
        scanned_paths: list[str] = []

        def nested_scan(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            return _mock_scan_result(location=path, scanner_name="xgboost")

        scanner = SevenZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: nested_scan})
        scan_complete = scanner._scan_extracted_file(
            str(extracted_path),
            "model.jpg",
            str(tmp_path / "outer.7z"),
            archive_result,
            depth=0,
            budget=_RecursiveScanBudget(),
            probed_format="xgboost",
        )

        assert scan_complete is True
        assert len(scanned_paths) == 1
        assert Path(scanned_paths[0]).suffix == ""
        assert not extracted_path.exists()

    def test_oversized_disguised_nested_zip_marks_scan_incomplete(
        self,
        tmp_path: Path,
    ) -> None:
        """Oversized disguised nested archives must fail closed once header probes classify them as scannable."""
        scanner = SevenZipScanner(config={"max_7z_extract_size": 8})
        archive_path = tmp_path / "mock_oversized.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(
                scanner,
                "_probe_extensionless_members",
                return_value={"payload.jpg": _NestedMemberProbeResult("zip")},
            ),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["payload.jpg"]
            mock_archive.getinfo.return_value = MagicMock(is_directory=False, is_symlink=False, uncompressed=32)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            oversized_checks = [c for c in result.checks if c.name == "Extracted File Size"]
            assert len(oversized_checks) == 1
            assert oversized_checks[0].details["size_limit"] == 8
            assert result.success is False
            assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_probe_extensionless_members_stops_each_member_at_header_limit(self) -> None:
        """Header probes should stop each disguised member after the bounded prefix."""
        scanner = SevenZipScanner()

        class FakeArchive:
            def __init__(self) -> None:
                self.targets: list[list[str]] = []
                self.reset_count = 0

            def extract(self, *, targets: list[str], factory: Any) -> None:
                self.targets.append(targets)
                probe = factory.create(targets[0])
                probe.write(b"PK\x03\x04" + (b"A" * scanner._NESTED_MEMBER_PROBE_BYTES * 2))
                raise AssertionError("probe extraction did not stop at the configured header budget")

            def reset(self) -> None:
                self.reset_count += 1

        fake_archive = FakeArchive()

        assert scanner._probe_extensionless_members(fake_archive, ["payload_a.jpg", "payload_b.jpg"]) == {
            "payload_a.jpg": _NestedMemberProbeResult("zip"),
            "payload_b.jpg": _NestedMemberProbeResult("zip"),
        }
        assert fake_archive.targets == [["payload_a.jpg"], ["payload_b.jpg"]]
        assert fake_archive.reset_count == 2

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_disguised_nested_zip_member_detects_malicious_payload_end_to_end(self, tmp_path: Path) -> None:
        """A ZIP payload hidden behind an image suffix inside 7z must still be scanned."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self) -> tuple[Any, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo disguised_zip_in_7z",))

        pickle_path = tmp_path / "payload.pkl"
        nested_zip_path = tmp_path / "nested.zip"
        archive_path = tmp_path / "outer.7z"
        self._write_pickle(pickle_path, MaliciousClass())
        with zipfile.ZipFile(nested_zip_path, "w") as archive:
            archive.write(pickle_path, "payload.pkl")
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(str(nested_zip_path), "payload.jpg")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            issue.location
            and f"{archive_path}:payload.jpg:payload.pkl" in issue.location
            and "system" in issue.message.lower()
            for issue in result.issues
        )

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_disguised_xgboost_member_detects_malicious_payload_end_to_end(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model_payload"
        payload_path.write_bytes(_xgboost_ubjson_probe(malicious=True))
        archive_path = tmp_path / "disguised_xgboost.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "models/model.jpg")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 1
        assert any(
            issue.location
            and f"{archive_path}:models/model.jpg" in issue.location
            and "System call in JSON" in str(issue.message)
            for issue in result.issues
        )

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_probe_limit_preserves_disguised_xgboost_security_finding(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model_payload"
        payload_path.write_bytes(_xgboost_ubjson_probe(malicious=True))
        archive_path = tmp_path / "capped_disguised_xgboost.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "models/model.jpg")
            archive.writestr(b"ordinary notes", "models/filler.jpg")

        result = scan_model_directory_or_file(
            str(archive_path),
            max_7z_extensionless_probes=1,
            cache_enabled=False,
        )

        metadata = result.file_metadata[str(archive_path)]
        assert "sevenzip_analysis_incomplete" in metadata["scan_outcome_reasons"]
        assert determine_exit_code(result) == 1
        assert any(
            issue.location
            and f"{archive_path}:models/model.jpg" in issue.location
            and "System call in JSON" in str(issue.message)
            for issue in result.issues
        )

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_json_suffixed_xgboost_member_detects_malicious_payload_end_to_end(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model_payload"
        payload_path.write_bytes(_xgboost_ubjson_probe(malicious=True))
        archive_path = tmp_path / "json_suffixed_xgboost.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "models/model.json")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 1
        assert any(
            issue.location
            and f"{archive_path}:models/model.json" in issue.location
            and "System call in JSON" in str(issue.message)
            for issue in result.issues
        )

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_disguised_nested_tar_member_detects_malicious_payload_end_to_end(self, tmp_path: Path) -> None:
        """A TAR payload hidden behind an opaque suffix inside 7z must still be scanned."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self) -> tuple[Any, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo disguised_tar_in_7z",))

        pickle_path = tmp_path / "payload.pkl"
        nested_tar_path = tmp_path / "nested.tar"
        archive_path = tmp_path / "outer_tar.7z"
        self._write_pickle(pickle_path, MaliciousClass())
        with tarfile.open(nested_tar_path, "w") as archive:
            archive.add(pickle_path, arcname="payload.pkl")
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(str(nested_tar_path), "payload.bin")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is False
        assert any(
            issue.location
            and f"{archive_path}:payload.bin:payload.pkl" in issue.location
            and "system" in issue.message.lower()
            for issue in result.issues
        )

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_benign_disguised_image_member_is_not_routed_as_nested_archive(self, tmp_path: Path) -> None:
        """Image-like members with unsupported magic should not become noisy nested archive scans."""
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "benign_image.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.writestr(b"\x89PNG\r\n\x1a\n" + (b"\0" * 128), "payload.jpg")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is True
        assert result.metadata["scannable_files"] == 0
        assert not result.issues

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_high_risk_python_member_is_scanned_through_shared_archive_security(self, tmp_path: Path) -> None:
        """Python source members must not bypass the AST archive-member detector."""
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "python_sidecar.7z"
        source_path = tmp_path / "setup.py"
        source_path.write_bytes(b"import os\nos.system('echo hidden')\n")
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(source_path, "assets/setup.py")

        result = SevenZipScanner().scan(str(archive_path))
        security_checks = [
            check
            for check in result.checks
            if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
        ]

        assert len(security_checks) == 1
        assert "high-risk calls: os.system" in security_checks[0].message
        assert security_checks[0].rule_code == "S101"
        aggregate = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)
        assert determine_exit_code(aggregate) == 1

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_python_named_pickle_still_reaches_nested_pickle_scanning(self, tmp_path: Path) -> None:
        """A pickle disguised as Python source must not stop at AST inspection."""
        import py7zr  # type: ignore[import-untyped]

        class MaliciousClass:
            def __reduce__(self) -> tuple[Any, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo disguised_python_pickle",))

        payload_path = tmp_path / "payload.pkl"
        archive_path = tmp_path / "python_named_pickle.7z"
        self._write_pickle(payload_path, MaliciousClass())
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "assets/payload.py")

        result = SevenZipScanner().scan(str(archive_path))

        assert any(
            issue.location
            and f"{archive_path}:assets/payload.py" in issue.location
            and "system" in issue.message.lower()
            for issue in result.issues
        )
        aggregate = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)
        assert determine_exit_code(aggregate) == 1

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_benign_python_named_pickle_does_not_mark_python_analysis_incomplete(self, tmp_path: Path) -> None:
        """A nested pickle owned by content routing must not be parsed as Python source."""
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "payload.pkl"
        archive_path = tmp_path / "benign_python_named_pickle.7z"
        self._write_pickle(payload_path, {"safe": True})
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "assets/payload.py")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is True
        assert result.metadata.get("analysis_incomplete") is not True
        assert not any(check.name == "Python Archive Member Security" for check in result.checks)
        aggregate = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)
        assert determine_exit_code(aggregate) == 0

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_benign_python_and_ordinary_members_stay_clean(self, tmp_path: Path) -> None:
        """Scanning generic member types must not turn inert sidecars into findings."""
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "benign_sidecars.7z"
        source_path = tmp_path / "setup.py"
        notes_path = tmp_path / "readme.dat"
        source_path.write_bytes(b"def transform(value):\n    return value\n")
        notes_path.write_bytes(b"ordinary model notes")
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(source_path, "assets/setup.py")
            archive.write(notes_path, "assets/readme.dat")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is True
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_unparseable_python_member_marks_scan_inconclusive(self, tmp_path: Path) -> None:
        """Unparseable Python source must fail closed instead of silently clearing coverage."""
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "unparseable_python.7z"
        source_path = tmp_path / "broken.py"
        source_path.write_bytes(b"def broken(:\n")
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(source_path, "assets/broken.py")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "sevenzip_python_member_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        parse_checks = [
            check
            for check in result.checks
            if check.name == "Python Archive Member Security" and check.status == CheckStatus.FAILED
        ]
        assert len(parse_checks) == 1
        assert parse_checks[0].severity == IssueSeverity.INFO
        aggregate = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)
        assert determine_exit_code(aggregate) == 2

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_disguised_executable_members_are_detected_by_content(self, tmp_path: Path) -> None:
        """Executable bytes must not disappear behind inert member suffixes."""
        import py7zr  # type: ignore[import-untyped]

        distant_pe_header = bytearray(b"\x00" * 2052)
        distant_pe_header[:2] = b"MZ"
        distant_pe_header[0x3C:0x40] = (2048).to_bytes(4, "little")
        distant_pe_header[2048:2052] = b"PE\x00\x00"
        archive_path = tmp_path / "executable_sidecars.7z"
        elf_path = tmp_path / "payload.dat"
        pe_path = tmp_path / "loader.txt"
        supported_path = tmp_path / "declared.pkl"
        python_named_path = tmp_path / "payload.py"
        elf_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))
        pe_path.write_bytes(bytes(distant_pe_header))
        supported_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))
        python_named_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(elf_path, "assets/payload.dat")
            archive.write(pe_path, "assets/loader.txt")
            archive.write(supported_path, "assets/declared.pkl")
            archive.write(python_named_path, "assets/payload.py")

        result = SevenZipScanner().scan(str(archive_path))
        security_messages = {
            check.message
            for check in result.checks
            if check.name == "Executable Archive Member Detection" and check.status == CheckStatus.FAILED
        }

        assert "Executable file found in 7z archive: assets/payload.dat" in security_messages
        assert "Executable file found in 7z archive: assets/loader.txt" in security_messages
        assert "Executable file found in 7z archive: assets/declared.pkl" in security_messages
        assert "Executable file found in 7z archive: assets/payload.py" in security_messages
        aggregate = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)
        assert determine_exit_code(aggregate) == 1

    def test_probed_executable_finding_survives_nested_extraction_size_limit(self, tmp_path: Path) -> None:
        """A positive content probe must be reported before nested extraction is rejected."""
        scanner = SevenZipScanner(config={"max_7z_extract_size": 8})
        archive_path = tmp_path / "mock_oversized_executable.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(
                scanner,
                "_probe_extensionless_members",
                return_value={"payload.py": _NestedMemberProbeResult(None, executable_content=True)},
            ),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["payload.py"]
            mock_archive.getinfo.return_value = MagicMock(is_directory=False, is_symlink=False, uncompressed=32)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

        assert any(
            check.name == "Executable Archive Member Detection"
            and check.message == "Executable file found in 7z archive: payload.py"
            for check in result.checks
        )
        assert any(check.name == "Extracted File Size" for check in result.checks)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_benign_llamafile_member_is_scanned_without_generic_executable_warning(self, tmp_path: Path) -> None:
        """An explicit Llamafile member is a model artifact, not an executable sidecar."""
        import py7zr  # type: ignore[import-untyped]

        archive_path = tmp_path / "llamafile_model.7z"
        source_path = tmp_path / "safe.llamafile"
        source_path.write_bytes(
            b"\x7fELF\x02\x01\x01\x00"
            + (b"\x00" * 56)
            + b"llamafile runtime\n--threads 4\n--ctx-size 2048"
            + (b"\x00" * 256)
            + (b"\x00" * 8192)
            + b"GGUF"
            + struct.pack("<IQQ", 3, 0, 0)
        )
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(source_path, "models/safe.llamafile")

        result = SevenZipScanner().scan(str(archive_path))

        assert not any(check.name == "Executable Archive Member Detection" for check in result.checks)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_unconfirmed_pe_pointer_marks_disguised_member_probe_inconclusive(self, tmp_path: Path) -> None:
        """An MZ near-match beyond the PE budget must not become a confirmed finding."""
        import py7zr  # type: ignore[import-untyped]

        payload = bytearray(64)
        payload[:2] = b"MZ"
        payload[0x3C:0x40] = ((1024 * 1024) + 1).to_bytes(4, "little")
        archive_path = tmp_path / "ambiguous_pe_sidecar.7z"
        payload_path = tmp_path / "loader.dat"
        payload_path.write_bytes(payload)
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, "assets/loader.dat")

        result = SevenZipScanner().scan(str(archive_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "sevenzip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Executable 7z Probe: assets/loader.dat" and check.details["analysis_incomplete"] is True
            for check in result.checks
        )
        assert not any(check.name == "Executable Archive Member Detection" for check in result.checks)

    # -- cumulative entry count -----------------------------------------------

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_cumulative_entry_limit_across_nesting(
        self,
        tmp_path: Path,
    ) -> None:
        """Cumulative entry count across nested archives must be enforced."""
        scanner = SevenZipScanner(config={"max_7z_cumulative_entries": 3})
        outer_path = tmp_path / "outer.7z"
        inner_path = tmp_path / "nested.7z"
        inner_a = tmp_path / "inner_a.pkl"
        inner_b = tmp_path / "inner_b.pkl"
        sibling = tmp_path / "sibling.pkl"

        self._write_pickle(inner_a, {"id": "inner-a"})
        self._write_pickle(inner_b, {"id": "inner-b"})
        self._write_pickle(sibling, {"id": "sibling"})
        self._write_7z_archive(inner_path, [(inner_a, "inner_a.pkl"), (inner_b, "inner_b.pkl")])
        self._write_7z_archive(outer_path, [(inner_path, "nested.7z"), (sibling, "sibling.pkl")])

        with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
            result = scanner.scan(str(outer_path))

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Entry Limit"]
        assert len(cumulative_checks) == 1
        assert not result.success
        assert cumulative_checks[0].severity == IssueSeverity.CRITICAL
        assert cumulative_checks[0].details["cumulative_entries"] == 4
        assert cumulative_checks[0].location is not None
        assert f"{outer_path}:nested.7z" in cumulative_checks[0].location
        mock_scan_file.assert_not_called()

    # -- cumulative extraction size -------------------------------------------

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_cumulative_extraction_size_limit(
        self,
        tmp_path: Path,
    ) -> None:
        """Cumulative extracted bytes must be capped."""
        outer_path = tmp_path / "outer.7z"
        inner_path = tmp_path / "nested.7z"
        inner_a = tmp_path / "inner_a.pkl"
        inner_b = tmp_path / "inner_b.pkl"
        sibling = tmp_path / "sibling.pkl"

        self._write_pickle(inner_a, {"payload": "a" * 512})
        self._write_pickle(inner_b, {"payload": "b" * 512})
        self._write_pickle(sibling, {"payload": "s" * 512})
        self._write_7z_archive(inner_path, [(inner_a, "inner_a.pkl"), (inner_b, "inner_b.pkl")])
        self._write_7z_archive(outer_path, [(inner_path, "nested.7z"), (sibling, "sibling.pkl")])

        limit = inner_path.stat().st_size + inner_a.stat().st_size + inner_b.stat().st_size - 1
        scanner = SevenZipScanner(config={"max_7z_total_extract_size": limit})

        with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
            result = scanner.scan(str(outer_path))

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Extraction Size"]
        assert len(cumulative_checks) == 1
        assert not result.success
        assert cumulative_checks[0].severity == IssueSeverity.CRITICAL
        assert cumulative_checks[0].details["limit"] == limit
        mock_scan_file.assert_not_called()

    def test_known_cumulative_extraction_size_limit_preflights_before_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        scanner.max_total_extract_size = 100

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file") as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["a.pkl", "b.pkl"]
            mock_archive.getinfo.side_effect = lambda _name: MagicMock(
                uncompressed=60,
                is_directory=False,
                is_symlink=False,
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Extraction Size"]
        assert result.success is False
        assert len(cumulative_checks) == 1
        assert cumulative_checks[0].severity == IssueSeverity.CRITICAL
        assert cumulative_checks[0].details["cumulative_bytes"] == 120
        mock_archive.extract.assert_not_called()
        mock_scan_extracted_file.assert_not_called()

    def test_unknown_cumulative_extraction_size_limit_uses_budgeted_factory(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        scanner.max_total_extract_size = 100
        extract_kwargs: dict[str, Any] = {}

        def fake_extract(*_args: Any, **kwargs: Any) -> None:
            extract_kwargs.update(kwargs)
            factory = kwargs["factory"]
            for target in kwargs["targets"]:
                writer = factory.create(target)
                writer.write(b"x" * 60)
                writer.close()

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file") as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["a.pkl", "b.pkl"]
            mock_archive.getinfo.side_effect = lambda _name: MagicMock(
                uncompressed=None,
                is_directory=False,
                is_symlink=False,
            )
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Extraction Size"]
        assert result.success is False
        assert len(cumulative_checks) == 1
        assert cumulative_checks[0].severity == IssueSeverity.CRITICAL
        assert cumulative_checks[0].details["cumulative_bytes"] == 120
        assert "factory" in extract_kwargs
        assert "path" not in extract_kwargs
        mock_scan_extracted_file.assert_not_called()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_real_many_small_members_abort_before_extraction_budget_is_exceeded(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "many_small.7z"
        members: list[tuple[Path, str]] = []
        for index in range(4):
            member_path = tmp_path / f"member_{index}.pkl"
            self._write_pickle(member_path, {"payload": "x" * 64, "index": index})
            members.append((member_path, f"member_{index}.pkl"))
        self._write_7z_archive(archive_path, members)
        limit = sum(path.stat().st_size for path, _name in members) - 1
        scanner = SevenZipScanner(config={"max_7z_total_extract_size": limit})

        with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
            result = scanner.scan(str(archive_path))

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Extraction Size"]
        assert result.success is False
        assert len(cumulative_checks) == 1
        assert cumulative_checks[0].details["limit"] == limit
        mock_scan_file.assert_not_called()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_real_archive_under_cumulative_extraction_budget_scans_members(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "under_budget.7z"
        members: list[tuple[Path, str]] = []
        for index in range(2):
            member_path = tmp_path / f"safe_{index}.pkl"
            self._write_pickle(member_path, {"payload": "safe", "index": index})
            members.append((member_path, f"safe_{index}.pkl"))
        self._write_7z_archive(archive_path, members)
        limit = sum(path.stat().st_size for path, _name in members)
        scanner = SevenZipScanner(config={"max_7z_total_extract_size": limit})

        with patch("modelaudit.core.scan_file", return_value=_mock_scan_result()) as mock_scan_file:
            result = scanner.scan(str(archive_path))

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Extraction Size"]
        assert result.success is True
        assert cumulative_checks == []
        assert mock_scan_file.call_count == 2

    # -- depth bomb finish() --------------------------------------------------

    def test_depth_bomb_sets_end_time(self, temp_7z_file: str) -> None:
        """Depth bomb early return must call finish() so end_time is set."""
        scanner = SevenZipScanner(config={"max_7z_depth": 1})

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_has_7z_magic", return_value=True),
            patch("os.path.isfile", return_value=True),
            patch("os.path.islink", return_value=False),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested.7z"]
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16, is_directory=False, is_symlink=False)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            # The inner result should have end_time set via finish()
            # Verify through checking the depth bomb check exists and result is usable
            depth_checks = [c for c in result.checks if "Depth Bomb" in c.name and c.status == CheckStatus.FAILED]
            assert len(depth_checks) >= 1
            assert result.metadata.get("file_size") is not None

    # -- nested header probe behavior via scanner API -------------------------

    def test_probe_detected_format_handles_missing_probe(self) -> None:
        """Header probe should return None when no probe buffer is available."""
        scanner = SevenZipScanner()

        assert scanner._probe_detected_format(None) is None

    def test_probe_detected_format_recognizes_7z_magic(self) -> None:
        """Header probes should classify 7z members from signature bytes."""
        scanner = SevenZipScanner()
        probe = io.BytesIO(scanner._SEVENZIP_MAGIC + b"\x00" * 16)

        assert scanner._probe_detected_format(probe) == "sevenzip"

    def test_probe_detected_format_recognizes_tar_headers(self) -> None:
        """Header probes should classify nested TAR members without relying on suffixes."""
        scanner = SevenZipScanner()
        tar_header = bytearray(scanner._NESTED_MEMBER_PROBE_BYTES)
        tar_header[257:262] = b"ustar"
        probe = io.BytesIO(bytes(tar_header))

        assert scanner._probe_detected_format(probe) == "tar"

    def test_probe_detected_format_recognizes_extensionless_proto0_pickle(self) -> None:
        """7z nested probes should route protocol-0 pickle members without suffixes."""
        scanner = SevenZipScanner()
        probe = io.BytesIO(b"cposix\nsystem\n(S'echo hidden'\ntR.")

        assert scanner._probe_detected_format(probe) == "pickle"

    def test_probe_detected_format_recognizes_protocolless_binary_pickle(self) -> None:
        """7z nested probes should route malicious binary pickles without PROTO."""
        scanner = SevenZipScanner()
        probe = io.BytesIO(
            (b"\x8c\x01x0" * 8) + b"\x8c\x02os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94."
        )

        assert scanner._probe_detected_format(probe) == "pickle"

    def test_probe_detected_format_fails_closed_at_protocolless_pickle_prefix_budget(self) -> None:
        scanner = SevenZipScanner()
        probe = io.BytesIO(b"\x8c\x01x0" * (scanner._NESTED_MEMBER_PROBE_BYTES // 4))

        assert scanner._probe_detected_format(probe) == PICKLE_ROUTING_INCONCLUSIVE_FORMAT

    def test_probe_detected_format_recognizes_extensionless_xgboost_ubjson(self) -> None:
        """7z nested probes should retain extensionless XGBoost UBJSON members."""
        scanner = SevenZipScanner()
        probe = io.BytesIO(_xgboost_ubjson_probe())

        assert scanner._probe_detected_format(probe) == "xgboost"

    def test_probe_detected_format_recognizes_noop_before_xgboost_learner(self) -> None:
        scanner = SevenZipScanner()
        probe = io.BytesIO(_xgboost_ubjson_probe(learner_noop=True))

        assert scanner._probe_detected_format(probe) == "xgboost"

    def test_probe_detected_format_recognizes_noop_before_counted_root_header(self) -> None:
        scanner = SevenZipScanner()
        probe = io.BytesIO(_xgboost_ubjson_noop_before_counted_root_header_probe())

        assert scanner._probe_detected_format(probe) == "xgboost"

    def test_probe_detected_format_bounds_counted_zero_payload_xgboost_array(self) -> None:
        """7z nested probes must not iterate attacker-controlled zero-payload arrays."""
        scanner = SevenZipScanner()
        probe = io.BytesIO(_xgboost_ubjson_counted_null_array_probe())

        assert scanner._probe_detected_format(probe) == "xgboost"

    def test_probe_detected_format_ignores_extensionless_ubjson_manifest_near_match(self) -> None:
        scanner = SevenZipScanner()
        payload = (
            b"{"
            + _ubjson_key(b"learner")
            + b"{}"
            + _ubjson_key(b"version")
            + b"[]"
            + _ubjson_key(b"note")
            + _ubjson_string(b"system(cpu)")
            + b"}"
        )

        assert scanner._probe_detected_format(io.BytesIO(payload)) is None

    def test_probe_detected_format_ignores_plain_extensionless_json(self) -> None:
        scanner = SevenZipScanner()

        assert scanner._probe_detected_format(io.BytesIO(b'{"kind":"manifest","safe":true}')) is None

    def test_probe_detected_format_ignores_benign_proto0_near_match_text(self) -> None:
        """Plain text that starts with proto0-looking bytes should not route as pickle."""
        scanner = SevenZipScanner()
        probe = io.BytesIO(b"cat is a category label, not a GLOBAL opcode stream")

        assert scanner._probe_detected_format(probe) is None

    def test_extensionless_probe_without_header_is_not_scanned(
        self,
        scanner: SevenZipScanner,
        tmp_path: Path,
    ) -> None:
        """Extensionless members without captured archive headers should be ignored."""
        archive_path = tmp_path / "empty_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_scan_extracted_file") as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                if factory is not None:
                    factory.create("nested_payload").write(b"")

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested_payload"]
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16, is_directory=False, is_symlink=False)
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            assert result.success
            assert result.metadata["scannable_files"] == 0
            assert mock_scan_extracted_file.call_count == 0

    def test_extensionless_tar_header_reaches_full_extraction(self, tmp_path: Path) -> None:
        """Header probes should route extensionless TAR members through scanner extraction."""
        scanner = SevenZipScanner()
        archive_path = tmp_path / "tar_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)

        tar_header = bytearray(scanner._NESTED_MEMBER_PROBE_BYTES)
        tar_header[257:262] = b"ustar"

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_has_7z_magic", return_value=True),
            patch.object(scanner, "_scan_extracted_file", return_value=_mock_scan_result()) as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.islink", return_value=False),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                if factory is not None:
                    factory.create("nested_payload").write(bytes(tar_header))

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested_payload"]
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16, is_directory=False, is_symlink=False)
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            assert result.success
            assert result.metadata["scannable_files"] == 1
            mock_scan_extracted_file.assert_called_once()

    def test_extensionless_proto0_pickle_probe_reaches_full_extraction(self, tmp_path: Path) -> None:
        """Header probes should route extensionless protocol-0 pickle members through scanner extraction."""
        scanner = SevenZipScanner()
        archive_path = tmp_path / "proto0_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)
        payload = b"cposix\nsystem\n(S'echo hidden'\ntR."

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_has_7z_magic", return_value=True),
            patch.object(scanner, "_scan_extracted_file", return_value=_mock_scan_result()) as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.islink", return_value=False),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                if factory is not None:
                    factory.create("nested_payload").write(payload)

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested_payload"]
            mock_archive.getinfo.return_value = MagicMock(
                uncompressed=len(payload),
                is_directory=False,
                is_symlink=False,
            )
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            assert result.success
            assert result.metadata["scannable_files"] == 1
            mock_scan_extracted_file.assert_called_once()

    def test_extensionless_xgboost_probe_reaches_full_extraction(self, tmp_path: Path) -> None:
        """Header probes should route extensionless XGBoost UBJSON members through extraction."""
        scanner = SevenZipScanner()
        archive_path = tmp_path / "xgboost_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)
        payload = _xgboost_ubjson_probe()

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_has_7z_magic", return_value=True),
            patch.object(scanner, "_scan_extracted_file", return_value=_mock_scan_result()) as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.islink", return_value=False),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                if factory is not None:
                    factory.create("nested_payload").write(payload)

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested_payload"]
            mock_archive.getinfo.return_value = MagicMock(
                uncompressed=len(payload),
                is_directory=False,
                is_symlink=False,
            )
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

            assert result.success
            assert result.metadata["scannable_files"] == 1
            mock_scan_extracted_file.assert_called_once()

    def test_extensionless_xgboost_incomplete_learner_probe_reaches_full_extraction(self, tmp_path: Path) -> None:
        """7z should preserve an incomplete bounded learner candidate for scanning."""
        scanner = SevenZipScanner()
        archive_path = tmp_path / "late_xgboost_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)
        payload = _xgboost_ubjson_probe(learner_padding=scanner._NESTED_MEMBER_PROBE_BYTES + 32)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_has_7z_magic", return_value=True),
            patch.object(scanner, "_scan_extracted_file", return_value=_mock_scan_result()) as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.islink", return_value=False),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                if factory is not None:
                    factory.create("nested_payload").write(payload)

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested_payload"]
            mock_archive.getinfo.return_value = MagicMock(
                uncompressed=len(payload),
                is_directory=False,
                is_symlink=False,
            )
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

        assert result.success
        assert result.metadata["scannable_files"] == 1
        mock_scan_extracted_file.assert_called_once()

    def test_extensionless_xgboost_incomplete_root_probe_reaches_full_extraction(self, tmp_path: Path) -> None:
        """7z should expand UBJSON roots whose learner begins after the header probe."""
        scanner = SevenZipScanner()
        archive_path = tmp_path / "reordered_xgboost_probe.7z"
        archive_path.write_bytes(scanner._SEVENZIP_MAGIC + b"\0" * 26)
        payload = _xgboost_ubjson_probe(root_padding=scanner._NESTED_MEMBER_PROBE_BYTES + 32)

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
            patch.object(scanner, "_has_7z_magic", return_value=True),
            patch.object(scanner, "_scan_extracted_file", return_value=_mock_scan_result()) as mock_scan_extracted_file,
            patch("os.path.isfile", return_value=True),
            patch("os.path.islink", return_value=False),
            patch("os.path.getsize", return_value=32),
        ):

            def fake_extract(*_args: Any, **kwargs: Any) -> None:
                factory = kwargs.get("factory")
                if factory is not None:
                    factory.create("nested_payload").write(payload)

            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["nested_payload"]
            mock_archive.getinfo.return_value = MagicMock(
                uncompressed=len(payload),
                is_directory=False,
                is_symlink=False,
            )
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(str(archive_path))

        assert result.success
        assert result.metadata["scannable_files"] == 1
        mock_scan_extracted_file.assert_called_once()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_xgboost_late_model_key_in_7z_fails_closed_in_routing(self, tmp_path: Path) -> None:
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(
            _xgboost_ubjson_probe(learner_padding=SevenZipScanner._XGBOOST_NESTED_MEMBER_PROBE_BYTES, malicious=True)
        )
        archive_path = tmp_path / "late_model.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)
        assert not any("System call in JSON" in str(issue.message) for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_disguised_xgboost_late_model_key_in_7z_fails_closed_in_routing(self, tmp_path: Path) -> None:
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(
            _xgboost_ubjson_probe(learner_padding=SevenZipScanner._XGBOOST_NESTED_MEMBER_PROBE_BYTES, malicious=True)
        )
        archive_path = tmp_path / "late_disguised.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model.jpg")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)
        assert not any("System call in JSON" in str(issue.message) for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_xgboost_late_learner_in_7z_fails_closed_in_routing(self, tmp_path: Path) -> None:
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(
            _xgboost_ubjson_probe(root_padding=SevenZipScanner._XGBOOST_NESTED_MEMBER_PROBE_BYTES, malicious=True)
        )
        archive_path = tmp_path / "late_learner.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)
        assert not any("System call in JSON" in str(issue.message) for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_root_noops_before_late_learner_in_7z_fail_closed_in_routing(self, tmp_path: Path) -> None:
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(
            b"{"
            + (b"N" * SevenZipScanner._XGBOOST_NESTED_MEMBER_PROBE_BYTES)
            + _ubjson_key(b"learner")
            + b"{"
            + _ubjson_key(b"learner_model_param")
            + b"{}"
            + b"}"
            + b"}"
        )
        archive_path = tmp_path / "late_noop_learner.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_large_ubjson_manifest_in_7z_fails_closed_without_attribution(self, tmp_path: Path) -> None:
        ubjson = pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(
            ubjson.dumpb(
                {
                    "learner": {
                        "metadata": "x" * SevenZipScanner._XGBOOST_NESTED_MEMBER_PROBE_BYTES,
                        "note": "system(cpu)",
                    },
                    "version": [1],
                }
            )
        )
        archive_path = tmp_path / "manifest.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("routing was inconclusive" in str(issue.message) for issue in result.issues)
        assert not any("System call in JSON" in str(issue.message) for issue in result.issues)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_xgboost_oversized_count_in_7z_fails_closed_before_decode(self, tmp_path: Path) -> None:
        """7z-routed UBJSON members must apply the decoder materialization guard."""
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(_xgboost_ubjson_counted_null_array_probe())
        archive_path = tmp_path / "bundle.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_disguised_xgboost_oversized_count_in_7z_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(_xgboost_ubjson_counted_null_array_probe())
        archive_path = tmp_path / "disguised_limit.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model.dat")

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_xgboost_oversized_uncounted_array_in_7z_fails_closed_before_decode(
        self, tmp_path: Path
    ) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(_xgboost_ubjson_uncounted_null_array_probe(5))
        archive_path = tmp_path / "uncounted.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        with (
            patch.object(XGBoostScanner, "_UBJSON_MAX_DECODED_ARRAY_ITEMS", 4),
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("decoded arrays exceed" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_extensionless_xgboost_deep_container_in_7z_fails_closed_before_decode(self, tmp_path: Path) -> None:
        pytest.importorskip("ubjson", reason="ubjson not installed")
        import py7zr  # type: ignore[import-untyped]

        payload_path = tmp_path / "model"
        payload_path.write_bytes(_xgboost_ubjson_deep_before_counted_null_array_probe())
        archive_path = tmp_path / "deep.7z"
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(payload_path, arcname="models/model")

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            result = scan_model_directory_or_file(str(archive_path), cache_enabled=False)

        assert determine_exit_code(result) == 2
        assert any("resource preflight could not complete" in str(issue.message) for issue in result.issues)
        mock_loadb.assert_not_called()

    # -- default config includes new limits -----------------------------------

    def test_default_configuration_includes_new_limits(self) -> None:
        """New hardening config options must have sensible defaults."""
        scanner = SevenZipScanner()
        assert scanner.max_extensionless_probes == 100
        assert scanner.max_total_extract_size == 5 * 1024 * 1024 * 1024
        assert scanner.max_cumulative_entries == 50000

    def test_custom_configuration_new_limits(self) -> None:
        """New hardening config options must be configurable."""
        config = {
            "max_7z_extensionless_probes": 50,
            "max_7z_total_extract_size": 1024,
            "max_7z_cumulative_entries": 200,
        }
        scanner = SevenZipScanner(config)
        assert scanner.max_extensionless_probes == 50
        assert scanner.max_total_extract_size == 1024
        assert scanner.max_cumulative_entries == 200

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_duplicate_archive_entries_fail_closed(
        self,
        scanner: SevenZipScanner,
        tmp_path: Path,
    ) -> None:
        """Duplicate archive members must be treated as ambiguous and fail closed."""
        safe_pickle = tmp_path / "safe.pkl"
        evil_pickle = tmp_path / "evil.pkl"
        archive_path = tmp_path / "duplicate.7z"

        self._write_pickle(safe_pickle, {"safe": True})

        class MaliciousClass:
            def __reduce__(self) -> tuple[Any, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo duplicate_7z_shadow",))

        self._write_pickle(evil_pickle, MaliciousClass())

        import py7zr  # type: ignore[import-untyped]

        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(str(safe_pickle), "dup.pkl")
            archive.write(str(evil_pickle), "dup.pkl")

        result = scanner.scan(str(archive_path))

        assert result.success is False
        duplicate_checks = [check for check in result.checks if check.name == "7z Duplicate Entry Protection"]
        assert len(duplicate_checks) == 1
        assert duplicate_checks[0].status == CheckStatus.FAILED
        assert duplicate_checks[0].severity == IssueSeverity.WARNING
        assert duplicate_checks[0].details["first_entry"] == "dup.pkl"
        assert duplicate_checks[0].details["entry"] == "dup.pkl"

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_duplicate_archive_entry_aliases_fail_closed(
        self,
        scanner: SevenZipScanner,
        tmp_path: Path,
    ) -> None:
        """Canonical path collisions such as subdir/../dup.pkl must fail closed."""
        safe_pickle = tmp_path / "safe.pkl"
        evil_pickle = tmp_path / "evil.pkl"
        archive_path = tmp_path / "duplicate_alias.7z"

        self._write_pickle(safe_pickle, {"safe": True})

        class MaliciousClass:
            def __reduce__(self) -> tuple[Any, tuple[str]]:
                import os as os_module

                return (os_module.system, ("echo duplicate_alias_7z_shadow",))

        self._write_pickle(evil_pickle, MaliciousClass())

        import py7zr  # type: ignore[import-untyped]

        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(str(safe_pickle), "dup.pkl")
            archive.write(str(evil_pickle), "subdir/../dup.pkl")

        result = scanner.scan(str(archive_path))

        assert result.success is False
        duplicate_checks = [check for check in result.checks if check.name == "7z Duplicate Entry Protection"]
        assert len(duplicate_checks) == 1
        assert duplicate_checks[0].status == CheckStatus.FAILED
        assert duplicate_checks[0].severity == IssueSeverity.WARNING
        assert duplicate_checks[0].details["first_entry"] == "dup.pkl"
        assert duplicate_checks[0].details["entry"] == "subdir/../dup.pkl"


# Integration test that requires actual test assets
class TestSevenZipScannerIntegration:
    """Integration tests using actual test assets (when available)"""

    @pytest.fixture
    def assets_dir(self):
        """Get the test assets directory"""
        return Path(__file__).parent.parent / "assets" / "samples" / "archives"

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available for integration tests")
    def test_scan_sample_archives_if_available(self, assets_dir):
        """Test scanning sample archives if they exist"""
        scanner = SevenZipScanner()

        # Test assets that might be available
        test_archives = ["safe.7z", "malicious.7z", "mixed_content.7z", "empty.7z"]

        for archive_name in test_archives:
            archive_path = assets_dir / archive_name
            if archive_path.exists():
                result = scanner.scan(str(archive_path))
                # Basic assertion - scan should complete
                assert result is not None
                assert hasattr(result, "success")
