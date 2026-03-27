"""
Test suite for SevenZipScanner

Tests the 7-Zip archive scanning functionality including:
- Basic format detection and scanning
- Security issue detection in contained files
- Error handling for missing dependencies
- Path traversal protection
- Large archive handling
"""

import os
import pickle
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.sevenzip_scanner import HAS_PY7ZR, SevenZipScanner

# Skip all tests if py7zr is not available for asset generation
pytest_plugins: list[str] = []


class TestSevenZipScanner:
    """Test suite for SevenZipScanner functionality"""

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
        # Missing optional dependency is a WARNING, not CRITICAL
        assert issue.severity == IssueSeverity.WARNING
        assert "py7zr library not installed" in issue.message
        assert "pip install py7zr" in issue.message

    @patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", False)
    def test_scan_mocked_unavailable(self, scanner, temp_7z_file):
        """Test scan behavior when py7zr is mocked as unavailable"""
        result = scanner.scan(temp_7z_file)

        assert not result.success
        assert len(result.issues) == 1

        issue = result.issues[0]
        # Missing optional dependency is a WARNING, not CRITICAL
        assert issue.severity == IssueSeverity.WARNING
        assert "py7zr library not installed" in issue.message

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

            # Mock the scanner registry to return a mock scanner
            with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
                mock_scanner = MagicMock()
                mock_result = MagicMock()
                mock_result.issues = []
                mock_result.checks = []
                mock_result.metadata = {}
                mock_scanner.scan.return_value = mock_result
                mock_get_scanner.return_value = mock_scanner

                result = scanner.scan(temp_7z_file)

                assert result.success
                assert result.metadata["total_files"] == 1
                assert result.metadata["scannable_files"] == 1

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_scan_malicious_archive(self, scanner, temp_7z_file):
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

            # Mock the scanner registry to return a scanner that finds issues
            with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
                mock_scanner = MagicMock()
                mock_result = MagicMock()

                # Create mock issue for malicious content
                mock_issue = MagicMock()
                mock_issue.message = "Malicious eval detected"
                mock_issue.location = "extracted_file"
                mock_issue.details = {}
                mock_result.issues = [mock_issue]
                mock_result.checks = []
                mock_result.metadata = {}

                mock_scanner.scan.return_value = mock_result
                mock_get_scanner.return_value = mock_scanner

                result = scanner.scan(temp_7z_file)

                assert result.success  # Scan completes successfully
                assert len(result.issues) > 0  # But issues are found

                # Check that location was adjusted for archive context
                for issue in result.issues:
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

            with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
                mock_scanner = MagicMock()
                mock_issue = MagicMock()
                mock_issue.message = "Nested pickle scanned"
                mock_issue.location = "pickle_scan"
                mock_issue.details = {}

                mock_result = MagicMock()
                mock_result.issues = [mock_issue]
                mock_result.checks = []
                mock_result.metadata = {}
                mock_scanner.scan.return_value = mock_result
                mock_get_scanner.return_value = mock_scanner

                result = scanner.scan(temp_7z_file)

            assert result.success
            mock_scanner.scan.assert_called_once()
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
            assert result.success
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

            depth_issues = [issue for issue in result.issues if "maximum 7z nesting depth" in issue.message.lower()]
            assert len(depth_issues) == 1
            assert depth_issues[0].severity == IssueSeverity.WARNING

        finally:
            for archive_path in archive_paths:
                if archive_path.exists():
                    archive_path.unlink()

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
            "weights.pt",  # Scannable
            "model.bin",  # Scannable
            "config.json",  # Scannable
            "readme.txt",  # Not scannable
            "image.png",  # Not scannable
            "data.csv",  # Not scannable
        ]

        scannable = scanner._identify_scannable_files(test_files)

        expected_scannable = ["nested.7z", "model.pkl", "weights.pt", "model.bin", "config.json"]
        assert set(scannable) == set(expected_scannable)

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr not available")
    def test_path_traversal_detection(self, scanner, temp_7z_file):
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
            traversal_issues = [i for i in result.issues if "path traversal" in i.message.lower()]
            assert len(traversal_issues) > 0

            issue = traversal_issues[0]
            assert issue.severity == IssueSeverity.CRITICAL
            assert "dangerous.pkl" in issue.location

        finally:
            if os.path.exists(temp_pickle_path):
                os.unlink(temp_pickle_path)

    def test_unsafe_entries_are_excluded_from_extraction_targets(self, scanner, temp_7z_file):
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
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert result.metadata["total_files"] == 3
            assert result.metadata["unsafe_entries"] == 1
            assert result.metadata["scannable_files"] == 1
            mock_archive.extract.assert_called_once()
            assert mock_archive.extract.call_args.kwargs["targets"] == ["safe.pkl"]

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
                uncompressed=1000 if name == "large_file.pkl" else 10
            )
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            large_file_issues = [i for i in result.issues if "too large" in i.message]
            assert len(large_file_issues) == 1
            assert large_file_issues[0].details["extracted_size"] == 1000
            mock_archive.extract.assert_called_once()
            assert mock_archive.extract.call_args.kwargs["targets"] == ["safe.pkl"]
            mock_scan_extracted_file.assert_called_once()

    def test_extensionless_non_7z_members_are_filtered_before_full_extraction(
        self,
        scanner: SevenZipScanner,
        temp_7z_file: str,
    ) -> None:
        """Only header-confirmed extensionless members should reach the full extraction pass."""
        extensionless_members = [f"asset_{index:03d}" for index in range(32)]

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
            mock_archive.getinfo.side_effect = lambda _name: MagicMock(uncompressed=16, is_directory=False)
            mock_archive.extract.side_effect = fake_extract
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert result.success
            assert mock_archive.reset.call_count == 1
            assert mock_archive.extract.call_count == 2
            assert mock_archive.extract.call_args_list[0].kwargs["targets"] == [
                "nested_archive",
                *extensionless_members,
            ]
            assert "factory" in mock_archive.extract.call_args_list[0].kwargs
            assert mock_archive.extract.call_args_list[1].kwargs["targets"] == ["safe.pkl", "nested_archive"]
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

            # Mock scanner that returns no issues
            with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
                mock_scanner = MagicMock()
                mock_result = MagicMock()
                mock_result.issues = []
                mock_result.checks = []
                mock_result.metadata = {}
                mock_scanner.scan.return_value = mock_result
                mock_get_scanner.return_value = mock_scanner

                result = scanner.scan(temp_7z_file)

                assert result.success
                assert result.metadata["total_files"] == 3
                assert result.metadata["scannable_files"] == 2  # .pkl and .json files

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

    def test_scan_with_extraction_error(self, scanner, temp_7z_file):
        """Test behavior when file extraction fails"""
        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["test.pkl"]
            mock_archive.extract.side_effect = Exception("Extraction failed")
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            # Should handle extraction errors gracefully
            # With batch extraction, errors are caught at archive level
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

            with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
                mock_scanner = MagicMock()
                mock_result = MagicMock()
                mock_result.issues = []
                mock_result.checks = []
                mock_result.metadata = {}
                mock_scanner.scan.return_value = mock_result
                mock_get_scanner.return_value = mock_scanner

                result = scanner.scan(temp_7z_file)

            assert result.success
            assert result.metadata["total_files"] == 1
            assert result.metadata["scannable_files"] == 1
            mock_scanner.scan.assert_called_once()
            extracted_path = mock_scanner.scan.call_args.args[0]
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

        expected = {"nested.7z", "model.pkl", "weights.pt", "model.onnx", "config.json", "tokenizer.bin"}
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
            patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner,
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["safe.pkl"]
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.issues = []
            mock_result.checks = []
            mock_result.metadata = {}
            mock_scanner.scan.return_value = mock_result
            mock_get_scanner.return_value = mock_scanner

            result = scanner.scan(temp_7z_file)

            assert result.success
            mock_get_scanner.assert_called_once()
            assert mock_get_scanner.call_args.kwargs["config"] == scanner.config
            mock_scanner.scan.assert_called_once_with(mock_get_scanner.call_args.args[0])

    def test_large_extracted_file_handling(self, scanner, temp_7z_file):
        """Test handling of files that are too large after extraction"""
        scanner.max_extract_size = 100  # Very small limit for testing

        with (
            patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", True),
            patch("modelaudit.scanners.sevenzip_scanner.py7zr") as mock_py7zr,
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = ["large_file.pkl"]
            mock_archive.extract = MagicMock()
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            # Mock os.path.isfile and os.path.getsize
            with (
                patch("os.path.isfile", return_value=True),
                patch("os.path.getsize", return_value=1000),  # Larger than limit
            ):
                result = scanner.scan(temp_7z_file)

                # Should warn about large file
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
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive
            mock_islink.return_value = True

            result = scanner.scan(temp_7z_file)

            symlink_checks = [c for c in result.checks if "Symlink" in c.name]
            assert len(symlink_checks) == 1
            assert symlink_checks[0].status == CheckStatus.FAILED
            assert symlink_checks[0].severity == IssueSeverity.CRITICAL
            assert symlink_checks[0].details["symlink_target"] == str(symlink_target)

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
            patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner,
        ):
            result = scanner.scan(temp_7z_file)

        symlink_issues = [c for c in result.checks if "Symlink" in c.name]
        assert len(symlink_issues) == 1
        assert symlink_issues[0].severity == IssueSeverity.CRITICAL
        assert symlink_issues[0].details["symlink_target"] == str(symlink_target)
        mock_get_scanner.assert_not_called()

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
                return_value=dict.fromkeys(extensionless_members[:3], False),
            ) as mock_probe,
            patch("os.path.getsize", return_value=32),
        ):
            mock_archive = MagicMock()
            mock_archive.getnames.return_value = extensionless_members
            mock_archive.getinfo.return_value = MagicMock(is_directory=False, uncompressed=16)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            assert mock_probe.call_count == 1
            assert mock_probe.call_args.args[1] == extensionless_members[:3]
            limit_checks = [c for c in result.checks if "Probe Limit" in c.name]
            assert len(limit_checks) == 1
            assert limit_checks[0].status == CheckStatus.FAILED

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

        with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
            mock_scanner = MagicMock()
            mock_result = ScanResult(scanner_name="mock")
            mock_result.finish(success=True)
            mock_scanner.scan.return_value = mock_result
            mock_get_scanner.return_value = mock_scanner

            result = scanner.scan(str(outer_path))

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Entry Limit"]
        assert len(cumulative_checks) == 1
        assert not result.success
        assert cumulative_checks[0].severity == IssueSeverity.CRITICAL
        assert cumulative_checks[0].details["cumulative_entries"] == 4
        assert cumulative_checks[0].location is not None
        assert f"{outer_path}:nested.7z" in cumulative_checks[0].location
        mock_get_scanner.assert_not_called()

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

        with patch("modelaudit.scanners.get_scanner_for_file") as mock_get_scanner:
            mock_scanner = MagicMock()
            mock_result = ScanResult(scanner_name="mock")
            mock_result.finish(success=True)
            mock_scanner.scan.return_value = mock_result
            mock_get_scanner.return_value = mock_scanner

            result = scanner.scan(str(outer_path))

        cumulative_checks = [c for c in result.checks if c.name == "Cumulative Extraction Size"]
        assert len(cumulative_checks) == 1
        assert not result.success
        assert cumulative_checks[0].severity == IssueSeverity.CRITICAL
        assert cumulative_checks[0].details["limit"] == limit
        assert mock_scanner.scan.call_count == 1
        scanned_file = Path(mock_scanner.scan.call_args.args[0])
        assert scanned_file.name == "inner_a.pkl"

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
            mock_archive.getinfo.return_value = MagicMock(uncompressed=16, is_directory=False)
            mock_py7zr.SevenZipFile.return_value.__enter__.return_value = mock_archive

            result = scanner.scan(temp_7z_file)

            # The inner result should have end_time set via finish()
            # Verify through checking the depth bomb check exists and result is usable
            depth_checks = [c for c in result.checks if "Depth Bomb" in c.name and c.status == CheckStatus.FAILED]
            assert len(depth_checks) >= 1
            assert result.metadata.get("file_size") is not None

    # -- _HeaderProbeBuffer empty write guard ---------------------------------

    def test_header_probe_buffer_empty_write_returns_zero(self) -> None:
        """_HeaderProbeBuffer.write(b'') must return 0 without looping."""
        from modelaudit.scanners.sevenzip_scanner import _HeaderProbeBuffer

        buf = _HeaderProbeBuffer(limit=6)
        assert buf.write(b"") == 0
        assert buf.size() == 0

    def test_header_probe_buffer_normal_flow(self) -> None:
        """_HeaderProbeBuffer should capture up to limit bytes then raise."""
        from modelaudit.scanners.sevenzip_scanner import (
            _HeaderProbeBuffer,
            _HeaderProbeComplete,
        )

        buf = _HeaderProbeBuffer(limit=6)
        buf.write(b"\x37\x7a")  # 2 bytes
        assert buf.size() == 2
        with pytest.raises(_HeaderProbeComplete):
            buf.write(b"\xbc\xaf\x27\x1c\x00\x00")  # 8 bytes, only 4 more captured
        buf.seek(0)
        assert buf.read(6) == b"\x37\x7a\xbc\xaf\x27\x1c"

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
