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
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity
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
        assert issue.severity == IssueSeverity.CRITICAL
        assert "py7zr library not installed" in issue.message
        assert "pip install py7zr" in issue.message

    @patch("modelaudit.scanners.sevenzip_scanner.HAS_PY7ZR", False)
    def test_scan_mocked_unavailable(self, scanner, temp_7z_file):
        """Test scan behavior when py7zr is mocked as unavailable"""
        result = scanner.scan(temp_7z_file)

        assert not result.success
        assert len(result.issues) == 1

        issue = result.issues[0]
        assert issue.severity == IssueSeverity.CRITICAL
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

    def test_identify_scannable_files(self, scanner):
        """Test identification of scannable files"""
        test_files = [
            "model.pkl",  # Scannable
            "weights.pt",  # Scannable
            "model.bin",  # Scannable
            "config.json",  # Scannable
            "readme.txt",  # Not scannable
            "image.png",  # Not scannable
            "data.csv",  # Not scannable
        ]

        scannable = scanner._identify_scannable_files(test_files)

        expected_scannable = ["model.pkl", "weights.pt", "model.bin", "config.json"]
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

        assert scanner.max_entries == 10000
        assert scanner.max_extract_size == 1024 * 1024 * 1024  # 1GB

    def test_custom_configuration(self):
        """Test custom scanner configuration"""
        config = {
            "max_7z_entries": 5000,
            "max_7z_extract_size": 512 * 1024 * 1024,  # 512MB
        }
        scanner = SevenZipScanner(config)

        assert scanner.max_entries == 5000
        assert scanner.max_extract_size == 512 * 1024 * 1024

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
