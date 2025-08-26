"""
Tests for graceful degradation and error handling in scanner registry.
This module tests the enhanced error handling capabilities implemented in Task 7,
ensuring that missing dependencies disable specific scanners without breaking the tool.
"""

import tempfile
import unittest.mock
from unittest.mock import patch

import pytest

from modelaudit.scanners import SCANNER_REGISTRY, ScannerRegistry, _registry, get_scanner_for_file


@pytest.fixture
def registry_state():
    """Fixture to save and restore registry state for test isolation."""
    # Save original state
    orig_scanners = _registry._scanners.copy()
    orig_loaded = _registry._loaded_scanners.copy()
    orig_failed = _registry._failed_scanners.copy()
    try:
        yield
    finally:
        # Restore original state
        _registry._scanners.clear()
        _registry._scanners.update(orig_scanners)
        _registry._loaded_scanners.clear()
        _registry._loaded_scanners.update(orig_loaded)
        _registry._failed_scanners.clear()
        _registry._failed_scanners.update(orig_failed)


class TestGracefulDegradation:
    """Test graceful degradation when scanners fail to load"""

    def test_missing_dependencies_dont_crash_registry(self):
        """Test that missing dependencies don't crash the scanner registry"""
        # Test with a fresh registry instance to avoid cached scanners
        fresh_registry = ScannerRegistry()

        with patch("importlib.import_module") as mock_import:
            # Simulate ImportError for tensorflow
            def mock_import_side_effect(module_name):
                if "tf_savedmodel_scanner" in module_name:
                    raise ImportError("No module named 'tensorflow'")
                return unittest.mock.MagicMock()

            mock_import.side_effect = mock_import_side_effect

            # Try to load TensorFlow scanner - should fail gracefully
            scanner_class = fresh_registry.load_scanner_by_id("tf_savedmodel")
            assert scanner_class is None

            # Should track the failure
            failed_scanners = fresh_registry.get_failed_scanners()
            assert "tf_savedmodel" in failed_scanners
            assert "tensorflow" in failed_scanners["tf_savedmodel"].lower()

    def test_numpy_compatibility_issues_handled(self):
        """Test that NumPy compatibility issues are handled gracefully"""
        # Use fresh registry to test error handling
        fresh_registry = ScannerRegistry()

        with patch("importlib.import_module") as mock_import:
            # Simulate NumPy compatibility error
            def mock_import_side_effect(module_name):
                if "keras_h5_scanner" in module_name:
                    raise RuntimeError("compiled using numpy 1.x cannot be run in numpy 2")
                return unittest.mock.MagicMock()

            mock_import.side_effect = mock_import_side_effect

            # Try to load scanner - should fail gracefully
            scanner_class = fresh_registry.load_scanner_by_id("keras_h5")
            assert scanner_class is None

            # Should provide helpful error message
            failed_scanners = fresh_registry.get_failed_scanners()
            assert "keras_h5" in failed_scanners
            error_msg = failed_scanners["keras_h5"]
            assert "numpy" in error_msg.lower() or "compatibility" in error_msg.lower()

    def test_core_functionality_works_with_failed_scanners(self):
        """Test that core functionality works even when some scanners fail"""
        # Even with failed scanners, core scanners should still work
        available_scanners = list(SCANNER_REGISTRY)
        assert len(available_scanners) > 0, "Some core scanners should always be available"

        # Core scanners should include pickle scanner at minimum
        scanner_names = [scanner.name for scanner in available_scanners]
        assert "pickle" in scanner_names, "Pickle scanner should always be available"

    def test_helpful_error_messages_for_missing_dependencies(self):
        """Test that error messages provide installation instructions"""
        failed_scanners = _registry.get_failed_scanners()

        for scanner_id, error_msg in failed_scanners.items():
            # Error messages should be helpful
            assert len(error_msg) > 20, f"Error message for {scanner_id} should be descriptive"

            # Should mention pip install if it's a dependency issue
            if "requires dependencies" in error_msg:
                assert "pip install" in error_msg, f"Error for {scanner_id} should include install instructions"
                assert "modelaudit[" in error_msg, f"Error for {scanner_id} should mention extras"

    def test_scanner_summary_provides_diagnostic_info(self):
        """Test that get_available_scanners_summary provides useful diagnostic info"""
        summary = _registry.get_available_scanners_summary()

        # Should contain expected keys
        assert "total_scanners" in summary
        assert "loaded_scanners" in summary
        assert "failed_scanners" in summary
        assert "loaded_scanner_list" in summary
        assert "failed_scanner_details" in summary

        # Values should be sensible
        assert isinstance(summary["total_scanners"], int)
        assert isinstance(summary["loaded_scanners"], int)
        assert isinstance(summary["failed_scanners"], int)
        assert isinstance(summary["loaded_scanner_list"], list)
        assert isinstance(summary["failed_scanner_details"], dict)

        # Total should equal loaded + failed
        assert summary["total_scanners"] == summary["loaded_scanners"] + summary["failed_scanners"]

    def test_get_scanner_for_file_handles_failures(self):
        """Test that get_scanner_for_file works even with some failed scanners"""
        # Create a test pickle file
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test")
            test_file = f.name

        try:
            # Should still be able to get a scanner for pickle files
            scanner = get_scanner_for_file(test_file)
            assert scanner is not None, "Should get a scanner for .pkl files"
            assert scanner.name == "pickle", "Should get the pickle scanner"
        finally:
            import os

            os.unlink(test_file)

    def test_failed_scanner_tracking_thread_safe(self):
        """Test that failed scanner tracking is thread-safe"""
        import threading
        import time

        # Test concurrent access to failed scanners
        results = []
        barrier = threading.Barrier(5)

        def get_failed_scanners():
            barrier.wait()  # Synchronize start
            failed = _registry.get_failed_scanners()
            results.append(id(failed))  # Track object identity
            time.sleep(0.01)  # Small delay to encourage race conditions
            failed2 = _registry.get_failed_scanners()
            results.append(len(failed) == len(failed2))  # Should be consistent

        threads = [threading.Thread(target=get_failed_scanners) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All calls should return consistent results
        consistency_checks = results[5:]  # Second half are consistency checks
        assert all(consistency_checks), "Failed scanner access should be consistent across threads"


class TestErrorHandlingSpecificity:
    """Test that error handling is specific and informative"""

    def test_import_error_vs_attribute_error(self):
        """Test that ImportError and AttributeError are handled differently"""
        # Test that different error types produce different error messages
        # This tests the error handling logic without mocking

        # Check any existing failed scanners for error message patterns
        failed_scanners = _registry.get_failed_scanners()

        # If we have failed scanners, check their error messages are informative
        for scanner_id, error_msg in failed_scanners.items():
            assert len(error_msg) > 10, f"Error message for {scanner_id} should be descriptive"

            # Should either mention dependencies (ImportError) or class not found (AttributeError)
            has_import_info = "dependencies" in error_msg or "import failed" in error_msg or "pip install" in error_msg
            has_attribute_info = "not found" in error_msg or "AttributeError" in error_msg

            assert has_import_info or has_attribute_info, f"Error message should be specific: {error_msg}"

    def test_numpy_compatibility_error_detection(self):
        """Test that NumPy compatibility errors are detected correctly"""
        from modelaudit.scanners import _is_numpy_compatibility_error

        # Test positive cases
        numpy_errors = [
            RuntimeError("compiled using numpy 1.x cannot be run in numpy 2"),
            ImportError("_array_api not found"),
            ValueError("numpy.dtype size changed"),
            Exception("binary incompatibility with numpy"),
        ]

        for error in numpy_errors:
            assert _is_numpy_compatibility_error(error), f"Should detect NumPy error: {error}"

        # Test negative cases
        non_numpy_errors = [
            ImportError("No module named 'tensorflow'"),
            AttributeError("module has no attribute 'Scanner'"),
            ValueError("Invalid configuration"),
        ]

        for error in non_numpy_errors:
            assert not _is_numpy_compatibility_error(error), f"Should not detect as NumPy error: {error}"

    def test_logging_levels_appropriate(self):
        """Test that the error handling system is set up correctly"""
        # This test ensures the logging system is properly configured
        # and that our error handling code paths exist

        # Verify that the registry has proper error tracking
        summary = _registry.get_available_scanners_summary()

        # Should have proper structure for tracking errors
        assert "failed_scanners" in summary
        assert "failed_scanner_details" in summary
        assert isinstance(summary["failed_scanner_details"], dict)

        # Verify the NumPy status system works
        numpy_compatible, numpy_status = _registry.get_numpy_status()
        assert isinstance(numpy_compatible, bool)
        assert isinstance(numpy_status, str)
        assert len(numpy_status) > 0

        # Test that _is_numpy_compatibility_error function exists and works
        from modelaudit.scanners import _is_numpy_compatibility_error

        # Should correctly identify NumPy errors
        test_error = RuntimeError("compiled using numpy 1.x cannot be run in numpy 2")
        assert _is_numpy_compatibility_error(test_error)

        # Should not misidentify regular errors
        test_error = ImportError("No module named 'some_module'")
        assert not _is_numpy_compatibility_error(test_error)


class TestDoctorCommand:
    """Test the enhanced doctor command functionality"""

    def test_doctor_command_provides_comprehensive_info(self, cli_runner):
        """Test that doctor command provides comprehensive diagnostic information"""
        from modelaudit.cli import cli

        result = cli_runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0

        output = result.output
        assert "ModelAudit Scanner Diagnostic Report" in output
        assert "Python version:" in output
        assert "NumPy status:" in output
        assert "Total scanners:" in output
        assert "Loaded successfully:" in output
        assert "Failed to load:" in output

    def test_doctor_command_show_failed_flag(self, cli_runner):
        """Test that doctor --show-failed provides detailed error information"""
        from modelaudit.cli import cli

        result = cli_runner.invoke(cli, ["doctor", "--show-failed"])
        assert result.exit_code == 0

        # If there are failed scanners, they should be shown
        failed_scanners = _registry.get_failed_scanners()
        if failed_scanners:
            for scanner_id in failed_scanners:
                assert scanner_id in result.output, f"Failed scanner {scanner_id} should be shown"

    def test_doctor_recommendations_helpful(self, cli_runner):
        """Test that doctor command provides helpful recommendations"""
        from modelaudit.cli import cli

        result = cli_runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0

        failed_scanners = _registry.get_failed_scanners()
        if failed_scanners:
            # Should provide recommendations
            assert "Recommendations:" in result.output
            assert "pip install" in result.output or "dependencies" in result.output
            assert "Core functionality works" in result.output


@pytest.fixture
def cli_runner():
    """Provide click test runner"""
    from click.testing import CliRunner

    return CliRunner()
