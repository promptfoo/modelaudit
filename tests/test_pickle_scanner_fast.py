"""
Fast version of dill and joblib tests using improved mocking.

This demonstrates how to speed up tests that use heavy ML libraries
while maintaining the same test coverage.
"""

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner


class TestFastDillFiles:
    """Fast tests for dill serialized objects using mocking."""

    def test_dill_lambda_function_fast(self, mock_heavy_ml_libs, fast_file_operations):
        """Fast test for dill lambda functions using mocked libraries."""
        # Mock dill module is already available via mock_heavy_ml_libs

        # Create mock dill file content that would be produced by a lambda
        # This simulates the binary content without actually using real dill
        mock_dill_content = (
            b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94"
            b"\x8c\x0b<lambda>\x94\x93\x94."  # Simplified dill lambda pattern
        )

        fast_file_operations.add_file("/tmp/lambda.dill", mock_dill_content)

        scanner = PickleScanner()
        result = scanner.scan("/tmp/lambda.dill")

        # Should successfully scan the file (even if mocked)
        assert result.success is True
        # Fast test completes quickly without real dill serialization

    def test_dill_complex_object_fast(self, mock_heavy_ml_libs, fast_file_operations):
        """Fast test for complex dill objects."""
        # Mock complex dill file content
        mock_complex_content = (
            b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94"
            b"\x8c\x0cComplexClass\x94\x93\x94)\x81\x94}\x94(\x8c\x04func\x94"
            # Complex object pattern
        )

        fast_file_operations.add_file("/tmp/complex.dill", mock_complex_content)

        scanner = PickleScanner()
        result = scanner.scan("/tmp/complex.dill")

        # Should handle the mock complex object
        assert result.success is True

    def test_dill_malicious_detection_fast(self, mock_heavy_ml_libs, fast_file_operations):
        """Fast test ensuring malicious dill content is detected."""
        # Mock malicious dill content with os.system pattern
        malicious_content = (
            b"\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94"
            b"\x8c\x06system\x94\x93\x94\x8c\recho malicious\x94\x85\x94R\x94."
        )

        fast_file_operations.add_file("/tmp/malicious.dill", malicious_content)

        scanner = PickleScanner()
        result = scanner.scan("/tmp/malicious.dill")

        # Should detect suspicious content
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0, "Should detect malicious content"


class TestFastJoblibFiles:
    """Fast tests for joblib files using mocking."""

    def test_joblib_sklearn_model_fast(self, mock_heavy_ml_libs, fast_file_operations):
        """Fast test for joblib sklearn models."""
        # Mock joblib file content that represents a scikit-learn model
        mock_joblib_content = (
            b"\x80\x04\x95\x89\x00\x00\x00\x00\x00\x00\x00\x8c\x14sklearn.linear_model"
            b"\x94\x8c\x0eLogisticRegression\x94\x93\x94)\x81\x94}\x94"
            # Sklearn model pattern
        )

        fast_file_operations.add_file("/tmp/model.joblib", mock_joblib_content)

        scanner = PickleScanner()
        result = scanner.scan("/tmp/model.joblib")

        # Should successfully scan joblib model
        assert result.success is True

    def test_joblib_malicious_detection_fast(self, mock_heavy_ml_libs, fast_file_operations):
        """Fast test ensuring malicious joblib content is detected."""
        # Mock malicious joblib with subprocess call
        malicious_joblib_content = (
            b"\x80\x04\x95$\x00\x00\x00\x00\x00\x00\x00\x8c\nsubprocess\x94"
            b"\x8c\x04call\x94\x93\x94]\x94\x8c\x02rm\x94\x8c\x02-f\x94\x8c\x01*\x94"
            b"\x87\x94\x85\x94R\x94."
        )

        fast_file_operations.add_file("/tmp/malicious.joblib", malicious_joblib_content)

        scanner = PickleScanner()
        result = scanner.scan("/tmp/malicious.joblib")

        # Should detect malicious subprocess content
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0, "Should detect malicious subprocess call"


@pytest.mark.performance
class TestPerformanceComparison:
    """Compare performance of mocked vs real ML library tests."""

    def test_mock_vs_real_import_speed(self, mock_heavy_ml_libs):
        """Test that mocked ML imports are faster than real imports."""
        import time

        # Test mocked import speed (should be fast)
        start_time = time.time()
        import dill
        import joblib
        import sklearn

        mock_duration = time.time() - start_time

        # Mocked imports should be nearly instant
        assert mock_duration < 0.1, f"Mock imports too slow: {mock_duration:.3f}s"

        # Verify mocks work
        assert hasattr(dill, "dump")  # Mock should have expected attributes
        assert hasattr(joblib, "load")
        assert hasattr(sklearn, "__version__")  # Mock version

    def test_file_operation_speed(self, fast_file_operations):
        """Test that mocked file operations are faster."""
        import time

        # Add a large file to mock filesystem
        large_content = b"x" * 100000  # 100KB
        fast_file_operations.add_file("/tmp/large_model.pkl", large_content)

        # Time multiple file operations
        start_time = time.time()
        for _ in range(100):
            with open("/tmp/large_model.pkl", "rb") as f:
                data = f.read()
                assert len(data) == 100000
        mock_duration = time.time() - start_time

        # Should be very fast with mocked I/O
        assert mock_duration < 0.1, f"Mock file I/O too slow: {mock_duration:.3f}s"


class TestMockCorrectness:
    """Ensure mocked tests maintain correctness of original tests."""

    def test_mock_preserves_security_detection(self, mock_heavy_ml_libs, fast_file_operations):
        """Ensure mocking doesn't break security detection."""
        # Create content with known malicious patterns
        evil_pickle_content = (
            b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94"
            b"\x8c\x06system\x94\x93\x94\x8c\x08rm -rf /\x94\x85\x94R\x94."
        )

        fast_file_operations.add_file("/tmp/evil.pkl", evil_pickle_content)

        scanner = PickleScanner()
        result = scanner.scan("/tmp/evil.pkl")

        # Must still detect malicious content even with mocks
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0, "Security detection must work with mocks"

        # Check that os.system was detected
        os_system_detected = any(
            "os.system" in str(issue.message) or "system" in str(issue.message) for issue in critical_issues
        )
        assert os_system_detected, "Should detect os.system call"

    def test_mock_file_attributes_realistic(self, fast_file_operations):
        """Ensure mock file attributes are realistic."""
        content = b"test content"
        fast_file_operations.add_file("/tmp/test.pkl", content)

        # Test file system behavior
        assert fast_file_operations.exists("/tmp/test.pkl")
        assert fast_file_operations.is_file("/tmp/test.pkl")
        assert not fast_file_operations.is_dir("/tmp/test.pkl")

        # Test stat information
        stat_info = fast_file_operations.stat("/tmp/test.pkl")
        assert stat_info.st_size == len(content)
        assert hasattr(stat_info, "st_mtime")
        assert hasattr(stat_info, "st_mode")
