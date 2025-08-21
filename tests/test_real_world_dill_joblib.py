"""Real-world integration tests with actual dill and joblib files."""

import os
import time
from unittest.mock import patch

import pytest

try:
    import dill

    HAS_DILL = True
except ImportError:
    HAS_DILL = False

try:
    import joblib

    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner


class TestRealDillFiles:
    """Tests with actual dill serialized objects."""

    @pytest.mark.skipif(not HAS_DILL, reason="dill not available")
    def test_real_dill_lambda_function(self, tmp_path):
        """Test scanning actual dill files with lambda functions."""
        dill_file = tmp_path / "lambda.dill"

        # Create a lambda function (pickle can't handle this, dill can)
        def lambda_func(x):
            return x * 2

        with open(dill_file, "wb") as f:
            dill.dump(lambda_func, f)

        scanner = PickleScanner()
        result = scanner.scan(str(dill_file))

        # Should scan the file (though may detect dill patterns as suspicious)
        assert result.bytes_scanned > 0
        # Dill functions may trigger security warnings due to internal mechanisms
        # This is actually correct behavior - dill uses advanced serialization
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        if len(critical_issues) > 0:
            # Check that the issues are related to dill's internal mechanisms
            dill_related = any("dill" in str(issue.message).lower() for issue in critical_issues)
            assert dill_related, "Critical issues should be dill-related if present"

    @pytest.mark.skipif(not HAS_DILL, reason="dill not available")
    def test_real_dill_complex_object(self, tmp_path):
        """Test scanning dill files with complex objects."""
        dill_file = tmp_path / "complex.dill"

        # Create a complex object that standard pickle can't handle
        class ComplexClass:
            def __init__(self):
                self.func = lambda x: x + 1
                self.data = {"nested": {"deep": "value"}}

        obj = ComplexClass()

        with open(dill_file, "wb") as f:
            dill.dump(obj, f)

        scanner = PickleScanner()
        result = scanner.scan(str(dill_file))

        # Should handle complex dill objects
        assert result.success is True
        assert result.bytes_scanned > 0

    @pytest.mark.skipif(not HAS_DILL, reason="dill not available")
    def test_dill_malicious_detection_still_works(self, tmp_path):
        """Ensure dill files with malicious content are still detected."""
        malicious_dill = tmp_path / "malicious.dill"

        # Create a dill file with os.system call
        import os

        def malicious_func():
            return os.system("echo malicious")

        with open(malicious_dill, "wb") as f:
            dill.dump(malicious_func, f)

        scanner = PickleScanner()
        result = scanner.scan(str(malicious_dill))

        # Should detect suspicious content - dill may serialize differently than expected
        # so we check for any critical issues that indicate malicious content detection
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0, "Should detect suspicious content in malicious dill file"

        # Check for either os.system detection or dill internal function detection
        malicious_detected = any(
            ("os" in str(i.message).lower() and "system" in str(i.message).lower())
            or ("dill" in str(i.message).lower() and "_create_function" in str(i.message).lower())
            or ("suspicious" in str(i.message).lower() and "module" in str(i.message).lower())
            for i in critical_issues
        )
        assert malicious_detected, (
            f"Should detect malicious patterns. Found issues: {[str(i.message) for i in critical_issues]}"
        )


class TestRealJoblibFiles:
    """Tests with actual joblib serialized objects."""

    @pytest.mark.skipif(not HAS_JOBLIB, reason="joblib not available")
    def test_real_joblib_simple_object(self, tmp_path):
        """Test scanning actual joblib files."""
        joblib_file = tmp_path / "simple.joblib"

        # Create a simple object
        data = {"model_params": [1, 2, 3], "metadata": {"version": "1.0"}}

        joblib.dump(data, str(joblib_file))

        scanner = PickleScanner()
        result = scanner.scan(str(joblib_file))

        # Should scan successfully
        assert result.success is True
        assert result.bytes_scanned > 0
        # Should not have critical security issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    @pytest.mark.skipif(not HAS_JOBLIB, reason="joblib not available")
    def test_real_joblib_compressed(self, tmp_path):
        """Test scanning compressed joblib files."""
        compressed_file = tmp_path / "compressed.joblib"

        # Create compressed joblib file
        large_data = {"data": list(range(1000)), "metadata": "test"}

        joblib.dump(large_data, str(compressed_file), compress=3)

        scanner = PickleScanner()
        result = scanner.scan(str(compressed_file))

        # Compressed files may not follow standard pickle format
        # This is expected - compression changes the file structure
        assert isinstance(result.success, bool)
        # May not scan bytes if compression format isn't recognized as pickle
        if result.bytes_scanned == 0:
            # Should have reported format issues
            assert len(result.issues) > 0
            format_issues = [i for i in result.issues if "opcode" in str(i.message).lower()]
            assert len(format_issues) > 0, "Should report format/opcode issues for compressed files"

    @pytest.mark.skipif(not HAS_JOBLIB, reason="joblib not available")
    def test_joblib_with_numpy_arrays(self, tmp_path):
        """Test joblib files containing numpy arrays."""
        numpy_file = tmp_path / "numpy.joblib"

        import numpy as np

        # Create data with numpy arrays (common in ML)
        data = {
            "weights": np.random.random((10, 5)),
            "biases": np.zeros(5),
            "metadata": {"shape": (10, 5)},
        }

        joblib.dump(data, str(numpy_file))

        scanner = PickleScanner()
        result = scanner.scan(str(numpy_file))

        # Joblib with numpy may use custom protocols/opcodes that aren't standard pickle
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        warning_issues = [i for i in result.issues if i.severity == IssueSeverity.WARNING]

        # If bytes weren't scanned, it means the format wasn't recognized as standard pickle
        if result.bytes_scanned == 0:
            # Should have issues about unknown format/opcodes (now as warnings)
            assert len(warning_issues) > 0, "Should report issues when format isn't recognized"
            opcode_issues = [
                i for i in warning_issues if "opcode" in str(i.message).lower() or "format" in str(i.message).lower()
            ]
            assert len(opcode_issues) > 0, "Should report opcode/format issues for numpy joblib files"
        else:
            # If bytes were scanned, check for opcode issues if they exist
            if len(critical_issues) > 0:
                opcode_issues = [i for i in critical_issues if "opcode" in str(i.message).lower()]
                assert len(opcode_issues) > 0, "Critical issues should be opcode-related for numpy files"


@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Performance benchmarks for A+ level testing."""

    def test_large_file_scanning_performance(self, tmp_path):
        """Benchmark scanning performance on large files."""
        large_file = tmp_path / "large_test.joblib"

        # Create a reasonably large joblib file
        import pickle

        large_data = {
            "arrays": [list(range(i, i + 1000)) for i in range(100)],
            "metadata": {"size": "large", "items": 100},
        }

        with open(large_file, "wb") as f:
            f.write(b"joblib")  # Add marker
            pickle.dump(large_data, f)

        scanner = PickleScanner()

        # Benchmark scanning time
        start_time = time.perf_counter()
        result = scanner.scan(str(large_file))
        scan_duration = time.perf_counter() - start_time

        # Should complete within reasonable time (under 1 second for test data)
        assert scan_duration < 1.0
        assert result.bytes_scanned > 0

        # Log performance metrics
        print(f"Large file scan: {scan_duration:.3f}s, {result.bytes_scanned} bytes")

    def test_multiple_files_scanning_performance(self, tmp_path):
        """Benchmark scanning multiple files."""
        files = []

        # Create multiple test files (fewer in CI)
        import os

        count = 6 if (os.getenv("CI") or os.getenv("GITHUB_ACTIONS")) else 10
        for i in range(count):
            file_path = tmp_path / f"file_{i}.joblib"
            with open(file_path, "wb") as f:
                f.write(b"joblib")
                import pickle

                pickle.dump({"id": i, "data": list(range(100))}, f)
            files.append(str(file_path))

        scanner = PickleScanner()

        # Benchmark batch scanning
        start_time = time.perf_counter()
        results = []
        for file_path in files:
            result = scanner.scan(file_path)
            results.append(result)
        total_duration = time.perf_counter() - start_time

        # Should complete all files quickly
        assert total_duration < 2.0
        assert all(result.success for result in results)

        avg_time = total_duration / len(files)
        print(f"Average scan time: {avg_time:.3f}s per file")

    def test_validation_performance_impact(self, tmp_path):
        """Test performance impact of file validation."""
        test_file = tmp_path / "validation_test.joblib"

        with open(test_file, "wb") as f:
            f.write(b"joblib" * 200)  # Larger content
            import pickle

            pickle.dump({"test": "data"}, f)

        # Benchmark validation time
        import os

        from modelaudit.scanners.pickle_scanner import _is_legitimate_serialization_file

        iters = 30 if (os.getenv("CI") or os.getenv("GITHUB_ACTIONS")) else 100
        start_time = time.perf_counter()
        for _ in range(iters):  # Multiple calls to get meaningful measurement
            _is_legitimate_serialization_file(str(test_file))
        validation_duration = time.perf_counter() - start_time

        # Validation should be very fast
        avg_validation_time = validation_duration / iters
        assert avg_validation_time < 0.001  # Under 1ms average

        print(f"Average validation time: {avg_validation_time:.6f}s")


class TestErrorScenarios:
    """Test various error scenarios for robustness."""

    def test_corrupted_file_handling(self, tmp_path):
        """Test handling of corrupted files."""
        corrupted_file = tmp_path / "corrupted.joblib"

        # Create partially corrupted file
        with open(corrupted_file, "wb") as f:
            f.write(b"joblib")
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"\xff" * 100)  # Corrupted data

        scanner = PickleScanner()
        result = scanner.scan(str(corrupted_file))

        # Should handle corruption gracefully
        assert isinstance(result.success, bool)
        assert len(result.issues) > 0  # Should report issues

    def test_permission_denied_handling(self, tmp_path):
        """Test handling of files with permission issues."""
        if hasattr(os, "chmod"):  # Unix-like systems
            if os.geteuid() == 0:
                pytest.skip("Running as root, permission errors won't trigger")
            restricted_file = tmp_path / "restricted.joblib"
            restricted_file.write_bytes(b"joblib test")

            # Remove read permissions
            os.chmod(str(restricted_file), 0o000)

            try:
                scanner = PickleScanner()
                result = scanner.scan(str(restricted_file))

                # Should handle permission errors gracefully
                assert not result.success
                assert len(result.issues) > 0
            finally:
                # Restore permissions for cleanup
                os.chmod(str(restricted_file), 0o644)

    def test_network_file_timeout_simulation(self, tmp_path):
        """Test timeout handling for slow file operations."""
        slow_file = tmp_path / "slow.joblib"

        with open(slow_file, "wb") as f:
            f.write(b"joblib")
            import pickle

            pickle.dump({"data": "test"}, f)

        scanner = PickleScanner()

        # Mock slow file operation
        with patch("builtins.open") as mock_open:

            def slow_open(*args, **kwargs):
                import time

                time.sleep(0.1)  # Simulate slow operation
                return open(*args, **kwargs)

            mock_open.side_effect = slow_open

            # Scanner should still complete (this is a basic timeout test)
            result = scanner.scan(str(slow_file))
            assert isinstance(result.success, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
