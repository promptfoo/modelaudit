"""
Comprehensive test suite for CVE-specific detection in ModelAudit.

This module tests detection of:
- CVE-2020-13092: scikit-learn joblib.load deserialization vulnerability
- CVE-2024-34997: joblib NumpyArrayWrapper deserialization vulnerability

Test categories:
1. Positive detection tests (should detect vulnerabilities)
2. False positive prevention (should not flag legitimate models)
3. Integration tests (end-to-end CVE detection)
4. Pattern validation tests
"""

import pickle

import pytest

from modelaudit.core import scan_file
from modelaudit.cve_patterns import analyze_cve_patterns
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.joblib_scanner import JoblibScanner
from modelaudit.scanners.pickle_scanner import PickleScanner


class TestCVE202013092Detection:
    """Test detection of CVE-2020-13092 (scikit-learn joblib.load vulnerability)."""

    def test_detect_cve_2020_13092_basic_pattern(self, tmp_path):
        """Test basic detection of CVE-2020-13092 patterns."""
        # Create a malicious pickle that simulates sklearn model with os.system
        malicious_content = b"""
        joblib.load
        sklearn.ensemble.RandomForestClassifier
        __reduce__
        os.system
        """

        test_file = tmp_path / "malicious_sklearn.pkl"
        test_file.write_bytes(malicious_content)

        result = scan_file(str(test_file))

        # Should detect CVE-2020-13092 patterns
        cve_detections = [
            issue
            for issue in result.issues
            if "CVE-2020-13092" in issue.message or "CVE-2020-13092" in str(issue.details)
        ]

        assert len(cve_detections) > 0, (
            f"Should detect CVE-2020-13092. Issues found: {[i.message for i in result.issues]}"
        )

        # Verify CVE details are present
        cve_issue = cve_detections[0]
        assert cve_issue.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
        assert "sklearn" in cve_issue.message.lower() or "sklearn" in str(cve_issue.details).lower()

    def test_detect_cve_2020_13092_joblib_with_system_call(self, tmp_path):
        """Test detection of joblib.load combined with system calls."""
        # Create a pickle that contains joblib.load and os.system patterns
        malicious_code = """
        import joblib
        import os
        model = joblib.load('model.pkl')
        os.system('echo pwned')
        """

        pickle_data = pickle.dumps({"code": malicious_code})

        test_file = tmp_path / "joblib_system.pkl"
        test_file.write_bytes(pickle_data)

        result = scan_file(str(test_file))

        # Should detect both joblib.load and os.system patterns
        assert any(
            "joblib" in issue.message.lower() or "joblib" in str(issue.details).lower() for issue in result.issues
        ), "Should detect joblib patterns"

        assert any(
            "os.system" in issue.message.lower() or "system" in issue.message.lower() for issue in result.issues
        ), "Should detect system call patterns"

    def test_detect_cve_2020_13092_sklearn_pipeline_attack(self, tmp_path):
        """Test detection of malicious sklearn Pipeline with __reduce__ method."""
        # Simulate a malicious sklearn Pipeline with __reduce__ calling os.system
        malicious_content = b"""
        sklearn.pipeline.Pipeline
        __reduce__
        os.system
        subprocess.call
        """

        test_file = tmp_path / "malicious_pipeline.pkl"
        test_file.write_bytes(malicious_content)

        result = scan_file(str(test_file))

        # Should detect dangerous patterns
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0, "Should detect critical security issues"

        # Should mention sklearn or Pipeline
        sklearn_detections = [
            issue
            for issue in result.issues
            if "sklearn" in issue.message.lower()
            or "pipeline" in issue.message.lower()
            or "sklearn" in str(issue.details).lower()
            or "pipeline" in str(issue.details).lower()
        ]
        assert len(sklearn_detections) > 0, "Should detect sklearn-related patterns"


class TestCVE202434997Detection:
    """Test detection of CVE-2024-34997 (joblib NumpyArrayWrapper vulnerability)."""

    def test_detect_cve_2024_34997_basic_pattern(self, tmp_path):
        """Test basic detection of CVE-2024-34997 patterns."""
        # Create content with NumpyArrayWrapper and pickle.load
        malicious_content = b"""
        NumpyArrayWrapper
        read_array
        pickle.load
        numpy_pickle
        """

        test_file = tmp_path / "numpy_wrapper_attack.pkl"
        test_file.write_bytes(malicious_content)

        result = scan_file(str(test_file))

        # Should detect CVE-2024-34997 patterns
        cve_detections = [
            issue
            for issue in result.issues
            if "CVE-2024-34997" in issue.message or "CVE-2024-34997" in str(issue.details)
        ]

        assert len(cve_detections) > 0, (
            f"Should detect CVE-2024-34997. Issues found: {[i.message for i in result.issues]}"
        )

    def test_detect_cve_2024_34997_cache_exploitation(self, tmp_path):
        """Test detection of NumpyArrayWrapper cache exploitation."""
        malicious_content = b"""
        joblib.cache
        NumpyArrayWrapper
        read_array
        pickle.load
        os.system
        """

        test_file = tmp_path / "cache_exploit.pkl"
        test_file.write_bytes(malicious_content)

        result = scan_file(str(test_file))

        # Should detect both cache and system patterns
        assert any("cache" in issue.message.lower() or "numpy" in issue.message.lower() for issue in result.issues), (
            "Should detect cache/numpy patterns"
        )

        assert any(
            issue.severity == IssueSeverity.CRITICAL or issue.severity == IssueSeverity.WARNING
            for issue in result.issues
        ), "Should flag as high severity"

    def test_detect_cve_2024_34997_numpy_pickle_exploitation(self, tmp_path):
        """Test detection of numpy_pickle module exploitation."""
        # Create a pickle with numpy_pickle and dangerous operations
        malicious_content = b"""
        numpy_pickle.read_array
        pickle.load
        __reduce__
        subprocess.Popen
        """

        test_file = tmp_path / "numpy_pickle_exploit.pkl"
        test_file.write_bytes(malicious_content)

        result = scan_file(str(test_file))

        # Should detect numpy_pickle patterns
        numpy_detections = [
            issue
            for issue in result.issues
            if "numpy" in issue.message.lower() or "numpy" in str(issue.details).lower()
        ]

        assert len(numpy_detections) > 0, "Should detect numpy_pickle patterns"


class TestCVEFalsePositivePrevention:
    """Test that legitimate sklearn models don't trigger false positives."""

    def test_legitimate_sklearn_model_no_false_positive(self, tmp_path):
        """Test that a normal sklearn model doesn't trigger CVE alerts."""
        # Create a benign sklearn-like pickle content (simulated)
        benign_content = b"""
        sklearn.ensemble.RandomForestClassifier
        sklearn.metrics.accuracy_score
        numpy.ndarray
        fit
        predict
        score
        """

        test_file = tmp_path / "legitimate_model.pkl"
        test_file.write_bytes(benign_content)

        result = scan_file(str(test_file))

        # Should not have CVE-2020-13092 detections for benign content
        cve_2020_detections = [
            issue
            for issue in result.issues
            if "CVE-2020-13092" in issue.message or "CVE-2020-13092" in str(issue.details)
        ]

        # Allow some warnings but no critical CVE detections for benign content
        critical_cve_detections = [issue for issue in cve_2020_detections if issue.severity == IssueSeverity.CRITICAL]

        assert len(critical_cve_detections) == 0, (
            f"Legitimate sklearn model should not trigger critical CVE alerts. "
            f"Found: {[i.message for i in critical_cve_detections]}"
        )

    def test_legitimate_joblib_usage_no_false_positive(self, tmp_path):
        """Test that normal joblib usage doesn't trigger false positives."""
        # Create benign joblib content
        benign_content = b"""
        joblib.dump
        joblib.load
        sklearn.linear_model.LogisticRegression
        numpy.ndarray
        """

        test_file = tmp_path / "legitimate_joblib.pkl"
        test_file.write_bytes(benign_content)

        result = scan_file(str(test_file))

        # Should not have critical CVE detections for normal usage
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]

        # Filter out non-CVE critical issues (like general dangerous patterns)
        cve_critical_issues = [
            issue for issue in critical_issues if "CVE-" in issue.message or "CVE-" in str(issue.details)
        ]

        assert len(cve_critical_issues) == 0, (
            f"Normal joblib usage should not trigger critical CVE alerts. "
            f"Found: {[i.message for i in cve_critical_issues]}"
        )


class TestCVEPatternAnalysis:
    """Test the CVE pattern analysis module directly."""

    def test_cve_pattern_analysis_cve_2020_13092(self):
        """Test CVE pattern analysis for CVE-2020-13092."""
        content = "joblib.load sklearn __reduce__ os.system"
        binary_content = b"joblib.load sklearn __reduce__ os.system"

        attributions = analyze_cve_patterns(content, binary_content)

        # Should detect CVE-2020-13092
        cve_2020_attrs = [attr for attr in attributions if attr.cve_id == "CVE-2020-13092"]
        assert len(cve_2020_attrs) > 0, "Should detect CVE-2020-13092 patterns"

        attr = cve_2020_attrs[0]
        assert attr.severity == "CRITICAL"
        assert attr.cvss == 9.8
        assert "scikit-learn" in attr.description.lower()
        assert len(attr.patterns_matched) > 0

    def test_cve_pattern_analysis_cve_2024_34997(self):
        """Test CVE pattern analysis for CVE-2024-34997."""
        content = "NumpyArrayWrapper read_array pickle.load"
        binary_content = b"NumpyArrayWrapper read_array pickle.load"

        attributions = analyze_cve_patterns(content, binary_content)

        # Should detect CVE-2024-34997
        cve_2024_attrs = [attr for attr in attributions if attr.cve_id == "CVE-2024-34997"]
        assert len(cve_2024_attrs) > 0, "Should detect CVE-2024-34997 patterns"

        attr = cve_2024_attrs[0]
        assert attr.severity == "HIGH"
        assert attr.cvss == 8.1
        assert "joblib" in attr.description.lower()
        assert len(attr.patterns_matched) > 0

    def test_no_cve_patterns_in_benign_content(self):
        """Test that benign content doesn't trigger CVE detection."""
        content = "import numpy as np\nfrom sklearn import datasets\ndata = datasets.load_iris()"
        binary_content = b"import numpy from sklearn datasets load_iris"

        attributions = analyze_cve_patterns(content, binary_content)

        # Should not detect any CVEs
        assert len(attributions) == 0, (
            f"Benign content should not trigger CVE detection. Found: {[a.cve_id for a in attributions]}"
        )


class TestCVEIntegration:
    """Integration tests for end-to-end CVE detection."""

    def test_joblib_scanner_cve_detection(self, tmp_path):
        """Test that JoblibScanner properly detects CVE patterns."""
        # Create a malicious joblib file content with multiple CVE indicators
        malicious_content = b"""
        sklearn.ensemble.RandomForestClassifier
        joblib.load os.system
        __reduce__ subprocess
        NumpyArrayWrapper pickle.load
        """

        test_file = tmp_path / "malicious.joblib"
        test_file.write_bytes(malicious_content)

        scanner = JoblibScanner()
        result = scanner.scan(str(test_file))

        # Should detect dangerous patterns (including CVE patterns)
        assert result.success is not None  # Scan completed

        # Look for dangerous pattern detections (CVE or general dangerous patterns)
        dangerous_checks = [
            check
            for check in result.checks
            if (
                "CVE" in check.name
                or "CVE" in check.message
                or "Dangerous" in check.name
                or check.status.value == "failed"
            )
        ]

        assert len(dangerous_checks) > 0, (
            f"JoblibScanner should detect dangerous patterns. Found checks: {[c.name for c in result.checks]}"
        )

    def test_pickle_scanner_cve_detection(self, tmp_path):
        """Test that PickleScanner properly detects CVE patterns."""
        # Create raw malicious content (not valid pickle, but with CVE indicators)
        malicious_content = b"""
        sklearn RandomForestClassifier
        __reduce__ os.system
        joblib.load subprocess
        NumpyArrayWrapper pickle.load
        """

        test_file = tmp_path / "malicious.pkl"
        test_file.write_bytes(malicious_content)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        # Should detect dangerous patterns
        dangerous_checks = [
            check
            for check in result.checks
            if (check.status.value == "failed" and check.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING])
        ]

        assert len(dangerous_checks) > 0, (
            f"PickleScanner should detect dangerous patterns. Found checks: {[c.name for c in result.checks]}"
        )

    def test_end_to_end_cve_reporting(self, tmp_path):
        """Test end-to-end CVE detection and reporting."""
        # Create a file with multiple CVE indicators
        malicious_content = b"""
        sklearn.ensemble.RandomForestClassifier
        joblib.load
        NumpyArrayWrapper
        read_array
        __reduce__
        os.system
        pickle.load
        """

        test_file = tmp_path / "multi_cve.pkl"
        test_file.write_bytes(malicious_content)

        result = scan_file(str(test_file))

        # Should detect multiple security issues
        security_issues = [
            issue for issue in result.issues if issue.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING]
        ]

        assert len(security_issues) > 0, "Should detect multiple security issues"

        # Check for CVE-specific metadata if present
        if hasattr(result, "metadata") and result.metadata:
            cve_info = result.metadata.get("cve_attributions", [])
            if cve_info:
                assert len(cve_info) > 0, "Should have CVE attribution information"


class TestCVEPatternValidation:
    """Test validation of CVE patterns themselves."""

    def test_cve_patterns_are_valid_regex(self):
        """Test that all CVE patterns are valid regex expressions."""
        import re

        from modelaudit.suspicious_symbols import CVE_2020_13092_PATTERNS, CVE_2024_34997_PATTERNS

        all_patterns = CVE_2020_13092_PATTERNS + CVE_2024_34997_PATTERNS

        for pattern in all_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex pattern '{pattern}': {e}")

    def test_cve_attribution_data_completeness(self):
        """Test that CVE attribution data is complete."""
        from modelaudit.suspicious_symbols import CVE_COMBINED_PATTERNS

        required_fields = ["patterns", "description", "severity", "cwe", "cvss", "affected_versions", "remediation"]

        for cve_id, cve_info in CVE_COMBINED_PATTERNS.items():
            assert cve_id.startswith("CVE-"), f"CVE ID should start with 'CVE-': {cve_id}"

            for field in required_fields:
                assert field in cve_info, f"Missing required field '{field}' in {cve_id}"
                assert cve_info[field], f"Field '{field}' should not be empty in {cve_id}"

            # Validate CVSS score range
            assert 0.0 <= cve_info["cvss"] <= 10.0, f"CVSS score should be 0-10 for {cve_id}"

            # Validate severity values
            assert cve_info["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"], (
                f"Invalid severity '{cve_info['severity']}' for {cve_id}"
            )


# Integration with existing test infrastructure
@pytest.mark.integration
def test_cve_detection_with_existing_scanners():
    """Test that CVE detection works with the existing scanner infrastructure."""
    from modelaudit.scanners.joblib_scanner import JoblibScanner
    from modelaudit.scanners.pickle_scanner import PickleScanner

    # Test scanner instantiation
    joblib_scanner = JoblibScanner()
    pickle_scanner = PickleScanner()

    # Check for CVE detection methods
    assert hasattr(joblib_scanner, "_detect_cve_patterns"), "JoblibScanner should have CVE detection"
    assert hasattr(joblib_scanner, "_scan_for_joblib_specific_threats"), (
        "JoblibScanner should have specific threat detection"
    )
    assert hasattr(pickle_scanner, "_analyze_cve_patterns"), "PickleScanner should have CVE analysis"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
