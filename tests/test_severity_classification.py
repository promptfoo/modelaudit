"""
Tests for graduated severity classification system.

This module tests the enhanced severity classification implemented in Task 3,
which replaces binary classification with graduated CRITICAL/HIGH/MEDIUM/LOW system.
"""

import pytest

from modelaudit.scanners.base import SEVERITY_SCORES, IssueSeverity, get_severity_score
from modelaudit.scanners.pickle_scanner import _get_graduated_severity
from modelaudit.suspicious_symbols import PICKLE_SEVERITY_MAP, TENSORFLOW_SEVERITY_MAP


class TestSeverityEnhancements:
    """Test graduated severity enum and scoring system"""

    def test_severity_enum_has_graduated_levels(self):
        """Test that IssueSeverity enum has all graduated levels"""
        assert hasattr(IssueSeverity, "CRITICAL")
        assert hasattr(IssueSeverity, "HIGH")
        assert hasattr(IssueSeverity, "MEDIUM")
        assert hasattr(IssueSeverity, "LOW")

        # Ensure backward compatibility
        assert hasattr(IssueSeverity, "WARNING")
        assert hasattr(IssueSeverity, "INFO")
        assert hasattr(IssueSeverity, "DEBUG")

    def test_severity_values_correct(self):
        """Test that severity values are correctly defined"""
        assert IssueSeverity.CRITICAL.value == "critical"
        assert IssueSeverity.HIGH.value == "high"
        assert IssueSeverity.MEDIUM.value == "medium"
        assert IssueSeverity.LOW.value == "low"
        assert IssueSeverity.WARNING.value == "warning"
        assert IssueSeverity.INFO.value == "info"
        assert IssueSeverity.DEBUG.value == "debug"

    def test_severity_scoring_system(self):
        """Test severity scoring provides proper numeric values"""
        assert get_severity_score(IssueSeverity.CRITICAL) == 10.0
        assert get_severity_score(IssueSeverity.HIGH) == 7.5
        assert get_severity_score(IssueSeverity.MEDIUM) == 5.0
        assert get_severity_score(IssueSeverity.LOW) == 2.5
        assert get_severity_score(IssueSeverity.INFO) == 1.0
        assert get_severity_score(IssueSeverity.DEBUG) == 0.0
        assert get_severity_score(IssueSeverity.WARNING) == 5.0  # Maps to MEDIUM

    def test_severity_scores_ordered_correctly(self):
        """Test that severity scores are properly ordered from highest to lowest"""
        scores = [
            get_severity_score(IssueSeverity.CRITICAL),
            get_severity_score(IssueSeverity.HIGH),
            get_severity_score(IssueSeverity.MEDIUM),
            get_severity_score(IssueSeverity.LOW),
            get_severity_score(IssueSeverity.INFO),
            get_severity_score(IssueSeverity.DEBUG),
        ]

        assert scores == sorted(scores, reverse=True), "Severity scores should be in descending order"


class TestPickleSeverityClassification:
    """Test pickle-specific severity classification"""

    def test_critical_severity_assignment(self):
        """Test that RCE patterns get CRITICAL severity"""
        critical_cases = [
            ("os", None),
            ("subprocess", None),
            ("sys", None),
            ("builtins", "eval"),
            ("builtins", "exec"),
            ("__builtin__", "eval"),
        ]

        for module, function in critical_cases:
            severity = _get_graduated_severity(module, function)
            assert severity == IssueSeverity.CRITICAL, f"{module}.{function} should be CRITICAL"

    def test_high_severity_assignment(self):
        """Test that file/network access patterns get HIGH severity"""
        high_cases = [
            ("webbrowser", None),
            ("shutil", "rmtree"),
            ("pickle", "loads"),
            ("requests", None),
            ("urllib", None),
        ]

        for module, function in high_cases:
            severity = _get_graduated_severity(module, function)
            assert severity == IssueSeverity.HIGH, f"{module}.{function} should be HIGH"

    def test_medium_severity_assignment(self):
        """Test that encoding/obfuscation patterns get MEDIUM severity"""
        medium_cases = [
            ("base64", "b64decode"),
            ("codecs", "decode"),
            ("operator", "attrgetter"),
            ("importlib", None),
        ]

        for module, function in medium_cases:
            severity = _get_graduated_severity(module, function)
            assert severity == IssueSeverity.MEDIUM, f"{module}.{function} should be MEDIUM"

    def test_low_severity_assignment(self):
        """Test that informational patterns get LOW severity"""
        low_cases = [
            ("warnings", None),
            ("logging", None),
            ("inspect", None),
        ]

        for module, function in low_cases:
            severity = _get_graduated_severity(module, function)
            assert severity == IssueSeverity.LOW, f"{module}.{function} should be LOW"

    def test_unknown_module_defaults_to_medium(self):
        """Test that unknown suspicious modules default to MEDIUM severity"""
        severity = _get_graduated_severity("unknown_suspicious_module")
        assert severity == IssueSeverity.MEDIUM

    def test_specific_function_detection(self):
        """Test that specific functions are detected correctly"""
        # base64 module has specific functions
        assert _get_graduated_severity("base64", "b64decode") == IssueSeverity.MEDIUM
        assert _get_graduated_severity("base64", "safe_function") == IssueSeverity.MEDIUM  # Default for unknown

    def test_wildcard_module_detection(self):
        """Test that wildcard modules catch all functions"""
        # os module uses "*" (all functions critical)
        assert _get_graduated_severity("os", "system") == IssueSeverity.CRITICAL
        assert _get_graduated_severity("os", "popen") == IssueSeverity.CRITICAL
        assert _get_graduated_severity("os", "any_function") == IssueSeverity.CRITICAL


class TestTensorFlowSeverityClassification:
    """Test TensorFlow operation severity classification"""

    def test_tensorflow_severity_map_structure(self):
        """Test that TensorFlow severity map has proper structure"""
        assert "CRITICAL" in TENSORFLOW_SEVERITY_MAP
        assert "HIGH" in TENSORFLOW_SEVERITY_MAP
        assert "MEDIUM" in TENSORFLOW_SEVERITY_MAP
        assert "LOW" in TENSORFLOW_SEVERITY_MAP

    def test_tensorflow_critical_operations(self):
        """Test that dangerous TF operations are classified as CRITICAL"""
        critical_ops = TENSORFLOW_SEVERITY_MAP["CRITICAL"]
        expected_critical = ["PyFunc", "PyCall", "ShellExecute"]

        for op in expected_critical:
            assert op in critical_ops, f"TF operation {op} should be CRITICAL"

    def test_tensorflow_high_operations(self):
        """Test that file system TF operations are classified as HIGH"""
        high_ops = TENSORFLOW_SEVERITY_MAP["HIGH"]
        expected_high = ["ReadFile", "WriteFile", "MergeV2Checkpoints"]

        for op in expected_high:
            assert op in high_ops, f"TF operation {op} should be HIGH"

    def test_tensorflow_medium_operations(self):
        """Test that save operations are classified as MEDIUM"""
        medium_ops = TENSORFLOW_SEVERITY_MAP["MEDIUM"]
        expected_medium = ["Save", "SaveV2"]

        for op in expected_medium:
            assert op in medium_ops, f"TF operation {op} should be MEDIUM"


class TestSeverityMappingConsistency:
    """Test that severity mappings are consistent and comprehensive"""

    def test_pickle_severity_map_completeness(self):
        """Test that pickle severity map covers all severity levels"""
        assert "CRITICAL" in PICKLE_SEVERITY_MAP
        assert "HIGH" in PICKLE_SEVERITY_MAP
        assert "MEDIUM" in PICKLE_SEVERITY_MAP
        assert "LOW" in PICKLE_SEVERITY_MAP

        # Ensure each level has at least one module
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert len(PICKLE_SEVERITY_MAP[level]) > 0, f"{level} severity should have modules"

    def test_no_module_duplicates_across_severities(self):
        """Test that modules don't appear in multiple severity levels"""
        all_modules = set()
        for _level, modules in PICKLE_SEVERITY_MAP.items():
            for module in modules:
                assert module not in all_modules, f"Module {module} appears in multiple severity levels"
                all_modules.add(module)

    def test_severity_map_types(self):
        """Test that severity maps have proper types"""
        for level, modules in PICKLE_SEVERITY_MAP.items():
            assert isinstance(modules, dict), f"Severity level {level} should be a dict"
            for module, spec in modules.items():
                assert isinstance(module, str), f"Module name {module} should be a string"
                assert spec == "*" or isinstance(spec, list), f"Module spec for {module} should be '*' or list"


class TestBackwardCompatibility:
    """Test that the graduated system maintains backward compatibility"""

    def test_warning_severity_preserved(self):
        """Test that WARNING severity is preserved for backward compatibility"""
        assert IssueSeverity.WARNING.value == "warning"
        assert get_severity_score(IssueSeverity.WARNING) == 5.0  # Same as MEDIUM

    def test_info_debug_preserved(self):
        """Test that INFO and DEBUG severities are preserved"""
        assert IssueSeverity.INFO.value == "info"
        assert IssueSeverity.DEBUG.value == "debug"
        assert get_severity_score(IssueSeverity.INFO) == 1.0
        assert get_severity_score(IssueSeverity.DEBUG) == 0.0

    def test_severity_scores_dict_completeness(self):
        """Test that SEVERITY_SCORES includes all severity levels"""
        all_severities = [
            IssueSeverity.CRITICAL,
            IssueSeverity.HIGH,
            IssueSeverity.MEDIUM,
            IssueSeverity.LOW,
            IssueSeverity.WARNING,
            IssueSeverity.INFO,
            IssueSeverity.DEBUG,
        ]

        for severity in all_severities:
            assert severity in SEVERITY_SCORES, f"Missing severity {severity} in SEVERITY_SCORES"


class TestSeverityClassificationIntegration:
    """Test integration of severity classification with existing components"""

    def test_severity_score_calculation_consistent(self):
        """Test that severity score calculation is consistent"""
        # Test that all severity levels return valid scores
        for severity in IssueSeverity:
            score = get_severity_score(severity)
            assert isinstance(score, float), f"Score for {severity} should be float"
            assert score >= 0.0, f"Score for {severity} should be non-negative"
            assert score <= 10.0, f"Score for {severity} should not exceed 10.0"

    def test_graduated_severity_function_robustness(self):
        """Test that severity classification handles edge cases"""
        # Test empty/None inputs
        assert _get_graduated_severity("") == IssueSeverity.MEDIUM

        # Test case sensitivity (should be case sensitive)
        assert _get_graduated_severity("OS") == IssueSeverity.MEDIUM  # Not same as "os"

        # Test function-specific matching
        assert _get_graduated_severity("builtins", "eval") == IssueSeverity.CRITICAL
        assert _get_graduated_severity("builtins", "safe_func") == IssueSeverity.MEDIUM  # Default for unknown func

    def test_severity_enum_serialization(self):
        """Test that severity enums can be properly serialized"""
        for severity in IssueSeverity:
            # Test that enum value can be converted to string
            assert isinstance(severity.value, str)
            # Test that enum can be reconstructed from value
            reconstructed = IssueSeverity(severity.value)
            assert reconstructed == severity


if __name__ == "__main__":
    pytest.main([__file__])
