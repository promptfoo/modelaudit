"""
Tests for PickleScan safety classification system implementation.

This module tests Task 8: PickleScan's Safety Level Classification System
adapted to ModelAudit's severity levels.
"""

from modelaudit.scanners.pickle_scanner import is_suspicious_global
from modelaudit.suspicious_symbols import (
    SAFE_GLOBALS,
    classify_global_safety,
    is_dangerous_global,
    is_safe_global,
)


class TestSafetyClassification:
    """Test the safety classification system."""

    def test_safe_globals_whitelist_structure(self):
        """Test that SAFE_GLOBALS has the expected structure."""
        assert isinstance(SAFE_GLOBALS, dict)
        assert len(SAFE_GLOBALS) > 0

        # Check key ML libraries are present
        assert "numpy" in SAFE_GLOBALS
        assert "torch" in SAFE_GLOBALS
        assert "sklearn" in SAFE_GLOBALS
        assert "tensorflow" in SAFE_GLOBALS

        # Check that dangerous libraries are not in safe list or have empty lists
        assert SAFE_GLOBALS.get("pickle", []) == []
        assert SAFE_GLOBALS.get("dill", []) == []
        assert SAFE_GLOBALS.get("_pickle", []) == []

    def test_classify_global_safety_innocuous(self):
        """Test classification of safe/innocuous operations."""
        # NumPy operations should be innocuous
        safety_level, severity = classify_global_safety("numpy", "array")
        assert safety_level == "innocuous"
        assert severity == "info"

        # PyTorch operations should be innocuous
        safety_level, severity = classify_global_safety("torch", "Tensor")
        assert safety_level == "innocuous"
        assert severity == "info"

        # Scikit-learn operations should be innocuous
        safety_level, severity = classify_global_safety("sklearn", "Pipeline")
        assert safety_level == "innocuous"
        assert severity == "info"

    def test_classify_global_safety_dangerous(self):
        """Test classification of dangerous operations."""
        # os.system should be dangerous
        safety_level, severity = classify_global_safety("os", "system")
        assert safety_level == "dangerous"
        assert severity == "critical"

        # subprocess operations should be dangerous
        safety_level, severity = classify_global_safety("subprocess", "call")
        assert safety_level == "dangerous"
        assert severity == "critical"

        # eval should be dangerous
        safety_level, severity = classify_global_safety("builtins", "eval")
        assert safety_level == "dangerous"
        assert severity == "critical"

    def test_classify_global_safety_suspicious(self):
        """Test classification of unknown/suspicious operations."""
        # Unknown modules should be suspicious
        safety_level, severity = classify_global_safety("unknown_module", "unknown_func")
        assert safety_level == "suspicious"
        assert severity == "warning"

        # New/unknown functions in known modules might be suspicious
        safety_level, severity = classify_global_safety("collections", "unknown_function")
        assert safety_level == "suspicious"
        assert severity == "warning"

    def test_is_safe_global(self):
        """Test the is_safe_global convenience function."""
        # Safe operations
        assert is_safe_global("numpy", "array") is True
        assert is_safe_global("torch", "Tensor") is True
        assert is_safe_global("pandas", "DataFrame") is True

        # Unsafe operations
        assert is_safe_global("os", "system") is False
        assert is_safe_global("subprocess", "call") is False
        assert is_safe_global("builtins", "eval") is False

    def test_is_dangerous_global(self):
        """Test the is_dangerous_global convenience function."""
        # Dangerous operations
        assert is_dangerous_global("os", "system") is True
        assert is_dangerous_global("subprocess", "call") is True
        assert is_dangerous_global("builtins", "eval") is True

        # Safe operations
        assert is_dangerous_global("numpy", "array") is False
        assert is_dangerous_global("torch", "Tensor") is False
        assert is_dangerous_global("pandas", "DataFrame") is False

    def test_is_suspicious_global_with_safety_classification(self):
        """Test that is_suspicious_global uses safety classification."""
        # Safe operations should not be suspicious
        assert is_suspicious_global("numpy", "array") is False
        assert is_suspicious_global("torch", "Tensor") is False
        assert is_suspicious_global("sklearn", "Pipeline") is False

        # Dangerous operations should be suspicious
        assert is_suspicious_global("os", "system") is True
        assert is_suspicious_global("subprocess", "call") is True
        assert is_suspicious_global("builtins", "eval") is True

        # Unknown operations should be suspicious (conservative approach)
        assert is_suspicious_global("unknown_module", "unknown_func") is True

    def test_ml_framework_coverage(self):
        """Test that major ML frameworks are covered in SAFE_GLOBALS."""
        ml_frameworks = [
            "numpy",
            "torch",
            "tensorflow",
            "sklearn",
            "scipy",
            "pandas",
            "matplotlib",
            "PIL",
            "cv2",
            "h5py",
            "transformers",
            "datasets",
            "xgboost",
            "lightgbm",
            "catboost",
            "onnx",
            "onnxruntime",
        ]

        for framework in ml_frameworks:
            assert framework in SAFE_GLOBALS, f"ML framework {framework} not in SAFE_GLOBALS"

    def test_dangerous_modules_excluded(self):
        """Test that known dangerous modules are not marked as safe."""
        dangerous_modules = [
            "os",
            "sys",
            "subprocess",
            "runpy",
            "commands",
            "webbrowser",
            "importlib",
            "shutil",
            "tempfile",
            "pty",
            "platform",
            "ctypes",
            "socket",
        ]

        for module in dangerous_modules:
            # These modules should either not be in SAFE_GLOBALS or have restrictive lists
            if module in SAFE_GLOBALS:
                # If present, should not be wildcard safe
                assert SAFE_GLOBALS[module] != "*", f"Dangerous module {module} marked as wildcard safe"

    def test_operator_module_safety(self):
        """Test that operator module excludes dangerous attrgetter."""
        # operator module should be in safe globals
        assert "operator" in SAFE_GLOBALS

        # attrgetter should not be in the safe list (it's dangerous)
        operator_safe_funcs = SAFE_GLOBALS["operator"]
        assert isinstance(operator_safe_funcs, list)
        assert "attrgetter" not in operator_safe_funcs

        # But safe functions should be included
        assert "itemgetter" in operator_safe_funcs
        assert "methodcaller" in operator_safe_funcs

    def test_base64_encoding_only(self):
        """Test that base64 only allows encoding, not decoding."""
        # base64 should be in safe globals
        assert "base64" in SAFE_GLOBALS

        base64_safe_funcs = SAFE_GLOBALS["base64"]
        assert isinstance(base64_safe_funcs, list)

        # Encoding functions should be safe
        assert "b64encode" in base64_safe_funcs
        assert "b32encode" in base64_safe_funcs
        assert "b16encode" in base64_safe_funcs

        # Decoding functions should not be safe (potential for malicious payloads)
        assert "b64decode" not in base64_safe_funcs

    def test_builtin_safety_restrictions(self):
        """Test that builtins have appropriate restrictions."""
        # Dangerous builtins should not be in the safe lists
        builtin_modules = ["builtins", "__builtin__", "__builtins__"]
        dangerous_builtins = ["eval", "exec", "compile", "__import__"]

        for module in builtin_modules:
            if module in SAFE_GLOBALS:
                safe_funcs = SAFE_GLOBALS[module]
                for dangerous_func in dangerous_builtins:
                    assert dangerous_func not in safe_funcs, (
                        f"Dangerous builtin {module}.{dangerous_func} should not be in SAFE_GLOBALS"
                    )

        # But safe builtins should be allowed
        safe_builtins = ["len", "str", "int", "float"]
        for module in builtin_modules:
            if module in SAFE_GLOBALS:
                safe_funcs = SAFE_GLOBALS[module]
                for safe_func in safe_builtins:
                    assert safe_func in safe_funcs, f"Safe builtin {module}.{safe_func} should be in SAFE_GLOBALS"

    def test_pickle_modules_unsafe(self):
        """Test that pickle-related modules are not marked as safe."""
        pickle_modules = ["pickle", "dill", "_pickle"]

        for module in pickle_modules:
            if module in SAFE_GLOBALS:
                # Should have empty list (no safe operations)
                assert SAFE_GLOBALS[module] == [], f"Pickle module {module} has safe operations listed"

    def test_torch_specific_operations(self):
        """Test PyTorch specific safe operations."""
        torch_safe_ops = SAFE_GLOBALS["torch"]
        assert isinstance(torch_safe_ops, list)

        # Core tensor operations should be safe
        essential_ops = ["Tensor", "tensor", "zeros", "ones", "randn", "FloatTensor"]
        for op in essential_ops:
            assert op in torch_safe_ops, f"Essential PyTorch operation {op} not in safe list"

    def test_collections_safety(self):
        """Test that collections module has appropriate restrictions."""
        collections_safe_ops = SAFE_GLOBALS["collections"]
        assert isinstance(collections_safe_ops, list)

        # Safe operations should be included
        safe_ops = ["OrderedDict", "namedtuple", "defaultdict", "deque", "Counter"]
        for op in safe_ops:
            assert op in collections_safe_ops, f"Safe collections operation {op} not in safe list"

    def test_severity_mapping_consistency(self):
        """Test that severity levels are consistently mapped."""
        # Test a variety of operations
        test_cases = [
            ("numpy", "array", "innocuous", "info"),
            ("os", "system", "dangerous", "critical"),
            ("unknown", "unknown", "suspicious", "warning"),
        ]

        for module, func, expected_level, expected_severity in test_cases:
            safety_level, severity = classify_global_safety(module, func)
            assert safety_level == expected_level
            assert severity == expected_severity


class TestSafetyClassificationIntegration:
    """Integration tests for safety classification with pickle scanner."""

    def test_false_positive_reduction(self):
        """Test that legitimate ML operations don't trigger false positives."""
        # These should not be flagged as suspicious
        legitimate_ml_ops = [
            ("numpy", "array"),
            ("numpy.core.multiarray", "ndarray"),
            ("torch", "FloatTensor"),
            ("torch.nn", "Linear"),
            ("sklearn.linear_model", "LinearRegression"),
            ("pandas", "DataFrame"),
            ("matplotlib.pyplot", "plot"),
        ]

        for module, func in legitimate_ml_ops:
            assert is_suspicious_global(module, func) is False, f"{module}.{func} incorrectly flagged as suspicious"

    def test_security_detection_maintained(self):
        """Test that dangerous operations are still detected."""
        # These should be flagged as suspicious
        dangerous_ops = [
            ("os", "system"),
            ("subprocess", "call"),
            ("builtins", "eval"),
            ("builtins", "exec"),
            ("importlib", "import_module"),
            ("webbrowser", "open"),
        ]

        for module, func in dangerous_ops:
            assert is_suspicious_global(module, func) is True, f"{module}.{func} not detected as dangerous"

    def test_unknown_operations_flagged(self):
        """Test that unknown operations are conservatively flagged."""
        # Unknown operations should be flagged for manual review
        unknown_ops = [
            ("mysterious_module", "unknown_function"),
            ("collections", "non_existent_operation"),  # collections has explicit whitelist
            ("requests", "unknown_dangerous_function"),  # non-core module with wildcard
        ]

        for module, func in unknown_ops:
            assert is_suspicious_global(module, func) is True, f"Unknown operation {module}.{func} not flagged"
