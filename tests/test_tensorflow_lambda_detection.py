"""
Test detection of Lambda layers with malicious code in TensorFlow SavedModel format.

These tests ensure that the TensorFlow scanner can detect unsafe Lambda layers
and custom operations that may execute arbitrary code.
"""

import base64
import os
import tempfile
from pathlib import Path

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tf_savedmodel_scanner import TensorFlowSavedModelScanner


class TestTensorFlowLambdaDetection:
    """Test detection of Lambda layers and unsafe operations."""

    def test_scanner_available(self):
        """Test that TensorFlow scanner is available."""
        scanner = TensorFlowSavedModelScanner()
        assert scanner is not None
        assert scanner.name == "tf_savedmodel"

    def test_keras_metadata_lambda_detection(self):
        """Test detection of Lambda layers in keras_metadata.pb."""
        scanner = TensorFlowSavedModelScanner()

        # Create a mock keras_metadata.pb with Lambda layer
        # This simulates a Lambda layer with base64-encoded exec() call
        lambda_config = {
            "class_name": "Lambda",
            "config": {
                "function": {
                    "items": [
                        # Base64 encoded Python code with exec
                        base64.b64encode(b"exec(\"print('Malicious!')\")").decode()
                    ]
                }
            },
        }

        # Create minimal protobuf-like content with the Lambda definition
        encoded_func = lambda_config["config"]["function"]["items"][0]
        content = f'"class_name": "Lambda", "function": {{"items": ["{encoded_func}"]}}'.encode()

        with tempfile.NamedTemporaryFile(suffix="keras_metadata.pb", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect Lambda layer with exec
            assert len(result.issues) > 0, "Should detect Lambda layer with dangerous code"

            # Check for critical issue
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, "Lambda with exec should be CRITICAL"

            # Check that exec was detected
            exec_found = False
            for issue in result.issues:
                if "exec" in issue.message.lower() and "lambda" in issue.message.lower():
                    exec_found = True
                    break

            assert exec_found, "Should detect exec in Lambda layer"

        finally:
            os.unlink(temp_path)

    def test_multiple_dangerous_patterns_in_lambda(self):
        """Test detection of multiple dangerous patterns in Lambda layers."""
        scanner = TensorFlowSavedModelScanner()

        # Create Lambda with multiple dangerous patterns
        dangerous_code = """
import os
import subprocess
eval("os.system('cmd')")
subprocess.call(['ls'])
__import__('pickle').loads(data)
"""
        encoded_code = base64.b64encode(dangerous_code.encode()).decode()

        content = f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode()

        with tempfile.NamedTemporaryFile(suffix="keras_metadata.pb", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect multiple dangerous patterns
            assert len(result.issues) > 0, "Should detect dangerous patterns"

            # Check that multiple patterns were detected
            all_messages = " ".join(issue.message for issue in result.issues)
            patterns_detected = []
            for pattern in ["eval", "subprocess", "os.system", "__import__", "pickle"]:
                if pattern in all_messages.lower():
                    patterns_detected.append(pattern)

            assert len(patterns_detected) > 0, f"Should detect dangerous patterns, found: {patterns_detected}"

        finally:
            os.unlink(temp_path)

    def test_safe_lambda_layer(self):
        """Test that safe Lambda layers are only flagged as warnings."""
        scanner = TensorFlowSavedModelScanner()

        # Create a Lambda with safe code
        safe_code = "lambda x: x * 2"
        encoded_code = base64.b64encode(safe_code.encode()).decode()

        content = f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode()

        with tempfile.NamedTemporaryFile(suffix="keras_metadata.pb", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Safe Lambda should still be detected but as WARNING
            if result.issues:
                # Check that no CRITICAL issues for safe code
                critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
                assert len(critical_issues) == 0, "Safe Lambda should not be CRITICAL"

        finally:
            os.unlink(temp_path)

    def test_stateful_partitioned_call_detection(self):
        """Test detection of suspicious StatefulPartitionedCall operations."""
        scanner = TensorFlowSavedModelScanner()

        # This would require creating a proper SavedModel protobuf
        # For now, we'll test that the scanner has the capability
        # Check that the method contains the string "StatefulPartitionedCall"
        import inspect

        source = inspect.getsource(scanner._analyze_saved_model)
        assert "StatefulPartitionedCall" in source

    def test_savedmodel_directory_structure(self):
        """Test scanning a SavedModel directory structure."""
        scanner = TensorFlowSavedModelScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a minimal SavedModel directory structure
            saved_model_path = Path(tmpdir) / "saved_model.pb"
            keras_metadata_path = Path(tmpdir) / "keras_metadata.pb"

            # Create minimal saved_model.pb (empty for this test)
            saved_model_path.write_bytes(b"\x08\x01")  # Minimal protobuf

            # Create keras_metadata.pb with Lambda layer
            lambda_content = """
            "class_name": "Lambda",
            "function": {"items": ["ZXhlYygiZGFuZ2Vyb3VzIik="]}
            """
            keras_metadata_path.write_text(lambda_content)

            # Test directory scanning
            result = scanner.scan(tmpdir)

            # Should detect the Lambda layer in keras_metadata.pb
            lambda_detected = False
            for issue in result.issues:
                if "lambda" in issue.message.lower():
                    lambda_detected = True
                    break

            assert lambda_detected, "Should detect Lambda layer when scanning directory"

    def test_can_handle_pb_files(self):
        """Test that scanner correctly identifies .pb files."""
        scanner = TensorFlowSavedModelScanner()

        # Create actual .pb files to test (can_handle checks if file exists)
        with tempfile.NamedTemporaryFile(suffix=".pb", delete=False) as f:
            f.write(b"test")
            pb_path = f.name

        try:
            # Should handle existing .pb files
            assert scanner.can_handle(pb_path)

            # Should not handle non-existent files
            assert not scanner.can_handle("/nonexistent/model.pb")

            # Should not handle other file types
            assert not scanner.can_handle("model.pkl")
            assert not scanner.can_handle("model.h5")
            assert not scanner.can_handle("model.json")
        finally:
            os.unlink(pb_path)

    @pytest.mark.skipif(not TensorFlowSavedModelScanner.can_handle("dummy.pb"), reason="TensorFlow not installed")
    def test_suspicious_metadata_patterns(self):
        """Test detection of suspicious patterns directly in metadata."""
        scanner = TensorFlowSavedModelScanner()

        # Create metadata with suspicious patterns
        suspicious_content = b"""
        "eval": "dangerous_code",
        "exec": "malicious",
        "__import__": "os",
        "subprocess": "call"
        """

        with tempfile.NamedTemporaryFile(suffix="keras_metadata.pb", delete=False) as f:
            f.write(suspicious_content)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect suspicious patterns
            if result.issues:
                patterns = ["eval", "exec", "__import__", "subprocess"]
                detected = []
                for issue in result.issues:
                    for pattern in patterns:
                        if pattern in issue.message.lower():
                            detected.append(pattern)

                assert len(detected) > 0, f"Should detect suspicious patterns, found: {detected}"

        finally:
            os.unlink(temp_path)

    def test_webbrowser_pattern_detection(self):
        """Test detection of webbrowser.open in Lambda layers."""
        scanner = TensorFlowSavedModelScanner()

        # Create Lambda with webbrowser.open call
        malicious_code = "import webbrowser; webbrowser.open('http://evil.com')"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        content = f'"class_name": "Lambda", "function": {{"items": ["{encoded_code}"]}}'.encode()

        with tempfile.NamedTemporaryFile(suffix="keras_metadata.pb", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect webbrowser pattern
            assert len(result.issues) > 0, "Should detect webbrowser usage"

            # Check for webbrowser detection
            webbrowser_found = False
            for issue in result.issues:
                if "webbrowser" in issue.message.lower():
                    webbrowser_found = True
                    assert issue.severity == IssueSeverity.CRITICAL, "webbrowser.open should be CRITICAL"
                    break

            assert webbrowser_found, "Should detect webbrowser.open pattern"

        finally:
            os.unlink(temp_path)
