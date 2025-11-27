"""
Test the Keras ZIP scanner for detecting malicious Lambda layers in .keras files.

The new .keras format is a ZIP archive containing:
- config.json: Model configuration with layer definitions
- metadata.json: Model metadata
- model.weights.h5: Model weights in HDF5 format
"""

import base64
import json
import os
import tempfile
import zipfile

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.keras_zip_scanner import KerasZipScanner


class TestKerasZipScanner:
    """Test the Keras ZIP scanner functionality."""

    def test_scanner_available(self):
        """Test that the scanner is available."""
        scanner = KerasZipScanner()
        assert scanner is not None
        assert scanner.name == "keras_zip"

    def test_can_handle_keras_zip(self):
        """Test that scanner can identify ZIP-based .keras files."""
        scanner = KerasZipScanner()

        # Create a minimal Keras ZIP file
        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                # Add minimal config.json
                config = {"class_name": "Sequential", "config": {"layers": []}}
                zf.writestr("config.json", json.dumps(config))
                # Add metadata.json
                metadata = {"keras_version": "3.0.0"}
                zf.writestr("metadata.json", json.dumps(metadata))
            temp_path = f.name

        try:
            assert scanner.can_handle(temp_path)
        finally:
            os.unlink(temp_path)

    def test_lambda_layer_with_exec(self):
        """Test detection of Lambda layer with exec() call."""
        scanner = KerasZipScanner()

        # Create malicious Lambda layer config
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "function": [encoded_code, None, None],
                            "function_type": "lambda",
                        },
                    },
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
                zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
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
                    assert "lambda_1" in issue.message or "lambda_1" in str(issue.details)
                    break

            assert exec_found, "Should detect exec in Lambda layer"

        finally:
            os.unlink(temp_path)

    def test_multiple_dangerous_patterns(self):
        """Test detection of multiple dangerous patterns in Lambda layers."""
        scanner = KerasZipScanner()

        # Create Lambda with multiple dangerous patterns
        dangerous_code = """
import os
import subprocess
eval("os.system('cmd')")
subprocess.call(['ls'])
__import__('pickle').loads(data)
"""
        encoded_code = base64.b64encode(dangerous_code.encode()).decode()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "dangerous_lambda",
                        "config": {
                            "function": [encoded_code, None, None],
                        },
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect dangerous patterns
            assert len(result.issues) > 0, "Should detect dangerous patterns"

            # Check that multiple patterns were detected
            all_messages = " ".join(issue.message for issue in result.issues)
            patterns_detected = []
            for pattern in ["eval", "subprocess", "__import__", "pickle"]:
                if pattern in all_messages.lower():
                    patterns_detected.append(pattern)

            assert len(patterns_detected) > 0, f"Should detect dangerous patterns, found: {patterns_detected}"

        finally:
            os.unlink(temp_path)

    def test_safe_lambda_layer(self):
        """Test that safe Lambda layers are handled appropriately."""
        scanner = KerasZipScanner()

        # Create a Lambda with safe code
        safe_code = "lambda x: x * 2"
        encoded_code = base64.b64encode(safe_code.encode()).decode()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "safe_lambda",
                        "config": {
                            "function": [encoded_code, None, None],
                        },
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Safe Lambda should not be CRITICAL
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) == 0, "Safe Lambda should not be CRITICAL"

        finally:
            os.unlink(temp_path)

    def test_custom_registered_objects(self):
        """Test detection of custom registered objects."""
        scanner = KerasZipScanner()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "registered_name": "custom_package.CustomDense",
                        "config": {},
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect custom registered object
            custom_found = False
            for check in result.checks:
                if "custom" in check.message.lower() and "registered" in check.message.lower():
                    custom_found = True
                    break

            assert custom_found, "Should detect custom registered objects"

        finally:
            os.unlink(temp_path)

    def test_executable_files_in_zip(self):
        """Test detection of executable files in the ZIP archive."""
        scanner = KerasZipScanner()

        config = {"class_name": "Sequential", "config": {"layers": []}}

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
                # Add suspicious files
                zf.writestr("malicious.py", "import os; os.system('cmd')")
                zf.writestr("script.sh", "#!/bin/bash\nrm -rf /")

            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect Python and shell scripts
            suspicious_files = []
            for check in result.checks:
                if "Python file" in check.message or "Executable file" in check.message:
                    suspicious_files.append(check.message)

            assert len(suspicious_files) >= 2, f"Should detect suspicious files, found: {suspicious_files}"

        finally:
            os.unlink(temp_path)

    def test_nested_models(self):
        """Test scanning of nested model structures."""
        scanner = KerasZipScanner()

        # Create nested model with Lambda in submodel
        malicious_code = '__import__("os").system("cmd")'
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "Lambda",
                                    "name": "nested_lambda",
                                    "config": {
                                        "function": [encoded_code, None, None],
                                    },
                                }
                            ]
                        },
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect Lambda in nested model
            assert len(result.issues) > 0, "Should detect Lambda in nested model"

            # Check that __import__ was detected
            import_found = False
            for issue in result.issues:
                if "__import__" in issue.message.lower():
                    import_found = True
                    break

            assert import_found, "Should detect __import__ in nested Lambda"

        finally:
            os.unlink(temp_path)

    def test_invalid_json_config(self):
        """Test handling of invalid JSON in config."""
        scanner = KerasZipScanner()

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", "{ invalid json }")
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should handle invalid JSON gracefully
            assert not result.success
            json_error_found = False
            for check in result.checks:
                if "parse" in check.message.lower() and "json" in check.message.lower():
                    json_error_found = True
                    break

            assert json_error_found, "Should report JSON parsing error"

        finally:
            os.unlink(temp_path)

    def test_missing_config_json(self):
        """Test handling of .keras file without config.json."""
        scanner = KerasZipScanner()

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                # Only add metadata, no config
                zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should handle missing config.json
            missing_config_found = False
            for check in result.checks:
                if "config.json" in check.message:
                    missing_config_found = True
                    break

            assert missing_config_found, "Should report missing config.json"

        finally:
            os.unlink(temp_path)
