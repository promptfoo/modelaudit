"""Scanner for ZIP-based Keras model files (.keras format)."""

import base64
import json
import os
import zipfile
from typing import Any, ClassVar, Optional

from modelaudit.suspicious_symbols import (
    SUSPICIOUS_CONFIG_PROPERTIES,
    SUSPICIOUS_LAYER_TYPES,
)
from modelaudit.utils.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)

from ..explanations import get_pattern_explanation
from .base import BaseScanner, IssueSeverity, ScanResult


class KerasZipScanner(BaseScanner):
    """Scanner for ZIP-based Keras .keras model files"""

    name = "keras_zip"
    description = "Scans ZIP-based Keras model files for suspicious configurations and Lambda layers"
    supported_extensions: ClassVar[list[str]] = [".keras"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Additional scanner-specific configuration
        self.suspicious_layer_types = dict(SUSPICIOUS_LAYER_TYPES)
        if config and "suspicious_layer_types" in config:
            self.suspicious_layer_types.update(config["suspicious_layer_types"])

        self.suspicious_config_props = list(SUSPICIOUS_CONFIG_PROPERTIES)
        if config and "suspicious_config_properties" in config:
            self.suspicious_config_props.extend(config["suspicious_config_properties"])

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Check if it's a ZIP file
        try:
            with zipfile.ZipFile(path, "r") as zf:
                # Check if it contains the expected Keras ZIP structure
                namelist = zf.namelist()
                # New Keras format should have config.json
                return "config.json" in namelist
        except (zipfile.BadZipFile, Exception):
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a ZIP-based Keras model file for suspicious configurations"""
        # Initialize context for this file
        self._initialize_context(path)

        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        # Store the file path for use in issue locations
        self.current_file_path = path

        try:
            with zipfile.ZipFile(path, "r") as zf:
                result.bytes_scanned = file_size

                # Check for config.json
                if "config.json" not in zf.namelist():
                    result.add_check(
                        name="Keras ZIP Format Check",
                        passed=False,
                        message="No config.json found in Keras ZIP file",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"files": zf.namelist()},
                    )
                    result.finish(success=True)
                    return result

                # Read and parse config.json
                with zf.open("config.json") as config_file:
                    config_data = config_file.read()
                    try:
                        model_config = json.loads(config_data)
                    except json.JSONDecodeError as e:
                        result.add_check(
                            name="Config JSON Parsing",
                            passed=False,
                            message=f"Failed to parse config.json: {e}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}/config.json",
                            details={"error": str(e)},
                        )
                        result.finish(success=False)
                        return result

                # Scan model configuration
                self._scan_model_config(model_config, result)

                # Check for metadata.json
                if "metadata.json" in zf.namelist():
                    with zf.open("metadata.json") as metadata_file:
                        metadata_data = metadata_file.read()
                        try:
                            metadata = json.loads(metadata_data)
                            result.metadata["keras_metadata"] = metadata
                        except json.JSONDecodeError:
                            pass  # Metadata parsing is optional

                # Check for suspicious files in the ZIP
                for filename in zf.namelist():
                    if filename.endswith((".py", ".pyc", ".pyo")):
                        result.add_check(
                            name="Python File Detection",
                            passed=False,
                            message=f"Python file found in Keras ZIP: {filename}",
                            severity=IssueSeverity.WARNING,
                            location=f"{path}/{filename}",
                            details={"filename": filename},
                        )
                    elif filename.endswith((".sh", ".bat", ".exe", ".dll")):
                        result.add_check(
                            name="Executable File Detection",
                            passed=False,
                            message=f"Executable file found in Keras ZIP: {filename}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}/{filename}",
                            details={"filename": filename},
                        )

        except Exception as e:
            result.add_check(
                name="Keras ZIP File Scan",
                passed=False,
                message=f"Error scanning Keras ZIP file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _scan_model_config(self, model_config: dict[str, Any], result: ScanResult) -> None:
        """Scan the model configuration for suspicious elements"""
        # Check model class name
        model_class = model_config.get("class_name", "")
        result.metadata["model_class"] = model_class

        # Check for suspicious model types
        if model_class in self.suspicious_layer_types:
            result.add_check(
                name="Model Type Security Check",
                passed=False,
                message=f"Suspicious model type: {model_class}",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={
                    "model_class": model_class,
                    "description": self.suspicious_layer_types.get(model_class, ""),
                },
            )

        # Get layers from config
        layers = []
        if "config" in model_config and isinstance(model_config["config"], dict):
            if "layers" in model_config["config"]:
                layers = model_config["config"]["layers"]
            elif "layer" in model_config["config"]:
                # Single layer model
                layers = [model_config["config"]["layer"]]

        # Count of each layer type
        layer_counts: dict[str, int] = {}

        # Check each layer
        for i, layer in enumerate(layers):
            if not isinstance(layer, dict):
                continue

            layer_class = layer.get("class_name", "")
            layer_name = layer.get("name", f"layer_{i}")

            # Update layer count
            layer_counts[layer_class] = layer_counts.get(layer_class, 0) + 1

            # Check for Lambda layers
            if layer_class == "Lambda":
                self._check_lambda_layer(layer, result, layer_name)
            elif layer_class in self.suspicious_layer_types:
                result.add_check(
                    name="Suspicious Layer Type Detection",
                    passed=False,
                    message=f"Suspicious layer type found: {layer_class}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_class": layer_class,
                        "layer_name": layer_name,
                        "description": self.suspicious_layer_types[layer_class],
                    },
                )

            # Check for custom objects
            if layer.get("registered_name"):
                result.add_check(
                    name="Custom Object Detection",
                    passed=False,
                    message=f"Custom registered object found: {layer['registered_name']}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_name": layer_name,
                        "registered_name": layer["registered_name"],
                    },
                )

            # Recursively check nested models
            if (
                layer_class in ["Model", "Functional", "Sequential"]
                and "config" in layer
                and isinstance(layer["config"], dict)
            ):
                self._scan_model_config(layer, result)

        # Add layer counts to metadata
        result.metadata["layer_counts"] = layer_counts

    def _check_lambda_layer(self, layer: dict[str, Any], result: ScanResult, layer_name: str) -> None:
        """Check Lambda layer for executable Python code"""
        layer_config = layer.get("config", {})

        # Lambda layers in Keras ZIP format store the function as a list
        # where the first element is base64-encoded Python code
        function_data = layer_config.get("function")

        if function_data and isinstance(function_data, list) and len(function_data) > 0:
            # First element is the base64-encoded function
            encoded_function = function_data[0]

            if encoded_function and isinstance(encoded_function, str):
                try:
                    # Decode the base64 function
                    decoded = base64.b64decode(encoded_function)
                    # Try to decode as string
                    decoded_str = decoded.decode("utf-8", errors="ignore")

                    # Check for dangerous patterns
                    dangerous_patterns = [
                        "exec",
                        "eval",
                        "__import__",
                        "compile",
                        "open",
                        "subprocess",
                        "os.system",
                        "os.popen",
                        "pickle",
                        "marshal",
                        "importlib",
                        "runpy",
                        "webbrowser",
                    ]

                    found_patterns = []
                    for pattern in dangerous_patterns:
                        if pattern in decoded_str.lower():
                            found_patterns.append(pattern)

                    if found_patterns:
                        result.add_issue(
                            message=f"Lambda layer '{layer_name}' contains dangerous code: {', '.join(found_patterns)}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} (layer: {layer_name})",
                            details={
                                "layer_name": layer_name,
                                "layer_class": "Lambda",
                                "dangerous_patterns": found_patterns,
                                "code_preview": (decoded_str[:200] + "..." if len(decoded_str) > 200 else decoded_str),
                                "encoding": "base64",
                            },
                            why=(
                                "Lambda layers can execute arbitrary Python code during model inference, "
                                "which poses a severe security risk."
                            ),
                        )
                    else:
                        # Check if it's valid Python code
                        is_valid, error = validate_python_syntax(decoded_str)
                        if is_valid:
                            # Valid Python but no obvious dangerous patterns
                            is_dangerous, risk_desc = is_code_potentially_dangerous(decoded_str, "low")
                            if is_dangerous:
                                result.add_check(
                                    name="Lambda Layer Code Analysis",
                                    passed=False,
                                    message=f"Lambda layer '{layer_name}' contains potentially dangerous code",
                                    severity=IssueSeverity.WARNING,
                                    location=f"{self.current_file_path} (layer: {layer_name})",
                                    details={
                                        "layer_name": layer_name,
                                        "layer_class": "Lambda",
                                        "code_analysis": risk_desc,
                                        "code_preview": (
                                            decoded_str[:200] + "..." if len(decoded_str) > 200 else decoded_str
                                        ),
                                    },
                                    why=get_pattern_explanation("lambda_layer"),
                                )
                            else:
                                result.add_check(
                                    name="Lambda Layer Code Analysis",
                                    passed=True,
                                    message=f"Lambda layer '{layer_name}' contains safe Python code",
                                    location=f"{self.current_file_path} (layer: {layer_name})",
                                    details={
                                        "layer_name": layer_name,
                                        "layer_class": "Lambda",
                                    },
                                )
                        else:
                            # Not valid Python - might be binary data
                            result.add_check(
                                name="Lambda Layer Detection",
                                passed=False,
                                message=f"Lambda layer '{layer_name}' contains encoded data (unable to validate)",
                                severity=IssueSeverity.WARNING,
                                location=f"{self.current_file_path} (layer: {layer_name})",
                                details={
                                    "layer_name": layer_name,
                                    "layer_class": "Lambda",
                                    "validation_error": error,
                                },
                                why="Lambda layers with encoded data may contain arbitrary code.",
                            )

                except Exception as e:
                    result.add_check(
                        name="Lambda Layer Decoding",
                        passed=False,
                        message=f"Failed to decode Lambda layer '{layer_name}' function",
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (layer: {layer_name})",
                        details={
                            "layer_name": layer_name,
                            "error": str(e),
                        },
                    )
        else:
            # Lambda layer without encoded function - check other fields
            module_name = layer_config.get("module")
            function_name = layer_config.get("function_name")

            if module_name or function_name:
                # Module/function reference - check for dangerous imports
                dangerous_modules = ["os", "sys", "subprocess", "eval", "exec", "__builtins__"]
                if module_name and any(dangerous in module_name for dangerous in dangerous_modules):
                    result.add_check(
                        name="Lambda Layer Module Reference Check",
                        passed=False,
                        message=f"Lambda layer '{layer_name}' references potentially dangerous module: {module_name}",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{self.current_file_path} (layer: {layer_name})",
                        details={
                            "layer_name": layer_name,
                            "module": module_name,
                            "function": function_name,
                        },
                        why=get_pattern_explanation("lambda_layer"),
                    )
