import json
import os
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

# Try to import h5py, but handle the case where it's not installed
try:
    import h5py

    HAS_H5PY = True
except ImportError:
    HAS_H5PY = False


class KerasH5Scanner(BaseScanner):
    """Scanner for Keras H5 model files"""

    name = "keras_h5"
    description = "Scans Keras H5 model files for suspicious layer configurations"
    supported_extensions: ClassVar[list[str]] = [".h5", ".hdf5", ".keras"]

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
        if not HAS_H5PY:
            return False

        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Try to open as HDF5 file
        try:
            with h5py.File(path, "r") as _:
                return True
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a Keras model file for suspicious configurations"""
        # Initialize context for this file
        self._initialize_context(path)

        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        # Check if h5py is installed
        if not HAS_H5PY:
            result = self._create_result()
            result.add_check(
                name="H5PY Library Check",
                passed=False,
                message="h5py not installed, cannot scan Keras H5 files. Install with 'pip install modelaudit[h5]'.",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path, "required_package": "h5py"},
            )
            result.finish(success=False)
            return result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            with h5py.File(path, "r") as f:
                result.bytes_scanned = file_size

                # Check if this is a Keras model file
                if "model_config" not in f.attrs:
                    # Check if this might be a TensorFlow SavedModel H5 file instead
                    # Look for common TensorFlow H5 structure patterns
                    is_tensorflow_h5 = any(
                        key.startswith(
                            ("model_weights", "optimizer_weights", "variables"),
                        )
                        for key in f
                    )

                    if is_tensorflow_h5:
                        result.add_check(
                            name="Keras Model Format Check",
                            passed=True,
                            message="File is a TensorFlow H5 model, not Keras format",
                            location=self.current_file_path,
                            details={"format": "tensorflow_h5"},
                        )
                    else:
                        result.add_check(
                            name="Keras Model Format Check",
                            passed=True,
                            message="File does not appear to be a Keras model (no model_config attribute)",
                            location=self.current_file_path,
                            details={"format": "generic_h5"},
                        )
                    result.finish(success=True)  # Still success, just not a Keras file
                    return result

                # Parse model config
                model_config_str = f.attrs["model_config"]
                model_config = json.loads(model_config_str)

                # Scan model configuration
                if isinstance(model_config, dict):
                    self._scan_model_config(model_config, result)
                else:
                    result.add_check(
                        name="Model Config Type Validation",
                        passed=False,
                        message=f"Invalid model config type: expected dict, got {type(model_config).__name__}",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"actual_type": type(model_config).__name__, "expected_type": "dict"},
                    )

                # Check for custom objects in the model
                if "custom_objects" in f.attrs:
                    custom_objects_attr = f.attrs["custom_objects"]
                    custom_objects_list = list(custom_objects_attr) if custom_objects_attr is not None else []
                    result.add_check(
                        name="Custom Objects Security Check",
                        passed=False,
                        message="Model contains custom objects which could contain arbitrary code",
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (model_config)",
                        details={"custom_objects": custom_objects_list},
                    )

                # Check for custom metrics
                if "training_config" in f.attrs:
                    training_config = json.loads(f.attrs["training_config"])
                    if "metrics" in training_config and training_config["metrics"] is not None:
                        metrics_list = training_config["metrics"]
                        if not isinstance(metrics_list, (list, tuple)):
                            metrics_list = []
                        for metric in metrics_list:
                            if isinstance(metric, dict) and metric.get(
                                "class_name",
                            ) not in [
                                "Accuracy",
                                "CategoricalAccuracy",
                                "BinaryAccuracy",
                            ]:
                                result.add_check(
                                    name="Custom Metric Detection",
                                    passed=False,
                                    message=f"Model contains custom metric: {metric.get('class_name', 'unknown')}",
                                    severity=IssueSeverity.WARNING,
                                    location=f"{self.current_file_path} (metrics)",
                                    details={"metric": metric},
                                )

        except Exception as e:
            result.add_check(
                name="Keras H5 File Scan",
                passed=False,
                message=f"Error scanning Keras H5 file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _scan_model_config(
        self,
        model_config: dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Scan the model configuration for suspicious elements"""

        # Check model class name
        model_class = model_config.get("class_name", "")
        result.metadata["model_class"] = model_class

        # Collect all layers
        layers = []
        if "config" in model_config and "layers" in model_config["config"]:
            layers_value = model_config["config"]["layers"]
            if isinstance(layers_value, list):
                layers = layers_value
            else:
                result.add_check(
                    name="Layers Type Validation",
                    passed=False,
                    message=f"Invalid layers type: expected list, got {type(layers_value).__name__}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"actual_type": type(layers_value).__name__, "expected_type": "list"},
                )

        # Count of each layer type
        layer_counts: dict[str, int] = {}

        # Check each layer
        for layer in layers:
            if not isinstance(layer, dict):
                result.add_check(
                    name="Layer Type Validation",
                    passed=False,
                    message=f"Invalid layer type: expected dict, got {type(layer).__name__}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"actual_type": type(layer).__name__, "expected_type": "dict"},
                )
                continue
            layer_class = layer.get("class_name", "")

            # Update layer count
            if layer_class in layer_counts:
                layer_counts[layer_class] += 1
            else:
                layer_counts[layer_class] = 1

            # Check for suspicious layer types
            if layer_class in self.suspicious_layer_types:
                layer_config = layer.get("config", {})

                # Special handling for Lambda layers - validate Python code
                if layer_class == "Lambda":
                    self._check_lambda_layer(layer_config, result)
                else:
                    result.add_check(
                        name="Suspicious Layer Type Detection",
                        passed=False,
                        message=f"Suspicious layer type found: {layer_class}",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={
                            "layer_class": layer_class,
                            "description": self.suspicious_layer_types[layer_class],
                            "layer_config": layer_config,
                        },
                        why=get_pattern_explanation("lambda_layer") if layer_class == "Lambda" else None,
                    )

            # Check layer configuration for suspicious strings
            self._check_config_for_suspicious_strings(
                layer.get("config", {}),
                result,
                layer_class,
            )

            # If there are nested models, scan them recursively
            if layer_class == "Model" and "config" in layer and "layers" in layer["config"] and isinstance(layer, dict):
                self._scan_model_config(layer, result)

        # Add layer counts to metadata
        result.metadata["layer_counts"] = layer_counts

    def _check_lambda_layer(self, layer_config: dict[str, Any], result: ScanResult) -> None:
        """Check Lambda layer for executable Python code with validation"""
        import re

        # Lambda layers can contain Python code in several forms:
        # 1. As a string in 'function' field (serialized Python code)
        # 2. As a module + function reference
        # 3. As inline code

        # Extract potential Python code from Lambda config
        function_str = layer_config.get("function")
        module_name = layer_config.get("module")
        function_name = layer_config.get("function_name")

        # Common safe Lambda patterns for normalization
        SAFE_LAMBDA_PATTERNS = [
            r"lambda\s+x\s*:\s*x\s*/\s*\d+",  # lambda x: x / 255
            r"lambda\s+x\s*:\s*x\s*\*\s*\d+",  # lambda x: x * 2
            r"lambda\s+x\s*:\s*tf\.nn\.\w+\(x\)",  # lambda x: tf.nn.softmax(x)
            r"lambda\s+x\s*:\s*K\.\w+\(x",  # lambda x: K.softmax(x)
            r"lambda\s+x\s*:\s*\(x\s*-\s*\d+\)\s*/\s*\d+",  # lambda x: (x - 128) / 128
        ]

        # Check if there's actual Python code to validate
        if function_str and isinstance(function_str, str):
            # First check if it matches safe patterns
            is_safe_pattern = any(re.match(pattern, function_str.strip()) for pattern in SAFE_LAMBDA_PATTERNS)

            if is_safe_pattern:
                result.add_check(
                    name="Lambda Layer Code Analysis",
                    passed=True,
                    message="Lambda layer contains safe normalization pattern",
                    location=self.current_file_path,
                    details={
                        "layer_class": "Lambda",
                        "pattern_type": "safe_normalization",
                    },
                )
                return

            # This might be serialized Python code
            is_valid, error = validate_python_syntax(function_str)

            if is_valid:
                # It's valid Python! Check if it's dangerous
                is_dangerous, risk_desc = is_code_potentially_dangerous(function_str, "low")

                # Check if code is dangerous
                if is_dangerous:
                    result.add_check(
                        name="Lambda Layer Code Analysis",
                        passed=False,
                        message="Lambda layer contains dangerous Python code",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={
                            "layer_class": "Lambda",
                            "code_analysis": risk_desc,
                            "code_preview": function_str[:200] + "..." if len(function_str) > 200 else function_str,
                            "validation_status": "valid_python",
                        },
                        why=get_pattern_explanation("lambda_layer"),
                    )
                else:
                    # Valid Python but not dangerous - record as passed
                    result.add_check(
                        name="Lambda Layer Code Analysis",
                        passed=True,
                        message="Lambda layer contains safe Python code",
                        location=self.current_file_path,
                        details={
                            "layer_class": "Lambda",
                            "validation_status": "valid_python",
                        },
                    )
            else:
                # Not valid Python syntax - might be a configuration issue
                # Only flag if it looks like attempted code execution
                if any(keyword in str(layer_config) for keyword in ["eval", "exec", "compile", "__import__"]):
                    result.add_check(
                        name="Lambda Layer Suspicious Keywords Check",
                        passed=False,
                        message="Lambda layer contains suspicious configuration",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={
                            "layer_class": "Lambda",
                            "description": self.suspicious_layer_types["Lambda"],
                            "layer_config": layer_config,
                            "validation_error": error,
                        },
                        why=get_pattern_explanation("lambda_layer"),
                    )
        elif module_name or function_name:
            # Module/function reference - check for dangerous imports
            dangerous_modules = ["os", "sys", "subprocess", "eval", "exec", "__builtins__"]
            if module_name and any(dangerous in module_name for dangerous in dangerous_modules):
                result.add_check(
                    name="Lambda Layer Module Reference Check",
                    passed=False,
                    message=f"Lambda layer references potentially dangerous module: {module_name}",
                    severity=IssueSeverity.CRITICAL,
                    location=self.current_file_path,
                    details={
                        "layer_class": "Lambda",
                        "module": module_name,
                        "function": function_name,
                    },
                    why=get_pattern_explanation("lambda_layer"),
                )
            else:
                # Safe module reference - record as passed
                result.add_check(
                    name="Lambda Layer Module Reference Check",
                    passed=True,
                    message="Lambda layer module references are safe",
                    location=self.current_file_path,
                    details={
                        "layer_class": "Lambda",
                        "module": module_name,
                        "function": function_name,
                    },
                )
        # Don't flag Lambda layers without code - they might just be placeholders

    def _check_config_for_suspicious_strings(
        self,
        config: Any,
        result: ScanResult,
        context: str = "",
    ) -> None:
        """Recursively check a configuration dictionary for suspicious strings"""

        # Validate config is actually a dict
        if not isinstance(config, dict):
            return

        # Check all string values in the config
        for key, value in config.items():
            if isinstance(value, str):
                # Check for suspicious strings
                for suspicious_term in self.suspicious_config_props:
                    if suspicious_term in value.lower():
                        result.add_check(
                            name="Suspicious Configuration String Check",
                            passed=False,
                            message=f"Suspicious configuration string found in {context}: '{suspicious_term}'",
                            severity=IssueSeverity.INFO,
                            location=f"{self.current_file_path} ({context})",
                            details={
                                "suspicious_term": suspicious_term,
                                "context": context,
                            },
                        )
            elif isinstance(value, dict):
                # Recursively check nested dictionaries
                self._check_config_for_suspicious_strings(
                    value,
                    result,
                    f"{context}.{key}",
                )
            elif isinstance(value, list):
                # Check each item in the list
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self._check_config_for_suspicious_strings(
                            item,
                            result,
                            f"{context}.{key}[{i}]",
                        )
