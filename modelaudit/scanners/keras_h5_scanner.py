import json
import os
from typing import Any, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import h5py, but handle the case where it's not installed
try:
    import h5py

    HAS_H5PY = True
except ImportError:
    HAS_H5PY = False

# Suspicious Keras layer types that might contain executable code
SUSPICIOUS_LAYER_TYPES = {
    "Lambda": "Can contain arbitrary Python code",
    "TFOpLambda": "Can call TensorFlow operations",
    "Functional": "Complex layer that might hide malicious components",
    "PyFunc": "Can execute Python code",
    "CallbackLambda": "Can execute callbacks at runtime",
}

# Suspicious config properties that might indicate security issues
SUSPICIOUS_CONFIG_PROPERTIES = [
    "function",
    "module",
    "code",
    "eval",
    "exec",
    "import",
    "subprocess",
    "os.",
    "system",
    "popen",
    "shell",
]


class KerasH5Scanner(BaseScanner):
    """Scanner for Keras H5 model files"""

    name = "keras_h5"
    description = "Scans Keras H5 model files for suspicious layer configurations"
    supported_extensions = [".h5", ".hdf5", ".keras"]

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
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        # Check if h5py is installed
        if not HAS_H5PY:
            result = self._create_result()
            result.add_issue(
                "h5py not installed, cannot scan Keras H5 files. Install with "
                "'pip install modelaudit[h5]'.",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            with h5py.File(path, "r") as f:
                result.bytes_scanned = file_size

                # Check if this is a Keras model file
                if "model_config" not in f.attrs:
                    result.add_issue(
                        "File does not appear to be a Keras model "
                        "(no model_config attribute)",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                    )
                    result.finish(success=True)  # Still success, just not a Keras file
                    return result

                # Parse model config
                model_config_str = f.attrs["model_config"]
                model_config = json.loads(model_config_str)

                # Scan model configuration
                self._scan_model_config(model_config, result)

                # Check for custom objects in the model
                if "custom_objects" in f.attrs:
                    result.add_issue(
                        "Model contains custom objects which could contain "
                        "arbitrary code",
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (model_config)",
                        details={"custom_objects": list(f.attrs["custom_objects"])},
                    )

                # Check for custom metrics
                if "training_config" in f.attrs:
                    training_config = json.loads(f.attrs["training_config"])
                    if "metrics" in training_config:
                        for metric in training_config["metrics"]:
                            if isinstance(metric, dict) and metric.get(
                                "class_name",
                            ) not in [
                                "Accuracy",
                                "CategoricalAccuracy",
                                "BinaryAccuracy",
                            ]:
                                result.add_issue(
                                    f"Model contains custom metric: "
                                    f"{metric.get('class_name', 'unknown')}",
                                    severity=IssueSeverity.WARNING,
                                    location=f"{self.current_file_path} (metrics)",
                                    details={"metric": metric},
                                )

        except Exception as e:
            result.add_issue(
                f"Error scanning Keras H5 file: {str(e)}",
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
        if not isinstance(model_config, dict):
            result.add_issue(
                "Invalid model configuration format",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
            )
            return

        # Check model class name
        model_class = model_config.get("class_name", "")
        result.metadata["model_class"] = model_class

        # Collect all layers
        layers = []
        if "config" in model_config and "layers" in model_config["config"]:
            layers = model_config["config"]["layers"]

        # Count of each layer type
        layer_counts: dict[str, int] = {}

        # Check each layer
        for layer in layers:
            layer_class = layer.get("class_name", "")

            # Update layer count
            if layer_class in layer_counts:
                layer_counts[layer_class] += 1
            else:
                layer_counts[layer_class] = 1

            # Check for suspicious layer types
            if layer_class in self.suspicious_layer_types:
                result.add_issue(
                    f"Suspicious layer type found: {layer_class}",
                    severity=IssueSeverity.CRITICAL,
                    location=self.current_file_path,
                    details={
                        "layer_class": layer_class,
                        "description": self.suspicious_layer_types[layer_class],
                        "layer_config": layer.get("config", {}),
                    },
                )

            # Check layer configuration for suspicious strings
            self._check_config_for_suspicious_strings(
                layer.get("config", {}),
                result,
                layer_class,
            )

            # If there are nested models, scan them recursively
            if (
                layer_class == "Model"
                and "config" in layer
                and "layers" in layer["config"]
            ):
                self._scan_model_config(layer, result)

        # Add layer counts to metadata
        result.metadata["layer_counts"] = layer_counts

    def _check_config_for_suspicious_strings(
        self,
        config: dict[str, Any],
        result: ScanResult,
        context: str = "",
    ) -> None:
        """Recursively check a configuration dictionary for suspicious strings"""
        if not isinstance(config, dict):
            return

        # Check all string values in the config
        for key, value in config.items():
            if isinstance(value, str):
                # Check for suspicious strings
                for suspicious_term in self.suspicious_config_props:
                    if suspicious_term in value.lower():
                        result.add_issue(
                            f"Suspicious configuration string found in {context}: "
                            f"'{suspicious_term}'",
                            severity=IssueSeverity.WARNING,
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
