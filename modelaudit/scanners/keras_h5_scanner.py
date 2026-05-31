"""Scanner for Keras HDF5 model files (.h5, .keras, .hdf5)."""

import json
import os
import re
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, ClassVar

from modelaudit.detectors.suspicious_symbols import (
    SUSPICIOUS_CONFIG_PROPERTIES,
    SUSPICIOUS_LAYER_TYPES,
)
from modelaudit.utils.helpers.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)

from ..config.explanations import (
    get_cve_2024_3660_explanation,
    get_cve_2025_9905_explanation,
    get_cve_2026_1669_explanation,
    get_pattern_explanation,
)
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult
from .keras_utils import (
    check_custom_loss_config,
    check_custom_metric_config,
    check_lambda_dict_function,
    check_subclassed_model,
    is_known_safe_keras_layer_class,
)

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
    _JSON_ATTRIBUTE_PARSE_FAILED: ClassVar[object] = object()
    _SAFE_LAMBDA_PATTERNS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"^lambda\s+x\s*:\s*x\s*/\s*\d+$"),
        re.compile(r"^lambda\s+x\s*:\s*x\s*\*\s*\d+$"),
        re.compile(r"^lambda\s+x\s*:\s*tf\.nn\.\w+\(x\)$"),
        re.compile(r"^lambda\s+x\s*:\s*K\.\w+\(x\)$"),
        re.compile(r"^lambda\s+x\s*:\s*\(x\s*-\s*\d+\)\s*/\s*\d+$"),
    )
    _DANGEROUS_LAMBDA_MODULE_TOKENS: ClassVar[frozenset[str]] = frozenset(
        {
            "__builtin__",
            "__builtins__",
            "builtins",
            "ctypes",
            "importlib",
            "marshal",
            "nt",
            "operator",
            "os",
            "pickle",
            "posix",
            "runpy",
            "socket",
            "subprocess",
            "sys",
        }
    )
    _DANGEROUS_LAMBDA_FUNCTION_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "__import__",
            "attrgetter",
            "compile",
            "eval",
            "exec",
            "open",
            "popen",
            "spawn",
            "system",
        }
    )
    _KERAS_WEIGHT_ROOT_GROUPS: ClassVar[frozenset[str]] = frozenset({"model_weights", "optimizer_weights"})
    _KERAS_WEIGHT_ROOT_ATTRS: ClassVar[frozenset[str]] = frozenset({"layer_names", "weight_names"})
    _MODEL_CONTAINER_CLASSES: ClassVar[frozenset[str]] = frozenset({"Model", "Functional", "Sequential"})
    _WRAPPED_LAYER_SCAN_MODEL: ClassVar[dict[str, Any]] = {"class_name": "Sequential", "config": {"layers": []}}

    def __init__(self, config: dict[str, Any] | None = None):
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

        if not HAS_H5PY:
            try:
                with open(path, "rb") as handle:
                    return handle.read(8) == b"\x89HDF\r\n\x1a\n"
            except OSError:
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
                message="h5py is required for Keras H5 scanning. Install with 'pip install modelaudit[h5]'.",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"path": path, "required_package": "h5py"},
                rule_code="S902",
            )
            result.finish(success=True)
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
                keras_version_attr = f.attrs.get("keras_version")
                if isinstance(keras_version_attr, bytes):
                    keras_version_attr = keras_version_attr.decode("utf-8", errors="ignore")
                if isinstance(keras_version_attr, str) and keras_version_attr.strip():
                    result.metadata["keras_version"] = keras_version_attr.strip()

                # CVE-2026-1669 applies to weight loading too. Inspect full
                # Keras files and weights-like HDF5 layouts while leaving
                # unrelated generic HDF5 artifacts quiet.
                if "model_config" in f.attrs or self._has_weights_like_hdf5_layout(f, path):
                    self._check_hdf5_external_references(f, result, path)

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
                            rule_code=None,  # Passing check
                        )
                    else:
                        result.add_check(
                            name="Keras Model Format Check",
                            passed=True,
                            message="File does not appear to be a Keras model (no model_config attribute)",
                            location=self.current_file_path,
                            details={"format": "generic_h5"},
                            rule_code=None,  # Passing check
                        )
                    result.finish(success=True)  # Still success, just not a Keras file
                    return result

                # Parse model config
                model_config = self._load_json_attribute(f.attrs["model_config"], result, "model_config")

                # Scan model configuration
                if model_config is self._JSON_ATTRIBUTE_PARSE_FAILED:
                    pass
                elif isinstance(model_config, dict):
                    self._scan_model_config(model_config, result)
                else:
                    self._mark_inconclusive_scan_result(result, "keras_h5_model_config_invalid_type")
                    result.add_check(
                        name="Model Config Type Validation",
                        passed=False,
                        message=f"Invalid model config type: expected dict, got {type(model_config).__name__}",
                        severity=IssueSeverity.INFO,
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
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path} (model_config)",
                        rule_code="S302",
                        details={"custom_objects": custom_objects_list},
                    )

                # Check for custom metrics and custom loss
                if "training_config" in f.attrs:
                    training_config = self._load_json_attribute(f.attrs["training_config"], result, "training_config")
                    if training_config is not self._JSON_ATTRIBUTE_PARSE_FAILED:
                        self._scan_training_config(training_config, result)

        except OSError as e:
            self._mark_inconclusive_scan_result(result, "keras_h5_read_failed")
            result.add_check(
                name="Keras H5 File Read",
                passed=False,
                message=f"Unable to read Keras H5 content: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_h5_read_failed",
                },
                rule_code="S902",
            )
            self._finish_scan_result(result)
            return result
        except Exception as e:
            self._mark_inconclusive_scan_result(result, "keras_h5_scan_failed")
            result.add_check(
                name="Keras H5 File Scan",
                passed=False,
                message=f"Error scanning Keras H5 file: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_h5_scan_failed",
                },
                rule_code="S902",
            )
            self._finish_scan_result(result)
            return result

        self._finish_scan_result(result)
        return result

    @staticmethod
    def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
        """Mark the scan as incomplete without converting it into a security finding."""
        existing_reasons = result.metadata.get("scan_outcome_reasons")
        reasons = existing_reasons if isinstance(existing_reasons, list) else []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = reasons
        result.metadata["analysis_incomplete"] = True

    @staticmethod
    def _scan_result_has_security_findings(result: ScanResult) -> bool:
        """Return True when the scan found warning or critical security risk."""
        return any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    @classmethod
    def _finish_scan_result(cls, result: ScanResult) -> None:
        """Fail closed on incomplete/no-finding scans while preserving security precedence."""
        is_inconclusive = result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        has_security_findings = cls._scan_result_has_security_findings(result)
        if is_inconclusive and not has_security_findings:
            result.finish(success=False)
            return

        result.finish(success=not result.has_errors)

    def _load_json_attribute(self, attr_value: Any, result: ScanResult, attr_name: str) -> Any:
        """Load a Keras JSON attribute, marking the scan incomplete on malformed metadata."""
        try:
            if isinstance(attr_value, bytes):
                attr_value = attr_value.decode("utf-8")
            return json.loads(attr_value)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as e:
            self._mark_inconclusive_scan_result(result, f"keras_h5_{attr_name}_parse_failed")
            result.add_check(
                name="Keras H5 Config Parse",
                passed=False,
                message=f"Malformed Keras H5 {attr_name}; static scan could not inspect this configuration",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "attribute": attr_name,
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            return self._JSON_ATTRIBUTE_PARSE_FAILED

    @classmethod
    def _has_weights_like_hdf5_layout(cls, h5_file: Any, path: str) -> bool:
        """Return True for HDF5 layouts that resemble Keras weights-only files."""
        if any(str(key).lower() in cls._KERAS_WEIGHT_ROOT_GROUPS for key in h5_file):
            return True

        if cls._has_legacy_weights_layout(h5_file):
            return True

        return Path(path).name.lower().endswith(".weights.h5") and cls._has_keras3_weights_layout(h5_file)

    @classmethod
    def _has_legacy_weights_layout(cls, h5_file: Any) -> bool:
        layer_names = cls._decode_hdf5_names(h5_file.attrs.get("layer_names"))
        if not layer_names:
            return False

        for layer_name in layer_names:
            link = h5_file.get(layer_name, getlink=True)
            if isinstance(link, h5py.ExternalLink):
                return True
            if not isinstance(link, h5py.HardLink):
                continue

            layer = h5_file.get(layer_name, getlink=False)
            if isinstance(layer, h5py.Group) and "weight_names" in layer.attrs:
                return True

        return False

    @classmethod
    def _has_keras3_weights_layout(cls, h5_file: Any) -> bool:
        """Detect Keras 3 H5IOStore weights-only layouts without generic HDF5 overreach."""
        if cls._has_group_or_external_link(h5_file, "vars"):
            return True

        layers_link = h5_file.get("layers", getlink=True)
        if isinstance(layers_link, h5py.ExternalLink):
            return True
        if not isinstance(layers_link, h5py.HardLink):
            return False

        layers = h5_file.get("layers", getlink=False)
        if not isinstance(layers, h5py.Group):
            return False

        for layer_name in layers:
            layer_link = layers.get(layer_name, getlink=True)
            if isinstance(layer_link, h5py.ExternalLink):
                return True
            if not isinstance(layer_link, h5py.HardLink):
                continue

            layer = layers.get(layer_name, getlink=False)
            if isinstance(layer, h5py.Group) and cls._has_group_or_external_link(layer, "vars"):
                return True

        return False

    @staticmethod
    def _has_group_or_external_link(group: Any, name: str) -> bool:
        link = group.get(name, getlink=True)
        if isinstance(link, h5py.ExternalLink):
            return True
        if not isinstance(link, h5py.HardLink):
            return False
        return isinstance(group.get(name, getlink=False), h5py.Group)

    @staticmethod
    def _decode_hdf5_names(value: Any) -> list[str]:
        if value is None:
            return []
        if hasattr(value, "tolist"):
            value = value.tolist()
        if isinstance(value, bytes):
            return [value.decode("utf-8", errors="ignore")]
        if isinstance(value, str):
            return [value]

        try:
            items = list(value)
        except TypeError:
            items = [value]

        names = []
        for item in items:
            if isinstance(item, bytes):
                names.append(item.decode("utf-8", errors="ignore"))
            elif isinstance(item, str):
                names.append(item)
        return [name for name in names if name]

    def _check_hdf5_external_references(self, h5_file: Any, result: ScanResult, source_path: str) -> None:
        """Detect HDF5 external links/storage before any Keras-specific parsing short-circuits."""
        findings: list[dict[str, Any]] = []

        def visit(name: str, link: Any) -> None:
            if isinstance(link, h5py.ExternalLink):
                findings.append(
                    {
                        "kind": "ExternalLink",
                        "hdf5_path": f"/{name}".replace("//", "/"),
                        "filename": link.filename,
                        "path": link.path,
                    },
                )
                return

            if not isinstance(link, h5py.HardLink):
                return

            obj = h5_file.get(name, getlink=False)
            if isinstance(obj, h5py.Dataset):
                external_storage = obj.external
                if external_storage:
                    findings.append(
                        {
                            "kind": "external_storage",
                            "hdf5_path": f"/{name}".replace("//", "/"),
                            "segments": [
                                {"filename": filename, "offset": int(offset), "size": int(size)}
                                for filename, offset, size in external_storage
                            ],
                        },
                    )

        self._visit_hdf5_links(h5_file, visit)

        if not findings:
            return

        keras_version = result.metadata.get("keras_version")
        location = f"{source_path} (weights)"
        details = {
            "cve_id": "CVE-2026-1669",
            "cvss": 8.1,
            "cwe": "CWE-200, CWE-73",
            "description": (
                "HDF5 external storage or ExternalLink entries can cause Keras weight loading to read arbitrary "
                "host files into model tensors."
            ),
            "remediation": "Upgrade to Keras >= 3.12.1 or >= 3.13.2 and reject weights using HDF5 external references.",
            "external_references": findings,
        }

        vuln_status = self._is_vulnerable_to_cve_2026_1669(keras_version) if isinstance(keras_version, str) else None
        if vuln_status is True:
            details["keras_version"] = keras_version
            result.add_check(
                name="CVE-2026-1669: HDF5 External Weight Reference",
                passed=False,
                message=(
                    f"CVE-2026-1669: Keras {keras_version} weight file uses HDF5 external references that can "
                    "disclose arbitrary local file contents during model loading"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2026_1669_explanation("hdf5_external_reference"),
            )
            return

        if isinstance(keras_version, str):
            details["keras_version"] = keras_version
            if vuln_status is False:
                details["parse_status"] = "untrusted_artifact_version"
                details["version_source"] = "hdf5_file_attribute"
                result.add_check(
                    name="HDF5 External Weight Reference Risk (Untrusted Version Metadata)",
                    passed=False,
                    message=(
                        "HDF5 external references detected in standalone Keras H5 weights; "
                        f"the file claims Keras {keras_version}, but artifact-controlled version metadata "
                        "cannot prove the loader runtime is outside the CVE-2026-1669 vulnerable ranges"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=location,
                    details=details
                    | {
                        "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
                    },
                    why=get_cve_2026_1669_explanation("hdf5_external_reference"),
                )
                return

        result.add_check(
            name="HDF5 External Weight Reference Risk (Version Unknown)",
            passed=False,
            message=(
                "HDF5 external references detected in weights, but "
                f"{self._format_keras_version_context(keras_version)}; cannot confidently attribute "
                "CVE-2026-1669 without reliable version context"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details=details
            | {
                "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
                "parse_status": "unknown",
            },
        )

    @staticmethod
    def _visit_hdf5_links(h5_file: Any, visit: Callable[[str, Any], None]) -> None:
        """Visit links without resolving external targets on every supported h5py version."""
        if hasattr(h5_file, "visititems_links"):
            h5_file.visititems_links(visit)
            return

        visited_group_ids = {h5_file.id}

        def walk(group: Any, prefix: str = "") -> None:
            for child_name in group:
                path = f"{prefix}/{child_name}" if prefix else str(child_name)
                link = group.get(child_name, getlink=True)
                visit(path, link)
                if not isinstance(link, h5py.HardLink):
                    continue

                obj = group.get(child_name, getlink=False)
                if not isinstance(obj, h5py.Group) or obj.id in visited_group_ids:
                    continue

                visited_group_ids.add(obj.id)
                walk(obj, path)

        walk(h5_file)

    def _scan_training_config(self, training_config: Any, result: ScanResult) -> None:
        """Inspect training_config for custom metrics and losses."""
        if not isinstance(training_config, dict):
            self._mark_inconclusive_scan_result(result, "keras_h5_training_config_invalid_type")
            result.add_check(
                name="Training Config Type Validation",
                passed=False,
                message=f"Invalid training config type: expected dict, got {type(training_config).__name__}",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path} (training_config)",
                details={"actual_type": type(training_config).__name__, "expected_type": "dict"},
                rule_code="S902",
            )
            return

        self._check_custom_metric_config(training_config.get("metrics"), result, "training_config.metrics")
        self._check_custom_metric_config(
            training_config.get("weighted_metrics"),
            result,
            "training_config.weighted_metrics",
        )
        self._check_custom_loss_config(training_config.get("loss"), result, "training_config.loss")

    def _check_custom_metric_config(self, metrics_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom metrics embedded anywhere in a serialized metric tree."""
        check_custom_metric_config(metrics_config, result, f"{self.current_file_path} ({context})")

    def _check_custom_loss_config(self, loss_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom losses embedded anywhere in a serialized loss tree."""
        check_custom_loss_config(loss_config, result, f"{self.current_file_path} ({context})")

    def _scan_model_config(
        self,
        model_config: dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Scan the model configuration for suspicious elements"""

        # Check model class name
        model_class = model_config.get("class_name", "")
        result.metadata["model_class"] = model_class

        # Check for subclassed models (custom class names)
        check_subclassed_model(model_class, result, self.current_file_path)

        # Collect all layers
        layers = []
        config_value = model_config.get("config")
        if config_value is None:
            if model_class in self._MODEL_CONTAINER_CLASSES:
                self._mark_inconclusive_scan_result(result, "keras_h5_model_layers_missing")
                result.add_check(
                    name="Layers Presence Validation",
                    passed=False,
                    message=f"Model config for {model_class} is missing required layers list",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"model_class": model_class, "expected_key": "config.layers"},
                )
            else:
                result.add_check(
                    name="Model Config Structure Validation",
                    passed=True,
                    message="Keras model config has no layer configuration",
                    location=self.current_file_path,
                    details={"model_class": model_class},
                )
        elif not isinstance(config_value, dict):
            self._mark_inconclusive_scan_result(result, "keras_h5_model_config_structure_invalid")
            result.add_check(
                name="Model Config Structure Validation",
                passed=False,
                message=f"Invalid model config.config type: expected dict, got {type(config_value).__name__}",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"actual_type": type(config_value).__name__, "expected_type": "dict"},
            )
        elif "layers" in config_value:
            layers_value = config_value["layers"]
            if isinstance(layers_value, list):
                layers = layers_value
            else:
                self._mark_inconclusive_scan_result(result, "keras_h5_model_layers_invalid_type")
                result.add_check(
                    name="Layers Type Validation",
                    passed=False,
                    message=f"Invalid layers type: expected list, got {type(layers_value).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"actual_type": type(layers_value).__name__, "expected_type": "list"},
                )
        elif model_class in self._MODEL_CONTAINER_CLASSES:
            self._mark_inconclusive_scan_result(result, "keras_h5_model_layers_missing")
            result.add_check(
                name="Layers Presence Validation",
                passed=False,
                message=f"Model config for {model_class} is missing required layers list",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"model_class": model_class, "expected_key": "config.layers"},
            )

        # Count of each layer type
        layer_counts: dict[str, int] = {}

        # Check each layer
        for layer in layers:
            if not isinstance(layer, dict):
                self._mark_inconclusive_scan_result(result, "keras_h5_model_layer_invalid_type")
                result.add_check(
                    name="Layer Type Validation",
                    passed=False,
                    message=f"Invalid layer type: expected dict, got {type(layer).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"actual_type": type(layer).__name__, "expected_type": "dict"},
                )
                continue
            layer_class = layer.get("class_name", "")
            layer_config = layer.get("config", {})
            if not isinstance(layer_config, dict):
                self._mark_inconclusive_scan_result(result, "keras_h5_layer_config_invalid_type")
                result.add_check(
                    name="Layer Config Type Validation",
                    passed=False,
                    message=f"Invalid layer config type: expected dict, got {type(layer_config).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"actual_type": type(layer_config).__name__, "expected_type": "dict"},
                )
                layer_config = {}

            # Update layer count
            if layer_class in layer_counts:
                layer_counts[layer_class] += 1
            else:
                layer_counts[layer_class] = 1

            # Check for suspicious layer types
            is_lambda_layer = self._is_lambda_layer_class(layer_class)
            if layer_class in self.suspicious_layer_types or is_lambda_layer:
                # Special handling for Lambda layers - validate Python code
                if is_lambda_layer:
                    raw_layer_name = layer.get("name")
                    if not raw_layer_name and isinstance(layer_config, dict):
                        raw_layer_name = layer_config.get("name")
                    layer_name = raw_layer_name or f"lambda_{layer_counts.get('Lambda', 1)}"
                    self._check_lambda_layer(layer_config, result)
                    keras_version = result.metadata.get("keras_version")

                    # CVE-2024-3660: Lambda layers enable arbitrary code injection
                    cve_2024_3660_status = (
                        self._is_vulnerable_to_cve_2024_3660(keras_version) if isinstance(keras_version, str) else None
                    )
                    if cve_2024_3660_status is True:
                        result.add_check(
                            name="CVE-2024-3660: Lambda Layer Code Injection",
                            passed=False,
                            message=(
                                f"CVE-2024-3660: Lambda layer '{layer_name}' in Keras {keras_version} enables "
                                "arbitrary code injection during model loading"
                            ),
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} (layer: {layer_name})",
                            details={
                                "layer_name": layer_name,
                                "layer_class": "Lambda",
                                "keras_version": keras_version,
                                "cve_id": "CVE-2024-3660",
                                "cvss": 9.8,
                                "cwe": "CWE-94",
                                "description": "Lambda layer deserialization can enable arbitrary code injection.",
                                "remediation": "Remove Lambda layers or upgrade Keras to >= 2.13",
                            },
                            why=get_cve_2024_3660_explanation("lambda_code_injection"),
                        )
                    elif cve_2024_3660_status is None:
                        result.add_check(
                            name="Lambda Layer Code Injection Risk (Version Unknown)",
                            passed=False,
                            message=(
                                f"Lambda layer '{layer_name}' detected in H5 model but "
                                f"{self._format_keras_version_context(keras_version)}; cannot confidently "
                                "attribute CVE-2024-3660 without reliable version context"
                            ),
                            severity=IssueSeverity.WARNING,
                            location=f"{self.current_file_path} (layer: {layer_name})",
                            details={
                                "layer_name": layer_name,
                                "layer_class": "Lambda",
                                "keras_version": keras_version,
                                "parse_status": "unknown",
                                "cve_id": "CVE-2024-3660",
                                "cvss": 9.8,
                                "cwe": "CWE-94",
                                "description": "Lambda layer deserialization can enable arbitrary code injection.",
                                "affected_versions": "Keras < 2.13",
                                "remediation": "Remove Lambda layers or upgrade Keras to >= 2.13",
                            },
                        )

                    # CVE-2025-9905: safe_mode=True is silently ignored for H5 format
                    vuln_status = (
                        self._is_vulnerable_to_cve_2025_9905(keras_version) if isinstance(keras_version, str) else None
                    )
                    if vuln_status is True:
                        result.add_check(
                            name="CVE-2025-9905: H5 safe_mode Bypass",
                            passed=False,
                            message=(
                                f"CVE-2025-9905: Lambda layer '{layer_name}' in H5 format with Keras {keras_version} - "
                                "safe_mode=True is silently ignored for .h5/.hdf5 files"
                            ),
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} (layer: {layer_name})",
                            details={
                                "layer_class": "Lambda",
                                "layer_name": layer_name,
                                "keras_version": keras_version,
                                "cve_id": "CVE-2025-9905",
                                "cvss": 7.3,
                                "cwe": "CWE-693",
                                "description": (
                                    "Keras H5 format can ignore safe_mode=True for Lambda layers, "
                                    "allowing arbitrary code execution during model load."
                                ),
                                "affected_versions": "Keras >= 3.0.0, < 3.11.3",
                                "remediation": "Upgrade Keras to >= 3.11.3 or convert to .keras format",
                            },
                            why=get_cve_2025_9905_explanation("h5_safe_mode_bypass"),
                        )
                    elif vuln_status is False:
                        result.add_check(
                            name="H5 Lambda Version Risk Check",
                            passed=True,
                            message=(
                                f"Lambda layer '{layer_name}' detected with Keras {keras_version}; "
                                "outside known CVE-2025-9905 vulnerable range (>=3.0.0, <3.11.3)"
                            ),
                            location=f"{self.current_file_path} (layer: {layer_name})",
                            details={"layer_class": "Lambda", "layer_name": layer_name, "keras_version": keras_version},
                        )
                    elif vuln_status is None:
                        version_context = (
                            self._format_keras_version_context(keras_version)
                            if isinstance(keras_version, str)
                            else "keras_version is unavailable"
                        )
                        result.add_check(
                            name="H5 Lambda Risk (Version Unknown)",
                            passed=False,
                            message=(
                                f"Lambda layer '{layer_name}' detected in H5 model but "
                                f"{version_context}; cannot confidently attribute "
                                "CVE-2025-9905 without reliable version context"
                            ),
                            severity=IssueSeverity.WARNING,
                            location=f"{self.current_file_path} (layer: {layer_name})",
                            details={
                                "layer_class": "Lambda",
                                "layer_name": layer_name,
                                "keras_version": keras_version,
                                "parse_status": "unknown",
                                "cve_id": "CVE-2025-9905",
                                "cvss": 7.3,
                                "cwe": "CWE-693",
                                "description": (
                                    "Keras H5 format can ignore safe_mode=True for Lambda layers; "
                                    "version context could not be parsed confidently."
                                ),
                                "affected_versions": "Keras >= 3.0.0, < 3.11.3",
                                "remediation": "Upgrade Keras to >= 3.11.3 or convert to .keras format",
                            },
                        )
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
                        why=get_pattern_explanation("lambda_layer") if is_lambda_layer else None,
                        rule_code="S902",
                    )

            # Detect unknown/custom layer classes not in the standard Keras set
            elif layer_class and not is_known_safe_keras_layer_class(layer_class):
                result.add_check(
                    name="Custom Layer Class Detection",
                    passed=False,
                    message=f"Unknown/custom layer class detected: {layer_class}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "layer_class": layer_class,
                        "layer_config": layer.get("config", {}),
                        "risk": "Custom layer classes require external code to load and may execute arbitrary logic",
                    },
                    rule_code="S810",
                )

            # Check layer configuration for suspicious strings
            self._check_config_for_suspicious_strings(
                layer_config,
                result,
                layer_class,
            )

            # If there are nested models, scan them recursively
            if layer_class in self._MODEL_CONTAINER_CLASSES and "config" in layer:
                nested_config = layer.get("config")
                if isinstance(nested_config, dict) and "layers" in nested_config:
                    self._scan_model_config(layer, result)
                elif isinstance(nested_config, dict):
                    self._mark_inconclusive_scan_result(result, "keras_h5_nested_model_layers_missing")
                    result.add_check(
                        name="Nested Model Layers Presence Validation",
                        passed=False,
                        message=f"Nested model config for {layer_class} is missing required layers list",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"layer_class": layer_class, "expected_key": "config.layers"},
                    )

            self._scan_wrapped_layer_config(layer_config, result)

        # Add layer counts to metadata
        result.metadata["layer_counts"] = layer_counts

    def _scan_wrapped_layer_config(self, layer_config: Any, result: ScanResult) -> None:
        """Scan wrapper-owned nested layer payloads such as `TimeDistributed.config.layer`."""
        if not isinstance(layer_config, dict) or "layer" not in layer_config:
            return

        nested_layer = layer_config.get("layer")
        if isinstance(nested_layer, dict):
            synthetic_model_config = {
                "class_name": self._WRAPPED_LAYER_SCAN_MODEL["class_name"],
                "config": {"layers": [nested_layer]},
            }
            self._scan_model_config(synthetic_model_config, result)
            return

        self._mark_inconclusive_scan_result(result, "keras_h5_wrapped_layer_invalid_type")
        result.add_check(
            name="Wrapped Layer Type Validation",
            passed=False,
            message=f"Invalid wrapped layer type: expected dict, got {type(nested_layer).__name__}",
            rule_code="S902",
            severity=IssueSeverity.INFO,
            location=self.current_file_path,
            details={"actual_type": type(nested_layer).__name__, "expected_type": "dict"},
        )

    def _check_lambda_layer(self, layer_config: dict[str, Any], result: ScanResult) -> None:
        """Check Lambda layer for executable Python code with validation"""
        # Lambda layers can contain Python code in several forms:
        # 1. As a string in 'function' field (serialized Python code)
        # 2. As a module + function reference
        # 3. As inline code

        # Extract potential Python code from Lambda config
        function_str = layer_config.get("function")
        module_name = layer_config.get("module")
        function_name = layer_config.get("function_name")

        # Check if there's actual Python code to validate
        if function_str and isinstance(function_str, str):
            # First check if it matches safe patterns
            is_safe_pattern = any(pattern.match(function_str.strip()) for pattern in self._SAFE_LAMBDA_PATTERNS)

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
                    rule_code=None,  # Passing check
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
                        },
                        rule_code="S507",  # Python embedded code
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
                        rule_code=None,  # Passing check
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
                        rule_code="S1103",
                    )
        elif module_name or function_name:
            # Module/function reference - check for dangerous imports
            if self._is_lambda_module_reference_dangerous(module_name, function_name):
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
                    rule_code="S1103",
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
                    rule_code=None,  # Passing check
                )
        elif isinstance(function_str, dict):
            # Keras 3.x dict-format Lambda: {"class_name": "__lambda__", "config": {"code": ...}}
            check_lambda_dict_function(function_str, result, self.current_file_path, layer_config.get("name", "lambda"))
        # Don't flag Lambda layers without code - they might just be placeholders

    @staticmethod
    def _is_lambda_layer_class(layer_class: Any) -> bool:
        """Return True for serialized Lambda variants such as `keras.layers.Lambda`."""
        if not isinstance(layer_class, str):
            return False

        normalized = layer_class.strip()
        if normalized == "Lambda":
            return True

        module_path, _, class_name = normalized.rpartition(".")
        if class_name != "Lambda":
            return False

        framework_prefixes = (
            "keras.",
            "tensorflow.keras.",
            "tensorflow.python.keras.",
            "tf.keras.",
            "tf_keras.",
        )
        return any(f"{module_path.lower()}.".startswith(prefix) for prefix in framework_prefixes)

    @staticmethod
    def _is_vulnerable_to_cve_2024_3660(version: str) -> bool | None:
        """Return True/False for parseable Keras versions, else None.

        Handles two-part versions (e.g. "2.10") by treating missing patch as 0.
        """
        parsed_version = KerasH5Scanner._parse_keras_version_components(version)
        if parsed_version is None:
            return None

        version_tuple, is_prerelease = parsed_version
        return version_tuple < (2, 13, 0) or (version_tuple == (2, 13, 0) and is_prerelease)

    @staticmethod
    def _is_vulnerable_to_cve_2026_1669(version: str) -> bool | None:
        """Return True/False for parseable Keras versions, else None."""
        parsed_version = KerasH5Scanner._parse_keras_version_components(version)
        if parsed_version is None:
            return None

        version_tuple, is_prerelease = parsed_version
        return (
            (3, 0, 0) <= version_tuple < (3, 12, 1)
            or (version_tuple == (3, 12, 1) and is_prerelease)
            or (3, 13, 0) <= version_tuple < (3, 13, 2)
            or (version_tuple == (3, 13, 2) and is_prerelease)
        )

    @staticmethod
    def _format_keras_version_context(keras_version: Any) -> str:
        if isinstance(keras_version, str):
            return f"keras_version '{keras_version}' is non-canonical"
        return "keras_version is unavailable"

    @staticmethod
    def _is_vulnerable_to_cve_2025_9905(version: str) -> bool | None:
        """Return True/False for parseable Keras versions, else None."""
        parsed_version = KerasH5Scanner._parse_keras_version_components(version)
        if parsed_version is None:
            return None

        version_tuple, is_prerelease = parsed_version
        if version_tuple[0] != 3 or version_tuple < (3, 0, 0):
            return False

        fix_version = (3, 11, 3)
        return version_tuple < fix_version or (version_tuple == fix_version and is_prerelease)

    @staticmethod
    def _parse_keras_version_components(version: str) -> tuple[tuple[int, int, int], bool] | None:
        """Parse a Keras version and preserve prerelease status for fix-boundary comparisons."""
        version_match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(.*)$", version.strip())
        if not version_match:
            return None

        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        patch = int(version_match.group(3) or "0")
        suffix = (version_match.group(4) or "").strip().lower()

        if not suffix:
            return (major, minor, patch), False

        if re.search(r"(?:^|[.\-])(dev|rc|a|b|alpha|beta|pre|preview)\d*", suffix):
            return (major, minor, patch), True

        if suffix.startswith("+") or suffix.startswith(".post") or suffix.startswith("post"):
            return (major, minor, patch), False

        return None

    @classmethod
    def _is_lambda_module_reference_dangerous(cls, module_name: Any, function_name: Any) -> bool:
        """Return True when a Lambda module/function reference resolves to a risky symbol."""
        if isinstance(function_name, str) and function_name.strip().lower() in cls._DANGEROUS_LAMBDA_FUNCTION_NAMES:
            return True

        if not isinstance(module_name, str):
            return False

        module_tokens = {token.strip().lower() for token in re.split(r"[^0-9A-Za-z_]+", module_name) if token.strip()}
        return bool(module_tokens & cls._DANGEROUS_LAMBDA_MODULE_TOKENS)

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
                    if self._contains_suspicious_config_term(value, suspicious_term):
                        result.add_check(
                            name="Suspicious Configuration String Check",
                            passed=False,
                            message=f"Suspicious configuration string found in {context}: '{suspicious_term}'",
                            severity=IssueSeverity.INFO,
                            location=f"{self.current_file_path} ({context})",
                            rule_code="S902",
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

    @staticmethod
    def _contains_suspicious_config_term(value: str, suspicious_term: str) -> bool:
        """Match suspicious config terms without substring hits inside benign identifiers."""
        normalized_term = suspicious_term.strip().lower()
        if not normalized_term:
            return False

        normalized_value = value.lower()
        if normalized_term.replace("_", "").isalnum():
            normalized_core_term = normalized_term.strip("_")
            if not normalized_core_term:
                return False

            pattern = rf"(?<![0-9A-Za-z])_*{re.escape(normalized_core_term)}_*(?![0-9A-Za-z])"
            return re.search(pattern, normalized_value) is not None

        return normalized_term in normalized_value

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract Keras H5 model metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            import h5py
        except Exception:
            metadata["extraction_error"] = "h5py is not installed"
            return metadata

        try:
            with h5py.File(file_path, "r") as h5_file:
                # Basic H5 structure
                metadata.update(
                    {
                        "h5_keys": list(h5_file.keys()),
                        "has_model_config": "model_config" in h5_file.attrs,
                        "has_model_weights": "model_weights" in h5_file,
                    }
                )

                # Try to extract model configuration
                if "model_config" in h5_file.attrs:
                    with suppress(Exception):
                        config_json = h5_file.attrs["model_config"]
                        if isinstance(config_json, bytes):
                            config_json = config_json.decode("utf-8")

                        config = json.loads(config_json)

                        metadata.update(
                            {
                                "model_class": config.get("class_name", "Unknown"),
                                "keras_version": h5_file.attrs.get("keras_version", "unknown").decode("utf-8")
                                if isinstance(h5_file.attrs.get("keras_version"), bytes)
                                else h5_file.attrs.get("keras_version", "unknown"),
                            }
                        )

                        # Extract layer information
                        if "config" in config:
                            layers = config["config"].get("layers", [])
                            metadata.update(
                                {
                                    "layer_count": len(layers),
                                    "layer_types": list({layer.get("class_name", "Unknown") for layer in layers}),
                                }
                            )

                # Analyze model weights structure
                if "model_weights" in h5_file:
                    with suppress(Exception):
                        weights_group = h5_file["model_weights"]

                        # Count parameters
                        total_params = 0
                        weight_layers = []

                        def count_params(name, obj):
                            nonlocal total_params
                            if isinstance(obj, h5py.Dataset):
                                param_count = obj.size
                                total_params += param_count
                                weight_layers.append(
                                    {
                                        "name": name,
                                        "shape": list(obj.shape),
                                        "dtype": str(obj.dtype),
                                        "size": param_count,
                                    }
                                )

                        weights_group.visititems(count_params)

                        metadata.update(
                            {
                                "total_parameters": total_params,
                                "weight_layers": len(weight_layers),
                                "parameter_details": weight_layers[:10],  # First 10 layers
                            }
                        )

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
