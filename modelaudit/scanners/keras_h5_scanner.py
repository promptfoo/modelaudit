"""Scanner for Keras HDF5 model files (.h5, .keras, .hdf5)."""

import ast
import json
import math
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
    get_cve_2025_1550_explanation,
    get_cve_2025_9905_explanation,
    get_cve_2026_1669_explanation,
    get_pattern_explanation,
)
from ..utils.file.hdf5 import find_hdf5_signature_offset
from ._evidence_redaction import redact_evidence_string
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult
from .keras_utils import (
    check_custom_loss_config,
    check_custom_metric_config,
    check_lambda_dict_function,
    check_lambda_list_function,
    check_subclassed_model,
    is_known_safe_keras_layer_class,
)

# Try to import h5py, but handle the case where it's not installed
try:
    import h5py

    HAS_H5PY = True
except Exception:
    HAS_H5PY = False

_KERAS_VERSION_SEPARATOR = r"[._-]?"
_KERAS_LOCAL_VERSION_SUFFIX = r"\+[a-z0-9]+(?:[._-][a-z0-9]+)*"
_KERAS_PRERELEASE_SUFFIX = (
    rf"{_KERAS_VERSION_SEPARATOR}(?:a|alpha|b|beta|c|rc|pre|preview)"
    rf"{_KERAS_VERSION_SEPARATOR}\d*"
)
_KERAS_POST_SUFFIX = rf"(?:-\d+|{_KERAS_VERSION_SEPARATOR}(?:post|rev|r){_KERAS_VERSION_SEPARATOR}\d*)"
_KERAS_DEV_SUFFIX = rf"{_KERAS_VERSION_SEPARATOR}dev{_KERAS_VERSION_SEPARATOR}\d*"
_KERAS_PRERELEASE_SUFFIX_PATTERN = re.compile(
    rf"(?i)^(?:{_KERAS_PRERELEASE_SUFFIX}(?:{_KERAS_POST_SUFFIX})?(?:{_KERAS_DEV_SUFFIX})?|"
    rf"{_KERAS_DEV_SUFFIX})(?:{_KERAS_LOCAL_VERSION_SUFFIX})?$"
)
_KERAS_POST_OR_LOCAL_SUFFIX_PATTERN = re.compile(
    rf"(?i)^(?:{_KERAS_LOCAL_VERSION_SUFFIX}|"
    rf"{_KERAS_POST_SUFFIX}(?:{_KERAS_DEV_SUFFIX})?(?:{_KERAS_LOCAL_VERSION_SUFFIX})?)$"
)

# CVE-2025-1550: Keras safe_mode bypass via arbitrary module references.
_SAFE_KERAS_MODULE_ROOTS: frozenset[str] = frozenset({"keras", "tensorflow", "tf_keras", "tf", "numpy", "math"})
_DANGEROUS_CONFIG_MODULE_ROOTS = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "builtins",
        "__builtin__",
        "importlib",
        "shutil",
        "socket",
        "http",
        "pickle",
        "marshal",
        "ctypes",
        "code",
        "codeop",
        "compileall",
        "runpy",
        "webbrowser",
        "tempfile",
        "signal",
        "multiprocessing",
        "threading",
        "pty",
        "commands",
        "pdb",
        "profile",
        "trace",
        "pip",
        "setuptools",
        "distutils",
    }
)
_DANGEROUS_EXACT_MODULE_SYMBOLS: dict[str, frozenset[str]] = {
    "_ctypes": frozenset({"dlopen"}),
    "_frozen_importlib": frozenset({"__import__", "_find_and_load", "_find_and_load_unlocked"}),
    "_imp": frozenset({"create_builtin", "create_dynamic", "exec_builtin", "exec_dynamic", "load_dynamic"}),
    "_interpreters": frozenset({"call", "exec"}),
    "_io": frozenset({"open"}),
    "_operator": frozenset({"attrgetter", "methodcaller"}),
    "_pickle": frozenset({"load", "loads"}),
    "_posixsubprocess": frozenset({"fork_exec"}),
    "_socket": frozenset({"socket"}),
    "_thread": frozenset({"start_new", "start_new_thread"}),
    "_winapi": frozenset({"CreateProcess", "ShellExecute"}),
    "_xxsubinterpreters": frozenset({"run_string"}),
    "io": frozenset({"open"}),
    "nt": frozenset({"popen", "startfile", "system"}),
    "operator": frozenset({"attrgetter", "methodcaller"}),
    "posix": frozenset({"popen", "system"}),
}
_DANGEROUS_EXACT_MODULE_SYMBOL_PREFIXES: dict[str, tuple[str, ...]] = {
    "nt": ("exec", "spawn"),
    "posix": ("exec", "spawn"),
}
_NESTED_SERIALIZED_OBJECT_KEYS = frozenset(
    {
        "activation",
        "activity_regularizer",
        "backward_layer",
        "beta_initializer",
        "bias_constraint",
        "bias_initializer",
        "bias_regularizer",
        "callable",
        "cell",
        "cells",
        "depthwise_constraint",
        "depthwise_initializer",
        "depthwise_regularizer",
        "embeddings_constraint",
        "embeddings_initializer",
        "embeddings_regularizer",
        "fn",
        "forward_layer",
        "function",
        "gamma_initializer",
        "kernel_constraint",
        "kernel_initializer",
        "kernel_regularizer",
        "layer",
        "layers",
        "learning_rate",
        "loss",
        "losses",
        "metric",
        "metrics",
        "moving_mean_initializer",
        "moving_variance_initializer",
        "optimizer",
        "output_activation",
        "pointwise_constraint",
        "pointwise_initializer",
        "pointwise_regularizer",
        "preprocessor",
        "recurrent_activation",
        "recurrent_constraint",
        "recurrent_initializer",
        "recurrent_regularizer",
        "schedule",
        "weighted_metrics",
    }
)


class KerasH5Scanner(BaseScanner):
    """Scanner for Keras H5 model files"""

    name = "keras_h5"
    description = "Scans Keras H5 model files for suspicious layer configurations"
    supported_extensions: ClassVar[list[str]] = [".h5", ".hdf5", ".keras"]
    _JSON_ATTRIBUTE_PARSE_FAILED: ClassVar[object] = object()
    _SAFE_K_BACKEND_LAMBDA_FUNCTIONS: ClassVar[frozenset[str]] = frozenset(
        {"abs", "elu", "hard_sigmoid", "l2_normalize", "relu", "sigmoid", "softmax", "softplus", "softsign", "tanh"}
    )
    _SAFE_KERAS_ACTIVATION_FUNCTIONS: ClassVar[frozenset[str]] = frozenset(
        {"elu", "gelu", "hard_sigmoid", "relu", "selu", "sigmoid", "softmax", "softplus", "softsign", "tanh"}
    )
    _SAFE_TF_NN_LAMBDA_FUNCTIONS: ClassVar[frozenset[str]] = frozenset(
        {
            "elu",
            "gelu",
            "l2_normalize",
            "leaky_relu",
            "log_softmax",
            "relu",
            "relu6",
            "selu",
            "sigmoid",
            "softmax",
            "softplus",
            "softsign",
            "swish",
            "tanh",
        }
    )
    _SAFE_LAMBDA_MODULE_FUNCTIONS: ClassVar[dict[str, frozenset[str]]] = {
        "keras.backend": _SAFE_K_BACKEND_LAMBDA_FUNCTIONS,
        "keras.activations": _SAFE_KERAS_ACTIVATION_FUNCTIONS,
        "keras.ops": frozenset({"abs", "identity", "normalize", "relu", "sigmoid", "softmax", "tanh"}),
        "tensorflow": frozenset({"abs", "identity", "sigmoid", "tanh"}),
        "tensorflow.keras.activations": _SAFE_KERAS_ACTIVATION_FUNCTIONS,
        "tensorflow.keras.backend": _SAFE_K_BACKEND_LAMBDA_FUNCTIONS,
        "tensorflow.math": frozenset({"abs", "sigmoid", "tanh"}),
        "tensorflow.nn": _SAFE_TF_NN_LAMBDA_FUNCTIONS,
        "tensorflow.python.keras.activations": _SAFE_KERAS_ACTIVATION_FUNCTIONS,
        "tensorflow.python.keras.backend": _SAFE_K_BACKEND_LAMBDA_FUNCTIONS,
        "tf.keras.activations": _SAFE_KERAS_ACTIVATION_FUNCTIONS,
        "tf.keras.backend": _SAFE_K_BACKEND_LAMBDA_FUNCTIONS,
        "tf_keras.activations": _SAFE_KERAS_ACTIVATION_FUNCTIONS,
        "tf_keras.backend": _SAFE_K_BACKEND_LAMBDA_FUNCTIONS,
    }
    _TRUSTED_LAMBDA_LAYER_CLASSES: ClassVar[frozenset[str]] = frozenset(
        {
            "keras.layers.Lambda",
            "keras.layers.core.Lambda",
            "keras.layers.experimental.core.Lambda",
            "keras.src.layers.core.Lambda",
            "keras.src.layers.core.lambda_layer.Lambda",
            "tensorflow.keras.layers.Lambda",
            "tensorflow.keras.layers.core.Lambda",
            "tensorflow.keras.layers.experimental.core.Lambda",
            "tensorflow.python.keras.layers.core.Lambda",
            "tensorflow.python.keras.layers.core.lambda_layer.Lambda",
            "tensorflow.python.keras.layers.legacy.Lambda",
            "tf.keras.layers.Lambda",
            "tf.keras.layers.core.Lambda",
            "tf.keras.layers.experimental.core.Lambda",
            "tf_keras.layers.Lambda",
            "tf_keras.layers.core.Lambda",
            "tf_keras.src.layers.core.Lambda",
            "tf_keras.src.layers.core.lambda_layer.Lambda",
        }
    )
    _DANGEROUS_LAMBDA_MODULE_TOKENS: ClassVar[frozenset[str]] = frozenset(
        {
            "__builtin__",
            "__builtins__",
            "builtins",
            "code",
            "codeop",
            "commands",
            "compileall",
            "ctypes",
            "distutils",
            "http",
            "importlib",
            "marshal",
            "multiprocessing",
            "os",
            "pdb",
            "pickle",
            "pip",
            "profile",
            "pty",
            "runpy",
            "setuptools",
            "shutil",
            "signal",
            "socket",
            "subprocess",
            "sys",
            "tempfile",
            "threading",
            "trace",
            "webbrowser",
        }
    )
    _EXACT_DANGEROUS_LAMBDA_MODULES: ClassVar[frozenset[str]] = frozenset(
        {
            "_ctypes",
            "_frozen_importlib",
            "_frozen_importlib_external",
            "_imp",
            "_interpreters",
            "_io",
            "_multiprocessing",
            "_pickle",
            "_posixsubprocess",
            "_signal",
            "_socket",
            "_thread",
            "_winapi",
            "_xxsubinterpreters",
            "nt",
            "posix",
        }
    )
    _DANGEROUS_LAMBDA_FUNCTION_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "__import__",
            "attrgetter",
            "compile",
            "eval",
            "eagerpyfunc",
            "exec",
            "load_file_system_library",
            "load_library",
            "load_op_library",
            "open",
            "popen",
            "numpy_function",
            "py_func",
            "py_function",
            "pyfunc",
            "pyfuncstateless",
            "spawn",
            "system",
        }
    )
    _ALWAYS_DANGEROUS_LAMBDA_FUNCTION_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "eagerpyfunc",
            "load_file_system_library",
            "load_library",
            "load_op_library",
            "numpy_function",
            "py_func",
            "py_function",
            "pyfunc",
            "pyfuncstateless",
        }
    )
    _DANGEROUS_LAMBDA_MODULE_FUNCTION_PAIRS: ClassVar[frozenset[tuple[str, str]]] = frozenset(
        {
            ("io", "open"),
        }
    )
    _KERAS_WEIGHT_ROOT_GROUPS: ClassVar[frozenset[str]] = frozenset({"model_weights", "optimizer_weights"})
    _KERAS_WEIGHT_ROOT_ATTRS: ClassVar[frozenset[str]] = frozenset({"layer_names", "weight_names"})
    _MAX_HDF5_LAYOUT_PROBE_ITEMS: ClassVar[int] = 4096
    _MAX_HDF5_LINK_VISITS: ClassVar[int] = 4096
    _MAX_HDF5_EXTERNAL_REFERENCE_REPORTS: ClassVar[int] = 20
    _MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS: ClassVar[int] = 20
    _MAX_SERIALIZED_CONFIG_NODES: ClassVar[int] = 10_000
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
        self._checked_config_module_references: set[tuple[int, str, str]] = set()
        self._remaining_serialized_config_nodes = self._MAX_SERIALIZED_CONFIG_NODES
        self._serialized_config_limit_reported = False

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        if not HAS_H5PY:
            return find_hdf5_signature_offset(path) is not None

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
        self._checked_config_module_references.clear()
        self._remaining_serialized_config_nodes = self._MAX_SERIALIZED_CONFIG_NODES
        self._serialized_config_limit_reported = False

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
            reason = "keras_h5_h5py_unavailable"
            result.metadata["file_size"] = self.get_file_size(path)
            self._mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="H5PY Library Check",
                passed=False,
                message="h5py is required for Keras H5 scanning. Install with 'pip install modelaudit[h5]'.",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "path": path,
                    "required_package": "h5py",
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                },
                rule_code="S902",
            )
            self._finish_scan_result(result)
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
                    self._finish_scan_result(result)
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

        for index, layer_name in enumerate(layer_names):
            if index >= cls._MAX_HDF5_LAYOUT_PROBE_ITEMS:
                return True

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

        for index, layer_name in enumerate(layers):
            if index >= cls._MAX_HDF5_LAYOUT_PROBE_ITEMS:
                return True

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
        external_reference_count = 0
        external_storage_segments_truncated = False

        def visit(name: str, link: Any) -> None:
            nonlocal external_reference_count, external_storage_segments_truncated
            if isinstance(link, h5py.ExternalLink):
                external_reference_count += 1
                if len(findings) < self._MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
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
                    external_reference_count += 1
                    if len(findings) >= self._MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                        return
                    segments = [
                        {"filename": filename, "offset": int(offset), "size": int(size)}
                        for filename, offset, size in external_storage[
                            : self._MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS
                        ]
                    ]
                    finding: dict[str, Any] = {
                        "kind": "external_storage",
                        "hdf5_path": f"/{name}".replace("//", "/"),
                        "segments": segments,
                    }
                    if len(external_storage) > len(segments):
                        external_storage_segments_truncated = True
                        finding["segment_count"] = len(external_storage)
                        finding["segments_truncated"] = True
                    findings.append(finding)

        visited_link_count, link_visits_truncated = self._visit_hdf5_links(
            h5_file,
            visit,
            max_links=self._MAX_HDF5_LINK_VISITS,
        )
        external_references_truncated = external_reference_count > len(findings)
        if link_visits_truncated or external_references_truncated or external_storage_segments_truncated:
            reason = "keras_h5_external_reference_analysis_limit_exceeded"
            self._mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="HDF5 External Reference Analysis Limit",
                passed=False,
                message="Keras H5 external-reference analysis reached a configured safety limit",
                severity=IssueSeverity.INFO,
                location=source_path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                    "visited_link_count": visited_link_count,
                    "max_link_visits": self._MAX_HDF5_LINK_VISITS,
                    "link_visits_truncated": link_visits_truncated,
                    "external_reference_count": external_reference_count,
                    "reported_external_reference_count": len(findings),
                    "external_references_truncated": external_references_truncated,
                    "external_storage_segments_truncated": external_storage_segments_truncated,
                },
                rule_code="S902",
            )

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
            "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
        }
        if external_references_truncated or external_storage_segments_truncated:
            details["external_reference_count"] = external_reference_count
            details["external_references_truncated"] = external_references_truncated
            details["external_storage_segments_truncated"] = external_storage_segments_truncated

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
                "parse_status": "unknown",
            },
            why=get_cve_2026_1669_explanation("hdf5_external_reference"),
        )

    @staticmethod
    def _visit_hdf5_links(
        h5_file: Any,
        visit: Callable[[str, Any], None],
        *,
        max_links: int,
    ) -> tuple[int, bool]:
        """Visit links without resolving external targets on every supported h5py version."""
        visited_link_count = 0

        def bounded_visit(name: str, link: Any) -> bool | None:
            nonlocal visited_link_count
            visited_link_count += 1
            if visited_link_count > max_links:
                return True
            visit(name, link)
            return None

        if hasattr(h5_file, "visititems_links"):
            h5_file.visititems_links(bounded_visit)
            return min(visited_link_count, max_links), visited_link_count > max_links

        visited_group_ids = {h5_file.id}
        groups_to_visit = [(h5_file, "")]
        while groups_to_visit:
            group, prefix = groups_to_visit.pop()
            for child_name in group:
                path = f"{prefix}/{child_name}" if prefix else str(child_name)
                link = group.get(child_name, getlink=True)
                if bounded_visit(path, link):
                    return max_links, True
                if not isinstance(link, h5py.HardLink):
                    continue

                obj = group.get(child_name, getlink=False)
                if not isinstance(obj, h5py.Group) or obj.id in visited_group_ids:
                    continue

                visited_group_ids.add(obj.id)
                groups_to_visit.append((obj, path))

        return visited_link_count, False

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
        for key in ("optimizer_config", "loss", "metrics", "weighted_metrics"):
            self._check_nested_serialized_module_references(
                training_config.get(key),
                result,
                f"training_config.{key}",
                trusted_container=True,
            )

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
        self._check_layer_module_references(
            model_config,
            result,
            "model_config",
            config_fields=(),
            check_nested=False,
        )

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
        lambda_layer_count = 0

        # Check each layer
        for index, layer in enumerate(layers):
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
            is_lambda_layer = self._is_lambda_layer_class(layer_class)
            layer_count_key = "Lambda" if is_lambda_layer else layer_class
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

            if is_lambda_layer:
                layer_reference_name = f"lambda_{lambda_layer_count + 1}"
            else:
                serialized_layer_name = layer.get("name")
                config_layer_name = layer_config.get("name")
                layer_reference_name = next(
                    (
                        name.strip()
                        for name in (serialized_layer_name, config_layer_name)
                        if isinstance(name, str) and name.strip()
                    ),
                    f"layer_{index}",
                )
            nested_suppress_root_reference_keys: frozenset[str] = frozenset()
            if is_lambda_layer:
                handled_callback_fields = {"function"}
                for callback_field in ("mask", "output_shape"):
                    callback_value = layer_config.get(callback_field)
                    callback_type = layer_config.get(f"{callback_field}_type")
                    if callback_type in {"function", "lambda"} or (
                        isinstance(callback_value, dict) and callback_value.get("class_name") == "__lambda__"
                    ):
                        handled_callback_fields.add(callback_field)
                nested_suppress_root_reference_keys = frozenset(handled_callback_fields)
            self._check_layer_module_references(
                layer,
                result,
                layer_reference_name,
                config_fields=("fn_module",) if is_lambda_layer else ("module", "fn_module"),
                nested_suppress_root_reference_keys=nested_suppress_root_reference_keys,
            )

            # Update layer count
            if layer_count_key in layer_counts:
                layer_counts[layer_count_key] += 1
            else:
                layer_counts[layer_count_key] = 1

            # Check for suspicious layer types
            if layer_class in self.suspicious_layer_types or is_lambda_layer:
                # Special handling for Lambda layers - validate Python code
                if is_lambda_layer:
                    lambda_layer_count += 1
                    layer_name = f"lambda_{lambda_layer_count}"
                    self._check_lambda_layer(layer_config, result, layer_name)
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
                "Lambda" if is_lambda_layer else layer_class,
                redact_nested_context=is_lambda_layer,
                case_sensitive=is_lambda_layer,
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

            if not is_lambda_layer:
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

    @staticmethod
    def _config_reference_symbols(source: dict[str, Any], object_class: str) -> set[str]:
        symbols = {object_class}
        for key in ("config", "registered_name", "function", "function_name"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                symbols.add(value.strip())
        return symbols

    @classmethod
    def _is_dangerous_exact_module_reference(
        cls,
        source: dict[str, Any],
        module_value: str,
        object_class: str,
    ) -> bool:
        symbols = cls._config_reference_symbols(source, object_class)
        dangerous_symbols = _DANGEROUS_EXACT_MODULE_SYMBOLS.get(module_value, frozenset())
        if symbols & dangerous_symbols:
            return True
        prefixes = _DANGEROUS_EXACT_MODULE_SYMBOL_PREFIXES.get(module_value, ())
        return any(symbol.startswith(prefixes) for symbol in symbols) if prefixes else False

    @classmethod
    def _config_reference_symbol_tokens(cls, source: dict[str, Any], object_class: str) -> set[str]:
        return {
            token.lower()
            for symbol in cls._config_reference_symbols(source, object_class)
            for token in re.split(r"[^0-9A-Za-z_]+", symbol)
            if token
        }

    @classmethod
    def _is_allowlisted_config_callable(
        cls,
        source: dict[str, Any],
        module_value: str,
    ) -> bool:
        symbols = {
            value.strip()
            for key in ("config", "registered_name", "function", "function_name")
            if isinstance((value := source.get(key)), str) and value.strip()
        }
        return bool(symbols) and all(
            cls._is_lambda_module_reference_allowlisted(module_value, symbol) for symbol in symbols
        )

    def _check_config_module_reference(
        self,
        source: dict[str, Any],
        key: str,
        module_value: str,
        object_class: str,
        result: ScanResult,
        layer_name: str,
    ) -> None:
        reference_key = (id(source), key, module_value)
        if reference_key in self._checked_config_module_references:
            return
        self._checked_config_module_references.add(reference_key)

        redacted_module_value = redact_evidence_string(module_value.split(".", 1)[0])
        redacted_object_class = redact_evidence_string(object_class)
        redacted_layer_name = redact_evidence_string(layer_name)
        top_module = module_value.split(".")[0]
        symbol_tokens = self._config_reference_symbol_tokens(source, object_class)
        is_callable_reference = key == "fn_module" or object_class == "function"
        is_dangerous = (
            self._is_dangerous_exact_module_reference(source, module_value, object_class)
            or bool(symbol_tokens & self._ALWAYS_DANGEROUS_LAMBDA_FUNCTION_NAMES)
            or (
                top_module in _DANGEROUS_CONFIG_MODULE_ROOTS
                and (object_class == "function" or bool(symbol_tokens & self._DANGEROUS_LAMBDA_FUNCTION_NAMES))
            )
        )
        is_outside_allowlist = top_module not in _SAFE_KERAS_MODULE_ROOTS
        is_untrusted_callable = is_callable_reference and not self._is_allowlisted_config_callable(
            source,
            module_value,
        )

        if is_dangerous:
            result.add_check(
                name="CVE-2025-1550: Dangerous Module in Config",
                passed=False,
                message=(
                    f"CVE-2025-1550: Layer '{redacted_layer_name}' references dangerous module "
                    f"'{redacted_module_value}' in {key} field - arbitrary code execution via safe_mode bypass"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                details={
                    "layer_name": redacted_layer_name,
                    "layer_class": redacted_object_class,
                    "key": key,
                    "module": redacted_module_value,
                    "cve_id": "CVE-2025-1550",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": (
                        "Arbitrary dangerous module references in Keras H5 metadata can bypass safe_mode "
                        "and execute attacker-controlled code during model loading."
                    ),
                    "remediation": "Upgrade Keras to >= 3.9.0 or remove untrusted module references",
                },
                why=get_cve_2025_1550_explanation("dangerous_module"),
            )
        elif is_untrusted_callable or (is_outside_allowlist and self._is_lambda_layer_class(object_class)):
            result.add_check(
                name="CVE-2025-1550: Untrusted Module in Config",
                passed=False,
                message=(
                    f"CVE-2025-1550: Layer '{redacted_layer_name}' references non-allowlisted module "
                    f"'{redacted_module_value}' in {key} field - potential safe_mode bypass"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} (layer: {redacted_layer_name})",
                details={
                    "layer_name": redacted_layer_name,
                    "layer_class": redacted_object_class,
                    "key": key,
                    "module": redacted_module_value,
                    "cve_id": "CVE-2025-1550",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": (
                        "Non-allowlisted callable module references may indicate safe_mode bypass "
                        "paths in untrusted Keras H5 metadata."
                    ),
                    "remediation": "Upgrade Keras to >= 3.9.0 or verify this module is safe",
                },
                why=get_cve_2025_1550_explanation("untrusted_module"),
            )

    def _check_nested_serialized_module_references(
        self,
        config_value: Any,
        result: ScanResult,
        layer_name: str,
        *,
        trusted_container: bool = False,
        suppress_root_reference_keys: frozenset[str] = frozenset(),
    ) -> None:
        """Inspect nested Keras object configs without recursing on attacker-controlled depth."""
        pending: list[tuple[Any, str | None, bool, bool, bool]] = [(config_value, None, trusted_container, True, False)]
        traversal_truncated = False
        while pending:
            if self._remaining_serialized_config_nodes <= 0:
                traversal_truncated = True
                break

            node, parent_key, container_is_trusted, is_root, suppress_reference_check = pending.pop()
            self._remaining_serialized_config_nodes -= 1
            child_capacity = max(self._remaining_serialized_config_nodes - len(pending), 0)
            if isinstance(node, list):
                children = list(node[: child_capacity + 1])
                if len(children) > child_capacity:
                    traversal_truncated = True
                    children.pop()
                pending.extend((item, parent_key, container_is_trusted, False, False) for item in reversed(children))
                continue
            if not isinstance(node, dict):
                continue

            object_class = node.get("class_name")
            serialized_shape = isinstance(object_class, str) and "config" in node
            is_serialized_object = serialized_shape and (
                container_is_trusted
                or parent_key in _NESTED_SERIALIZED_OBJECT_KEYS
                or "registered_name" in node
                or object_class == "function"
                or self._is_lambda_layer_class(object_class)
            )
            if is_serialized_object and not suppress_reference_check:
                assert isinstance(object_class, str)
                for key in ("module", "fn_module"):
                    module_value = node.get(key)
                    if isinstance(module_value, str) and module_value.strip():
                        self._check_config_module_reference(
                            node,
                            key,
                            module_value.strip(),
                            object_class,
                            result,
                            layer_name,
                        )

            next_container_is_trusted = container_is_trusted and not is_serialized_object
            children = []
            for key, value in node.items():
                normalized_key = str(key).lower()
                if normalized_key in {"module", "fn_module", "class_name", "registered_name"}:
                    continue
                if len(children) >= child_capacity:
                    traversal_truncated = True
                    break
                children.append(
                    (
                        value,
                        normalized_key,
                        next_container_is_trusted,
                        False,
                        is_root and normalized_key in suppress_root_reference_keys,
                    )
                )
            pending.extend(reversed(children))

        if traversal_truncated and not self._serialized_config_limit_reported:
            self._serialized_config_limit_reported = True
            reason = "keras_h5_serialized_config_node_limit_exceeded"
            self._mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="Serialized Config Traversal Limit",
                passed=False,
                message="Keras serialized config exceeded the bounded module-reference analysis limit",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                    "max_nodes": self._MAX_SERIALIZED_CONFIG_NODES,
                },
            )

    def _check_layer_module_references(
        self,
        layer: dict[str, Any],
        result: ScanResult,
        layer_name: str,
        *,
        config_fields: tuple[str, ...] = ("module", "fn_module"),
        check_nested: bool = True,
        nested_suppress_root_reference_keys: frozenset[str] = frozenset(),
    ) -> None:
        """Check H5 layer config for CVE-2025-1550 module references."""
        layer_class = layer.get("class_name")
        if not isinstance(layer_class, str) or "config" not in layer:
            return

        for key in ("module", "fn_module"):
            layer_value = layer.get(key)
            if isinstance(layer_value, str) and layer_value.strip():
                self._check_config_module_reference(
                    layer,
                    key,
                    layer_value.strip(),
                    layer_class,
                    result,
                    layer_name,
                )

        layer_config = layer.get("config")
        if not isinstance(layer_config, dict):
            return

        for key in config_fields:
            config_value = layer_config.get(key)
            if isinstance(config_value, str) and config_value.strip():
                self._check_config_module_reference(
                    layer_config,
                    key,
                    config_value.strip(),
                    layer_class,
                    result,
                    layer_name,
                )

        if layer_class == "FlaxLayer":
            self._check_nested_serialized_module_references(
                layer_config.get("module"),
                result,
                layer_name,
                trusted_container=True,
            )

        inbound_nodes = layer.get("inbound_nodes")
        if isinstance(inbound_nodes, list):
            for inbound_node in inbound_nodes:
                if not isinstance(inbound_node, dict):
                    continue
                for key in ("args", "kwargs"):
                    self._check_nested_serialized_module_references(
                        inbound_node.get(key),
                        result,
                        layer_name,
                        trusted_container=True,
                    )

        if check_nested:
            self._check_nested_serialized_module_references(
                layer_config,
                result,
                layer_name,
                suppress_root_reference_keys=nested_suppress_root_reference_keys,
            )

    def _check_lambda_layer(
        self,
        layer_config: dict[str, Any],
        result: ScanResult,
        layer_name: str,
        *,
        callback_field: str = "function",
    ) -> None:
        """Check Lambda layer for executable Python code with validation"""
        # Lambda layers can contain Python code in several forms:
        # 1. As a string in 'function' field (serialized Python code)
        # 2. As a module + function reference
        # 3. As inline code

        # Extract potential Python code from Lambda config
        function_str = layer_config.get(callback_field)
        function_type = layer_config.get(f"{callback_field}_type")
        module_key = "module" if callback_field == "function" else f"{callback_field}_module"
        module_name = layer_config.get(module_key)
        function_name = layer_config.get("function_name") if callback_field == "function" else None

        # Legacy Keras H5 stores named callables in `function` and distinguishes
        # them from serialized Lambda code with `function_type="function"`.
        is_named_function_reference = (
            function_type == "function"
            and function_name is None
            and isinstance(function_str, str)
            and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
                function_str.strip(),
            )
            is not None
        )
        reference_function_name = function_name
        if reference_function_name is None and is_named_function_reference:
            reference_function_name = function_str

        callback_layer_name = layer_name if callback_field == "function" else f"{layer_name}.{callback_field}"
        callback_details = {"layer_class": "Lambda", "callback_field": callback_field}
        encoded_function_handled = False
        function_requires_review = False
        nested_callable_reference: tuple[Any, Any] | None = None
        if isinstance(function_str, dict):
            encoded_function_handled = check_lambda_dict_function(
                function_str,
                result,
                self.current_file_path,
                callback_layer_name,
            )
            nested_callable_reference = self._lambda_callable_dict_reference(function_str)
            if not encoded_function_handled and nested_callable_reference is None:
                function_requires_review = True
                result.add_check(
                    name="Lambda Layer Code Analysis",
                    passed=False,
                    message="Lambda layer contains unrecognized dict-format function metadata",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        **callback_details,
                        "function_format": "dict",
                        "parse_status": "unrecognized",
                    },
                    why="Unrecognized Lambda function metadata cannot be safely classified.",
                    rule_code="S507",
                )
        elif isinstance(function_str, list):
            encoded_function_handled = check_lambda_list_function(
                function_str,
                result,
                self.current_file_path,
                callback_layer_name,
            )
        # Check if there's actual Python code to validate
        if isinstance(function_str, str) and not is_named_function_reference:
            normalized_function_source = function_str.strip()
            if normalized_function_source:
                is_valid, _ = validate_python_syntax(normalized_function_source)
            else:
                is_valid = False
            is_safe_pattern = is_valid and self._is_lambda_source_allowlisted(normalized_function_source)

            if is_safe_pattern:
                result.add_check(
                    name="Lambda Layer Code Analysis",
                    passed=True,
                    message="Lambda layer contains safe normalization pattern",
                    location=self.current_file_path,
                    details={
                        **callback_details,
                        "pattern_type": "safe_normalization",
                    },
                    rule_code=None,  # Passing check
                )
            else:
                if is_valid:
                    # It's valid Python! Check if it's dangerous
                    is_dangerous, _ = is_code_potentially_dangerous(normalized_function_source, "low")

                    # Check if code is dangerous
                    if is_dangerous:
                        result.add_check(
                            name="Lambda Layer Code Analysis",
                            passed=False,
                            message="Lambda layer contains dangerous Python code",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={
                                **callback_details,
                                "code_analysis_omitted": "lambda_code_analysis_may_contain_sensitive_identifiers",
                                "code_preview_omitted": "lambda_code_may_contain_sensitive_literals",
                            },
                            rule_code="S507",  # Python embedded code
                        )
                        function_requires_review = True
                    else:
                        # Valid Python outside the narrow allowlist is still attacker-controlled executable code.
                        result.add_check(
                            name="Lambda Layer Code Analysis",
                            passed=False,
                            message="Lambda layer contains non-allowlisted Python code",
                            severity=IssueSeverity.WARNING,
                            location=self.current_file_path,
                            details={
                                **callback_details,
                                "validation_status": "valid_python",
                                "code_analysis_omitted": "lambda_code_analysis_may_contain_sensitive_identifiers",
                                "code_preview_omitted": "lambda_code_may_contain_sensitive_literals",
                                "allowlist_status": "not_allowlisted",
                            },
                            rule_code="S507",  # Python embedded code
                        )
                        function_requires_review = True
                else:
                    result.add_check(
                        name="Lambda Layer Code Analysis",
                        passed=False,
                        message="Lambda layer contains malformed Python source",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={
                            **callback_details,
                            "validation_status": "invalid_python",
                            "validation_error_omitted": "lambda_code_may_contain_sensitive_literals",
                        },
                        why="Malformed Lambda source cannot be safely classified.",
                        rule_code="S507",
                    )
                    function_requires_review = True
        elif (
            function_str is not None
            and not isinstance(function_str, (dict, list))
            and not (is_named_function_reference and isinstance(function_str, str))
        ):
            result.add_check(
                name="Lambda Layer Code Analysis",
                passed=False,
                message="Lambda layer uses malformed function metadata",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={
                    **callback_details,
                    "function_type": type(function_str).__name__,
                    "function_payload_omitted": "malformed_lambda_function_may_contain_sensitive_payload",
                },
                why="Lambda function metadata must be source text or a recognized serialized function structure.",
                rule_code="S507",
            )
            function_requires_review = True

        module_references: list[tuple[Any, Any, str]] = []
        if module_name is not None or reference_function_name is not None:
            module_references.append((module_name, reference_function_name, "layer_config"))
        if nested_callable_reference is not None:
            module_references.append((*nested_callable_reference, "function_dict"))

        allowlisted_references: list[tuple[str, str, str]] = []
        reference_requires_review = encoded_function_handled or function_requires_review
        for reference_module, reference_function, reference_source in module_references:
            module_reference_values = (reference_module, reference_function)
            has_invalid_module_reference = any(
                value is not None and not isinstance(value, str) for value in module_reference_values
            )
            has_module_reference = any(
                isinstance(value, str) and bool(value.strip()) for value in module_reference_values
            )
            if not has_module_reference and not has_invalid_module_reference:
                continue

            if self._is_lambda_module_reference_dangerous(reference_module, reference_function):
                result.add_check(
                    name="Lambda Layer Module Reference Check",
                    passed=False,
                    message="Lambda layer references a potentially dangerous module or function",
                    severity=IssueSeverity.CRITICAL,
                    location=self.current_file_path,
                    details={
                        **callback_details,
                        "module_omitted": "artifact_controlled_lambda_reference",
                        "function_omitted": "artifact_controlled_lambda_reference",
                        "reference_source": reference_source,
                    },
                    why=get_pattern_explanation("lambda_layer"),
                    rule_code="S1103",
                )
                reference_requires_review = True
            elif has_invalid_module_reference:
                result.add_check(
                    name="Lambda Layer Module Reference Check",
                    passed=False,
                    message="Lambda layer uses malformed module/function reference metadata",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        **callback_details,
                        "module_type": type(reference_module).__name__,
                        "function_type": type(reference_function).__name__,
                        "reference_source": reference_source,
                    },
                    why="Malformed Lambda module references cannot be safely classified.",
                    rule_code="S1103",
                )
                reference_requires_review = True
            elif self._is_lambda_module_reference_allowlisted(reference_module, reference_function):
                allowlisted_references.append((reference_module, reference_function, reference_source))
            else:
                result.add_check(
                    name="Lambda Layer Module Reference Check",
                    passed=False,
                    message="Lambda layer contains non-allowlisted module reference",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        **callback_details,
                        "module_omitted": "artifact_controlled_lambda_reference",
                        "function_omitted": "artifact_controlled_lambda_reference",
                        "reference_source": reference_source,
                        "allowlist_status": "not_allowlisted",
                    },
                    why=get_pattern_explanation("lambda_layer"),
                    rule_code="S1103",
                )
                reference_requires_review = True

        if not reference_requires_review:
            for _reference_module, _reference_function, reference_source in allowlisted_references:
                result.add_check(
                    name="Lambda Layer Module Reference Check",
                    passed=True,
                    message="Lambda layer module reference is allowlisted",
                    location=self.current_file_path,
                    details={
                        **callback_details,
                        "module_omitted": "artifact_controlled_lambda_reference",
                        "function_omitted": "artifact_controlled_lambda_reference",
                        "reference_source": reference_source,
                        "allowlist_status": "allowlisted",
                    },
                    rule_code=None,
                )
        if callback_field == "function":
            for auxiliary_field in ("output_shape", "mask"):
                auxiliary_value = layer_config.get(auxiliary_field)
                is_serialized_lambda = (
                    isinstance(auxiliary_value, dict) and auxiliary_value.get("class_name") == "__lambda__"
                )
                if layer_config.get(f"{auxiliary_field}_type") in {"function", "lambda"} or is_serialized_lambda:
                    self._check_lambda_layer(
                        layer_config,
                        result,
                        layer_name,
                        callback_field=auxiliary_field,
                    )
        # Don't flag Lambda layers without code - they might just be placeholders

    @staticmethod
    def _is_lambda_layer_class(layer_class: Any) -> bool:
        """Return True for serialized Lambda variants such as `keras.layers.Lambda`."""
        if not isinstance(layer_class, str):
            return False

        return layer_class == "Lambda" or layer_class in KerasH5Scanner._TRUSTED_LAMBDA_LAYER_CLASSES

    @staticmethod
    def _lambda_callable_dict_reference(function_dict: dict[str, Any]) -> tuple[Any, Any] | None:
        """Extract a module/function pair from a serialized callable dictionary."""
        for function_key in ("function_name", "function", "registered_name"):
            if function_key in function_dict:
                return function_dict.get("module"), function_dict.get(function_key)
        function_config = function_dict.get("config")
        if "module" in function_dict and isinstance(function_config, str):
            return function_dict.get("module"), function_config
        return None

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

        if _KERAS_PRERELEASE_SUFFIX_PATTERN.fullmatch(suffix):
            return (major, minor, patch), True

        if _KERAS_POST_OR_LOCAL_SUFFIX_PATTERN.fullmatch(suffix):
            return (major, minor, patch), False

        return None

    @classmethod
    def _is_lambda_module_reference_dangerous(cls, module_name: Any, function_name: Any) -> bool:
        """Return True when a Lambda module/function reference resolves to a risky symbol."""
        if isinstance(function_name, str):
            normalized_function_name = function_name.strip().lower()
            function_tokens = {
                token.strip() for token in re.split(r"[^0-9A-Za-z_]+", normalized_function_name) if token.strip()
            }
            normalized_module_name = module_name.strip().lower() if isinstance(module_name, str) else ""
            function_leaf = normalized_function_name.rsplit(".", 1)[-1]
            if (normalized_module_name, function_leaf) in cls._DANGEROUS_LAMBDA_MODULE_FUNCTION_PAIRS:
                return True
            if function_tokens & cls._ALWAYS_DANGEROUS_LAMBDA_FUNCTION_NAMES:
                return True
            if (
                not isinstance(module_name, str) or not module_name.strip()
            ) and function_tokens & cls._DANGEROUS_LAMBDA_FUNCTION_NAMES:
                return True

        if not isinstance(module_name, str):
            return False

        normalized_module_name = module_name.strip()
        if normalized_module_name in cls._EXACT_DANGEROUS_LAMBDA_MODULES:
            return True

        module_tokens = {token.strip().lower() for token in re.split(r"[^0-9A-Za-z_]+", module_name) if token.strip()}
        return bool(module_tokens & cls._DANGEROUS_LAMBDA_MODULE_TOKENS)

    @staticmethod
    def _safe_lambda_number(node: ast.AST, *, allow_zero: bool = True) -> bool:
        unary_depth = 0
        while isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            unary_depth += 1
            if unary_depth > 32:
                return False
            node = node.operand
        if (
            not isinstance(node, ast.Constant)
            or isinstance(node.value, bool)
            or not isinstance(node.value, (int, float))
        ):
            return False
        if isinstance(node.value, float) and not math.isfinite(node.value):
            return False
        return allow_zero or node.value != 0

    @classmethod
    def _is_lambda_source_allowlisted(cls, source: str) -> bool:
        """Accept only simple normalization or framework activation Lambda expressions."""
        try:
            expression = ast.parse(source.strip(), mode="eval")
        except SyntaxError:
            return False

        lambda_node = expression.body
        if not isinstance(lambda_node, ast.Lambda):
            return False
        args = lambda_node.args
        if (
            len(args.args) != 1
            or args.posonlyargs
            or args.kwonlyargs
            or args.vararg is not None
            or args.kwarg is not None
            or args.defaults
            or args.kw_defaults
        ):
            return False
        argument_name = args.args[0].arg

        body = lambda_node.body
        if isinstance(body, ast.BinOp) and isinstance(body.left, ast.Name) and body.left.id == argument_name:
            if isinstance(body.op, ast.Mult):
                return cls._safe_lambda_number(body.right)
            if isinstance(body.op, ast.Div):
                return cls._safe_lambda_number(body.right, allow_zero=False)

        if (
            isinstance(body, ast.BinOp)
            and isinstance(body.op, ast.Div)
            and cls._safe_lambda_number(body.right, allow_zero=False)
            and isinstance(body.left, ast.BinOp)
            and isinstance(body.left.op, ast.Sub)
            and isinstance(body.left.left, ast.Name)
            and body.left.left.id == argument_name
        ):
            return cls._safe_lambda_number(body.left.right)

        if not isinstance(body, ast.Call) or body.keywords or len(body.args) != 1:
            return False
        if (
            not isinstance(body.args[0], ast.Name)
            or body.args[0].id != argument_name
            or not isinstance(body.func, ast.Attribute)
        ):
            return False

        if isinstance(body.func.value, ast.Name) and body.func.value.id == "K":
            return body.func.attr in cls._SAFE_K_BACKEND_LAMBDA_FUNCTIONS
        return (
            isinstance(body.func.value, ast.Attribute)
            and body.func.value.attr == "nn"
            and isinstance(body.func.value.value, ast.Name)
            and body.func.value.value.id == "tf"
            and body.func.attr in cls._SAFE_TF_NN_LAMBDA_FUNCTIONS
        )

    @classmethod
    def _is_lambda_module_reference_allowlisted(cls, module_name: Any, function_name: Any) -> bool:
        """Return True for explicitly safe functions from trusted framework roots."""
        if (
            not isinstance(module_name, str)
            or not module_name.strip()
            or not isinstance(function_name, str)
            or not function_name.strip()
        ):
            return False
        normalized_module = module_name.strip()
        normalized_function = function_name.strip()
        if (
            module_name != normalized_module
            or normalized_module != normalized_module.lower()
            or function_name != normalized_function
            or normalized_function != normalized_function.lower()
        ):
            return False
        return normalized_function in cls._SAFE_LAMBDA_MODULE_FUNCTIONS.get(normalized_module, frozenset())

    def _check_config_for_suspicious_strings(
        self,
        config: Any,
        result: ScanResult,
        context: str = "",
        *,
        redact_nested_context: bool = False,
        case_sensitive: bool = False,
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
                    if self._contains_suspicious_config_term(
                        value,
                        suspicious_term,
                        case_sensitive=case_sensitive and key == "function",
                    ):
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
                nested_context = context if redact_nested_context else f"{context}.{key}"
                self._check_config_for_suspicious_strings(
                    value,
                    result,
                    nested_context,
                    redact_nested_context=redact_nested_context,
                    case_sensitive=False,
                )
            elif isinstance(value, list):
                # Check each item in the list
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        nested_context = context if redact_nested_context else f"{context}.{key}[{i}]"
                        self._check_config_for_suspicious_strings(
                            item,
                            result,
                            nested_context,
                            redact_nested_context=redact_nested_context,
                            case_sensitive=False,
                        )

    @staticmethod
    def _contains_suspicious_config_term(
        value: str,
        suspicious_term: str,
        *,
        case_sensitive: bool = False,
    ) -> bool:
        """Match suspicious config terms without substring hits inside benign identifiers."""
        normalized_term = suspicious_term.strip()
        if not normalized_term:
            return False

        if not case_sensitive:
            normalized_term = normalized_term.lower()
            value = value.lower()
        if normalized_term.replace("_", "").isalnum():
            normalized_core_term = normalized_term.strip("_")
            if not normalized_core_term:
                return False

            pattern = rf"(?<![0-9A-Za-z])_*{re.escape(normalized_core_term)}_*(?![0-9A-Za-z])"
            return re.search(pattern, value) is not None

        return normalized_term in value

    @staticmethod
    def _resolve_internal_hdf5_soft_link_group(root: Any, soft_link: Any) -> tuple[Any | None, bool]:
        """Resolve a root SoftLink only through internal hard links."""
        path = getattr(soft_link, "path", None)
        if not isinstance(path, str) or not path:
            return None, False

        current = root
        parts = [part for part in path.split("/") if part and part != "."]
        if not parts or any(part == ".." for part in parts):
            return None, False

        for index, part in enumerate(parts):
            link = current.get(part, getlink=True)
            if isinstance(link, h5py.ExternalLink):
                return None, True
            if not isinstance(link, h5py.HardLink):
                return None, False

            obj = current.get(part, getlink=False)
            if index == len(parts) - 1:
                return (obj, False) if isinstance(obj, h5py.Group) else (None, False)
            if not isinstance(obj, h5py.Group):
                return None, False
            current = obj

        return (current, False) if isinstance(current, h5py.Group) else (None, False)

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
                model_weights_link = h5_file.get("model_weights", getlink=True)
                # Basic H5 structure
                metadata.update(
                    {
                        "h5_keys": list(h5_file.keys()),
                        "has_model_config": "model_config" in h5_file.attrs,
                        "has_model_weights": model_weights_link is not None,
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

                # Analyze model weights structure without resolving HDF5 external links.
                if model_weights_link is not None:
                    with suppress(Exception):
                        if isinstance(model_weights_link, h5py.ExternalLink):
                            metadata["model_weights_external_reference"] = True
                            return metadata

                        if isinstance(model_weights_link, h5py.SoftLink):
                            weights_group, points_to_external = self._resolve_internal_hdf5_soft_link_group(
                                h5_file,
                                model_weights_link,
                            )
                            if points_to_external:
                                metadata["model_weights_external_reference"] = True
                                return metadata
                        else:
                            weights_group = h5_file.get("model_weights", getlink=False)
                        if not isinstance(weights_group, h5py.Group):
                            if isinstance(model_weights_link, h5py.SoftLink):
                                metadata["model_weights_internal_link_unresolved"] = True
                            return metadata
                        if isinstance(model_weights_link, h5py.SoftLink):
                            metadata["model_weights_internal_link"] = True

                        # Count parameters
                        total_params = 0
                        weight_layers = []
                        skipped_external_weight_entries = False

                        def count_params(name: str, link: Any) -> None:
                            nonlocal total_params, skipped_external_weight_entries
                            if not isinstance(link, h5py.HardLink):
                                skipped_external_weight_entries = True
                                return
                            obj = weights_group.get(name, getlink=False)
                            if isinstance(obj, h5py.Dataset):
                                if obj.external:
                                    skipped_external_weight_entries = True
                                    return
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

                        visited_links, visits_truncated = self._visit_hdf5_links(
                            weights_group,
                            count_params,
                            max_links=self._MAX_HDF5_LINK_VISITS,
                        )

                        metadata.update(
                            {
                                "total_parameters": total_params,
                                "weight_layers": len(weight_layers),
                                "parameter_details": weight_layers[:10],  # First 10 layers
                                "weight_link_visits": visited_links,
                            }
                        )
                        if skipped_external_weight_entries:
                            metadata["external_weight_entries_skipped"] = True
                        if visits_truncated:
                            metadata["weight_link_visits_truncated"] = True

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
