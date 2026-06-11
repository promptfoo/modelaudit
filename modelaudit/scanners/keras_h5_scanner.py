"""Scanner for Keras HDF5 model files (.h5, .keras, .hdf5)."""

import ast
import json
import math
import os
import re
from collections.abc import Callable
from contextlib import suppress
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
from ._evidence_redaction import (
    redact_evidence_mapping_key,
    redact_evidence_string,
    redact_evidence_value,
    redact_untrusted_error_message,
)
from .base import DEFAULT_MAX_FILE_READ_SIZE, INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult
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
    # HDF5 inspection is file-backed through h5py and uses bounded metadata/link
    # traversal, so total file size is not a whole-file read/memory proxy.
    default_max_file_read_size: ClassVar[int] = 0
    _JSON_ATTRIBUTE_PARSE_FAILED: ClassVar[object] = object()
    _HDF5_ATTRIBUTE_READ_SKIPPED: ClassVar[object] = object()
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
    _MAX_HDF5_REFERENCE_TEXT_CHARS: ClassVar[int] = 4096
    _MAX_HDF5_JSON_ATTRIBUTE_BYTES: ClassVar[int] = 10 * 1024 * 1024
    _MAX_HDF5_NAME_ATTRIBUTE_BYTES: ClassVar[int] = 10 * 1024 * 1024
    _MAX_HDF5_SOFT_LINK_RESOLUTION_DEPTH: ClassVar[int] = 32
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
        self._current_h5_keras_version: str | None = None
        self._checked_config_module_references: set[tuple[int, str, str]] = set()
        self.max_hdf5_json_attribute_bytes = self._normalize_positive_int_config(
            self.config.get("max_hdf5_json_attribute_bytes"),
            self._MAX_HDF5_JSON_ATTRIBUTE_BYTES,
        )
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
        self._current_h5_keras_version = None
        self._checked_config_module_references.clear()
        self._remaining_serialized_config_nodes = self._MAX_SERIALIZED_CONFIG_NODES
        self._serialized_config_limit_reported = False

        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result

        # Check if h5py is installed
        if not HAS_H5PY:
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

        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        whole_file_hash_skipped = file_size > DEFAULT_MAX_FILE_READ_SIZE
        self._add_file_backed_hdf5_inspection_check(
            path,
            result,
            file_size,
            whole_file_hash_skipped=whole_file_hash_skipped,
        )
        if not whole_file_hash_skipped:
            self.add_file_integrity_check(path, result)

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            with h5py.File(path, "r") as f:
                result.bytes_scanned = file_size
                raw_keras_version: str | None = None
                keras_version_attr = (
                    self._read_bounded_hdf5_attribute(
                        f.attrs,
                        "keras_version",
                        result,
                        max_bytes=self._MAX_HDF5_REFERENCE_TEXT_CHARS,
                        fail_closed=False,
                    )
                    if "keras_version" in f.attrs
                    else None
                )
                if keras_version_attr is self._HDF5_ATTRIBUTE_READ_SKIPPED:
                    keras_version_attr = None
                if isinstance(keras_version_attr, bytes):
                    keras_version_attr = keras_version_attr.decode("utf-8", errors="ignore")
                if isinstance(keras_version_attr, str) and keras_version_attr.strip():
                    raw_keras_version = keras_version_attr.strip()
                    result.metadata["keras_version"] = redact_evidence_string(raw_keras_version)
                self._current_h5_keras_version = raw_keras_version

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
                model_config = self._load_json_hdf5_attribute(f.attrs, "model_config", result)

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
                    custom_objects_attr = self._read_bounded_hdf5_attribute(
                        f.attrs,
                        "custom_objects",
                        result,
                        max_bytes=self.max_hdf5_json_attribute_bytes,
                        fail_closed=False,
                    )
                    custom_objects_truncated = custom_objects_attr is self._HDF5_ATTRIBUTE_READ_SKIPPED
                    if custom_objects_attr is None or custom_objects_truncated:
                        custom_objects_list = []
                    else:
                        try:
                            custom_objects_list = list(custom_objects_attr)
                        except TypeError:
                            custom_objects_list = [custom_objects_attr]
                    result.add_check(
                        name="Custom Objects Security Check",
                        passed=False,
                        message="Model contains custom objects which could contain arbitrary code",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path} (model_config)",
                        rule_code="S302",
                        details={
                            "custom_objects": redact_evidence_value(custom_objects_list, max_string_chars=200),
                            "custom_objects_truncated": custom_objects_truncated,
                        },
                    )

                # Check for custom metrics and custom loss
                if "training_config" in f.attrs:
                    training_config = self._load_json_hdf5_attribute(f.attrs, "training_config", result)
                    if training_config is not self._JSON_ATTRIBUTE_PARSE_FAILED:
                        self._scan_training_config(training_config, result)

        except OSError as e:
            redacted_error = redact_untrusted_error_message(e)
            self._mark_inconclusive_scan_result(result, "keras_h5_read_failed")
            result.add_check(
                name="Keras H5 File Read",
                passed=False,
                message=f"Unable to read Keras H5 content: {redacted_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": redacted_error,
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_h5_read_failed",
                },
                rule_code="S902",
            )
            self._finish_scan_result(result)
            return result
        except Exception as e:
            redacted_error = redact_untrusted_error_message(e)
            self._mark_inconclusive_scan_result(result, "keras_h5_scan_failed")
            result.add_check(
                name="Keras H5 File Scan",
                passed=False,
                message=f"Error scanning Keras H5 file: {redacted_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": redacted_error,
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

    def _add_file_backed_hdf5_inspection_check(
        self,
        path: str,
        result: ScanResult,
        file_size: int,
        *,
        whole_file_hash_skipped: bool,
    ) -> None:
        """Record that Keras H5 security inspection does not require whole-file materialization."""
        result.metadata["file_backed_scan"] = True
        result.add_check(
            name="Keras H5 File-Backed Inspection",
            passed=True,
            message="Keras H5 inspection uses file-backed HDF5 metadata traversal",
            location=path,
            details={
                "file_size": file_size,
                "file_backed": True,
                "whole_file_materialized": False,
                "whole_file_hash_skipped": whole_file_hash_skipped,
                "max_hdf5_link_visits": self._MAX_HDF5_LINK_VISITS,
                "max_hdf5_json_attribute_bytes": self.max_hdf5_json_attribute_bytes,
            },
        )

    @staticmethod
    def _json_attribute_size(attr_value: Any) -> int | None:
        """Best-effort byte size for a loaded JSON-like HDF5 attribute."""
        if isinstance(attr_value, str):
            return len(attr_value.encode("utf-8", errors="ignore"))
        if isinstance(attr_value, bytes | bytearray | memoryview):
            return len(attr_value)

        nbytes = getattr(attr_value, "nbytes", None)
        if isinstance(nbytes, int):
            return nbytes

        return None

    @staticmethod
    def _hdf5_attribute_is_variable_string(attr_id: Any) -> bool:
        try:
            attr_type = attr_id.get_type()
            is_variable_str = getattr(attr_type, "is_variable_str", None)
            return bool(is_variable_str()) if callable(is_variable_str) else False
        except Exception:
            return False

    @staticmethod
    def _read_hdf5_variable_string_prefix(attr_id: Any, max_bytes: int) -> bytes:
        import numpy as np

        memory_type = h5py.h5t.C_S1.copy()
        memory_type.set_size(max_bytes)
        buffer = np.zeros((), dtype=f"S{max_bytes}")
        attr_id.read(buffer, memory_type)
        value = buffer.item()
        return bytes(value) if isinstance(value, bytes) else str(value).encode("utf-8", errors="ignore")

    def _mark_hdf5_attribute_size_limit(
        self,
        result: ScanResult,
        attr_name: str,
        *,
        attr_size: int,
        max_bytes: int,
        fail_closed: bool,
    ) -> None:
        reason = f"keras_h5_{attr_name}_size_limit_exceeded"
        if fail_closed:
            self._mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name="Keras H5 Config Size Limit"
            if attr_name in {"model_config", "training_config"}
            else "Keras H5 Attribute Size Limit",
            passed=False,
            message=f"Keras H5 {attr_name} exceeds bounded parse budget",
            severity=IssueSeverity.INFO,
            location=self.current_file_path,
            details={
                "attribute": attr_name,
                "attribute_bytes": attr_size,
                "max_attribute_bytes": max_bytes,
                "analysis_incomplete": fail_closed,
                "scan_outcome_reason": reason,
            },
            rule_code="S902",
        )

    def _read_bounded_hdf5_attribute(
        self,
        attrs: Any,
        attr_name: str,
        result: ScanResult,
        *,
        max_bytes: int,
        fail_closed: bool,
    ) -> Any:
        """Read a small HDF5 attribute without materializing unbounded variable-length values."""
        attr_id = attrs.get_id(attr_name)
        if self._hdf5_attribute_is_variable_string(attr_id):
            raw_prefix = self._read_hdf5_variable_string_prefix(attr_id, max_bytes + 1)
            if len(raw_prefix) > max_bytes:
                self._mark_hdf5_attribute_size_limit(
                    result,
                    attr_name,
                    attr_size=len(raw_prefix),
                    max_bytes=max_bytes,
                    fail_closed=fail_closed,
                )
                return self._HDF5_ATTRIBUTE_READ_SKIPPED
            return raw_prefix.decode("utf-8")

        with suppress(Exception):
            storage_size = int(attr_id.get_storage_size())
            if storage_size > max_bytes:
                self._mark_hdf5_attribute_size_limit(
                    result,
                    attr_name,
                    attr_size=storage_size,
                    max_bytes=max_bytes,
                    fail_closed=fail_closed,
                )
                return self._HDF5_ATTRIBUTE_READ_SKIPPED

        attr_value = attrs[attr_name]
        attr_size = self._json_attribute_size(attr_value)
        if attr_size is not None and attr_size > max_bytes:
            self._mark_hdf5_attribute_size_limit(
                result,
                attr_name,
                attr_size=attr_size,
                max_bytes=max_bytes,
                fail_closed=fail_closed,
            )
            return self._HDF5_ATTRIBUTE_READ_SKIPPED

        return attr_value

    def _load_json_hdf5_attribute(self, attrs: Any, attr_name: str, result: ScanResult) -> Any:
        attr_value = self._read_bounded_hdf5_attribute(
            attrs,
            attr_name,
            result,
            max_bytes=self.max_hdf5_json_attribute_bytes,
            fail_closed=True,
        )
        if attr_value is self._HDF5_ATTRIBUTE_READ_SKIPPED:
            return self._JSON_ATTRIBUTE_PARSE_FAILED
        return self._load_json_attribute(attr_value, result, attr_name)

    def _load_json_attribute(self, attr_value: Any, result: ScanResult, attr_name: str) -> Any:
        """Load a Keras JSON attribute, marking the scan incomplete on malformed metadata."""
        attr_size = self._json_attribute_size(attr_value)
        if attr_size is not None and attr_size > self.max_hdf5_json_attribute_bytes:
            reason = f"keras_h5_{attr_name}_size_limit_exceeded"
            self._mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="Keras H5 Config Size Limit",
                passed=False,
                message=f"Keras H5 {attr_name} exceeds bounded parse budget",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "attribute": attr_name,
                    "attribute_bytes": attr_size,
                    "max_attribute_bytes": self.max_hdf5_json_attribute_bytes,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                },
                rule_code="S902",
            )
            return self._JSON_ATTRIBUTE_PARSE_FAILED

        try:
            if isinstance(attr_value, bytes):
                attr_value = attr_value.decode("utf-8")
            return json.loads(attr_value)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as e:
            redacted_error = redact_untrusted_error_message(e)
            self._mark_inconclusive_scan_result(result, f"keras_h5_{attr_name}_parse_failed")
            result.add_check(
                name="Keras H5 Config Parse",
                passed=False,
                message=f"Malformed Keras H5 {attr_name}; static scan could not inspect this configuration",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={
                    "attribute": attr_name,
                    "exception": redacted_error,
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            return self._JSON_ATTRIBUTE_PARSE_FAILED

    @classmethod
    def _has_weights_like_hdf5_layout(cls, h5_file: Any, _path: str) -> bool:
        """Return True for HDF5 layouts that resemble Keras weights-only files."""
        if cls._has_legacy_weights_layout(h5_file):
            return True

        return cls._has_keras3_weights_layout(h5_file)

    @classmethod
    def _has_legacy_weights_layout(cls, h5_file: Any) -> bool:
        layer_names, layer_names_truncated = cls._read_bounded_hdf5_name_attribute(h5_file.attrs, "layer_names")
        if layer_names_truncated:
            return True
        if not layer_names:
            return False

        for index, layer_name in enumerate(layer_names):
            if index >= cls._MAX_HDF5_LAYOUT_PROBE_ITEMS:
                return True

            link = h5_file.get(layer_name, getlink=True)
            if isinstance(link, (h5py.ExternalLink, h5py.SoftLink)):
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
        layers_link = h5_file.get("layers", getlink=True)
        if isinstance(layers_link, (h5py.ExternalLink, h5py.SoftLink)):
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
            if isinstance(layer_link, (h5py.ExternalLink, h5py.SoftLink)):
                return True
            if not isinstance(layer_link, h5py.HardLink):
                continue

            layer = layers.get(layer_name, getlink=False)
            if isinstance(layer, h5py.Group) and cls._has_group_or_external_link(layer, "vars"):
                return True

        return False

    @classmethod
    def _hdf5_weight_scan_roots(cls, h5_file: Any) -> tuple[list[str], bool]:
        """Return loader-consumed HDF5 roots without following external links."""
        roots: list[str] = []
        root_set: set[str] = set()
        roots_truncated = False
        inspected_name_count = 0

        def consume_name_budget() -> bool:
            nonlocal inspected_name_count, roots_truncated
            if inspected_name_count >= cls._MAX_HDF5_LINK_VISITS:
                roots_truncated = True
                return False
            inspected_name_count += 1
            return True

        def add_root(path: str) -> bool:
            nonlocal roots_truncated
            if path in root_set:
                return True
            if len(roots) >= cls._MAX_HDF5_LINK_VISITS:
                roots_truncated = True
                return False
            roots.append(path)
            root_set.add(path)
            return True

        def add_weight_names(group: Any, prefix: str) -> bool:
            nonlocal roots_truncated
            weight_names, weight_names_truncated = cls._read_bounded_hdf5_name_attribute(
                group.attrs,
                "weight_names",
            )
            if weight_names_truncated:
                roots_truncated = True
                return False
            for weight_name in weight_names:
                if not consume_name_budget():
                    return False
                lookup_name = weight_name or "."
                if group.get(lookup_name, getlink=True) is None:
                    continue
                if weight_name.startswith("/"):
                    weight_path = weight_name.lstrip("/")
                else:
                    weight_path = f"{prefix}/{weight_name}" if prefix else weight_name
                if not add_root(weight_path):
                    return False
            return True

        def add_legacy_group_roots(group: Any, prefix: str) -> None:
            nonlocal roots_truncated
            if not add_weight_names(group, prefix):
                return
            layer_names, layer_names_truncated = cls._read_bounded_hdf5_name_attribute(group.attrs, "layer_names")
            if layer_names_truncated:
                roots_truncated = True
                return
            for layer_name in layer_names:
                if not consume_name_budget():
                    return
                layer_link = group.get(layer_name, getlink=True)
                if layer_link is None:
                    continue
                layer_path = f"{prefix}/{layer_name}" if prefix else layer_name
                if isinstance(layer_link, (h5py.ExternalLink, h5py.SoftLink)):
                    if not add_root(layer_path):
                        return
                    continue
                if not isinstance(layer_link, h5py.HardLink):
                    continue
                layer_group = group.get(layer_name, getlink=False)
                if isinstance(layer_group, h5py.Group) and not add_weight_names(layer_group, layer_path):
                    return

        if "model_config" in h5_file.attrs:
            for root_name in cls._KERAS_WEIGHT_ROOT_GROUPS:
                root_link = h5_file.get(root_name, getlink=True)
                if isinstance(root_link, (h5py.ExternalLink, h5py.SoftLink)):
                    if not add_root(root_name):
                        break
                    continue
                if not isinstance(root_link, h5py.HardLink):
                    continue
                root_group = h5_file.get(root_name, getlink=False)
                if isinstance(root_group, h5py.Group):
                    add_legacy_group_roots(root_group, root_name)
                if roots_truncated:
                    break
            return roots, roots_truncated

        layer_names, layer_names_truncated = cls._read_bounded_hdf5_name_attribute(h5_file.attrs, "layer_names")
        if layer_names_truncated:
            return roots, True
        if layer_names:
            add_legacy_group_roots(h5_file, "")
            return roots, roots_truncated

        layers_link = h5_file.get("layers", getlink=True)
        if isinstance(layers_link, (h5py.ExternalLink, h5py.SoftLink)):
            add_root("layers")
            return roots, roots_truncated
        if not isinstance(layers_link, h5py.HardLink):
            return roots, False

        layers = h5_file.get("layers", getlink=False)
        if not isinstance(layers, h5py.Group):
            return roots, False

        for layer_name in layers:
            if not consume_name_budget():
                break
            layer_path = f"layers/{layer_name}"
            layer_link = layers.get(layer_name, getlink=True)
            if isinstance(layer_link, (h5py.ExternalLink, h5py.SoftLink)):
                if not add_root(layer_path):
                    break
                continue
            if not isinstance(layer_link, h5py.HardLink):
                continue

            layer = layers.get(layer_name, getlink=False)
            if (
                isinstance(layer, h5py.Group)
                and layer.get("vars", getlink=True) is not None
                and not add_root(f"{layer_path}/vars")
            ):
                break

        return roots, roots_truncated

    @staticmethod
    def _has_group_or_external_link(group: Any, name: str) -> bool:
        link = group.get(name, getlink=True)
        if isinstance(link, (h5py.ExternalLink, h5py.SoftLink)):
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

    @classmethod
    def _read_bounded_hdf5_name_attribute(cls, attrs: Any, attr_name: str) -> tuple[list[str], bool]:
        """Read Keras HDF5 name-list attributes only when their encoded size is bounded."""
        if attr_name not in attrs:
            return [], False

        try:
            attr_id = attrs.get_id(attr_name)
        except Exception:
            return [], True

        attr_point_count: int | None = None
        with suppress(Exception):
            attr_space = attr_id.get_space()
            attr_point_count = int(attr_space.get_simple_extent_npoints())
            if attr_point_count > cls._MAX_HDF5_LINK_VISITS:
                return [], True

        if cls._hdf5_attribute_is_variable_string(attr_id):
            return cls._read_hdf5_variable_string_name_attribute(
                attr_id,
                max_bytes=cls._MAX_HDF5_NAME_ATTRIBUTE_BYTES,
                point_count=attr_point_count,
            )

        with suppress(Exception):
            if int(attr_id.get_storage_size()) > cls._MAX_HDF5_NAME_ATTRIBUTE_BYTES:
                return [], True

        try:
            attr_value = attrs[attr_name]
        except Exception:
            return [], True

        attr_size = cls._json_attribute_size(attr_value)
        if attr_size is not None and attr_size > cls._MAX_HDF5_NAME_ATTRIBUTE_BYTES:
            return [], True

        names = cls._decode_hdf5_names(attr_value)
        if len(names) > cls._MAX_HDF5_LINK_VISITS:
            return names[: cls._MAX_HDF5_LINK_VISITS], True
        return names, False

    @classmethod
    def _read_hdf5_variable_string_name_attribute(
        cls,
        attr_id: Any,
        *,
        max_bytes: int,
        point_count: int | None,
    ) -> tuple[list[str], bool]:
        import numpy as np

        if point_count is None:
            with suppress(Exception):
                point_count = int(attr_id.get_space().get_simple_extent_npoints())
        if point_count is None or point_count <= 0 or point_count > cls._MAX_HDF5_LINK_VISITS:
            return [], True

        per_item_bytes = min(cls._MAX_HDF5_REFERENCE_TEXT_CHARS, max(max_bytes // point_count, 1)) + 1
        if point_count * per_item_bytes > max_bytes + cls._MAX_HDF5_LINK_VISITS:
            return [], True

        with suppress(Exception):
            dims = tuple(int(dimension) for dimension in attr_id.get_space().get_simple_extent_dims())
            buffer_shape = dims if dims else ()
            memory_type = h5py.h5t.C_S1.copy()
            memory_type.set_size(per_item_bytes)
            buffer = np.zeros(buffer_shape, dtype=f"S{per_item_bytes}")
            attr_id.read(buffer, memory_type)
            raw_items = [buffer.item()] if buffer_shape == () else buffer.reshape(-1).tolist()

            names = []
            total_bytes = 0
            truncated = False
            for raw_item in raw_items:
                raw_bytes = bytes(raw_item) if isinstance(raw_item, bytes) else str(raw_item).encode("utf-8", "ignore")
                total_bytes += len(raw_bytes)
                if len(raw_bytes) >= per_item_bytes or total_bytes > max_bytes:
                    truncated = True
                names.append(raw_bytes.decode("utf-8", errors="ignore"))
            names = [name for name in names if name]
            if len(names) > cls._MAX_HDF5_LINK_VISITS:
                return names[: cls._MAX_HDF5_LINK_VISITS], True
            return names, truncated

        return [], True

    @staticmethod
    def _normalize_hdf5_soft_link_path(source_name: str, target_path: str) -> str | None:
        if not target_path:
            return None

        base_parts: list[str] = []
        if not target_path.startswith("/"):
            base_parts = [part for part in source_name.split("/")[:-1] if part]

        parts: list[str] = []
        for part in [*base_parts, *target_path.split("/")]:
            if part in {"", "."}:
                continue
            if part == "..":
                return None
            parts.append(part)

        return "/".join(parts)

    @classmethod
    def _resolve_hdf5_soft_link(
        cls,
        h5_file: Any,
        source_name: str,
        soft_link: Any,
    ) -> tuple[str | None, Any | None, bool]:
        """Resolve internal SoftLinks to a final link without following ExternalLinks."""
        target_path = cls._normalize_hdf5_soft_link_path(source_name, getattr(soft_link, "path", ""))
        if target_path is None:
            return None, None, True

        visited_paths: set[str] = set()
        for _depth in range(cls._MAX_HDF5_SOFT_LINK_RESOLUTION_DEPTH):
            if target_path in visited_paths:
                return target_path, None, True
            visited_paths.add(target_path)

            target_link = h5_file.get(target_path, getlink=True)
            if target_link is None:
                return target_path, None, True
            if not isinstance(target_link, h5py.SoftLink):
                return target_path, target_link, False

            next_target_path = cls._normalize_hdf5_soft_link_path(target_path, getattr(target_link, "path", ""))
            if next_target_path is None:
                return target_path, None, True
            target_path = next_target_path

        return target_path, None, True

    def _check_hdf5_external_references(
        self,
        h5_file: Any,
        result: ScanResult,
        source_path: str,
        *,
        keras_version: str | None = None,
    ) -> None:
        """Detect HDF5 external links/storage before any Keras-specific parsing short-circuits."""
        if keras_version is None:
            keras_version = self._current_h5_keras_version

        findings: list[dict[str, Any]] = []
        external_reference_count = 0
        external_storage_segments_truncated = False
        soft_link_resolution_incomplete = False
        weight_roots, weight_roots_truncated = self._hdf5_weight_scan_roots(h5_file)

        def record_external_storage(name: str, obj: Any) -> None:
            nonlocal external_reference_count, external_storage_segments_truncated
            storage_properties = obj.id.get_create_plist()
            external_storage_segment_count = storage_properties.get_external_count()
            if external_storage_segment_count <= 0:
                return

            external_reference_count += 1
            if len(findings) >= self._MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                return
            segments = [
                {
                    **self._hdf5_external_storage_filename_details(filename),
                    "offset": int(offset),
                    "size": int(size),
                }
                for filename, offset, size in (
                    storage_properties.get_external(index)
                    for index in range(
                        min(
                            external_storage_segment_count,
                            self._MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS,
                        )
                    )
                )
            ]
            hdf5_path, hdf5_path_truncated = self._bounded_hdf5_reference_text(f"/{name}".replace("//", "/"))
            external_storage_finding: dict[str, Any] = {
                "kind": "external_storage",
                "hdf5_path": hdf5_path,
                "segments": segments,
            }
            if hdf5_path_truncated:
                external_storage_finding["hdf5_path_truncated"] = True
            if external_storage_segment_count > len(segments):
                external_storage_segments_truncated = True
                external_storage_finding["segment_count"] = external_storage_segment_count
                external_storage_finding["segments_truncated"] = True
            findings.append(external_storage_finding)

        def visit(name: str, link: Any, *, obj: Any | None = None, source_name: str | None = None) -> None:
            nonlocal external_reference_count, soft_link_resolution_incomplete
            resolution_source_name = source_name or name
            if isinstance(link, h5py.ExternalLink):
                external_reference_count += 1
                if len(findings) < self._MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                    hdf5_path, hdf5_path_truncated = self._bounded_hdf5_reference_text(f"/{name}".replace("//", "/"))
                    filename, filename_truncated = self._bounded_hdf5_reference_text(link.filename)
                    target_path, target_path_truncated = self._bounded_hdf5_reference_text(link.path)
                    external_link_finding: dict[str, Any] = {
                        "kind": "ExternalLink",
                        "hdf5_path": hdf5_path,
                        "filename": filename,
                        "path": target_path,
                    }
                    if hdf5_path_truncated:
                        external_link_finding["hdf5_path_truncated"] = True
                    if filename_truncated:
                        external_link_finding["filename_truncated"] = True
                    if target_path_truncated:
                        external_link_finding["path_truncated"] = True
                    findings.append(external_link_finding)
                return

            if isinstance(link, h5py.SoftLink):
                soft_target_path, target_link, incomplete = self._resolve_hdf5_soft_link(
                    h5_file,
                    resolution_source_name,
                    link,
                )
                if incomplete or soft_target_path is None or target_link is None:
                    soft_link_resolution_incomplete = True
                    return
                if isinstance(target_link, h5py.ExternalLink):
                    visit(name, target_link)
                    return
                if not isinstance(target_link, h5py.HardLink):
                    return
                target_obj = h5_file.get(soft_target_path, getlink=False)
                if isinstance(target_obj, h5py.Dataset):
                    record_external_storage(name, target_obj)
                return

            if not isinstance(link, h5py.HardLink):
                return

            if obj is None:
                obj = h5_file.get(name, getlink=False)
            if isinstance(obj, h5py.Dataset):
                record_external_storage(name, obj)

        visited_link_count = 0
        link_visits_truncated = False
        for root_path in weight_roots:
            root_link = h5_file.get(root_path, getlink=True)
            if root_link is None:
                continue
            resolved_root_link = root_link
            if isinstance(root_link, h5py.ExternalLink):
                visited_link_count += 1
                visit(root_path, root_link)
                continue
            if isinstance(root_link, h5py.SoftLink):
                visited_link_count += 1
                target_path, target_link, incomplete = self._resolve_hdf5_soft_link(h5_file, root_path, root_link)
                if incomplete or target_path is None or target_link is None:
                    soft_link_resolution_incomplete = True
                    continue
                if isinstance(target_link, h5py.ExternalLink):
                    visit(root_path, target_link)
                    continue
                if not isinstance(target_link, h5py.HardLink):
                    continue
                root_obj = h5_file.get(target_path, getlink=False)
                if isinstance(root_obj, h5py.Dataset):
                    visit(root_path, target_link, obj=root_obj)
                    continue
                resolved_root_path = target_path
                resolved_root_link = target_link
            else:
                resolved_root_path = root_path
            if not isinstance(resolved_root_link, h5py.HardLink):
                continue

            root_obj = h5_file.get(resolved_root_path, getlink=False)
            if isinstance(root_obj, h5py.Dataset):
                visited_link_count += 1
                visit(root_path, resolved_root_link, obj=root_obj)
                continue
            if not isinstance(root_obj, h5py.Group):
                continue

            remaining_link_visits = max(self._MAX_HDF5_LINK_VISITS - visited_link_count, 0)
            if remaining_link_visits == 0:
                link_visits_truncated = True
                break

            def visit_root(
                name: str,
                link: Any,
                *,
                prefix: str = root_path,
                source_prefix: str = resolved_root_path,
            ) -> None:
                visit(f"{prefix}/{name}", link, source_name=f"{source_prefix}/{name}")

            root_visited, root_truncated = self._visit_hdf5_links(
                root_obj,
                visit_root,
                max_links=remaining_link_visits,
            )
            visited_link_count += root_visited
            if root_truncated:
                link_visits_truncated = True
                break

        external_references_truncated = external_reference_count > len(findings)
        if (
            weight_roots_truncated
            or link_visits_truncated
            or external_references_truncated
            or external_storage_segments_truncated
            or soft_link_resolution_incomplete
        ):
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
                    "weight_roots_truncated": weight_roots_truncated,
                    "link_visits_truncated": link_visits_truncated,
                    "external_reference_count": external_reference_count,
                    "reported_external_reference_count": len(findings),
                    "external_references_truncated": external_references_truncated,
                    "external_storage_segments_truncated": external_storage_segments_truncated,
                    "soft_link_resolution_incomplete": soft_link_resolution_incomplete,
                },
                rule_code="S902",
            )

        if not findings:
            return

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

        display_keras_version = redact_evidence_string(keras_version) if isinstance(keras_version, str) else None
        vuln_status = self._is_vulnerable_to_cve_2026_1669(keras_version) if isinstance(keras_version, str) else None
        if vuln_status is True:
            details["keras_version"] = display_keras_version
            result.add_check(
                name="CVE-2026-1669: HDF5 External Weight Reference",
                passed=False,
                message=(
                    f"CVE-2026-1669: Keras {display_keras_version} weight file uses HDF5 external references that can "
                    "disclose arbitrary local file contents during model loading"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2026_1669_explanation("hdf5_external_reference"),
            )
            return

        if isinstance(keras_version, str):
            details["keras_version"] = display_keras_version
            if vuln_status is False:
                details["parse_status"] = "untrusted_artifact_version"
                details["version_source"] = "hdf5_file_attribute"
                result.add_check(
                    name="HDF5 External Weight Reference Risk (Untrusted Version Metadata)",
                    passed=False,
                    message=(
                        "HDF5 external references detected in standalone Keras H5 weights; "
                        f"the file claims Keras {display_keras_version}, but artifact-controlled version metadata "
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
                f"{self._format_keras_version_context(display_keras_version)}; cannot confidently attribute "
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
    def _fsdecode_evidence(value: Any) -> str:
        try:
            return os.fsdecode(value)
        except TypeError:
            return str(value)

    @classmethod
    def _bounded_hdf5_reference_text(cls, value: Any) -> tuple[str, bool]:
        """Return redacted, bounded HDF5 reference evidence and whether it was truncated."""
        text = cls._fsdecode_evidence(value)
        redacted_text = redact_evidence_string(text, max_chars=cls._MAX_HDF5_REFERENCE_TEXT_CHARS)
        was_truncated = max(len(text), len(redacted_text)) > cls._MAX_HDF5_REFERENCE_TEXT_CHARS
        return redacted_text[: cls._MAX_HDF5_REFERENCE_TEXT_CHARS], was_truncated

    @classmethod
    def _hdf5_external_storage_filename_details(cls, filename: Any) -> dict[str, Any]:
        """Return bounded external-storage filename evidence."""
        bounded_filename, filename_truncated = cls._bounded_hdf5_reference_text(filename)
        details: dict[str, Any] = {"filename": bounded_filename}
        if filename_truncated:
            details["filename_truncated"] = True
        return details

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
        model_class_is_string = isinstance(model_class, str)
        redacted_model_class = (
            redact_evidence_string(model_class) if model_class_is_string else f"<invalid:{type(model_class).__name__}>"
        )
        result.metadata["model_class"] = redacted_model_class

        # Check for subclassed models (custom class names)
        if model_class_is_string:
            check_subclassed_model(model_class, result, self.current_file_path)
        else:
            self._mark_inconclusive_scan_result(result, "keras_h5_model_class_invalid_type")
            result.add_check(
                name="Model Class Type Validation",
                passed=False,
                message=f"Invalid model class type: expected str, got {type(model_class).__name__}",
                rule_code="S902",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={"actual_type": type(model_class).__name__, "expected_type": "str"},
            )
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
            if model_class_is_string and model_class in self._MODEL_CONTAINER_CLASSES:
                self._mark_inconclusive_scan_result(result, "keras_h5_model_layers_missing")
                result.add_check(
                    name="Layers Presence Validation",
                    passed=False,
                    message=f"Model config for {redacted_model_class} is missing required layers list",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"model_class": redacted_model_class, "expected_key": "config.layers"},
                )
            else:
                result.add_check(
                    name="Model Config Structure Validation",
                    passed=True,
                    message="Keras model config has no layer configuration",
                    location=self.current_file_path,
                    details={"model_class": redacted_model_class},
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
        elif model_class_is_string and model_class in self._MODEL_CONTAINER_CLASSES:
            self._mark_inconclusive_scan_result(result, "keras_h5_model_layers_missing")
            result.add_check(
                name="Layers Presence Validation",
                passed=False,
                message=f"Model config for {redacted_model_class} is missing required layers list",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"model_class": redacted_model_class, "expected_key": "config.layers"},
            )

        # Count of each layer type
        layer_counts: dict[str, int] = {}
        layer_count_display_keys: dict[str, str] = {}
        layer_count_next_occurrences: dict[str, int] = {}
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
            layer_class_is_string = isinstance(layer_class, str)
            redacted_layer_class = (
                redact_evidence_string(layer_class)
                if layer_class_is_string
                else f"<invalid:{type(layer_class).__name__}>"
            )
            if not layer_class_is_string:
                self._mark_inconclusive_scan_result(result, "keras_h5_layer_class_invalid_type")
                result.add_check(
                    name="Layer Class Type Validation",
                    passed=False,
                    message=f"Invalid layer class type: expected str, got {type(layer_class).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"actual_type": type(layer_class).__name__, "expected_type": "str"},
                )
            layer_config = layer.get("config", {})
            is_lambda_layer = layer_class_is_string and self._is_lambda_layer_class(layer_class)
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
            layer_count_identity = (
                f"str:{layer_count_key}"
                if isinstance(layer_count_key, str)
                else f"invalid:{type(layer_count_key).__name__}"
            )
            redacted_layer_count_key = layer_count_display_keys.get(layer_count_identity)
            if redacted_layer_count_key is None:
                display_key = (
                    layer_count_key
                    if isinstance(layer_count_key, str)
                    else f"<invalid:{type(layer_count_key).__name__}>"
                )
                redacted_layer_count_key = redact_evidence_mapping_key(
                    display_key,
                    layer_counts,
                    next_occurrences=layer_count_next_occurrences,
                )
                layer_count_display_keys[layer_count_identity] = redacted_layer_count_key
            layer_counts[redacted_layer_count_key] = layer_counts.get(redacted_layer_count_key, 0) + 1

            # Check for suspicious layer types
            if (layer_class_is_string and layer_class in self.suspicious_layer_types) or is_lambda_layer:
                # Special handling for Lambda layers - validate Python code
                if is_lambda_layer:
                    lambda_layer_count += 1
                    layer_name = f"lambda_{lambda_layer_count}"
                    self._check_lambda_layer(layer_config, result, layer_name)
                    keras_version = result.metadata.get("keras_version")
                    classification_keras_version = self._current_h5_keras_version

                    # CVE-2024-3660: Lambda layers enable arbitrary code injection
                    cve_2024_3660_status = (
                        self._is_vulnerable_to_cve_2024_3660(classification_keras_version)
                        if isinstance(classification_keras_version, str)
                        else None
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
                        self._is_vulnerable_to_cve_2025_9905(classification_keras_version)
                        if isinstance(classification_keras_version, str)
                        else None
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
                        message=f"Suspicious layer type found: {redacted_layer_class}",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={
                            "layer_class": redacted_layer_class,
                            "description": self.suspicious_layer_types[layer_class],
                            "layer_config": redact_evidence_value(layer_config, max_string_chars=200),
                        },
                        why=get_pattern_explanation("lambda_layer") if is_lambda_layer else None,
                        rule_code="S902",
                    )

            # Detect unknown/custom layer classes not in the standard Keras set
            elif layer_class_is_string and layer_class and not is_known_safe_keras_layer_class(layer_class):
                result.add_check(
                    name="Custom Layer Class Detection",
                    passed=False,
                    message=f"Unknown/custom layer class detected: {redacted_layer_class}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "layer_class": redacted_layer_class,
                        "layer_config": redact_evidence_value(layer.get("config", {}), max_string_chars=200),
                        "risk": "Custom layer classes require external code to load and may execute arbitrary logic",
                    },
                    rule_code="S810",
                )

            # Check layer configuration for suspicious strings
            self._check_config_for_suspicious_strings(
                layer_config,
                result,
                "Lambda" if is_lambda_layer else redacted_layer_class,
                redact_nested_context=is_lambda_layer,
                case_sensitive=is_lambda_layer,
            )

            # If there are nested models, scan them recursively
            if layer_class_is_string and layer_class in self._MODEL_CONTAINER_CLASSES and "config" in layer:
                nested_config = layer.get("config")
                if isinstance(nested_config, dict) and "layers" in nested_config:
                    self._scan_model_config(layer, result)
                elif isinstance(nested_config, dict):
                    self._mark_inconclusive_scan_result(result, "keras_h5_nested_model_layers_missing")
                    result.add_check(
                        name="Nested Model Layers Presence Validation",
                        passed=False,
                        message=f"Nested model config for {redacted_layer_class} is missing required layers list",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"layer_class": redacted_layer_class, "expected_key": "config.layers"},
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
            or top_module in _DANGEROUS_CONFIG_MODULE_ROOTS
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
                    "cvss": 7.3,
                    "cwe": "CWE-94",
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
                    "cvss": 7.3,
                    "cwe": "CWE-94",
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
        nested_callable_references: list[tuple[Any, Any]] = []
        if isinstance(function_str, dict):
            encoded_function_handled = check_lambda_dict_function(
                function_str,
                result,
                self.current_file_path,
                callback_layer_name,
            )
            nested_callable_references = self._lambda_callable_dict_references(function_str)
            if not encoded_function_handled and not nested_callable_references:
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
        module_references.extend((*reference, "function_dict") for reference in nested_callable_references)

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
    def _lambda_callable_dict_references(function_dict: dict[str, Any]) -> list[tuple[Any, Any]]:
        """Extract every module/function pair that may drive callable lookup."""
        if "module" not in function_dict:
            return []

        module_value = function_dict.get("module")
        references: list[tuple[Any, Any]] = []
        for function_key in ("function_name", "function", "config", "registered_name"):
            if function_key not in function_dict:
                continue
            function_value = function_dict.get(function_key)
            if any(type(existing) is type(function_value) and existing == function_value for _, existing in references):
                continue
            references.append((module_value, function_value))
        return references

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
                        redacted_context = redact_evidence_string(str(context))
                        result.add_check(
                            name="Suspicious Configuration String Check",
                            passed=False,
                            message=(
                                f"Suspicious configuration string found in {redacted_context}: '{suspicious_term}'"
                            ),
                            severity=IssueSeverity.INFO,
                            location=f"{self.current_file_path} ({redacted_context})",
                            rule_code="S902",
                            details={
                                "suspicious_term": suspicious_term,
                                "context": redacted_context,
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
                        "h5_keys": redact_evidence_value(list(h5_file.keys()), max_string_chars=200),
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
                                "model_class": redact_evidence_value(
                                    config.get("class_name", "Unknown"),
                                    max_string_chars=200,
                                ),
                                "keras_version": redact_evidence_value(
                                    h5_file.attrs.get("keras_version", "unknown").decode("utf-8")
                                    if isinstance(h5_file.attrs.get("keras_version"), bytes)
                                    else h5_file.attrs.get("keras_version", "unknown"),
                                    max_string_chars=200,
                                ),
                            }
                        )

                        # Extract layer information
                        if "config" in config:
                            layers = config["config"].get("layers", [])
                            metadata.update(
                                {
                                    "layer_count": len(layers),
                                    "layer_types": redact_evidence_value(
                                        list({layer.get("class_name", "Unknown") for layer in layers}),
                                        max_string_chars=200,
                                    ),
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
                                if obj.id.get_create_plist().get_external_count() > 0:
                                    skipped_external_weight_entries = True
                                    return
                                param_count = obj.size
                                total_params += param_count
                                weight_layers.append(
                                    {
                                        "name": redact_evidence_string(name, max_chars=200),
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
                                "parameter_details": redact_evidence_value(
                                    weight_layers[:10],
                                    max_string_chars=200,
                                ),  # First 10 layers
                                "weight_link_visits": visited_links,
                            }
                        )
                        if skipped_external_weight_entries:
                            metadata["external_weight_entries_skipped"] = True
                        if visits_truncated:
                            metadata["weight_link_visits_truncated"] = True

        except Exception as e:
            metadata["extraction_error"] = redact_untrusted_error_message(e)

        return metadata
