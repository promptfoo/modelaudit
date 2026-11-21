"""Shared utilities for Keras scanners."""

import base64
import re
from abc import abstractmethod
from collections.abc import Callable, Iterable, Iterator
from enum import Enum, auto
from typing import Any, ClassVar

from modelaudit.detectors.suspicious_symbols import (
    KNOWN_SAFE_KERAS_LAYER_CLASSES,
    KNOWN_SAFE_KERAS_LOSSES,
    KNOWN_SAFE_KERAS_METRICS,
    KNOWN_SAFE_MODEL_CLASSES,
    SUSPICIOUS_CONFIG_PROPERTIES,
    SUSPICIOUS_LAYER_TYPES,
)

from ..config.explanations import get_cve_2025_1550_explanation
from ._evidence_redaction import redact_evidence_string, redact_evidence_value
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult

# Importable module roots that are explicitly dangerous when referenced in config.json.
DANGEROUS_CONFIG_MODULE_ROOTS = frozenset(
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

_SAFE_KERAS_MODULE_ROOTS: frozenset[str] = frozenset({"keras", "tensorflow", "tf_keras", "tf", "numpy", "math"})

# Native modules expose both safe and executable symbols. Match individual symbols.
_DANGEROUS_EXACT_MODULE_SYMBOLS = {
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

# Dangerous patterns to look for inside decoded Lambda bytecode / source
_LAMBDA_DANGEROUS_PATTERNS: list[str] = [
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
    "socket",
    "http",
    "https",
    "urllib",
    "urllib3",
    "shutil",
    "ctypes",
]
_MARSHALLED_CODE_FILENAME_RE = re.compile(r"(?i)(?:[A-Za-z]:)?[\\/][^\x00-\x1f\x7f\"'`<>|]+?\.py[co]?")
_MARSHALLED_NAME_SEPARATOR_RE = r"(?:\.|[\x00-\x1f\x7f\ufffd]{1,16})"
_MAX_LAMBDA_CODE_B64_CHARS = 1024 * 1024

_EXTRA_SAFE_KERAS_LOSS_IDENTIFIERS: frozenset[str] = frozenset(
    {
        "bce",
        "cce",
        "scce",
    }
)

_EXTRA_SAFE_KERAS_METRIC_IDENTIFIERS: frozenset[str] = frozenset(
    {
        "acc",
        "accuracy",
        "auc",
        "bce",
        "cce",
        "fn",
        "fp",
        "iou",
        "kld",
        "mae",
        "mape",
        "mean_metric_wrapper",
        "mse",
        "msle",
        "rmse",
        "scce",
        "tn",
        "tp",
    }
)
_TRUSTED_KERAS_ROOT_CLASS_MODULES: frozenset[str] = frozenset(
    {
        "keras",
        "tensorflow.keras",
        "tensorflow.python.keras",
        "tf.keras",
        "tf_keras",
    }
)
_TRUSTED_KERAS_LAYER_CLASS_MODULES: frozenset[str] = frozenset(
    {
        "keras.layers",
        "tensorflow.keras.layers",
        "tensorflow.python.keras.layers",
        "tf.keras.layers",
        "tf_keras.layers",
    }
)
_TRUSTED_KERAS_MODEL_CLASS_MODULES: frozenset[str] = frozenset(
    {
        "keras.models",
        "tensorflow.keras.models",
        "tensorflow.python.keras.models",
        "tf.keras.models",
        "tf_keras.models",
    }
)


def _normalize_keras_identifier(value: str) -> str:
    """Normalize serialized Keras identifiers for allowlist lookups."""
    return value.strip().lower()


def normalize_keras_layer_class(value: str) -> str:
    """Normalize Keras layer class names while preserving custom namespaces."""
    normalized = value.strip()
    module_path, _, class_name = normalized.rpartition(".")
    normalized_module_path = module_path.lower()
    if class_name and (
        (
            class_name in KNOWN_SAFE_MODEL_CLASSES
            and normalized_module_path in (_TRUSTED_KERAS_ROOT_CLASS_MODULES | _TRUSTED_KERAS_MODEL_CLASS_MODULES)
        )
        or (
            class_name in KNOWN_SAFE_KERAS_LAYER_CLASSES
            and class_name not in KNOWN_SAFE_MODEL_CLASSES
            and normalized_module_path in _TRUSTED_KERAS_LAYER_CLASS_MODULES
        )
    ):
        return class_name
    return normalized


def _camel_to_snake(value: str) -> str:
    """Convert CamelCase Keras class names to snake_case identifiers."""
    compact = value.strip()
    if not compact:
        return ""

    first_pass = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", compact)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first_pass).replace("-", "_").lower()


def _build_safe_identifier_index(
    identifiers: frozenset[str],
    extra_aliases: frozenset[str] = frozenset(),
) -> frozenset[str]:
    """Build a normalized lookup index for class names and string aliases."""
    safe_identifiers: set[str] = {_normalize_keras_identifier(alias) for alias in extra_aliases if alias.strip()}

    for identifier in identifiers:
        cleaned_identifier = identifier.strip()
        if not cleaned_identifier:
            continue

        safe_identifiers.add(_normalize_keras_identifier(cleaned_identifier))
        safe_identifiers.add(_camel_to_snake(cleaned_identifier))

    return frozenset(filter(None, safe_identifiers))


_SAFE_KERAS_LAYER_CLASSES = frozenset(
    _normalize_keras_identifier(layer_class) for layer_class in KNOWN_SAFE_KERAS_LAYER_CLASSES if layer_class.strip()
)
_SAFE_KERAS_LOSS_IDENTIFIERS = _build_safe_identifier_index(
    KNOWN_SAFE_KERAS_LOSSES,
    _EXTRA_SAFE_KERAS_LOSS_IDENTIFIERS,
)
_SAFE_KERAS_METRIC_IDENTIFIERS = _build_safe_identifier_index(
    KNOWN_SAFE_KERAS_METRICS,
    _EXTRA_SAFE_KERAS_METRIC_IDENTIFIERS,
)


def is_known_safe_keras_layer_class(layer_class: Any) -> bool:
    """Return True when a serialized Keras layer class is known-safe."""
    return (
        isinstance(layer_class, str)
        and _normalize_keras_identifier(normalize_keras_layer_class(layer_class)) in _SAFE_KERAS_LAYER_CLASSES
    )


def is_known_safe_keras_loss(identifier: Any) -> bool:
    """Return True when a serialized Keras loss identifier is known-safe."""
    return isinstance(identifier, str) and _normalize_keras_identifier(identifier) in _SAFE_KERAS_LOSS_IDENTIFIERS


def is_known_safe_keras_metric(identifier: Any) -> bool:
    """Return True when a serialized Keras metric identifier is known-safe."""
    return isinstance(identifier, str) and _normalize_keras_identifier(identifier) in _SAFE_KERAS_METRIC_IDENTIFIERS


def find_case_insensitive_substrings(text: str, patterns: Iterable[str]) -> list[str]:
    """Return configured substrings present in `text` using one lowercase pass."""
    lowered = text.lower()
    return [pattern for pattern in patterns if pattern in lowered]


def find_lambda_dangerous_patterns(text: str, patterns: Iterable[str]) -> list[str]:
    """Match dangerous Lambda bytecode text while ignoring marshalled source filenames."""
    sanitized = _MARSHALLED_CODE_FILENAME_RE.sub(" ", text)
    return [
        pattern for pattern in patterns if re.search(_lambda_dangerous_pattern_regex(pattern), sanitized, re.IGNORECASE)
    ]


def _lambda_dangerous_pattern_regex(pattern: str) -> str:
    """Match dotted names across bounded marshal metadata without identifier substrings."""
    pattern_body = _MARSHALLED_NAME_SEPARATOR_RE.join(re.escape(part) for part in pattern.split("."))
    return rf"(?<![0-9A-Za-z_]){pattern_body}(?![0-9A-Za-z_])"


def iter_keras_serialized_identifiers(value: Any) -> Iterator[tuple[str, Any]]:
    """Yield meaningful serialized Keras identifiers from nested configs.

    This walks nested `loss`, `metrics`, and related config trees while avoiding
    unrelated fields such as `name`, `dtype`, and other bookkeeping entries that
    would otherwise create noisy false positives.
    """
    if isinstance(value, str):
        identifier = value.strip()
        if identifier:
            yield identifier, value
        return

    if isinstance(value, dict):
        class_name = value.get("class_name")
        if isinstance(class_name, str) and class_name.strip():
            yield class_name.strip(), value

        registered_name = value.get("registered_name")
        if isinstance(registered_name, str) and registered_name.strip():
            yield registered_name.strip(), value

        config = value.get("config")
        if isinstance(config, dict):
            for key in ("fn", "function", "loss", "losses", "metric", "metrics", "weighted_metrics"):
                if key in config:
                    yield from iter_keras_serialized_identifiers(config[key])

        for key, nested_value in value.items():
            if key in {"class_name", "config", "module", "name", "registered_name"}:
                continue
            yield from iter_keras_serialized_identifiers(nested_value)
        return

    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from iter_keras_serialized_identifiers(item)


def _check_custom_object_config(
    config_value: Any,
    result: ScanResult,
    location: str,
    *,
    check_name: str,
    object_kind: str,
    details_key: str,
    is_known_safe_identifier: Callable[[Any], bool],
) -> None:
    """Flag custom serialized Keras objects while deduplicating normalized identifiers."""
    seen_identifiers: set[str] = set()

    for identifier, raw_object in iter_keras_serialized_identifiers(config_value):
        normalized_identifier = _normalize_keras_identifier(identifier)
        if not normalized_identifier or is_known_safe_identifier(identifier):
            continue
        if normalized_identifier in seen_identifiers:
            continue
        seen_identifiers.add(normalized_identifier)

        redacted_identifier = redact_evidence_string(identifier)
        result.add_check(
            name=check_name,
            passed=False,
            message=f"Model contains custom {object_kind}: {redacted_identifier}",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                details_key: redact_evidence_value(raw_object),
                "identifier": redacted_identifier,
            },
            rule_code="S305",
        )


def check_custom_metric_config(metrics_config: Any, result: ScanResult, location: str) -> None:
    """Flag custom metrics embedded anywhere in a serialized metric tree."""
    _check_custom_object_config(
        metrics_config,
        result,
        location,
        check_name="Custom Metric Detection",
        object_kind="metric",
        details_key="metric",
        is_known_safe_identifier=is_known_safe_keras_metric,
    )


def check_custom_loss_config(loss_config: Any, result: ScanResult, location: str) -> None:
    """Flag custom losses embedded anywhere in a serialized loss tree."""
    _check_custom_object_config(
        loss_config,
        result,
        location,
        check_name="Custom Loss Detection",
        object_kind="loss",
        details_key="loss",
        is_known_safe_identifier=is_known_safe_keras_loss,
    )


def check_lambda_dict_function(
    function_dict: dict[str, Any],
    result: ScanResult,
    location: str,
    layer_name: str,
) -> bool:
    """Check a Keras 3.x dict-format Lambda function for dangerous code.

    Keras 3.x serialises Lambda functions as::

        {"class_name": "__lambda__",
         "config": {"code": "<base64-encoded bytecode>", ...}}

    Returns True if the dict was recognised and handled, False otherwise.
    """
    class_name = function_dict.get("class_name")
    if class_name != "__lambda__":
        return False

    redacted_layer_name = redact_evidence_string(str(layer_name))
    config = function_dict.get("config")
    if not isinstance(config, dict):
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=(
                f"Lambda layer '{redacted_layer_name}' uses malformed dict-format function metadata "
                "(config is not a dict)"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "function_format": "dict",
                "parse_status": "invalid_config",
                "function_payload_omitted": "malformed_lambda_config_may_contain_sensitive_payload",
                "config_type": type(config).__name__,
            },
            why="Malformed dict-format Lambda metadata is suspicious and prevents bytecode inspection.",
        )
        return True

    code_b64 = config.get("code")
    if not code_b64 or not isinstance(code_b64, str):
        # Dict-format Lambda with no code field — flag as suspicious
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{redacted_layer_name}' uses dict-format function with no code field",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "function_format": "dict",
            },
            why="Lambda layers with dict-format functions indicate Keras 3.x bytecode serialisation.",
        )
        return True

    if len(code_b64) > _MAX_LAMBDA_CODE_B64_CHARS:
        _add_lambda_code_size_limit_check(code_b64, result, location, layer_name, function_format="dict")
        return True

    _check_lambda_encoded_code(
        code_b64,
        result,
        location,
        layer_name,
        function_format="dict",
        bytecode_format="dict_bytecode",
        format_label="dict-format",
    )
    return True


def check_lambda_list_function(
    function_data: list[Any],
    result: ScanResult,
    location: str,
    layer_name: str,
) -> bool:
    """Check legacy Keras list-format Lambda function bytecode."""
    redacted_layer_name = redact_evidence_string(str(layer_name))
    if not function_data:
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{redacted_layer_name}' uses list-format function with no encoded code field",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "function_format": "list",
            },
            why="Lambda layers with list-format functions indicate encoded bytecode serialisation.",
        )
        return True

    code_b64 = function_data[0]
    if not code_b64 or not isinstance(code_b64, str):
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{redacted_layer_name}' uses list-format function with no encoded code field",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "function_format": "list",
                "code_type": type(code_b64).__name__,
            },
            why="Lambda layers with list-format functions indicate encoded bytecode serialisation.",
        )
        return True

    if len(code_b64) > _MAX_LAMBDA_CODE_B64_CHARS:
        _add_lambda_code_size_limit_check(code_b64, result, location, layer_name, function_format="list")
        return True

    _check_lambda_encoded_code(
        code_b64,
        result,
        location,
        layer_name,
        function_format="list",
        bytecode_format="list_bytecode",
        format_label="list-format",
    )
    return True


def _add_lambda_code_size_limit_check(
    code_b64: str,
    result: ScanResult,
    location: str,
    layer_name: str,
    *,
    function_format: str,
) -> None:
    redacted_layer_name = redact_evidence_string(str(layer_name))
    result.add_check(
        name="Lambda Layer Detection",
        passed=False,
        message=(
            f"Lambda layer '{redacted_layer_name}' contains {function_format}-format code "
            "that exceeds the bounded analysis limit"
        ),
        severity=IssueSeverity.WARNING,
        location=location,
        details={
            "layer_name": redacted_layer_name,
            "layer_class": "Lambda",
            "function_format": function_format,
            "analysis_status": "code_size_limit_exceeded",
            "encoded_code_chars": len(code_b64),
            "max_encoded_code_chars": _MAX_LAMBDA_CODE_B64_CHARS,
        },
        why="Oversized Lambda bytecode was not decoded because it exceeds the bounded static-analysis limit.",
    )


def _check_lambda_encoded_code(
    code_b64: str,
    result: ScanResult,
    location: str,
    layer_name: str,
    *,
    function_format: str,
    bytecode_format: str,
    format_label: str,
) -> None:
    redacted_layer_name = redact_evidence_string(str(layer_name))
    try:
        decoded = base64.b64decode(code_b64)
        decoded_str = decoded.decode("utf-8", errors="replace")
    except Exception:
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{redacted_layer_name}' contains non-decodable {function_format}-format code",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "function_format": function_format,
            },
            why="Unable to decode Lambda bytecode for security analysis.",
        )
        return

    found_patterns = find_lambda_dangerous_patterns(decoded_str, _LAMBDA_DANGEROUS_PATTERNS)

    if found_patterns:
        result.add_check(
            name="Lambda Layer Code Analysis",
            passed=False,
            message=(
                f"Lambda layer '{redacted_layer_name}' contains dangerous patterns in bytecode: "
                f"{', '.join(found_patterns)}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "dangerous_patterns": found_patterns,
                "function_format": bytecode_format,
                "code_preview_omitted": "opaque_bytecode_may_contain_sensitive_constants",
            },
            why=(
                "Lambda layers can execute arbitrary Python code during model inference. "
                "Dangerous patterns found in the embedded bytecode."
            ),
        )
    else:
        result.add_check(
            name="Lambda Layer Code Analysis",
            passed=False,
            message=(
                f"Lambda layer '{redacted_layer_name}' contains embedded bytecode ({format_label}) with no dangerous "
                "text patterns detected"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": redacted_layer_name,
                "layer_class": "Lambda",
                "function_format": bytecode_format,
                "analysis_status": "opaque_bytecode",
            },
            why=(
                "Keras Lambda layers embed compiled bytecode that will execute "
                "during model loading or inference; no high-risk text patterns were detected."
            ),
        )


def check_subclassed_model(
    model_class: str,
    result: ScanResult,
    location: str,
) -> None:
    """Check whether a Keras model class is subclassed (custom) or a known safe class.

    Subclassed models can contain arbitrary Python code in their call() method,
    unlike standard Keras models that use declarative layer configurations.

    Args:
        model_class: The class_name from the Keras model config.
        result: ScanResult to add the check to.
        location: File path for the check location.
    """
    normalized_model_class = normalize_keras_layer_class(model_class)
    redacted_model_class = redact_evidence_string(model_class)
    if model_class and normalized_model_class not in KNOWN_SAFE_MODEL_CLASSES:
        result.add_check(
            name="Subclassed Model Detection",
            passed=False,
            message=f"Subclassed Keras model detected: {redacted_model_class}",
            severity=IssueSeverity.INFO,
            location=location,
            details={
                "model_class": redacted_model_class,
                "known_safe_classes": sorted(KNOWN_SAFE_MODEL_CLASSES),
                "risk": "Subclassed models require external Python code to load, which should be reviewed",
            },
            why=(
                "Subclassed Keras models (custom class names) require external Python class "
                "definitions to load. The model file itself does not contain executable code, "
                "but the loading code should be reviewed. Standard Keras models (Sequential, "
                "Functional, Model) use declarative layer configurations and load without custom code."
            ),
        )
    elif normalized_model_class in KNOWN_SAFE_MODEL_CLASSES:
        result.add_check(
            name="Subclassed Model Detection",
            passed=True,
            message=f"Standard Keras model class: {redacted_model_class}",
            location=location,
            details={"model_class": redacted_model_class},
        )


def _is_feature_space(node: dict[str, Any]) -> bool:
    # Keras also looks up registered_name when the module does not export class_name.
    return node.get("class_name") == "FeatureSpace" or node.get("registered_name") == "FeatureSpace"


class KerasConfigScope(Enum):
    """How Keras interprets the next object in a serialized config."""

    CONFIG = auto()
    OBJECT_FIELD = auto()  # A named field such as "activation" or "layer".
    OBJECT_TREE = auto()  # A collection of objects, e.g. metrics grouped by output.
    FEATURE_SPACE = auto()
    FEATURE_MAP = auto()
    LEGACY_LAMBDA = auto()

    def child(self, key: str, value: Any, object_class: str | None) -> "KerasConfigScope | None":
        if self is KerasConfigScope.FEATURE_MAP:
            # Feature names are user-supplied, including names such as "module".
            return KerasConfigScope.OBJECT_TREE
        if key in {"module", "fn_module", "class_name", "registered_name"}:
            return None
        if object_class == "FeatureSpace" and key == "config":
            return KerasConfigScope.FEATURE_SPACE
        if self is KerasConfigScope.FEATURE_SPACE:
            if key == "features" and isinstance(value, dict):
                return KerasConfigScope.FEATURE_MAP
            if key == "crosses":
                return KerasConfigScope.OBJECT_TREE
        if self is KerasConfigScope.OBJECT_TREE and object_class is None:
            return KerasConfigScope.OBJECT_TREE
        if key.lower() in _NESTED_SERIALIZED_OBJECT_KEYS:
            return KerasConfigScope.OBJECT_FIELD
        return KerasConfigScope.CONFIG


class BaseKerasScanner(BaseScanner):
    """Security checks on serialized Keras configuration in H5 and ZIP containers."""

    _CONFIG_SYMBOL_FIELDS: ClassVar[tuple[str, ...]] = ("config", "registered_name", "function_name")

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

    @staticmethod
    def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
        """Mark the scan as incomplete without converting it into a security finding."""
        BaseScanner._mark_inconclusive_reason_first(result, reason, INCONCLUSIVE_SCAN_OUTCOME)

    @staticmethod
    def _finish_scan_result(result: ScanResult) -> None:
        """Fail closed on incomplete scans while preserving security precedence."""
        is_inconclusive = result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        success = result.success and not result.has_errors and (not is_inconclusive or result.has_warnings)
        result.finish(success=success)

    @staticmethod
    @abstractmethod
    def _is_lambda_layer_class(layer_class: Any) -> bool:
        """Recognize the Lambda layer names supported by this format."""

    @abstractmethod
    def _check_nested_serialized_module_references(
        self,
        config_value: Any,
        result: ScanResult,
        layer_name: str,
        *,
        scope: KerasConfigScope = KerasConfigScope.CONFIG,
    ) -> None:
        """Inspect nested objects within the container's traversal budget."""

    def _check_training_objects(
        self, config: dict[str, Any], result: ScanResult, context: str, optimizer_key: str
    ) -> None:
        for key in ("metrics", "weighted_metrics"):
            check_custom_metric_config(config.get(key), result, f"{self.current_file_path} ({context}.{key})")
        check_custom_loss_config(config.get("loss"), result, f"{self.current_file_path} ({context}.loss)")
        for key in (optimizer_key, "loss", "metrics", "weighted_metrics"):
            self._check_nested_serialized_module_references(
                config.get(key), result, f"{context}.{key}", scope=KerasConfigScope.OBJECT_TREE
            )

    def _check_serialized_module_node(
        self,
        node: dict[str, Any],
        scope: KerasConfigScope,
        result: ScanResult,
        layer_name: str,
        *,
        skip_reference: bool = False,
    ) -> str | None:
        """Check references in deserialized objects, returning their class for traversal."""
        object_class = node.get("class_name")
        if not isinstance(object_class, str) or "config" not in node:
            return None
        if (
            scope in (KerasConfigScope.OBJECT_FIELD, KerasConfigScope.OBJECT_TREE)
            or "registered_name" in node
            or object_class == "function"
            or self._is_lambda_layer_class(object_class)
        ):
            if not skip_reference:
                self._check_module_fields(node, object_class, result, layer_name)
            return "FeatureSpace" if _is_feature_space(node) else object_class
        return None

    @classmethod
    def _has_dangerous_config_symbol(cls, module: str, symbols: set[str]) -> bool:
        if not symbols.isdisjoint(_DANGEROUS_EXACT_MODULE_SYMBOLS.get(module, ())):
            return True
        return module in {"nt", "posix"} and any(symbol.startswith(("exec", "spawn")) for symbol in symbols)

    @classmethod
    def _is_allowlisted_config_callable(cls, module: str, symbols: set[str]) -> bool:
        return module.partition(".")[0] in _SAFE_KERAS_MODULE_ROOTS

    def _check_module_fields(
        self,
        source: dict[str, Any],
        object_class: str,
        result: ScanResult,
        layer_name: str,
        fields: tuple[str, ...] = ("module", "fn_module"),
    ) -> None:
        for key in fields:
            module_value = source.get(key)
            if not isinstance(module_value, str) or not (module := module_value.strip()):
                continue
            reference = (id(source), key, module)
            if reference in self._checked_config_module_references:
                continue
            self._checked_config_module_references.add(reference)

            symbols = {
                value.strip()
                for field in self._CONFIG_SYMBOL_FIELDS
                if isinstance((value := source.get(field)), str) and value.strip()
            }
            root = module.partition(".")[0]
            is_callable = key == "fn_module" or object_class == "function"
            if root in DANGEROUS_CONFIG_MODULE_ROOTS or self._has_dangerous_config_symbol(
                module, symbols | {object_class}
            ):
                severity = IssueSeverity.CRITICAL
            elif (is_callable and not self._is_allowlisted_config_callable(module, symbols)) or (
                root not in _SAFE_KERAS_MODULE_ROOTS and self._is_lambda_layer_class(object_class)
            ):
                severity = IssueSeverity.WARNING
            else:
                continue
            self._report_config_module_reference(module, object_class, key, result, layer_name, severity)

    def _report_config_module_reference(
        self, module: str, object_class: str, key: str, result: ScanResult, layer_name: str, severity: IssueSeverity
    ) -> None:
        h5 = self.name == "keras_h5"
        module = redact_evidence_string(module.partition(".")[0] if h5 else module)
        if h5:
            layer_name = redact_evidence_string(layer_name)
        separator = "-" if h5 else "—"
        if severity == IssueSeverity.CRITICAL:
            name = "Dangerous Module in Config"
            module_type = "dangerous"
            risk = "arbitrary code execution via safe_mode bypass"
            context = "Keras H5 metadata" if h5 else ".keras config"
            description = (
                f"Arbitrary dangerous module references in {context} can bypass safe_mode "
                "and execute attacker-controlled code during model loading."
            )
            remediation = "Upgrade Keras to >= 3.9.0 or remove untrusted module references"
            why = get_cve_2025_1550_explanation("dangerous_module")
        else:
            name = "Untrusted Module in Config"
            module_type = "non-allowlisted"
            risk = "potential safe_mode bypass"
            context = "Keras H5 metadata" if h5 else ".keras config content"
            description = (
                "Non-allowlisted callable module references may indicate safe_mode bypass "
                f"paths in untrusted {context}."
            )
            remediation = "Upgrade Keras to >= 3.9.0 or verify this module is safe"
            why = get_cve_2025_1550_explanation("untrusted_module")

        result.add_check(
            name=f"CVE-2025-1550: {name}",
            passed=False,
            message=(
                f"CVE-2025-1550: Layer '{layer_name}' references {module_type} module "
                f"'{module}' in {key} field {separator} {risk}"
            ),
            severity=severity,
            location=f"{self.current_file_path} (layer: {layer_name})",
            details={
                "layer_name": layer_name,
                "layer_class": redact_evidence_string(object_class),
                "key": key,
                "module": module,
                "cve_id": "CVE-2025-1550",
                "cvss": 7.3,
                "cwe": "CWE-94",
                "description": description,
                "remediation": remediation,
            },
            why=why,
        )

    def _check_layer_module_references(
        self,
        layer: dict[str, Any],
        result: ScanResult,
        layer_name: str,
        *,
        scope: KerasConfigScope | None = KerasConfigScope.CONFIG,
    ) -> None:
        """Check a layer or a model root (scope=None) for importable modules."""
        layer_class = layer.get("class_name")
        if not isinstance(layer_class, str) or "config" not in layer:
            return
        self._check_module_fields(layer, layer_class, result, layer_name)

        layer_config = layer.get("config")
        if not isinstance(layer_config, dict):
            return
        if scope is not None:
            config_fields = ("fn_module",) if scope is KerasConfigScope.LEGACY_LAMBDA else ("module", "fn_module")
            self._check_module_fields(layer_config, layer_class, result, layer_name, config_fields)

        if layer_class == "FlaxLayer":
            self._check_nested_serialized_module_references(
                layer_config.get("module"),
                result,
                layer_name,
                scope=KerasConfigScope.OBJECT_TREE,
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
                        scope=KerasConfigScope.OBJECT_TREE,
                    )

        if _is_feature_space(layer):
            # FeatureSpace.save() serializes the object at the model root without a layers array.
            scope = KerasConfigScope.FEATURE_SPACE
        if scope is not None:
            self._check_nested_serialized_module_references(layer_config, result, layer_name, scope=scope)
