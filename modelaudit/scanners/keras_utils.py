"""Shared utilities for Keras scanners."""

import base64
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from modelaudit.detectors.suspicious_symbols import (
    KNOWN_SAFE_KERAS_LAYER_CLASSES,
    KNOWN_SAFE_KERAS_LOSSES,
    KNOWN_SAFE_KERAS_METRICS,
    KNOWN_SAFE_MODEL_CLASSES,
)

from .base import IssueSeverity, ScanResult

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
    "urllib",
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
_TRUSTED_KERAS_MODULE_PREFIXES: tuple[str, ...] = (
    "keras.",
    "tensorflow.keras.",
    "tensorflow.python.keras.",
    "tf.keras.",
    "tf_keras.",
)


def _normalize_keras_identifier(value: str) -> str:
    """Normalize serialized Keras identifiers for allowlist lookups."""
    return value.strip().lower()


def _normalize_keras_layer_class(value: str) -> str:
    """Normalize Keras layer class names while preserving custom namespaces."""
    normalized = value.strip()
    module_path, _, class_name = normalized.rpartition(".")
    if class_name and any(f"{module_path.lower()}.".startswith(prefix) for prefix in _TRUSTED_KERAS_MODULE_PREFIXES):
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
        and _normalize_keras_identifier(_normalize_keras_layer_class(layer_class)) in _SAFE_KERAS_LAYER_CLASSES
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

        result.add_check(
            name=check_name,
            passed=False,
            message=f"Model contains custom {object_kind}: {identifier}",
            severity=IssueSeverity.WARNING,
            location=location,
            details={details_key: raw_object, "identifier": identifier},
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

    config = function_dict.get("config")
    if not isinstance(config, dict):
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{layer_name}' uses malformed dict-format function metadata (config is not a dict)",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": layer_name,
                "layer_class": "Lambda",
                "function_format": "dict",
                "parse_status": "invalid_config",
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
            message=f"Lambda layer '{layer_name}' uses dict-format function with no code field",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": layer_name,
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
    if not function_data:
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{layer_name}' uses list-format function with no encoded code field",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": layer_name,
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
            message=f"Lambda layer '{layer_name}' uses list-format function with no encoded code field",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": layer_name,
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
    result.add_check(
        name="Lambda Layer Detection",
        passed=False,
        message=(
            f"Lambda layer '{layer_name}' contains {function_format}-format code "
            "that exceeds the bounded analysis limit"
        ),
        severity=IssueSeverity.WARNING,
        location=location,
        details={
            "layer_name": layer_name,
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
    try:
        decoded = base64.b64decode(code_b64)
        decoded_str = decoded.decode("utf-8", errors="replace")
    except Exception:
        result.add_check(
            name="Lambda Layer Detection",
            passed=False,
            message=f"Lambda layer '{layer_name}' contains non-decodable {function_format}-format code",
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": layer_name,
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
                f"Lambda layer '{layer_name}' contains dangerous patterns in bytecode: {', '.join(found_patterns)}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=location,
            details={
                "layer_name": layer_name,
                "layer_class": "Lambda",
                "dangerous_patterns": found_patterns,
                "function_format": bytecode_format,
                "code_preview": decoded_str[:200] + "..." if len(decoded_str) > 200 else decoded_str,
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
                f"Lambda layer '{layer_name}' contains embedded bytecode ({format_label}) with no dangerous "
                "text patterns detected"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details={
                "layer_name": layer_name,
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
    if model_class and model_class not in KNOWN_SAFE_MODEL_CLASSES:
        result.add_check(
            name="Subclassed Model Detection",
            passed=False,
            message=f"Subclassed Keras model detected: {model_class}",
            severity=IssueSeverity.INFO,
            location=location,
            details={
                "model_class": model_class,
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
    elif model_class in KNOWN_SAFE_MODEL_CLASSES:
        result.add_check(
            name="Subclassed Model Detection",
            passed=True,
            message=f"Standard Keras model class: {model_class}",
            location=location,
            details={"model_class": model_class},
        )
