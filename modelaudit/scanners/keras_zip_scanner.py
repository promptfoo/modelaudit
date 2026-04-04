"""Scanner for ZIP-based Keras model files (.keras format)."""

import base64
import json
import os
import re
import tempfile
import zipfile
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
    get_cve_2025_8747_explanation,
    get_cve_2025_9906_explanation,
    get_cve_2025_12058_explanation,
    get_cve_2025_49655_explanation,
    get_cve_2026_1669_explanation,
    get_pattern_explanation,
)
from ..utils.file.detection import _normalize_archive_member_name, _read_zip_member_bounded
from .base import BaseScanner, IssueSeverity, ScanResult
from .keras_utils import (
    check_lambda_dict_function,
    check_subclassed_model,
    is_known_safe_keras_layer_class,
    is_known_safe_keras_loss,
    is_known_safe_keras_metric,
    iter_keras_serialized_identifiers,
)

# CVE-2025-1550: Keras safe_mode bypass via arbitrary module references in config.json
# Allowlist of top-level module names that are safe in Keras model configs.
# Any module outside this list in a layer's "module" or "fn_module" key is suspicious.
# Uses exact root matching: "math" matches "math" and "math.ops" but NOT "mathutils".
_SAFE_KERAS_MODULE_ROOTS: frozenset[str] = frozenset({"keras", "tensorflow", "tf_keras", "tf", "numpy", "math"})
_SAFE_ALLOWLISTED_REGISTERED_OBJECTS: frozenset[str] = frozenset({"notequal"})

# Modules that are explicitly dangerous when referenced in config.json
_DANGEROUS_CONFIG_MODULES = frozenset(
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

# CVE-2025-8747: keras.utils.get_file used as gadget to download + execute files
_GET_FILE_PATTERN = re.compile(r"get_file", re.IGNORECASE)
_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)
_URL_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(r"^(?:[a-zA-Z]:[\\/]|\\\\)")
_KERAS_CONFIG_ENTRY = "config.json"
_KERAS_CONFIG_MAX_BYTES = 10 * 1024 * 1024
_KERAS_METADATA_ENTRY = "metadata.json"
_KERAS_METADATA_MAX_BYTES = 10 * 1024 * 1024
_KERAS_WEIGHTS_ENTRY = "model.weights.h5"

try:
    import h5py

    HAS_H5PY = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_H5PY = False


class _EmbeddedWeightsLimitExceeded(Exception):
    """Raised when embedded weights exceed the configured extraction limit."""

    def __init__(self, message: str, extracted_bytes: int) -> None:
        super().__init__(message)
        self.extracted_bytes = extracted_bytes


class _AmbiguousKerasArchiveMemberError(Exception):
    """Raised when multiple non-canonical members normalize to the same Keras root path."""

    def __init__(self, member_name: str, candidate_filenames: list[str]) -> None:
        super().__init__(
            f"Ambiguous Keras ZIP member '{member_name}' matches multiple archive entries: "
            f"{', '.join(candidate_filenames)}"
        )
        self.member_name = member_name
        self.candidate_filenames = candidate_filenames


class KerasZipScanner(BaseScanner):
    """Scanner for ZIP-based Keras .keras model files"""

    MAX_EMBEDDED_WEIGHTS_BYTES: ClassVar[int] = 100 * 1024 * 1024
    MAX_DUPLICATE_MEMBER_COMPARE_CANDIDATES: ClassVar[int] = 16

    name = "keras_zip"
    description = "Scans ZIP-based Keras model files for suspicious configurations and Lambda layers"
    supported_extensions: ClassVar[list[str]] = [".keras"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Additional scanner-specific configuration
        self.suspicious_layer_types = dict(SUSPICIOUS_LAYER_TYPES)
        if config and "suspicious_layer_types" in config:
            self.suspicious_layer_types.update(config["suspicious_layer_types"])

        self.suspicious_config_props = list(SUSPICIOUS_CONFIG_PROPERTIES)
        if config and "suspicious_config_properties" in config:
            self.suspicious_config_props.extend(config["suspicious_config_properties"])

        configured_embedded_limit = self._normalize_positive_int_config(
            self.config.get("max_embedded_weights_bytes"),
            self.MAX_EMBEDDED_WEIGHTS_BYTES,
        )
        if self.max_file_read_size > 0:
            configured_embedded_limit = min(configured_embedded_limit, self.max_file_read_size)
        self.max_embedded_weights_bytes = configured_embedded_limit

    @staticmethod
    def _is_allowlisted_keras_module(module_value: Any) -> bool:
        if not isinstance(module_value, str) or not module_value.strip():
            return False
        return module_value.strip().split(".")[0] in _SAFE_KERAS_MODULE_ROOTS

    def _iter_layer_module_references(self, layer: dict[str, Any]) -> list[str]:
        layer_config = layer.get("config", {})
        if not isinstance(layer_config, dict):
            layer_config = {}

        module_references: list[str] = []
        for key in ("module", "fn_module"):
            for value in (layer.get(key), layer_config.get(key)):
                if isinstance(value, str) and value.strip():
                    module_references.append(value.strip())
        return module_references

    def _layer_uses_allowlisted_module(self, layer: dict[str, Any]) -> bool:
        return any(
            self._is_allowlisted_keras_module(module_value)
            for module_value in self._iter_layer_module_references(layer)
        )

    def _layer_uses_non_allowlisted_module(self, layer: dict[str, Any]) -> bool:
        return any(
            not self._is_allowlisted_keras_module(module_value)
            for module_value in self._iter_layer_module_references(layer)
        )

    @staticmethod
    def _is_known_safe_allowlisted_registered_object(identifier: Any) -> bool:
        return isinstance(identifier, str) and identifier.strip().lower() in _SAFE_ALLOWLISTED_REGISTERED_OBJECTS

    def _is_known_safe_serialized_layer(self, layer: dict[str, Any]) -> bool:
        layer_class = layer.get("class_name")
        if is_known_safe_keras_layer_class(layer_class) or self._is_known_safe_allowlisted_registered_object(
            layer_class
        ):
            return not self._layer_uses_non_allowlisted_module(layer)

        return False

    def _should_flag_registered_object(self, layer: dict[str, Any]) -> bool:
        registered_name = layer.get("registered_name")
        if not isinstance(registered_name, str) or not registered_name.strip():
            return False

        normalized_registered_name = registered_name.strip()
        has_non_allowlisted_module = self._layer_uses_non_allowlisted_module(layer)
        layer_class = layer.get("class_name")
        if isinstance(layer_class, str) and normalized_registered_name == layer_class.strip():
            if self._is_known_safe_serialized_layer(layer) or self._is_known_safe_allowlisted_registered_object(
                layer_class
            ):
                return has_non_allowlisted_module
            return True

        if is_known_safe_keras_layer_class(normalized_registered_name):
            return has_non_allowlisted_module

        return True

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        # Check if it's a ZIP file
        try:
            from ..utils.file.detection import is_keras_zip_archive

            return is_keras_zip_archive(path, allow_config_only=Path(path).suffix.lower() == ".keras")
        except Exception:
            return False

    def _get_archive_member_info(
        self,
        archive: zipfile.ZipFile,
        member_name: str,
    ) -> zipfile.ZipInfo | None:
        """Return a canonical ZIP member deterministically by normalized archive-relative name."""
        exact_matches: list[zipfile.ZipInfo] = []
        normalized_matches: list[zipfile.ZipInfo] = []
        for info in archive.infolist():
            if not info.filename or info.is_dir():
                continue
            if info.filename == member_name:
                exact_matches.append(info)
            elif _normalize_archive_member_name(info.filename) == member_name:
                normalized_matches.append(info)

        if not exact_matches and not normalized_matches:
            return None

        if exact_matches:
            candidate_members = [*exact_matches, *normalized_matches]
            preferred_info = exact_matches[0]
        else:
            candidate_members = normalized_matches
            preferred_info = normalized_matches[0]

        if len(candidate_members) == 1:
            return preferred_info

        if len(candidate_members) > self.MAX_DUPLICATE_MEMBER_COMPARE_CANDIDATES:
            raise _AmbiguousKerasArchiveMemberError(
                member_name,
                [info.filename for info in candidate_members],
            )

        compare_limit = self._get_duplicate_member_compare_limit(member_name)
        try:
            preferred_data = _read_zip_member_bounded(archive, preferred_info, compare_limit)
            for candidate_info in candidate_members[1:]:
                candidate_data = _read_zip_member_bounded(archive, candidate_info, compare_limit)
                if candidate_data != preferred_data:
                    raise _AmbiguousKerasArchiveMemberError(
                        member_name,
                        [info.filename for info in candidate_members],
                    )
        except (ValueError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as exc:
            raise _AmbiguousKerasArchiveMemberError(
                member_name,
                [info.filename for info in candidate_members],
            ) from exc

        return preferred_info

    def _get_duplicate_member_compare_limit(self, member_name: str) -> int:
        """Return a bounded duplicate-content comparison limit for Keras root members."""
        if member_name == _KERAS_CONFIG_ENTRY:
            return _KERAS_CONFIG_MAX_BYTES
        if member_name == _KERAS_METADATA_ENTRY:
            return _KERAS_METADATA_MAX_BYTES
        if member_name == _KERAS_WEIGHTS_ENTRY:
            return self.max_embedded_weights_bytes
        return _KERAS_CONFIG_MAX_BYTES

    def _get_recursive_archive_scan_config(self) -> dict[str, Any]:
        """Return a ZIP scanner config with an explicit bounded per-member extraction limit."""
        recursive_config = dict(self.config)
        member_size_limits = [self.max_embedded_weights_bytes]
        for config_key in ("max_file_size", "max_entry_size"):
            configured_limit = self._normalize_positive_int_config(
                recursive_config.get(config_key),
                0,
            )
            if configured_limit > 0:
                member_size_limits.append(configured_limit)

        recursive_member_size_limit = min(member_size_limits)
        recursive_config["max_file_size"] = recursive_member_size_limit
        recursive_config["max_entry_size"] = recursive_member_size_limit
        return recursive_config

    def _merge_recursive_archive_scan(self, path: str, result: ScanResult) -> None:
        """Recursively scan every ZIP member through the generic archive scanner."""
        from .zip_scanner import ZipScanner

        zip_scanner = ZipScanner(self._get_recursive_archive_scan_config())
        nested_result = zip_scanner._scan_zip_file(
            path,
            depth=max(zip_scanner._get_archive_depth(), zip_scanner._get_zip_depth()),
        )
        preserved_metadata = dict(result.metadata)
        nested_contents = nested_result.metadata.get("contents")
        result.merge(nested_result)
        result.metadata.update(preserved_metadata)
        if nested_contents is not None:
            result.metadata["contents"] = nested_contents
        result.success = result.success and nested_result.success

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

                config_info = self._get_archive_member_info(zf, _KERAS_CONFIG_ENTRY)
                # Check for config.json
                if config_info is None:
                    result.add_check(
                        name="Keras ZIP Format Check",
                        passed=False,
                        message="No config.json found in Keras ZIP file",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"files": zf.namelist()},
                    )
                    self._merge_recursive_archive_scan(path, result)
                    result.finish(success=result.success)
                    return result

                # Read and parse config.json
                raw_config_text = ""
                try:
                    config_data = _read_zip_member_bounded(
                        zf,
                        config_info,
                        _KERAS_CONFIG_MAX_BYTES,
                    )
                    raw_config_text = config_data.decode("utf-8", errors="ignore")
                    model_config = json.loads(config_data)
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                    # Fall back to a structure-aware raw scan only when the archive
                    # config is malformed and cannot be parsed as JSON.
                    if raw_config_text:
                        self._check_unsafe_deserialization_bypass_raw(raw_config_text, result)
                    result.add_check(
                        name="Config JSON Parsing",
                        passed=False,
                        message=f"Failed to parse config.json: {e}",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{path}/{config_info.filename}",
                        details={
                            "error": str(e),
                            "max_config_bytes": _KERAS_CONFIG_MAX_BYTES,
                        },
                    )
                    self._merge_recursive_archive_scan(path, result)
                    result.finish(success=False)
                    return result

                # CVE-2025-8747: Check for structured get_file gadget usage
                self._check_get_file_gadget(model_config, result)
                # CVE-2025-9906: structured fallback check on parsed config
                self._check_unsafe_deserialization_bypass(model_config, result)

                # Check for metadata.json
                metadata_info = self._get_archive_member_info(zf, _KERAS_METADATA_ENTRY)
                if metadata_info is not None:
                    try:
                        metadata_data = _read_zip_member_bounded(
                            zf,
                            metadata_info,
                            _KERAS_METADATA_MAX_BYTES,
                        )
                        metadata = json.loads(metadata_data)
                        result.metadata["keras_metadata"] = metadata
                        keras_version = metadata.get("keras_version")
                        if isinstance(keras_version, str) and keras_version.strip():
                            result.metadata["keras_version"] = keras_version.strip()
                    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                        pass  # Metadata parsing is optional

                self._check_embedded_hdf5_weights_external_references(zf, result)

                # Scan model configuration
                self._scan_model_config(model_config, result)

                # Check for suspicious files in the ZIP
                for filename in zf.namelist():
                    normalized_name = filename.lower()
                    if normalized_name.endswith((".py", ".pyc", ".pyo")):
                        result.add_check(
                            name="Python File Detection",
                            passed=False,
                            message=f"Python file found in Keras ZIP: {filename}",
                            severity=IssueSeverity.WARNING,
                            location=f"{path}/{filename}",
                            details={"filename": filename},
                        )
                    elif normalized_name.endswith((".sh", ".bat", ".exe", ".dll")):
                        result.add_check(
                            name="Executable File Detection",
                            passed=False,
                            message=f"Executable file found in Keras ZIP: {filename}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path}/{filename}",
                            details={"filename": filename},
                        )

                self._merge_recursive_archive_scan(path, result)

        except _AmbiguousKerasArchiveMemberError as e:
            result.add_check(
                name="Keras ZIP Member Path Validation",
                passed=False,
                message=str(e),
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "member_name": e.member_name,
                    "candidate_filenames": e.candidate_filenames,
                },
            )
            self._merge_recursive_archive_scan(path, result)
            result.finish(success=False)
            return result
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

        result.finish(success=result.success)
        return result

    def _scan_model_config(self, model_config: dict[str, Any], result: ScanResult) -> None:
        """Scan the model configuration for suspicious elements"""
        # Check model class name
        model_class = model_config.get("class_name", "")
        result.metadata["model_class"] = model_class

        # Check for subclassed models (custom class names)
        check_subclassed_model(model_class, result, self.current_file_path)

        # Check for suspicious model types (Lambda, etc.)
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

        self._scan_compile_config(model_config.get("compile_config"), result)

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

            # CVE-2025-49655: TorchModuleWrapper uses torch.load(weights_only=False)
            if layer_class == "TorchModuleWrapper":
                self._check_torch_module_wrapper(result, layer_name)
            # CVE-2025-1550: Check ALL layers for dangerous module references
            self._check_layer_module_references(layer, result, layer_name)
            # CVE-2025-12058: StringLookup can load external vocabulary paths even with safe_mode=True
            if layer_class == "StringLookup":
                self._check_stringlookup_vocabulary_path(layer, result, layer_name)

            # Check for Lambda layers
            if layer_class == "Lambda":
                self._check_lambda_layer(layer, result, layer_name)
                keras_version = result.metadata.get("keras_version")
                if isinstance(keras_version, str) and self._is_vulnerable_to_cve_2024_3660(keras_version):
                    # CVE-2024-3660: Lambda layers enable arbitrary code injection
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
                elif isinstance(keras_version, str):
                    result.add_check(
                        name="Lambda Version Risk Check",
                        passed=True,
                        message=(
                            f"Lambda layer '{layer_name}' detected with Keras {keras_version}; "
                            "outside known CVE-2024-3660 vulnerable range (<2.13.0)"
                        ),
                        location=f"{self.current_file_path} (layer: {layer_name})",
                        details={"layer_name": layer_name, "layer_class": "Lambda", "keras_version": keras_version},
                    )
                else:
                    result.add_check(
                        name="Lambda Risk (Version Unknown)",
                        passed=False,
                        message=(
                            f"Lambda layer '{layer_name}' detected but keras_version is unavailable; "
                            "cannot confidently attribute CVE-2024-3660 without version context"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (layer: {layer_name})",
                        details={
                            "layer_name": layer_name,
                            "layer_class": "Lambda",
                            "cve_id": "CVE-2024-3660",
                            "affected_versions": "Keras < 2.13.0",
                        },
                    )
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
            elif layer_class and not self._is_known_safe_serialized_layer(layer):
                result.add_check(
                    name="Custom Layer Class Detection",
                    passed=False,
                    message=f"Unknown/custom layer class detected: {layer_class}",
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_class": layer_class,
                        "layer_name": layer_name,
                        "layer_config": layer.get("config", {}),
                        "risk": "Custom layer classes require external code to load and may execute arbitrary logic",
                    },
                    rule_code="S810",
                )

            # Check for custom objects
            if self._should_flag_registered_object(layer):
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

    def _scan_compile_config(self, compile_config: Any, result: ScanResult) -> None:
        """Inspect compile_config for custom metrics and losses."""
        if not isinstance(compile_config, dict):
            return

        self._check_custom_metric_config(compile_config.get("metrics"), result, "compile_config.metrics")
        self._check_custom_metric_config(
            compile_config.get("weighted_metrics"),
            result,
            "compile_config.weighted_metrics",
        )
        self._check_custom_loss_config(compile_config.get("loss"), result, "compile_config.loss")

    def _check_custom_metric_config(self, metrics_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom metrics embedded anywhere in a serialized metric tree."""
        seen_metrics: set[str] = set()

        for identifier, raw_metric in iter_keras_serialized_identifiers(metrics_config):
            normalized_identifier = identifier.strip().lower()
            if not normalized_identifier or is_known_safe_keras_metric(identifier):
                continue
            if normalized_identifier in seen_metrics:
                continue
            seen_metrics.add(normalized_identifier)

            result.add_check(
                name="Custom Metric Detection",
                passed=False,
                message=f"Model contains custom metric: {identifier}",
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} ({context})",
                details={"metric": raw_metric, "identifier": identifier},
                rule_code="S305",
            )

    def _check_custom_loss_config(self, loss_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom losses embedded anywhere in a serialized loss tree."""
        seen_losses: set[str] = set()

        for identifier, raw_loss in iter_keras_serialized_identifiers(loss_config):
            normalized_identifier = identifier.strip().lower()
            if not normalized_identifier or is_known_safe_keras_loss(identifier):
                continue
            if normalized_identifier in seen_losses:
                continue
            seen_losses.add(normalized_identifier)

            result.add_check(
                name="Custom Loss Detection",
                passed=False,
                message=f"Model contains custom loss: {identifier}",
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} ({context})",
                details={"loss": raw_loss, "identifier": identifier},
                rule_code="S305",
            )

    def _check_torch_module_wrapper(self, result: ScanResult, layer_name: str) -> None:
        """Check for CVE-2025-49655: TorchModuleWrapper deserialization RCE.

        TorchModuleWrapper in Keras 3.11.0-3.11.2 calls torch.load(weights_only=False)
        in from_config(), enabling arbitrary code execution via pickle deserialization.
        """
        keras_version = result.metadata.get("keras_version")
        vulnerability_status: bool | None = None
        if isinstance(keras_version, str):
            vulnerability_status = self._is_vulnerable_keras_3_11_x(keras_version)

        if vulnerability_status is True:
            result.add_check(
                name="CVE-2025-49655: TorchModuleWrapper Deserialization RCE",
                passed=False,
                message=(
                    f"CVE-2025-49655: Layer '{layer_name}' is a TorchModuleWrapper in "
                    f"Keras {keras_version} (3.11.0-3.11.2 vulnerable range) — "
                    "uses torch.load(weights_only=False) enabling arbitrary code execution"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": "TorchModuleWrapper",
                    "keras_version": keras_version,
                    "cve_id": "CVE-2025-49655",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": (
                        "TorchModuleWrapper in vulnerable Keras versions can deserialize attacker-controlled "
                        "pickles via torch.load(weights_only=False), enabling RCE."
                    ),
                    "affected_versions": "Keras 3.11.0-3.11.2",
                    "remediation": "Upgrade Keras to >= 3.11.3",
                },
                why=get_cve_2025_49655_explanation("torch_module_wrapper"),
            )
        elif vulnerability_status is False and isinstance(keras_version, str):
            result.add_check(
                name="TorchModuleWrapper Version Risk Check",
                passed=False,
                message=(
                    f"TorchModuleWrapper detected in Keras {keras_version}; "
                    "version metadata is outside known CVE-2025-49655 range (3.11.0-3.11.2), "
                    "but metadata-only assessment is inconclusive without runtime verification"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": "TorchModuleWrapper",
                    "keras_version": keras_version,
                    "metadata_only_assessment": True,
                    "parse_status": "metadata_non_vulnerable",
                },
            )
        else:
            version_context = (
                f"keras_version '{keras_version}' is non-canonical"
                if isinstance(keras_version, str)
                else "keras_version is unavailable"
            )
            result.add_check(
                name="TorchModuleWrapper Risk (Version Unknown)",
                passed=False,
                message=(
                    f"Layer '{layer_name}' is a TorchModuleWrapper but {version_context}; "
                    "cannot confidently attribute CVE-2025-49655 without reliable version context"
                ),
                severity=IssueSeverity.WARNING,
                location=f"{self.current_file_path} (layer: {layer_name})",
                details={
                    "layer_name": layer_name,
                    "layer_class": "TorchModuleWrapper",
                    "keras_version": keras_version,
                    "parse_status": "unknown",
                    "cve_id": "CVE-2025-49655",
                    "cvss": 9.8,
                    "cwe": "CWE-502",
                    "description": (
                        "TorchModuleWrapper may deserialize unsafe content, but version data was missing or "
                        "non-canonical so CVE attribution confidence is reduced."
                    ),
                    "affected_versions": "Keras 3.11.0-3.11.2",
                    "remediation": "Ensure model metadata includes keras_version and upgrade to >= 3.11.3",
                },
                why=get_cve_2025_49655_explanation("torch_module_wrapper"),
            )

    @staticmethod
    def _is_vulnerable_keras_3_11_x(version: str) -> bool | None:
        """Return True for Keras 3.11.0-3.11.2 (including prerelease/dev), else False/None."""
        version_match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9.+-]*)$", version.strip())
        if not version_match:
            return None

        try:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3) or 0)
            suffix = (version_match.group(4) or "").strip().lower()

            if suffix and not (
                re.search(r"(?:^|[.\-])(dev|rc|a|b|alpha|beta|pre|preview)\d*", suffix)
                or suffix.startswith("+")
                or suffix.startswith(".post")
                or suffix.startswith("post")
            ):
                return None

            return major == 3 and minor == 11 and 0 <= patch <= 2
        except ValueError:
            return None

    def _check_layer_module_references(self, layer: dict[str, Any], result: ScanResult, layer_name: str) -> None:
        """Check layer config for dangerous module references (CVE-2025-1550).

        CVE-2025-1550: Keras Model.load_model allows arbitrary code execution even
        with safe_mode=True by specifying arbitrary Python modules/functions in
        config.json's module/fn_module keys. This checks ALL layers, not just Lambda.
        """
        layer_config = layer.get("config", {})
        if not isinstance(layer_config, dict):
            return

        # Check both the layer-level and config-level module references
        module_keys_to_check: list[tuple[str, str]] = []
        for key in ("module", "fn_module"):
            layer_value = layer.get(key)
            if isinstance(layer_value, str) and layer_value.strip():
                module_keys_to_check.append((key, layer_value.strip()))
            config_value = layer_config.get(key)
            if isinstance(config_value, str) and config_value.strip():
                module_keys_to_check.append((key, config_value.strip()))

        layer_class = str(layer.get("class_name", ""))
        for key, module_value in module_keys_to_check:
            # Extract the top-level module name (e.g., "os" from "os.path")
            top_module = module_value.split(".")[0]

            # Check if it's an explicitly dangerous module
            is_dangerous = top_module in _DANGEROUS_CONFIG_MODULES

            # Check if it's outside the safe allowlist (exact root matching)
            is_outside_allowlist = top_module not in _SAFE_KERAS_MODULE_ROOTS

            if is_dangerous:
                result.add_check(
                    name="CVE-2025-1550: Dangerous Module in Config",
                    passed=False,
                    message=(
                        f"CVE-2025-1550: Layer '{layer_name}' references dangerous module "
                        f"'{module_value}' in {key} field — arbitrary code execution via safe_mode bypass"
                    ),
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_name": layer_name,
                        "layer_class": layer.get("class_name", ""),
                        "key": key,
                        "module": module_value,
                        "cve_id": "CVE-2025-1550",
                        "cvss": 9.8,
                        "cwe": "CWE-502",
                        "description": (
                            "Arbitrary dangerous module references in .keras config can bypass safe_mode "
                            "and execute attacker-controlled code during model loading."
                        ),
                        "remediation": "Upgrade Keras to >= 3.9.0 or remove untrusted module references",
                    },
                    why=get_cve_2025_1550_explanation("dangerous_module"),
                )
            elif is_outside_allowlist and (key == "fn_module" or layer_class == "Lambda"):
                result.add_check(
                    name="CVE-2025-1550: Untrusted Module in Config",
                    passed=False,
                    message=(
                        f"CVE-2025-1550: Layer '{layer_name}' references non-allowlisted module "
                        f"'{module_value}' in {key} field — potential safe_mode bypass"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_name": layer_name,
                        "layer_class": layer.get("class_name", ""),
                        "key": key,
                        "module": module_value,
                        "cve_id": "CVE-2025-1550",
                        "cvss": 9.8,
                        "cwe": "CWE-502",
                        "description": (
                            "Non-allowlisted callable module references may indicate safe_mode bypass "
                            "paths in untrusted .keras config content."
                        ),
                        "remediation": "Upgrade Keras to >= 3.9.0 or verify this module is safe",
                    },
                    why=get_cve_2025_1550_explanation("untrusted_module"),
                )

    def _check_get_file_gadget(self, model_config: dict[str, Any], result: ScanResult) -> None:
        """Check for CVE-2025-8747: keras.utils.get_file gadget bypass.

        CVE-2025-8747: Bypass of CVE-2025-1550 fix. Uses keras.utils.get_file
        as a gadget to download and execute arbitrary files even with safe_mode=True.
        Detected when a single config object references get_file and includes URL arguments.
        """
        for context, node in self._iter_dict_nodes(model_config):
            if self._is_primarily_documentation(context, node):
                continue
            direct_string_values: list[str] = []
            url_candidate_values: list[str] = []
            for key, value in node.items():
                direct_string_values.extend(self._extract_string_literals(value))
                key_lower = str(key).lower()
                if key_lower in {"url", "origin", "args", "kwargs"}:
                    url_candidate_values.extend(self._extract_string_literals(value, include_dict_values=True))
            has_get_file = any(
                _GET_FILE_PATTERN.fullmatch(value.strip()) is not None
                or value.strip().lower().endswith(".get_file")
                or "keras.utils.get_file" in value.strip().lower()
                for value in direct_string_values
            )
            has_url = any(_URL_PATTERN.search(value) is not None for value in url_candidate_values)
            if not (has_get_file and has_url):
                continue
            result.add_check(
                name="CVE-2025-8747: get_file Gadget Bypass",
                passed=False,
                message=(
                    "CVE-2025-8747: config.json contains structured 'get_file' invocation with URL - "
                    "potential safe_mode bypass via file download gadget"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path}/config.json",
                details={
                    "cve_id": "CVE-2025-8747",
                    "context": context,
                    "cvss": 8.8,
                    "cwe": "CWE-502",
                    "description": (
                        "Keras config references get_file with a remote URL in executable context, "
                        "which can bypass safe_mode protections and load attacker-controlled payloads."
                    ),
                    "affected_versions": "Keras 3.0.0-3.10.0",
                    "remediation": "Upgrade Keras to >= 3.11.0",
                },
                why=get_cve_2025_8747_explanation("get_file_gadget"),
            )
            return

    def _check_unsafe_deserialization_bypass(self, model_config: dict[str, Any], result: ScanResult) -> None:
        """Check for CVE-2025-9906: enable_unsafe_deserialization bypass in config.json.

        CVE-2025-9906: config.json in .keras archives can reference
        keras.config.enable_unsafe_deserialization to disable safe_mode
        from within the deserialization process itself, then load malicious layers.
        """
        if self._has_cve_2025_9906_issue(result):
            return

        if self._has_unsafe_deserialization_reference(model_config):
            result.add_check(
                name="CVE-2025-9906: Unsafe Deserialization Bypass",
                passed=False,
                message=(
                    "CVE-2025-9906: config.json contains structured reference to "
                    "keras.config.enable_unsafe_deserialization (safe_mode bypass attempt)"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path}/config.json",
                details={
                    "cve_id": "CVE-2025-9906",
                    "cvss": 8.6,
                    "cwe": "CWE-502",
                    "description": (
                        "config.json can invoke enable_unsafe_deserialization during model loading, "
                        "disabling safe_mode protections for subsequent deserialization."
                    ),
                    "remediation": "Upgrade Keras to >= 3.11.0 and remove untrusted model files",
                    "config_path": "config.json",
                    "matched_symbol": "enable_unsafe_deserialization",
                    "detection_method": "structured_config_scan",
                },
                why=get_cve_2025_9906_explanation("config_bypass"),
            )

    def _check_unsafe_deserialization_bypass_raw(self, raw_config_text: str, result: ScanResult) -> None:
        """Raw-text CVE fallback for malformed JSON configs."""
        if self._has_cve_2025_9906_issue(result):
            return

        lowered = raw_config_text.lower()
        full_symbol_match = re.search(
            r'"(?:loader|fn|function|callable)"\s*:\s*"(keras(?:\.src)?\.config\.enable_unsafe_deserialization)"',
            lowered,
        )
        executable_pair_patterns = (
            r'\{[^{}]{0,1024}"module"\s*:\s*"keras(?:\.src)?\.config"[^{}]{0,1024}'
            r'"(?:fn|function|callable)"\s*:\s*"enable_unsafe_deserialization"',
            r'\{[^{}]{0,1024}"(?:fn|function|callable)"\s*:\s*"enable_unsafe_deserialization"'
            r'[^{}]{0,1024}"module"\s*:\s*"keras(?:\.src)?\.config"',
        )
        has_scoped_executable_pair = any(re.search(pattern, lowered) for pattern in executable_pair_patterns)
        if not (has_scoped_executable_pair or full_symbol_match):
            return
        matched_symbol = full_symbol_match.group(1) if full_symbol_match else "enable_unsafe_deserialization"

        result.add_check(
            name="CVE-2025-9906: Unsafe Deserialization Bypass",
            passed=False,
            message=(
                "CVE-2025-9906: config.json contains raw executable reference to "
                "enable_unsafe_deserialization (safe_mode bypass attempt)"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{self.current_file_path}/config.json",
            details={
                "cve_id": "CVE-2025-9906",
                "cvss": 8.6,
                "cwe": "CWE-502",
                "description": (
                    "config.json can invoke enable_unsafe_deserialization during model loading, "
                    "disabling safe_mode protections for subsequent deserialization."
                ),
                "remediation": "Upgrade Keras to >= 3.11.0 and remove untrusted model files",
                "config_path": "config.json",
                "matched_symbol": matched_symbol,
                "detection_method": "raw_config_scan",
            },
            why=get_cve_2025_9906_explanation("config_bypass"),
        )

    def _has_unsafe_deserialization_reference(self, obj: Any) -> bool:
        """Recursively detect object-scoped unsafe-deserialization references."""
        if isinstance(obj, str):
            token = obj.strip()
            if self._is_primarily_documentation_text(token):
                return False
            lowered = token.lower()
            return lowered in {
                "keras.config.enable_unsafe_deserialization",
                "keras.src.config.enable_unsafe_deserialization",
            }

        if isinstance(obj, dict):
            string_values = [
                value.strip().lower()
                for value in obj.values()
                if isinstance(value, str) and not self._is_primarily_documentation_text(value)
            ]
            has_enable_unsafe = any(
                token == "enable_unsafe_deserialization" or token.endswith(".enable_unsafe_deserialization")
                for token in string_values
            )
            has_keras_config_context = any(
                token == "keras.config"
                or token.startswith("keras.config.")
                or token == "keras.src.config"
                or token.startswith("keras.src.config.")
                for token in string_values
            )
            if has_enable_unsafe and has_keras_config_context:
                return True

            if has_keras_config_context and any(self._subtree_has_enable_unsafe(value) for value in obj.values()):
                return True

            return any(self._has_unsafe_deserialization_reference(value) for value in obj.values())

        if isinstance(obj, list):
            return any(self._has_unsafe_deserialization_reference(value) for value in obj)

        return False

    def _subtree_has_enable_unsafe(self, obj: Any) -> bool:
        """Return True if subtree contains an enable_unsafe_deserialization token."""
        if isinstance(obj, str):
            if self._is_primarily_documentation_text(obj):
                return False
            token = obj.strip().lower()
            return token == "enable_unsafe_deserialization" or token.endswith(".enable_unsafe_deserialization")

        if isinstance(obj, dict):
            return any(self._subtree_has_enable_unsafe(value) for value in obj.values())

        if isinstance(obj, list):
            return any(self._subtree_has_enable_unsafe(value) for value in obj)

        return False

    @staticmethod
    def _has_cve_2025_9906_issue(result: ScanResult) -> bool:
        """Avoid duplicate CVE-2025-9906 checks from raw + structured paths."""
        return any(issue.details.get("cve_id") == "CVE-2025-9906" for issue in result.issues)

    def _check_stringlookup_vocabulary_path(self, layer: dict[str, Any], result: ScanResult, layer_name: str) -> None:
        """Check for CVE-2025-12058: external StringLookup vocabulary paths in .keras configs."""
        layer_config = layer.get("config")
        if not isinstance(layer_config, dict):
            return

        vocabulary = layer_config.get("vocabulary")
        if not self._is_external_stringlookup_vocabulary(vocabulary):
            return

        keras_version = result.metadata.get("keras_version")
        location = f"{self.current_file_path} (layer: {layer_name})"
        details = {
            "layer_name": layer_name,
            "layer_class": "StringLookup",
            "vocabulary": vocabulary,
            "cve_id": "CVE-2025-12058",
            "cvss": 5.9,
            "cwe": "CWE-502, CWE-918",
            "description": (
                "StringLookup vocabulary paths can trigger arbitrary local file loading or SSRF when a crafted "
                ".keras archive is loaded."
            ),
            "remediation": "Upgrade Keras to >= 3.12.0 and avoid loading models with external vocabulary paths.",
        }

        if isinstance(keras_version, str) and self._is_vulnerable_to_cve_2025_12058(keras_version):
            details["keras_version"] = keras_version
            result.add_check(
                name="CVE-2025-12058: StringLookup External Vocabulary Path",
                passed=False,
                message=(
                    f"CVE-2025-12058: StringLookup layer '{layer_name}' in Keras {keras_version} references "
                    f"external vocabulary path '{vocabulary}', which can expose local files or trigger SSRF "
                    "during model loading"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2025_12058_explanation("stringlookup_external_vocabulary"),
            )
            return

        if isinstance(keras_version, str):
            details["keras_version"] = keras_version
            result.add_check(
                name="StringLookup External Vocabulary Metadata Check",
                passed=False,
                message=(
                    f"StringLookup layer '{layer_name}' references external vocabulary path '{vocabulary}', "
                    f"and archive metadata reports Keras {keras_version} outside the known CVE-2025-12058 "
                    "vulnerable range (<3.12.0), but metadata-only assessment is inconclusive without runtime "
                    "verification"
                ),
                severity=IssueSeverity.INFO,
                location=location,
                details=details,
            )
            return

        result.add_check(
            name="StringLookup External Vocabulary Risk (Version Unknown)",
            passed=False,
            message=(
                f"StringLookup layer '{layer_name}' references external vocabulary path '{vocabulary}', but "
                "keras_version is unavailable; cannot confidently attribute CVE-2025-12058 without version context"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details=details | {"affected_versions": "Keras < 3.12.0"},
        )

    @staticmethod
    def _is_external_stringlookup_vocabulary(vocabulary: Any) -> bool:
        """Return True only for scalar vocabulary strings that clearly point outside the archive."""
        if not isinstance(vocabulary, str):
            return False

        candidate = vocabulary.strip()
        if not candidate:
            return False

        normalized = candidate.replace("\\", "/")
        return (
            bool(_URL_SCHEME_PATTERN.match(candidate))
            or candidate.startswith("/")
            or normalized.startswith("~/")
            or bool(_WINDOWS_ABSOLUTE_PATH_PATTERN.match(candidate))
            or normalized.startswith("../")
            or "/../" in normalized
        )

    def _check_embedded_hdf5_weights_external_references(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        """Detect CVE-2026-1669 external HDF5 references inside embedded .keras weights."""
        if not HAS_H5PY:
            return

        weights_info = self._get_archive_member_info(archive, _KERAS_WEIGHTS_ENTRY)
        if weights_info is None:
            return

        if weights_info.file_size > self.max_embedded_weights_bytes:
            weights_entry = weights_info.filename
            result.add_check(
                name="Embedded Weights Size Limit",
                passed=False,
                message=(
                    "Skipping embedded model.weights.h5 inspection because the uncompressed weights entry "
                    f"exceeds the configured size limit ({weights_info.file_size} > {self.max_embedded_weights_bytes})"
                ),
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{weights_entry}",
                details={
                    "entry": weights_entry,
                    "uncompressed_size": weights_info.file_size,
                    "compressed_size": weights_info.compress_size,
                    "max_embedded_weights_bytes": self.max_embedded_weights_bytes,
                },
                why=(
                    "Large embedded archive members can consume excessive disk space or processing time when "
                    "extracted for inspection."
                ),
            )
            return

        temp_path = None
        findings: list[dict[str, Any]] = []
        try:
            with tempfile.NamedTemporaryFile(suffix=".h5", delete=False) as temp_file:
                temp_path = temp_file.name
                extracted_bytes = 0
                with archive.open(weights_info, "r") as source:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        extracted_bytes += len(chunk)
                        if extracted_bytes > self.max_embedded_weights_bytes:
                            raise _EmbeddedWeightsLimitExceeded(
                                "Embedded model.weights.h5 exceeded the configured extraction limit "
                                f"({self.max_embedded_weights_bytes} bytes) after reading {extracted_bytes} bytes",
                                extracted_bytes,
                            )
                        temp_file.write(chunk)

            with h5py.File(temp_path, "r") as h5_file:
                findings = self._collect_hdf5_external_references(h5_file)
        except _EmbeddedWeightsLimitExceeded as exc:
            weights_entry = weights_info.filename
            result.add_check(
                name="Embedded Weights Size Limit",
                passed=False,
                message=str(exc),
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{weights_entry}",
                details={
                    "entry": weights_entry,
                    "extracted_bytes": exc.extracted_bytes,
                    "uncompressed_size": weights_info.file_size,
                    "compressed_size": weights_info.compress_size,
                    "max_embedded_weights_bytes": self.max_embedded_weights_bytes,
                },
                why=(
                    "Large embedded archive members can consume excessive disk space or processing time when "
                    "extracted for inspection."
                ),
            )
            return
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

        if not findings:
            return

        keras_version = result.metadata.get("keras_version")
        location = f"{self.current_file_path}:{weights_info.filename}"
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

        if isinstance(keras_version, str) and self._is_vulnerable_to_cve_2026_1669(keras_version):
            details["keras_version"] = keras_version
            result.add_check(
                name="CVE-2026-1669: HDF5 External Weight Reference",
                passed=False,
                message=(
                    f"CVE-2026-1669: embedded Keras {keras_version} weights use HDF5 external references that can "
                    "disclose arbitrary local file contents during model loading"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2026_1669_explanation("hdf5_external_reference"),
            )
            return

        if isinstance(keras_version, str):
            result.add_check(
                name="HDF5 External Weight Reference Version Check",
                passed=True,
                message=(
                    f"Embedded HDF5 external references detected in weights, but Keras {keras_version} is outside "
                    "the known CVE-2026-1669 vulnerable ranges"
                ),
                location=location,
                details={"keras_version": keras_version, "external_references": findings},
            )
            return

        result.add_check(
            name="HDF5 External Weight Reference Risk (Version Unknown)",
            passed=False,
            message=(
                "Embedded HDF5 external references detected in weights, but keras_version is unavailable; cannot "
                "confidently attribute CVE-2026-1669 without version context"
            ),
            severity=IssueSeverity.WARNING,
            location=location,
            details=details
            | {
                "affected_versions": "Keras >= 3.0.0, < 3.12.1 and >= 3.13.0, < 3.13.2",
            },
        )

    @staticmethod
    def _collect_hdf5_external_references(h5_file: Any) -> list[dict[str, Any]]:
        """Collect HDF5 ExternalLink and external-storage datasets without following links."""
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

            obj = h5_file.get(name, getlink=False)
            if isinstance(obj, h5py.Dataset) and obj.external:
                findings.append(
                    {
                        "kind": "external_storage",
                        "hdf5_path": f"/{name}".replace("//", "/"),
                        "segments": [
                            {"filename": filename, "offset": int(offset), "size": int(size)}
                            for filename, offset, size in obj.external
                        ],
                    },
                )

        if hasattr(h5_file, "visititems_links"):
            h5_file.visititems_links(visit)
        else:  # pragma: no cover - compatibility fallback for older h5py
            h5_file.visititems(lambda name, _obj: visit(name, h5_file.get(name, getlink=True)))

        return findings

    @staticmethod
    def _extract_string_literals(value: Any, *, include_dict_values: bool = False) -> list[str]:
        """Extract string literals from simple container values."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple, set)):
            values: list[str] = []
            for item in value:
                values.extend(KerasZipScanner._extract_string_literals(item, include_dict_values=include_dict_values))
            return values
        if include_dict_values and isinstance(value, dict):
            dict_values: list[str] = []
            for item in value.values():
                dict_values.extend(KerasZipScanner._extract_string_literals(item, include_dict_values=True))
            return dict_values
        return []

    @staticmethod
    def _is_primarily_documentation(context: str, node: dict[str, Any]) -> bool:
        """Heuristically detect documentation-only nodes to reduce false positives."""
        context_lower = context.lower()
        doc_markers = (".description", ".doc", ".docs", ".comment", ".comments", ".notes", ".help", ".readme")
        if any(marker in context_lower for marker in doc_markers):
            return True

        lowered_keys = {str(key).lower() for key in node}
        doc_keys = {"description", "doc", "docs", "comment", "comments", "notes", "help", "readme", "citation"}
        execution_keys = {"fn", "function", "module", "url", "args", "kwargs", "class_name", "callable"}
        return bool(lowered_keys) and lowered_keys.issubset(doc_keys) and lowered_keys.isdisjoint(execution_keys)

    @staticmethod
    def _is_primarily_documentation_text(text: str) -> bool:
        """Return True when content is mostly documentation-style text."""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False

        dangerous_tokens = (
            "enable_unsafe_deserialization",
            "keras.config",
            "__import__",
            "exec(",
            "eval(",
        )
        structured_markers = ('":', '{"', '"class_name"', '"module"', '"config"')
        doc_like_lines = 0
        for line in lines:
            lowered = line.lower()
            if any(token in lowered for token in dangerous_tokens):
                continue
            if any(marker in lowered for marker in structured_markers):
                continue
            if (
                line.startswith(("#", "//", "/*", "*", "- ", "* "))
                or "documentation" in lowered
                or "example" in lowered
                or "for awareness" in lowered
                or (len(line.split()) >= 7 and "." not in line)
            ):
                doc_like_lines += 1

        return (doc_like_lines / len(lines)) > 0.5

    def _iter_dict_nodes(self, obj: Any, path: str = "root") -> list[tuple[str, dict[str, Any]]]:
        """Yield all dict nodes with their traversal path."""
        nodes: list[tuple[str, dict[str, Any]]] = []
        if isinstance(obj, dict):
            nodes = [(path, obj)]
            for key, value in obj.items():
                nodes.extend(self._iter_dict_nodes(value, f"{path}.{key}"))
            return nodes
        if isinstance(obj, list):
            for idx, value in enumerate(obj):
                nodes.extend(self._iter_dict_nodes(value, f"{path}[{idx}]"))
            return nodes
        return []

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
                        result.add_check(
                            name="Dangerous Lambda Layer",
                            passed=False,
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
        elif isinstance(function_data, dict):
            # Keras 3.x dict-format Lambda: {"class_name": "__lambda__", "config": {"code": ...}}
            check_lambda_dict_function(
                function_data, result, f"{self.current_file_path} (layer: {layer_name})", layer_name
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

    @staticmethod
    def _is_vulnerable_to_cve_2024_3660(version: str) -> bool:
        """Return True for Keras versions lower than 2.13.0.

        Handles two-part versions (e.g. "2.10") by treating missing patch as 0.
        """
        parts = version.split(".", 2)
        if len(parts) < 2:
            return False
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = 0
            if len(parts) == 3:
                patch_digits = "".join(ch for ch in parts[2] if ch.isdigit())
                if patch_digits:
                    patch = int(patch_digits)
            return (major, minor, patch) < (2, 13, 0)
        except ValueError:
            return False

    @staticmethod
    def _is_vulnerable_to_cve_2025_12058(version: str) -> bool:
        """Return True for Keras versions lower than 3.12.0, including prereleases of 3.12.0."""
        version_match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9.+-]*)$", version.strip())
        if not version_match:
            return False

        try:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3) or 0)
            suffix = (version_match.group(4) or "").strip().lower()

            parsed = (major, minor, patch)
            if parsed < (3, 12, 0):
                return True
            if parsed > (3, 12, 0):
                return False

            return bool(re.search(r"(?:^|[.\-])(dev|rc|a|b|alpha|beta|pre|preview)\d*", suffix))
        except ValueError:
            return False

    @staticmethod
    def _is_vulnerable_to_cve_2026_1669(version: str) -> bool:
        """Return True for Keras versions in the known CVE-2026-1669 affected ranges."""
        parts = version.split(".", 2)
        if len(parts) < 2:
            return False

        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = 0
            if len(parts) == 3:
                patch_digits = "".join(ch for ch in parts[2] if ch.isdigit())
                if patch_digits:
                    patch = int(patch_digits)
        except ValueError:
            return False

        parsed = (major, minor, patch)
        return (3, 0, 0) <= parsed < (3, 12, 1) or (3, 13, 0) <= parsed < (3, 13, 2)
