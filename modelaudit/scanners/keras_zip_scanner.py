"""Scanner for ZIP-based Keras model files (.keras format)."""

import base64
import json
import os
import re
import zipfile
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
    get_cve_2025_49655_explanation,
    get_pattern_explanation,
)
from .base import BaseScanner, IssueSeverity, ScanResult
from .keras_utils import check_subclassed_model

# CVE-2025-8747: keras.utils.get_file used as gadget to download + execute files
_GET_FILE_PATTERN = re.compile(r"get_file", re.IGNORECASE)
_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)


class KerasZipScanner(BaseScanner):
    """Scanner for ZIP-based Keras .keras model files"""

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
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"files": zf.namelist()},
                    )
                    result.finish(success=True)
                    return result

                # Read and parse config.json
                with zf.open("config.json") as config_file:
                    config_data = config_file.read()
                    raw_config_text = config_data.decode("utf-8", errors="ignore")
                    # Run raw-text CVE detection before JSON parsing so malformed JSON cannot bypass it.
                    self._check_unsafe_deserialization_bypass_raw(raw_config_text, result)
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

                # CVE-2025-8747: Check for structured get_file gadget usage
                self._check_get_file_gadget(model_config, result)
                # CVE-2025-9906: structured fallback check on parsed config
                self._check_unsafe_deserialization_bypass(model_config, result)

                # Check for metadata.json
                if "metadata.json" in zf.namelist():
                    with zf.open("metadata.json") as metadata_file:
                        metadata_data = metadata_file.read()
                        try:
                            metadata = json.loads(metadata_data)
                            result.metadata["keras_metadata"] = metadata
                            keras_version = metadata.get("keras_version")
                            if isinstance(keras_version, str) and keras_version.strip():
                                result.metadata["keras_version"] = keras_version.strip()
                        except json.JSONDecodeError:
                            pass  # Metadata parsing is optional

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

    def _check_get_file_gadget(self, model_config: dict[str, Any], result: ScanResult) -> None:
        """Check for CVE-2025-8747: keras.utils.get_file gadget bypass.

        CVE-2025-8747: Bypass of CVE-2025-1550 fix. Uses keras.utils.get_file
        as a gadget to download and execute arbitrary files even with safe_mode=True.
        Detected when a single config object references get_file and includes URL arguments.
        """
        for context, node in self._iter_dict_nodes(model_config):
            if self._is_primarily_documentation(context, node):
                continue
            string_values: list[str] = []
            for value in node.values():
                string_values.extend(self._extract_string_literals(value))
            has_get_file = any(
                _GET_FILE_PATTERN.fullmatch(value.strip()) is not None
                or value.strip().lower().endswith(".get_file")
                or "keras.utils.get_file" in value.strip().lower()
                for value in string_values
            )
            has_url = any(_URL_PATTERN.search(value) is not None for value in string_values)
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
        """Raw-text CVE check to catch references before JSON parsing."""
        if self._has_cve_2025_9906_issue(result):
            return

        lowered = raw_config_text.lower()
        raw_symbols = (
            "keras.config.enable_unsafe_deserialization",
            "keras.src.config.enable_unsafe_deserialization",
        )
        matched_symbol = next((symbol for symbol in raw_symbols if symbol in lowered), None)
        if not matched_symbol:
            return
        if self._is_primarily_documentation_text(raw_config_text):
            return

        result.add_check(
            name="CVE-2025-9906: Unsafe Deserialization Bypass",
            passed=False,
            message=(
                "CVE-2025-9906: config.json contains raw reference to "
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

    @staticmethod
    def _extract_string_literals(value: Any) -> list[str]:
        """Extract string literals from simple container values."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple, set)):
            values: list[str] = []
            for item in value:
                values.extend(KerasZipScanner._extract_string_literals(item))
            return values
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

        doc_like_lines = 0
        for line in lines:
            lowered = line.lower()
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
