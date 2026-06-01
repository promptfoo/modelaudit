"""Scanner for ZIP-based Keras model files (.keras format)."""

import base64
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

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
    get_cve_2025_12060_explanation,
    get_cve_2025_49655_explanation,
    get_cve_2026_1669_explanation,
    get_pattern_explanation,
)
from ..utils.file.detection import _normalize_archive_member_name, _read_zip_member_bounded
from .archive_dispatch import SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY
from .archive_member_security import is_executable_archive_member_name
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult
from .keras_utils import (
    check_custom_loss_config,
    check_custom_metric_config,
    check_lambda_dict_function,
    check_subclassed_model,
    find_lambda_dangerous_patterns,
    is_known_safe_keras_layer_class,
)
from .zip_scanner import ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY

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
_DANGEROUS_LAMBDA_MODULE_TOKENS = frozenset(
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
_DANGEROUS_LAMBDA_FUNCTION_NAMES = frozenset(
    {"__import__", "attrgetter", "compile", "eval", "exec", "open", "popen", "spawn", "system"}
)

# CVE-2025-8747: keras.utils.get_file used as gadget to download + execute files
_GET_FILE_PATTERN = re.compile(r"get_file", re.IGNORECASE)
_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)
_ARCHIVE_EXTRACT_URL_PATTERN = re.compile(
    r"\.(?:tar|tgz|tbz2|txz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tar\.lz|tar\.lz4|tar\.lzma)(?:[?#]|$)",
    re.IGNORECASE,
)
_URL_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(r"^(?:[a-zA-Z]:[\\/]|\\\\)")
_KERAS_CONFIG_ENTRY = "config.json"
_KERAS_CONFIG_MAX_BYTES = 10 * 1024 * 1024


def _has_get_file_reference(values: list[str]) -> bool:
    """Return whether config string values reference a get_file callable."""
    for value in values:
        stripped_value = value.strip()
        if _GET_FILE_PATTERN.fullmatch(stripped_value) is not None:
            return True

        stripped_value_lower = stripped_value.lower()
        if stripped_value_lower.endswith(".get_file") or "keras.utils.get_file" in stripped_value_lower:
            return True

    return False


_KERAS_METADATA_ENTRY = "metadata.json"
_KERAS_METADATA_MAX_BYTES = 10 * 1024 * 1024
_KERAS_WEIGHTS_ENTRY = "model.weights.h5"
_KERAS_RELEASE_VERSION_PATTERN = re.compile(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9.+_-]*)\s*$")
_KERAS_PRERELEASE_SUFFIX_PATTERN = re.compile(r"(?i)^(?:a|alpha|b|beta|c|rc|pre|preview|dev)")


def _redact_url_for_display(url: str) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.hostname:
        return "[invalid-url]"

    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


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
    MAX_LAMBDA_LIST_CODE_B64_CHARS: ClassVar[int] = 1024 * 1024
    MAX_HDF5_LINK_VISITS: ClassVar[int] = 4096
    MAX_HDF5_EXTERNAL_REFERENCE_REPORTS: ClassVar[int] = 20
    MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS: ClassVar[int] = 20

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

    def _get_recursive_archive_scan_config(self, *, skip_weights_entry: bool = False) -> dict[str, Any]:
        """Return bounded ZIP-recursion config for entries not owned by this scanner."""
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
        recursive_config["max_entry_size"] = recursive_member_size_limit
        if self.config.get("max_file_size") not in (None, 0):
            recursive_config["max_file_size"] = recursive_member_size_limit
        else:
            recursive_config.pop("max_file_size", None)
        skip_entries = recursive_config.get("skip_archive_entries", ())
        if isinstance(skip_entries, str):
            skip_entry_values: list[str] = [skip_entries]
        elif isinstance(skip_entries, (list, tuple, set, frozenset)):
            skip_entry_values = [entry for entry in skip_entries if isinstance(entry, str)]
        else:
            skip_entry_values = []
        raw_security_only_entries = recursive_config.get(ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY, ())
        if isinstance(raw_security_only_entries, str):
            security_only_entries: list[str] = [raw_security_only_entries]
        elif isinstance(raw_security_only_entries, (list, tuple, set, frozenset)):
            security_only_entries = [entry for entry in raw_security_only_entries if isinstance(entry, str)]
        else:
            security_only_entries = []
        owned_entries = [_KERAS_CONFIG_ENTRY]
        if skip_weights_entry:
            owned_entries.append(_KERAS_WEIGHTS_ENTRY)
        for owned_entry in owned_entries:
            if owned_entry not in security_only_entries:
                security_only_entries.append(owned_entry)
        recursive_config["skip_archive_entries"] = skip_entry_values
        recursive_config[ZIP_SECURITY_ONLY_MEMBER_ENTRIES_CONFIG_KEY] = security_only_entries
        return recursive_config

    def _merge_recursive_archive_scan(self, path: str, result: ScanResult) -> None:
        """Recursively scan every ZIP member through the generic archive scanner."""
        if self.config.get(SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY):
            return

        from .zip_scanner import ZipScanner

        has_embedded_weights_limit = self._has_embedded_weights_limit_reason(result)
        zip_scanner = ZipScanner(self._get_recursive_archive_scan_config(skip_weights_entry=has_embedded_weights_limit))
        nested_result = zip_scanner._scan_zip_file(
            path,
            depth=max(zip_scanner._get_archive_depth(), zip_scanner._get_zip_depth()),
        )
        if has_embedded_weights_limit:
            self._suppress_expected_embedded_weights_limit_noise(nested_result)
        preserved_metadata = dict(result.metadata)
        nested_contents = nested_result.metadata.get("contents")
        result.merge(nested_result)
        result.metadata.update(preserved_metadata)
        if nested_contents is not None:
            result.metadata["contents"] = nested_contents
        result.success = result.success and nested_result.success

    def _merge_recursive_archive_scan_after_primary_failure(self, path: str, result: ScanResult) -> None:
        """Preserve independently detectable archive findings when Keras analysis is unavailable."""
        try:
            self._merge_recursive_archive_scan(path, result)
        except Exception:
            # The primary failure already makes this scan inconclusive; a
            # failing fallback must not replace that explicit outcome.
            return

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
                    self._mark_inconclusive_scan_result(result, "keras_zip_config_missing")
                    result.add_check(
                        name="Keras ZIP Format Check",
                        passed=False,
                        message="No config.json found in Keras ZIP file",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"files": zf.namelist()},
                    )
                    self._load_keras_metadata(zf, result)
                    self._check_archive_security_members(zf, path, result)
                    self._merge_recursive_archive_scan(path, result)
                    self._finish_scan_result(result)
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
                    self._mark_inconclusive_scan_result(result, "keras_zip_config_parse_failed")
                    # Fall back to a structure-aware raw scan only when the archive
                    # config is malformed and cannot be parsed as JSON.
                    if raw_config_text:
                        self._check_unsafe_deserialization_bypass_raw(raw_config_text, result)
                    result.add_check(
                        name="Config JSON Parsing",
                        passed=False,
                        message=f"Failed to parse config.json: {e}",
                        severity=IssueSeverity.INFO,
                        location=f"{path}/{config_info.filename}",
                        details={
                            "error": str(e),
                            "max_config_bytes": _KERAS_CONFIG_MAX_BYTES,
                        },
                    )
                    self._load_keras_metadata(zf, result)
                    self._check_archive_security_members(zf, path, result)
                    self._merge_recursive_archive_scan(path, result)
                    self._finish_scan_result(result)
                    return result

                # CVE-2025-9906 can be detected in any parsed JSON shape; the
                # rest of the structured model scan requires a top-level object.
                self._check_unsafe_deserialization_bypass(model_config, result)
                self._check_get_file_archive_extraction(model_config, result)
                self._check_get_file_gadget(model_config, result)
                self._load_keras_metadata(zf, result)

                if not isinstance(model_config, dict):
                    self._mark_inconclusive_scan_result(result, "keras_zip_config_invalid_type")
                    result.add_check(
                        name="Model Config Type Validation",
                        passed=False,
                        message=f"Invalid config.json type: expected dict, got {type(model_config).__name__}",
                        severity=IssueSeverity.INFO,
                        location=f"{path}/{config_info.filename}",
                        details={"actual_type": type(model_config).__name__, "expected_type": "dict"},
                    )
                    self._check_archive_security_members(zf, path, result)
                    self._merge_recursive_archive_scan(path, result)
                    self._finish_scan_result(result)
                    return result

                # Scan model configuration
                self._scan_model_config(model_config, result)

                self._check_archive_security_members(zf, path, result)

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
        except OSError as e:
            self._mark_inconclusive_scan_result(result, "keras_zip_read_failed")
            result.add_check(
                name="Keras ZIP File Read",
                passed=False,
                message=f"Unable to read Keras ZIP content: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_zip_read_failed",
                },
            )
            self._merge_recursive_archive_scan_after_primary_failure(path, result)
            self._finish_scan_result(result)
            return result
        except Exception as e:
            self._mark_inconclusive_scan_result(result, "keras_zip_scan_failed")
            result.add_check(
                name="Keras ZIP File Scan",
                passed=False,
                message=f"Error scanning Keras ZIP file: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "keras_zip_scan_failed",
                },
            )
            self._merge_recursive_archive_scan_after_primary_failure(path, result)
            self._finish_scan_result(result)
            return result

        self._finish_scan_result(result)
        return result

    def _load_keras_metadata(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        metadata_info = self._get_archive_member_info(archive, _KERAS_METADATA_ENTRY)
        if metadata_info is None:
            return

        try:
            metadata_data = _read_zip_member_bounded(
                archive,
                metadata_info,
                _KERAS_METADATA_MAX_BYTES,
            )
            metadata = json.loads(metadata_data)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return

        if not isinstance(metadata, dict):
            return

        result.metadata["keras_metadata"] = metadata
        keras_version = metadata.get("keras_version")
        if isinstance(keras_version, str) and keras_version.strip():
            result.metadata["keras_version"] = keras_version.strip()

    def _check_archive_security_members(
        self,
        archive: zipfile.ZipFile,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        self._check_embedded_hdf5_weights_external_references(archive, result)

        for filename in archive.namelist():
            normalized_name = filename.lower()
            if normalized_name.endswith((".py", ".pyc", ".pyo")):
                result.add_check(
                    name="Python File Detection",
                    passed=False,
                    message=f"Python file found in Keras ZIP: {filename}",
                    severity=IssueSeverity.WARNING,
                    location=f"{archive_path}/{filename}",
                    details={"filename": filename},
                )
            elif is_executable_archive_member_name(normalized_name):
                result.add_check(
                    name="Executable File Detection",
                    passed=False,
                    message=f"Executable file found in Keras ZIP: {filename}",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{archive_path}/{filename}",
                    details={"filename": filename},
                )

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
    def _has_embedded_weights_limit_reason(result: ScanResult) -> bool:
        reasons = result.metadata.get("scan_outcome_reasons")
        return isinstance(reasons, list) and "keras_zip_embedded_weights_too_large" in reasons

    @staticmethod
    def _is_expected_recursive_weights_limit_noise(entry: Any) -> bool:
        details = getattr(entry, "details", None)
        message = getattr(entry, "message", "")
        return (
            isinstance(details, dict)
            and details.get("entry") == _KERAS_WEIGHTS_ENTRY
            and isinstance(message, str)
            and "exceeds maximum size" in message
        )

    @classmethod
    def _suppress_expected_embedded_weights_limit_noise(cls, result: ScanResult) -> None:
        result.issues = [issue for issue in result.issues if not cls._is_expected_recursive_weights_limit_noise(issue)]
        result.checks = [check for check in result.checks if not cls._is_expected_recursive_weights_limit_noise(check)]

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

        result.finish(success=result.success and not result.has_errors)

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

        if "compile_config" in model_config:
            self._scan_compile_config(model_config.get("compile_config"), result)

        # Get layers from config
        layers = []
        config_value = model_config.get("config")
        if "config" in model_config and not isinstance(config_value, dict):
            self._mark_inconclusive_scan_result(result, "keras_zip_model_config_structure_invalid")
            result.add_check(
                name="Model Config Structure Validation",
                passed=False,
                message=f"Invalid model config type: expected dict, got {type(config_value).__name__}",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}/config.json",
                details={"actual_type": type(config_value).__name__, "expected_type": "dict"},
            )
        elif isinstance(config_value, dict):
            if "layers" in config_value:
                layers_value = config_value["layers"]
                if isinstance(layers_value, list):
                    layers = layers_value
                else:
                    self._mark_inconclusive_scan_result(result, "keras_zip_model_layers_invalid_type")
                    result.add_check(
                        name="Layers Type Validation",
                        passed=False,
                        message=f"Invalid layers type: expected list, got {type(layers_value).__name__}",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path}/config.json",
                        details={"actual_type": type(layers_value).__name__, "expected_type": "list"},
                    )
            elif "layer" in config_value:
                # Single layer model
                layer_value = config_value["layer"]
                if isinstance(layer_value, dict):
                    layers = [layer_value]
                else:
                    self._mark_inconclusive_scan_result(result, "keras_zip_model_layer_invalid_type")
                    result.add_check(
                        name="Single Layer Type Validation",
                        passed=False,
                        message=f"Invalid layer type: expected dict, got {type(layer_value).__name__}",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path}/config.json",
                        details={"actual_type": type(layer_value).__name__, "expected_type": "dict"},
                    )

        # Count of each layer type
        layer_counts: dict[str, int] = {}

        # Check each layer
        for i, layer in enumerate(layers):
            if not isinstance(layer, dict):
                self._mark_inconclusive_scan_result(result, "keras_zip_model_layer_invalid_type")
                result.add_check(
                    name="Layer Type Validation",
                    passed=False,
                    message=f"Invalid layer type: expected dict, got {type(layer).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path}/config.json",
                    details={"actual_type": type(layer).__name__, "expected_type": "dict", "index": i},
                )
                continue

            layer_class = layer.get("class_name", "")
            layer_name = layer.get("name", f"layer_{i}")

            layer_config = layer.get("config")
            if "config" in layer and not isinstance(layer_config, dict):
                self._mark_inconclusive_scan_result(result, "keras_zip_layer_config_invalid_type")
                result.add_check(
                    name="Layer Config Type Validation",
                    passed=False,
                    message=f"Invalid layer config type: expected dict, got {type(layer_config).__name__}",
                    rule_code="S902",
                    severity=IssueSeverity.INFO,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_name": layer_name,
                        "actual_type": type(layer_config).__name__,
                        "expected_type": "dict",
                    },
                )

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

            is_lambda_layer = self._is_lambda_layer_class(layer_class)

            # Check for Lambda layers
            if is_lambda_layer:
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
            if layer_class in ["Model", "Functional", "Sequential"] and "config" in layer:
                nested_config = layer["config"]
                if isinstance(nested_config, dict):
                    self._scan_model_config(layer, result)
                else:
                    self._mark_inconclusive_scan_result(result, "keras_zip_nested_model_config_invalid_type")
                    result.add_check(
                        name="Nested Model Config Type Validation",
                        passed=False,
                        message=f"Invalid nested model config type: expected dict, got {type(nested_config).__name__}",
                        rule_code="S902",
                        severity=IssueSeverity.INFO,
                        location=f"{self.current_file_path} (layer: {layer_name})",
                        details={"actual_type": type(nested_config).__name__, "expected_type": "dict"},
                    )

        # Add layer counts to metadata
        result.metadata["layer_counts"] = layer_counts

    def _scan_compile_config(self, compile_config: Any, result: ScanResult) -> None:
        """Inspect compile_config for custom metrics and losses."""
        if compile_config is None:
            return
        if not isinstance(compile_config, dict):
            self._mark_inconclusive_scan_result(result, "keras_zip_compile_config_invalid_type")
            result.add_check(
                name="Compile Config Type Validation",
                passed=False,
                message=f"Invalid compile_config type: expected dict, got {type(compile_config).__name__}",
                rule_code="S902",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}/config.json",
                details={"actual_type": type(compile_config).__name__, "expected_type": "dict"},
            )
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
        check_custom_metric_config(metrics_config, result, f"{self.current_file_path} ({context})")

    def _check_custom_loss_config(self, loss_config: Any, result: ScanResult, context: str) -> None:
        """Flag custom losses embedded anywhere in a serialized loss tree."""
        check_custom_loss_config(loss_config, result, f"{self.current_file_path} ({context})")

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
            elif is_outside_allowlist and (key == "fn_module" or self._is_lambda_layer_class(layer_class)):
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

    def _check_get_file_gadget(self, model_config: Any, result: ScanResult) -> None:
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
            has_get_file = _has_get_file_reference(direct_string_values)
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

    def _check_get_file_archive_extraction(self, model_config: Any, result: ScanResult) -> None:
        """Check for CVE-2025-12060: get_file(extract=True) tar traversal risk."""
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

            has_get_file = _has_get_file_reference(direct_string_values)
            if not has_get_file or not self._node_has_get_file_extract_true(node):
                continue

            archive_urls = [
                value
                for value in url_candidate_values
                if _URL_PATTERN.search(value) is not None and _ARCHIVE_EXTRACT_URL_PATTERN.search(value) is not None
            ]
            if not archive_urls:
                continue

            result.add_check(
                name="CVE-2025-12060: get_file Archive Extraction Traversal",
                passed=False,
                message=(
                    "CVE-2025-12060: config.json contains keras.utils.get_file with extract=True "
                    "and a remote tar archive URL"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path}/config.json",
                details={
                    "cve_id": "CVE-2025-12060",
                    "context": context,
                    "urls": [_redact_url_for_display(url) for url in archive_urls[:5]],
                    "cvss": 8.8,
                    "cwe": "CWE-22",
                    "description": (
                        "keras.utils.get_file(extract=True) can extract attacker-controlled tar archives "
                        "with traversal or symlink entries outside the intended destination."
                    ),
                    "affected_versions": "Keras < 3.12.0",
                    "remediation": (
                        "Upgrade Keras to >= 3.12.0 and reject configs that download and extract tar archives."
                    ),
                },
                why=get_cve_2025_12060_explanation("get_file_extract_tar"),
            )
            return

    @staticmethod
    def _node_has_get_file_extract_true(node: dict[str, Any]) -> bool:
        """Return True only for direct get_file extract=True argument positions."""
        if node.get("extract") is True:
            return True

        kwargs = node.get("kwargs")
        if isinstance(kwargs, dict) and kwargs.get("extract") is True:
            return True

        args = node.get("args")
        if isinstance(args, list | tuple):
            # keras.utils.get_file positional args: fname, origin, untar, ..., extract.
            return (len(args) > 2 and args[2] is True) or (len(args) > 7 and args[7] is True)

        return False

    def _check_unsafe_deserialization_bypass(self, model_config: Any, result: ScanResult) -> None:
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
        weights_info = self._get_archive_member_info(archive, _KERAS_WEIGHTS_ENTRY)
        if weights_info is None:
            return

        if weights_info.file_size > self.max_embedded_weights_bytes:
            weights_entry = weights_info.filename
            self._mark_inconclusive_scan_result(result, "keras_zip_embedded_weights_too_large")
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

        if not HAS_H5PY:
            return

        temp_path = None
        findings: list[dict[str, Any]] = []
        external_reference_analysis: dict[str, Any] = {}
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
                findings = self._collect_hdf5_external_references(
                    h5_file,
                    analysis=external_reference_analysis,
                )
        except _EmbeddedWeightsLimitExceeded as exc:
            weights_entry = weights_info.filename
            self._mark_inconclusive_scan_result(result, "keras_zip_embedded_weights_too_large")
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

        if any(
            external_reference_analysis.get(key)
            for key in (
                "link_visits_truncated",
                "external_references_truncated",
                "external_storage_segments_truncated",
            )
        ):
            reason = "keras_zip_external_reference_analysis_limit_exceeded"
            self._mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="Embedded HDF5 External Reference Analysis Limit",
                passed=False,
                message="Embedded Keras HDF5 external-reference analysis reached a configured safety limit",
                severity=IssueSeverity.INFO,
                location=f"{self.current_file_path}:{weights_info.filename}",
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                    **external_reference_analysis,
                },
                rule_code="S902",
            )

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
        if external_reference_analysis.get("external_references_truncated") or external_reference_analysis.get(
            "external_storage_segments_truncated"
        ):
            details.update(
                {
                    "external_reference_count": external_reference_analysis["external_reference_count"],
                    "external_references_truncated": external_reference_analysis["external_references_truncated"],
                    "external_storage_segments_truncated": external_reference_analysis[
                        "external_storage_segments_truncated"
                    ],
                }
            )

        if isinstance(keras_version, str):
            details["keras_version"] = keras_version
            if not self._is_vulnerable_to_cve_2026_1669(keras_version):
                details["parse_status"] = "untrusted_artifact_version"
                details["version_source"] = "metadata_json"
            result.add_check(
                name="CVE-2026-1669: HDF5 External Weight Reference",
                passed=False,
                message=(
                    "CVE-2026-1669: embedded Keras weights use HDF5 external references that can disclose "
                    "arbitrary local file contents during model loading; archive-controlled metadata claims "
                    f"Keras {keras_version}"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details=details,
                why=get_cve_2026_1669_explanation("hdf5_external_reference"),
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

    @classmethod
    def _collect_hdf5_external_references(
        cls,
        h5_file: Any,
        *,
        analysis: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Collect HDF5 ExternalLink and external-storage datasets without following links."""
        findings: list[dict[str, Any]] = []
        external_reference_count = 0
        external_storage_segments_truncated = False

        def visit(name: str, link: Any) -> None:
            nonlocal external_reference_count, external_storage_segments_truncated
            if isinstance(link, h5py.ExternalLink):
                external_reference_count += 1
                if len(findings) < cls.MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
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
            if not isinstance(obj, h5py.Dataset):
                return

            external_storage = obj.external
            if not external_storage:
                return

            external_reference_count += 1
            if len(findings) >= cls.MAX_HDF5_EXTERNAL_REFERENCE_REPORTS:
                return

            segments = [
                {"filename": filename, "offset": int(offset), "size": int(size)}
                for filename, offset, size in external_storage[: cls.MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS]
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

        visited_link_count, link_visits_truncated = cls._visit_hdf5_links(
            h5_file,
            visit,
            max_links=cls.MAX_HDF5_LINK_VISITS,
        )
        if analysis is not None:
            analysis.update(
                {
                    "visited_link_count": visited_link_count,
                    "max_link_visits": cls.MAX_HDF5_LINK_VISITS,
                    "link_visits_truncated": link_visits_truncated,
                    "external_reference_count": external_reference_count,
                    "reported_external_reference_count": len(findings),
                    "external_references_truncated": external_reference_count > len(findings),
                    "external_storage_segments_truncated": external_storage_segments_truncated,
                }
            )

        return findings

    @classmethod
    def _visit_hdf5_links(cls, h5_file: Any, visit: Any, *, max_links: int) -> tuple[int, bool]:
        """Traverse HDF5 links without following ExternalLink or SoftLink targets."""
        visited_link_count = 0
        visited_group_ids: set[Any] = set()
        groups_to_visit: list[tuple[Any, str]] = [(h5_file, "")]

        while groups_to_visit:
            group, prefix = groups_to_visit.pop()
            group_identity = cls._hdf5_object_identity(group)
            if group_identity in visited_group_ids:
                continue
            visited_group_ids.add(group_identity)

            for child_name in group:
                if visited_link_count >= max_links:
                    return visited_link_count, True
                visited_link_count += 1

                child_key = str(child_name)
                child_path = f"{prefix}/{child_key}" if prefix else child_key
                link = group.get(child_name, getlink=True)
                visit(child_path, link)

                if not isinstance(link, h5py.HardLink):
                    continue

                obj = group.get(child_name, getlink=False)
                if isinstance(obj, h5py.Group):
                    groups_to_visit.append((obj, child_path))

        return visited_link_count, False

    @staticmethod
    def _hdf5_object_identity(obj: Any) -> Any:
        """Return a stable identity for cycle-safe HDF5 hard-link traversal."""
        try:
            return ("h5o_addr", int(h5py.h5o.get_info(obj.id).addr))
        except Exception:
            return ("python_id", id(obj))

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
        lowered_keys = {str(key).lower() for key in node}
        doc_keys = {
            "description",
            "doc",
            "docs",
            "comment",
            "comments",
            "notes",
            "help",
            "readme",
            "citation",
            "url",
            "homepage",
            "link",
            "reference",
        }
        if any(marker in context_lower for marker in doc_markers):
            return not KerasZipScanner._has_serialized_callable_context(node, lowered_keys)

        return (
            bool(lowered_keys)
            and lowered_keys.issubset(doc_keys)
            and not KerasZipScanner._has_serialized_callable_context(node, lowered_keys)
        )

    @staticmethod
    def _has_serialized_callable_context(node: dict[str, Any], lowered_keys: set[str]) -> bool:
        """Return True when a doc-like node still resembles Keras callable config."""
        callable_keys = {"fn", "function", "callable"}
        callable_context_keys = {"module", "fn_module", "args", "kwargs", "config", "origin", "url"}
        if lowered_keys & callable_keys:
            return bool(lowered_keys & callable_context_keys)

        class_context_keys = {"module", "fn_module", "args", "kwargs", "config"}
        return bool(lowered_keys & {"class_name", "registered_name"}) and bool(lowered_keys & class_context_keys)

    @staticmethod
    def _is_lambda_layer_class(layer_class: Any) -> bool:
        """Return True for Keras/TensorFlow Lambda serialization names."""
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
        if not isinstance(layer_config, dict):
            return

        # Lambda layers in Keras ZIP format store the function as a list
        # where the first element is base64-encoded Python code
        function_data = layer_config.get("function")

        if function_data and isinstance(function_data, list) and len(function_data) > 0:
            # First element is the base64-encoded function
            encoded_function = function_data[0]

            if (
                encoded_function
                and isinstance(encoded_function, str)
                and len(encoded_function) > self.MAX_LAMBDA_LIST_CODE_B64_CHARS
            ):
                result.add_check(
                    name="Lambda Layer Detection",
                    passed=False,
                    message=(
                        f"Lambda layer '{layer_name}' contains list-format code that exceeds the bounded analysis limit"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=f"{self.current_file_path} (layer: {layer_name})",
                    details={
                        "layer_name": layer_name,
                        "layer_class": "Lambda",
                        "function_format": "list",
                        "analysis_status": "code_size_limit_exceeded",
                        "encoded_code_chars": len(encoded_function),
                        "max_encoded_code_chars": self.MAX_LAMBDA_LIST_CODE_B64_CHARS,
                    },
                    why=(
                        "Oversized Lambda bytecode was not decoded because it exceeds the bounded "
                        "static-analysis limit."
                    ),
                )
                encoded_function = ""

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

                    found_patterns = find_lambda_dangerous_patterns(decoded_str, dangerous_patterns)

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
                                message=(
                                    f"Lambda layer '{layer_name}' contains opaque encoded bytecode with no dangerous "
                                    "text patterns detected"
                                ),
                                severity=IssueSeverity.WARNING,
                                location=f"{self.current_file_path} (layer: {layer_name})",
                                details={
                                    "layer_name": layer_name,
                                    "layer_class": "Lambda",
                                    "validation_error": error,
                                    "analysis_status": "opaque_bytecode",
                                },
                                why=(
                                    "Keras Lambda layers can embed bytecode that executes during model loading or "
                                    "inference; no high-risk text patterns were detected."
                                ),
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

        module_name = layer_config.get("module")
        function_name = layer_config.get("function_name")
        if self._is_lambda_module_reference_dangerous(module_name, function_name):
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
    def _is_lambda_module_reference_dangerous(module_name: Any, function_name: Any) -> bool:
        """Return True when Lambda sibling metadata names a risky symbol."""
        if isinstance(function_name, str) and function_name.strip().lower() in _DANGEROUS_LAMBDA_FUNCTION_NAMES:
            return True
        if not isinstance(module_name, str):
            return False

        module_tokens = {token.strip().lower() for token in re.split(r"[^0-9A-Za-z_]+", module_name) if token.strip()}
        return bool(module_tokens & _DANGEROUS_LAMBDA_MODULE_TOKENS)

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
        version_match = _KERAS_RELEASE_VERSION_PATTERN.match(version)
        if not version_match:
            return False

        try:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3) or 0)
        except ValueError:
            return False

        suffix = (version_match.group(4) or "").strip().lower()
        public_suffix = suffix.lstrip("._-")
        is_prerelease = not suffix.startswith("+") and bool(_KERAS_PRERELEASE_SUFFIX_PATTERN.match(public_suffix))
        parsed = (major, minor, patch)
        if (3, 0, 0) <= parsed < (3, 12, 1) or (3, 13, 0) <= parsed < (3, 13, 2):
            return True
        return parsed in {(3, 12, 1), (3, 13, 2)} and is_prerelease
