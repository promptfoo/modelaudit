"""
XGBoost Model Scanner

Comprehensive security scanner for XGBoost model files that detects potential
vulnerabilities in .bst, .json, .ubj, and pickle-based XGBoost models.

Supported XGBoost Model Formats:
- Binary models (.bst, .model): XGBoost's proprietary binary format
- JSON models (.json): Human-readable JSON representation
- UBJ models (.ubj): Universal Binary JSON format
- Pickle models (.pkl, .pickle, .joblib): Python-serialized XGBoost models

Security Focus:
- Insecure deserialization in pickle/joblib files
- Malformed JSON/UBJ structure validation
- Binary .bst integrity and consistency checks
- Embedded code execution patterns
- Known CVE patterns and exploit signatures
"""

import importlib.util
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from contextlib import suppress
from typing import Any, ClassVar

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)

# Precompiled regex patterns for performance
SUSPICIOUS_JSON_PATTERNS = [
    (re.compile(r"__reduce__", re.IGNORECASE), "Pickle-like reduction pattern in JSON"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "Eval function call in JSON"),
    (re.compile(r"exec\s*\(", re.IGNORECASE), "Exec function call in JSON"),
    (re.compile(r"import\s+os", re.IGNORECASE), "OS module import in JSON"),
    (re.compile(r"subprocess\.", re.IGNORECASE), "Subprocess usage in JSON"),
    (re.compile(r"system\s*\(", re.IGNORECASE), "System call in JSON"),
    (re.compile(r"__import__", re.IGNORECASE), "Dynamic import in JSON"),
    (re.compile(r"\\x[0-9a-fA-F]{2}", re.IGNORECASE), "Hex-encoded data (potential shellcode)"),
]
_INERT_JSON_SECURITY_PATHS: frozenset[tuple[str, ...]] = frozenset({("learner", "feature_names")})
XGBOOST_DEFAULT_MAX_FILE_READ_SIZE = 256 * 1024 * 1024
XGBOOST_JSON_ROUTING_CHUNK_BYTES = 64 * 1024
_JSON_KEY_MAX_BYTES = 256
_JSON_WHITESPACE_BYTES = frozenset(b" \t\r\n")


def _check_xgboost_available() -> bool:
    """Check if XGBoost package is available."""
    return importlib.util.find_spec("xgboost") is not None


def _check_ubjson_available() -> bool:
    """Check if UBJSON decoder is available."""
    try:
        import ubjson  # noqa: F401

        return True
    except ImportError:
        return False


def _decode_json_key(raw_key: bytes, key_overflow: bool) -> str | None:
    """Decode a bounded JSON object key captured with surrounding quotes."""
    if key_overflow:
        return None
    try:
        value = json.JSONDecoder().decode(raw_key.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, str) else None


def _json_file_has_xgboost_markers(path: str, max_bytes: int) -> bool:
    """Return True if a bounded stream finds top-level XGBoost JSON markers."""
    found_version = False
    found_learner = False
    bytes_read = 0
    started = False
    stack: list[int] = []
    in_string = False
    escaped = False
    collecting_key = False
    key_overflow = False
    raw_key = bytearray()
    expecting_key = False
    awaiting_colon = False
    pending_key: str | None = None
    awaiting_value_for: str | None = None
    version_array_depth: int | None = None
    version_array_items = 0
    version_array_expects_value = False

    def record_value_marker(byte: int, key: str) -> bool:
        nonlocal found_learner, version_array_depth, version_array_items, version_array_expects_value
        if key == "version" and byte == ord("["):
            version_array_depth = len(stack) + 1
            version_array_items = 0
            version_array_expects_value = True
            return True
        if key == "learner" and byte == ord("{"):
            found_learner = True
        return False

    with open(path, "rb") as f:
        initial = f.read(3)
        if initial != b"\xef\xbb\xbf":
            f.seek(0)

        while bytes_read < max_bytes:
            chunk = f.read(min(XGBOOST_JSON_ROUTING_CHUNK_BYTES, max_bytes - bytes_read))
            if not chunk:
                break
            bytes_read += len(chunk)

            for byte in chunk:
                if in_string:
                    if collecting_key:
                        if len(raw_key) < _JSON_KEY_MAX_BYTES:
                            raw_key.append(byte)
                        else:
                            key_overflow = True

                    if escaped:
                        escaped = False
                    elif byte == ord("\\"):
                        escaped = True
                    elif byte == ord('"'):
                        in_string = False
                        if collecting_key:
                            pending_key = _decode_json_key(bytes(raw_key), key_overflow)
                            awaiting_colon = True
                            collecting_key = False
                            key_overflow = False
                            expecting_key = False
                    continue

                if not started:
                    if byte in _JSON_WHITESPACE_BYTES:
                        continue
                    if byte != ord("{"):
                        return False
                    started = True
                    stack.append(ord("}"))
                    expecting_key = True
                    continue

                if awaiting_colon:
                    if byte in _JSON_WHITESPACE_BYTES:
                        continue
                    if byte != ord(":"):
                        return False
                    awaiting_value_for = pending_key
                    pending_key = None
                    awaiting_colon = False
                    expecting_key = False
                    continue

                if awaiting_value_for is not None:
                    if byte in _JSON_WHITESPACE_BYTES:
                        continue
                    started_version_array = record_value_marker(byte, awaiting_value_for)
                    awaiting_value_for = None
                else:
                    started_version_array = False

                if version_array_depth is not None and not started_version_array and len(stack) == version_array_depth:
                    if byte in _JSON_WHITESPACE_BYTES:
                        continue
                    if byte == ord("]"):
                        if version_array_items >= 2:
                            found_version = True
                        version_array_depth = None
                    elif byte == ord(","):
                        version_array_expects_value = True
                    elif version_array_expects_value:
                        version_array_items += 1
                        version_array_expects_value = False
                    if found_version and found_learner:
                        return True

                if byte == ord('"'):
                    if len(stack) == 1 and expecting_key:
                        collecting_key = True
                        raw_key = bytearray(b'"')
                    in_string = True
                    escaped = False
                    continue

                if byte == ord("{"):
                    stack.append(ord("}"))
                elif byte == ord("["):
                    stack.append(ord("]"))
                elif byte in {ord("}"), ord("]")}:
                    if not stack or stack[-1] != byte:
                        return False
                    if len(stack) == 1:
                        return found_version and found_learner
                    stack.pop()
                elif byte == ord(",") and len(stack) == 1:
                    expecting_key = True

    return False


class XGBoostScanner(BaseScanner):
    """Scanner for XGBoost model files with comprehensive security analysis."""

    name: ClassVar[str] = "xgboost"
    description: ClassVar[str] = "Scans XGBoost models for security vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".bst", ".model", ".json", ".ubj"]
    default_max_file_read_size: ClassVar[int] = XGBOOST_DEFAULT_MAX_FILE_READ_SIZE
    _JSON_PROBE_READ_BYTES: ClassVar[int] = 256 * 1024
    _JSON_REQUIRED_MARKERS: ClassVar[tuple[bytes, ...]] = (b'"learner"', b'"version"')
    _JSON_STRONG_MARKERS: ClassVar[tuple[bytes, ...]] = (
        b'"gradient_booster"',
        b'"learner_model_param"',
        b'"gbtree_model_param"',
        b'"tree_info"',
        b'"gbtree"',
        b'"gblinear"',
        b'"dart"',
    )
    _UBJSON_PROBE_READ_BYTES: ClassVar[int] = 256 * 1024
    _UBJSON_OBJECT_START: ClassVar[int] = ord("{")
    _UBJSON_NEXT_VALID: ClassVar[frozenset[int]] = frozenset(b"iUIlLdDSC#$}")
    _UBJSON_REQUIRED_MARKERS: ClassVar[tuple[bytes, ...]] = (b"learner",)
    _UBJSON_STRONG_MARKERS: ClassVar[tuple[bytes, ...]] = (
        b"version",
        b"gradient_booster",
        b"learner_model_param",
        b"gbtree_model_param",
        b"tree_info",
        b"gbtree",
        b"gblinear",
        b"dart",
    )
    _BINARY_MIN_STRUCTURE_BYTES: ClassVar[int] = 32
    _INCONCLUSIVE_REASONS: ClassVar[dict[str, str]] = {
        "json_parse_failed": "xgboost_json_parse_failed",
        "json_analysis_failed": "xgboost_json_analysis_failed",
        "ubj_dependency_missing": "xgboost_ubj_dependency_missing",
        "ubj_analysis_failed": "xgboost_ubj_analysis_failed",
        "binary_empty": "xgboost_binary_empty",
        "binary_structure_too_small": "xgboost_binary_structure_too_small",
        "binary_structure_unrecognized": "xgboost_binary_structure_unrecognized",
        "binary_analysis_failed": "xgboost_binary_analysis_failed",
        "binary_pickle_spoof": "xgboost_binary_pickle_spoof",
        "binary_load_dependency_missing": "xgboost_binary_load_dependency_missing",
        "binary_load_failed": "xgboost_binary_load_failed",
        "binary_load_timeout": "xgboost_binary_load_timeout",
        "binary_load_exception": "xgboost_binary_load_exception",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.enable_xgb_loading = self._get_bool_config("enable_xgb_loading", False)
        self.max_num_trees = self.config.get("max_num_trees", 10000)
        self.max_tree_depth = self.config.get("max_tree_depth", 1000)

    def _mark_inconclusive_scan_result(self, result: ScanResult, reason: str) -> None:
        """Mark XGBoost analysis as incomplete so callers fail closed."""
        existing_reasons = result.metadata.get("scan_outcome_reasons")
        reasons = existing_reasons if isinstance(existing_reasons, list) else []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = reasons
        result.metadata["analysis_incomplete"] = True

    def _finish_scan_result(self, result: ScanResult) -> None:
        """Fail closed on inconclusive scans while preserving clean valid models."""
        result.finish(
            success=not result.has_errors and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        if not os.path.isfile(path):
            return False

        file_ext = os.path.splitext(path)[1].lower()

        # For exclusive XGBoost formats, accept immediately
        if file_ext in [".bst", ".ubj"]:
            return True

        # For .json files, validate it's actually an XGBoost model
        if file_ext == ".json":
            return cls._is_xgboost_json(path) or cls._is_probable_xgboost_json_candidate(path)

        # For .model files, accept (generic extension)
        if file_ext == ".model":
            return True

        # Check for XGBoost files without extension
        if file_ext == "":
            if cls._is_ubjson_file(path):
                return True
            with suppress(OSError), open(path, "rb") as f:
                header = f.read(16)
                # Check for XGBoost binary signature patterns
                if b"binf" in header or b"gblinear" in header[:100]:
                    return True

        return False

    @classmethod
    def _is_probable_xgboost_json_candidate(cls, path: str) -> bool:
        """Sniff malformed-but-XGBoost-like JSON so parse failures fail closed."""
        try:
            with open(path, "rb") as f:
                probe = f.read(cls._JSON_PROBE_READ_BYTES).lower()
        except OSError:
            return False

        has_required_markers = all(marker in probe for marker in cls._JSON_REQUIRED_MARKERS)
        if not has_required_markers:
            return False

        return any(marker in probe for marker in cls._JSON_STRONG_MARKERS)

    @classmethod
    def _is_xgboost_json(cls, path: str) -> bool:
        """
        Bounded structural check for XGBoost JSON format.

        XGBoost JSON models have this structure (any version):
        {
            "version": [major, minor, ...],  // Array with at least 2 elements
            "learner": {                     // Dict with model configuration
                ...
            }
        }

        This matches what _validate_xgboost_json_schema() checks.
        """
        try:
            return _json_file_has_xgboost_markers(path, cls.default_max_file_read_size)
        except OSError:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan XGBoost model file for security vulnerabilities."""
        # Standard path checks
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path

        # Add file integrity check
        self.add_file_integrity_check(path, result)

        # Determine file format and dispatch to appropriate scanner
        file_ext = os.path.splitext(path)[1].lower()

        try:
            if file_ext == ".json":
                self._scan_json_model(path, result)
            elif file_ext == ".ubj":
                self._scan_ubj_model(path, result)
            elif file_ext in [".bst", ".model", ""]:
                self._scan_binary_model(path, result)
            else:
                result.add_check(
                    name="File Format Recognition",
                    passed=False,
                    message=f"Unsupported XGBoost file format: {file_ext}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                )

        except Exception as e:
            result.add_check(
                name="Scan Execution",
                passed=False,
                message=f"Error during XGBoost model scan: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
                why="Scanning failures may indicate file corruption or malicious content",
            )
            self._mark_inconclusive_scan_result(result, "xgboost_scan_execution_failed")

        self._finish_scan_result(result)
        return result

    def _scan_json_model(self, path: str, result: ScanResult) -> None:
        """Scan XGBoost JSON model for security issues."""
        file_size = os.path.getsize(path)

        try:
            with open(path, encoding="utf-8") as f:
                model_data = json.load(f)

            result.add_check(
                name="JSON Parsing",
                passed=True,
                message="XGBoost JSON model parsed successfully",
                location=path,
                details={"file_size": file_size},
            )

            # Validate XGBoost JSON schema
            self._validate_xgboost_json_schema(model_data, result, path)

            # Check for suspicious content in JSON
            self._check_json_for_malicious_content(model_data, result, path)

        except json.JSONDecodeError as e:
            result.add_check(
                name="JSON Parsing",
                passed=False,
                message=f"Invalid JSON format in XGBoost model: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"json_error": str(e)},
                why="Malformed JSON may indicate file corruption or crafted exploit",
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["json_parse_failed"])
        except Exception as e:
            result.add_check(
                name="JSON Analysis",
                passed=False,
                message=f"Error analyzing XGBoost JSON model: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["json_analysis_failed"])

    def _scan_ubj_model(self, path: str, result: ScanResult) -> None:
        """Scan XGBoost UBJ (Universal Binary JSON) model for security issues."""
        if not _check_ubjson_available():
            self._record_missing_ubjson_dependency(path, result)
            return

        try:
            import ubjson

            with open(path, "rb") as f:
                model_data = ubjson.loadb(f.read())

            result.add_check(
                name="UBJ Decoding",
                passed=True,
                message="XGBoost UBJ model decoded successfully",
                location=path,
            )

            # Treat decoded UBJ as JSON structure for validation
            self._validate_xgboost_json_schema(model_data, result, path)
            self._check_json_for_malicious_content(model_data, result, path)

        except Exception as e:
            result.add_check(
                name="UBJ Analysis",
                passed=False,
                message=f"Error analyzing XGBoost UBJ model: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e)},
                why="UBJ decoding failures may indicate file corruption or malicious content",
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["ubj_analysis_failed"])

    def _scan_binary_model(self, path: str, result: ScanResult) -> None:
        """Scan XGBoost binary (.bst) model for security issues."""
        file_size = os.path.getsize(path)

        if file_size == 0:
            result.add_check(
                name="Binary File Size Check",
                passed=False,
                message="XGBoost binary model file is empty",
                severity=IssueSeverity.INFO,
                location=path,
                details={"file_size": 0},
                why="Empty model files are invalid and may indicate corruption or attack",
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_empty"])
            return

        try:
            # Check if it's actually a pickle file masquerading as .bst
            if self._is_pickle_file(path):
                claimed_format = os.path.splitext(path)[1].lower().lstrip(".") or "binary"
                result.add_check(
                    name="File Format Validation",
                    passed=False,
                    message=f"File appears to be a pickle file with .{claimed_format} extension",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"detected_format": "pickle", "claimed_format": claimed_format},
                    why=(
                        "File extension spoofing is a security evasion technique "
                        "used to bypass security scanners. This may indicate malicious intent."
                    ),
                )
                self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_pickle_spoof"])
                return

            # Modern XGBoost (2.0+) saves .bst files in UBJSON format by default.
            # Route to the UBJ scanner when the decoder is available; otherwise
            # fail closed while still attempting the optional XGBoost load.
            file_ext = os.path.splitext(path)[1].lower()
            is_ubjson = self._is_ubjson_file(path, require_strong_marker=file_ext not in {".bst", ".model"})
            if is_ubjson:
                if _check_ubjson_available():
                    self._scan_ubj_model(path, result)
                    return

                self._record_missing_ubjson_dependency(path, result)
                if self.enable_xgb_loading:
                    self._safe_xgboost_load(path, result)
                return

            # Basic binary structure validation
            self._validate_binary_structure(path, result)

            # Attempt safe XGBoost loading if enabled
            if self.enable_xgb_loading:
                self._safe_xgboost_load(path, result)
            else:
                result.add_check(
                    name="XGBoost Loading",
                    passed=True,
                    message="XGBoost loading disabled (safe mode)",
                    location=path,
                    details={"safe_mode": True},
                )

        except Exception as e:
            result.add_check(
                name="Binary Analysis",
                passed=False,
                message=f"Error analyzing XGBoost binary model: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_analysis_failed"])

    def _record_missing_ubjson_dependency(self, path: str, result: ScanResult) -> None:
        """Record that UBJSON structural scanning could not run."""
        result.add_check(
            name="UBJSON Library Check",
            passed=False,
            message=(
                "Cannot scan UBJ file: ubjson package is not installed. "
                "Install with 'pip install ubjson' to enable scanning."
            ),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "required_package": "ubjson",
                "install_command": "pip install ubjson",
                "detected_format": "ubjson",
            },
            why="UBJ file scanning requires the ubjson package to decode Universal Binary JSON format",
        )
        self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["ubj_dependency_missing"])

    def _validate_xgboost_json_schema(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate XGBoost JSON model schema and structure."""
        # Note: Basic structure validation (version, learner keys) is already done in can_handle()
        # This method performs additional validation on the structure

        # Validate version
        version = data.get("version")
        if not isinstance(version, list | tuple) or len(version) < 2:
            result.add_check(
                name="XGBoost Version Validation",
                passed=False,
                message=f"Invalid XGBoost version format: {version}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"version": version},
                why="Invalid version information may indicate file tampering",
            )

        # Validate learner structure
        learner = data.get("learner", {})
        if not isinstance(learner, dict):
            result.add_check(
                name="Learner Structure Validation",
                passed=False,
                message="XGBoost learner section is not a dictionary",
                severity=IssueSeverity.INFO,
                location=path,
                details={"learner_type": type(learner).__name__},
                why="Invalid learner structure may indicate malformed or malicious content",
            )
            return

        # Check learner parameters for sanity
        self._validate_learner_parameters(learner, result, path)

    def _validate_learner_parameters(self, learner: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate XGBoost learner parameters for suspicious values."""
        # Check for gradient booster
        gradient_booster = learner.get("gradient_booster")
        if gradient_booster and isinstance(gradient_booster, dict):
            model = gradient_booster.get("model")
            if model and isinstance(model, dict):
                # Check number of trees
                trees = model.get("trees", [])
                if isinstance(trees, list):
                    num_trees = len(trees)
                    if num_trees > self.max_num_trees:
                        result.add_check(
                            name="Tree Count Validation",
                            passed=False,
                            message=f"Large number of trees detected: {num_trees} (threshold: {self.max_num_trees})",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"num_trees": num_trees, "max_trees": self.max_num_trees},
                            why=(
                                "Large tree counts may impact performance but are often legitimate in production models"
                            ),
                        )

                    # Check individual tree structures
                    self._validate_tree_structures(trees[:10], result, path)  # Sample first 10 trees

        # Check learner model parameters
        params = learner.get("learner_model_param", {})
        if isinstance(params, dict):
            self._validate_model_parameters(params, result, path)

    def _validate_tree_structures(self, trees: list[dict[str, Any]], result: ScanResult, path: str) -> None:
        """Validate individual tree structures for anomalies."""
        for i, tree in enumerate(trees):
            left_children = tree.get("left_children")
            right_children = tree.get("right_children")
            if not isinstance(left_children, list) or not isinstance(right_children, list):
                continue
            if len(left_children) != len(right_children) or len(left_children) == 0:
                continue

            try:
                left = [int(child) for child in left_children]
                right = [int(child) for child in right_children]
            except (ValueError, TypeError):
                continue

            depth = self._compute_tree_depth(left, right)
            if depth > self.max_tree_depth:
                result.add_check(
                    name="Tree Depth Validation",
                    passed=False,
                    message=f"Tree {i} has deep structure: depth {depth} (threshold: {self.max_tree_depth})",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"tree_index": i, "depth": depth, "max_depth": self.max_tree_depth},
                    why="Deep trees may impact performance but can be legitimate in complex models",
                )

    @staticmethod
    def _compute_tree_depth(left_children: list[int], right_children: list[int]) -> int:
        """Compute tree depth from XGBoost child-index arrays."""
        max_depth = 0
        stack = [(0, 0)]
        visited: set[int] = set()

        while stack:
            node_idx, node_depth = stack.pop()
            if node_idx in visited:
                continue
            if node_idx < 0 or node_idx >= len(left_children):
                continue

            visited.add(node_idx)
            max_depth = max(max_depth, node_depth)

            left_idx = left_children[node_idx]
            right_idx = right_children[node_idx]
            if left_idx != -1:
                stack.append((left_idx, node_depth + 1))
            if right_idx != -1:
                stack.append((right_idx, node_depth + 1))

        return max_depth

    def _validate_model_parameters(self, params: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate XGBoost model parameters for suspicious values."""
        # Check for numeric parameters that could be maliciously large
        suspicious_params = {
            "num_features": (0, 1000000),  # (min, max) reasonable range
            "num_parallel_tree": (1, 1000),
            "num_roots": (1, 100),
        }

        for param_name, (min_val, max_val) in suspicious_params.items():
            if param_name in params:
                try:
                    value = int(params[param_name])
                    if value < min_val or value > max_val:
                        result.add_check(
                            name="Model Parameter Validation",
                            passed=False,
                            message=f"Unusual {param_name} value: {value} (typical range: {min_val}-{max_val})",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={param_name: value, "range": [min_val, max_val]},
                            why=(
                                f"Parameter {param_name} outside typical range. "
                                "Review if this is expected for your model."
                            ),
                        )
                except (ValueError, TypeError):
                    result.add_check(
                        name="Model Parameter Type Validation",
                        passed=False,
                        message=f"Invalid type for parameter {param_name}: {type(params[param_name])}",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={param_name: str(params[param_name])},
                    )

    def _sanitize_for_json(self, obj: Any, *, path: tuple[str, ...] = ()) -> Any:
        """Recursively sanitize object for JSON security scanning."""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, dict):
            return {
                k: self._sanitize_for_json(v, path=(*path, k))
                for k, v in obj.items()
                if (*path, k) not in _INERT_JSON_SECURITY_PATHS
            }
        elif isinstance(obj, list | tuple):
            return [self._sanitize_for_json(item, path=path) for item in obj]
        return obj

    def _check_json_for_malicious_content(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check XGBoost JSON data for potentially malicious content."""
        # Sanitize data to handle bytes objects before JSON serialization
        sanitized_data = self._sanitize_for_json(data)
        # Convert to string for pattern matching
        json_str = json.dumps(sanitized_data, separators=(",", ":"))

        # Check for suspicious patterns using precompiled regex
        for pattern, description in SUSPICIOUS_JSON_PATTERNS:
            if pattern.search(json_str):
                result.add_check(
                    name="JSON Content Analysis",
                    passed=False,
                    message=f"Suspicious pattern detected: {description}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"pattern": pattern.pattern, "description": description},
                    why="Suspicious patterns in model JSON may indicate embedded malicious code",
                )

    def _is_pickle_file(self, path: str) -> bool:
        """Check if file is actually a Python pickle file."""
        try:
            from modelaudit.utils.file.detection import detect_file_format

            return detect_file_format(path) == "pickle"
        except Exception:
            return False

    @staticmethod
    def _is_ubjson_file(path: str, *, require_strong_marker: bool = True) -> bool:
        """Check if a file is probably an XGBoost UBJSON model."""
        try:
            with open(path, "rb") as f:
                probe = f.read(XGBoostScanner._UBJSON_PROBE_READ_BYTES)
            is_ubjson_with_required_markers = (
                len(probe) >= 2
                and probe[0] == XGBoostScanner._UBJSON_OBJECT_START
                and probe[1] in XGBoostScanner._UBJSON_NEXT_VALID
                and all(marker in probe for marker in XGBoostScanner._UBJSON_REQUIRED_MARKERS)
            )
            if not is_ubjson_with_required_markers:
                return False
            return not require_strong_marker or any(marker in probe for marker in XGBoostScanner._UBJSON_STRONG_MARKERS)
        except OSError:
            return False

    def _validate_binary_structure(self, path: str, result: ScanResult) -> None:
        """Validate XGBoost binary file structure."""
        try:
            with open(path, "rb") as f:
                # Read first few bytes to check for basic structure
                header = f.read(64)

                if len(header) < self._BINARY_MIN_STRUCTURE_BYTES:
                    result.add_check(
                        name="Binary Structure Validation",
                        passed=False,
                        message="XGBoost binary file too small to contain valid model",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"header_length": len(header), "min_header_length": self._BINARY_MIN_STRUCTURE_BYTES},
                        why="Truncated files may indicate corruption or attack",
                    )
                    self._mark_inconclusive_scan_result(
                        result, self._INCONCLUSIVE_REASONS["binary_structure_too_small"]
                    )
                    return

                # Check for readable strings that typically appear in XGBoost models
                header_str = header.decode("utf-8", errors="ignore")
                expected_patterns = ["binf", "gbtree", "gblinear", "dart", "reg:", "binary:", "multi:"]

                has_expected_pattern = any(pattern in header_str.lower() for pattern in expected_patterns)

                if not has_expected_pattern:
                    # Check if it looks like binary data or something else
                    if all(b < 32 or b > 126 for b in header[:16]):
                        result.add_check(
                            name="Binary Content Validation",
                            passed=False,
                            message="File contains unusual binary patterns, may not be standard XGBoost format",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"header_hex": header[:16].hex()},
                            why=(
                                "File does not contain expected XGBoost text markers. "
                                "May be compressed, encrypted, or a non-standard format."
                            ),
                        )
                    else:
                        result.add_check(
                            name="Binary Structure Validation",
                            passed=False,
                            message="File does not contain expected XGBoost binary model markers",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={"expected_patterns": expected_patterns},
                            why="Missing XGBoost markers may indicate a truncated, corrupted, or mislabeled model file",
                        )
                    if not self.enable_xgb_loading:
                        self._mark_inconclusive_scan_result(
                            result, self._INCONCLUSIVE_REASONS["binary_structure_unrecognized"]
                        )
                else:
                    result.add_check(
                        name="XGBoost Binary Pattern Check",
                        passed=True,
                        message="Found expected XGBoost patterns in binary file",
                        location=path,
                        details={"patterns_found": [p for p in expected_patterns if p in header_str.lower()]},
                    )

        except Exception as e:
            result.add_check(
                name="Binary Structure Analysis",
                passed=False,
                message=f"Error validating binary structure: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_analysis_failed"])

    def _safe_xgboost_load(self, path: str, result: ScanResult) -> None:
        """Attempt to safely load XGBoost model with timeout and error handling."""
        if not _check_xgboost_available():
            result.add_check(
                name="XGBoost Library Check",
                passed=False,
                message="XGBoost library not available for model validation",
                severity=IssueSeverity.INFO,
                location=path,
                details={"required_package": "xgboost"},
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_load_dependency_missing"])
            return

        try:
            # Use subprocess for isolation
            timeout = min(self.timeout, 30)  # Max 30 seconds for model loading
            cmd = [
                sys.executable,
                "-c",
                """
import sys
import xgboost as xgb
try:
    booster = xgb.Booster()
    booster.load_model(sys.argv[1])
    sys.stdout.write("SUCCESS: Model loaded successfully\\n")
except Exception as e:
    sys.stderr.write(f"ERROR: {e}\\n")
    sys.exit(1)
""",
                path,
            ]

            cmd.insert(1, "-I")
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)

            with tempfile.TemporaryDirectory(prefix="modelaudit-xgb-") as safe_cwd:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=safe_cwd,
                    env=env,
                )

            if proc.returncode == 0 and "SUCCESS" in proc.stdout:
                result.add_check(
                    name="XGBoost Model Loading",
                    passed=True,
                    message="XGBoost model loaded successfully in isolated process",
                    location=path,
                    details={"load_test": "passed"},
                )
            else:
                error_msg = proc.stderr.strip() or proc.stdout.strip()
                result.add_check(
                    name="XGBoost Model Loading",
                    passed=False,
                    message=f"Failed to load XGBoost model: {error_msg}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"error": error_msg, "return_code": proc.returncode},
                    why=(
                        "Loading failures may indicate file corruption or version incompatibility. "
                        "This is a compatibility test run in an isolated subprocess for safety."
                    ),
                )
                self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_load_failed"])

        except subprocess.TimeoutExpired:
            result.add_check(
                name="XGBoost Model Loading",
                passed=False,
                message=f"XGBoost model loading timeout after {timeout} seconds",
                severity=IssueSeverity.INFO,
                location=path,
                details={"timeout": timeout},
                why="Loading timeout may indicate an extremely large model. The subprocess was safely terminated.",
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_load_timeout"])
        except Exception as e:
            result.add_check(
                name="XGBoost Model Loading",
                passed=False,
                message=f"Error during XGBoost model loading test: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"exception": str(e)},
            )
            self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["binary_load_exception"])

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract XGBoost model metadata."""
        metadata = super().extract_metadata(file_path)
        allow_deserialization = self.config.get("allow_metadata_deserialization", False)

        if not allow_deserialization:
            metadata["deserialization_skipped"] = True
            metadata["reason"] = "Deserialization disabled for metadata extraction"
            return metadata

        try:
            import xgboost as xgb

            # SECURITY: xgb.Booster().load_model() deserializes the model in-process.
            # Only reached when allow_metadata_deserialization is explicitly True.
            model = xgb.Booster()
            model.load_model(file_path)

            # Basic model info
            metadata.update(
                {
                    "xgboost_version": xgb.__version__,
                    "model_type": "XGBoost Booster",
                }
            )

            # Get model attributes
            try:
                # Number of boosting rounds
                num_boosted_rounds = model.num_boosted_rounds()
                metadata["num_boosted_rounds"] = num_boosted_rounds

                # Number of features
                num_features = model.num_features()
                metadata["num_features"] = num_features

                # Model configuration
                config = model.save_config()
                if config:
                    try:
                        config_dict = json.loads(config)

                        # Extract key parameters
                        learner_config = config_dict.get("learner", {})
                        if learner_config:
                            gradient_booster = learner_config.get("gradient_booster", {})
                            objective = learner_config.get("objective", {})

                            metadata.update(
                                {
                                    "booster_type": gradient_booster.get("name", "unknown"),
                                    "objective_type": objective.get("name", "unknown"),
                                }
                            )

                            # Tree-specific parameters
                            if gradient_booster.get("name") == "gbtree":
                                gbtree_params = gradient_booster.get("gbtree_train_param", {})
                                metadata.update(
                                    {
                                        "max_depth": gbtree_params.get("max_depth", "unknown"),
                                        "eta": gbtree_params.get("eta", "unknown"),
                                        "subsample": gbtree_params.get("subsample", "unknown"),
                                        "colsample_bytree": gbtree_params.get("colsample_bytree", "unknown"),
                                    }
                                )
                    except Exception as exc:
                        logger.debug("Unable to parse XGBoost model configuration: %s", exc)

                # Feature importance (if available)
                try:
                    importance = model.get_score(importance_type="gain")
                    if importance:
                        metadata.update(
                            {
                                "feature_importance_available": True,
                                "top_features": dict(sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]),
                            }
                        )
                except Exception:
                    metadata["feature_importance_available"] = False

            except Exception as e:
                metadata["model_info_error"] = str(e)

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
