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
import struct
import subprocess
import sys
import tempfile
from typing import Any, ClassVar, cast

from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from ..utils.file.detection import has_jax_json_checkpoint_structure, is_huggingface_tokenizer_json_file
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
_INERT_JSON_SECURITY_PATHS: frozenset[tuple[str | int, ...]] = frozenset({("learner", "feature_names")})
XGBOOST_DEFAULT_MAX_FILE_READ_SIZE = 256 * 1024 * 1024
XGBOOST_JSON_ROUTING_CHUNK_BYTES = 64 * 1024
XGBOOST_CONTENT_ROUTED_JSON_CONFIG_KEY = "_xgboost_content_routed_json"
XGBOOST_CONTENT_ROUTED_UBJSON_CONFIG_KEY = "_xgboost_content_routed_ubjson"
XGBOOST_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY = "_xgboost_skip_jax_json_overlap"
XGBOOST_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY = "_xgboost_skip_jinja_json_overlap"
_JSON_KEY_MAX_BYTES = 256
_JSON_WHITESPACE_BYTES = frozenset(b" \t\r\n")
_JSON_ROUTING_MAX_DEPTH = 64
_XGBOOST_OVERLAP_STRONG_LEARNER_KEYS = frozenset(
    {
        "gradient_booster",
        "learner_model_param",
        "gbtree_model_param",
        "tree_info",
        "gbtree",
        "gblinear",
        "dart",
    }
)


def configure_content_routed_json_scan(config: dict[str, Any], *, max_bytes: int) -> None:
    """Route renamed JSON through XGBoost while preserving the tighter discovery bound."""
    config[XGBOOST_CONTENT_ROUTED_JSON_CONFIG_KEY] = True
    limits = [max_bytes]
    for key in ("max_file_read_size", "max_file_size"):
        value = config.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            limits.append(value)
    config["max_file_read_size"] = min(limits)


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
                    if found_version and found_learner:
                        return True
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
                    if len(stack) >= _JSON_ROUTING_MAX_DEPTH:
                        return False
                    stack.append(ord("}"))
                elif byte == ord("["):
                    if len(stack) >= _JSON_ROUTING_MAX_DEPTH:
                        return False
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


def _json_file_has_probable_xgboost_overlap_markers(path: str, max_bytes: int) -> bool:
    """Find malformed XGBoost overlap markers without matching nested MXNet metadata."""
    found_version = False
    found_learner = False
    found_strong_learner_key = False
    bytes_read = 0
    started = False
    stack: list[int] = []
    in_string = False
    escaped = False
    collecting_key = False
    collecting_key_depth: int | None = None
    key_overflow = False
    raw_key = bytearray()
    expecting_key = False
    awaiting_colon = False
    pending_key: str | None = None
    pending_key_depth: int | None = None
    awaiting_value_for: tuple[str, int] | None = None
    learner_depth: int | None = None

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
                opened_learner_object = False
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
                            pending_key_depth = collecting_key_depth
                            awaiting_colon = True
                            collecting_key = False
                            collecting_key_depth = None
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
                    if byte != ord(":") or pending_key is None or pending_key_depth is None:
                        return False
                    awaiting_value_for = (pending_key, pending_key_depth)
                    pending_key = None
                    pending_key_depth = None
                    awaiting_colon = False
                    expecting_key = False
                    continue

                if awaiting_value_for is not None:
                    if byte in _JSON_WHITESPACE_BYTES:
                        continue
                    key, key_depth = awaiting_value_for
                    if key_depth == 1:
                        if key == "version":
                            found_version = True
                        elif key == "learner" and byte == ord("{"):
                            found_learner = True
                            learner_depth = len(stack) + 1
                            opened_learner_object = True
                    elif (
                        learner_depth is not None
                        and key_depth == learner_depth
                        and key in _XGBOOST_OVERLAP_STRONG_LEARNER_KEYS
                    ):
                        found_strong_learner_key = True
                    awaiting_value_for = None
                    if found_version and found_learner and found_strong_learner_key:
                        return True

                if byte == ord('"'):
                    if expecting_key and (
                        len(stack) == 1 or (learner_depth is not None and len(stack) == learner_depth)
                    ):
                        collecting_key = True
                        collecting_key_depth = len(stack)
                        raw_key = bytearray(b'"')
                    in_string = True
                    escaped = False
                    continue

                if byte == ord("{"):
                    if len(stack) >= _JSON_ROUTING_MAX_DEPTH:
                        return False
                    stack.append(ord("}"))
                    if opened_learner_object:
                        expecting_key = True
                elif byte == ord("["):
                    if len(stack) >= _JSON_ROUTING_MAX_DEPTH:
                        return False
                    stack.append(ord("]"))
                elif byte in {ord("}"), ord("]")}:
                    if not stack or stack[-1] != byte:
                        return False
                    if learner_depth is not None and len(stack) == learner_depth:
                        learner_depth = None
                    if len(stack) == 1:
                        return found_version and found_learner and found_strong_learner_key
                    stack.pop()
                elif byte == ord(",") and (
                    len(stack) == 1 or (learner_depth is not None and len(stack) == learner_depth)
                ):
                    expecting_key = True

    return found_version and found_learner and found_strong_learner_key


class XGBoostScanner(BaseScanner):
    """Scanner for XGBoost model files with comprehensive security analysis."""

    name: ClassVar[str] = "xgboost"
    description: ClassVar[str] = "Scans XGBoost models for security vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".bst", ".model", ".json", ".ubj", ""]
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
    _UBJSON_REQUIRED_KEYS: ClassVar[frozenset[bytes]] = frozenset({b"learner"})
    _UBJSON_STRONG_KEYS: ClassVar[frozenset[bytes]] = frozenset({b"gradient_booster", b"learner_model_param"})
    _UBJSON_INTEGER_WIDTHS: ClassVar[dict[int, tuple[int, bool]]] = {
        ord("i"): (1, True),
        ord("U"): (1, False),
        ord("I"): (2, True),
        ord("l"): (4, True),
        ord("L"): (8, True),
    }
    _UBJSON_FIXED_VALUE_WIDTHS: ClassVar[dict[int, int]] = {
        ord("Z"): 0,
        ord("N"): 0,
        ord("T"): 0,
        ord("F"): 0,
        ord("i"): 1,
        ord("U"): 1,
        ord("I"): 2,
        ord("l"): 4,
        ord("L"): 8,
        ord("d"): 4,
        ord("D"): 8,
        ord("C"): 1,
    }
    _UBJSON_MAX_PROBE_DEPTH: ClassVar[int] = 64
    _UBJSON_MAX_DECODED_ARRAY_ITEMS: ClassVar[int] = 1_000_000
    _BINARY_MIN_STRUCTURE_BYTES: ClassVar[int] = 32
    _LEGACY_HEADER_BYTES: ClassVar[int] = 136
    _LEGACY_HEADER_PATTERNS: ClassVar[tuple[str, ...]] = ("gbtree", "gblinear", "dart", "reg:", "binary:", "multi:")
    _BINARY_SIGNATURE: ClassVar[bytes] = b"binf"
    _MAX_LEGACY_HEADER_MAJOR_VERSION: ClassVar[int] = 3
    _MAX_LEGACY_HEADER_MINOR_VERSION: ClassVar[int] = 100
    _INCONCLUSIVE_REASONS: ClassVar[dict[str, str]] = {
        "json_parse_failed": "xgboost_json_parse_failed",
        "json_analysis_failed": "xgboost_json_analysis_failed",
        "json_structure_invalid": "xgboost_json_structure_invalid",
        "json_mxnet_overlap": "xgboost_mxnet_symbol_overlap",
        "ubj_dependency_missing": "xgboost_ubj_dependency_missing",
        "ubj_analysis_failed": "xgboost_ubj_analysis_failed",
        "ubj_array_limit_exceeded": "xgboost_ubj_array_limit_exceeded",
        "ubj_preflight_incomplete": "xgboost_ubj_preflight_incomplete",
        "binary_empty": "xgboost_binary_empty",
        "binary_structure_too_small": "xgboost_binary_structure_too_small",
        "binary_structure_unrecognized": "xgboost_binary_structure_unrecognized",
        "binary_analysis_failed": "xgboost_binary_analysis_failed",
        "binary_pickle_spoof": "xgboost_binary_pickle_spoof",
        "binary_load_dependency_missing": "xgboost_binary_load_dependency_missing",
        "binary_load_failed": "xgboost_binary_load_failed",
        "binary_load_timeout": "xgboost_binary_load_timeout",
        "binary_load_exception": "xgboost_binary_load_exception",
        "read_failed": "xgboost_read_failed",
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

    def _record_read_failure(self, path: str, result: ScanResult, exc: OSError) -> None:
        """Record unavailable XGBoost bytes as incomplete analysis, not a security finding."""
        result.add_check(
            name="XGBoost File Read",
            passed=False,
            message=f"Unable to read XGBoost model for analysis: {exc!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(exc),
                "exception_type": type(exc).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": self._INCONCLUSIVE_REASONS["read_failed"],
            },
            rule_code="S902",
        )
        self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["read_failed"])

    @classmethod
    def _find_legacy_header_patterns(cls, header_text: str) -> list[str]:
        lowered_header = header_text.lower()
        return [pattern for pattern in cls._LEGACY_HEADER_PATTERNS if pattern in lowered_header]

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
            if is_huggingface_tokenizer_json_file(path):
                return False
            return cls._is_xgboost_json(path) or cls._is_probable_xgboost_json_candidate(path)

        # For .model files, accept (generic extension)
        if file_ext == ".model":
            return True

        # Check for XGBoost files without extension
        if file_ext == "":
            return cls._is_ubjson_file(path)

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
    def _is_probable_mxnet_overlap_candidate(cls, path: str, *, max_bytes: int | None = None) -> bool:
        """Recognize probable XGBoost ownership using only top-level overlap fields."""
        try:
            return _json_file_has_probable_xgboost_overlap_markers(
                path,
                max_bytes or cls._JSON_PROBE_READ_BYTES,
            )
        except OSError:
            return False

    @classmethod
    def _is_probable_parsed_mxnet_overlap(cls, data: dict[str, Any]) -> bool:
        """Recognize a parsed malformed XGBoost model without matching MXNet metadata."""
        learner = data.get("learner")
        return (
            "version" in data
            and isinstance(learner, dict)
            and any(key in learner for key in _XGBOOST_OVERLAP_STRONG_LEARNER_KEYS)
        )

    @classmethod
    def _is_xgboost_json(cls, path: str, *, max_bytes: int | None = None) -> bool:
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
            return _json_file_has_xgboost_markers(path, max_bytes or cls.default_max_file_read_size)
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

        # Determine file format and dispatch to appropriate scanner
        file_ext = os.path.splitext(path)[1].lower()

        try:
            # Hashing reads the model content and is part of available scan coverage.
            self.add_file_integrity_check(path, result)

            if self.config.get(XGBOOST_CONTENT_ROUTED_JSON_CONFIG_KEY) is True:
                self._scan_json_model(path, result)
            elif self.config.get(XGBOOST_CONTENT_ROUTED_UBJSON_CONFIG_KEY) is True:
                self._scan_ubj_model(path, result)
            elif file_ext == ".json":
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

        except OSError as e:
            self._record_read_failure(path, result, e)
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
        from ..utils.file.detection import inspect_mxnet_symbol_root_keys

        file_size = os.path.getsize(path)
        params_overlap_composed = self._compose_content_routed_mxnet_params_security(path, result)

        try:
            with open(path, "rb") as f:
                duplicate_mxnet_root_keys = inspect_mxnet_symbol_root_keys(f)
            with open(path, encoding="utf-8-sig") as f:
                model_data = json.load(f)

            result.add_check(
                name="JSON Parsing",
                passed=True,
                message="XGBoost JSON model parsed successfully",
                location=path,
                details={"file_size": file_size},
            )

            self.scan_parsed_json_security(path, model_data, result)
            self._scan_filename_owned_json_overlap(path, result, model_data)
            self._record_duplicate_mxnet_root_keys(duplicate_mxnet_root_keys, result, path)
            self._record_mxnet_symbol_overlap(
                model_data,
                result,
                path,
                duplicate_mxnet_root_keys,
                params_overlap_composed=params_overlap_composed,
            )

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
            self._scan_filename_owned_json_overlap(path, result)
        except OSError as e:
            self._record_read_failure(path, result, e)
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
            self._scan_filename_owned_json_overlap(path, result)

    def _compose_content_routed_mxnet_params_security(self, path: str, result: ScanResult) -> bool:
        """Preserve raw params checks before JSON decoding can fail or shadow content."""
        if self.config.get(XGBOOST_CONTENT_ROUTED_JSON_CONFIG_KEY) is not True:
            return False
        if os.path.splitext(path)[1].lower() != ".params":
            return False

        from .mxnet_scanner import MXNetScanner

        scanner_selection = policy_from_config(self.config)
        if scanner_selection.allows("mxnet"):
            MXNetScanner(config=self.config).scan_params_file_security(path, result)
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "mxnet",
                scanner_selection,
                context="overlapping JSON analysis",
            )
        return True

    def scan_parsed_json_security(self, path: str, data: dict[str, Any], result: ScanResult) -> None:
        """Apply XGBoost JSON-specific security checks to an already parsed overlap."""
        self._validate_xgboost_json_schema(data, result, path)
        self._check_json_for_malicious_content(data, result, path)

    def _merge_filename_owned_result(self, result: ScanResult, owner_result: ScanResult) -> None:
        """Merge an owner scan without dropping existing incomplete-coverage reasons."""
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        result.merge(owner_result)
        for reason in existing_reasons:
            self._mark_inconclusive_scan_result(result, reason)

    def _scan_filename_owned_json_overlap(
        self,
        path: str,
        result: ScanResult,
        parsed_payload: object | None = None,
    ) -> None:
        """Preserve additional JSON analyses for XGBoost-shaped content."""
        from .jax_checkpoint_scanner import (
            JAX_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY,
            JAX_SKIP_XGBOOST_JSON_OVERLAP_CONFIG_KEY,
            JaxCheckpointScanner,
        )
        from .jinja2_template_scanner import JINJA_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY, Jinja2TemplateScanner
        from .manifest_scanner import ManifestScanner

        scanner_selection = policy_from_config(self.config)
        if (
            self.config.get(XGBOOST_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY) is not True
            and parsed_payload is not None
            and has_jax_json_checkpoint_structure(parsed_payload)
        ):
            if scanner_selection.allows("jax_checkpoint"):
                jax_config = dict(self.config)
                jax_config[JAX_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY] = True
                jax_config[JAX_SKIP_XGBOOST_JSON_OVERLAP_CONFIG_KEY] = True
                self._merge_filename_owned_result(result, JaxCheckpointScanner(config=jax_config).scan(path))
            elif scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "jax_checkpoint",
                    scanner_selection,
                    context="overlapping JAX JSON analysis",
                )
        manifest_covered_templates = False
        if ManifestScanner.can_handle(path):
            if scanner_selection.allows("manifest"):
                manifest_result = ManifestScanner(config=self.config).scan(path)
                self._merge_filename_owned_result(result, manifest_result)
                manifest_covered_templates = manifest_result.metadata.get("analysis_incomplete") is not True
            elif scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "manifest",
                    scanner_selection,
                    context="overlapping manifest JSON analysis",
                )
        if (
            self.config.get(XGBOOST_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY) is not True
            and not manifest_covered_templates
            and Jinja2TemplateScanner.can_handle(path)
        ):
            if scanner_selection.allows("jinja2_template"):
                jinja_config = dict(self.config)
                jinja_config[JINJA_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY] = True
                self._merge_filename_owned_result(result, Jinja2TemplateScanner(config=jinja_config).scan(path))
            elif scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "jinja2_template",
                    scanner_selection,
                    context="overlapping Jinja JSON analysis",
                )

    def _record_duplicate_mxnet_root_keys(self, duplicate_keys: set[str], result: ScanResult, path: str) -> None:
        """Fail closed when JSON key shadowing can discard MXNet graph content."""
        if not duplicate_keys:
            return
        reason = self._INCONCLUSIVE_REASONS["json_mxnet_overlap"]
        result.add_check(
            name="XGBoost / MXNet JSON Routing",
            passed=False,
            message="JSON model contains duplicate MXNet graph keys; shadowed graph content cannot be safely analyzed",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
                "duplicate_root_keys": sorted(duplicate_keys),
            },
        )
        self._mark_inconclusive_scan_result(result, reason)

    def _record_mxnet_symbol_overlap(
        self,
        data: object,
        result: ScanResult,
        path: str,
        duplicate_root_keys: set[str] | None = None,
        *,
        params_overlap_composed: bool = False,
    ) -> None:
        """Run MXNet security checks and fail closed when JSON ownership overlaps."""
        from ..utils.file.detection import has_mxnet_symbol_graph_structure
        from .mxnet_scanner import MXNetScanner

        is_mxnet_symbol = has_mxnet_symbol_graph_structure(data)
        needs_params_byte_analysis = os.path.splitext(path)[1].lower() == ".params"
        if not is_mxnet_symbol and not (duplicate_root_keys and needs_params_byte_analysis):
            return

        scanner_selection = policy_from_config(self.config)
        if scanner_selection.allows("mxnet"):
            mxnet_scanner = MXNetScanner(config=self.config)
            if needs_params_byte_analysis and not params_overlap_composed:
                mxnet_scanner.scan_params_file_security(path, result)
            if is_mxnet_symbol:
                mxnet_scanner.scan_parsed_symbol_security(path, cast(dict[str, Any], data), result)
            analysis_message = "both static analyses ran but format ownership is ambiguous"
        else:
            if not params_overlap_composed:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "mxnet",
                    scanner_selection,
                    context="overlapping JSON analysis",
                )
            return
        if not is_mxnet_symbol:
            return
        reason = self._INCONCLUSIVE_REASONS["json_mxnet_overlap"]
        result.add_check(
            name="XGBoost / MXNet JSON Routing",
            passed=False,
            message=(f"JSON model matches both XGBoost and MXNet contracts; {analysis_message}"),
            severity=IssueSeverity.INFO,
            location=path,
            details={"analysis_incomplete": True, "scan_outcome_reason": reason},
        )
        self._mark_inconclusive_scan_result(result, reason)

    def _scan_ubj_model(self, path: str, result: ScanResult) -> None:
        """Scan XGBoost UBJ (Universal Binary JSON) model for security issues."""
        if not _check_ubjson_available():
            self._record_missing_ubjson_dependency(path, result)
            return

        try:
            encoded_model = self._read_ubjson_for_safe_decode(path, result)
            if encoded_model is None:
                return

            import ubjson

            model_data = ubjson.loadb(encoded_model)

            result.add_check(
                name="UBJ Decoding",
                passed=True,
                message="XGBoost UBJ model decoded successfully",
                location=path,
            )

            if not os.path.splitext(path)[1] and not self._decoded_extensionless_ubjson_confirms_xgboost(model_data):
                result.add_check(
                    name="UBJ Content Routing",
                    passed=True,
                    message="Extensionless UBJSON content does not confirm an XGBoost model",
                    location=path,
                    details={"detected_format": "ubjson", "xgboost_structure_confirmed": False},
                )
                return

            # Treat decoded UBJ as JSON structure for validation
            self._validate_xgboost_json_schema(model_data, result, path)
            self._check_json_for_malicious_content(model_data, result, path)

        except OSError as e:
            self._record_read_failure(path, result, e)
        except Exception as e:
            result.add_check(
                name="UBJ Analysis",
                passed=False,
                message=f"Error analyzing XGBoost UBJ model: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._INCONCLUSIVE_REASONS["ubj_analysis_failed"],
                },
                why="UBJ decoding did not complete, so content-based security checks could not be completed",
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
                    if self._read_ubjson_for_safe_decode(path, result) is None:
                        return
                    self._safe_xgboost_load(path, result)
                return

            # Basic binary structure validation
            self._validate_binary_structure(path, result)
            if self._INCONCLUSIVE_REASONS["read_failed"] in result.metadata.get("scan_outcome_reasons", []):
                return

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

        except OSError as e:
            self._record_read_failure(path, result, e)
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

    def _read_ubjson_for_safe_decode(self, path: str, result: ScanResult) -> bytes | None:
        """Read UBJSON only when declared arrays stay within a decode budget."""
        with open(path, "rb") as f:
            encoded_model = f.read()

        _, _, exceeds_array_limit, _, parse_complete = self._ubjson_object_keys_in_probe(encoded_model)
        if not exceeds_array_limit and parse_complete:
            return encoded_model

        reason = (
            self._INCONCLUSIVE_REASONS["ubj_array_limit_exceeded"]
            if exceeds_array_limit
            else self._INCONCLUSIVE_REASONS["ubj_preflight_incomplete"]
        )
        message = (
            "Cannot safely decode XGBoost UBJ model: decoded arrays exceed "
            f"{self._UBJSON_MAX_DECODED_ARRAY_ITEMS:,} materialized items"
            if exceeds_array_limit
            else "Cannot safely decode XGBoost UBJ model: bounded resource preflight could not complete"
        )
        result.add_check(
            name="UBJ Decode Resource Limit",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "max_decoded_array_items": self._UBJSON_MAX_DECODED_ARRAY_ITEMS,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
            why="Decoding attacker-controlled counted arrays can exhaust scanner memory",
        )
        self._mark_inconclusive_scan_result(result, reason)
        return None

    def _validate_xgboost_json_schema(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate XGBoost JSON model schema and structure."""
        # Note: Basic structure validation (version, learner keys) is already done in can_handle()
        # This method performs additional validation on the structure

        # Validate version
        version = data.get("version")
        if not isinstance(version, list | tuple) or len(version) < 2:
            reason = self._INCONCLUSIVE_REASONS["json_structure_invalid"]
            result.add_check(
                name="XGBoost Version Validation",
                passed=False,
                message=f"Invalid XGBoost version format: {version}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "version": version,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                },
                why="Invalid version information may indicate file tampering",
            )
            self._mark_inconclusive_scan_result(result, reason)

        # Validate learner structure
        learner = data.get("learner", {})
        if not isinstance(learner, dict):
            reason = self._INCONCLUSIVE_REASONS["json_structure_invalid"]
            result.add_check(
                name="Learner Structure Validation",
                passed=False,
                message="XGBoost learner section is not a dictionary",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "learner_type": type(learner).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                },
                why="Invalid learner structure may indicate malformed or malicious content",
            )
            self._mark_inconclusive_scan_result(result, reason)
            return

        # Check learner parameters for sanity
        self._validate_learner_parameters(learner, result, path)

    def _validate_learner_parameters(self, learner: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate XGBoost learner parameters for suspicious values."""
        # Check for gradient booster
        gradient_booster = learner.get("gradient_booster")
        if "gradient_booster" in learner and not isinstance(gradient_booster, dict):
            self._record_invalid_json_structure(
                result,
                path,
                field="learner.gradient_booster",
                expected_type="dict",
                value=gradient_booster,
            )
        elif isinstance(gradient_booster, dict):
            model = gradient_booster.get("model")
            if "model" in gradient_booster and not isinstance(model, dict):
                self._record_invalid_json_structure(
                    result,
                    path,
                    field="learner.gradient_booster.model",
                    expected_type="dict",
                    value=model,
                )
            elif isinstance(model, dict):
                # Check number of trees
                trees = model.get("trees", [])
                if not isinstance(trees, list):
                    self._record_invalid_json_structure(
                        result,
                        path,
                        field="learner.gradient_booster.model.trees",
                        expected_type="list",
                        value=trees,
                    )
                else:
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

                    self._validate_tree_structures(trees, result, path)

        # Check learner model parameters
        params = learner.get("learner_model_param", {})
        if isinstance(params, dict):
            self._validate_model_parameters(params, result, path)

    def _validate_tree_structures(self, trees: list[Any], result: ScanResult, path: str) -> None:
        """Validate individual tree structures for anomalies."""
        invalid_tree_count = 0
        invalid_tree_examples: list[dict[str, str]] = []
        over_depth_trees: list[tuple[int, int]] = []
        for i, tree in enumerate(trees):
            if not isinstance(tree, dict):
                invalid_tree_count = self._collect_invalid_tree_structure(
                    invalid_tree_examples,
                    invalid_tree_count,
                    field=f"learner.gradient_booster.model.trees[{i}]",
                    expected_type="dict",
                    value=tree,
                )
                continue

            left_children = tree.get("left_children")
            right_children = tree.get("right_children")
            if not isinstance(left_children, list) or not isinstance(right_children, list):
                invalid_tree_count = self._collect_invalid_tree_structure(
                    invalid_tree_examples,
                    invalid_tree_count,
                    field=f"learner.gradient_booster.model.trees[{i}].children",
                    expected_type="list",
                    value={"left_children": left_children, "right_children": right_children},
                )
                continue
            if len(left_children) != len(right_children) or len(left_children) == 0:
                invalid_tree_count = self._collect_invalid_tree_structure(
                    invalid_tree_examples,
                    invalid_tree_count,
                    field=f"learner.gradient_booster.model.trees[{i}].children",
                    expected_type="same-length non-empty lists",
                    value={"left_children": left_children, "right_children": right_children},
                )
                continue

            if not self._child_indices_are_valid(left_children, right_children):
                invalid_tree_count = self._collect_invalid_tree_structure(
                    invalid_tree_examples,
                    invalid_tree_count,
                    field=f"learner.gradient_booster.model.trees[{i}].children",
                    expected_type="in-range integer child indices",
                    value={"left_children": left_children, "right_children": right_children},
                )
                continue

            depth = self._compute_tree_depth(cast(list[int], left_children), cast(list[int], right_children))
            if depth > self.max_tree_depth:
                over_depth_trees.append((i, depth))

        if invalid_tree_count:
            self._record_invalid_tree_structures(result, path, invalid_tree_count, invalid_tree_examples)

        if not over_depth_trees:
            return

        first_tree_index, first_depth = over_depth_trees[0]
        max_observed_depth = max(depth for _, depth in over_depth_trees)
        example_trees = [{"tree_index": tree_index, "depth": depth} for tree_index, depth in over_depth_trees[:10]]
        result.add_check(
            name="Tree Depth Validation",
            passed=False,
            message=(
                f"{len(over_depth_trees)} tree(s) have deep structure; "
                f"first is tree {first_tree_index} at depth {first_depth} "
                f"(threshold: {self.max_tree_depth})"
            ),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "tree_index": first_tree_index,
                "depth": first_depth,
                "max_depth": self.max_tree_depth,
                "max_observed_depth": max_observed_depth,
                "tree_count": len(over_depth_trees),
                "examples": example_trees,
                "aggregated": True,
            },
            why="Deep trees may impact performance but can be legitimate in complex models",
        )

    @staticmethod
    def _child_indices_are_valid(left_children: list[Any], right_children: list[Any]) -> bool:
        child_count = len(left_children)
        for children in (left_children, right_children):
            for child in children:
                if type(child) is not int:
                    return False
                if child < -1 or child >= child_count:
                    return False
        return True

    @staticmethod
    def _invalid_json_structure_detail(*, field: str, expected_type: str, value: Any) -> dict[str, str]:
        return {
            "field": field,
            "expected_type": expected_type,
            "actual_type": type(value).__name__,
        }

    def _collect_invalid_tree_structure(
        self,
        examples: list[dict[str, str]],
        invalid_count: int,
        *,
        field: str,
        expected_type: str,
        value: Any,
    ) -> int:
        if len(examples) < 10:
            examples.append(self._invalid_json_structure_detail(field=field, expected_type=expected_type, value=value))
        return invalid_count + 1

    def _record_invalid_tree_structures(
        self,
        result: ScanResult,
        path: str,
        invalid_count: int,
        examples: list[dict[str, str]],
    ) -> None:
        first_invalid = examples[0]
        result.add_check(
            name="XGBoost JSON Structure Validation",
            passed=False,
            message=(
                f"Invalid XGBoost JSON structure at {first_invalid['field']}"
                if invalid_count == 1
                else (f"{invalid_count} invalid XGBoost tree structure(s); first at {first_invalid['field']}")
            ),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                **first_invalid,
                "invalid_count": invalid_count,
                "examples": examples,
                "aggregated": invalid_count > 1,
            },
            why="Malformed XGBoost JSON structure prevents complete model validation",
        )
        self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["json_structure_invalid"])

    def _record_invalid_json_structure(
        self,
        result: ScanResult,
        path: str,
        *,
        field: str,
        expected_type: str,
        value: Any,
    ) -> None:
        detail = self._invalid_json_structure_detail(
            field=field,
            expected_type=expected_type,
            value=value,
        )
        result.add_check(
            name="XGBoost JSON Structure Validation",
            passed=False,
            message=f"Invalid XGBoost JSON structure at {field}",
            severity=IssueSeverity.INFO,
            location=path,
            details=detail,
            why="Malformed XGBoost JSON structure prevents complete model validation",
        )
        self._mark_inconclusive_scan_result(result, self._INCONCLUSIVE_REASONS["json_structure_invalid"])

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

    def _sanitize_for_json(self, obj: Any, *, path: tuple[str | int, ...] = ()) -> Any:
        """Recursively sanitize object for JSON security scanning."""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, dict):
            return {
                k: self._sanitize_for_json(v, path=(*path, k))
                for k, v in obj.items()
                if not self._is_inert_json_security_value((*path, k), v)
            }
        elif isinstance(obj, list | tuple):
            return [self._sanitize_for_json(item, path=(*path, index)) for index, item in enumerate(obj)]
        return obj

    @staticmethod
    def _is_inert_json_security_value(path: tuple[str | int, ...], value: Any) -> bool:
        """Return True only for canonical inert metadata shapes."""
        return (
            path in _INERT_JSON_SECURITY_PATHS
            and isinstance(value, list)
            and all(isinstance(item, str) for item in value)
        )

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

    @classmethod
    def _read_ubjson_length(cls, probe: bytes, offset: int) -> tuple[int, int] | None:
        """Read a bounded UBJSON integer length and return the next offset."""
        if offset >= len(probe):
            return None
        width_spec = cls._UBJSON_INTEGER_WIDTHS.get(probe[offset])
        if width_spec is None:
            return None
        width, signed = width_spec
        end = offset + 1 + width
        if end > len(probe):
            return None
        length = int.from_bytes(probe[offset + 1 : end], byteorder="big", signed=signed)
        if length < 0:
            return None
        return length, end

    @classmethod
    def _decoded_extensionless_ubjson_confirms_xgboost(cls, data: Any) -> bool:
        """Confirm content-routed UBJSON has direct XGBoost learner structure."""
        if not isinstance(data, dict):
            return False
        learner = data.get("learner")
        if not isinstance(learner, dict):
            return False
        return any(key.decode("ascii") in learner for key in cls._UBJSON_STRONG_KEYS)

    @classmethod
    def _ubjson_object_keys_in_probe(cls, probe: bytes) -> tuple[set[bytes], set[bytes], bool, bool, bool]:
        """Collect root/learner UBJSON keys and detect unsafe or incomplete candidates."""
        learner_keys: set[bytes] = set()
        top_level_keys: set[bytes] = set()
        decoded_array_items = 0
        exceeds_array_limit = False
        root_learner_incomplete = False

        def read_sized_payload(offset: int) -> int | None:
            length_result = cls._read_ubjson_length(probe, offset)
            if length_result is None:
                return None
            length, payload_offset = length_result
            end = payload_offset + length
            return end if end <= len(probe) else None

        def read_container_header(offset: int) -> tuple[int | None, int | None, int] | None:
            typed_marker: int | None = None
            count: int | None = None
            while offset < len(probe):
                if probe[offset] == ord("N"):
                    offset += 1
                    continue
                if probe[offset] not in {ord("$"), ord("#")}:
                    break
                marker = probe[offset]
                offset += 1
                if marker == ord("$"):
                    if offset >= len(probe):
                        return None
                    typed_marker = probe[offset]
                    offset += 1
                else:
                    length_result = cls._read_ubjson_length(probe, offset)
                    if length_result is None:
                        return None
                    count, offset = length_result
            return typed_marker, count, offset

        def parse_value(
            offset: int,
            depth: int,
            typed_marker: int | None = None,
            *,
            direct_learner_object: bool = False,
        ) -> int | None:
            nonlocal decoded_array_items, exceeds_array_limit, root_learner_incomplete
            if depth > cls._UBJSON_MAX_PROBE_DEPTH:
                return None
            marker = typed_marker
            if marker is None:
                while offset < len(probe) and probe[offset] == ord("N"):
                    offset += 1
                if offset >= len(probe):
                    return None
                marker = probe[offset]
                offset += 1

            fixed_width = cls._UBJSON_FIXED_VALUE_WIDTHS.get(marker)
            if fixed_width is not None:
                end = offset + fixed_width
                return end if end <= len(probe) else None
            if marker in {ord("S"), ord("H")}:
                return read_sized_payload(offset)
            if marker == ord("["):
                header = read_container_header(offset)
                if header is None:
                    return None
                value_marker, count, offset = header
                if count is not None:
                    if count > cls._UBJSON_MAX_DECODED_ARRAY_ITEMS - decoded_array_items:
                        exceeds_array_limit = True
                    else:
                        decoded_array_items += count
                if value_marker is not None and cls._UBJSON_FIXED_VALUE_WIDTHS.get(value_marker) == 0:
                    if count is None:
                        return offset + 1 if offset < len(probe) and probe[offset] == ord("]") else None
                    return offset + 1 if offset < len(probe) and probe[offset] == ord("]") else offset
                if exceeds_array_limit:
                    return None
                if value_marker is not None:
                    fixed_width = cls._UBJSON_FIXED_VALUE_WIDTHS.get(value_marker)
                    if fixed_width is not None and count is not None:
                        end = offset + fixed_width * count
                        return end if end <= len(probe) else None
                item_count = 0
                while count is None or item_count < count:
                    while value_marker is None and offset < len(probe) and probe[offset] == ord("N"):
                        offset += 1
                    if count is None and offset < len(probe) and probe[offset] == ord("]"):
                        return offset + 1
                    if count is None:
                        if decoded_array_items >= cls._UBJSON_MAX_DECODED_ARRAY_ITEMS:
                            exceeds_array_limit = True
                            return None
                        decoded_array_items += 1
                    next_offset = parse_value(offset, depth + 1, value_marker)
                    if next_offset is None or next_offset <= offset:
                        return None
                    offset = next_offset
                    item_count += 1
                return offset + 1 if offset < len(probe) and probe[offset] == ord("]") else offset
            if marker == ord("{"):
                header = read_container_header(offset)
                if header is None:
                    return None
                value_marker, count, offset = header
                item_count = 0
                while count is None or item_count < count:
                    while offset < len(probe) and probe[offset] == ord("N"):
                        offset += 1
                    if count is None and offset < len(probe) and probe[offset] == ord("}"):
                        return offset + 1
                    length_result = cls._read_ubjson_length(probe, offset)
                    if length_result is None:
                        return None
                    key_length, key_offset = length_result
                    key_end = key_offset + key_length
                    if key_end > len(probe):
                        return None
                    key = probe[key_offset:key_end]
                    if depth == 0:
                        top_level_keys.add(key)
                    if direct_learner_object:
                        learner_keys.add(key)
                    value_offset = key_end
                    if value_marker is None:
                        while value_offset < len(probe) and probe[value_offset] == ord("N"):
                            value_offset += 1
                    is_root_learner_object = (
                        depth == 0
                        and key == b"learner"
                        and (
                            value_marker == ord("{")
                            or (value_marker is None and value_offset < len(probe) and probe[value_offset] == ord("{"))
                        )
                    )
                    next_offset = parse_value(
                        key_end,
                        depth + 1,
                        value_marker,
                        direct_learner_object=is_root_learner_object,
                    )
                    if next_offset is None:
                        if is_root_learner_object:
                            root_learner_incomplete = True
                        return None
                    offset = next_offset
                    item_count += 1
                return offset + 1 if offset < len(probe) and probe[offset] == ord("}") else offset
            return None

        parse_complete = bool(probe) and parse_value(0, 0) is not None
        return top_level_keys, learner_keys, exceeds_array_limit, root_learner_incomplete, parse_complete

    @classmethod
    def _classify_extensionless_ubjson_probe(cls, probe: bytes) -> str | None:
        """Classify a bounded extensionless UBJSON prefix without overclaiming."""
        top_level_keys, learner_keys, _, _, parse_complete = cls._ubjson_object_keys_in_probe(probe)
        if top_level_keys >= cls._UBJSON_REQUIRED_KEYS and cls._UBJSON_STRONG_KEYS & learner_keys:
            return "xgboost"

        if cls._is_incomplete_ubjson_object_probe(
            probe,
            has_parsed_key=bool(top_level_keys),
            parse_complete=parse_complete,
        ):
            return "inconclusive"
        return None

    @classmethod
    def _is_incomplete_ubjson_object_probe(
        cls,
        probe: bytes,
        *,
        has_parsed_key: bool,
        parse_complete: bool,
    ) -> bool:
        """Recognize a bounded but plausible UBJSON object prefix."""
        if parse_complete:
            return False
        root_offset = 0
        while root_offset < len(probe) and probe[root_offset] == ord("N"):
            root_offset += 1
        return (
            root_offset < len(probe)
            and probe[root_offset] == cls._UBJSON_OBJECT_START
            and cls._has_ubjson_object_key_prefix(probe, root_offset + 1, has_parsed_key)
        )

    @classmethod
    def _has_ubjson_object_key_prefix(cls, probe: bytes, offset: int, has_parsed_key: bool) -> bool:
        """Distinguish incomplete UBJSON object roots from ordinary JSON objects."""
        if has_parsed_key:
            return True
        saw_noop = False
        while offset < len(probe):
            if probe[offset] == ord("N"):
                saw_noop = True
                offset += 1
                continue
            if probe[offset] not in {ord("$"), ord("#")}:
                break
            marker = probe[offset]
            offset += 1
            if marker == ord("$"):
                if offset >= len(probe):
                    return True
                offset += 1
            else:
                length_result = cls._read_ubjson_length(probe, offset)
                if length_result is None:
                    return True
                _, offset = length_result
        if offset >= len(probe):
            return saw_noop
        return probe[offset] in cls._UBJSON_INTEGER_WIDTHS

    @classmethod
    def _is_ubjson_probe(cls, probe: bytes, *, require_strong_marker: bool = True) -> bool:
        """Check whether a bounded UBJSON prefix has XGBoost object structure."""
        top_level_keys, learner_keys, _, _, _ = cls._ubjson_object_keys_in_probe(probe)
        if not top_level_keys >= cls._UBJSON_REQUIRED_KEYS:
            return False
        return not require_strong_marker or bool(cls._UBJSON_STRONG_KEYS & learner_keys)

    @classmethod
    def _is_ubjson_file(cls, path: str, *, require_strong_marker: bool = True) -> bool:
        """Check if a file is probably an XGBoost UBJSON model."""
        try:
            with open(path, "rb") as f:
                probe = f.read(cls._UBJSON_PROBE_READ_BYTES)
            top_level_keys, learner_keys, exceeds_array_limit, _, parse_complete = cls._ubjson_object_keys_in_probe(
                probe
            )
            if top_level_keys >= cls._UBJSON_REQUIRED_KEYS and (
                not require_strong_marker or bool(cls._UBJSON_STRONG_KEYS & learner_keys)
            ):
                return True
            return not require_strong_marker and (
                exceeds_array_limit
                or (
                    len(probe) == cls._UBJSON_PROBE_READ_BYTES
                    and cls._is_incomplete_ubjson_object_probe(
                        probe,
                        has_parsed_key=bool(top_level_keys),
                        parse_complete=parse_complete,
                    )
                )
            )
        except OSError:
            return False

    @classmethod
    def _looks_like_headerless_legacy_binary(cls, header: bytes) -> bool:
        """Recognize the older legacy payload header written before `binf` existed."""
        if len(header) < cls._LEGACY_HEADER_BYTES:
            return False

        try:
            (
                base_score,
                num_feature,
                num_class,
                contain_extra_attrs,
                contain_eval_metrics,
                major_version,
                minor_version,
            ) = struct.unpack("<fIiiiII", header[:28])
        except struct.error:
            return False

        reserved = header[28 : cls._LEGACY_HEADER_BYTES]
        return (
            0.0 <= base_score <= 1.0
            and 0 <= num_feature <= 1_000_000
            and 0 <= num_class <= 100_000
            and contain_extra_attrs in {0, 1}
            and contain_eval_metrics in {0, 1}
            and 0 <= major_version <= cls._MAX_LEGACY_HEADER_MAJOR_VERSION
            and 0 <= minor_version <= cls._MAX_LEGACY_HEADER_MINOR_VERSION
            and not any(reserved)
        )

    def _validate_binary_structure(self, path: str, result: ScanResult) -> None:
        """Validate XGBoost binary file structure."""
        try:
            with open(path, "rb") as f:
                # Read first few bytes to check for basic structure
                header = f.read(self._LEGACY_HEADER_BYTES)

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

                # The legacy binary format starts with `binf`; marker strings
                # alone can be planted in arbitrary text payloads.
                header_str = header.decode("utf-8", errors="ignore")
                patterns_found = self._find_legacy_header_patterns(header_str)
                has_binary_signature = header.startswith(self._BINARY_SIGNATURE)
                has_headerless_legacy_structure = self._looks_like_headerless_legacy_binary(header)

                if not has_binary_signature and not has_headerless_legacy_structure:
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
                            message="File does not start with the expected XGBoost binary signature",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                "expected_signature": self._BINARY_SIGNATURE.decode("ascii"),
                                "text_markers_found": patterns_found,
                            },
                            why=(
                                "Missing the XGBoost binary signature may indicate a truncated, corrupted, "
                                "or mislabeled model file"
                            ),
                        )
                    if not self.enable_xgb_loading:
                        self._mark_inconclusive_scan_result(
                            result, self._INCONCLUSIVE_REASONS["binary_structure_unrecognized"]
                        )
                else:
                    binary_format = "binf" if has_binary_signature else "headerless_legacy"
                    result.add_check(
                        name="XGBoost Binary Pattern Check",
                        passed=True,
                        message=(
                            "Found expected XGBoost binary signature"
                            if has_binary_signature
                            else "Found plausible headerless XGBoost legacy binary structure"
                        ),
                        location=path,
                        details={
                            "binary_format": binary_format,
                            "patterns_found": (
                                [self._BINARY_SIGNATURE.decode("ascii"), *patterns_found]
                                if has_binary_signature
                                else patterns_found
                            ),
                        },
                    )

        except OSError as e:
            self._record_read_failure(path, result, e)
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
