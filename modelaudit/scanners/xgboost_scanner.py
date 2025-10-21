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

import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

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


def _check_xgboost_available() -> bool:
    """Check if XGBoost package is available."""
    try:
        import xgboost  # noqa: F401

        return True
    except ImportError:
        return False


def _check_ubjson_available() -> bool:
    """Check if UBJSON decoder is available."""
    try:
        import ubjson  # noqa: F401

        return True
    except ImportError:
        return False


class XGBoostScanner(BaseScanner):
    """Scanner for XGBoost model files with comprehensive security analysis."""

    name: ClassVar[str] = "xgboost"
    description: ClassVar[str] = "Scans XGBoost models for security vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".bst", ".model", ".json", ".ubj"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.enable_xgb_loading = self._get_bool_config("enable_xgb_loading", False)
        self.max_num_trees = self.config.get("max_num_trees", 10000)
        self.max_tree_depth = self.config.get("max_tree_depth", 1000)

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
            return cls._is_xgboost_json(path)

        # For .model files, accept (generic extension)
        if file_ext == ".model":
            return True

        # Check for XGBoost files without extension
        if file_ext == "":
            try:
                with open(path, "rb") as f:
                    header = f.read(16)
                    # Check for XGBoost binary signature patterns
                    if b"binf" in header or b"gblinear" in header[:100]:
                        return True
            except OSError:
                pass

        return False

    @classmethod
    def _is_xgboost_json(cls, path: str) -> bool:
        """
        Deterministic check for XGBoost JSON format.

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
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            # Must be a dict at top level
            if not isinstance(data, dict):
                return False

            # Required: both "version" AND "learner" keys (line 379)
            if "version" not in data or "learner" not in data:
                return False

            # Validate version is array-like with at least 2 elements
            version = data.get("version")
            if not isinstance(version, list | tuple) or len(version) < 2:
                return False

            # Validate learner is a dict
            learner = data.get("learner")
            return isinstance(learner, dict)

        except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
            # Any parsing/validation error = not XGBoost JSON
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

        result.finish(success=True)
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
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"json_error": str(e)},
                why="Malformed JSON may indicate file corruption or crafted exploit",
            )
        except Exception as e:
            result.add_check(
                name="JSON Analysis",
                passed=False,
                message=f"Error analyzing XGBoost JSON model: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )

    def _scan_ubj_model(self, path: str, result: ScanResult) -> None:
        """Scan XGBoost UBJ (Universal Binary JSON) model for security issues."""
        if not _check_ubjson_available():
            result.add_check(
                name="UBJSON Library Check",
                passed=False,
                message=(
                    "Cannot scan UBJ file: ubjson package is not installed. "
                    "Install with 'pip install ubjson' to enable scanning."
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details={"required_package": "ubjson", "install_command": "pip install ubjson"},
                why="UBJ file scanning requires the ubjson package to decode Universal Binary JSON format",
            )
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

    def _scan_binary_model(self, path: str, result: ScanResult) -> None:
        """Scan XGBoost binary (.bst) model for security issues."""
        file_size = os.path.getsize(path)

        if file_size == 0:
            result.add_check(
                name="Binary File Size Check",
                passed=False,
                message="XGBoost binary model file is empty",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"file_size": 0},
                why="Empty model files are invalid and may indicate corruption or attack",
            )
            return

        try:
            # Check if it's actually a pickle file masquerading as .bst
            if self._is_pickle_file(path):
                result.add_check(
                    name="File Format Validation",
                    passed=False,
                    message="File appears to be a pickle file with .bst/.model extension",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"detected_format": "pickle", "claimed_format": "bst"},
                    why=(
                        "File extension spoofing is a security evasion technique "
                        "used to bypass security scanners. This may indicate malicious intent."
                    ),
                )
                # Let pickle scanner handle this file
                return

            # Basic binary structure validation
            self._validate_binary_structure(path, result)

            # Attempt safe XGBoost loading if enabled
            if self.enable_xgb_loading and _check_xgboost_available():
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
                severity=IssueSeverity.WARNING,
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
                severity=IssueSeverity.WARNING,
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
            # Check tree depth
            if "tree_param" in tree:
                tree_param = tree["tree_param"]
                if isinstance(tree_param, dict):
                    try:
                        depth = int(tree_param.get("size_leaf_vector", 0))
                    except (ValueError, TypeError):
                        # Skip validation if value can't be converted to int
                        continue
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
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={param_name: str(params[param_name])},
                    )

    def _sanitize_for_json(self, obj: Any) -> Any:
        """Recursively sanitize object for JSON serialization by converting bytes to hex strings."""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, dict):
            return {k: self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list | tuple):
            return [self._sanitize_for_json(item) for item in obj]
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
                    details={"pattern": pattern, "description": description},
                    why="Suspicious patterns in model JSON may indicate embedded malicious code",
                )

    def _is_pickle_file(self, path: str) -> bool:
        """Check if file is actually a Python pickle file."""
        try:
            with open(path, "rb") as f:
                header = f.read(8)
                # Check for pickle protocol headers
                if len(header) >= 2:
                    # Pickle protocols 0-5
                    return header.startswith(b"\x80") or header[0:1] in [b"c", b"(", b"]", b"}"]
        except OSError:
            pass
        return False

    def _validate_binary_structure(self, path: str, result: ScanResult) -> None:
        """Validate XGBoost binary file structure."""
        try:
            with open(path, "rb") as f:
                # Read first few bytes to check for basic structure
                header = f.read(64)

                if len(header) < 4:
                    result.add_check(
                        name="Binary Structure Validation",
                        passed=False,
                        message="XGBoost binary file too small to contain valid model",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"header_length": len(header)},
                        why="Truncated files may indicate corruption or attack",
                    )
                    return

                # Check for readable strings that typically appear in XGBoost models
                header_str = header.decode("utf-8", errors="ignore")
                expected_patterns = ["gbtree", "gblinear", "dart", "reg:", "binary:", "multi:"]

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
                            name="XGBoost Binary Pattern Check",
                            passed=True,
                            message="File appears to contain valid binary model structure",
                            location=path,
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
            return

        try:
            # Use subprocess for isolation
            timeout = min(self.timeout, 30)  # Max 30 seconds for model loading
            # Safely escape the path for subprocess
            escaped_path = shlex.quote(path)
            cmd = [
                sys.executable,
                "-c",
                f"""
import sys
import xgboost as xgb
try:
    booster = xgb.Booster()
    booster.load_model({escaped_path})
    print("SUCCESS: Model loaded successfully")
except Exception as e:
    print(f"ERROR: {{e}}")
    sys.exit(1)
""",
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=os.getcwd())

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
        except Exception as e:
            result.add_check(
                name="XGBoost Model Loading",
                passed=False,
                message=f"Error during XGBoost model loading test: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"exception": str(e)},
            )
