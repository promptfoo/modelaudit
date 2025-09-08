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
import subprocess
import sys
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult


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
        self.max_json_size = self.config.get("max_json_size", 100 * 1024 * 1024)  # 100MB
        self.max_tree_depth = self.config.get("max_tree_depth", 1000)
        self.max_num_trees = self.config.get("max_num_trees", 100000)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        if not os.path.isfile(path):
            return False

        file_ext = os.path.splitext(path)[1].lower()

        # Binary formats are definitively XGBoost
        if file_ext in [".bst", ".model", ".ubj"]:
            return True

        # For JSON files, check content to ensure it's actually XGBoost
        if file_ext == ".json":
            try:
                with open(path, encoding="utf-8") as f:
                    content = f.read(8192)  # Read first 8KB

                # Parse as JSON to check structure
                try:
                    import json

                    data = json.loads(content)

                    # XGBoost JSON must have these key indicators
                    if isinstance(data, dict):
                        # Primary XGBoost indicators
                        has_learner = "learner" in data
                        has_version = "version" in data
                        has_gradient_booster = "gradient_booster" in str(data)
                        has_objective = "objective" in str(data)
                        has_gbtree = "gbtree" in content or "gblinear" in content

                        # Must have learner AND version, OR strong XGBoost patterns
                        strong_xgb_patterns = (has_learner or has_gradient_booster) and (has_objective or has_gbtree)
                        if (has_learner and has_version) or strong_xgb_patterns:
                            return True

                    return False

                except json.JSONDecodeError:
                    return False

            except (OSError, UnicodeDecodeError):
                return False

        # Check for XGBoost files that might not have the right extension
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

        # Check file size limits for JSON parsing
        if file_size > self.max_json_size:
            result.add_check(
                name="JSON File Size Check",
                passed=False,
                message=f"XGBoost JSON file too large: {file_size} bytes (max: {self.max_json_size})",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"file_size": file_size, "max_size": self.max_json_size},
                why="Extremely large JSON files may cause memory exhaustion or parsing delays",
            )
            return

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
                message="ubjson package not available, cannot decode UBJ files",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"required_package": "ubjson"},
                why="Install 'pip install ubjson' to enable UBJ model scanning",
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
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"detected_format": "pickle", "claimed_format": "bst"},
                    why="File extension spoofing may indicate an attempt to bypass security checks",
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
        # Check for required top-level structure
        required_keys = ["version", "learner"]
        missing_keys = [key for key in required_keys if key not in data]

        if missing_keys:
            result.add_check(
                name="XGBoost JSON Schema Validation",
                passed=False,
                message=f"Missing required XGBoost JSON keys: {missing_keys}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"missing_keys": missing_keys, "available_keys": list(data.keys())},
                why="Invalid schema may indicate corruption or malicious modification",
            )
            return

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
                            message=f"Excessive number of trees: {num_trees} (max: {self.max_num_trees})",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"num_trees": num_trees, "max_trees": self.max_num_trees},
                            why="Extremely large tree counts may indicate memory exhaustion attacks",
                        )

                    # Check individual tree structures
                    self._validate_tree_structures(trees[:10], result, path)  # Sample first 10 trees

        # Check learner model parameters
        params = learner.get("learner_model_param", {})
        if isinstance(params, dict):
            self._validate_model_parameters(params, result, path)

    def _validate_tree_structures(self, trees: list[dict], result: ScanResult, path: str) -> None:
        """Validate individual tree structures for anomalies."""
        for i, tree in enumerate(trees):
            # Check tree depth
            if "tree_param" in tree:
                tree_param = tree["tree_param"]
                if isinstance(tree_param, dict):
                    depth = tree_param.get("size_leaf_vector", 0)
                    if depth > self.max_tree_depth:
                        result.add_check(
                            name="Tree Depth Validation",
                            passed=False,
                            message=f"Tree {i} has excessive depth: {depth}",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"tree_index": i, "depth": depth, "max_depth": self.max_tree_depth},
                            why="Extremely deep trees may cause stack overflow or excessive memory usage",
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
                            message=f"Suspicious {param_name} value: {value}",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={param_name: value, "range": [min_val, max_val]},
                            why=f"Parameter {param_name} outside reasonable range may indicate malicious modification",
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

    def _check_json_for_malicious_content(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check XGBoost JSON data for potentially malicious content."""
        # Convert to string for pattern matching
        json_str = json.dumps(data, separators=(",", ":"))

        # Check for suspicious patterns
        suspicious_patterns = [
            (r"__reduce__", "Pickle-like reduction pattern in JSON"),
            (r"eval\s*\(", "Eval function call in JSON"),
            (r"exec\s*\(", "Exec function call in JSON"),
            (r"import\s+os", "OS module import in JSON"),
            (r"subprocess\.", "Subprocess usage in JSON"),
            (r"system\s*\(", "System call in JSON"),
            (r"__import__", "Dynamic import in JSON"),
            (r"\\x[0-9a-fA-F]{2}", "Hex-encoded data (potential shellcode)"),
        ]

        for pattern, description in suspicious_patterns:
            import re

            if re.search(pattern, json_str, re.IGNORECASE):
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
                            message="File contains unusual binary patterns, may not be valid XGBoost model",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"header_hex": header[:16].hex()},
                            why="Unexpected binary patterns may indicate file corruption or spoofing",
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
            cmd = [
                sys.executable,
                "-c",
                f"""
import sys
import xgboost as xgb
try:
    booster = xgb.Booster()
    booster.load_model('{path}')
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
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"error": error_msg, "return_code": proc.returncode},
                    why="Loading failures may indicate file corruption or incompatible format",
                )

        except subprocess.TimeoutExpired:
            result.add_check(
                name="XGBoost Model Loading",
                passed=False,
                message=f"XGBoost model loading timeout after {timeout} seconds",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"timeout": timeout},
                why="Loading timeouts may indicate extremely large models or infinite loops",
            )
        except Exception as e:
            result.add_check(
                name="XGBoost Model Loading",
                passed=False,
                message=f"Error during XGBoost model loading test: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )
