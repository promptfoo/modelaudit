import json
import os
from typing import Any, Optional

from .base import BaseScanner, IssueSeverity, ScanResult, logger

# Try to import the name policies module
try:
    from modelaudit.name_policies.blacklist import check_model_name_policies

    HAS_NAME_POLICIES = True
except ImportError:
    HAS_NAME_POLICIES = False

    # Create a placeholder function when the module is not available
    def check_model_name_policies(
        model_name: str,
        additional_patterns: Optional[list[str]] = None,
    ) -> tuple[bool, str]:
        return False, ""


# Try to import yaml, but handle the case where it's not installed
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Common manifest and config file formats
MANIFEST_EXTENSIONS = [
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".config",
    ".manifest",
    ".model",
    ".metadata",
]

# Keys that might contain model names
MODEL_NAME_KEYS = [
    "name",
    "model_name",
    "model",
    "model_id",
    "id",
    "title",
    "artifact_name",
    "artifact_id",
    "package_name",
]

# Pre-compute lowercase versions for faster checks
MODEL_NAME_KEYS_LOWER = [key.lower() for key in MODEL_NAME_KEYS]

# Suspicious configuration patterns
SUSPICIOUS_CONFIG_PATTERNS = {
    "network_access": [
        "url",
        "endpoint",
        "server",
        "host",
        "callback",
        "webhook",
        "http",
        "https",
        "ftp",
        "socket",
    ],
    "file_access": [
        "file",
        "path",
        "directory",
        "folder",
        "output",
        "save",
        "load",
        "write",
        "read",
    ],
    "execution": [
        "exec",
        "eval",
        "execute",
        "run",
        "command",
        "script",
        "shell",
        "subprocess",
        "system",
        "code",
    ],
    "credentials": [
        "password",
        "secret",
        "credential",
        "auth",
        "authentication",
        "api_key",
    ],
}


class ManifestScanner(BaseScanner):
    """Scanner for model manifest and configuration files"""

    name = "manifest"
    description = (
        "Scans model manifest and configuration files for suspicious content "
        "and blacklisted names"
    )
    supported_extensions = MANIFEST_EXTENSIONS

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Get blacklist patterns from config
        self.blacklist_patterns = self.config.get("blacklist_patterns", [])

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        filename = os.path.basename(path).lower()

        # Whitelist: Only scan files that are unique to AI/ML models
        aiml_specific_patterns = [
            # HuggingFace/Transformers specific configuration files
            "config.json",  # Model architecture config (when in ML model context)
            "generation_config.json",  # Text generation parameters
            "preprocessor_config.json",  # Data preprocessing config
            "feature_extractor_config.json",  # Feature extraction config
            "image_processor_config.json",  # Image processing config
            "scheduler_config.json",  # Learning rate scheduler config
            # Model metadata and manifest files specific to ML
            "model_index.json",  # Diffusion model index
            "model_card.json",  # Model card metadata
            "pytorch_model.bin.index.json",  # PyTorch model shard index
            "model.safetensors.index.json",  # SafeTensors model index
            "tf_model.h5.index.json",  # TensorFlow model index
            # ML-specific execution and deployment configs
            "inference_config.json",  # Model inference configuration
            "deployment_config.json",  # Model deployment configuration
            "serving_config.json",  # Model serving configuration
            # ONNX model specific
            "onnx_config.json",  # ONNX export configuration
            # Custom model configs that might contain execution parameters
            "custom_config.json",  # Custom model configurations
            "runtime_config.json",  # Runtime execution parameters
        ]

        # Check if filename matches any AI/ML specific pattern
        if any(pattern in filename for pattern in aiml_specific_patterns):
            return True

        # Additional check: files with "config" in name that are in ML model context
        # (but exclude tokenizer configs and general software configs)
        if (
            "config" in filename
            and "tokenizer" not in filename
            and filename
            not in [
                "config.py",
                "config.yaml",
                "config.yml",
                "config.ini",
                "config.cfg",
            ]
        ):
            # Only if it's likely an ML model config
            # (has model-related terms in path or specific extensions)
            path_lower = path.lower()
            if any(
                ml_term in path_lower
                for ml_term in ["model", "checkpoint", "huggingface", "transformers"]
            ) or os.path.splitext(path)[1].lower() in [".json"]:
                return True

        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a manifest or configuration file"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            # First, check the raw file content for blacklisted terms
            self._check_file_for_blacklist(path, result)

            # Parse the file based on its extension
            ext = os.path.splitext(path)[1].lower()
            content = self._parse_file(path, ext, result)

            if content:
                result.bytes_scanned = file_size

                # Check for suspicious configuration patterns
                self._check_suspicious_patterns(content, result)

            else:
                result.add_issue(
                    f"Unable to parse file as a manifest or configuration: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                )

        except Exception as e:
            result.add_issue(
                f"Error scanning manifest file: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _check_file_for_blacklist(self, path: str, result: ScanResult) -> None:
        """Check the entire file content for blacklisted terms"""
        if not self.blacklist_patterns:
            return

        try:
            with open(path, encoding="utf-8") as f:
                content = (
                    f.read().lower()
                )  # Convert to lowercase for case-insensitive matching

                for pattern in self.blacklist_patterns:
                    pattern_lower = pattern.lower()
                    if pattern_lower in content:
                        result.add_issue(
                            f"Blacklisted term '{pattern}' found in file",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={"blacklisted_term": pattern, "file_path": path},
                        )
        except Exception as e:
            result.add_issue(
                f"Error checking file for blacklist: {str(e)}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

    def _parse_file(
        self, path: str, ext: str, result: Optional[ScanResult] = None
    ) -> Optional[dict[str, Any]]:
        """Parse the file based on its extension"""
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()

                # Try JSON format first
                if ext in [
                    ".json",
                    ".manifest",
                    ".model",
                    ".metadata",
                ] or content.strip().startswith(("{", "[")):
                    return json.loads(content)

                # Try YAML format if available
                if HAS_YAML and (
                    ext in [".yaml", ".yml"] or content.strip().startswith("---")
                ):
                    return yaml.safe_load(content)

                # For other formats, try JSON and then YAML if available
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    if HAS_YAML:
                        try:
                            return yaml.safe_load(content)
                        except Exception:
                            pass

        except Exception as e:
            # Log the error but don't raise, as we want to continue scanning
            logger.warning(f"Error parsing file {path}: {str(e)}")
            if result is not None:
                result.add_issue(
                    f"Error parsing file: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )

        return None

    def _check_suspicious_patterns(
        self,
        content: dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Smart pattern detection with value analysis and ML context awareness"""

        # STEP 1: Detect ML context for smart filtering
        ml_context = self._detect_ml_context(content)

        def check_dict(d, prefix=""):
            if not isinstance(d, dict):
                return

            for key, value in d.items():
                key_lower = key.lower()
                full_key = f"{prefix}.{key}" if prefix else key

                # STEP 1.5: Check for blacklisted model names (integrated from original)
                if key_lower in MODEL_NAME_KEYS_LOWER:
                    blocked, reason = check_model_name_policies(
                        str(value), self.blacklist_patterns
                    )
                    if blocked:
                        result.add_issue(
                            f"Model name blocked by policy: {value}",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={
                                "model_name": str(value),
                                "reason": reason,
                                "key": full_key,
                            },
                        )

                # STEP 2: Value-based analysis - check for actually dangerous content
                if self._is_actually_dangerous_value(key, value):
                    result.add_issue(
                        f"Dangerous configuration content: {full_key}",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={
                            "key": full_key,
                            "analysis": "value_based",
                            "danger": "executable_content",
                            "value": self._format_value(value),
                        },
                    )
                    # Don't continue here - still check for patterns and recurse

                # STEP 3: Smart pattern matching
                matches = self._find_suspicious_matches(key_lower)
                if matches:
                    # STEP 4: Context-aware filtering
                    if not self._should_ignore_in_context(
                        key, value, matches, ml_context
                    ):
                        # STEP 5: Report with context-aware severity
                        severity = self._get_context_aware_severity(matches, ml_context)
                        result.add_issue(
                            f"Suspicious configuration pattern: {full_key} "
                            f"(category: {', '.join(matches)})",
                            severity=severity,
                            location=self.current_file_path,
                            details={
                                "key": full_key,
                                "value": self._format_value(value),
                                "categories": matches,
                                "ml_context": ml_context,
                                "analysis": "pattern_based",
                            },
                        )

                # ALWAYS recursively check nested structures,
                # regardless of pattern matches
                if isinstance(value, dict):
                    check_dict(value, full_key)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            check_dict(item, f"{full_key}[{i}]")

        check_dict(content)

    def _is_actually_dangerous_value(self, key: str, value: Any) -> bool:
        """Check if value content is actually dangerous executable code"""
        if not isinstance(value, str):
            return False

        value_lower = value.lower().strip()

        # Look for ACTUAL executable content patterns
        dangerous_patterns = [
            "import os",
            "subprocess.",
            "eval(",
            "exec(",
            "os.system",
            "__import__",
            "runpy",
            "shell=true",
            "rm -rf",
            "/bin/sh",
            "cmd.exe",
            # Add more specific patterns
            "exec('",
            'exec("',
            "eval('",
            'eval("',
        ]

        return any(pattern in value_lower for pattern in dangerous_patterns)

    def _detect_ml_context(self, content: dict) -> dict:
        """Detect ML model context to adjust sensitivity"""
        indicators = {
            "framework": None,
            "model_type": None,
            "confidence": 0,
            "is_tokenizer": False,
            "is_model_config": False,
        }

        # Framework detection patterns
        framework_patterns = {
            "huggingface": [
                "tokenizer_class",
                "transformers_version",
                "model_type",
                "architectures",
                "auto_map",
                "_name_or_path",
            ],
            "pytorch": [
                "torch",
                "state_dict",
                "pytorch_model",
                "model.pt",
                "torch_dtype",
            ],
            "tensorflow": [
                "tensorflow",
                "saved_model",
                "model.h5",
                "tf_version",
                "keras",
            ],
            "sklearn": ["sklearn", "pickle_module", "scikit"],
        }

        # Model type indicators
        tokenizer_indicators = [
            "tokenizer_class",
            "added_tokens_decoder",
            "model_input_names",
            "special_tokens_map",
            "bos_token",
            "eos_token",
            "pad_token",
        ]

        model_config_indicators = [
            "hidden_size",
            "num_attention_heads",
            "num_hidden_layers",
            "vocab_size",
            "max_position_embeddings",
            "architectures",
        ]

        def check_indicators(d):
            if not isinstance(d, dict):
                return

            for key, val in d.items():
                key_str = str(key).lower()
                val_str = str(val).lower()

                # Check framework patterns
                for framework, patterns in framework_patterns.items():
                    if any(
                        pattern in key_str or pattern in val_str for pattern in patterns
                    ):
                        indicators["framework"] = framework
                        indicators["confidence"] += 1

                # Check tokenizer indicators
                if any(indicator in key_str for indicator in tokenizer_indicators):
                    indicators["is_tokenizer"] = True
                    indicators["confidence"] += 1

                # Check model config indicators
                if any(indicator in key_str for indicator in model_config_indicators):
                    indicators["is_model_config"] = True
                    indicators["confidence"] += 1

                # Recursive check
                if isinstance(val, dict):
                    check_indicators(val)

        check_indicators(content)
        return indicators

    def _find_suspicious_matches(self, key_lower: str) -> list[str]:
        """Find all categories that match this key"""
        matches = []
        for category, patterns in SUSPICIOUS_CONFIG_PATTERNS.items():
            if any(pattern in key_lower for pattern in patterns):
                matches.append(category)
        return matches

    def _should_ignore_in_context(
        self, key: str, value: Any, matches: list[str], ml_context: dict
    ) -> bool:
        """Context-aware ignore logic combining smart patterns with value analysis"""
        key_lower = key.lower()

        # High-confidence ML context gets more lenient treatment
        if ml_context.get("confidence", 0) >= 2:
            # File access patterns in ML context
            if "file_access" in matches:
                # First check if this is an actual file path - never ignore those
                if key_lower.endswith(
                    ("_dir", "_path", "_file")
                ) and self._is_file_path_value(value):
                    return False  # Don't ignore actual file paths

                # Common ML config patterns that aren't actual file access
                safe_ml_patterns = [
                    "_input",
                    "input_",
                    "_output",
                    "output_",
                    "_size",
                    "_dim",
                    "hidden_",
                    "attention_",
                    "embedding_",
                    "_token_",
                    "vocab_",
                    "_names",
                    "model_input_names",
                    "model_output_names",
                ]

                if any(pattern in key_lower for pattern in safe_ml_patterns):
                    return True

            # Credentials in ML context
            if "credentials" in matches:
                # Token IDs and model tokens are not credentials in ML context
                if any(
                    pattern in key_lower
                    for pattern in ["_token_id", "token_id_", "_token", "token_type"]
                ):
                    return True

        # Special case for tokenizer configs
        if ml_context.get("is_tokenizer"):
            tokenizer_safe_keys = [
                "added_tokens_decoder",
                "model_input_names",
                "special_tokens_map",
                "tokenizer_class",
                "model_max_length",
            ]
            if any(safe_key in key_lower for safe_key in tokenizer_safe_keys):
                return True

        return False

    def _is_file_path_value(self, value: Any) -> bool:
        """Check if value appears to be an actual file system path"""
        if not isinstance(value, str):
            return False

        # Absolute paths
        if value.startswith(("/", "\\", "C:", "D:")):
            return True

        # Relative paths with separators
        if "/" in value or "\\" in value:
            return True

        # File extensions that suggest actual files (using endswith for better matching)
        file_extensions = [
            ".json",
            ".h5",
            ".pt",
            ".onnx",
            ".pkl",
            ".model",
            ".txt",
            ".log",
            ".csv",
            ".xml",
            ".yaml",
            ".yml",
            ".py",
            ".js",
            ".html",
            ".css",
            ".sql",
            ".md",
        ]
        if any(value.lower().endswith(ext) for ext in file_extensions):
            return True

        # Common path indicators
        if any(
            indicator in value.lower()
            for indicator in ["/tmp", "/var", "/data", "/home", "/etc", "c:\\", "d:\\"]
        ):
            return True

        return False

    def _get_context_aware_severity(
        self, matches: list[str], ml_context: dict
    ) -> IssueSeverity:
        """Determine severity based on context and match types"""
        # Execution patterns are always ERROR
        if "execution" in matches:
            return IssueSeverity.CRITICAL

        # In high-confidence ML context, downgrade some warnings
        if ml_context.get("confidence", 0) >= 2:
            # In ML context, file_access and network_access are less concerning
            if all(match in ["file_access", "network_access"] for match in matches):
                return IssueSeverity.INFO

        # Credentials are high priority
        if "credentials" in matches:
            return IssueSeverity.WARNING

        return IssueSeverity.WARNING

    def _format_value(self, value: Any) -> str:
        """Format a value for display, truncating if necessary"""
        str_value = str(value)
        if len(str_value) > 100:
            return str_value[:100] + "..."
        return str_value
