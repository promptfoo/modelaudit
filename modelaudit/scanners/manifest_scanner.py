import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from modelaudit.suspicious_symbols import SUSPICIOUS_CONFIG_PATTERNS

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


class ManifestScanner(BaseScanner):
    """Scanner for model manifest and configuration files"""

    name = "manifest"
    description = "Scans model manifest and configuration files for suspicious content and blacklisted names"
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
                ml_term in path_lower for ml_term in ["model", "checkpoint", "huggingface", "transformers"]
            ) or os.path.splitext(path)[1].lower() in [".json"]:
                return True

        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a manifest or configuration file"""
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
                if isinstance(content, dict):
                    result.metadata["keys"] = list(content.keys())

                    # Extract model metadata for HuggingFace config files
                    if os.path.basename(path) == "config.json":
                        model_info = {}
                        # Extract key model configuration
                        if "model_type" in content:
                            model_info["model_type"] = content["model_type"]
                        if "architectures" in content:
                            model_info["architectures"] = content["architectures"]
                        if "num_parameters" in content:
                            model_info["num_parameters"] = content["num_parameters"]
                        if "hidden_size" in content:
                            model_info["hidden_size"] = content["hidden_size"]
                        if "num_hidden_layers" in content:
                            model_info["num_layers"] = content["num_hidden_layers"]
                        if "num_attention_heads" in content:
                            model_info["num_heads"] = content["num_attention_heads"]
                        if "vocab_size" in content:
                            model_info["vocab_size"] = content["vocab_size"]
                        if "task" in content:
                            model_info["task"] = content["task"]
                        if "transformers_version" in content:
                            model_info["framework_version"] = content["transformers_version"]

                        if model_info:
                            result.metadata["model_info"] = model_info

                # Extract license information if present
                if isinstance(content, dict):
                    license_info = self._extract_license_info(content)
                    if license_info:
                        result.metadata["license"] = license_info

                # Check for suspicious configuration patterns
                self._check_suspicious_patterns(content, result)

            else:
                result.add_check(
                    name="Manifest Parse Attempt",
                    passed=False,
                    message=f"Unable to parse file as a manifest or configuration: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                )

        except Exception as e:
            result.add_check(
                name="Manifest File Scan",
                passed=False,
                message=f"Error scanning manifest file: {e!s}",
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
                content = f.read().lower()  # Convert to lowercase for case-insensitive matching

                found_blacklisted = False
                for pattern in self.blacklist_patterns:
                    pattern_lower = pattern.lower()
                    if pattern_lower in content:
                        result.add_check(
                            name="Blacklist Pattern Check",
                            passed=False,
                            message=f"Blacklisted term '{pattern}' found in file",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={"blacklisted_term": pattern, "file_path": path},
                            why=(
                                "This term matches a user-defined blacklist pattern. Organizations use blacklists to "
                                "identify models or configurations that violate security policies or contain known "
                                "malicious indicators."
                            ),
                        )
                        found_blacklisted = True

                if not found_blacklisted:
                    result.add_check(
                        name="Blacklist Pattern Check",
                        passed=True,
                        message="No blacklisted patterns found in file",
                        location=self.current_file_path,
                        details={"patterns_checked": len(self.blacklist_patterns)},
                    )
        except Exception as e:
            result.add_check(
                name="Blacklist Pattern Check",
                passed=False,
                message=f"Error checking file for blacklist: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

    def _parse_file(
        self,
        path: str,
        ext: str,
        result: Optional[ScanResult] = None,
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
                if HAS_YAML and (ext in [".yaml", ".yml"] or content.strip().startswith("---")):
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
            logger.warning(f"Error parsing file {path}: {e!s}")
            if result is not None:
                result.add_check(
                    name="File Parse Error",
                    passed=False,
                    message=f"Error parsing file: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )

        return None

    def _extract_license_info(self, content: dict[str, Any]) -> Optional[str]:
        """Return license string if found in manifest content"""

        potential_keys = ["license", "licence", "licenses"]
        for key in potential_keys:
            if key in content:
                value = content[key]
                if isinstance(value, str):
                    return value
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, str):
                        return first

        return None

    def _check_suspicious_patterns(
        self,
        content: dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Smart pattern detection with value analysis and ML context awareness"""

        # STEP 1: Detect ML context for smart filtering
        ml_context = self._detect_ml_context(content)

        def check_dict(d, prefix: str = "") -> None:
            if not isinstance(d, dict):
                return

            for key, value in d.items():
                if key in ["label2id", "text_config", "vision_config"]:
                    continue
                key_lower = key.lower()
                full_key = f"{prefix}.{key}" if prefix else key

                # STEP 1.5: Check for blacklisted model names (integrated from original)
                if key_lower in MODEL_NAME_KEYS_LOWER:
                    blocked, reason = check_model_name_policies(
                        str(value),
                        self.blacklist_patterns,
                    )
                    if blocked:
                        result.add_check(
                            name="Model Name Policy Check",
                            passed=False,
                            message=f"Model name blocked by policy: {value}",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={
                                "model_name": str(value),
                                "reason": reason,
                                "key": full_key,
                            },
                        )
                    else:
                        result.add_check(
                            name="Model Name Policy Check",
                            passed=True,
                            message=f"Model name '{value}' passed policy check",
                            location=self.current_file_path,
                            details={
                                "model_name": str(value),
                                "key": full_key,
                            },
                        )

                # STEP 2: Value-based analysis - check for actually dangerous content
                if self._is_actually_dangerous_value(key, value):
                    result.add_check(
                        name="Dangerous Content Detection",
                        passed=False,
                        message=f"Dangerous configuration content: {full_key}",
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
                if matches and not self._should_ignore_in_context(
                    key,
                    value,
                    matches,
                    ml_context,
                    full_key,
                ):
                    # STEP 5: Report with context-aware severity
                    severity = self._get_context_aware_severity(matches, ml_context)
                    why = None
                    if severity == IssueSeverity.INFO:
                        if "file_access" in matches and "network_access" in matches:
                            why = (
                                "File and network access patterns in ML model configurations are common for loading "
                                "datasets and downloading resources. They are flagged for awareness but are typically "
                                "benign in ML contexts."
                            )
                        elif "file_access" in matches:
                            why = (
                                "File access patterns in ML model configurations often indicate dataset paths "
                                "or model checkpoints. This is flagged for awareness but is typical in ML workflows."
                            )
                        elif "network_access" in matches:
                            why = (
                                "Network access patterns in ML model configurations may indicate remote model "
                                "repositories or dataset URLs. This is common in ML pipelines but worth reviewing."
                            )

                    result.add_check(
                        name="Suspicious Configuration Pattern Detection",
                        passed=False,
                        message=f"Suspicious configuration pattern: {full_key} (category: {', '.join(matches)})",
                        severity=severity,
                        location=self.current_file_path,
                        details={
                            "key": full_key,
                            "value": self._format_value(value),
                            "categories": matches,
                            "ml_context": ml_context,
                            "analysis": "pattern_based",
                        },
                        why=why,
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

    def _detect_ml_context(self, content: dict[str, Any]) -> dict[str, Any]:
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

        vision_indicators = [
            "image_size",
            "img_size",
            "num_channels",
            "channels",
            "resolution",
            "input_shape",
            "image_mean",
            "image_std",
            "vision_config",
        ]

        classification_keys = [
            "imagenet_classes",
            "labels",
            "class_names",
            "class_labels",
            "label_map",
            "label_names",
        ]

        def check_indicators(d):
            if not isinstance(d, dict):
                return

            for key, val in d.items():
                key_str = str(key).lower()
                val_str = str(val).lower()

                # Check framework patterns
                for framework, patterns in framework_patterns.items():
                    if any(pattern in key_str or pattern in val_str for pattern in patterns):
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

                # Vision model indicators
                if any(indicator in key_str for indicator in vision_indicators) or any(
                    indicator in val_str for indicator in vision_indicators
                ):
                    indicators["model_type"] = "vision"
                    indicators["confidence"] += 1

                # Classification label keys
                if key_str in classification_keys:
                    indicators["model_type"] = "vision"
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
        self,
        key: str,
        value: Any,
        matches: list[str],
        ml_context: dict,
        full_key: str = "",
    ) -> bool:
        """Context-aware ignore logic combining smart patterns with value analysis"""
        key_lower = key.lower()
        full_key_lower = full_key.lower() if full_key else key_lower

        # Special case for HuggingFace patterns - check this FIRST before other logic
        if ml_context.get("framework") == "huggingface" or "_name_or_path" in key_lower:
            huggingface_safe_patterns = [
                "_name_or_path",
                "name_or_path",
                "model_input_names",
                "model_output_names",
                "transformers_version",
                "torch_dtype",
                "architectures",
            ]
            if any(pattern in key_lower for pattern in huggingface_safe_patterns):
                return True

        # High-confidence ML context gets more lenient treatment
        if ml_context.get("confidence", 0) >= 2:
            # File access patterns in ML context
            if "file_access" in matches:
                # First check if this is an actual file path - never ignore those
                if key_lower.endswith(
                    ("_dir", "_path", "_file"),
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
            if "credentials" in matches and any(
                pattern in key_lower for pattern in ["_token_id", "token_id_", "_token", "token_type"]
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

        # Special case for encoder-decoder transformer models (T5, BART, etc.)
        if ml_context.get("framework") == "huggingface" and "execution" in matches:
            # These are legitimate sequence-to-sequence model configuration patterns
            # that contain "decoder" or "encoder" but are not actually execution-related
            encoder_decoder_safe_patterns = [
                # T5 specific patterns
                "decoder_start_token_id",  # T5/seq2seq start token configuration
                "is_encoder_decoder",  # Architecture flag for encoder-decoder models
                "decoder_input_ids",  # Input configuration for decoder
                "decoder_attention_mask",  # Attention configuration for decoder
                "decoder_head_mask",  # Head masking for decoder
                "forced_decoder_ids",  # Forced decoding configuration
                "suppress_tokens",  # Token suppression configuration
                "begin_suppress_tokens",  # Begin token suppression
                "forced_bos_token_id",  # Beginning of sequence token
                "forced_eos_token_id",  # End of sequence token
                "encoder_no_repeat_ngram_size",  # N-gram repetition control
                "decoder_start_token",  # Alternative start token naming
                "decoder_config",  # Decoder-specific configuration
                "encoder_config",  # Encoder-specific configuration
                # BART specific patterns - architecture configuration
                "decoder_attention_heads",  # Number of attention heads in decoder
                "decoder_ffn_dim",  # Feed-forward network dimension in decoder
                "decoder_layerdrop",  # Layer dropout rate for decoder
                "decoder_layers",  # Number of decoder layers
                "encoder_attention_heads",  # Number of attention heads in encoder
                "encoder_ffn_dim",  # Feed-forward network dimension in encoder
                "encoder_layerdrop",  # Layer dropout rate for encoder
                "encoder_layers",  # Number of encoder layers
                # Additional encoder-decoder patterns
                "decoder_hidden_size",  # Hidden dimension size for decoder
                "encoder_hidden_size",  # Hidden dimension size for encoder
                "decoder_intermediate_size",  # Intermediate layer size for decoder
                "encoder_intermediate_size",  # Intermediate layer size for encoder
                "decoder_max_position_embeddings",  # Max position embeddings for decoder
                "encoder_max_position_embeddings",  # Max position embeddings for encoder
            ]

            if any(pattern in key_lower for pattern in encoder_decoder_safe_patterns):
                return True

        # Special case for GLM (General Language Model) architecture patterns
        # GLM models use specific layer naming conventions that trigger false positives
        # GLM models can be detected as "huggingface", "pytorch", or have null framework (SafeTensors)
        if (ml_context.get("framework") in ["huggingface", "pytorch", None]) and "execution" in matches:
            # GLM architecture patterns from models like ChatGLM, GLM-4, etc.
            # These are legitimate transformer components with GLM-specific naming
            # Note: keys include "weight_map." prefix from model index files
            # IMPORTANT: All patterns must be lowercase since key_lower is used for matching
            glm_safe_patterns = [
                # GLM transformer layer patterns (with weight_map prefix) - LOWERCASE
                "weight_map.transformer.encoder.layers.",  # GLM encoder layer prefix
                "weight_map.transformer.encoder.final_layernorm",  # GLM final layer normalization
                "weight_map.transformer.output_layer",  # GLM output layer
                # GLM layer component patterns (can appear anywhere in key) - LOWERCASE
                ".input_layernorm.weight",  # Input layer normalization weights
                ".post_attention_layernorm.weight",  # Post-attention layer normalization
                ".mlp.dense_4h_to_h.weight",  # MLP dense layer (4h to h dimension)
                ".mlp.dense_h_to_4h.weight",  # MLP dense layer (h to 4h dimension)
                ".self_attention.dense.weight",  # Self-attention dense projection
                ".self_attention.query_key_value.weight",  # QKV projection weights
                ".self_attention.query_key_value.bias",  # QKV projection bias
                # Additional GLM-specific patterns (with weight_map prefix) - LOWERCASE
                "weight_map.rotary_pos_emb",  # Rotary positional embeddings
                "weight_map.word_embeddings",  # Word embedding layers
                "weight_map.position_embeddings",  # Position embedding layers (if used)
            ]

            # Check for GLM patterns in the key
            if any(pattern in key_lower for pattern in glm_safe_patterns):
                return True

        # Special case for vision-language models (CLIP, ViLT, BLIP, etc.)
        # Check CLIP specific patterns first - these are legitimate config keys
        if "execution" in matches and "config" in key_lower:
            clip_patterns = [
                "text_config.is_decoder",
                "text_config.pruned_heads",
                "text_config.tie_encoder_decoder",
                "text_config.torchscript",
                "vision_config.is_decoder",
                "vision_config.pruned_heads",
                "vision_config.tie_encoder_decoder",
                "vision_config.torchscript",
            ]
            if key_lower in clip_patterns:
                return True

        # Classification labels for vision models can contain words like "shell"
        # that match execution patterns. Ignore these when the context indicates
        # a vision model.
        if "execution" in matches and ml_context.get("model_type") == "vision":
            label_container_keys = {
                "imagenet_classes",
                "labels",
                "class_names",
                "class_labels",
                "label_map",
                "label_names",
            }
            parts = full_key_lower.split(".")
            if key_lower in label_container_keys or any(part in label_container_keys for part in parts[:-1]):
                return True

        return False

    def _is_file_path_value(self, value: Any) -> bool:
        """Check if value appears to be an actual file system path"""
        if not isinstance(value, str):
            return False

        # Absolute paths (Unix or Windows)
        if Path(value).is_absolute() or re.match(r"^[a-zA-Z]:\\", value):
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
        lower_value = value.lower()
        indicators = ["/tmp", "/var", "/data", "/home", "/etc"]
        return bool(any(indicator in lower_value for indicator in indicators) or re.search(r"[a-z]:\\", lower_value))

    def _get_context_aware_severity(
        self,
        matches: list[str],
        ml_context: dict,
    ) -> IssueSeverity:
        """Determine severity based on context and match types"""
        # Execution patterns are always ERROR
        if "execution" in matches:
            return IssueSeverity.CRITICAL

        # In high-confidence ML context, downgrade some warnings
        if ml_context.get("confidence", 0) >= 2 and all(
            match in ["file_access", "network_access"] for match in matches
        ):
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
