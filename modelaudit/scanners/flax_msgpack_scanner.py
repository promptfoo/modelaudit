from __future__ import annotations

import os
import re
from typing import Any, ClassVar

try:
    import msgpack

    HAS_MSGPACK = True
except Exception:  # pragma: no cover - optional dependency missing
    HAS_MSGPACK = False

from .base import BaseScanner, IssueSeverity, ScanResult


class FlaxMsgpackScanner(BaseScanner):
    """Scanner for Flax/JAX msgpack checkpoint files with enhanced security threat detection."""

    name = "flax_msgpack"
    description = "Scans Flax/JAX msgpack checkpoints for security threats and integrity issues"
    # Enhanced file extension support for JAX/Flax ecosystem
    supported_extensions: ClassVar[list[str]] = [
        ".msgpack",
        ".flax",
        ".orbax",  # Orbax checkpoint format
        ".jax",  # Generic JAX model files
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_blob_bytes = self.config.get(
            "max_blob_bytes",
            500 * 1024 * 1024,  # Increased to 500MB for large language models
        )
        self.max_recursion_depth = self.config.get("max_recursion_depth", 100)
        self.max_items_per_container = self.config.get("max_items_per_container", 50000)  # Increased for large models

        # Enhanced suspicious patterns for JAX/Flax specific threats
        self.suspicious_patterns = self.config.get(
            "suspicious_patterns",
            [
                # Standard serialization attacks
                r"__reduce__",
                r"__getstate__",
                r"__setstate__",
                r"eval\s*\(",
                r"exec\s*\(",
                r"subprocess",
                r"os\.system",
                r"import\s+os",
                r"import\s+subprocess",
                r"__import__",
                r"compile\s*\(",
                r"pickle\.loads",
                r"marshal\.loads",
                r"base64\.decode",
                # JAX/Flax specific patterns
                r"jax\.eval_shape",
                r"jax\.numpy\.eval",
                r"flax\.core\.eval",
                r"haiku\.eval",
                # Code injection through JAX transforms
                r"jax\.jit\s*\(\s*eval",
                r"jax\.vmap\s*\(\s*exec",
                r"jax\.pmap\s*\(\s*eval",
                # Dynamic code execution
                r"getattr\s*\(\s*.*\s*,\s*['\"]__.*__['\"]",
                # Dangerous imports in serialized functions
                r"import\s+subprocess",
                r"from\s+subprocess\s+import",
                r"import\s+sys",
                r"from\s+os\s+import\s+system",
            ],
        )

        self.suspicious_keys = self.config.get(
            "suspicious_keys",
            {
                # Standard Python serialization threats
                "__class__",
                "__module__",
                "__reduce__",
                "__getstate__",
                "__setstate__",
                "__dict__",
                "__code__",
                "__globals__",
                "__builtins__",
                "__import__",
                # JAX/Flax specific suspicious keys
                "__jax_array__",  # Potential fake JAX array
                "__tree_flatten__",
                "__tree_unflatten__",
                "jax_fn",
                "compiled_fn",
                "eval_fn",
                "exec_fn",
                # Orbax specific
                "__orbax_metadata__",
                "restore_fn",
                "transform_fn",
            },
        )

        # JAX/Flax architecture patterns for better ML detection
        self.jax_patterns: dict[str, list[str]] = {
            "transformer_patterns": [
                "attention",
                "self_attention",
                "multi_head",
                "mha",
                "mqa",
                "gqa",
                "feed_forward",
                "ffn",
                "mlp",
                "dense",
                "linear",
                "layer_norm",
                "rms_norm",
                "batch_norm",
                "encoder",
                "decoder",
                "transformer_block",
            ],
            "cnn_patterns": [
                "conv1d",
                "conv2d",
                "conv3d",
                "convolution",
                "batch_norm",
                "group_norm",
                "layer_norm",
                "pool",
                "pooling",
                "max_pool",
                "avg_pool",
                "dropout",
                "activation",
            ],
            "embedding_patterns": [
                "embedding",
                "embed",
                "token_embedding",
                "position_embedding",
                "vocab_embedding",
                "word_embedding",
            ],
            "optimization_patterns": [
                "adam",
                "sgd",
                "rmsprop",
                "adagrad",
                "momentum",
                "learning_rate",
                "lr",
                "optimizer",
                "opt_state",
                "gradient",
                "grad",
            ],
        }

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()

        # Check file extension first
        if ext in cls.supported_extensions and HAS_MSGPACK:
            return True

        # For files without clear extensions, check if they might be msgpack
        if HAS_MSGPACK and ext in [".ckpt", ""]:  # Some JAX checkpoints have no extension
            try:
                with open(path, "rb") as f:
                    # Read first few bytes to check for msgpack format
                    header = f.read(32)
                    if len(header) > 0 and header[0:1] in [
                        b"\x80",
                        b"\x81",
                        b"\x82",
                        b"\x83",
                        b"\x84",
                        b"\x85",
                        b"\x86",
                        b"\x87",
                        b"\x88",
                        b"\x89",
                        b"\x8a",
                        b"\x8b",
                        b"\x8c",
                        b"\x8d",
                        b"\x8e",
                        b"\x8f",
                        b"\xde",
                        b"\xdf",  # Common msgpack format markers
                    ]:
                        return True
            except Exception:
                pass

        return False

    def _extract_jax_metadata(self, obj: Any, result: ScanResult) -> dict[str, Any]:
        """Extract JAX/Flax specific metadata from the checkpoint."""
        metadata: dict[str, Any] = {
            "model_type": "unknown",
            "architecture_hints": [],
            "parameter_count": 0,
            "layer_count": 0,
            "has_optimizer_state": False,
            "jax_version_hints": [],
            "orbax_format": False,
        }

        if not isinstance(obj, dict):
            return metadata

        # Check for Orbax format indicators
        if any(key.startswith("__orbax") for key in obj):
            metadata["orbax_format"] = True
            result.add_check(
                name="Checkpoint Format Detection",
                passed=True,
                message="Orbax checkpoint format detected",
                location="root",
                details={"checkpoint_format": "orbax"},
            )

        # Analyze architecture patterns
        obj_str = str(obj).lower()
        for _pattern_type, patterns in self.jax_patterns.items():
            found_patterns = [p for p in patterns if p in obj_str]
            if found_patterns:
                metadata["architecture_hints"].extend(found_patterns)

        # Determine likely model type based on patterns
        if any(p in metadata["architecture_hints"] for p in self.jax_patterns["transformer_patterns"]):
            metadata["model_type"] = "transformer"
        elif any(p in metadata["architecture_hints"] for p in self.jax_patterns["cnn_patterns"]):
            metadata["model_type"] = "cnn"
        elif any(p in metadata["architecture_hints"] for p in self.jax_patterns["embedding_patterns"]):
            metadata["model_type"] = "embedding"

        # Check for optimizer state
        opt_indicators = ["opt_state", "optimizer", "adam", "sgd", "learning_rate"]
        if any(indicator in obj_str for indicator in opt_indicators):
            metadata["has_optimizer_state"] = True

        # Estimate parameter count and layer count
        def count_parameters(data: Any, path: str = "") -> int:
            count = 0
            if isinstance(data, dict):
                # Count layers
                layer_keys = [
                    k for k in data if any(layer_word in str(k).lower() for layer_word in ["layer", "block", "level"])
                ]
                if layer_keys:
                    metadata["layer_count"] += len(layer_keys)

                for key, value in data.items():
                    count += count_parameters(value, f"{path}/{key}" if path else key)
            elif isinstance(data, (list, tuple)):
                for i, value in enumerate(data):
                    count += count_parameters(value, f"{path}[{i}]")
            elif isinstance(data, (bytes, bytearray)):
                # Estimate parameter count from byte arrays (assuming float32)
                if len(data) >= 16 and len(data) % 4 == 0:
                    count += len(data) // 4
            return count

        metadata["parameter_count"] = count_parameters(obj)

        # Perform ML structure analysis to get confidence score
        ml_analysis = self._analyze_ml_structure(obj, result)

        # Add confidence and ML analysis results to metadata
        metadata["confidence"] = ml_analysis["confidence"]
        metadata["is_ml_model"] = ml_analysis["is_ml_model"]
        metadata["ml_evidence"] = ml_analysis["evidence"]
        metadata["tensor_count"] = ml_analysis["tensor_count"]

        # Add metadata to scan result
        result.metadata.update(
            {
                "jax_metadata": metadata,
                "estimated_parameters": metadata["parameter_count"],
                "model_architecture": metadata["model_type"],
                "layer_count": metadata["layer_count"],
            }
        )

        return metadata

    def _check_jax_specific_threats(self, obj: Any, result: ScanResult) -> None:
        """Check for JAX/Flax specific security threats."""

        def check_jax_transforms(data: Any, path: str = "") -> None:
            """Check for potentially dangerous JAX transform usage."""
            if isinstance(data, dict):
                for key, value in data.items():
                    key_str = str(key).lower()
                    value_str = str(value)

                    # Check for suspicious JAX transform patterns
                    dangerous_transforms = ["jit_compile", "eval_jit", "exec_transform", "dynamic_eval", "runtime_eval"]

                    for transform in dangerous_transforms:
                        if transform in key_str or transform in value_str.lower():
                            result.add_check(
                                name="JAX Transform Security Check",
                                passed=False,
                                message=f"Suspicious JAX transform detected: {transform}",
                                severity=IssueSeverity.CRITICAL,
                                location=f"{path}/{key}",
                                details={
                                    "transform": transform,
                                    "context": value_str[:200] if len(value_str) > 200 else value_str,
                                },
                            )

                    check_jax_transforms(value, f"{path}/{key}" if path else key)
            elif isinstance(data, (list, tuple)):
                for i, value in enumerate(data):
                    check_jax_transforms(value, f"{path}[{i}]")

        # Check for JAX-specific attack patterns
        check_jax_transforms(obj)

        # Check for fake JAX arrays or suspicious array metadata
        def check_array_metadata(data: Any, path: str = "") -> None:
            if isinstance(data, dict):
                # Look for fake JAX array indicators
                if "__jax_array__" in data:
                    result.add_check(
                        name="JAX Array Metadata Check",
                        passed=False,
                        message="Suspicious JAX array metadata detected",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"suspicious_key": "__jax_array__"},
                    )

                # Check for unusual shape specifications that might indicate attacks
                if "shape" in data and isinstance(data["shape"], (list, tuple)):
                    shape = data["shape"]
                    if any(dim < 0 for dim in shape if isinstance(dim, int)):
                        result.add_check(
                            name="Tensor Shape Validation",
                            passed=False,
                            message="Invalid tensor shape with negative dimensions",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"shape": shape},
                        )
                    elif any(dim > 10**9 for dim in shape if isinstance(dim, int)):
                        result.add_check(
                            name="Tensor Dimension Check",
                            passed=False,
                            message="Suspiciously large tensor dimensions",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={"shape": shape, "max_safe_dimension": 10**9},
                        )

                for key, value in data.items():
                    check_array_metadata(value, f"{path}/{key}" if path else key)

        check_array_metadata(obj)

    def _check_suspicious_strings(
        self,
        value: str,
        location: str,
        result: ScanResult,
    ) -> None:
        """Check string values for suspicious patterns that might indicate code injection."""
        for pattern in self.suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result.add_check(
                    name="Code Pattern Security Check",
                    passed=False,
                    message=f"Suspicious code pattern detected: {pattern}",
                    severity=IssueSeverity.CRITICAL,
                    location=location,
                    details={
                        "pattern": pattern,
                        "sample": value[:200] + "..." if len(value) > 200 else value,
                        "full_length": len(value),
                    },
                )

    def _check_suspicious_keys(
        self,
        key: str,
        location: str,
        result: ScanResult,
    ) -> None:
        """Check dictionary keys for suspicious names that might indicate serialization attacks."""
        if key in self.suspicious_keys:
            result.add_check(
                name="Object Attribute Security Check",
                passed=False,
                message=f"Suspicious object attribute detected: {key}",
                severity=IssueSeverity.CRITICAL,
                location=location,
                details={"suspicious_key": key},
            )

    def _analyze_content(
        self,
        value: Any,
        location: str,
        result: ScanResult,
        depth: int = 0,
    ) -> None:
        """Recursively analyze msgpack content for security threats and anomalies."""
        if depth > self.max_recursion_depth:
            result.add_check(
                name="Recursion Depth Check",
                passed=False,
                message=f"Maximum recursion depth exceeded: {depth}",
                severity=IssueSeverity.CRITICAL,
                location=location,
                details={"depth": depth, "max_allowed": self.max_recursion_depth},
            )
            return

        if isinstance(value, (bytes, bytearray)):
            size = len(value)
            if size > self.max_blob_bytes:
                result.add_check(
                    name="Binary Blob Size Check",
                    passed=False,
                    message=f"Suspiciously large binary blob: {size:,} bytes",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={"size": size, "max_allowed": self.max_blob_bytes},
                )

            # Check for embedded executable content in binary data
            try:
                # Try to decode as UTF-8 to check for hidden text
                decoded = value.decode("utf-8", errors="ignore")
                if len(decoded) > 50:  # Only check substantial text
                    self._check_suspicious_strings(
                        decoded,
                        f"{location}[decoded_binary]",
                        result,
                    )
            except Exception:  # pragma: no cover - encoding edge cases
                pass

        elif isinstance(value, str):
            # Check for suspicious string patterns
            self._check_suspicious_strings(value, location, result)

            # Check for very long strings that might be attacks
            if len(value) > 100000:  # 100KB string
                result.add_check(
                    name="String Length Check",
                    passed=False,
                    message=f"Extremely long string found: {len(value):,} characters",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={"length": len(value), "threshold": 100000},
                )

        elif isinstance(value, dict):
            if len(value) > self.max_items_per_container:
                result.add_check(
                    name="Dictionary Size Check",
                    passed=False,
                    message=f"Dictionary with excessive items: {len(value):,}",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={
                        "item_count": len(value),
                        "max_allowed": self.max_items_per_container,
                    },
                )

            for k, v in value.items():
                key_str = str(k)
                self._check_suspicious_keys(key_str, f"{location}/{key_str}", result)

                # Check if key itself contains suspicious patterns
                if isinstance(k, str):
                    self._check_suspicious_strings(k, f"{location}[key:{k}]", result)

                self._analyze_content(v, f"{location}/{key_str}", result, depth + 1)

        elif isinstance(value, (list, tuple)):
            if len(value) > self.max_items_per_container:
                result.add_check(
                    name="Array Size Check",
                    passed=False,
                    message=f"Array with excessive items: {len(value):,}",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={
                        "item_count": len(value),
                        "max_allowed": self.max_items_per_container,
                    },
                )

            for i, v in enumerate(value):
                self._analyze_content(v, f"{location}[{i}]", result, depth + 1)

        elif isinstance(value, (int, float)):
            # Check for suspicious numerical values that might indicate attacks
            if isinstance(value, int) and abs(value) > 2**63:
                result.add_check(
                    name="Integer Value Range Check",
                    passed=False,
                    message=f"Extremely large integer value: {value}",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={"value": value},
                )

    def _analyze_ml_structure(self, obj: Any, result: ScanResult) -> dict[str, Any]:
        """
        Analyze the mathematical and structural properties to determine if this looks like a legitimate ML model.
        Returns analysis results with confidence scores based on actual model characteristics, not naming.
        """
        analysis: dict[str, Any] = {
            "is_ml_model": False,
            "confidence": 0.0,
            "evidence": [],
            "tensor_count": 0,
            "weight_matrices": [],
            "suspicious_patterns": [],
        }

        if not isinstance(obj, dict):
            return analysis

        # Recursively collect all numerical arrays that could be tensors
        def collect_tensors(data: Any, path: str = "") -> list[dict[str, Any]]:
            tensors: list[dict[str, Any]] = []
            if isinstance(data, dict):
                for key, value in data.items():
                    tensors.extend(collect_tensors(value, f"{path}/{key}" if path else key))
            elif isinstance(data, (list, tuple)):
                for i, value in enumerate(data):
                    tensors.extend(collect_tensors(value, f"{path}[{i}]"))
            elif (
                isinstance(data, (bytes, bytearray)) and len(data) >= 16 and (len(data) % 4 == 0 or len(data) % 8 == 0)
            ):
                # Check if binary data could be a serialized tensor
                tensors.append(
                    {
                        "path": path,
                        "size": len(data),
                        "type": "binary_blob",
                        "potential_elements": len(data) // 4,  # Assume float32
                    }
                )
            return tensors

        tensors = collect_tensors(obj)
        analysis["tensor_count"] = len(tensors)

        if len(tensors) == 0:
            analysis["suspicious_patterns"].append("No numerical data found - not a typical ML model")
            return analysis

        # Analyze tensor size patterns
        large_tensors = [t for t in tensors if t["size"] > 1024]  # > 1KB
        if not large_tensors:
            analysis["suspicious_patterns"].append("No substantial weight matrices found")
            return analysis

        # Check for common ML model patterns in tensor sizes
        common_ml_sizes: list[dict[str, Any]] = []
        for tensor in large_tensors:
            size = tensor["size"]
            # Check if size could represent common ML architectures
            elements = size // 4  # Assume float32

            # Look for typical ML matrix dimensions (powers of 2, common vocab sizes, etc.)
            potential_shapes: list[tuple[int, int]] = []
            for dim1 in [64, 128, 256, 512, 768, 1024, 1536, 2048, 4096, 8192]:
                if elements % dim1 == 0:
                    dim2 = elements // dim1
                    if 1 <= dim2 <= 100000:  # Reasonable range for ML dimensions
                        potential_shapes.append((dim1, dim2))

            if potential_shapes:
                common_ml_sizes.append(
                    {
                        "tensor": tensor,
                        "potential_shapes": potential_shapes[:5],  # Limit output
                    }
                )

        if common_ml_sizes:
            analysis["evidence"].append(f"Found {len(common_ml_sizes)} tensors with ML-compatible dimensions")
            analysis["weight_matrices"] = common_ml_sizes
            analysis["confidence"] += 0.4

        # Check for hierarchical structure (multiple layers)
        layer_evidence = 0
        layer_keywords = ["layer", "block", "attention", "ffn", "mlp", "linear", "conv"]

        for keyword in layer_keywords:
            if keyword in str(obj).lower():
                layer_evidence += 1

        if layer_evidence >= 2:
            analysis["evidence"].append(f"Found hierarchical layer structure ({layer_evidence} layer indicators)")
            analysis["confidence"] += 0.5

        # Check for embedding-like structures (large matrices typical of word embeddings)
        embedding_evidence = 0
        for tensor in large_tensors:
            size = tensor["size"]
            elements = size // 4

            # Common embedding sizes: vocab_size x embedding_dim
            # Common vocab sizes: 30522 (BERT), 50257 (GPT-2), 32000 (T5)
            common_vocab_sizes = [30522, 50257, 32000, 28996, 51200]
            common_embed_dims = [128, 256, 384, 512, 768, 1024, 1536, 2048]

            for vocab_size in common_vocab_sizes:
                for embed_dim in common_embed_dims:
                    if abs(elements - (vocab_size * embed_dim)) < (vocab_size * embed_dim * 0.1):  # 10% tolerance
                        embedding_evidence += 1
                        analysis["evidence"].append(f"Found embedding-like matrix: ~{vocab_size}x{embed_dim}")
                        break

        if embedding_evidence > 0:
            analysis["confidence"] += 0.3

        # Penalize suspicious patterns
        suspicious_data = 0
        for tensor in tensors:
            # Check for non-ML-like data patterns
            if tensor["size"] < 100:  # Very small tensors are suspicious for model weights
                suspicious_data += 1
            elif tensor["size"] > 500 * 1024 * 1024:  # Extremely large (>500MB) single tensors
                analysis["suspicious_patterns"].append(
                    f"Extremely large single tensor: {tensor['size'] // 1024 // 1024}MB"
                )
                suspicious_data += 1

        if suspicious_data > len(tensors) * 0.5:  # More than 50% suspicious
            analysis["confidence"] *= 0.5

        # Final confidence calculation
        if analysis["confidence"] >= 0.7:
            analysis["is_ml_model"] = True
            analysis["evidence"].append("High confidence this is a legitimate ML model based on structural analysis")
        elif analysis["confidence"] > 0.4:
            analysis["evidence"].append("Moderate confidence this could be an ML model")
        else:
            analysis["suspicious_patterns"].append("Low confidence in ML model structure - may be malicious data")

        return analysis

    def _validate_flax_structure(self, obj: Any, result: ScanResult) -> None:
        """Validate that the msgpack structure looks like a legitimate Flax checkpoint using structural analysis."""
        if not isinstance(obj, dict):
            result.add_check(
                name="Flax Structure Validation",
                passed=False,
                message=f"Unexpected top-level type: {type(obj).__name__} (expected dict)",
                severity=IssueSeverity.WARNING,
                location="root",
                details={"actual_type": type(obj).__name__, "expected_type": "dict"},
            )
            return

        # Check for standard Flax checkpoint patterns first
        expected_keys = {"params", "state", "opt_state", "model_state", "step", "epoch"}
        found_keys = set(obj.keys()) if isinstance(obj, dict) else set()

        # Also check for common transformer model patterns (BERT, GPT, T5, etc.)
        transformer_keys = {"embeddings", "encoder", "decoder", "pooler", "lm_head", "transformer", "model"}
        has_transformer_keys = any(key in found_keys for key in transformer_keys)

        has_standard_flax_keys = any(key in found_keys for key in expected_keys)

        if has_standard_flax_keys:
            # This looks like a standard Flax checkpoint
            result.add_check(
                name="Flax Checkpoint Format Detection",
                passed=True,
                message="Standard Flax checkpoint format detected",
                location="root",
                details={
                    "found_standard_keys": [k for k in expected_keys if k in found_keys],
                    "model_type": "standard_flax",
                },
            )
            return

        # Check if this is a transformer model (BERT, GPT, T5, etc.)
        if has_transformer_keys:
            # This looks like a transformer model checkpoint
            result.add_check(
                name="Model Format Detection",
                passed=True,
                message="Transformer model format detected (BERT/GPT/T5 style)",
                location="root",
                details={
                    "found_transformer_keys": [k for k in transformer_keys if k in found_keys],
                    "model_type": "transformer_model",
                    "all_keys": list(found_keys)[:20],  # Show first 20 keys
                },
            )
            return

        # If no standard keys, perform deep structural analysis
        ml_analysis = self._analyze_ml_structure(obj, result)

        if ml_analysis["is_ml_model"]:
            # High confidence legitimate ML model based on structural analysis
            result.add_check(
                name="ML Model Detection",
                passed=True,
                message=f"Converted ML model detected (confidence: {ml_analysis['confidence']:.2f})",
                location="root",
                details={
                    "analysis": ml_analysis,
                    "model_type": "converted_ml_model",
                    "structural_evidence": ml_analysis["evidence"],
                },
            )
        elif ml_analysis["confidence"] > 0.4:
            # Moderate confidence - flag for review but don't alarm
            result.add_check(
                name="ML Model Detection",
                passed=True,
                message=f"Possible ML model with moderate confidence ({ml_analysis['confidence']:.2f})",
                location="root",
                details={
                    "analysis": ml_analysis,
                    "model_type": "possible_ml_model",
                    "recommendation": "Manual review recommended",
                },
            )
        else:
            # Low confidence - this is suspicious
            result.add_check(
                name="ML Model Pattern Validation",
                passed=False,
                message="Suspicious data structure - does not match known ML model patterns",
                severity=IssueSeverity.WARNING,
                location="root",
                details={
                    "analysis": ml_analysis,
                    "found_keys": list(found_keys)[:20],
                    "expected_any_of": list(expected_keys),
                    "model_type": "suspicious",
                    "suspicious_patterns": ml_analysis["suspicious_patterns"],
                },
            )

        # Always check for truly suspicious top-level keys regardless of ML confidence
        dangerous_keys = {
            "__class__",
            "__module__",
            "__reduce__",
            "__getstate__",
            "__setstate__",
            "__dict__",
            "__code__",
            "__globals__",
            "__builtins__",
            "__import__",
            "eval",
            "exec",
            "subprocess",
            "os",
            "system",
        }

        suspicious_top_level = found_keys & dangerous_keys
        if suspicious_top_level:
            result.add_check(
                name="Top-Level Key Security Check",
                passed=False,
                message=f"Dangerous top-level keys detected: {suspicious_top_level}",
                severity=IssueSeverity.CRITICAL,
                location="root",
                details={"dangerous_keys": list(suspicious_top_level)},
            )

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        self.current_file_path = path

        if not HAS_MSGPACK:
            result.add_check(
                name="msgpack Library Check",
                passed=False,
                message="msgpack library not installed - cannot analyze Flax checkpoints",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"required_package": "msgpack"},
            )
            result.finish(success=False)
            return result

        try:
            self.current_file_path = path

            # Read entire file to check for trailing data
            with open(path, "rb") as f:
                file_data = f.read()

            # Try to unpack and detect trailing data
            try:
                obj = msgpack.unpackb(file_data, raw=False, strict_map_key=False)
                # If we get here, the entire file was valid msgpack - no trailing data
            except msgpack.exceptions.ExtraData:
                # This means there's extra data after valid msgpack
                result.add_check(
                    name="Msgpack Stream Integrity Check",
                    passed=False,
                    message="Extra trailing data found after msgpack content",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"has_trailing_data": True},
                )
                # Unpack just the first object
                unpacker = msgpack.Unpacker(None, raw=False, strict_map_key=False)
                unpacker.feed(file_data)
                obj = unpacker.unpack()
            except (
                msgpack.exceptions.UnpackException,
                msgpack.exceptions.OutOfData,
            ) as e:
                result.add_check(
                    name="Msgpack Format Validation",
                    passed=False,
                    message=f"Invalid msgpack format: {e!s}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"msgpack_error": str(e)},
                )
                result.finish(success=False)
                return result

            # Record metadata
            result.metadata["top_level_type"] = type(obj).__name__
            if isinstance(obj, dict):
                result.metadata["top_level_keys"] = list(obj.keys())[:50]  # Limit for large dicts
                result.metadata["key_count"] = len(obj.keys())

            # Extract JAX/Flax specific metadata and architecture information
            self._extract_jax_metadata(obj, result)

            # Validate Flax structure with enhanced analysis
            self._validate_flax_structure(obj, result)

            # Check for JAX/Flax specific security threats
            self._check_jax_specific_threats(obj, result)

            # Perform deep security analysis
            self._analyze_content(obj, "root", result)

            result.bytes_scanned = file_size
        except MemoryError:
            result.add_check(
                name="File Size Safety Check",
                passed=False,
                message="File too large to process safely - potential memory exhaustion attack",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_check(
                name="Flax Msgpack Processing",
                passed=False,
                message=f"Unexpected error processing Flax msgpack file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error_type": type(e).__name__, "error_message": str(e)},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
