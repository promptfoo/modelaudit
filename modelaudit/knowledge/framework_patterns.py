"""Framework-specific pattern knowledge base for reducing false positives."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class FrameworkType(Enum):
    """Supported ML frameworks."""

    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    KERAS = "keras"
    SKLEARN = "sklearn"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    ONNX = "onnx"
    JAX = "jax"
    PADDLE = "paddle"
    MXNET = "mxnet"


@dataclass
class FrameworkPattern:
    """Pattern specific to a framework."""

    pattern: str
    pattern_type: str  # 'module', 'function', 'attribute', 'file_structure'
    is_safe: bool
    context: str
    risk_level: str  # 'safe', 'low', 'medium', 'high'
    explanation: str


class FrameworkKnowledgeBase:
    """Knowledge base of framework-specific patterns."""

    def __init__(self):
        self._build_knowledge_base()

    def _build_knowledge_base(self):
        """Build comprehensive framework-specific patterns."""
        self.patterns = {
            FrameworkType.PYTORCH: self._build_pytorch_patterns(),
            FrameworkType.TENSORFLOW: self._build_tensorflow_patterns(),
            FrameworkType.KERAS: self._build_keras_patterns(),
            FrameworkType.SKLEARN: self._build_sklearn_patterns(),
            FrameworkType.JAX: self._build_jax_patterns(),
        }

        # Safe operations by framework
        self.safe_operations = {
            FrameworkType.PYTORCH: {
                "torch.load",
                "torch.save",
                "torch.jit.load",
                "torch.jit.save",
                "torch.onnx.export",
                "torch.utils.data.DataLoader",
                "torch.nn.Module",
                "torch.optim",
                "torch.cuda",
                "pickle.load",
                "pickle.dump",  # When used with torch objects
            },
            FrameworkType.TENSORFLOW: {
                "tf.saved_model.load",
                "tf.saved_model.save",
                "tf.keras.models.load_model",
                "tf.keras.models.save_model",
                "tf.lite.TFLiteConverter",
                "tf.data.Dataset",
                "tf.function",
                "tf.Variable",
                "tf.GradientTape",
            },
            FrameworkType.SKLEARN: {
                "joblib.load",
                "joblib.dump",
                "pickle.load",
                "pickle.dump",
                "sklearn.externals.joblib",
                "sklearn.model_selection",
                "sklearn.preprocessing",
                "sklearn.pipeline.Pipeline",
            },
        }

        # Common false positive patterns
        self.false_positive_patterns = {
            # Documentation strings
            "doc_strings": [
                r"['\"]{3}.*eval\(\).*['\"]{3}",  # Docstrings mentioning eval
                r"#.*\beval\b.*",  # Comments about eval
                r"help\(.*eval.*\)",  # Help text
            ],
            # Variable names
            "variable_names": [
                r"\beval_[a-zA-Z_]+\b",  # eval_metrics, eval_loss, etc.
                r"\bexec_[a-zA-Z_]+\b",  # exec_time, exec_count, etc.
                r"[a-zA-Z_]+_eval\b",  # model_eval, train_eval, etc.
            ],
            # ML-specific patterns
            "ml_operations": [
                r"model\.eval\(\)",  # PyTorch evaluation mode
                r"\.evaluate\(",  # Model evaluation
                r"eval_dataset",  # Evaluation dataset
                r"evaluation_strategy",  # Training argument
            ],
            # String literals that aren't code
            "string_literals": [
                r"['\"].*os\.system.*['\"].*['\"]",  # Nested quotes indicate string
                r"logging\..*['\"].*eval.*['\"]",  # Log messages
                r"print\(.*['\"].*exec.*['\"]",  # Print statements
            ],
        }

        # Architecture-specific patterns
        self.architecture_patterns = {
            "transformer": {
                "layers": ["attention", "multi_head_attention", "position_embedding", "layer_norm", "feed_forward"],
                "params": ["num_heads", "hidden_size", "num_layers", "max_position_embeddings"],
                "safe_lambdas": ["lambda x: x * 0.5", "lambda x: torch.sqrt(x)"],  # Common in attention
            },
            "cnn": {
                "layers": ["conv2d", "maxpool2d", "batchnorm2d", "dropout2d"],
                "params": ["kernel_size", "stride", "padding", "dilation"],
                "safe_lambdas": ["lambda x: F.relu(x)", "lambda x: x.view(-1)"],
            },
            "rnn": {
                "layers": ["lstm", "gru", "rnn", "embedding"],
                "params": ["hidden_size", "num_layers", "bidirectional", "dropout"],
                "safe_lambdas": ["lambda x: x.squeeze()", "lambda x: x.unsqueeze(0)"],
            },
        }

    def _build_pytorch_patterns(self) -> list[FrameworkPattern]:
        """PyTorch-specific patterns."""
        return [
            # Safe patterns
            FrameworkPattern(
                pattern="torch.load",
                pattern_type="function",
                is_safe=True,
                context="model_loading",
                risk_level="safe",
                explanation="Standard PyTorch model loading",
            ),
            FrameworkPattern(
                pattern="pickle.load.*torch",
                pattern_type="function",
                is_safe=True,
                context="model_loading",
                risk_level="safe",
                explanation="Pickle used for PyTorch serialization",
            ),
            FrameworkPattern(
                pattern="torch.jit.load",
                pattern_type="function",
                is_safe=True,
                context="jit_loading",
                risk_level="safe",
                explanation="TorchScript model loading",
            ),
            FrameworkPattern(
                pattern="model.eval()",
                pattern_type="function",
                is_safe=True,
                context="model_evaluation",
                risk_level="safe",
                explanation="Setting model to evaluation mode",
            ),
            # Patterns that need context
            FrameworkPattern(
                pattern="__reduce__",
                pattern_type="attribute",
                is_safe=False,
                context="serialization",
                risk_level="medium",
                explanation="Can be exploited but commonly used in PyTorch",
            ),
            FrameworkPattern(
                pattern="Lambda",
                pattern_type="module",
                is_safe=False,
                context="layer_definition",
                risk_level="low",
                explanation="Lambda layers are common in PyTorch models",
            ),
        ]

    def _build_tensorflow_patterns(self) -> list[FrameworkPattern]:
        """TensorFlow-specific patterns."""
        return [
            # Safe patterns
            FrameworkPattern(
                pattern="tf.saved_model.load",
                pattern_type="function",
                is_safe=True,
                context="model_loading",
                risk_level="safe",
                explanation="Standard TensorFlow SavedModel loading",
            ),
            FrameworkPattern(
                pattern="tf.keras.models.load_model",
                pattern_type="function",
                is_safe=True,
                context="model_loading",
                risk_level="safe",
                explanation="Keras model loading in TensorFlow",
            ),
            FrameworkPattern(
                pattern="tf.function",
                pattern_type="decorator",
                is_safe=True,
                context="graph_compilation",
                risk_level="safe",
                explanation="TensorFlow function compilation",
            ),
            # Patterns needing context
            FrameworkPattern(
                pattern="tf.py_function",
                pattern_type="function",
                is_safe=False,
                context="custom_operation",
                risk_level="medium",
                explanation="Executes Python code in TF graph",
            ),
        ]

    def _build_keras_patterns(self) -> list[FrameworkPattern]:
        """Keras-specific patterns."""
        return [
            FrameworkPattern(
                pattern="Lambda",
                pattern_type="layer",
                is_safe=False,
                context="custom_layer",
                risk_level="medium",
                explanation="Lambda layers can contain arbitrary code",
            ),
            FrameworkPattern(
                pattern="model.load_weights",
                pattern_type="function",
                is_safe=True,
                context="weight_loading",
                risk_level="safe",
                explanation="Standard Keras weight loading",
            ),
        ]

    def _build_sklearn_patterns(self) -> list[FrameworkPattern]:
        """Scikit-learn specific patterns."""
        return [
            FrameworkPattern(
                pattern="joblib.load",
                pattern_type="function",
                is_safe=True,
                context="model_loading",
                risk_level="safe",
                explanation="Standard sklearn model loading",
            ),
            FrameworkPattern(
                pattern="pickle.*sklearn",
                pattern_type="function",
                is_safe=True,
                context="model_serialization",
                risk_level="safe",
                explanation="Pickle used for sklearn models",
            ),
        ]

    def _build_jax_patterns(self) -> list[FrameworkPattern]:
        """JAX-specific patterns."""
        return [
            FrameworkPattern(
                pattern="flax.serialization",
                pattern_type="module",
                is_safe=True,
                context="model_serialization",
                risk_level="safe",
                explanation="Flax serialization for JAX models",
            ),
            FrameworkPattern(
                pattern="jax.tree_util",
                pattern_type="module",
                is_safe=True,
                context="tree_operations",
                risk_level="safe",
                explanation="JAX tree utilities for nested structures",
            ),
        ]

    def is_pattern_safe_in_framework(
        self, pattern: str, framework: FrameworkType, context: dict[str, Any]
    ) -> tuple[bool, str]:
        """Check if a pattern is safe within a specific framework context."""
        if framework not in self.patterns:
            return False, "Unknown framework"

        # Check framework-specific patterns
        for fw_pattern in self.patterns[framework]:
            if re.search(fw_pattern.pattern, pattern, re.IGNORECASE):
                if fw_pattern.is_safe:
                    return True, fw_pattern.explanation
                else:
                    # Check additional context
                    if self._validate_context(fw_pattern, context):
                        return True, f"{fw_pattern.explanation} (validated in context)"

        # Check if it's a known safe operation
        if framework in self.safe_operations and pattern in self.safe_operations[framework]:
            return True, f"Known safe operation in {framework.value}"

        # Check false positive patterns
        for category, patterns in self.false_positive_patterns.items():
            for fp_pattern in patterns:
                if re.search(fp_pattern, pattern):
                    return True, f"False positive: {category}"

        return False, "Pattern not recognized as safe"

    def _validate_context(self, pattern: FrameworkPattern, context: dict[str, Any]) -> bool:
        """Validate pattern safety based on context."""
        # Check if we're in the right context
        if pattern.context not in str(context):
            return False

        # Additional validation based on pattern type
        if pattern.pattern_type == "layer" and pattern.pattern == "Lambda":
            # Check if Lambda contains safe operations
            lambda_code = context.get("lambda_code", "")
            if lambda_code:
                # Check against known safe lambda patterns
                for _arch, arch_patterns in self.architecture_patterns.items():
                    if any(safe_lambda in lambda_code for safe_lambda in arch_patterns.get("safe_lambdas", [])):
                        return True

        return pattern.risk_level in ["safe", "low"]

    def get_framework_from_imports(self, imports: list[str]) -> Optional[FrameworkType]:
        """Detect framework from import statements."""
        import_str = " ".join(imports).lower()

        framework_indicators = {
            FrameworkType.PYTORCH: ["torch", "torchvision", "pytorch"],
            FrameworkType.TENSORFLOW: ["tensorflow", "tf.", "keras"],
            FrameworkType.SKLEARN: ["sklearn", "scikit-learn", "joblib"],
            FrameworkType.JAX: ["jax", "flax", "haiku"],
            FrameworkType.XGBOOST: ["xgboost", "xgb"],
            FrameworkType.LIGHTGBM: ["lightgbm", "lgb"],
            FrameworkType.PADDLE: ["paddle", "paddlepaddle"],
            FrameworkType.MXNET: ["mxnet", "mx."],
        }

        scores = {}
        for framework, indicators in framework_indicators.items():
            score = sum(1 for ind in indicators if ind in import_str)
            if score > 0:
                scores[framework] = score

        if scores:
            return max(scores, key=lambda k: scores[k])

        return None

    def get_safe_alternatives(self, dangerous_pattern: str, framework: FrameworkType) -> list[str]:
        """Suggest safe alternatives to dangerous patterns."""
        alternatives = {
            "eval": {
                FrameworkType.PYTORCH: [
                    "Use torch.jit.script for dynamic computation",
                    "Use torch.compile for optimization",
                    "Define functions explicitly instead of eval",
                ],
                FrameworkType.TENSORFLOW: [
                    "Use tf.function for dynamic computation",
                    "Use tf.keras.layers.Lambda with explicit functions",
                    "Use tf.py_function with careful validation",
                ],
            },
            "pickle.load": {
                FrameworkType.PYTORCH: [
                    "Use torch.load with map_location specified",
                    "Use torch.jit.load for TorchScript models",
                    "Validate file source before loading",
                ],
                FrameworkType.SKLEARN: [
                    "Use joblib.load instead of pickle",
                    "Implement model versioning",
                    "Validate model source before loading",
                ],
            },
            "__reduce__": {
                FrameworkType.PYTORCH: [
                    "Use state_dict() for saving model weights only",
                    "Use TorchScript for model serialization",
                    "Implement custom serialization without __reduce__",
                ],
            },
        }

        pattern_key = None
        for key in alternatives:
            if key in dangerous_pattern:
                pattern_key = key
                break

        if pattern_key and framework in alternatives.get(pattern_key, {}):
            return alternatives[pattern_key][framework]

        return ["Consider using framework-specific serialization methods"]

    def should_skip_pattern_for_framework(
        self, pattern: str, framework: FrameworkType, file_context: dict[str, Any]
    ) -> bool:
        """Determine if a pattern check should be skipped for a framework."""
        # Framework-specific skips
        skip_rules = {
            FrameworkType.PYTORCH: {
                "model.eval()": True,  # Always safe
                "pickle.*state_dict": True,  # State dict pickling is safe
                "torch.load.*map_location": True,  # Safe loading pattern
            },
            FrameworkType.TENSORFLOW: {
                "tf.function": True,
                "model.evaluate": True,
                "tf.saved_model": True,
            },
            FrameworkType.SKLEARN: {
                "joblib.load": True,
                "Pipeline": True,
                "cross_val": True,
            },
        }

        if framework in skip_rules:
            for skip_pattern, should_skip in skip_rules[framework].items():
                if re.search(skip_pattern, pattern, re.IGNORECASE) and should_skip:
                    return True

        # Check if pattern appears in safe context
        safe_contexts = ["test_", "eval_", "validate_", "benchmark_"]
        if any(ctx in str(file_context.get("filename", "")).lower() for ctx in safe_contexts):
            # More lenient in test files
            return pattern in ["eval", "exec", "assert"]

        return False
