"""ML framework context analysis for reducing false positives.

This module provides context-aware analysis of ML framework operations to distinguish
legitimate model operations from security threats, significantly reducing false
positive rates in ML model scanning.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class MLFramework(Enum):
    """Supported ML frameworks."""

    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    SKLEARN = "sklearn"
    KERAS = "keras"
    NUMPY = "numpy"
    UNKNOWN = "unknown"


class OperationRisk(Enum):
    """Risk levels for ML operations."""

    SAFE = "safe"  # Standard ML operations
    SUSPICIOUS = "suspicious"  # Unusual but potentially legitimate
    DANGEROUS = "dangerous"  # High risk operations


@dataclass
class MLOperation:
    """Represents an identified ML framework operation."""

    framework: MLFramework
    operation_type: str
    function_name: str
    risk_level: OperationRisk
    description: str
    legitimate_use_cases: list[str]


@dataclass
class MLContextResult:
    """Result of ML context analysis."""

    framework: MLFramework
    operation: MLOperation | None
    confidence: float
    risk_adjustment: float  # Multiplier for base risk (0.1 = 90% reduction)
    explanation: str


class MLContextAnalyzer:
    """Analyzes ML framework context to reduce false positives.

    This analyzer identifies legitimate ML framework operations and adjusts
    risk scores accordingly, helping distinguish between model loading and
    malicious code execution.
    """

    def __init__(self):
        """Initialize ML context analyzer."""
        self.ml_operations: list[MLOperation] = self._initialize_ml_operations()
        self.framework_patterns: dict[MLFramework, list[str]] = self._initialize_framework_patterns()

    def _initialize_ml_operations(self) -> list[MLOperation]:
        """Initialize known legitimate ML operations."""
        return [
            # PyTorch operations
            MLOperation(
                framework=MLFramework.PYTORCH,
                operation_type="model_loading",
                function_name="torch.load",
                risk_level=OperationRisk.SAFE,
                description="Standard PyTorch model loading",
                legitimate_use_cases=["Loading pre-trained models", "Checkpoint restoration"],
            ),
            MLOperation(
                framework=MLFramework.PYTORCH,
                operation_type="tensor_ops",
                function_name="torch.tensor",
                risk_level=OperationRisk.SAFE,
                description="Tensor creation and manipulation",
                legitimate_use_cases=["Data preprocessing", "Model inference"],
            ),
            MLOperation(
                framework=MLFramework.PYTORCH,
                operation_type="model_construction",
                function_name="torch.nn.Module",
                risk_level=OperationRisk.SAFE,
                description="Neural network module construction",
                legitimate_use_cases=["Model architecture definition", "Layer composition"],
            ),
            MLOperation(
                framework=MLFramework.PYTORCH,
                operation_type="data_structure",
                function_name="collections.OrderedDict",
                risk_level=OperationRisk.SAFE,
                description="OrderedDict construction for model state_dict",
                legitimate_use_cases=["PyTorch state_dict container", "Model parameter storage"],
            ),
            # TensorFlow operations
            MLOperation(
                framework=MLFramework.TENSORFLOW,
                operation_type="model_loading",
                function_name="tf.saved_model.load",
                risk_level=OperationRisk.SAFE,
                description="TensorFlow SavedModel loading",
                legitimate_use_cases=["Loading exported models", "Model serving"],
            ),
            MLOperation(
                framework=MLFramework.TENSORFLOW,
                operation_type="tensor_ops",
                function_name="tf.constant",
                risk_level=OperationRisk.SAFE,
                description="TensorFlow tensor operations",
                legitimate_use_cases=["Data manipulation", "Constant definitions"],
            ),
            # Scikit-learn operations
            MLOperation(
                framework=MLFramework.SKLEARN,
                operation_type="model_loading",
                function_name="sklearn.externals.joblib.load",
                risk_level=OperationRisk.SAFE,
                description="Scikit-learn model loading via joblib",
                legitimate_use_cases=["Loading trained models", "Pipeline restoration"],
            ),
            # NumPy operations
            MLOperation(
                framework=MLFramework.NUMPY,
                operation_type="array_ops",
                function_name="numpy.array",
                risk_level=OperationRisk.SAFE,
                description="NumPy array operations",
                legitimate_use_cases=["Data manipulation", "Numerical computations"],
            ),
            # Suspicious but potentially legitimate operations
            MLOperation(
                framework=MLFramework.PYTORCH,
                operation_type="compilation",
                function_name="torch.jit.compile",
                risk_level=OperationRisk.SUSPICIOUS,
                description="PyTorch JIT compilation",
                legitimate_use_cases=["Model optimization", "Performance improvement"],
            ),
            MLOperation(
                framework=MLFramework.PYTORCH,
                operation_type="dynamic_import",
                function_name="importlib.import_module",
                risk_level=OperationRisk.SUSPICIOUS,
                description="Dynamic module import (common in ML frameworks)",
                legitimate_use_cases=["Plugin loading", "Optional dependencies"],
            ),
        ]

    def _initialize_framework_patterns(self) -> dict[MLFramework, list[str]]:
        """Initialize regex patterns for framework detection."""
        return {
            MLFramework.PYTORCH: [
                r"\btorch\.",
                r"\btorch\.nn\.",
                r"\btorch\.optim\.",
                r"\btorch\.utils\.",
                r"\btorch\.jit\.",
                r"\.state_dict\(\)",
                r"\.load_state_dict\(",
                r"OrderedDict",  # Common in PyTorch state dicts
            ],
            MLFramework.TENSORFLOW: [
                r"\btf\.",
                r"\btensorflow\.",
                r"\.SavedModel",
                r"\.pb$",  # Protocol buffer files
                r"saved_model\.load",
                r"keras\.",
            ],
            MLFramework.SKLEARN: [
                r"\bsklearn\.",
                r"\.fit\(",
                r"\.predict\(",
                r"\.transform\(",
                r"joblib\.load",
                r"pickle\.load",  # sklearn models are often pickled
            ],
            MLFramework.NUMPY: [
                r"\bnumpy\.",
                r"\bnp\.",
                r"\.npy$",
                r"\.npz$",
                r"\.array\(",
                r"\.ndarray",
            ],
        }

    def analyze_context(
        self, function_call: str, stack_context: list[str], file_context: str | None = None
    ) -> MLContextResult:
        """Analyze ML context for a function call.

        Args:
            function_call: The function being called (e.g., "os.system")
            stack_context: Recent stack operations for context
            file_context: Additional file-level context if available

        Returns:
            MLContextResult with framework detection and risk adjustment
        """
        # Detect framework from various contexts
        detected_framework = self._detect_framework(function_call, stack_context, file_context)

        # Find matching ML operation
        ml_operation = self._identify_operation(function_call, detected_framework)

        # Calculate confidence and risk adjustment
        confidence = self._calculate_confidence(detected_framework, ml_operation, stack_context)
        risk_adjustment = self._calculate_risk_adjustment(ml_operation, confidence)

        # Generate explanation
        explanation = self._generate_explanation(detected_framework, ml_operation, function_call)

        return MLContextResult(
            framework=detected_framework,
            operation=ml_operation,
            confidence=confidence,
            risk_adjustment=risk_adjustment,
            explanation=explanation,
        )

    def _detect_framework(
        self, function_call: str, stack_context: list[str], file_context: str | None = None
    ) -> MLFramework:
        """Detect ML framework from context."""
        framework_scores: dict[MLFramework, float] = {framework: 0.0 for framework in MLFramework}  # noqa: C420

        # Analyze function call
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, function_call, re.IGNORECASE):
                    framework_scores[framework] += 2

        # Analyze stack context
        context_text = " ".join(stack_context)
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, context_text, re.IGNORECASE))
                framework_scores[framework] += matches

        # Analyze file context if available
        if file_context:
            for framework, patterns in self.framework_patterns.items():
                for pattern in patterns:
                    matches = len(re.findall(pattern, file_context, re.IGNORECASE))
                    framework_scores[framework] += matches * 0.5  # Lower weight

        # Return framework with highest score
        max_score = max(framework_scores.values())
        if max_score > 0:
            for framework, score in framework_scores.items():
                if score == max_score:
                    return framework

        return MLFramework.UNKNOWN

    def _identify_operation(self, function_call: str, framework: MLFramework) -> MLOperation | None:
        """Identify specific ML operation."""
        # Direct function name match
        for operation in self.ml_operations:
            if operation.framework == framework and operation.function_name in function_call:
                return operation

        # Pattern-based matching for broader operations
        for operation in self.ml_operations:
            if operation.framework == framework and (
                (
                    operation.operation_type == "model_loading"
                    and any(keyword in function_call.lower() for keyword in ["load", "restore", "checkpoint"])
                )
                or (
                    operation.operation_type == "tensor_ops"
                    and any(keyword in function_call.lower() for keyword in ["tensor", "array", "constant"])
                )
            ):
                return operation

        return None

    def _calculate_confidence(
        self, framework: MLFramework, operation: MLOperation | None, stack_context: list[str]
    ) -> float:
        """Calculate confidence in ML context detection."""
        if framework == MLFramework.UNKNOWN:
            return 0.0

        base_confidence = 0.6

        # Higher confidence if we identified specific operation
        if operation:
            base_confidence += 0.2

        # Higher confidence with more ML framework indicators in stack
        ml_indicators = 0
        context_text = " ".join(stack_context).lower()

        ml_keywords = [
            "model",
            "tensor",
            "layer",
            "weight",
            "bias",
            "parameter",
            "optimizer",
            "loss",
            "gradient",
            "batch",
            "epoch",
            "train",
            "inference",
            "predict",
            "classify",
            "embedding",
        ]

        for keyword in ml_keywords:
            if keyword in context_text:
                ml_indicators += 1

        # Boost confidence based on ML indicators (up to 0.2 bonus)
        confidence_boost = min(ml_indicators * 0.02, 0.2)

        return min(base_confidence + confidence_boost, 1.0)

    def _calculate_risk_adjustment(self, operation: MLOperation | None, confidence: float) -> float:
        """Calculate risk adjustment factor based on ML context."""
        if not operation or confidence < 0.3:
            return 1.0  # No adjustment for low confidence

        # Base adjustments by operation risk level
        base_adjustments = {
            OperationRisk.SAFE: 0.1,  # 90% risk reduction
            OperationRisk.SUSPICIOUS: 0.5,  # 50% risk reduction
            OperationRisk.DANGEROUS: 0.8,  # 20% risk reduction
        }

        base_adjustment = base_adjustments.get(operation.risk_level, 1.0)

        # Scale by confidence (higher confidence = more reduction)
        risk_adjustment = base_adjustment + (1.0 - base_adjustment) * (1.0 - confidence)

        return max(risk_adjustment, 0.05)  # Minimum 5% of original risk

    def _generate_explanation(self, framework: MLFramework, operation: MLOperation | None, function_call: str) -> str:
        """Generate human-readable explanation."""
        if framework == MLFramework.UNKNOWN:
            return f"Function '{function_call}' does not appear to be an ML framework operation"

        if operation:
            if operation.risk_level == OperationRisk.SAFE:
                return (
                    f"Function '{function_call}' appears to be a legitimate {framework.value} "
                    f"operation ({operation.description}). Risk significantly reduced."
                )
            elif operation.risk_level == OperationRisk.SUSPICIOUS:
                return (
                    f"Function '{function_call}' is a {framework.value} operation but could be "
                    f"misused ({operation.description}). Risk moderately reduced."
                )
            else:
                return (
                    f"Function '{function_call}' is a potentially dangerous {framework.value} "
                    f"operation ({operation.description}). Risk slightly reduced."
                )
        else:
            return (
                f"Function '{function_call}' appears related to {framework.value} but specific "
                f"operation not recognized. Risk moderately reduced."
            )

    def is_ml_context(self, function_call: str, stack_context: list[str]) -> bool:
        """Quick check if this appears to be ML context."""
        result = self.analyze_context(function_call, stack_context)
        return result.framework != MLFramework.UNKNOWN and result.confidence > 0.4
