"""Unified context system for sharing intelligence across scanners."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class ModelArchitecture(Enum):
    """Known ML model architectures."""

    UNKNOWN = "unknown"
    TRANSFORMER = "transformer"
    CNN = "cnn"
    RNN = "rnn"
    GAN = "gan"
    DIFFUSION = "diffusion"
    VISION_TRANSFORMER = "vit"
    BERT_LIKE = "bert"
    GPT_LIKE = "gpt"
    RESNET_LIKE = "resnet"
    UNET = "unet"


@dataclass
class TensorInfo:
    """Information about a tensor in the model."""

    name: str
    shape: tuple[int, ...]
    dtype: str
    parameter_count: int
    statistics: dict[str, float] = field(default_factory=dict)  # mean, std, min, max, entropy


@dataclass
class LayerPattern:
    """Pattern information for a model layer."""

    layer_type: str
    parameter_names: list[str]
    activation_functions: list[str]
    has_batch_norm: bool = False
    has_dropout: bool = False


@dataclass
class UnifiedMLContext:
    """Unified context shared across all scanners."""

    # Basic info
    file_path: Path
    file_size: int
    file_type: str

    # ML Framework detection
    frameworks: dict[str, float] = field(default_factory=dict)  # framework -> confidence
    primary_framework: Optional[str] = None
    framework_version: Optional[str] = None

    # Architecture analysis
    architecture: ModelArchitecture = ModelArchitecture.UNKNOWN
    architecture_confidence: float = 0.0
    layer_patterns: list[LayerPattern] = field(default_factory=list)

    # Tensor/Weight analysis
    tensors: list[TensorInfo] = field(default_factory=list)
    total_parameters: int = 0
    weight_statistics: dict[str, list[float]] = field(default_factory=dict)

    # Pattern analysis
    suspicious_patterns_found: set[str] = field(default_factory=set)
    safe_patterns_found: set[str] = field(default_factory=set)
    pattern_locations: dict[str, list[int]] = field(default_factory=dict)

    # Risk scoring
    risk_factors: dict[str, float] = field(default_factory=dict)
    confidence_adjustments: dict[str, float] = field(default_factory=dict)

    # Binary analysis
    has_weight_structure: bool = False
    entropy_score: float = 0.0
    float_pattern_ratio: float = 0.0

    # Code analysis results
    validated_code_blocks: list[dict[str, Any]] = field(default_factory=list)

    def get_adjusted_severity(self, base_severity: float, pattern: str) -> float:
        """Get severity adjusted for ML context."""
        # Start with base severity
        severity = base_severity

        # Apply framework-specific adjustments
        if self.primary_framework:
            framework_adjustment = self.confidence_adjustments.get(f"{self.primary_framework}_{pattern}", 0.0)
            severity *= 1.0 - framework_adjustment

        # Apply architecture-specific adjustments
        if self.architecture != ModelArchitecture.UNKNOWN:
            arch_adjustment = self.confidence_adjustments.get(f"{self.architecture.value}_{pattern}", 0.0)
            severity *= 1.0 - arch_adjustment

        # Apply weight structure adjustments
        if self.has_weight_structure and self.float_pattern_ratio > 0.8:
            severity *= 0.5  # Halve severity for clear weight files

        return severity

    def is_known_safe_pattern(self, pattern: str, context: str) -> bool:
        """Check if a pattern is known to be safe in this context."""
        # Check framework-specific safe patterns
        safe_key = f"{self.primary_framework}:{context}:{pattern}"
        if safe_key in self.safe_patterns_found:
            return True

        # Check architecture-specific safe patterns
        if self.architecture != ModelArchitecture.UNKNOWN:
            arch_safe_key = f"{self.architecture.value}:{context}:{pattern}"
            if arch_safe_key in self.safe_patterns_found:
                return True

        return False

    def add_tensor_info(self, tensor: TensorInfo):
        """Add tensor information and update statistics."""
        self.tensors.append(tensor)
        self.total_parameters += tensor.parameter_count

        # Update weight statistics
        if tensor.statistics:
            for key, value in tensor.statistics.items():
                if key not in self.weight_statistics:
                    self.weight_statistics[key] = []
                self.weight_statistics[key].append(value)

    def analyze_architecture_patterns(self):
        """Analyze layer patterns to determine architecture."""
        # Count layer types
        layer_type_counts = {}
        for pattern in self.layer_patterns:
            layer_type_counts[pattern.layer_type] = layer_type_counts.get(pattern.layer_type, 0) + 1

        # Transformer detection
        transformer_indicators = ["attention", "multi_head", "position", "embedding"]
        transformer_score = sum(
            1
            for indicator in transformer_indicators
            if any(indicator in str(layer.layer_type).lower() for layer in self.layer_patterns)
        )

        # CNN detection
        cnn_indicators = ["conv", "pool", "batch_norm"]
        cnn_score = sum(
            1
            for indicator in cnn_indicators
            if any(indicator in str(layer.layer_type).lower() for layer in self.layer_patterns)
        )

        # Determine architecture
        if transformer_score >= 3:
            self.architecture = ModelArchitecture.TRANSFORMER
            self.architecture_confidence = min(transformer_score / 4.0, 1.0)
        elif cnn_score >= 2:
            self.architecture = ModelArchitecture.CNN
            self.architecture_confidence = min(cnn_score / 3.0, 1.0)

        # Specific architecture detection
        if "bert" in str(self.layer_patterns).lower():
            self.architecture = ModelArchitecture.BERT_LIKE
            self.architecture_confidence = 0.9
        elif "gpt" in str(self.layer_patterns).lower():
            self.architecture = ModelArchitecture.GPT_LIKE
            self.architecture_confidence = 0.9

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on all factors."""
        base_risk = sum(self.risk_factors.values())

        # Apply mitigations
        if self.has_weight_structure:
            base_risk *= 0.7

        if self.architecture != ModelArchitecture.UNKNOWN:
            base_risk *= 0.8

        if self.primary_framework in ["pytorch", "tensorflow", "keras"]:
            base_risk *= 0.9

        return min(base_risk, 1.0)
