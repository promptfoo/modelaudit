"""Tests for unified context module."""

from pathlib import Path

import pytest

from modelaudit.context.unified_context import (
    LayerPattern,
    ModelArchitecture,
    TensorInfo,
    UnifiedMLContext,
)


class TestModelArchitecture:
    """Tests for ModelArchitecture enum."""

    def test_all_architectures_defined(self):
        """Test that all expected architectures are defined."""
        archs = [a.value for a in ModelArchitecture]
        assert "unknown" in archs
        assert "transformer" in archs
        assert "cnn" in archs
        assert "rnn" in archs
        assert "bert" in archs
        assert "gpt" in archs


class TestTensorInfo:
    """Tests for TensorInfo dataclass."""

    def test_create_tensor_info(self):
        """Test creating tensor info."""
        tensor = TensorInfo(
            name="layer.weight",
            shape=(768, 768),
            dtype="float32",
            parameter_count=768 * 768,
        )
        assert tensor.name == "layer.weight"
        assert tensor.shape == (768, 768)
        assert tensor.parameter_count == 768 * 768
        assert tensor.statistics == {}

    def test_tensor_info_with_statistics(self):
        """Test tensor info with statistics."""
        tensor = TensorInfo(
            name="weight",
            shape=(100, 100),
            dtype="float32",
            parameter_count=10000,
            statistics={"mean": 0.0, "std": 0.02},
        )
        assert tensor.statistics["mean"] == 0.0
        assert tensor.statistics["std"] == 0.02


class TestLayerPattern:
    """Tests for LayerPattern dataclass."""

    def test_create_layer_pattern(self):
        """Test creating layer pattern."""
        pattern = LayerPattern(
            layer_type="attention",
            parameter_names=["q_proj", "k_proj", "v_proj"],
            activation_functions=["softmax"],
        )
        assert pattern.layer_type == "attention"
        assert len(pattern.parameter_names) == 3
        assert pattern.has_batch_norm is False
        assert pattern.has_dropout is False

    def test_layer_pattern_with_flags(self):
        """Test layer pattern with batch norm and dropout."""
        pattern = LayerPattern(
            layer_type="conv2d",
            parameter_names=["weight", "bias"],
            activation_functions=["relu"],
            has_batch_norm=True,
            has_dropout=True,
        )
        assert pattern.has_batch_norm is True
        assert pattern.has_dropout is True


class TestUnifiedMLContext:
    """Tests for UnifiedMLContext dataclass."""

    @pytest.fixture
    def basic_context(self):
        """Create a basic context for testing."""
        return UnifiedMLContext(
            file_path=Path("/test/model.pt"),
            file_size=1000000,
            file_type="pytorch",
        )

    def test_create_basic_context(self, basic_context):
        """Test creating basic context."""
        assert basic_context.file_path == Path("/test/model.pt")
        assert basic_context.file_size == 1000000
        assert basic_context.file_type == "pytorch"
        assert basic_context.architecture == ModelArchitecture.UNKNOWN

    def test_default_values(self, basic_context):
        """Test default values are set correctly."""
        assert basic_context.model_id is None
        assert basic_context.primary_framework is None
        assert basic_context.total_parameters == 0
        assert basic_context.has_weight_structure is False
        assert len(basic_context.tensors) == 0

    def test_get_adjusted_severity_no_adjustments(self, basic_context):
        """Test severity adjustment with no context."""
        severity = basic_context.get_adjusted_severity(1.0, "eval")
        assert severity == 1.0

    def test_get_adjusted_severity_with_framework(self, basic_context):
        """Test severity adjustment with framework."""
        basic_context.primary_framework = "pytorch"
        basic_context.confidence_adjustments["pytorch_eval"] = 0.5
        severity = basic_context.get_adjusted_severity(1.0, "eval")
        assert severity == 0.5

    def test_get_adjusted_severity_with_architecture(self, basic_context):
        """Test severity adjustment with architecture."""
        basic_context.architecture = ModelArchitecture.TRANSFORMER
        basic_context.confidence_adjustments["transformer_eval"] = 0.3
        severity = basic_context.get_adjusted_severity(1.0, "eval")
        assert severity == 0.7

    def test_get_adjusted_severity_with_weight_structure(self, basic_context):
        """Test severity adjustment with weight structure."""
        basic_context.has_weight_structure = True
        basic_context.float_pattern_ratio = 0.9
        severity = basic_context.get_adjusted_severity(1.0, "pattern")
        assert severity == 0.5

    def test_is_known_safe_pattern_not_found(self, basic_context):
        """Test safe pattern not found."""
        result = basic_context.is_known_safe_pattern("eval", "model_loading")
        assert result is False

    def test_is_known_safe_pattern_found(self, basic_context):
        """Test safe pattern found in context."""
        basic_context.primary_framework = "pytorch"
        basic_context.safe_patterns_found.add("pytorch:model_loading:eval")
        result = basic_context.is_known_safe_pattern("eval", "model_loading")
        assert result is True

    def test_is_known_safe_pattern_architecture(self, basic_context):
        """Test safe pattern found via architecture."""
        basic_context.architecture = ModelArchitecture.TRANSFORMER
        basic_context.safe_patterns_found.add("transformer:attention:softmax")
        result = basic_context.is_known_safe_pattern("softmax", "attention")
        assert result is True

    def test_add_tensor_info(self, basic_context):
        """Test adding tensor info."""
        tensor = TensorInfo(
            name="weight",
            shape=(100, 100),
            dtype="float32",
            parameter_count=10000,
            statistics={"mean": 0.0, "std": 0.02},
        )
        basic_context.add_tensor_info(tensor)
        assert len(basic_context.tensors) == 1
        assert basic_context.total_parameters == 10000
        assert "mean" in basic_context.weight_statistics

    def test_add_multiple_tensors(self, basic_context):
        """Test adding multiple tensors."""
        for i in range(3):
            tensor = TensorInfo(
                name=f"weight_{i}",
                shape=(100,),
                dtype="float32",
                parameter_count=100,
            )
            basic_context.add_tensor_info(tensor)
        assert len(basic_context.tensors) == 3
        assert basic_context.total_parameters == 300

    def test_analyze_architecture_transformer(self, basic_context):
        """Test transformer architecture detection."""
        basic_context.layer_patterns = [
            LayerPattern(
                layer_type="multi_head_attention",
                parameter_names=["q", "k", "v"],
                activation_functions=[],
            ),
            LayerPattern(
                layer_type="position_embedding",
                parameter_names=["pos_emb"],
                activation_functions=[],
            ),
            LayerPattern(
                layer_type="attention_output",
                parameter_names=["dense"],
                activation_functions=[],
            ),
        ]
        basic_context.analyze_architecture_patterns()
        assert basic_context.architecture == ModelArchitecture.TRANSFORMER
        assert basic_context.architecture_confidence > 0

    def test_analyze_architecture_cnn(self, basic_context):
        """Test CNN architecture detection."""
        basic_context.layer_patterns = [
            LayerPattern(
                layer_type="conv2d",
                parameter_names=["weight"],
                activation_functions=["relu"],
            ),
            LayerPattern(
                layer_type="batch_norm",
                parameter_names=["gamma", "beta"],
                activation_functions=[],
            ),
            LayerPattern(
                layer_type="maxpool2d",
                parameter_names=[],
                activation_functions=[],
            ),
        ]
        basic_context.analyze_architecture_patterns()
        assert basic_context.architecture == ModelArchitecture.CNN

    def test_analyze_architecture_bert(self, basic_context):
        """Test BERT architecture detection."""
        basic_context.layer_patterns = [
            LayerPattern(
                layer_type="BertAttention",
                parameter_names=["query", "key", "value"],
                activation_functions=[],
            ),
        ]
        basic_context.analyze_architecture_patterns()
        assert basic_context.architecture == ModelArchitecture.BERT_LIKE
        assert basic_context.architecture_confidence == 0.9

    def test_analyze_architecture_gpt(self, basic_context):
        """Test GPT architecture detection."""
        basic_context.layer_patterns = [
            LayerPattern(
                layer_type="GPTAttention",
                parameter_names=["c_attn"],
                activation_functions=["gelu"],
            ),
        ]
        basic_context.analyze_architecture_patterns()
        assert basic_context.architecture == ModelArchitecture.GPT_LIKE

    def test_calculate_risk_score_no_factors(self, basic_context):
        """Test risk score with no factors."""
        score = basic_context.calculate_risk_score()
        assert score == 0.0

    def test_calculate_risk_score_with_factors(self, basic_context):
        """Test risk score with risk factors."""
        basic_context.risk_factors = {"dangerous_import": 0.5, "suspicious_pattern": 0.3}
        score = basic_context.calculate_risk_score()
        assert score == 0.8

    def test_calculate_risk_score_mitigation_weights(self, basic_context):
        """Test risk score mitigation from weight structure."""
        basic_context.risk_factors = {"pattern": 1.0}
        basic_context.has_weight_structure = True
        score = basic_context.calculate_risk_score()
        assert score < 1.0
        assert score == 0.7

    def test_calculate_risk_score_mitigation_architecture(self, basic_context):
        """Test risk score mitigation from architecture."""
        basic_context.risk_factors = {"pattern": 1.0}
        basic_context.architecture = ModelArchitecture.TRANSFORMER
        score = basic_context.calculate_risk_score()
        assert score == 0.8

    def test_calculate_risk_score_mitigation_framework(self, basic_context):
        """Test risk score mitigation from framework."""
        basic_context.risk_factors = {"pattern": 1.0}
        basic_context.primary_framework = "pytorch"
        score = basic_context.calculate_risk_score()
        assert score == 0.9

    def test_calculate_risk_score_all_mitigations(self, basic_context):
        """Test risk score with all mitigations."""
        basic_context.risk_factors = {"pattern": 1.0}
        basic_context.has_weight_structure = True
        basic_context.architecture = ModelArchitecture.CNN
        basic_context.primary_framework = "tensorflow"
        score = basic_context.calculate_risk_score()
        assert score < 0.7  # Multiple mitigations should reduce score significantly

    def test_calculate_risk_score_capped(self, basic_context):
        """Test risk score is capped at 1.0."""
        basic_context.risk_factors = {"a": 0.5, "b": 0.5, "c": 0.5}
        score = basic_context.calculate_risk_score()
        assert score <= 1.0


class TestContextIntegration:
    """Integration tests for context usage patterns."""

    def test_full_context_workflow(self):
        """Test a complete context workflow."""
        context = UnifiedMLContext(
            file_path=Path("/models/bert-base.pt"),
            file_size=500_000_000,
            file_type="pytorch",
            model_id="bert-base-uncased",
            model_source="huggingface",
        )

        # Set framework
        context.primary_framework = "pytorch"
        context.frameworks = {"pytorch": 0.95}

        # Add layer patterns
        context.layer_patterns = [
            LayerPattern(
                layer_type="BertSelfAttention",
                parameter_names=["query", "key", "value"],
                activation_functions=["softmax"],
            ),
            LayerPattern(
                layer_type="BertIntermediate",
                parameter_names=["dense"],
                activation_functions=["gelu"],
            ),
        ]

        # Analyze architecture
        context.analyze_architecture_patterns()
        assert context.architecture == ModelArchitecture.BERT_LIKE

        # Add tensors
        for i in range(12):  # 12 layers
            context.add_tensor_info(
                TensorInfo(
                    name=f"layer_{i}.attention.weight",
                    shape=(768, 768),
                    dtype="float32",
                    parameter_count=768 * 768,
                    statistics={"mean": 0.0, "std": 0.02},
                )
            )

        assert context.total_parameters > 0
        assert len(context.tensors) == 12

        # Set weight structure detection
        context.has_weight_structure = True
        context.float_pattern_ratio = 0.92

        # Calculate risk
        context.risk_factors = {"pickle_usage": 0.3}
        risk = context.calculate_risk_score()
        assert risk < 0.3  # Should be mitigated significantly
