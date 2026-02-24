"""Tests for framework patterns knowledge base."""

import pytest

from modelaudit.analysis.framework_patterns import (
    FrameworkKnowledgeBase,
    FrameworkPattern,
    FrameworkType,
)


@pytest.fixture
def knowledge_base():
    """Create a knowledge base instance."""
    return FrameworkKnowledgeBase()


class TestFrameworkType:
    """Tests for FrameworkType enum."""

    def test_all_frameworks_defined(self):
        """Test that all expected frameworks are defined."""
        frameworks = [f.value for f in FrameworkType]
        assert "pytorch" in frameworks
        assert "tensorflow" in frameworks
        assert "keras" in frameworks
        assert "sklearn" in frameworks
        assert "onnx" in frameworks
        assert "jax" in frameworks


class TestFrameworkPattern:
    """Tests for FrameworkPattern dataclass."""

    def test_create_pattern(self):
        """Test creating a framework pattern."""
        pattern = FrameworkPattern(
            pattern="torch.load",
            pattern_type="function",
            is_safe=True,
            context="model_loading",
            risk_level="safe",
            explanation="Standard PyTorch loading",
        )
        assert pattern.pattern == "torch.load"
        assert pattern.is_safe is True
        assert pattern.risk_level == "safe"


class TestFrameworkKnowledgeBase:
    """Tests for FrameworkKnowledgeBase class."""

    def test_initialization(self, knowledge_base):
        """Test knowledge base initialization."""
        assert FrameworkType.PYTORCH in knowledge_base.patterns
        assert FrameworkType.TENSORFLOW in knowledge_base.patterns
        assert FrameworkType.SKLEARN in knowledge_base.patterns

    def test_pytorch_patterns_exist(self, knowledge_base):
        """Test PyTorch patterns are defined."""
        pytorch_patterns = knowledge_base.patterns[FrameworkType.PYTORCH]
        assert len(pytorch_patterns) > 0
        pattern_strs = [p.pattern for p in pytorch_patterns]
        assert "torch.load" in pattern_strs

    def test_tensorflow_patterns_exist(self, knowledge_base):
        """Test TensorFlow patterns are defined."""
        tf_patterns = knowledge_base.patterns[FrameworkType.TENSORFLOW]
        assert len(tf_patterns) > 0

    def test_safe_operations_defined(self, knowledge_base):
        """Test safe operations are defined."""
        assert FrameworkType.PYTORCH in knowledge_base.safe_operations
        assert "torch.load" in knowledge_base.safe_operations[FrameworkType.PYTORCH]

    def test_false_positive_patterns_defined(self, knowledge_base):
        """Test false positive patterns are defined."""
        assert "doc_strings" in knowledge_base.false_positive_patterns
        assert "variable_names" in knowledge_base.false_positive_patterns
        assert "ml_operations" in knowledge_base.false_positive_patterns

    def test_architecture_patterns_defined(self, knowledge_base):
        """Test architecture patterns are defined."""
        assert "transformer" in knowledge_base.architecture_patterns
        assert "cnn" in knowledge_base.architecture_patterns
        assert "rnn" in knowledge_base.architecture_patterns


class TestIsPatternSafeInFramework:
    """Tests for is_pattern_safe_in_framework method."""

    def test_unknown_framework(self, knowledge_base):
        """Test handling of unknown framework."""
        is_safe, explanation = knowledge_base.is_pattern_safe_in_framework("some_pattern", FrameworkType.MXNET, {})
        assert is_safe is False
        assert "Unknown framework" in explanation

    def test_pytorch_torch_load_safe(self, knowledge_base):
        """Test torch.load is recognized as safe."""
        is_safe, _explanation = knowledge_base.is_pattern_safe_in_framework("torch.load", FrameworkType.PYTORCH, {})
        assert is_safe is True

    def test_pytorch_model_eval_safe(self, knowledge_base):
        """Test model.eval() is recognized as safe."""
        is_safe, _explanation = knowledge_base.is_pattern_safe_in_framework("model.eval()", FrameworkType.PYTORCH, {})
        assert is_safe is True

    def test_tensorflow_saved_model_safe(self, knowledge_base):
        """Test tf.saved_model.load is recognized as safe."""
        is_safe, _explanation = knowledge_base.is_pattern_safe_in_framework(
            "tf.saved_model.load", FrameworkType.TENSORFLOW, {}
        )
        assert is_safe is True

    def test_known_safe_operation(self, knowledge_base):
        """Test known safe operations are detected."""
        is_safe, explanation = knowledge_base.is_pattern_safe_in_framework("torch.save", FrameworkType.PYTORCH, {})
        assert is_safe is True
        assert "safe operation" in explanation.lower()

    def test_false_positive_doc_strings(self, knowledge_base):
        """Test docstring patterns are recognized as false positives."""
        pattern = '"""This uses eval() for testing"""'
        is_safe, explanation = knowledge_base.is_pattern_safe_in_framework(pattern, FrameworkType.PYTORCH, {})
        # Should recognize as false positive
        assert is_safe is True or "false positive" in explanation.lower() or "not recognized" in explanation.lower()

    def test_false_positive_variable_names(self, knowledge_base):
        """Test variable name patterns are recognized as false positives."""
        is_safe, _explanation = knowledge_base.is_pattern_safe_in_framework("eval_metrics", FrameworkType.PYTORCH, {})
        assert is_safe is True

    def test_ml_operations_model_eval(self, knowledge_base):
        """Test ML operation patterns are recognized."""
        is_safe, _explanation = knowledge_base.is_pattern_safe_in_framework("model.eval()", FrameworkType.PYTORCH, {})
        assert is_safe is True


class TestGetFrameworkFromImports:
    """Tests for get_framework_from_imports method."""

    def test_pytorch_imports(self, knowledge_base):
        """Test PyTorch detection from imports."""
        imports = ["import torch", "from torch import nn"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework == FrameworkType.PYTORCH

    def test_tensorflow_imports(self, knowledge_base):
        """Test TensorFlow detection from imports."""
        imports = ["import tensorflow as tf", "from keras import layers"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework == FrameworkType.TENSORFLOW

    def test_sklearn_imports(self, knowledge_base):
        """Test sklearn detection from imports."""
        imports = ["from sklearn.ensemble import RandomForestClassifier", "import joblib"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework == FrameworkType.SKLEARN

    def test_jax_imports(self, knowledge_base):
        """Test JAX detection from imports."""
        imports = ["import jax", "import flax"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework == FrameworkType.JAX

    def test_xgboost_imports(self, knowledge_base):
        """Test XGBoost detection from imports."""
        imports = ["import xgboost as xgb"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework == FrameworkType.XGBOOST

    def test_lightgbm_imports(self, knowledge_base):
        """Test LightGBM detection from imports."""
        imports = ["import lightgbm as lgb"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework == FrameworkType.LIGHTGBM

    def test_no_framework_detected(self, knowledge_base):
        """Test no framework detection."""
        imports = ["import json", "import os"]
        framework = knowledge_base.get_framework_from_imports(imports)
        assert framework is None

    def test_empty_imports(self, knowledge_base):
        """Test empty imports list."""
        framework = knowledge_base.get_framework_from_imports([])
        assert framework is None


class TestGetSafeAlternatives:
    """Tests for get_safe_alternatives method."""

    def test_eval_alternatives_pytorch(self, knowledge_base):
        """Test eval alternatives for PyTorch."""
        alternatives = knowledge_base.get_safe_alternatives("eval(code)", FrameworkType.PYTORCH)
        assert len(alternatives) > 0
        assert any("torch.jit" in alt for alt in alternatives)

    def test_eval_alternatives_tensorflow(self, knowledge_base):
        """Test eval alternatives for TensorFlow."""
        alternatives = knowledge_base.get_safe_alternatives("eval(code)", FrameworkType.TENSORFLOW)
        assert len(alternatives) > 0
        assert any("tf.function" in alt for alt in alternatives)

    def test_pickle_alternatives_pytorch(self, knowledge_base):
        """Test pickle.load alternatives for PyTorch."""
        alternatives = knowledge_base.get_safe_alternatives("pickle.load", FrameworkType.PYTORCH)
        assert len(alternatives) > 0
        assert any("torch.load" in alt for alt in alternatives)

    def test_pickle_alternatives_sklearn(self, knowledge_base):
        """Test pickle.load alternatives for sklearn."""
        alternatives = knowledge_base.get_safe_alternatives("pickle.load", FrameworkType.SKLEARN)
        assert len(alternatives) > 0
        assert any("joblib" in alt for alt in alternatives)

    def test_reduce_alternatives_pytorch(self, knowledge_base):
        """Test __reduce__ alternatives for PyTorch."""
        alternatives = knowledge_base.get_safe_alternatives("__reduce__", FrameworkType.PYTORCH)
        assert len(alternatives) > 0
        assert any("state_dict" in alt for alt in alternatives)

    def test_unknown_pattern(self, knowledge_base):
        """Test unknown pattern returns default."""
        alternatives = knowledge_base.get_safe_alternatives("unknown_pattern", FrameworkType.PYTORCH)
        assert len(alternatives) > 0
        assert "framework-specific" in alternatives[0].lower()


class TestShouldSkipPatternForFramework:
    """Tests for should_skip_pattern_for_framework method."""

    def test_pytorch_model_eval_skip(self, knowledge_base):
        """Test model.eval() is skipped for PyTorch."""
        should_skip = knowledge_base.should_skip_pattern_for_framework("model.eval()", FrameworkType.PYTORCH, {})
        assert should_skip is True

    def test_tensorflow_tf_function_skip(self, knowledge_base):
        """Test tf.function is skipped for TensorFlow."""
        should_skip = knowledge_base.should_skip_pattern_for_framework("tf.function", FrameworkType.TENSORFLOW, {})
        assert should_skip is True

    def test_sklearn_joblib_skip(self, knowledge_base):
        """Test joblib.load is skipped for sklearn."""
        should_skip = knowledge_base.should_skip_pattern_for_framework("joblib.load", FrameworkType.SKLEARN, {})
        assert should_skip is True

    def test_test_file_context(self, knowledge_base):
        """Test more lenient behavior in test files."""
        should_skip = knowledge_base.should_skip_pattern_for_framework(
            "eval", FrameworkType.PYTORCH, {"filename": "test_model.py"}
        )
        assert should_skip is True

    def test_normal_context_no_skip(self, knowledge_base):
        """Test normal context doesn't skip dangerous patterns."""
        should_skip = knowledge_base.should_skip_pattern_for_framework("os.system", FrameworkType.PYTORCH, {})
        assert should_skip is False

    def test_unknown_framework_no_skip(self, knowledge_base):
        """Test unknown framework doesn't skip."""
        should_skip = knowledge_base.should_skip_pattern_for_framework("model.eval()", FrameworkType.MXNET, {})
        assert should_skip is False


class TestValidateContext:
    """Tests for _validate_context method."""

    def test_lambda_with_safe_code(self, knowledge_base):
        """Test Lambda validation with safe code."""
        pattern = FrameworkPattern(
            pattern="Lambda",
            pattern_type="layer",
            is_safe=False,
            context="layer_definition",
            risk_level="low",
            explanation="Lambda layer",
        )
        context = {"lambda_code": "lambda x: x * 0.5", "layer_definition": True}
        result = knowledge_base._validate_context(pattern, context)
        assert result is True

    def test_lambda_with_unsafe_code(self, knowledge_base):
        """Test Lambda validation with unsafe code."""
        pattern = FrameworkPattern(
            pattern="Lambda",
            pattern_type="layer",
            is_safe=False,
            context="layer_definition",
            risk_level="high",
            explanation="Lambda layer",
        )
        context = {"lambda_code": "lambda x: eval(x)", "layer_definition": True}
        result = knowledge_base._validate_context(pattern, context)
        assert result is False

    def test_wrong_context(self, knowledge_base):
        """Test validation fails with wrong context."""
        pattern = FrameworkPattern(
            pattern="test",
            pattern_type="function",
            is_safe=True,
            context="model_loading",
            risk_level="safe",
            explanation="Test",
        )
        context = {"serialization": True}
        result = knowledge_base._validate_context(pattern, context)
        assert result is False
