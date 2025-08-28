"""Test cases for ML Context Analyzer."""

import pytest

from modelaudit.analysis.ml_context_analyzer import MLContextAnalyzer, MLFramework, OperationRisk


class TestMLContextAnalyzer:
    """Test cases for ML context analysis."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = MLContextAnalyzer()
        assert len(analyzer.ml_operations) > 0
        assert len(analyzer.framework_patterns) > 0
        assert MLFramework.PYTORCH in analyzer.framework_patterns

    def test_pytorch_detection(self):
        """Test PyTorch framework detection."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context("torch.load", ["torch.nn.Module", "state_dict"], "model.pth")

        assert result.framework == MLFramework.PYTORCH
        assert result.confidence > 0.6
        assert result.risk_adjustment < 0.5  # Significant risk reduction

    def test_tensorflow_detection(self):
        """Test TensorFlow framework detection."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context("tf.saved_model.load", ["tensorflow", "SavedModel"], "saved_model.pb")

        assert result.framework == MLFramework.TENSORFLOW
        assert result.confidence > 0.6

    def test_sklearn_detection(self):
        """Test Scikit-learn framework detection."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context("joblib.load", ["sklearn.ensemble", "RandomForestClassifier"], "model.pkl")

        assert result.framework == MLFramework.SKLEARN
        assert result.confidence > 0.5

    def test_unknown_framework(self):
        """Test detection when no ML framework is present."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context("os.system", ["subprocess", "shell command"], "malicious.py")

        assert result.framework == MLFramework.UNKNOWN
        assert result.confidence == 0.0
        assert result.risk_adjustment == 1.0  # No risk reduction

    def test_safe_operation_detection(self):
        """Test detection of safe ML operations."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context(
            "torch.load",
            ["torch.nn", "model", "state_dict"],
        )

        assert result.operation is not None
        assert result.operation.risk_level == OperationRisk.SAFE
        assert result.risk_adjustment < 0.3  # Significant risk reduction

    def test_suspicious_operation_detection(self):
        """Test detection of suspicious but potentially legitimate operations."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context(
            "torch.jit.compile",
            ["torch", "model optimization"],
        )

        if result.operation:
            assert result.operation.risk_level == OperationRisk.SUSPICIOUS
            assert 0.3 < result.risk_adjustment < 0.7  # Moderate risk reduction

    def test_confidence_calculation(self):
        """Test confidence calculation with various scenarios."""
        analyzer = MLContextAnalyzer()

        # High confidence: many ML indicators
        high_conf_result = analyzer.analyze_context(
            "torch.load",
            ["torch.nn.Module", "model", "state_dict", "optimizer", "loss", "train"],
        )

        # Low confidence: few indicators
        low_conf_result = analyzer.analyze_context(
            "torch.something",
            ["other", "unrelated", "content"],
        )

        assert high_conf_result.confidence > low_conf_result.confidence

    def test_risk_adjustment_scaling(self):
        """Test that risk adjustment scales with confidence."""
        analyzer = MLContextAnalyzer()

        # High confidence torch.load should have lower risk
        result = analyzer.analyze_context("torch.load", ["torch.nn", "model", "checkpoint", "state_dict"])

        if result.operation and result.operation.risk_level == OperationRisk.SAFE:
            assert result.risk_adjustment < 0.3
            assert result.confidence > 0.7

    def test_explanation_generation(self):
        """Test explanation generation."""
        analyzer = MLContextAnalyzer()

        # Safe operation
        safe_result = analyzer.analyze_context("torch.load", ["torch.nn"])
        assert "legitimate" in safe_result.explanation.lower()
        assert "pytorch" in safe_result.explanation.lower()

        # Unknown operation
        unknown_result = analyzer.analyze_context("unknown.function", ["random", "content"])
        assert "does not appear to be" in unknown_result.explanation.lower()

    def test_is_ml_context_method(self):
        """Test quick ML context check method."""
        analyzer = MLContextAnalyzer()

        # Should detect ML context
        assert analyzer.is_ml_context("torch.load", ["torch.nn", "model"])
        assert analyzer.is_ml_context("tf.saved_model.load", ["tensorflow"])

        # Should not detect ML context
        assert not analyzer.is_ml_context("os.system", ["malicious", "code"])
        assert not analyzer.is_ml_context("random.function", ["unknown", "content"])

    def test_framework_pattern_matching(self):
        """Test framework detection patterns."""
        analyzer = MLContextAnalyzer()

        test_cases = [
            # PyTorch patterns
            ("torch.nn.Linear", MLFramework.PYTORCH),
            ("torch.optim.Adam", MLFramework.PYTORCH),
            ("model.state_dict()", MLFramework.PYTORCH),
            ("OrderedDict", MLFramework.PYTORCH),
            # TensorFlow patterns
            ("tf.keras.Model", MLFramework.TENSORFLOW),
            ("tensorflow.saved_model", MLFramework.TENSORFLOW),
            ("saved_model.load", MLFramework.TENSORFLOW),
            # Scikit-learn patterns
            ("sklearn.ensemble.RandomForest", MLFramework.SKLEARN),
            ("model.fit()", MLFramework.SKLEARN),
            ("model.predict()", MLFramework.SKLEARN),
            ("joblib.load", MLFramework.SKLEARN),
            # NumPy patterns
            ("numpy.array", MLFramework.NUMPY),
            ("np.ndarray", MLFramework.NUMPY),
        ]

        for function_call, expected_framework in test_cases:
            result = analyzer.analyze_context(function_call, [function_call])
            assert result.framework == expected_framework, (
                f"Expected {expected_framework} for '{function_call}', got {result.framework}"
            )


class TestMLOperationPatterns:
    """Test ML operation pattern detection."""

    def test_pytorch_model_loading(self):
        """Test PyTorch model loading patterns."""
        analyzer = MLContextAnalyzer()

        # Standard torch.load
        result = analyzer.analyze_context("torch.load('model.pth')", ["torch", "model"])
        assert result.framework == MLFramework.PYTORCH
        if result.operation:
            assert "model_loading" in result.operation.operation_type

    def test_tensorflow_model_loading(self):
        """Test TensorFlow model loading patterns."""
        analyzer = MLContextAnalyzer()

        result = analyzer.analyze_context("tf.saved_model.load('/path/to/model')", ["tensorflow", "saved_model"])
        assert result.framework == MLFramework.TENSORFLOW

    def test_sklearn_model_operations(self):
        """Test sklearn model operations."""
        analyzer = MLContextAnalyzer()

        # Model training
        result = analyzer.analyze_context("model.fit(X, y)", ["sklearn", "RandomForestClassifier"])
        assert result.framework == MLFramework.SKLEARN


class TestFalsePositiveReduction:
    """Test false positive reduction scenarios."""

    def test_legitimate_torch_operations(self):
        """Test that legitimate PyTorch operations get low risk scores."""
        analyzer = MLContextAnalyzer()

        legitimate_cases = [
            "torch.load('model.pth', map_location='cpu')",
            "torch.nn.Module()",
            "model.load_state_dict(checkpoint)",
            "torch.tensor([1, 2, 3])",
        ]

        for case in legitimate_cases:
            result = analyzer.analyze_context(case, ["torch", "model", "neural network"])

            # Should have significant risk reduction
            assert result.risk_adjustment < 0.5, f"High risk for legitimate case: {case}"

    def test_suspicious_but_legitimate_operations(self):
        """Test operations that are suspicious but can be legitimate in ML context."""
        analyzer = MLContextAnalyzer()

        # Dynamic imports are common in ML frameworks for optional dependencies
        result = analyzer.analyze_context(
            "importlib.import_module('torch.cuda')", ["torch", "GPU acceleration", "optional dependency"]
        )

        # Should have moderate risk reduction (not as safe as direct model ops)
        assert 0.3 < result.risk_adjustment < 0.8

    def test_actual_malicious_operations(self):
        """Test that actual malicious operations maintain high risk."""
        analyzer = MLContextAnalyzer()

        malicious_cases = [
            "os.system('rm -rf /')",
            "subprocess.call(['malicious', 'command'])",
            "eval('dangerous code')",
        ]

        for case in malicious_cases:
            result = analyzer.analyze_context(case, ["malicious", "system call"])

            # Should maintain high risk (minimal reduction)
            assert result.risk_adjustment > 0.8, f"Low risk for malicious case: {case}"


# Real-world test scenarios
REAL_WORLD_ML_SCENARIOS = [
    {
        "name": "huggingface_model_loading",
        "function_call": "torch.load('pytorch_model.bin')",
        "stack_context": ["transformers.modeling_utils", "torch.nn.Module", "state_dict", "PreTrainedModel"],
        "expected_framework": MLFramework.PYTORCH,
        "expected_low_risk": True,
    },
    {
        "name": "tensorflow_savedmodel",
        "function_call": "tf.saved_model.load('/model/path')",
        "stack_context": ["tensorflow.saved_model.loader_impl", "tf.Graph", "tf.Session"],
        "expected_framework": MLFramework.TENSORFLOW,
        "expected_low_risk": True,
    },
    {
        "name": "sklearn_pipeline",
        "function_call": "joblib.load('model.pkl')",
        "stack_context": ["sklearn.ensemble", "RandomForestClassifier", "fit", "predict"],
        "expected_framework": MLFramework.SKLEARN,
        "expected_low_risk": True,
    },
    {
        "name": "disguised_malicious",
        "function_call": "os.system('malicious')",
        "stack_context": [
            "torch",  # Tries to look like ML context
            "model",
        ],
        "expected_framework": MLFramework.UNKNOWN,  # Should not be fooled
        "expected_low_risk": False,
    },
]


@pytest.mark.parametrize("scenario", REAL_WORLD_ML_SCENARIOS)
def test_real_world_ml_scenarios(scenario):
    """Test analyzer against real-world ML scenarios."""
    analyzer = MLContextAnalyzer()

    result = analyzer.analyze_context(scenario["function_call"], scenario["stack_context"])

    assert result.framework == scenario["expected_framework"], (
        f"Expected {scenario['expected_framework']} for {scenario['name']}"
    )

    if scenario["expected_low_risk"]:
        assert result.risk_adjustment < 0.6, f"Expected low risk for {scenario['name']}, got {result.risk_adjustment}"
    else:
        assert result.risk_adjustment > 0.7, f"Expected high risk for {scenario['name']}, got {result.risk_adjustment}"
