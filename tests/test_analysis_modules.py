"""Basic tests for analysis modules."""


class TestAnalysisModules:
    """Test that analysis modules can be imported and instantiated."""

    def test_import_modules(self):
        """Test importing all analysis modules."""
        # These imports should not raise exceptions
        from modelaudit.analysis import (
            AnalysisConfidence,
            CodeRiskLevel,
        )

        # Verify we can access the enums
        assert AnalysisConfidence.HIGH.value == 0.8
        assert CodeRiskLevel.SAFE.value == "safe"  # It's a string enum

    def test_instantiate_analyzers(self):
        """Test instantiating analyzer objects."""
        from modelaudit.analysis import (
            AnomalyDetector,
            EntropyAnalyzer,
            IntegratedAnalyzer,
            SemanticAnalyzer,
        )
        from modelaudit.context import UnifiedMLContext
        from modelaudit.knowledge import FrameworkKnowledgeBase

        # These should instantiate without errors
        entropy = EntropyAnalyzer()
        semantic = SemanticAnalyzer()
        anomaly = AnomalyDetector()
        integrated = IntegratedAnalyzer()
        # UnifiedMLContext requires file info
        context = UnifiedMLContext("test.pkl", 1024, "pickle")
        kb = FrameworkKnowledgeBase()

        # Basic sanity checks
        assert entropy is not None
        assert semantic is not None
        assert anomaly is not None
        assert integrated is not None
        assert context is not None
        assert kb is not None

    def test_entropy_analyzer_basic(self):
        """Test basic entropy analyzer functionality."""
        from modelaudit.analysis import EntropyAnalyzer

        analyzer = EntropyAnalyzer()

        # Test with some sample data
        code_data = b"import os\nos.system('rm -rf /')"
        weight_data = b"\x00\x01\x02\x03" * 100  # Repetitive binary data

        code_entropy = analyzer.calculate_shannon_entropy(code_data)
        weight_entropy = analyzer.calculate_shannon_entropy(weight_data)

        # Code should have higher entropy than repetitive data
        assert code_entropy > weight_entropy

    def test_semantic_analyzer_basic(self):
        """Test basic semantic analyzer functionality."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()

        # Test with simple code
        safe_code = "x = 1 + 2"
        dangerous_code = "import os\nos.system('rm -rf /')"

        # analyze_code_behavior returns (risk_level, details)
        safe_risk, _ = analyzer.analyze_code_behavior(safe_code, {})
        dangerous_risk, _ = analyzer.analyze_code_behavior(dangerous_code, {})

        # Dangerous code should have higher risk
        # Convert string risk levels to comparable values
        risk_order = {
            CodeRiskLevel.SAFE: 0,
            CodeRiskLevel.LOW: 1,
            CodeRiskLevel.MEDIUM: 2,
            CodeRiskLevel.HIGH: 3,
            CodeRiskLevel.CRITICAL: 4,
        }
        assert risk_order[safe_risk] < risk_order[dangerous_risk]

    def test_integrated_analyzer_basic(self):
        """Test basic integrated analyzer functionality."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.context import UnifiedMLContext

        analyzer = IntegratedAnalyzer()

        # Create a context for the analysis
        context = UnifiedMLContext("test.pkl", 1024, "pickle")

        # Test with simple analysis
        result = analyzer.analyze_suspicious_pattern(
            pattern="eval",
            pattern_type="code_execution",
            context=context,
            code_snippet="eval('2+2')",
        )

        assert result is not None
        assert isinstance(result.is_suspicious, bool)
        assert isinstance(result.confidence, float)
        assert isinstance(result.risk_level, str)
