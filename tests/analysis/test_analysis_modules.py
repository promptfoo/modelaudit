"""Basic tests for analysis modules."""

from pathlib import Path


class TestAnalysisModules:
    """Test that analysis modules can be imported and instantiated."""

    def test_import_modules(self) -> None:
        """Test importing all analysis modules."""
        # These imports should not raise exceptions
        from modelaudit.analysis import (
            AnalysisConfidence,
            CodeRiskLevel,
        )

        # Verify we can access the enums
        assert AnalysisConfidence.HIGH.value == 0.8
        assert CodeRiskLevel.SAFE.value == "safe"  # It's a string enum

    def test_entropy_analyzer_basic(self) -> None:
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

    def test_semantic_analyzer_basic(self) -> None:
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

    def test_integrated_analyzer_includes_code_specific_analysis(self) -> None:
        """Code patterns should include semantic and syntax validation details."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import UnifiedMLContext

        analyzer = IntegratedAnalyzer()
        context = UnifiedMLContext(Path("test.pkl"), 1024, "pickle")

        result = analyzer.analyze_suspicious_pattern(
            pattern="os.system",
            pattern_type="code",
            context=context,
            code_snippet="import os\nos.system('id')",
        )

        assert result.detailed_analysis["semantic"]["risk_level"] == "medium"
        assert result.detailed_analysis["validation"]["is_valid_python"] is True
        assert "Dangerous operation: os.system" in result.reasoning
