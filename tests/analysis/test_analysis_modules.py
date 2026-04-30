"""Basic tests for analysis modules."""

from pathlib import Path

import pytest


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
        from modelaudit.analysis.framework_patterns import FrameworkKnowledgeBase
        from modelaudit.analysis.unified_context import UnifiedMLContext

        # These should instantiate without errors
        entropy = EntropyAnalyzer()
        semantic = SemanticAnalyzer()
        anomaly = AnomalyDetector()
        integrated = IntegratedAnalyzer()
        # UnifiedMLContext requires file info
        context = UnifiedMLContext(Path("test.pkl"), 1024, "pickle")
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

    def test_semantic_analyzer_resolves_import_aliases(self) -> None:
        """Dangerous calls made through imported aliases should remain visible."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()

        risk_level, details = analyzer.analyze_code_behavior("import os as o\no.system('id')", {})

        assert risk_level != CodeRiskLevel.SAFE
        assert "os.system" in details["function_calls"]

    def test_semantic_analyzer_preserves_bare_builtin_aliases(self) -> None:
        """Dangerous builtins imported from builtins should keep their dangerous names."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()

        risk_level, details = analyzer.analyze_code_behavior("from builtins import eval\neval(user_input)", {})

        assert risk_level != CodeRiskLevel.SAFE
        assert "eval" in details["function_calls"]

    def test_semantic_analyzer_scopes_safe_patterns_to_operation(self) -> None:
        """A safe eval should not pardon an unrelated dangerous operation."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()

        risk_level, details = analyzer.analyze_code_behavior("eval('1+1')\nimport os\nos.system('id')", {})

        assert risk_level != CodeRiskLevel.SAFE
        assert "Dangerous operation: os.system" in details["risk_factors"]
        assert "Safe usage of os.system" not in details["mitigating_factors"]

    def test_semantic_analyzer_updates_aliases_after_rebinding(self) -> None:
        """Assignments should update imported aliases before later calls are normalized."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()
        risk_level, details = analyzer.analyze_code_behavior(
            "import math as os\nimport os as real_os\nos = real_os\nos.system('id')",
            {},
        )

        assert risk_level != CodeRiskLevel.SAFE
        assert "os.system" in details["function_calls"]

    def test_semantic_analyzer_drops_aliases_after_shadowing(self) -> None:
        """Reassigned names should no longer be treated as imported call targets."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()
        risk_level, details = analyzer.analyze_code_behavior(
            "from os import system\nsystem = print\nsystem('hello')",
            {},
        )

        assert risk_level == CodeRiskLevel.SAFE
        assert "os.system" not in details["function_calls"]

    def test_semantic_analyzer_preserves_safe_builtin_alias_usage(self) -> None:
        """Builtin aliases should keep the same safe-pattern treatment as direct calls."""
        from modelaudit.analysis import CodeRiskLevel, SemanticAnalyzer

        analyzer = SemanticAnalyzer()
        risk_level, details = analyzer.analyze_code_behavior("from builtins import eval as e\ne('1+1')", {})

        assert risk_level == CodeRiskLevel.SAFE
        assert details["mitigating_factors"] == ["Safe usage of eval"]

    def test_integrated_analyzer_basic(self):
        """Test basic integrated analyzer functionality."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import UnifiedMLContext

        analyzer = IntegratedAnalyzer()

        # Create a context for the analysis
        context = UnifiedMLContext(Path("test.pkl"), 1024, "pickle")

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

    def test_integrated_analyzer_treats_high_safety_confidence_as_not_suspicious(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The final suspiciousness flag should agree with the safety-confidence scale."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import UnifiedMLContext

        context = UnifiedMLContext(Path("test.pkl"), 1024, "pickle")
        analyzer = IntegratedAnalyzer()
        monkeypatch.setattr(analyzer, "_analyze_ml_context", lambda *_args: {"confidence": 0.9, "reasoning": []})
        monkeypatch.setattr(analyzer, "_analyze_anomalies", lambda *_args: {"confidence": 0.9, "reasoning": []})
        monkeypatch.setattr(
            analyzer,
            "_analyze_framework_patterns",
            lambda *_args: {"confidence": 0.9, "reasoning": []},
        )

        result = analyzer.analyze_suspicious_pattern("x", "token", context)

        assert result.confidence == pytest.approx(0.9)
        assert result.risk_level == "safe"
        assert result.is_suspicious is False

    def test_integrated_analyzer_treats_low_safety_confidence_as_suspicious(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Low confidence in safety should remain suspicious."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import UnifiedMLContext

        context = UnifiedMLContext(Path("test.pkl"), 1024, "pickle")
        analyzer = IntegratedAnalyzer()
        monkeypatch.setattr(analyzer, "_analyze_ml_context", lambda *_args: {"confidence": 0.1, "reasoning": []})
        monkeypatch.setattr(analyzer, "_analyze_anomalies", lambda *_args: {"confidence": 0.1, "reasoning": []})
        monkeypatch.setattr(
            analyzer,
            "_analyze_framework_patterns",
            lambda *_args: {"confidence": 0.1, "reasoning": []},
        )

        result = analyzer.analyze_suspicious_pattern("x", "token", context)

        assert result.confidence == pytest.approx(0.1)
        assert result.risk_level == "critical"
        assert result.is_suspicious is True

    def test_integrated_analyzer_uses_adjusted_risk_for_suspiciousness(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Critical component signals should override a safe-looking average."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import UnifiedMLContext

        context = UnifiedMLContext(Path("test.pkl"), 1024, "pickle")
        analyzer = IntegratedAnalyzer()
        monkeypatch.setattr(analyzer, "_analyze_ml_context", lambda *_args: {"confidence": 1.0, "reasoning": []})
        monkeypatch.setattr(analyzer, "_analyze_anomalies", lambda *_args: {"confidence": 1.0, "reasoning": []})
        monkeypatch.setattr(
            analyzer,
            "_analyze_framework_patterns",
            lambda *_args: {"confidence": 1.0, "reasoning": []},
        )
        monkeypatch.setattr(analyzer, "_analyze_semantics", lambda *_args: {"confidence": 0.2, "reasoning": []})

        result = analyzer.analyze_suspicious_pattern("x", "code", context, code_snippet="x")

        assert result.confidence > 0.5
        assert result.risk_level == "high"
        assert result.is_suspicious is True
        assert "Pattern appears safe in current context" not in result.recommendations

    def test_integrated_analyzer_keeps_explicit_semantic_risks_suspicious(self) -> None:
        """Dangerous semantic findings should not disappear behind reassuring context."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import ModelArchitecture, UnifiedMLContext

        context = UnifiedMLContext(
            Path("test.pkl"),
            1024,
            "pickle",
            primary_framework="pytorch",
            architecture=ModelArchitecture.TRANSFORMER,
        )

        result = IntegratedAnalyzer().analyze_suspicious_pattern(
            "eval",
            "code_execution",
            context,
            code_snippet="eval(user_input)",
        )

        assert result.risk_level == "low"
        assert result.is_suspicious is True
        assert "Dangerous operation: eval" in result.reasoning

    def test_integrated_entropy_does_not_upgrade_exact_dangerous_literals(self) -> None:
        """Weight-like bytes with an exact sink literal must not get skip confidence."""
        import numpy as np

        from modelaudit.analysis import IntegratedAnalyzer

        np.random.seed(42)
        weights = np.random.normal(0, 0.2, 1000).astype(np.float32)
        data = weights.tobytes() + b"os.system"

        result = IntegratedAnalyzer()._analyze_entropy(data, "os.system")

        assert result["data_type"] == "ml_weights"
        assert result["confidence"] == 0.85
        assert "Pattern search not recommended for this data type" not in result["reasoning"]

    def test_integrated_analyzer_ignores_attacker_controlled_filename_context(self) -> None:
        """Filename text should not change framework-pattern confidence."""
        from modelaudit.analysis import IntegratedAnalyzer
        from modelaudit.analysis.unified_context import UnifiedMLContext

        analyzer = IntegratedAnalyzer()
        normal_context = UnifiedMLContext(Path("payload.py"), 1024, "python", primary_framework="pytorch")
        spoofed_context = UnifiedMLContext(
            Path("samples/eval_bucket/validate_payload.py"),
            1024,
            "python",
            primary_framework="pytorch",
        )

        normal = analyzer._analyze_framework_patterns("eval", "code_execution", normal_context)
        spoofed = analyzer._analyze_framework_patterns("eval", "code_execution", spoofed_context)

        assert spoofed == normal
