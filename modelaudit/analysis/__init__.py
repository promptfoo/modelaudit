"""ML model analysis and context detection.

This package contains modules for analyzing ML models and detecting framework-specific patterns:
- anomaly_detector.py - Statistical anomaly detection
- enhanced_pattern_detector.py - Advanced pattern matching
- entropy_analyzer.py - Entropy-based analysis
- framework_patterns.py - ML framework detection patterns and heuristics
- integrated_analyzer.py - Combined analysis techniques
- ml_context_analyzer.py - ML context analysis
- opcode_sequence_analyzer.py - Pickle opcode sequence analysis
- semantic_analyzer.py - Semantic code analysis
- unified_context.py - Unified ML context for cross-framework analysis
"""

from typing import Any

from modelaudit.analysis import framework_patterns, unified_context

# Lazy imports to avoid circular dependencies
# Import specific classes only when accessed via __getattr__


def __getattr__(name: str) -> Any:
    """Lazy import analysis classes to avoid circular dependencies."""
    if name == "AnomalyDetector":
        from modelaudit.analysis.anomaly_detector import AnomalyDetector

        return AnomalyDetector
    elif name == "EntropyAnalyzer":
        from modelaudit.analysis.entropy_analyzer import EntropyAnalyzer

        return EntropyAnalyzer
    elif name == "AnalysisConfidence":
        from modelaudit.analysis.integrated_analyzer import AnalysisConfidence

        return AnalysisConfidence
    elif name == "IntegratedAnalyzer":
        from modelaudit.analysis.integrated_analyzer import IntegratedAnalyzer

        return IntegratedAnalyzer
    elif name == "CodeRiskLevel":
        from modelaudit.analysis.semantic_analyzer import CodeRiskLevel

        return CodeRiskLevel
    elif name == "SemanticAnalyzer":
        from modelaudit.analysis.semantic_analyzer import SemanticAnalyzer

        return SemanticAnalyzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AnalysisConfidence",
    "AnomalyDetector",
    "CodeRiskLevel",
    "EntropyAnalyzer",
    "IntegratedAnalyzer",
    "SemanticAnalyzer",
    "framework_patterns",
    "unified_context",
]
