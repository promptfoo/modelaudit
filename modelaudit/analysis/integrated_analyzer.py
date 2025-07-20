"""Integrated analyzer combining all false positive reduction techniques."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from modelaudit.analysis.anomaly_detector import AnomalyDetector
from modelaudit.analysis.entropy_analyzer import EntropyAnalyzer
from modelaudit.analysis.semantic_analyzer import CodeRiskLevel, SemanticAnalyzer
from modelaudit.context.unified_context import ModelArchitecture, UnifiedMLContext
from modelaudit.knowledge.framework_patterns import FrameworkKnowledgeBase, FrameworkType
from modelaudit.utils.code_validation import is_code_potentially_dangerous, validate_python_syntax


class AnalysisConfidence(Enum):
    """Confidence levels for analysis results."""

    VERY_LOW = 0.2
    LOW = 0.4
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.95


@dataclass
class IntegratedAnalysisResult:
    """Result from integrated analysis."""

    is_suspicious: bool
    confidence: float
    risk_level: str  # 'safe', 'low', 'medium', 'high', 'critical'
    reasoning: list[str]
    mitigations: list[str]
    recommendations: list[str]
    detailed_analysis: dict[str, Any]


class IntegratedAnalyzer:
    """Combines all analysis techniques for comprehensive false positive reduction."""

    def __init__(self):
        self.entropy_analyzer = EntropyAnalyzer()
        self.semantic_analyzer = SemanticAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.framework_kb = FrameworkKnowledgeBase()

        # Confidence weights for different signals
        self.signal_weights = {
            "ml_context": 0.25,
            "entropy_analysis": 0.15,
            "semantic_analysis": 0.20,
            "anomaly_detection": 0.15,
            "framework_knowledge": 0.20,
            "code_validation": 0.05,
        }

    def analyze_suspicious_pattern(
        self,
        pattern: str,
        pattern_type: str,
        context: UnifiedMLContext,
        raw_data: Optional[bytes] = None,
        code_snippet: Optional[str] = None,
    ) -> IntegratedAnalysisResult:
        """Perform integrated analysis on a suspicious pattern."""

        # Initialize analysis components
        signals = {}
        reasoning = []
        mitigations = []
        recommendations = []
        detailed = {}

        # 1. ML Context Analysis
        ml_signal = self._analyze_ml_context(pattern, context)
        signals["ml_context"] = ml_signal["confidence"]
        reasoning.extend(ml_signal["reasoning"])
        detailed["ml_context"] = ml_signal

        # 2. Entropy Analysis (if raw data available)
        if raw_data:
            entropy_signal = self._analyze_entropy(raw_data, pattern)
            signals["entropy_analysis"] = entropy_signal["confidence"]
            reasoning.extend(entropy_signal["reasoning"])
            detailed["entropy"] = entropy_signal

        # 3. Semantic Analysis (if code available)
        if code_snippet:
            semantic_signal = self._analyze_semantics(code_snippet, context)
            signals["semantic_analysis"] = semantic_signal["confidence"]
            reasoning.extend(semantic_signal["reasoning"])
            mitigations.extend(semantic_signal.get("mitigations", []))
            detailed["semantic"] = semantic_signal

        # 4. Anomaly Detection
        anomaly_signal = self._analyze_anomalies(pattern, context)
        signals["anomaly_detection"] = anomaly_signal["confidence"]
        reasoning.extend(anomaly_signal["reasoning"])
        detailed["anomaly"] = anomaly_signal

        # 5. Framework Knowledge
        framework_signal = self._analyze_framework_patterns(pattern, pattern_type, context)
        signals["framework_knowledge"] = framework_signal["confidence"]
        reasoning.extend(framework_signal["reasoning"])
        recommendations.extend(framework_signal.get("recommendations", []))
        detailed["framework"] = framework_signal

        # 6. Code Validation (if applicable)
        if pattern_type == "code" and code_snippet:
            validation_signal = self._validate_code(code_snippet)
            signals["code_validation"] = validation_signal["confidence"]
            reasoning.extend(validation_signal["reasoning"])
            detailed["validation"] = validation_signal

        # Calculate weighted confidence
        total_weight = sum(self.signal_weights[k] for k in signals)
        weighted_confidence = sum(signals[k] * self.signal_weights[k] for k in signals) / total_weight

        # Determine if suspicious
        is_suspicious = weighted_confidence > 0.5

        # Determine risk level
        risk_level = self._calculate_risk_level(weighted_confidence, signals)

        # Add general recommendations
        if not is_suspicious:
            recommendations.append("Pattern appears safe in current context")
        else:
            recommendations.extend(self._get_recommendations(pattern, pattern_type, context))

        return IntegratedAnalysisResult(
            is_suspicious=is_suspicious,
            confidence=weighted_confidence,
            risk_level=risk_level,
            reasoning=reasoning,
            mitigations=mitigations,
            recommendations=recommendations,
            detailed_analysis=detailed,
        )

    def _analyze_ml_context(self, pattern: str, context: UnifiedMLContext) -> dict[str, Any]:
        """Analyze pattern within ML context."""
        confidence_safe = 0.5  # Start neutral
        reasoning = []

        # Check if pattern is known safe in this context
        if context.is_known_safe_pattern(pattern, "ml_operation"):
            confidence_safe = 0.9
            reasoning.append(f"Pattern '{pattern}' is known safe in ML context")

        # Adjust based on framework confidence
        if context.primary_framework:
            confidence_safe += 0.1
            reasoning.append(f"Recognized framework: {context.primary_framework}")

        # Adjust based on architecture
        if context.architecture != ModelArchitecture.UNKNOWN:
            confidence_safe += 0.1
            reasoning.append(f"Recognized architecture: {context.architecture.value}")

        # Check weight structure
        if context.has_weight_structure and context.float_pattern_ratio > 0.8:
            confidence_safe += 0.2
            reasoning.append("Strong weight structure detected")

        # Adjust for risk factors
        risk_adjustment = sum(context.risk_factors.values()) * 0.1
        confidence_safe -= risk_adjustment

        return {
            "confidence": max(0, min(1, confidence_safe)),
            "reasoning": reasoning,
            "framework": context.primary_framework,
            "architecture": context.architecture.value,
        }

    def _analyze_entropy(self, data: bytes, pattern: str) -> dict[str, Any]:
        """Analyze entropy characteristics."""
        confidence_safe = 0.5
        reasoning = []

        # Classify data type
        data_type, type_confidence = self.entropy_analyzer.classify_data_type(data)

        if data_type == "ml_weights" and type_confidence > 0.8:
            confidence_safe = 0.85
            reasoning.append(f"Data classified as ML weights (confidence: {type_confidence:.2f})")

            # Check if pattern search should be skipped
            if self.entropy_analyzer.should_skip_pattern_search(data, pattern.encode()):
                confidence_safe = 0.95
                reasoning.append("Pattern search not recommended for this data type")

        elif data_type == "code" and type_confidence > 0.7:
            confidence_safe = 0.3
            reasoning.append(f"Data appears to contain code (confidence: {type_confidence:.2f})")

        elif data_type == "random_data":
            confidence_safe = 0.7
            reasoning.append("Data appears to be random/encrypted")

        # Get entropy info
        entropy_info = self.entropy_analyzer.detect_code_patterns(data)

        return {
            "confidence": confidence_safe,
            "reasoning": reasoning,
            "data_type": data_type,
            "type_confidence": type_confidence,
            "entropy": entropy_info.get("entropy", 0),
            "code_probability": entropy_info.get("code_probability", 0),
        }

    def _analyze_semantics(self, code: str, context: UnifiedMLContext) -> dict[str, Any]:
        """Perform semantic analysis."""
        confidence_safe = 0.5
        reasoning = []
        mitigations = []

        # Analyze code behavior
        ml_context_dict = {"framework": context.primary_framework}
        risk_level, analysis = self.semantic_analyzer.analyze_code_behavior(code, ml_context_dict)

        # Convert risk level to confidence
        risk_confidence_map = {
            CodeRiskLevel.SAFE: 0.95,
            CodeRiskLevel.LOW: 0.75,
            CodeRiskLevel.MEDIUM: 0.5,
            CodeRiskLevel.HIGH: 0.25,
            CodeRiskLevel.CRITICAL: 0.05,
        }

        confidence_safe = risk_confidence_map.get(risk_level, 0.5)

        # Add reasoning
        reasoning.extend(analysis.get("risk_factors", []))
        mitigations.extend(analysis.get("mitigating_factors", []))

        # Check for obfuscation
        is_obfuscated, obfuscation_types = self.semantic_analyzer.detect_obfuscation(code)
        if is_obfuscated:
            confidence_safe *= 0.5
            reasoning.append(f"Code appears obfuscated: {', '.join(obfuscation_types)}")

        return {
            "confidence": confidence_safe,
            "reasoning": reasoning,
            "mitigations": mitigations,
            "risk_level": risk_level.value,
            "analysis": analysis,
        }

    def _analyze_anomalies(self, pattern: str, context: UnifiedMLContext) -> dict[str, Any]:
        """Analyze statistical anomalies."""
        confidence_safe = 0.7  # Start assuming safe
        reasoning = []

        # If we have tensor information, check for anomalies
        if context.tensors:
            # Convert tensors to weight dict for analysis
            weights = {}
            for tensor in context.tensors:
                if hasattr(tensor, "data"):
                    weights[tensor.name] = tensor.data

            if weights:
                anomalies = self.anomaly_detector.detect_weight_anomalies(weights)

                if anomalies:
                    # Reduce confidence based on anomaly severity
                    severity_impact = {"low": 0.1, "medium": 0.2, "high": 0.4, "critical": 0.6}

                    for layer, anomaly_info in anomalies.items():
                        severity = anomaly_info.get("severity", "medium")
                        confidence_safe -= severity_impact.get(severity, 0.2)
                        reasoning.append(f"Anomaly in {layer}: {anomaly_info.get('type')}")
                else:
                    confidence_safe = 0.85
                    reasoning.append("No statistical anomalies detected in weights")

        return {"confidence": max(0, confidence_safe), "reasoning": reasoning, "anomalies_found": len(reasoning) > 0}

    def _analyze_framework_patterns(self, pattern: str, pattern_type: str, context: UnifiedMLContext) -> dict[str, Any]:
        """Analyze using framework-specific knowledge."""
        confidence_safe = 0.5
        reasoning = []
        recommendations = []

        # Detect framework
        framework = None
        if context.primary_framework:
            framework_map = {
                "pytorch": FrameworkType.PYTORCH,
                "tensorflow": FrameworkType.TENSORFLOW,
                "keras": FrameworkType.KERAS,
                "sklearn": FrameworkType.SKLEARN,
                "jax": FrameworkType.JAX,
            }
            framework = framework_map.get(context.primary_framework.lower())

        if framework:
            # Check if pattern is safe in framework
            is_safe, explanation = self.framework_kb.is_pattern_safe_in_framework(
                pattern, framework, {"context": pattern_type}
            )

            if is_safe:
                confidence_safe = 0.9
                reasoning.append(explanation)
            else:
                confidence_safe = 0.3
                reasoning.append(f"Pattern not recognized as safe in {framework.value}")

                # Get safe alternatives
                alternatives = self.framework_kb.get_safe_alternatives(pattern, framework)
                recommendations.extend(alternatives)

            # Check if should skip
            if self.framework_kb.should_skip_pattern_for_framework(pattern, framework, {"filename": context.file_path}):
                confidence_safe = 0.95
                reasoning.append(f"Pattern check skipped for {framework.value}")

        return {
            "confidence": confidence_safe,
            "reasoning": reasoning,
            "recommendations": recommendations,
            "framework": framework.value if framework else None,
        }

    def _validate_code(self, code: str) -> dict[str, Any]:
        """Validate code syntax and safety."""
        confidence_safe = 0.5
        reasoning = []

        # Check syntax
        is_valid, error = validate_python_syntax(code)

        if is_valid:
            # Check for dangerous constructs
            is_dangerous, risk_desc = is_code_potentially_dangerous(code, "low")

            if is_dangerous:
                confidence_safe = 0.2
                reasoning.append(f"Code contains dangerous constructs: {risk_desc}")
            else:
                confidence_safe = 0.8
                reasoning.append("Code syntax valid, no dangerous constructs found")
        else:
            confidence_safe = 0.6
            reasoning.append(f"Invalid Python syntax: {error}")

        return {
            "confidence": confidence_safe,
            "reasoning": reasoning,
            "is_valid_python": is_valid,
            "syntax_error": error,
        }

    def _calculate_risk_level(self, confidence: float, signals: dict[str, float]) -> str:
        """Calculate overall risk level."""
        # Invert confidence (high confidence in safety = low risk)
        risk_score = 1.0 - confidence

        # Adjust based on critical signals
        if signals.get("semantic_analysis", 1.0) < 0.3:
            risk_score = max(risk_score, 0.7)  # High risk if semantics are bad

        if signals.get("anomaly_detection", 1.0) < 0.3:
            risk_score = max(risk_score, 0.6)  # Medium-high risk if anomalous

        # Map to risk levels
        if risk_score < 0.2:
            return "safe"
        elif risk_score < 0.4:
            return "low"
        elif risk_score < 0.6:
            return "medium"
        elif risk_score < 0.8:
            return "high"
        else:
            return "critical"

    def _get_recommendations(self, pattern: str, pattern_type: str, context: UnifiedMLContext) -> list[str]:
        """Get specific recommendations."""
        recommendations = []

        if pattern_type == "code":
            recommendations.append("Review code for intended functionality")
            recommendations.append("Consider sandboxed execution for validation")

        if context.primary_framework:
            recommendations.append(f"Use {context.primary_framework}-specific security tools")

        if "eval" in pattern or "exec" in pattern:
            recommendations.append("Consider static alternatives to dynamic execution")

        return recommendations
