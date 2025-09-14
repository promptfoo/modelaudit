"""Enhanced pattern detection with context awareness.

This module provides sophisticated pattern detection that goes beyond simple string
matching to include semantic analysis, obfuscation detection, and ML context awareness.
"""

import base64
import logging
import re
from dataclasses import dataclass
from typing import Any

from .ml_context_analyzer import MLContextAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """Represents a detected dangerous pattern."""

    pattern_name: str
    matched_text: str
    position: int
    severity: str
    confidence: float
    context: dict[str, Any]
    deobfuscated_text: str | None = None
    ml_context_adjustment: float = 1.0


class EnhancedPatternDetector:
    """Enhanced pattern detection with context awareness and deobfuscation.

    This detector improves upon basic string matching by:
    - Detecting obfuscated patterns (base64, hex, etc.)
    - Analyzing semantic context
    - Considering ML framework legitimacy
    - Reducing false positives through context awareness
    """

    def __init__(self):
        """Initialize enhanced pattern detector."""
        self.ml_analyzer = MLContextAnalyzer()
        self.dangerous_patterns = self._initialize_dangerous_patterns()
        self.obfuscation_patterns = self._initialize_obfuscation_patterns()
        self.ml_whitelist_patterns = self._initialize_ml_whitelist_patterns()

    def _initialize_dangerous_patterns(self) -> dict[str, dict[str, Any]]:
        """Initialize dangerous pattern definitions."""
        return {
            # System command execution
            "os_system": {
                "patterns": [
                    r"\bos\.system\b",
                    r"\bos\.popen\b",
                    r"\bos\.spawn\w*\b",  # os.spawn, os.spawnl, os.spawnv, etc.
                    r"\bsubprocess\.call\b",
                    r"\bsubprocess\.run\b",
                    r"\bsubprocess\.Popen\b",
                    r"\bcommands\.getoutput\b",
                    r"\bcommands\.getstatusoutput\b",
                    r"\bposix\.system\b",
                ],
                "severity": "critical",
                "description": "System command execution",
                "category": "command_execution",
            },
            # Code execution
            "code_eval": {
                "patterns": [r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\("],
                "severity": "critical",
                "description": "Dynamic code execution",
                "category": "code_execution",
            },
            # Dynamic imports
            "dynamic_import": {
                "patterns": [
                    r"\b__import__\s*\(",
                    r"\bimportlib\.import_module\b",
                    r"\bimportlib\.machinery\b",
                    r"\bimportlib\.util\b",
                    r"\bfrom\s+importlib\b",
                    r"\bimport\s+importlib\b",
                    r"\bimportlib\b",  # importlib as string value (restored general pattern)
                    r"\brunpy\.run_module\b",
                    r"\brunpy\.run_path\b",
                    r"\brunpy\._run_module_as_main\b",
                    r"\brunpy\._run_code\b",
                    r"\brunpy\b",  # General runpy module reference
                ],
                "severity": "critical",
                "description": "Dynamic module import",
                "category": "dynamic_import",
            },
            # File operations
            "file_operations": {
                "patterns": [r"\bopen\s*\(", r"\bfile\s*\(", r"\bbuiltins\.open\b"],
                "severity": "warning",
                "description": "File system operations",
                "category": "file_access",
            },
            # Network operations
            "network_ops": {
                "patterns": [
                    r"\bsocket\.socket\b",
                    r"\burllib\.request\b",
                    r"\brequests\.get\b",
                    r"\bhttplib\b",
                    r"\bhttp\.client\b",
                    r"\bwebbrowser\.open\b",
                    r"\bwebbrowser\.open_new\b",
                    r"\bwebbrowser\.open_new_tab\b",
                    r"\bwebbrowser\b",  # General webbrowser module reference
                ],
                "severity": "critical",  # Upgraded to critical for security
                "description": "Network communication",
                "category": "network_access",
            },
            # Environment access
            "env_access": {
                "patterns": [r"\bos\.environ\b", r"\bgetenv\b", r"\bputenv\b"],
                "severity": "warning",
                "description": "Environment variable access",
                "category": "environment_access",
            },
        }

    def _initialize_obfuscation_patterns(self) -> list[dict[str, Any]]:
        """Initialize obfuscation detection patterns."""
        return [
            {
                "name": "base64_encoded",
                "pattern": r"[A-Za-z0-9+/]{20,}={0,2}",
                "decoder": lambda x: base64.b64decode(x).decode("utf-8", errors="ignore"),
                "min_length": 20,
            },
            {
                "name": "hex_encoded",
                "pattern": r"(?:\\x[0-9a-fA-F]{2})+",
                "decoder": lambda x: bytes.fromhex(x.replace("\\x", "")).decode("utf-8", errors="ignore"),
                "min_length": 8,
            },
            {
                "name": "unicode_escape",
                "pattern": r"(?:\\u[0-9a-fA-F]{4})+",
                "decoder": lambda x: x.encode().decode("unicode_escape"),
                "min_length": 6,
            },
            {
                "name": "string_concat",
                "pattern": r'["\'][^"\']*["\'](\s*\+\s*["\'][^"\']*["\'])+',
                "decoder": lambda x: "".join(re.findall(r'["\']([^"\']*)["\']', x)),
                "min_length": 10,
            },
        ]

    def _initialize_ml_whitelist_patterns(self) -> dict[str, list[str]]:
        """Initialize ML framework whitelist patterns."""
        return {
            "torch_safe_operations": [
                r"torch\.load\s*\([^,]*,\s*map_location\s*=",  # Safe torch.load with map_location
                r"torch\.jit\.load\s*\(",  # JIT model loading
                r"torch\.nn\.Module\.",  # Neural network modules
                r"\.state_dict\(\)",  # Model state access
                r"\.load_state_dict\(",  # State loading
            ],
            "tensorflow_safe_operations": [
                r"tf\.saved_model\.load\s*\(",  # SavedModel loading
                r"tf\.keras\.models\.load_model\s*\(",  # Keras model loading
                r"tf\.constant\s*\(",  # Constant tensors
                r"tf\.Variable\s*\(",  # Variables
            ],
            "sklearn_safe_operations": [
                r"joblib\.load\s*\(",  # Joblib model loading
                r"pickle\.load\s*\([^,]*\)",  # Basic pickle load (common in sklearn)
                r"\.fit\s*\(",
                r"\.predict\s*\(",
                r"\.transform\s*\(",  # Model methods
            ],
        }

    def detect_patterns(self, data: bytes | str, context: dict[str, Any] | None = None) -> list[PatternMatch]:
        """Detect dangerous patterns in data with context awareness.

        Args:
            data: Binary or text data to analyze
            context: Optional context information (file path, stack state, etc.)

        Returns:
            List of detected pattern matches with context analysis
        """
        if isinstance(data, bytes):
            # Try to decode as text, handle encoding errors gracefully
            try:
                text_data = data.decode("utf-8")
            except UnicodeDecodeError:
                # Try latin-1 as fallback (preserves byte values)
                text_data = data.decode("latin-1")
        else:
            text_data = data

        matches = []

        # First, check for obfuscated content
        deobfuscated_segments = self._detect_and_deobfuscate(text_data)

        # Analyze both original and deobfuscated content
        all_content = [("original", text_data), *deobfuscated_segments]

        for content_type, content in all_content:
            for pattern_name, pattern_info in self.dangerous_patterns.items():
                matches.extend(self._find_pattern_matches(content, pattern_name, pattern_info, content_type, context))

        # Apply ML context analysis to reduce false positives
        matches = self._apply_ml_context_analysis(matches, context)

        # Sort by severity and confidence
        matches.sort(
            key=lambda x: (0 if x.severity == "critical" else 1 if x.severity == "warning" else 2, -x.confidence)
        )

        return matches

    def _detect_and_deobfuscate(self, text_data: str) -> list[tuple[str, str]]:
        """Detect and deobfuscate encoded content."""
        deobfuscated = []

        for obf_pattern in self.obfuscation_patterns:
            pattern = obf_pattern["pattern"]
            decoder = obf_pattern["decoder"]
            min_length = obf_pattern.get("min_length", 0)

            matches = re.finditer(pattern, text_data)

            for match in matches:
                matched_text = match.group(0)

                if len(matched_text) >= min_length:
                    try:
                        decoded = decoder(matched_text)
                        if decoded and len(decoded) > 3:  # Reasonable decoded content
                            deobfuscated.append((f"deobfuscated_{obf_pattern['name']}", decoded))
                    except Exception as e:
                        logger.debug(f"Failed to decode {obf_pattern['name']}: {e}")

        return deobfuscated

    def _find_pattern_matches(
        self,
        content: str,
        pattern_name: str,
        pattern_info: dict[str, Any],
        content_type: str,
        context: dict[str, Any] | None,
    ) -> list[PatternMatch]:
        """Find pattern matches in content."""
        matches = []

        for pattern_regex in pattern_info["patterns"]:
            for match in re.finditer(pattern_regex, content, re.IGNORECASE):
                # Calculate base confidence
                confidence = self._calculate_base_confidence(match, content, content_type)

                # Create match object
                pattern_match = PatternMatch(
                    pattern_name=pattern_name,
                    matched_text=match.group(0),
                    position=match.start(),
                    severity=pattern_info["severity"],
                    confidence=confidence,
                    context={
                        "category": pattern_info["category"],
                        "description": pattern_info["description"],
                        "content_type": content_type,
                        "surrounding_context": self._extract_surrounding_context(content, match),
                    },
                    deobfuscated_text=content if content_type.startswith("deobfuscated") else None,
                )

                matches.append(pattern_match)

        return matches

    def _calculate_base_confidence(self, match: re.Match, content: str, content_type: str) -> float:
        """Calculate base confidence for a pattern match."""
        base_confidence = 0.7

        # Higher confidence for exact matches
        matched_text = match.group(0)
        if matched_text.endswith("("):
            base_confidence += 0.1  # Likely function call

        # Higher confidence for deobfuscated content
        if content_type.startswith("deobfuscated"):
            base_confidence += 0.2

        # Context analysis
        surrounding = self._extract_surrounding_context(content, match)

        # Lower confidence if surrounded by comments or documentation
        if "#" in surrounding or "//" in surrounding:
            base_confidence -= 0.2

        # Lower confidence for documentation-like contexts
        doc_indicators = ["documentation", "comment", "note", "description", "does not use", "safe"]
        if any(indicator in surrounding.lower() for indicator in doc_indicators):
            base_confidence -= 0.3

        # Higher confidence for dangerous argument patterns
        dangerous_args = ["shell=True", "/bin/sh", "cmd.exe", "/c ", ";", "&&", "||"]
        for arg in dangerous_args:
            if arg in surrounding:
                base_confidence += 0.15
                break

        return max(min(base_confidence, 1.0), 0.1)

    def _extract_surrounding_context(self, content: str, match: re.Match, window: int = 100) -> str:
        """Extract surrounding context for a match."""
        start = max(0, match.start() - window)
        end = min(len(content), match.end() + window)
        return content[start:end]

    def _apply_ml_context_analysis(
        self, matches: list[PatternMatch], context: dict[str, Any] | None
    ) -> list[PatternMatch]:
        """Apply ML context analysis to reduce false positives."""
        if not matches:
            return matches

        # Get stack context if available
        stack_context = []
        if context:
            stack_context = context.get("stack_state", [])
            if isinstance(stack_context, list):
                stack_context = [str(item) for item in stack_context]

        for match in matches:
            # Check if this looks like an ML operation
            ml_result = self.ml_analyzer.analyze_context(
                match.matched_text, stack_context, context.get("file_path") if context else None
            )

            # Apply ML context adjustment
            match.ml_context_adjustment = ml_result.risk_adjustment

            # Update confidence based on ML context
            if ml_result.confidence > 0.5:
                # High confidence ML context - boost overall confidence in our assessment
                match.confidence = min(match.confidence * 1.2, 1.0)

                # Add ML context to match context
                match.context.update(
                    {
                        "ml_framework": ml_result.framework.value,
                        "ml_explanation": ml_result.explanation,
                        "ml_confidence": ml_result.confidence,
                        "original_risk_adjustment": ml_result.risk_adjustment,
                    }
                )

        return matches

    def is_whitelisted_ml_operation(self, function_call: str, framework: str = "any") -> bool:
        """Check if a function call is a whitelisted ML operation."""
        if framework == "any":
            # Check all framework whitelists
            for framework_patterns in self.ml_whitelist_patterns.values():
                for pattern in framework_patterns:
                    if re.search(pattern, function_call, re.IGNORECASE):
                        return True
        else:
            # Check specific framework whitelist
            framework_key = f"{framework}_safe_operations"
            if framework_key in self.ml_whitelist_patterns:
                for pattern in self.ml_whitelist_patterns[framework_key]:
                    if re.search(pattern, function_call, re.IGNORECASE):
                        return True

        return False

    def get_pattern_statistics(self, matches: list[PatternMatch]) -> dict[str, Any]:
        """Get statistics about detected patterns."""
        if not matches:
            return {"total_matches": 0, "severity_breakdown": {}, "category_breakdown": {}, "ml_adjusted_matches": 0}

        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        ml_adjusted_count = 0

        for match in matches:
            # Count by severity
            severity = match.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Count by category
            category = match.context.get("category", "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1

            # Count ML adjustments
            if match.ml_context_adjustment < 0.9:  # Significant risk reduction
                ml_adjusted_count += 1

        return {
            "total_matches": len(matches),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "ml_adjusted_matches": ml_adjusted_count,
            "ml_adjustment_rate": ml_adjusted_count / len(matches) if matches else 0,
        }
