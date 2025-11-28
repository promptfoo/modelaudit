"""Advanced opcode sequence analysis for pickle security.

This module analyzes sequences and patterns of pickle opcodes to detect sophisticated
attack techniques that use combinations of individually safe opcodes to perform
malicious operations.
"""

import logging
from collections import deque
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class OpcodePattern:
    """Represents a dangerous opcode sequence pattern."""

    name: str
    opcodes: list[str]
    description: str
    severity: str
    cve_references: list[str] | None = None

    def matches(self, opcode_window: list[str]) -> bool:
        """Check if the opcode window matches this pattern."""
        if len(opcode_window) < len(self.opcodes):
            return False

        # Check for exact sequence match at the end of the window
        window_end = opcode_window[-len(self.opcodes) :]
        return window_end == self.opcodes


@dataclass
class SequenceAnalysisResult:
    """Result of opcode sequence analysis."""

    pattern_name: str
    matched_opcodes: list[str]
    position: int | None
    severity: str
    description: str
    evidence: dict[str, Any]
    confidence: float


class OpcodeSequenceAnalyzer:
    """Analyzes pickle opcode sequences for dangerous patterns.

    This analyzer detects attack patterns that combine multiple opcodes to perform
    malicious operations, such as:
    - Function call chains (GLOBAL -> REDUCE)
    - Dynamic imports (STACK_GLOBAL -> BUILD_* -> REDUCE)
    - Object instantiation attacks (INST -> BUILD_* -> REDUCE)
    - Complex nested operations
    """

    def __init__(self, window_size: int = 10):
        """Initialize the opcode sequence analyzer.

        Args:
            window_size: Number of recent opcodes to keep in analysis window
        """
        self.window_size = window_size
        self.opcode_window: deque[str] = deque(maxlen=window_size)
        self.stack_simulation: list[Any] = []
        self.patterns = self._initialize_attack_patterns()
        self.detected_patterns: list[SequenceAnalysisResult] = []

    def _initialize_attack_patterns(self) -> list[OpcodePattern]:
        """Initialize known dangerous opcode patterns."""
        return [
            # Direct function call pattern
            OpcodePattern(
                name="direct_function_call",
                opcodes=["GLOBAL", "REDUCE"],
                description="Direct function call using GLOBAL + REDUCE pattern",
                severity="critical",
                cve_references=["CVE-2019-16935"],
            ),
            # Dynamic import with arguments
            OpcodePattern(
                name="dynamic_import_with_args",
                opcodes=["STACK_GLOBAL", "BUILD_TUPLE", "REDUCE"],
                description="Dynamic import with arguments using STACK_GLOBAL pattern",
                severity="critical",
            ),
            # Alternative dynamic import patterns
            OpcodePattern(
                name="dynamic_import_list",
                opcodes=["STACK_GLOBAL", "BUILD_LIST", "REDUCE"],
                description="Dynamic import with list arguments",
                severity="critical",
            ),
            # Object instantiation attack
            OpcodePattern(
                name="dangerous_instantiation",
                opcodes=["INST", "BUILD_TUPLE", "REDUCE"],
                description="Dangerous object instantiation with constructor arguments",
                severity="warning",
            ),
            # Chained function calls (REDUCE followed by GLOBAL/REDUCE sequence)
            OpcodePattern(
                name="chained_function_calls",
                opcodes=["REDUCE", "GLOBAL", "REDUCE"],
                description="Chained function calls that could escalate privileges",
                severity="warning",
            ),
            # Build and execute pattern
            OpcodePattern(
                name="build_and_execute",
                opcodes=["BUILD_STRING", "GLOBAL", "REDUCE"],
                description="String construction followed by execution",
                severity="critical",
            ),
            # Stack manipulation for obfuscation
            OpcodePattern(
                name="stack_manipulation_obfuscation",
                opcodes=["DUP", "ROT", "GLOBAL", "REDUCE"],
                description="Stack manipulation potentially used for obfuscation",
                severity="warning",
            ),
        ]

    def analyze_opcode(
        self, opcode_name: str, arg: Any = None, position: int | None = None
    ) -> list[SequenceAnalysisResult]:
        """Analyze a single opcode in the context of recent opcodes.

        Args:
            opcode_name: Name of the current opcode
            arg: Opcode argument (if any)
            position: Position in the pickle stream

        Returns:
            List of detected attack patterns
        """
        # Add current opcode to analysis window
        self.opcode_window.append(opcode_name)

        # Simulate stack operations for context
        self._simulate_stack_operation(opcode_name, arg)

        # Check for pattern matches
        results = []
        current_window = list(self.opcode_window)

        for pattern in self.patterns:
            if pattern.matches(current_window):
                result = self._analyze_pattern_match(pattern, current_window, position)
                if result:
                    results.append(result)
                    self.detected_patterns.append(result)

        return results

    def _simulate_stack_operation(self, opcode_name: str, arg: Any) -> None:
        """Simulate pickle stack operations for context analysis."""
        try:
            # Simple simulation of key stack operations
            if opcode_name == "GLOBAL" and arg:
                # GLOBAL pushes module.name onto stack
                module, name = arg
                self.stack_simulation.append(f"{module}.{name}")

            elif opcode_name == "STACK_GLOBAL":
                # STACK_GLOBAL pops module and name from stack
                if len(self.stack_simulation) >= 2:
                    name = self.stack_simulation.pop()
                    module = self.stack_simulation.pop()
                    self.stack_simulation.append(f"{module}.{name}")

            elif opcode_name in ["BUILD_TUPLE", "BUILD_LIST"]:
                # BUILD_* operations consume stack items
                if arg and isinstance(arg, int) and len(self.stack_simulation) >= arg:
                    items = []
                    for _ in range(arg):
                        items.append(self.stack_simulation.pop())
                    self.stack_simulation.append(f"[{', '.join(reversed(items))}]")

            elif opcode_name == "REDUCE":
                # REDUCE pops function and args, simulates call
                if len(self.stack_simulation) >= 2:
                    args = self.stack_simulation.pop()
                    func = self.stack_simulation.pop()
                    self.stack_simulation.append(f"{func}({args})")

            elif opcode_name in ["DUP", "DUP2"]:
                # Duplicate top stack items
                if self.stack_simulation:
                    self.stack_simulation.append(self.stack_simulation[-1])

            elif opcode_name == "POP":
                # Remove top item
                if self.stack_simulation:
                    self.stack_simulation.pop()

        except Exception as e:
            # Stack simulation is best-effort, don't fail analysis on errors
            logger.debug(f"Stack simulation error for {opcode_name}: {e}")

    def _analyze_pattern_match(
        self, pattern: OpcodePattern, window: list[str], position: int | None
    ) -> SequenceAnalysisResult | None:
        """Analyze a detected pattern match for detailed results."""
        try:
            # Get evidence from stack simulation
            evidence = {
                "stack_state": self.stack_simulation.copy(),
                "opcode_window": window.copy(),
                "pattern_opcodes": pattern.opcodes,
            }

            # Calculate confidence based on context
            confidence = self._calculate_confidence(pattern, evidence)

            # Extract relevant opcodes that matched
            matched_opcodes = window[-len(pattern.opcodes) :]

            return SequenceAnalysisResult(
                pattern_name=pattern.name,
                matched_opcodes=matched_opcodes,
                position=position,
                severity=pattern.severity,
                description=pattern.description,
                evidence=evidence,
                confidence=confidence,
            )

        except Exception as e:
            logger.warning(f"Error analyzing pattern {pattern.name}: {e}")
            return None

    def _calculate_confidence(self, pattern: OpcodePattern, evidence: dict[str, Any]) -> float:
        """Calculate confidence score for a pattern match."""
        base_confidence = 0.7  # Base confidence for pattern match

        # Increase confidence based on stack context
        stack_state = evidence.get("stack_state", [])

        # Higher confidence if we can see dangerous function names in stack
        dangerous_functions = ["system", "exec", "eval", "__import__", "open", "compile"]
        for item in stack_state:
            if isinstance(item, str):
                for func in dangerous_functions:
                    if func in item.lower():
                        base_confidence += 0.15
                        break

        # Higher confidence for patterns with CVE references
        if pattern.cve_references:
            base_confidence += 0.1

        # Adjust for pattern severity
        if pattern.severity == "critical":
            base_confidence += 0.05

        return min(base_confidence, 1.0)

    def get_analysis_summary(self) -> dict[str, Any]:
        """Get summary of all detected patterns."""
        if not self.detected_patterns:
            return {"patterns_detected": 0, "max_severity": "info", "summary": "No dangerous opcode sequences detected"}

        # Group by severity
        severity_counts: dict[str, int] = {}
        for result in self.detected_patterns:
            severity = result.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Determine max severity
        severity_order = ["critical", "warning", "info"]
        max_severity = "info"
        for severity in severity_order:
            if severity in severity_counts:
                max_severity = severity
                break

        return {
            "patterns_detected": len(self.detected_patterns),
            "severity_breakdown": severity_counts,
            "max_severity": max_severity,
            "unique_patterns": len({r.pattern_name for r in self.detected_patterns}),
            "summary": f"Detected {len(self.detected_patterns)} dangerous opcode sequences",
        }

    def reset(self) -> None:
        """Reset analyzer state for new analysis."""
        self.opcode_window.clear()
        self.stack_simulation.clear()
        self.detected_patterns.clear()
