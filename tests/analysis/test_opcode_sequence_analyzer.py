"""Test cases for OpcodeSequenceAnalyzer."""

import pytest

from modelaudit.analysis.opcode_sequence_analyzer import OpcodePattern, OpcodeSequenceAnalyzer


class TestOpcodeSequenceAnalyzer:
    """Test cases for opcode sequence analysis."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = OpcodeSequenceAnalyzer()
        assert analyzer.window_size == 10
        assert len(analyzer.patterns) > 0
        assert len(analyzer.detected_patterns) == 0

    def test_direct_function_call_detection(self):
        """Test detection of GLOBAL -> REDUCE attack pattern."""
        analyzer = OpcodeSequenceAnalyzer()

        # Simulate dangerous pattern: os.system call
        result1 = analyzer.analyze_opcode("GLOBAL", ("os", "system"), 100)
        assert len(result1) == 0  # No pattern yet

        result2 = analyzer.analyze_opcode("REDUCE", None, 101)
        assert len(result2) == 1  # Pattern detected

        pattern_result = result2[0]
        assert pattern_result.pattern_name == "direct_function_call"
        assert pattern_result.severity == "critical"
        assert pattern_result.matched_opcodes == ["GLOBAL", "REDUCE"]

    def test_dynamic_import_detection(self):
        """Test detection of dynamic import patterns."""
        analyzer = OpcodeSequenceAnalyzer()

        # Simulate STACK_GLOBAL -> BUILD_TUPLE -> REDUCE pattern
        analyzer.analyze_opcode("STACK_GLOBAL", None, 100)
        analyzer.analyze_opcode("BUILD_TUPLE", 2, 101)
        results = analyzer.analyze_opcode("REDUCE", None, 102)

        assert len(results) == 1
        pattern_result = results[0]
        assert pattern_result.pattern_name == "dynamic_import_with_args"
        assert pattern_result.severity == "critical"

    def test_chained_function_calls(self):
        """Test detection of chained REDUCE operations."""
        analyzer = OpcodeSequenceAnalyzer()

        # Create a chained function call scenario: REDUCE -> GLOBAL -> REDUCE
        analyzer.analyze_opcode("GLOBAL", ("subprocess", "Popen"), 100)
        analyzer.analyze_opcode("BUILD_TUPLE", 1, 101)
        analyzer.analyze_opcode("REDUCE", None, 102)  # First REDUCE
        analyzer.analyze_opcode("GLOBAL", ("os", "system"), 103)  # Second function
        results = analyzer.analyze_opcode("REDUCE", None, 104)  # Second REDUCE

        # Should detect chained function calls
        chained_results = [r for r in results if r.pattern_name == "chained_function_calls"]
        assert len(chained_results) == 1

    def test_stack_simulation(self):
        """Test stack simulation for context."""
        analyzer = OpcodeSequenceAnalyzer()

        # Simulate stack operations
        analyzer.analyze_opcode("GLOBAL", ("os", "system"), 100)
        assert "os.system" in analyzer.stack_simulation

        analyzer.analyze_opcode("BUILD_TUPLE", 1, 101)
        analyzer.analyze_opcode("REDUCE", None, 102)

        # Stack should show function call simulation
        assert any("os.system" in str(item) for item in analyzer.stack_simulation)

    def test_confidence_calculation(self):
        """Test confidence scoring."""
        analyzer = OpcodeSequenceAnalyzer()

        # High confidence scenario: dangerous function + pattern match
        analyzer.analyze_opcode("GLOBAL", ("os", "system"), 100)
        results = analyzer.analyze_opcode("REDUCE", None, 101)

        assert len(results) == 1
        assert results[0].confidence > 0.8  # High confidence for os.system

    def test_multiple_pattern_detection(self):
        """Test detection of multiple different patterns."""
        analyzer = OpcodeSequenceAnalyzer()

        # Create a complex sequence with multiple patterns
        opcodes = [
            ("GLOBAL", ("os", "system")),
            ("REDUCE", None),  # First pattern: direct_function_call
            ("STACK_GLOBAL", None),
            ("BUILD_TUPLE", 2),
            ("REDUCE", None),  # Second pattern: dynamic_import_with_args
        ]

        all_results = []
        for i, (opcode, arg) in enumerate(opcodes):
            results = analyzer.analyze_opcode(opcode, arg, i)
            all_results.extend(results)

        # Should detect both patterns
        pattern_names = {r.pattern_name for r in all_results}
        assert "direct_function_call" in pattern_names
        assert "dynamic_import_with_args" in pattern_names

    def test_analysis_summary(self):
        """Test analysis summary generation."""
        analyzer = OpcodeSequenceAnalyzer()

        # No patterns detected
        summary = analyzer.get_analysis_summary()
        assert summary["patterns_detected"] == 0
        assert summary["max_severity"] == "info"

        # Add some patterns
        analyzer.analyze_opcode("GLOBAL", ("os", "system"), 100)
        analyzer.analyze_opcode("REDUCE", None, 101)

        summary = analyzer.get_analysis_summary()
        assert summary["patterns_detected"] > 0
        assert summary["max_severity"] == "critical"

    def test_reset_functionality(self):
        """Test analyzer reset."""
        analyzer = OpcodeSequenceAnalyzer()

        # Add some data
        analyzer.analyze_opcode("GLOBAL", ("os", "system"), 100)
        analyzer.analyze_opcode("REDUCE", None, 101)

        assert len(analyzer.detected_patterns) > 0
        assert len(analyzer.opcode_window) > 0

        # Reset and verify clean state
        analyzer.reset()
        assert len(analyzer.detected_patterns) == 0
        assert len(analyzer.opcode_window) == 0
        assert len(analyzer.stack_simulation) == 0

    def test_window_size_limit(self):
        """Test that opcode window respects size limit."""
        analyzer = OpcodeSequenceAnalyzer(window_size=3)

        # Add more opcodes than window size
        for i in range(5):
            analyzer.analyze_opcode(f"OPCODE_{i}", None, i)

        # Window should only contain last 3 opcodes
        assert len(analyzer.opcode_window) == 3
        assert list(analyzer.opcode_window) == ["OPCODE_2", "OPCODE_3", "OPCODE_4"]

    def test_pattern_matching_logic(self):
        """Test pattern matching logic directly."""
        pattern = OpcodePattern(
            name="test_pattern", opcodes=["A", "B", "C"], description="Test pattern", severity="warning"
        )

        # Exact match at end
        assert pattern.matches(["X", "Y", "A", "B", "C"])

        # No match - different sequence
        assert not pattern.matches(["A", "B", "X"])

        # No match - too short
        assert not pattern.matches(["A", "B"])

        # No match - pattern in middle but not at end
        assert not pattern.matches(["A", "B", "C", "X", "Y"])


class TestOpcodePattern:
    """Test cases for OpcodePattern class."""

    def test_pattern_creation(self):
        """Test pattern creation."""
        pattern = OpcodePattern(
            name="test",
            opcodes=["GLOBAL", "REDUCE"],
            description="Test pattern",
            severity="critical",
            cve_references=["CVE-2019-16935"],
        )

        assert pattern.name == "test"
        assert pattern.opcodes == ["GLOBAL", "REDUCE"]
        assert pattern.severity == "critical"
        assert pattern.cve_references is not None and "CVE-2019-16935" in pattern.cve_references

    def test_pattern_matching(self):
        """Test pattern matching method."""
        pattern = OpcodePattern(name="test", opcodes=["GLOBAL", "REDUCE"], description="Test", severity="warning")

        # Should match when pattern is at the end
        assert pattern.matches(["OTHER", "GLOBAL", "REDUCE"])

        # Should not match when pattern is not at the end
        assert not pattern.matches(["GLOBAL", "REDUCE", "OTHER"])


# Integration test data for real-world scenarios
REAL_WORLD_TEST_CASES = [
    {
        "name": "CVE-2019-16935_reproduction",
        "description": "Reproduction of known pickle vulnerability",
        "opcodes": [("GLOBAL", ("os", "system")), ("REDUCE", None)],
        "expected_patterns": ["direct_function_call"],
        "expected_severity": "critical",
    },
    {
        "name": "complex_attack_chain",
        "description": "Multi-step attack using multiple techniques",
        "opcodes": [
            ("STACK_GLOBAL", None),  # Dynamic import
            ("BUILD_TUPLE", 2),
            ("REDUCE", None),
            ("GLOBAL", ("subprocess", "call")),  # Then subprocess
            ("REDUCE", None),
        ],
        "expected_patterns": ["dynamic_import_with_args", "chained_function_calls"],
        "expected_severity": "critical",
    },
]


@pytest.mark.parametrize("test_case", REAL_WORLD_TEST_CASES)
def test_real_world_scenarios(test_case):
    """Test analyzer against real-world attack scenarios."""
    analyzer = OpcodeSequenceAnalyzer()

    all_results = []
    for opcode, arg in test_case["opcodes"]:
        results = analyzer.analyze_opcode(opcode, arg)
        all_results.extend(results)

    # Check that expected patterns were detected
    detected_patterns = {r.pattern_name for r in all_results}
    for expected_pattern in test_case["expected_patterns"]:
        assert expected_pattern in detected_patterns, (
            f"Expected pattern '{expected_pattern}' not detected in {test_case['name']}"
        )

    # Check severity (proper severity ordering)
    severity_order = {"info": 0, "warning": 1, "critical": 2}
    max_severity = max((r.severity for r in all_results), key=lambda s: severity_order.get(s, 0), default="info")
    assert max_severity == test_case["expected_severity"], (
        f"Expected severity '{test_case['expected_severity']}' but got '{max_severity}'"
    )
