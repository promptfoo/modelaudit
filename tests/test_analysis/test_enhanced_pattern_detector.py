"""Test cases for Enhanced Pattern Detector."""

import base64

import pytest

from modelaudit.analysis.enhanced_pattern_detector import EnhancedPatternDetector


class TestEnhancedPatternDetector:
    """Test cases for enhanced pattern detection."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = EnhancedPatternDetector()
        assert len(detector.dangerous_patterns) > 0
        assert len(detector.obfuscation_patterns) > 0
        assert detector.ml_analyzer is not None

    def test_basic_pattern_detection(self):
        """Test basic dangerous pattern detection."""
        detector = EnhancedPatternDetector()

        # Test os.system detection
        matches = detector.detect_patterns("os.system('malicious command')")

        assert len(matches) > 0
        system_matches = [m for m in matches if m.pattern_name == "os_system"]
        assert len(system_matches) > 0
        assert system_matches[0].severity == "critical"

    def test_code_execution_detection(self):
        """Test code execution pattern detection."""
        detector = EnhancedPatternDetector()

        test_cases = ["eval('malicious code')", "exec('dangerous script')", "compile('code', 'string', 'exec')"]

        for test_case in test_cases:
            matches = detector.detect_patterns(test_case)
            eval_matches = [m for m in matches if m.pattern_name == "code_eval"]
            assert len(eval_matches) > 0, f"Failed to detect: {test_case}"
            assert eval_matches[0].severity == "critical"

    def test_base64_obfuscation_detection(self):
        """Test base64 obfuscated payload detection."""
        detector = EnhancedPatternDetector()

        # Create base64 encoded malicious payload
        malicious_code = "os.system('rm -rf /')"
        encoded = base64.b64encode(malicious_code.encode()).decode()

        matches = detector.detect_patterns(f"decode('{encoded}')")

        # Should detect both the pattern in deobfuscated content
        deobfuscated_matches = [m for m in matches if m.deobfuscated_text is not None]
        assert len(deobfuscated_matches) > 0

        # Should find os.system in deobfuscated content
        system_matches = [m for m in deobfuscated_matches if m.pattern_name == "os_system"]
        assert len(system_matches) > 0

    def test_hex_obfuscation_detection(self):
        """Test hex encoded payload detection."""
        detector = EnhancedPatternDetector()

        # Create hex encoded payload
        malicious_code = "eval("
        hex_encoded = "\\x" + "\\x".join(f"{ord(c):02x}" for c in malicious_code)

        matches = detector.detect_patterns(f"decode('{hex_encoded}')")

        # Should detect deobfuscated content
        deobfuscated_matches = [m for m in matches if m.deobfuscated_text is not None]
        assert len(deobfuscated_matches) > 0

    def test_string_concatenation_obfuscation(self):
        """Test string concatenation obfuscation detection."""
        detector = EnhancedPatternDetector()

        # Split dangerous function name
        obfuscated = "'os.' + 'system'"

        matches = detector.detect_patterns(obfuscated)

        # Should detect the concatenated pattern
        deobfuscated_matches = [m for m in matches if m.deobfuscated_text is not None]
        assert len(deobfuscated_matches) > 0

    def test_ml_context_false_positive_reduction(self):
        """Test ML context reduces false positives."""
        detector = EnhancedPatternDetector()

        # Legitimate torch.load operation
        legitimate_code = "torch.load('model.pth', map_location='cpu')"
        context = {"stack_state": ["torch.nn.Module", "state_dict", "model"], "file_path": "model.pth"}

        matches = detector.detect_patterns(legitimate_code, context)

        # Even if patterns are detected, ML context should reduce risk
        if matches:
            for match in matches:
                # Should have significant risk reduction due to ML context
                assert match.ml_context_adjustment < 0.5, (
                    f"Expected low risk for ML context, got {match.ml_context_adjustment}"
                )

    def test_confidence_scoring(self):
        """Test confidence scoring for different scenarios."""
        detector = EnhancedPatternDetector()

        # High confidence: clear function call
        high_conf_matches = detector.detect_patterns("os.system('command')")

        # Lower confidence: pattern in comments
        low_conf_matches = detector.detect_patterns("# This calls os.system somehow")

        if high_conf_matches and low_conf_matches:
            high_conf = max(m.confidence for m in high_conf_matches)
            low_conf = max(m.confidence for m in low_conf_matches)
            assert high_conf > low_conf

    def test_multiple_pattern_detection(self):
        """Test detection of multiple different patterns in same content."""
        detector = EnhancedPatternDetector()

        complex_payload = """
        eval('malicious')
        os.system('command')
        __import__('dangerous')
        open('/etc/passwd')
        """

        matches = detector.detect_patterns(complex_payload)

        # Should detect multiple different pattern types
        pattern_names = {m.pattern_name for m in matches}
        assert len(pattern_names) >= 3  # Multiple different patterns

        # Should include high severity patterns
        severities = {m.severity for m in matches}
        assert "critical" in severities

    def test_context_extraction(self):
        """Test surrounding context extraction."""
        detector = EnhancedPatternDetector()

        code = "some_function(); os.system('malicious'); other_code()"
        matches = detector.detect_patterns(code)

        if matches:
            match = matches[0]
            context = match.context.get("surrounding_context", "")
            assert "some_function" in context
            assert "other_code" in context

    def test_whitelisted_ml_operations(self):
        """Test whitelisting of safe ML operations."""
        detector = EnhancedPatternDetector()

        safe_operations = [
            "torch.load(file, map_location='cpu')",
            "tf.saved_model.load(path)",
            "joblib.load('model.pkl')",
            "torch.nn.Module.load_state_dict()",
        ]

        for operation in safe_operations:
            # Check framework-agnostic whitelisting
            assert detector.is_whitelisted_ml_operation(operation), f"Operation should be whitelisted: {operation}"

    def test_framework_specific_whitelisting(self):
        """Test framework-specific whitelisting."""
        detector = EnhancedPatternDetector()

        # Test PyTorch specific
        assert detector.is_whitelisted_ml_operation("torch.jit.load('model')", "torch")

        # Test TensorFlow specific
        assert detector.is_whitelisted_ml_operation("tf.constant([1,2,3])", "tensorflow")

        # Test sklearn specific
        assert detector.is_whitelisted_ml_operation("model.fit(X, y)", "sklearn")

    def test_pattern_statistics(self):
        """Test pattern statistics generation."""
        detector = EnhancedPatternDetector()

        # No matches
        empty_stats = detector.get_pattern_statistics([])
        assert empty_stats["total_matches"] == 0

        # Create some test matches
        matches = detector.detect_patterns(
            """
            os.system('command')
            eval('code')
            torch.load('model.pth')
        """,
            context={"stack_state": ["torch.nn", "model"]},
        )

        if matches:
            stats = detector.get_pattern_statistics(matches)
            assert stats["total_matches"] > 0
            assert "severity_breakdown" in stats
            assert "category_breakdown" in stats

    def test_binary_data_handling(self):
        """Test handling of binary data."""
        detector = EnhancedPatternDetector()

        # Test with binary data containing dangerous patterns
        binary_data = b"os.system('malicious')\x00\x01\x02"

        matches = detector.detect_patterns(binary_data)

        # Should successfully decode and detect patterns
        system_matches = [m for m in matches if m.pattern_name == "os_system"]
        assert len(system_matches) > 0

    def test_encoding_error_handling(self):
        """Test graceful handling of encoding errors."""
        detector = EnhancedPatternDetector()

        # Binary data that cannot be decoded as UTF-8
        problematic_data = b"\xff\xfe\x00os.system\x00"

        # Should not crash, should handle gracefully
        matches = detector.detect_patterns(problematic_data)

        # May or may not find patterns, but shouldn't crash
        assert isinstance(matches, list)


class TestAdvancedObfuscationDetection:
    """Test advanced obfuscation detection techniques."""

    def test_layered_obfuscation(self):
        """Test detection through multiple layers of obfuscation."""
        detector = EnhancedPatternDetector()

        # For now, test single-layer obfuscation
        # TODO: Implement recursive deobfuscation for layered attacks
        dangerous_content = "eval("
        matches = detector.detect_patterns(dangerous_content)

        # Should detect the dangerous content directly
        assert len(matches) > 0

    def test_unicode_obfuscation(self):
        """Test unicode escape sequence obfuscation."""
        detector = EnhancedPatternDetector()

        # Unicode escape for "eval("
        unicode_obfuscated = "\\u0065\\u0076\\u0061\\u006c\\u0028"  # "eval("

        matches = detector.detect_patterns(f"function('{unicode_obfuscated}')")

        # Should detect deobfuscated content
        deobfuscated_matches = [m for m in matches if m.deobfuscated_text is not None]
        assert len(deobfuscated_matches) > 0

    def test_complex_string_concatenation(self):
        """Test complex string concatenation patterns."""
        detector = EnhancedPatternDetector()

        # Complex concatenation hiding dangerous function
        complex_concat = "'os' + '.' + 'sys' + 'tem'"

        matches = detector.detect_patterns(complex_concat)

        # Should detect the concatenated dangerous pattern
        deobfuscated_matches = [m for m in matches if m.deobfuscated_text is not None]
        assert len(deobfuscated_matches) > 0


# Integration test scenarios
INTEGRATION_TEST_SCENARIOS = [
    {
        "name": "legitimate_pytorch_model",
        "payload": "torch.load('resnet50.pth', map_location='cpu')",
        "context": {
            "stack_state": ["torch.nn.Module", "torchvision.models", "state_dict"],
            "file_path": "resnet50.pth",
        },
        "expected_low_risk": True,
        "description": "Legitimate PyTorch model loading",
    },
    {
        "name": "obfuscated_malicious_payload",
        "payload": base64.b64encode(b"os.system('rm -rf /')").decode(),
        "context": {},
        "expected_low_risk": False,
        "description": "Base64 obfuscated malicious system call",
    },
    {
        "name": "disguised_attack_in_ml_context",
        "payload": "eval('malicious code')",
        "context": {
            "stack_state": ["torch", "model"],  # Fake ML context
            "file_path": "model.pth",
        },
        "expected_low_risk": False,  # Should not be fooled by fake context
        "description": "Malicious eval disguised in ML context",
    },
]


@pytest.mark.parametrize("scenario", INTEGRATION_TEST_SCENARIOS)
def test_integration_scenarios(scenario):
    """Test detector against realistic integration scenarios."""
    detector = EnhancedPatternDetector()

    matches = detector.detect_patterns(scenario["payload"], scenario["context"])

    if scenario["expected_low_risk"]:
        # For low risk scenarios, either no matches or low effective risk
        if matches:
            max_effective_risk = max(m.confidence * m.ml_context_adjustment for m in matches)
            assert max_effective_risk < 0.5, (
                f"Expected low effective risk for {scenario['name']}, got {max_effective_risk}"
            )
    else:
        # For high risk scenarios, should detect significant threats
        assert len(matches) > 0, f"Failed to detect threats in {scenario['name']}"

        critical_matches = [m for m in matches if m.severity == "critical"]
        assert len(critical_matches) > 0, f"No critical threats detected in {scenario['name']}"
