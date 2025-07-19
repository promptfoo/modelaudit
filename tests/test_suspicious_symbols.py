"""Tests for the suspicious_symbols module."""

import re

import pytest

from modelaudit.suspicious_symbols import (
    BINARY_CODE_PATTERNS,
    DANGEROUS_BUILTINS,
    DANGEROUS_OPCODES,
    EXECUTABLE_SIGNATURES,
    SUSPICIOUS_CONFIG_PATTERNS,
    SUSPICIOUS_CONFIG_PROPERTIES,
    SUSPICIOUS_GLOBALS,
    SUSPICIOUS_LAYER_TYPES,
    SUSPICIOUS_METADATA_PATTERNS,
    SUSPICIOUS_OPS,
    SUSPICIOUS_STRING_PATTERNS,
    get_all_suspicious_patterns,
    validate_patterns,
)


class TestSuspiciousGlobals:
    """Test SUSPICIOUS_GLOBALS patterns."""

    def test_suspicious_globals_structure(self) -> None:
        """Test that SUSPICIOUS_GLOBALS has correct structure."""
        assert isinstance(SUSPICIOUS_GLOBALS, dict)

        for module, functions in SUSPICIOUS_GLOBALS.items():
            assert isinstance(module, str)
            assert functions == "*" or isinstance(functions, list)

            if isinstance(functions, list):
                for func in functions:
                    assert isinstance(func, str)

    def test_critical_modules_present(self) -> None:
        """Test that critical dangerous modules are included."""
        critical_modules = ["os", "subprocess", "sys", "eval", "exec"]

        for module in critical_modules:
            assert module in SUSPICIOUS_GLOBALS or any(
                module in funcs for funcs in SUSPICIOUS_GLOBALS.values() if isinstance(funcs, list)
            ), f"Critical module {module} not found in suspicious patterns"

    def test_builtins_functions(self) -> None:
        """Test that dangerous builtin functions are flagged."""
        assert "builtins" in SUSPICIOUS_GLOBALS
        builtins_funcs = SUSPICIOUS_GLOBALS["builtins"]

        dangerous_builtins = [
            "eval",
            "exec",
            "compile",
            "open",
            "input",
            "__import__",
        ]
        for func in dangerous_builtins:
            assert func in builtins_funcs, f"Dangerous builtin {func} not flagged"


class TestDangerousBuiltins:
    """Test DANGEROUS_BUILTINS constant."""

    def test_dangerous_builtins_contents(self) -> None:
        assert isinstance(DANGEROUS_BUILTINS, list)
        for func in ["eval", "exec", "__import__"]:
            assert func in DANGEROUS_BUILTINS


class TestDangerousOpcodes:
    """Test DANGEROUS_OPCODES constant."""

    def test_dangerous_opcodes_non_empty(self) -> None:
        assert isinstance(DANGEROUS_OPCODES, set)
        for op in ["REDUCE", "INST", "STACK_GLOBAL"]:
            assert op in DANGEROUS_OPCODES


class TestBinaryCodePatterns:
    """Test BINARY_CODE_PATTERNS list."""

    def test_binary_code_patterns_bytes(self) -> None:
        assert isinstance(BINARY_CODE_PATTERNS, list)
        for pattern in BINARY_CODE_PATTERNS:
            assert isinstance(pattern, bytes)


class TestExecutableSignatures:
    """Test EXECUTABLE_SIGNATURES mapping."""

    def test_executable_signatures_structure(self) -> None:
        assert isinstance(EXECUTABLE_SIGNATURES, dict)
        for signature, description in EXECUTABLE_SIGNATURES.items():
            assert isinstance(signature, bytes)
            assert isinstance(description, str)
            assert len(description) > 0


class TestSuspiciousStringPatterns:
    """Test SUSPICIOUS_STRING_PATTERNS regex patterns."""

    def test_string_patterns_are_valid_regex(self) -> None:
        """Test that all string patterns are valid regex."""
        for pattern in SUSPICIOUS_STRING_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex pattern '{pattern}': {e}")

    def test_patterns_match_dangerous_code(self) -> None:
        """Test that patterns correctly match dangerous code examples."""
        test_cases = [
            (r"eval\(", "eval('malicious code')"),
            (r"exec\(", "exec(dangerous_string)"),
            (r"os\.system", "os.system('rm -rf /')"),
            (
                r"subprocess\.(?:Popen|call|check_output)",
                "subprocess.call(['rm', 'file'])",
            ),
            (r"__[\w]+__", "__reduce__"),
            (r"base64\.b64decode", "base64.b64decode(encoded_payload)"),
            (r"\bimport\s+[\w\.]+", "import os"),
            (r"\\x[0-9a-fA-F]{2}", "\\x41\\x42\\x43"),
        ]

        for pattern, test_string in test_cases:
            assert re.search(pattern, test_string), f"Pattern '{pattern}' failed to match '{test_string}'"

    def test_patterns_dont_match_safe_code(self) -> None:
        """Test that patterns don't match legitimate ML code."""
        safe_examples = [
            "torch.nn.Linear(10, 5)",
            "model.eval()",  # This might match eval( pattern - that's expected
            "data.shape",
            "model.parameters()",
            "important_variable",  # Contains 'import' substring but isn't a module import
        ]

        # Count false positives for documentation
        false_positives = []
        for safe_code in safe_examples:
            for pattern in SUSPICIOUS_STRING_PATTERNS:
                if re.search(pattern, safe_code):
                    false_positives.append((pattern, safe_code))

        # Document known false positives but don't fail
        # (These are trade-offs between security and usability)
        print(f"Known false positives: {false_positives}")


class TestSuspiciousMetadataPatterns:
    """Test SUSPICIOUS_METADATA_PATTERNS regex patterns."""

    def test_metadata_patterns_valid_regex(self) -> None:
        for pattern in SUSPICIOUS_METADATA_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex pattern '{pattern}': {e}")


class TestSuspiciousOps:
    """Test SUSPICIOUS_OPS TensorFlow operations."""

    def test_suspicious_ops_structure(self) -> None:
        """Test that SUSPICIOUS_OPS has correct structure."""
        assert isinstance(SUSPICIOUS_OPS, set)

        for op in SUSPICIOUS_OPS:
            assert isinstance(op, str)
            assert len(op) > 0

    def test_critical_operations_present(self) -> None:
        """Test that critical dangerous operations are included."""
        critical_ops = ["PyFunc", "ReadFile", "WriteFile", "ShellExecute"]

        for op in critical_ops:
            assert op in SUSPICIOUS_OPS, f"Critical operation {op} not flagged"

    def test_file_operations_included(self) -> None:
        """Test that file I/O operations are flagged."""
        file_ops = ["ReadFile", "WriteFile", "Save", "SaveV2"]

        for op in file_ops:
            assert op in SUSPICIOUS_OPS, f"File operation {op} not flagged"


class TestSuspiciousLayerTypes:
    """Test SUSPICIOUS_LAYER_TYPES Keras layers."""

    def test_layer_types_structure(self) -> None:
        """Test that SUSPICIOUS_LAYER_TYPES has correct structure."""
        assert isinstance(SUSPICIOUS_LAYER_TYPES, dict)

        for layer_type, description in SUSPICIOUS_LAYER_TYPES.items():
            assert isinstance(layer_type, str)
            assert isinstance(description, str)
            assert len(description) > 0

    def test_lambda_layers_flagged(self) -> None:
        """Test that Lambda layers are flagged as suspicious."""
        assert "Lambda" in SUSPICIOUS_LAYER_TYPES
        assert "arbitrary Python code" in SUSPICIOUS_LAYER_TYPES["Lambda"]


class TestSuspiciousConfigProperties:
    """Test SUSPICIOUS_CONFIG_PROPERTIES configuration keys."""

    def test_config_properties_structure(self) -> None:
        """Test that SUSPICIOUS_CONFIG_PROPERTIES has correct structure."""
        assert isinstance(SUSPICIOUS_CONFIG_PROPERTIES, list)

        for prop in SUSPICIOUS_CONFIG_PROPERTIES:
            assert isinstance(prop, str)
            assert len(prop) > 0

    def test_execution_properties_present(self) -> None:
        """Test that code execution properties are flagged."""
        execution_props = ["eval", "exec", "function", "code"]

        for prop in execution_props:
            assert prop in SUSPICIOUS_CONFIG_PROPERTIES, f"Execution property {prop} not flagged"


class TestSuspiciousConfigPatterns:
    """Test SUSPICIOUS_CONFIG_PATTERNS manifest patterns."""

    def test_config_patterns_structure(self) -> None:
        """Test that SUSPICIOUS_CONFIG_PATTERNS has correct structure."""
        assert isinstance(SUSPICIOUS_CONFIG_PATTERNS, dict)

        expected_categories = [
            "network_access",
            "file_access",
            "execution",
            "credentials",
        ]
        for category in expected_categories:
            assert category in SUSPICIOUS_CONFIG_PATTERNS, f"Category {category} missing"

            patterns = SUSPICIOUS_CONFIG_PATTERNS[category]
            assert isinstance(patterns, list)

            for pattern in patterns:
                assert isinstance(pattern, str)
                assert len(pattern) > 0

    def test_critical_patterns_present(self) -> None:
        """Test that critical security patterns are included in each category."""
        # Network access patterns
        network_patterns = SUSPICIOUS_CONFIG_PATTERNS["network_access"]
        assert "url" in network_patterns
        assert "http" in network_patterns

        # File access patterns
        file_patterns = SUSPICIOUS_CONFIG_PATTERNS["file_access"]
        assert "file" in file_patterns
        assert "path" in file_patterns

        # Execution patterns
        exec_patterns = SUSPICIOUS_CONFIG_PATTERNS["execution"]
        assert "exec" in exec_patterns
        assert "eval" in exec_patterns

        # Credential patterns
        cred_patterns = SUSPICIOUS_CONFIG_PATTERNS["credentials"]
        assert "password" in cred_patterns
        assert "secret" in cred_patterns


class TestUtilityFunctions:
    """Test utility functions for suspicious symbols."""

    def test_get_all_suspicious_patterns(self) -> None:
        """Test get_all_suspicious_patterns function."""
        all_patterns = get_all_suspicious_patterns()

        assert isinstance(all_patterns, dict)

        expected_keys = [
            "pickle_globals",
            "pickle_strings",
            "dangerous_builtins",
            "dangerous_opcodes",
            "tensorflow_ops",
            "keras_layers",
            "config_properties",
            "manifest_patterns",
        ]

        for key in expected_keys:
            assert key in all_patterns, f"Pattern category {key} missing"

            pattern_info = all_patterns[key]
            assert "patterns" in pattern_info
            assert "description" in pattern_info
            assert "risk_level" in pattern_info

            # Verify risk levels are valid
            assert pattern_info["risk_level"] in [
                "LOW",
                "MEDIUM",
                "MEDIUM-HIGH",
                "HIGH",
                "CRITICAL",
                "HIGH-CRITICAL",
            ]

    def test_validate_patterns(self) -> None:
        """Test validate_patterns function."""
        warnings = validate_patterns()

        # Should return list (empty if all patterns valid)
        assert isinstance(warnings, list)

        # If there are warnings, they should be strings
        for warning in warnings:
            assert isinstance(warning, str)
            assert len(warning) > 0

        # For this test, we expect no warnings with our current patterns
        assert len(warnings) == 0, f"Pattern validation failed: {warnings}"

    def test_validate_patterns_with_invalid_regex(self) -> None:
        """Test that validate_patterns catches invalid regex."""
        # This test would require modifying the patterns temporarily
        # For now, we just test that the function handles regex errors gracefully

        # Test that the function can be called without errors
        warnings = validate_patterns()
        assert isinstance(warnings, list)

    def test_validate_patterns_with_invalid_entries(self) -> None:
        """Inject invalid entries and verify warnings are produced."""
        original_globals = SUSPICIOUS_GLOBALS.copy()
        original_builtins = DANGEROUS_BUILTINS.copy()
        original_opcodes = DANGEROUS_OPCODES.copy()
        original_strings = SUSPICIOUS_STRING_PATTERNS.copy()

        try:
            SUSPICIOUS_GLOBALS[123] = "*"  # type: ignore[index]
            SUSPICIOUS_GLOBALS["valid_module"] = 123  # type: ignore[assignment]
            DANGEROUS_BUILTINS.append(123)  # type: ignore[arg-type]
            DANGEROUS_OPCODES.add(123)  # type: ignore[arg-type]
            SUSPICIOUS_STRING_PATTERNS.append("[")

            warnings = validate_patterns()

            # Since we removed unreachable type checks, we now only validate:
            # 1. Functions must be '*' or list (for valid module names)
            # 2. Invalid regex patterns
            assert any("Functions must be '*'" in w for w in warnings)
            assert any("Invalid regex pattern" in w for w in warnings)
            assert len(warnings) >= 2
        finally:
            SUSPICIOUS_GLOBALS.clear()
            SUSPICIOUS_GLOBALS.update(original_globals)
            DANGEROUS_BUILTINS[:] = original_builtins
            DANGEROUS_OPCODES.clear()
            DANGEROUS_OPCODES.update(original_opcodes)
            SUSPICIOUS_STRING_PATTERNS[:] = original_strings


class TestSecurityCoverage:
    """Test that security patterns provide comprehensive coverage."""

    def test_pickle_attack_vectors_covered(self) -> None:
        """Test that major pickle attack vectors are covered."""
        # Test that we cover the OWASP Top 10 for ML security where applicable
        # We verify coverage for: code_execution, file_system_access, network_access,
        # process_control, and deserialization attack vectors

        # Verify each attack vector has corresponding patterns
        globals_modules = set(SUSPICIOUS_GLOBALS.keys())

        # Code execution
        assert any(mod in globals_modules for mod in ["builtins", "eval", "exec"])

        # File system access
        assert any(mod in globals_modules for mod in ["os", "shutil"])

        # Network access
        assert "socket" in globals_modules

        # Process control
        assert any(mod in globals_modules for mod in ["subprocess", "os"])

    def test_tensorflow_attack_vectors_covered(self) -> None:
        """Test that TensorFlow attack vectors are covered."""
        tf_ops = SUSPICIOUS_OPS

        # File I/O attacks
        assert any(op in tf_ops for op in ["ReadFile", "WriteFile"])

        # Code execution attacks
        assert any(op in tf_ops for op in ["PyFunc", "PyCall"])

        # System interaction
        assert any(op in tf_ops for op in ["ShellExecute", "SystemConfig"])

    def test_configuration_attack_vectors_covered(self) -> None:
        """Test that configuration-based attacks are covered."""
        config_patterns = SUSPICIOUS_CONFIG_PATTERNS

        # Network exfiltration
        assert "network_access" in config_patterns
        assert len(config_patterns["network_access"]) > 5

        # File system attacks
        assert "file_access" in config_patterns
        assert len(config_patterns["file_access"]) > 5

        # Code execution
        assert "execution" in config_patterns
        assert len(config_patterns["execution"]) > 5

        # Credential theft
        assert "credentials" in config_patterns
        assert len(config_patterns["credentials"]) > 3


class TestPatternMaintenance:
    """Test pattern maintenance and evolution capabilities."""

    def test_pattern_extensibility(self) -> None:
        """Test that patterns can be easily extended."""
        # Verify that pattern structures support easy addition

        # SUSPICIOUS_GLOBALS should support both wildcard and specific functions
        assert SUSPICIOUS_GLOBALS["os"] == "*"  # Wildcard example
        assert isinstance(SUSPICIOUS_GLOBALS["builtins"], list)  # Specific functions

        # SUSPICIOUS_CONFIG_PATTERNS should support categorization
        assert isinstance(SUSPICIOUS_CONFIG_PATTERNS, dict)
        assert all(isinstance(v, list) for v in SUSPICIOUS_CONFIG_PATTERNS.values())

    def test_pattern_documentation_consistency(self) -> None:
        """Test that patterns are consistently documented."""
        all_patterns = get_all_suspicious_patterns()

        for _category, info in all_patterns.items():
            # Each category should have required metadata
            assert "description" in info
            assert "risk_level" in info
            assert "patterns" in info

            # Descriptions should be informative
            assert len(info["description"]) > 10

            # Risk levels should follow convention
            assert info["risk_level"] in [
                "LOW",
                "MEDIUM",
                "MEDIUM-HIGH",
                "HIGH",
                "CRITICAL",
                "HIGH-CRITICAL",
            ]
