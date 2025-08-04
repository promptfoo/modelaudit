import json
import logging
from pathlib import Path

import pytest

from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.scanners.manifest_scanner import ManifestScanner


def test_manifest_scanner_json(tmp_path):
    """Test the manifest scanner with a JSON file."""
    # Create a temporary JSON file with unique name
    test_file = tmp_path / "config.json"
    manifest_content = {
        "model_name": "test_model",
        "version": "1.0.0",
        "description": "A test model",
        "config": {
            "input_shape": [224, 224, 3],
            "output_shape": [1000],
            "file_path": "/path/to/model/weights.h5",
            "api_key": "secret_key_12345",
        },
    }

    with test_file.open("w") as f:
        json.dump(manifest_content, f)

    # Create scanner with blacklist patterns
    scanner = ManifestScanner(
        config={"blacklist_patterns": ["unsafe", "malicious"]},
    )

    # Test can_handle
    assert scanner.can_handle(str(test_file)) is True

    # Test scan
    result = scanner.scan(str(test_file))

    # Verify scan completed successfully
    assert result.success is True

    # Check that suspicious keys were detected
    suspicious_keys = [
        issue.details.get("key", "") for issue in result.issues if hasattr(issue, "details") and "key" in issue.details
    ]
    assert any("file_path" in key for key in suspicious_keys)
    assert any("api_key" in key for key in suspicious_keys)


def test_manifest_scanner_blacklist():
    """Test the manifest scanner with blacklisted terms."""
    # Create a temporary JSON file with a blacklisted term
    test_file = "model_card.json"
    manifest_content = {
        "model_name": "test_model",
        "version": "1.0.0",
        "description": "This is an UNSAFE model that should be flagged",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(manifest_content, f)

        # Create scanner with blacklist patterns
        scanner = ManifestScanner(
            config={"blacklist_patterns": ["unsafe", "malicious"]},
        )

        # Test scan
        result = scanner.scan(test_file)

        # Verify scan completed successfully
        assert result.success is True

        # Check that blacklisted term was detected
        blacklist_issues = [
            issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
        ]
        assert len(blacklist_issues) > 0
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in blacklist_issues)

        # Verify the specific blacklisted term was identified
        blacklisted_terms = [
            issue.details.get("blacklisted_term", "") for issue in blacklist_issues if hasattr(issue, "details")
        ]
        assert "unsafe" in blacklisted_terms

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_case_insensitive_blacklist():
    """Test that blacklist matching is case-insensitive."""
    # Create a temporary file with mixed-case blacklisted term
    test_file = "inference_config.json"

    try:
        with Path(test_file).open("w") as f:
            f.write('{"model": "This is a MaLiCiOuS model"}')

        # Create scanner with lowercase blacklist pattern
        scanner = ManifestScanner(config={"blacklist_patterns": ["malicious"]})

        # Test scan
        result = scanner.scan(test_file)

        # Check that the mixed-case term was detected
        blacklist_issues = [
            issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
        ]
        assert len(blacklist_issues) > 0

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_yaml():
    """Test the manifest scanner with a YAML file."""
    # Skip this test - YAML files are no longer supported after whitelist changes
    pytest.skip("YAML files are no longer supported by manifest scanner whitelist")


def test_manifest_scanner_nested_structures():
    """Test the manifest scanner with nested structures."""
    # Create a temporary JSON file with nested structures
    test_file = "model_index.json"
    manifest_content = {
        "model": {
            "name": "nested_model",
            "config": {
                "layers": [
                    {"name": "layer1", "type": "conv2d"},
                    {"name": "layer2", "type": "lambda", "code": "x => x * 2"},
                ],
            },
        },
        "deployment": {
            "environments": [
                {"name": "prod", "url": "https://api.example.com/models"},
                {"name": "dev", "url": "http://localhost:8000"},
            ],
        },
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(manifest_content, f)

        # Create scanner
        scanner = ManifestScanner()

        # Test scan
        result = scanner.scan(test_file)

        # Verify scan completed successfully
        assert result.success is True

        # Check that suspicious keys were detected in nested structures
        suspicious_keys = [issue.details.get("key", "") for issue in result.issues if hasattr(issue, "details")]
        assert any("url" in key for key in suspicious_keys)
        assert any("code" in key for key in suspicious_keys)

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_parse_file_logs_warning(caplog, capsys):
    """Ensure parsing errors log warnings without stdout output."""
    scanner = ManifestScanner()

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result = ScanResult(scanner.name)
        content = scanner._parse_file("nonexistent.json", ".json", result)

    assert content is None
    assert any("Error parsing file nonexistent.json" in record.getMessage() for record in caplog.records)
    assert capsys.readouterr().out == ""
    assert any(issue.severity == IssueSeverity.DEBUG for issue in result.issues)


def test_huggingface_name_or_path_pattern():
    """Test that _name_or_path HuggingFace pattern is not flagged as suspicious."""
    test_file = "config.json"
    huggingface_config = {
        "_name_or_path": "openai-community/gpt2",
        "model_type": "gpt2",
        "transformers_version": "4.35.0",
        "architectures": ["GPT2LMHeadModel"],
        "vocab_size": 50257,
        "n_positions": 1024,
        "n_embd": 768,
        "n_layer": 12,
        "n_head": 12,
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(huggingface_config, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Check that _name_or_path was not flagged as suspicious
        suspicious_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "message") and "suspicious" in issue.message.lower() and "_name_or_path" in issue.message
        ]
        assert len(suspicious_issues) == 0, "HuggingFace _name_or_path should not be flagged"

        # Also check that it wasn't flagged as file_access category
        file_access_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "details")
            and issue.details.get("categories") == ["file_access"]
            and "_name_or_path" in issue.details.get("key", "")
        ]
        assert len(file_access_issues) == 0, "_name_or_path should not be flagged as file access"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_huggingface_patterns_ignored_in_context():
    """Test that various HuggingFace patterns are ignored when in ML context."""
    test_file = "model_config.json"
    huggingface_config = {
        "_name_or_path": "microsoft/DialoGPT-medium",
        "name_or_path": "gpt2-medium",  # Alternative format
        "model_input_names": ["input_ids", "attention_mask"],
        "model_output_names": ["logits"],
        "transformers_version": "4.21.0",
        "torch_dtype": "float32",
        "architectures": ["GPT2LMHeadModel"],
        "model_type": "gpt2",
        # Add some legitimately suspicious patterns for contrast
        "api_endpoint": "https://api.openai.com/v1/models",  # This should be flagged
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(huggingface_config, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # HuggingFace patterns should NOT be flagged
        huggingface_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "details")
            and any(
                pattern in issue.details.get("key", "")
                for pattern in [
                    "_name_or_path",
                    "name_or_path",
                    "model_input_names",
                    "transformers_version",
                    "torch_dtype",
                    "architectures",
                ]
            )
        ]
        assert len(huggingface_issues) == 0, "HuggingFace patterns should be ignored"

        # But genuine suspicious patterns should still be flagged
        suspicious_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "details") and "api_endpoint" in issue.details.get("key", "")
        ]
        assert len(suspicious_issues) > 0, "Real suspicious patterns should still be detected"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_tokenizer_config_patterns():
    """Test that tokenizer configuration patterns are properly handled."""
    test_file = "tokenizer_config.json"
    tokenizer_config = {
        "tokenizer_class": "GPT2Tokenizer",
        "model_input_names": ["input_ids", "attention_mask"],
        "special_tokens_map": {
            "bos_token": "<|endoftext|>",
            "eos_token": "<|endoftext|>",
            "pad_token": "<|endoftext|>",
        },
        "model_max_length": 1024,
        "added_tokens_decoder": {
            "50256": {"content": "<|endoftext|>", "lstrip": False, "normalized": False},
        },
        # Add something that should be flagged
        "api_key": "secret_key_12345",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(tokenizer_config, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Tokenizer patterns should NOT be flagged
        tokenizer_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "details")
            and any(
                pattern in issue.details.get("key", "")
                for pattern in [
                    "tokenizer_class",
                    "model_input_names",
                    "special_tokens_map",
                    "model_max_length",
                    "added_tokens_decoder",
                ]
            )
        ]
        assert len(tokenizer_issues) == 0, "Tokenizer patterns should be ignored"

        # But credentials should still be flagged
        credential_issues = [
            issue for issue in result.issues if hasattr(issue, "details") and "api_key" in issue.details.get("key", "")
        ]
        assert len(credential_issues) > 0, "Real credential patterns should be detected"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_ml_context_detection():
    """Test that ML context is properly detected and influences pattern analysis."""
    test_file = "pytorch_model_config.json"
    ml_config = {
        "model_type": "bert",
        "hidden_size": 768,
        "num_attention_heads": 12,
        "num_hidden_layers": 12,
        "vocab_size": 30522,
        "max_position_embeddings": 512,
        "architectures": ["BertModel"],
        "torch_dtype": "float32",
        # Patterns that could be suspicious in non-ML context
        "model_input_names": ["input_ids", "attention_mask", "token_type_ids"],
        "hidden_dropout_prob": 0.1,
        "attention_probs_dropout_prob": 0.1,
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(ml_config, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # ML-specific patterns should be ignored due to high ML context confidence
        ml_pattern_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "details")
            and any(
                pattern in issue.details.get("key", "") for pattern in ["model_input_names", "hidden_", "attention_"]
            )
        ]
        assert len(ml_pattern_issues) == 0, "ML patterns should be ignored in ML context"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_non_ml_context_still_flags_suspicious_patterns():
    """Test that suspicious patterns are still flagged in non-ML contexts."""
    test_file = "generic_config.json"
    non_ml_config = {
        "application_name": "generic_app",
        "version": "1.0.0",
        "database_url": "postgresql://user:pass@host/db",
        "api_endpoint": "https://api.example.com/data",
        "file_path": "/tmp/sensitive_data.csv",
        "execute_command": "rm -rf /tmp/*",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(non_ml_config, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # In non-ML context, these patterns should be flagged
        suspicious_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "details")
            and any(
                pattern in issue.details.get("key", "")
                for pattern in [
                    "database_url",
                    "api_endpoint",
                    "file_path",
                    "execute_command",
                ]
            )
        ]
        assert len(suspicious_issues) > 0, "Suspicious patterns should be flagged in non-ML context"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_imagenet_labels_not_flagged(tmp_path):
    """ImageNet label strings should not trigger critical issues."""
    test_file = tmp_path / "vision_config.json"
    manifest_content = {
        "model_type": "vision",
        "labels": {"shell": 0, "cat": 1, "dog": 2},
    }

    with test_file.open("w") as f:
        json.dump(manifest_content, f)

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert not critical_issues, "Classification labels should not be critical"
