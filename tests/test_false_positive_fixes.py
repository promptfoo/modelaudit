"""
Integration tests for false positive fixes in ModelAudit.

This test suite specifically verifies that legitimate ML models don't trigger
false positive security alerts while maintaining detection of real threats.
"""

import contextlib
import json
import tempfile
from pathlib import Path

import numpy as np
import pytest

from modelaudit.cli import main as cli_main
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner

# Skip tests if required libraries are not available
try:
    import torch

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    import h5py

    HAS_H5PY = True
except ImportError:
    HAS_H5PY = False

try:
    from safetensors.numpy import save_file

    HAS_SAFETENSORS = True
except ImportError:
    HAS_SAFETENSORS = False


class TestFalsePositiveFixes:
    """Test suite for verifying false positive fixes don't break legitimate model scanning."""

    def test_gpt2_style_model_no_false_positives(self, tmp_path):
        """Test that GPT-2 style models don't generate false positives."""
        # Create a GPT-2 style model structure
        test_files = []

        # 1. Create SafeTensors file with GPT-2 layer patterns
        if HAS_SAFETENSORS:
            safetensors_path = tmp_path / "model.safetensors"
            gpt2_weights = {
                "h.0.mlp.c_fc.weight": np.random.randn(768, 3072).astype(np.float32) * 0.02,
                "h.0.mlp.c_proj.weight": np.random.randn(3072, 768).astype(np.float32) * 0.02,
                "h.1.attn.c_attn.weight": np.random.randn(768, 2304).astype(np.float32) * 0.02,
                "h.1.attn.c_proj.weight": np.random.randn(768, 768).astype(np.float32) * 0.02,
                "wte.weight": np.random.randn(50257, 768).astype(np.float32) * 0.02,  # Token embeddings
            }
            save_file(gpt2_weights, safetensors_path)
            test_files.append(safetensors_path)

        # 2. Create HuggingFace config file
        config_path = tmp_path / "config.json"
        gpt2_config = {
            "_name_or_path": "openai-community/gpt2",
            "model_type": "gpt2",
            "architectures": ["GPT2LMHeadModel"],
            "vocab_size": 50257,
            "n_positions": 1024,
            "n_embd": 768,
            "n_layer": 12,
            "n_head": 12,
            "transformers_version": "4.35.0",
            "torch_dtype": "float32",
        }
        with open(config_path, "w") as f:
            json.dump(gpt2_config, f)
        test_files.append(config_path)

        # 3. Create TensorFlow H5 file (not Keras)
        if HAS_H5PY:
            h5_path = tmp_path / "tf_model.h5"
            with h5py.File(h5_path, "w") as f:
                model_weights = f.create_group("model_weights")
                layer_group = model_weights.create_group("transformer/h_0/mlp/c_fc")
                layer_group.create_dataset(
                    "kernel:0",
                    data=np.random.randn(768, 3072).astype(np.float32) * 0.02,
                )
                layer_group.create_dataset(
                    "bias:0",
                    data=np.random.randn(3072).astype(np.float32) * 0.01,
                )

                # Add optimizer weights to make it clearly a TensorFlow file
                optimizer_weights = f.create_group("optimizer_weights")
                optimizer_weights.create_dataset("iteration:0", data=[1000])
            test_files.append(h5_path)

        # Test each file individually
        for file_path in test_files:
            # Use CLI to scan (most comprehensive test)
            result = self._run_cli_scan(str(file_path))

            # Should complete successfully with no warnings/errors
            assert result["exit_code"] == 0, f"File {file_path.name} should scan without issues"
            assert result["has_warnings"] is False, f"File {file_path.name} should not have warnings"
            assert result["has_errors"] is False, f"File {file_path.name} should not have errors"

    def test_huggingface_patterns_not_flagged(self, tmp_path):
        """Test that common HuggingFace configuration patterns are not flagged."""
        test_configs = [
            # GPT-2 config
            {
                "filename": "gpt2_config.json",
                "content": {
                    "_name_or_path": "gpt2",
                    "model_type": "gpt2",
                    "transformers_version": "4.35.0",
                    "architectures": ["GPT2LMHeadModel"],
                    "model_input_names": ["input_ids", "attention_mask"],
                    "torch_dtype": "float32",
                },
            },
            # BERT config
            {
                "filename": "bert_config.json",
                "content": {
                    "_name_or_path": "bert-base-uncased",
                    "model_type": "bert",
                    "transformers_version": "4.21.0",
                    "architectures": ["BertForSequenceClassification"],
                    "model_input_names": [
                        "input_ids",
                        "attention_mask",
                        "token_type_ids",
                    ],
                    "torch_dtype": "float32",
                    "hidden_size": 768,
                    "num_attention_heads": 12,
                },
            },
            # Tokenizer config
            {
                "filename": "tokenizer_config.json",
                "content": {
                    "tokenizer_class": "GPT2Tokenizer",
                    "model_input_names": ["input_ids", "attention_mask"],
                    "special_tokens_map": {"pad_token": "<|endoftext|>"},
                    "model_max_length": 1024,
                    "added_tokens_decoder": {"50256": {"content": "<|endoftext|>"}},
                },
            },
        ]

        for config_info in test_configs:
            config_path = tmp_path / config_info["filename"]
            with open(config_path, "w") as f:
                json.dump(config_info["content"], f)

            result = self._run_cli_scan(str(config_path))

            # Should not flag any of these patterns as suspicious
            assert result["exit_code"] == 0, f"HuggingFace config {config_info['filename']} should not be flagged"
            assert result["has_warnings"] is False, (
                f"HuggingFace config {config_info['filename']} should not have warnings"
            )

    def test_tensorflow_h5_not_flagged_as_warning(self, tmp_path):
        """Test that TensorFlow H5 files don't generate warnings."""
        if not HAS_H5PY:
            pytest.skip("h5py not installed")

        tf_h5_path = tmp_path / "tensorflow_model.h5"

        with h5py.File(tf_h5_path, "w") as f:
            # Create clear TensorFlow structure
            model_weights = f.create_group("model_weights")
            dense_layer = model_weights.create_group("dense_1")
            dense_layer.create_dataset(
                "kernel:0",
                data=np.random.randn(100, 50).astype(np.float32),
            )
            dense_layer.create_dataset(
                "bias:0",
                data=np.random.randn(50).astype(np.float32),
            )

            # Add optimizer state (clear TensorFlow indicator)
            optimizer_weights = f.create_group("optimizer_weights")
            optimizer_weights.create_dataset("iteration:0", data=[500])
            optimizer_weights.create_dataset("learning_rate:0", data=[0.001])

        result = self._run_cli_scan(str(tf_h5_path))

        # Should complete successfully without warnings
        assert result["exit_code"] == 0, "TensorFlow H5 should not be flagged"
        assert result["has_warnings"] is False, "TensorFlow H5 should not have warnings"

    def test_large_language_model_layers_ignored(self):
        """Test that large language model layers are ignored by weight analysis."""
        scanner = WeightDistributionScanner()

        # Test various LLM layer patterns that should be ignored
        llm_test_cases = [
            # GPT-2 style
            ("h.0.mlp.c_fc.weight", (768, 3072)),
            ("h.5.attn.c_attn.weight", (768, 2304)),
            ("h.11.mlp.c_proj.weight", (3072, 768)),
            # Generic transformer patterns
            ("transformer.layers.0.mlp.dense_h_to_4h.weight", (1024, 4096)),
            ("model.layers.10.attention.dense.weight", (2048, 2048)),
            # Large vocabulary layers
            ("lm_head.weight", (4096, 32000)),
            ("wte.weight", (50257, 768)),
        ]

        for layer_name, weight_shape in llm_test_cases:
            # Create weights with natural variation (not anomalous)
            np.random.seed(42)
            weights = np.random.randn(*weight_shape).astype(np.float32) * 0.02

            # Add some natural scaling variation
            if weight_shape[1] > 1000:  # Large output dimension
                weights[:, :100] *= 1.3  # Some outputs have different scales

            # Create mock architecture analysis for LLM layers
            architecture_analysis = {
                "is_likely_transformer": True,
                "is_likely_llm": True,
                "confidence": 0.9,
                "evidence": ["Mock LLM evidence"],
                "architectural_features": {},
                "total_parameters": 100_000_000,
                "layer_count": 12,
            }
            anomalies = scanner._analyze_layer_weights(layer_name, weights, architecture_analysis)

            # Should return no anomalies due to LLM detection
            assert len(anomalies) == 0, f"LLM layer {layer_name} should not generate anomalies"

    def test_small_models_still_analyzed(self):
        """Test that small/non-LLM models are still properly analyzed."""
        scanner = WeightDistributionScanner()

        # Create a small classification model with a clear anomaly
        np.random.seed(42)
        weights = np.random.randn(512, 10).astype(np.float32) * 0.1  # 512 features -> 10 classes

        # Add a clear anomaly - one class with much larger weights (potential backdoor)
        weights[:, 5] = np.random.randn(512).astype(np.float32) * 3.0

        # Create mock architecture analysis for small model
        architecture_analysis = {
            "is_likely_transformer": False,
            "is_likely_llm": False,
            "confidence": 0.3,
            "evidence": ["Mock small model evidence"],
            "architectural_features": {},
            "total_parameters": 1_000_000,
            "layer_count": 3,
        }
        anomalies = scanner._analyze_layer_weights("classifier.weight", weights, architecture_analysis)

        # Should detect the anomaly since this is not an LLM layer
        assert len(anomalies) > 0, "Non-LLM models should still be analyzed for anomalies"

        # Should detect outlier or extreme weight patterns
        has_outlier = any("abnormal weight magnitudes" in a["description"] for a in anomalies)
        has_extreme = any("extremely large weight values" in a["description"] for a in anomalies)
        assert has_outlier or has_extreme, "Should detect the injected anomaly"

    def test_bert_model_no_false_positive_executables(self, tmp_path):
        """Test that BERT models with random MZ bytes don't trigger false positives."""
        if not HAS_TORCH:
            pytest.skip("torch not installed")

        # Create a realistic BERT model binary file
        bert_file = tmp_path / "bert-base-uncased-pytorch_model.bin"

        # Create model weights with realistic sizes
        np.random.seed(42)
        bert_weights = {
            "embeddings.word_embeddings.weight": torch.randn(30522, 768) * 0.02,  # Vocab size x hidden size
            "embeddings.position_embeddings.weight": torch.randn(512, 768) * 0.02,
            "embeddings.token_type_embeddings.weight": torch.randn(2, 768) * 0.02,
            "encoder.layer.0.attention.self.query.weight": torch.randn(768, 768) * 0.02,
            "encoder.layer.0.attention.self.key.weight": torch.randn(768, 768) * 0.02,
            "encoder.layer.0.attention.self.value.weight": torch.randn(768, 768) * 0.02,
        }

        # Save the model
        torch.save(bert_weights, bert_file)

        # Inject MZ bytes in the middle of the file to simulate random occurrence
        with open(bert_file, "rb") as f:
            data = f.read()

        # Find a position in the middle and insert MZ
        mid_point = len(data) // 2
        modified_data = data[:mid_point] + b"MZ" + data[mid_point + 2 :]

        with open(bert_file, "wb") as f:
            f.write(modified_data)

        # Scan the file
        result = self._run_cli_scan(str(bert_file))

        # Should not flag as executable
        assert result["exit_code"] == 0, "BERT model with random MZ bytes should not be flagged"
        assert not any("Windows executable" in issue.get("message", "") for issue in result["issues"]), (
            "Should not detect Windows executable in BERT model"
        )

    def test_malicious_files_still_detected(self, tmp_path):
        """Regression test: ensure malicious files are still detected after false positive fixes."""
        # Test 1: Malicious pickle file
        evil_pickle_path = tmp_path / "evil.pickle"
        # Create a simple malicious pickle that tries to execute system commands
        import pickle

        class MaliciousClass:
            def __reduce__(self):
                import os

                return (os.system, ("echo 'malicious code executed'",))

        with open(evil_pickle_path, "wb") as f:
            pickle.dump(MaliciousClass(), f)

        result = self._run_cli_scan(str(evil_pickle_path))
        assert result["exit_code"] == 1, "Malicious pickle should be detected"
        assert result["has_errors"] is True, "Malicious pickle should have critical issues"

        # Test 2: Malicious Keras model
        if HAS_H5PY:
            evil_keras_path = tmp_path / "evil_model.h5"
            with h5py.File(evil_keras_path, "w") as f:
                malicious_config = {
                    "class_name": "Sequential",
                    "config": {
                        "layers": [
                            {
                                "class_name": "Lambda",
                                "config": {
                                    "function": 'lambda x: eval(\'__import__("os").system("rm -rf /")\')',
                                },
                            },
                        ],
                    },
                }
                f.attrs["model_config"] = json.dumps(malicious_config)

            result = self._run_cli_scan(str(evil_keras_path))
            assert result["exit_code"] == 1, "Malicious Keras model should be detected"
            assert result["has_warnings"] is True or result["has_errors"] is True, "Malicious Keras should have issues"

        # Test 3: Real executable at beginning of .bin file should still be detected
        if True:  # Always run this test
            exe_bin_path = tmp_path / "malicious_model.bin"
            # Create a file that starts with a Windows executable
            # This simulates someone renaming an .exe to .bin
            with open(exe_bin_path, "wb") as f:
                # Write actual PE header structure
                f.write(b"MZ")  # DOS header
                f.write(b"\x90\x00" * 30)  # DOS stub
                f.write(b"This program cannot be run in DOS mode")
                f.write(b"\x00" * 100)

            result = self._run_cli_scan(str(exe_bin_path))
            assert result["exit_code"] == 1, "Real executable disguised as .bin should be detected"
            assert any("Windows executable" in issue.get("message", "") for issue in result["issues"]), (
                "Should detect Windows executable at start of file"
            )

        # Test 4: Malicious manifest file (use ML-specific filename to ensure it's scanned)
        evil_manifest_path = tmp_path / "config.json"  # Use standard config.json name
        malicious_manifest = {
            "model_name": "legitimate_model",
            "model_type": "bert",  # Add ML context to ensure scanning
            "version": "1.0",
            "config": {
                "execute_command": "rm -rf /tmp/*",
                "api_key": "stolen_secret_key",
                "malicious_code": 'eval(\'__import__("os").system("malicious")\')',
            },
        }
        with open(evil_manifest_path, "w") as f:
            json.dump(malicious_manifest, f)

        # Test directly with the scanner instead of CLI
        from modelaudit.scanners.manifest_scanner import ManifestScanner

        scanner = ManifestScanner()
        scan_result = scanner.scan(str(evil_manifest_path))

        # Check that malicious content was detected
        critical_issues = [issue for issue in scan_result.issues if issue.severity == IssueSeverity.CRITICAL]
        warning_issues = [issue for issue in scan_result.issues if issue.severity == IssueSeverity.WARNING]

        assert len(critical_issues) > 0 or len(warning_issues) > 0, (
            f"Malicious manifest should be detected. Found {len(scan_result.issues)} issues: "
            f"{[str(issue) for issue in scan_result.issues]}"
        )

    def test_comprehensive_gpt2_model_scan(self, tmp_path):
        """Comprehensive test simulating a complete GPT-2 model directory scan."""
        # Create a realistic GPT-2 model directory structure
        model_dir = tmp_path / "gpt2_model"
        model_dir.mkdir()

        # Main model config
        config = {
            "_name_or_path": "openai-community/gpt2",
            "model_type": "gpt2",
            "architectures": ["GPT2LMHeadModel"],
            "vocab_size": 50257,
            "n_positions": 1024,
            "n_embd": 768,
            "n_layer": 12,
            "n_head": 12,
            "transformers_version": "4.35.0",
            "torch_dtype": "float32",
        }
        with open(model_dir / "config.json", "w") as f:
            json.dump(config, f)

        # Tokenizer config
        tokenizer_config = {
            "tokenizer_class": "GPT2Tokenizer",
            "model_input_names": ["input_ids", "attention_mask"],
            "model_max_length": 1024,
        }
        with open(model_dir / "tokenizer_config.json", "w") as f:
            json.dump(tokenizer_config, f)

        # SafeTensors model weights
        if HAS_SAFETENSORS:
            gpt2_weights = {
                "h.0.mlp.c_fc.weight": np.random.randn(768, 3072).astype(np.float32) * 0.02,
                "h.0.mlp.c_proj.weight": np.random.randn(3072, 768).astype(np.float32) * 0.02,
                "h.1.attn.c_attn.weight": np.random.randn(768, 2304).astype(np.float32) * 0.02,
                "wte.weight": np.random.randn(50257, 768).astype(np.float32) * 0.02,
            }
            save_file(gpt2_weights, model_dir / "model.safetensors")

        # PyTorch binary weights
        if HAS_TORCH:
            torch_weights = {
                "h.0.mlp.c_fc.weight": torch.randn(3072, 768) * 0.02,
                "h.0.mlp.c_proj.weight": torch.randn(768, 3072) * 0.02,
                "wte.weight": torch.randn(50257, 768) * 0.02,
            }
            torch.save(torch_weights, model_dir / "pytorch_model.bin")

        # TensorFlow H5 format
        if HAS_H5PY:
            with h5py.File(model_dir / "tf_model.h5", "w") as f:
                model_weights = f.create_group("model_weights")
                layer_group = model_weights.create_group("h_0_mlp_c_fc")
                layer_group.create_dataset(
                    "kernel:0",
                    data=np.random.randn(768, 3072).astype(np.float32) * 0.02,
                )

                # Add optimizer to make it clearly TensorFlow
                optimizer_weights = f.create_group("optimizer_weights")
                optimizer_weights.create_dataset("iteration:0", data=[1000])

        # Scan the entire directory
        result = self._run_cli_scan(str(model_dir))

        # Should complete with no issues
        assert result["exit_code"] == 0, "Complete GPT-2 model directory should scan clean"
        assert result["has_warnings"] is False, "GPT-2 model should not have warnings"
        assert result["has_errors"] is False, "GPT-2 model should not have errors"

    def _run_cli_scan(self, path):
        """Helper method to run CLI scan and parse results."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            # Run CLI scan with JSON output
            import sys
            from io import StringIO

            old_argv = sys.argv
            old_stdout = sys.stdout
            old_stderr = sys.stderr

            sys.argv = [
                "modelaudit",
                "scan",
                path,
                "--format",
                "json",
                "--output",
                output_file,
            ]
            sys.stdout = StringIO()
            sys.stderr = StringIO()

            try:
                exit_code = cli_main()
            except SystemExit as e:
                exit_code = e.code

            stdout_content = sys.stdout.getvalue()
            stderr_content = sys.stderr.getvalue()

            # Restore original streams
            sys.argv = old_argv
            sys.stdout = old_stdout
            sys.stderr = old_stderr

            # Parse JSON output
            try:
                with open(output_file) as f:
                    scan_results = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                scan_results = {"issues": []}

            # Analyze results
            issues = scan_results.get("issues", [])
            has_warnings = any(issue.get("severity") in ["warning", "critical"] for issue in issues)
            has_errors = any(issue.get("severity") == "critical" for issue in issues)

            return {
                "exit_code": exit_code or 0,
                "has_warnings": has_warnings,
                "has_errors": has_errors,
                "issues": issues,
                "stdout": stdout_content,
                "stderr": stderr_content,
            }

        finally:
            # Clean up
            with contextlib.suppress(FileNotFoundError):
                Path(output_file).unlink()
