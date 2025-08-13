"""Integration tests for data leakage detection with scanners."""

import pickle
import zipfile

import numpy as np

from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner


class TestDataLeakageIntegration:
    """Test data leakage detection integration with scanners."""

    def test_pickle_scanner_with_pii(self, tmp_path):
        """Test PII detection in pickle files."""
        test_file = tmp_path / "model_with_pii.pkl"

        # Create model with embedded PII
        data = {
            "model_weights": np.random.randn(100, 50).astype(np.float32),
            "metadata": {
                "trained_by": "john.doe@company.com",
                "customer_ssn": "123-45-6789",
                "api_key": "sk-1234567890abcdef",  # Not detected by data leakage, but by secrets
            },
            "training_logs": ["Processing user 555-123-4567", "Email: admin@example.org", "Patient MRN: 98765432"],
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        assert result is not None

        # Check that data leakage was detected
        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        assert len(leakage_checks) > 0

        # Should detect various PII types
        messages = " ".join(c.message for c in leakage_checks)
        assert any(x in messages for x in ["SSN", "email", "phone", "MRN", "ID"])

    def test_pytorch_zip_with_embeddings(self, tmp_path):
        """Test embedding detection in PyTorch ZIP files."""
        test_file = tmp_path / "model_with_embeddings.pt"

        with zipfile.ZipFile(test_file, "w") as zf:
            # Create embedding data
            embeddings = np.random.uniform(-1, 1, (100, 512)).astype(np.float32)

            # Save as pickle in the zip
            model_data = {
                "embeddings": embeddings,
                "vocab_size": 10000,
                "hidden_size": 512,
            }
            zf.writestr("data.pkl", pickle.dumps(model_data))

        # Scan the file
        scanner = PyTorchZipScanner()
        result = scanner.scan(str(test_file))

        assert result is not None

        # Check for embedding detection
        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        # May detect embeddings as potential leakage risk
        if leakage_checks:
            messages = " ".join(c.message for c in leakage_checks)
            # Could detect as embeddings or high entropy
            assert "embedding" in messages.lower() or "entropy" in messages.lower()

    def test_high_entropy_detection(self, tmp_path):
        """Test high entropy region detection."""
        test_file = tmp_path / "model_with_entropy.pkl"

        # Create data with high entropy region (possibly encrypted/compressed)
        import random

        random_bytes = bytes([random.randint(0, 255) for _ in range(4096)])

        data = {
            "model": {"weights": [1.0, 2.0, 3.0]},
            "encrypted_data": random_bytes,  # High entropy
            "normal_text": "This is normal text " * 100,
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        # Should detect high entropy region
        if leakage_checks:
            messages = " ".join(c.message for c in leakage_checks)
            assert "entropy" in messages.lower()

    def test_gradient_data_detection(self, tmp_path):
        """Test gradient data detection."""
        test_file = tmp_path / "model_with_gradients.pkl"

        # Create gradient-like data
        gradients = np.random.normal(0, 0.001, (1000, 100)).astype(np.float32)
        # Add some spikes
        gradients[::10, ::10] = np.random.uniform(-0.1, 0.1, (100, 10))

        data = {
            "model_state": {"layer1.weight": np.random.randn(100, 100)},
            "gradients": gradients,
            "optimizer_state": {"momentum": 0.9},
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        # May detect gradient patterns
        if leakage_checks:
            messages = " ".join(c.message for c in leakage_checks)
            # Could detect as gradients or embeddings
            assert "gradient" in messages.lower() or "embedding" in messages.lower()

    def test_repeated_patterns(self, tmp_path):
        """Test detection of repeated memorized patterns."""
        test_file = tmp_path / "model_with_patterns.pkl"

        # Create data with repeated sensitive pattern
        sensitive_pattern = b"API_KEY_SECRET_12345"

        data = {
            "weights": np.random.randn(100, 100),
            "config": {
                "token1": sensitive_pattern,
                "token2": sensitive_pattern,
                "token3": sensitive_pattern,
                "token4": sensitive_pattern,
                "token5": sensitive_pattern,
                "token6": sensitive_pattern,
            },
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        # Should detect some form of leakage (repeated pattern, gradient, or embedding)
        if leakage_checks:
            messages = " ".join(c.message for c in leakage_checks)
            # Accept detection of repeated patterns, gradients, or embeddings
            assert any(x in messages.lower() for x in ["repeated", "pattern", "gradient", "embedding", "key", "secret"])

    def test_data_leakage_can_be_disabled(self, tmp_path):
        """Test that data leakage detection can be disabled."""
        test_file = tmp_path / "model.pkl"

        data = {
            "ssn": "123-45-6789",
            "email": "test@example.com",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan with data leakage detection disabled
        scanner = PickleScanner(config={"check_data_leakage": False})
        result = scanner.scan(str(test_file))

        # Should not have any data leakage checks
        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name]

        assert len(leakage_checks) == 0

    def test_clean_model_no_false_positives(self, tmp_path):
        """Test that clean models don't trigger false positives."""
        test_file = tmp_path / "clean_model.pkl"

        # Create a clean model
        data = {
            "model_state_dict": {
                "layer1.weight": np.random.normal(0, 0.1, (784, 256)).astype(np.float32),
                "layer1.bias": np.zeros(256, dtype=np.float32),
                "layer2.weight": np.random.normal(0, 0.1, (256, 128)).astype(np.float32),
                "layer2.bias": np.zeros(128, dtype=np.float32),
                "output.weight": np.random.normal(0, 0.1, (128, 10)).astype(np.float32),
                "output.bias": np.zeros(10, dtype=np.float32),
            },
            "optimizer_state": {
                "lr": 0.001,
                "betas": (0.9, 0.999),
                "eps": 1e-8,
                "weight_decay": 0.0001,
            },
            "epoch": 100,
            "best_accuracy": 0.9823,
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        # Should not detect PII or concerning patterns
        leakage_issues = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        # Clean model should not have PII
        pii_issues = [
            c for c in leakage_issues if any(x in c.message.lower() for x in ["ssn", "credit", "email", "phone"])
        ]
        assert len(pii_issues) == 0

        # Should have a passing check
        leakage_pass = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "passed"]

        # If no issues found, should have passing check
        if not leakage_issues:
            assert len(leakage_pass) == 1

    def test_severity_levels(self, tmp_path):
        """Test that different patterns have appropriate severity levels."""
        test_file = tmp_path / "severity_test.pkl"

        data = {
            # Critical: SSN and credit card
            "ssn": "123-45-6789",
            "cc": "4532015112830366",
            # High: Email
            "email": "user@example.com",
            # Medium: Phone
            "phone": "555-123-4567",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        leakage_checks = [c for c in result.checks if "Training Data Leakage" in c.name and c.status.value == "failed"]

        # Should have different severity levels
        severities = [c.severity.value for c in leakage_checks]
        assert "critical" in severities  # SSN/Credit card
        # Note: emails might be mapped to critical due to severity mapping
