"""Tests for CVE-2025-23304: NVIDIA NeMo Hydra _target_ injection."""

import io
import tarfile

import pytest

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.nemo_scanner import NemoScanner


def _create_nemo_file(tmp_path, config_dict, filename="model.nemo", config_name="model_config.yaml"):
    """Helper to create a .nemo tar file with the given YAML config."""
    nemo_path = tmp_path / filename
    with tarfile.open(nemo_path, "w") as tar:
        if config_dict is not None:
            config_bytes = yaml.dump(config_dict).encode() if HAS_YAML else b"{}"
            info = tarfile.TarInfo(name=config_name)
            info.size = len(config_bytes)
            tar.addfile(info, io.BytesIO(config_bytes))
    return nemo_path


class TestNemoScannerBasic:
    """Basic scanner functionality tests."""

    def test_scanner_available(self):
        scanner = NemoScanner()
        assert scanner.name == "nemo"

    def test_can_handle_nemo_file(self, tmp_path):
        path = _create_nemo_file(tmp_path, {"model": "test"})
        assert NemoScanner.can_handle(str(path))

    def test_rejects_non_tar(self, tmp_path):
        path = tmp_path / "model.nemo"
        path.write_bytes(b"not a tar file")
        assert not NemoScanner.can_handle(str(path))

    def test_rejects_wrong_extension(self, tmp_path):
        path = tmp_path / "model.pt"
        with tarfile.open(path, "w") as tar:
            info = tarfile.TarInfo(name="config.yaml")
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))
        assert not NemoScanner.can_handle(str(path))


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestCVE202523304HydraTarget:
    """Tests for CVE-2025-23304: Hydra _target_ injection detection."""

    def test_dangerous_os_system_detected(self, tmp_path):
        """os.system _target_ should trigger CVE-2025-23304 CRITICAL."""
        config = {
            "model": {
                "_target_": "os.system",
                "command": "echo pwned",
            }
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) > 0, f"Should detect dangerous _target_. Checks: {[c.message for c in result.checks]}"
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details.get("cve_id") == "CVE-2025-23304"
        assert cve_checks[0].details.get("target") == "os.system"

    def test_dangerous_subprocess_detected(self, tmp_path):
        """subprocess.Popen _target_ should trigger CVE-2025-23304."""
        config = {"trainer": {"callbacks": [{"_target_": "subprocess.Popen", "args": ["whoami"]}]}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) > 0, "Should detect subprocess.Popen"
        assert cve_checks[0].details.get("target") == "subprocess.Popen"

    def test_dangerous_eval_detected(self, tmp_path):
        """builtins.eval _target_ should trigger CVE-2025-23304."""
        config = {"_target_": "builtins.eval", "expression": "__import__('os').system('id')"}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) > 0, "Should detect builtins.eval"

    def test_suspicious_pattern_detected(self, tmp_path):
        """Unknown target containing 'eval' pattern should be flagged."""
        config = {"model": {"_target_": "custom_module.eval_function"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        suspicious_checks = [c for c in result.checks if "Suspicious" in c.name and "CVE-2025-23304" in c.name]
        assert len(suspicious_checks) > 0, f"Should flag suspicious pattern. Checks: {[c.name for c in result.checks]}"

    def test_safe_nemo_target_passes(self, tmp_path):
        """Known-safe NeMo/PyTorch targets should pass."""
        config = {
            "model": {"_target_": "nemo.collections.nlp.models.TextClassification"},
            "optim": {"_target_": "torch.optim.Adam"},
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) == 0, f"Safe targets should not trigger CVE. Checks: {[c.name for c in result.checks]}"

    def test_nested_target_detected(self, tmp_path):
        """Deeply nested _target_ should still be found."""
        config = {
            "model": {
                "encoder": {
                    "layers": [
                        {
                            "attention": {
                                "_target_": "os.popen",
                                "cmd": "cat /etc/passwd",
                            }
                        }
                    ]
                }
            }
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) > 0, "Should detect nested _target_"

    def test_cve_details_fields(self, tmp_path):
        """CVE check details should include required fields."""
        config = {"_target_": "pickle.loads", "data": "..."}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if c.details.get("cve_id") == "CVE-2025-23304"]
        assert len(cve_checks) > 0
        details = cve_checks[0].details
        assert details["cvss"] == 7.6
        assert details["cwe"] == "CWE-94"
        assert "remediation" in details

    def test_executable_file_in_archive_flagged(self, tmp_path):
        """Executable files (.py, .sh) in the archive should be flagged."""
        nemo_path = tmp_path / "model.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            # Add a config
            config_bytes = yaml.dump({"model": {"_target_": "nemo.Model"}}).encode()
            info = tarfile.TarInfo(name="config.yaml")
            info.size = len(config_bytes)
            tar.addfile(info, io.BytesIO(config_bytes))
            # Add suspicious script
            script = b"#!/bin/bash\nrm -rf /"
            info = tarfile.TarInfo(name="exploit.sh")
            info.size = len(script)
            tar.addfile(info, io.BytesIO(script))

        result = NemoScanner().scan(str(nemo_path))

        suspicious = [c for c in result.checks if "Suspicious File" in c.name]
        assert len(suspicious) > 0, "Should detect executable in archive"

    def test_no_yaml_configs(self, tmp_path):
        """Archive with no YAML should note absence."""
        nemo_path = tmp_path / "model.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            data = b"binary weights data"
            info = tarfile.TarInfo(name="weights.bin")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        result = NemoScanner().scan(str(nemo_path))

        from modelaudit.scanners.base import CheckStatus

        no_config = [c for c in result.checks if "Config Presence" in c.name and c.status != CheckStatus.PASSED]
        assert len(no_config) > 0, "Should note missing YAML configs"
