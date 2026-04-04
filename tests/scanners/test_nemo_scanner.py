"""Tests for CVE-2025-23304: NVIDIA NeMo Hydra _target_ injection."""

import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from modelaudit.core import scan_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.nemo_scanner import NemoScanner


def _create_nemo_file_from_bytes(
    tmp_path: Path,
    config_bytes: bytes,
    filename: str = "model.nemo",
    config_name: str = "model_config.yaml",
) -> Path:
    """Helper to create a .nemo tar file with the given YAML config."""
    nemo_path = tmp_path / filename
    with tarfile.open(nemo_path, "w") as tar:
        info = tarfile.TarInfo(name=config_name)
        info.size = len(config_bytes)
        tar.addfile(info, io.BytesIO(config_bytes))
    return nemo_path


def _create_nemo_file(
    tmp_path: Path,
    config_dict: dict[str, Any] | None,
    filename: str = "model.nemo",
    config_name: str = "model_config.yaml",
) -> Path:
    """Helper to create a .nemo tar file with the given YAML config."""
    if config_dict is None:
        nemo_path = tmp_path / filename
        with tarfile.open(nemo_path, "w"):
            pass
        return nemo_path

    config_bytes = yaml.safe_dump(config_dict).encode() if HAS_YAML else b"{}"
    return _create_nemo_file_from_bytes(tmp_path, config_bytes, filename=filename, config_name=config_name)


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

    def test_valid_nemo_does_not_trigger_file_type_mismatch(self, tmp_path):
        """Valid .nemo tar archives should not be flagged as spoofed file types."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": "nemo.Model"}})

        result = NemoScanner().scan(str(path))

        mismatch_checks = [
            c
            for c in result.checks
            if c.name == "File Type Validation"
            and c.status != CheckStatus.PASSED
            and "extension indicates nemo but magic bytes indicate tar" in c.message
        ]
        assert len(mismatch_checks) == 0

    def test_missing_yaml_dependency_is_reported_as_warning(self, tmp_path, monkeypatch):
        """Missing PyYAML should be a non-passing warning, not a pass."""
        import modelaudit.scanners.nemo_scanner as nemo_scanner_mod

        path = _create_nemo_file(tmp_path, {"model": "test"})
        monkeypatch.setattr(nemo_scanner_mod, "HAS_YAML", False)
        scanner = NemoScanner()
        result = scanner.scan(str(path))

        checks = [c for c in result.checks if c.name == "YAML Parser Availability"]
        assert len(checks) == 1
        assert checks[0].status != CheckStatus.PASSED
        assert checks[0].severity == IssueSeverity.WARNING


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

    def test_core_scan_file_routes_nemo_archive_to_nemo_scanner(self, tmp_path: Path) -> None:
        """Real .nemo scans should use NemoScanner, not the generic TAR scanner."""
        config = {
            "model": {
                "_target_": "os.system",
                "command": "echo pwned",
            }
        }
        path = _create_nemo_file(tmp_path, config)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details["target"] == "os.system"
            for check in result.checks
        )

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

    def test_suspicious_pattern_detected(self, tmp_path: Path) -> None:
        """Unknown target containing 'eval' pattern should be flagged."""
        config = {"model": {"_target_": "custom_module.eval_function"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        suspicious_checks = [c for c in result.checks if "Suspicious" in c.name and "CVE-2025-23304" in c.name]
        assert len(suspicious_checks) > 0, f"Should flag suspicious pattern. Checks: {[c.name for c in result.checks]}"
        details = suspicious_checks[0].details
        assert details["description"]
        assert details["remediation"]

    def test_suspicious_target_with_numeric_suffix_detected(self, tmp_path: Path) -> None:
        """Suffix-number variants like eval2 should still be treated as suspicious."""
        config = {"model": {"_target_": "custom_module.eval2"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        suspicious_checks = [c for c in result.checks if c.name == "CVE-2025-23304: Suspicious Hydra _target_"]
        assert len(suspicious_checks) == 1
        assert suspicious_checks[0].details["pattern"] == "eval"

    def test_benign_embedded_keyword_target_is_review_only(self, tmp_path: Path) -> None:
        """Benign near-match words like 'systematic' should not trigger CVE-2025-23304."""
        config = {
            "model": {"_target_": "custom_package.systematic_factory.Builder"},
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) == 0, (
            f"Benign near-match should not trigger CVE. Checks: {[c.message for c in result.checks]}"
        )

        review_checks = [c for c in result.checks if c.name == "Hydra _target_ Review"]
        assert len(review_checks) == 1
        assert review_checks[0].severity == IssueSeverity.INFO

    def test_oversized_yaml_config_is_rejected_before_parse(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Oversized YAML members should be rejected without parsing the full config payload."""

        def fail_safe_load(_: bytes) -> Any:
            raise AssertionError("safe_load should not be called for oversized configs")

        monkeypatch.setattr(yaml, "safe_load", fail_safe_load)
        oversized_config = b"notes: '" + (b"A" * (NemoScanner.MAX_CONFIG_SIZE + 1)) + b"'\n"
        path = _create_nemo_file_from_bytes(tmp_path, oversized_config)

        result = NemoScanner().scan(str(path))

        size_checks = [c for c in result.checks if c.name == "NeMo Config Size Check"]
        assert len(size_checks) == 1
        assert size_checks[0].status == CheckStatus.FAILED
        assert size_checks[0].severity == IssueSeverity.WARNING

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

    def test_safe_prefix_not_flagged_for_suspicious_pattern(self, tmp_path):
        """Safe-prefixed target containing suspicious keyword (e.g. 'eval') should not be flagged."""
        config = {
            "model": {"_target_": "nemo.collections.nlp.eval_utils.EvalModule"},
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) == 0, (
            f"Safe-prefixed target with 'eval' should not trigger CVE. Checks: {[c.name for c in result.checks]}"
        )

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

    def test_unknown_target_review_is_info(self, tmp_path):
        """Unknown targets should be reviewable info, not warning noise."""
        config = {"model": {"_target_": "custom_package.builders.SafeFactory"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        review_checks = [c for c in result.checks if c.name == "Hydra _target_ Review"]
        assert len(review_checks) > 0
        assert review_checks[0].severity == IssueSeverity.INFO

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

        no_config = [c for c in result.checks if "Config Presence" in c.name and c.status != CheckStatus.PASSED]
        assert len(no_config) > 0, "Should note missing YAML configs"
