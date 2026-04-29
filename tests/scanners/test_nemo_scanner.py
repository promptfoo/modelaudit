"""Tests for CVE-2025-23304: NVIDIA NeMo Hydra _target_ injection."""

import io
import pickle
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.nemo_scanner import NemoScanner, _get_nested_scanner_for_file


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


def _add_tar_bytes(tar: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))


def _build_malicious_pickle() -> bytes:
    import os as os_module

    class DangerousPayload:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (os_module.system, ("echo nemo-checkpoint-test",))

    return pickle.dumps(DangerousPayload())


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
        path = _create_nemo_file(tmp_path, {"model": "test"})
        monkeypatch.setattr("modelaudit.scanners.nemo_scanner.HAS_YAML", False)
        scanner = NemoScanner()
        result = scanner.scan(str(path))

        checks = [c for c in result.checks if c.name == "YAML Parser Availability"]
        assert len(checks) == 1
        assert checks[0].status != CheckStatus.PASSED
        assert checks[0].severity == IssueSeverity.WARNING

    def test_get_nested_scanner_for_file_delegates_to_registry(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}
        sentinel = object()

        def fake_get_scanner_for_file(path: str, *, config: dict[str, Any]) -> object:
            captured["path"] = path
            captured["config"] = config
            return sentinel

        monkeypatch.setattr("modelaudit.scanners.get_scanner_for_file", fake_get_scanner_for_file)

        config = {"max_nemo_checkpoint_scan_bytes": 1024}

        assert _get_nested_scanner_for_file("/tmp/model_weights.ckpt", config=config) is sentinel
        assert captured["path"] == "/tmp/model_weights.ckpt"
        assert captured["config"] is config


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestNemoArchiveVulnerabilityCoverage:
    """Tests for NeMo archive traversal and checkpoint deserialization coverage."""

    def test_relative_member_path_traversal_detects_cve_2025_23360(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "traversal.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "../../evil.txt", b"overwrite")

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23360"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        details = cve_checks[0].details
        assert details["cvss"] == 7.1
        assert details["cwe"] == "CWE-23"
        assert "remediation" in details

    def test_absolute_member_path_traversal_detects_cve_2025_23250(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "absolute.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "/tmp/evil.txt", b"overwrite")

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23250"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["cvss"] == 7.6
        assert cve_checks[0].details["cwe"] == "CWE-22"

    def test_symlink_escape_detects_relative_path_traversal_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "symlink.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            link_info = tarfile.TarInfo(name="weights_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "../../outside_weights.ckpt"
            tar.addfile(link_info)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23360"]
        assert len(cve_checks) == 1
        assert cve_checks[0].details["entry"] == "weights_link"
        assert cve_checks[0].details["target"] == "../../outside_weights.ckpt"

    def test_normalized_safe_member_path_not_flagged_as_traversal(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "normalized-safe.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "configs/../model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "weights/../model_weights.ckpt", b"not a pickle")

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23360"]
        assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23250"]

    def test_malicious_checkpoint_detects_nemo_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-rce.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.ckpt", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        details = cve_checks[0].details
        assert details["cvss"] == 7.6
        assert details["cwe"] == "CWE-502"
        assert "CVE-2026-24157" in details["related_cves"]
        assert details["nested_scanner"] == "pickle"

    def test_symlink_checkpoint_alias_detects_nemo_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-symlink-alias.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            link_info = tarfile.TarInfo(name="model_weights.ckpt")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "payload.pkl"
            tar.addfile(link_info)
            _add_tar_bytes(tar, "payload.pkl", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_large_checkpoint_member_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-large.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.ckpt", b"not scanned")

        result = NemoScanner({"max_nemo_checkpoint_scan_bytes": 1}).scan(str(nemo_path))

        skipped_checks = [
            check
            for check in result.checks
            if check.details.get("scan_outcome_reason") == "nemo_checkpoint_scan_skipped_size_limit"
        ]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert len(skipped_checks) == 1
        assert skipped_checks[0].status == CheckStatus.FAILED
        assert skipped_checks[0].details["max_scan_bytes"] == 1

    def test_nested_checkpoint_scanner_failure_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class RaisingScanner:
            name = "raising_nested"

            def scan(self, _path: str) -> None:
                raise RuntimeError("nested boom")

        monkeypatch.setattr(
            "modelaudit.scanners.nemo_scanner._get_nested_scanner_for_file",
            lambda _path, config=None: RaisingScanner(),
        )

        nemo_path = tmp_path / "checkpoint-nested-fails.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.ckpt", b"checkpoint bytes")

        result = NemoScanner().scan(str(nemo_path))

        failed_checks = [
            check
            for check in result.checks
            if check.details.get("scan_outcome_reason") == "nemo_checkpoint_nested_scan_failed"
        ]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert len(failed_checks) == 1
        assert failed_checks[0].details["nested_scanner"] == "raising_nested"
        assert failed_checks[0].details["exception_type"] == "RuntimeError"

    def test_checkpoint_without_nested_scanner_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "modelaudit.scanners.nemo_scanner._get_nested_scanner_for_file",
            lambda _path, config=None: None,
        )

        nemo_path = tmp_path / "checkpoint-no-scanner.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.ckpt", b"checkpoint bytes")

        result = NemoScanner().scan(str(nemo_path))

        unsupported_checks = [
            check
            for check in result.checks
            if check.details.get("scan_outcome_reason") == "nemo_checkpoint_no_nested_scanner"
        ]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert len(unsupported_checks) == 1
        assert unsupported_checks[0].details["entry"] == "model_weights.ckpt"

    def test_benign_checkpoint_pickle_no_nemo_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-safe.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.ckpt", pickle.dumps({"weights": [1, 2, 3]}))

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]

    def test_metadata_referenced_misnamed_payload_detects_nemo_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-misnamed-payload.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/payload.jpg"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/payload.jpg", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "artifacts/payload.jpg"
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["config_file"] == "model_config.yaml"
        assert cve_checks[0].details["config_path"] == "tokenizer.model"
        assert cve_checks[0].details["source_entry"] == "artifacts/payload.jpg"

    def test_config_referenced_checkpoint_suffix_is_not_scanned_twice(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-checkpoint.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "checkpoint": "nemo:model_weights.ckpt",
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "model_weights.ckpt", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].details["entry"] == "model_weights.ckpt"
        assert cve_checks[0].details["config_file"] == "model_config.yaml"
        assert cve_checks[0].details["config_path"] == "checkpoint"

    def test_large_config_referenced_member_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-large-artifact.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/tokenizer.model"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/tokenizer.model", b"not scanned")

        result = NemoScanner({"max_nemo_checkpoint_scan_bytes": 1}).scan(str(nemo_path))

        skipped_checks = [
            check
            for check in result.checks
            if check.details.get("scan_outcome_reason") == "nemo_checkpoint_scan_skipped_size_limit"
        ]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert len(skipped_checks) == 1
        assert skipped_checks[0].details["entry"] == "artifacts/tokenizer.model"
        assert skipped_checks[0].details["source_entry"] == "artifacts/tokenizer.model"
        assert skipped_checks[0].details["config_file"] == "model_config.yaml"
        assert skipped_checks[0].details["config_path"] == "tokenizer.model"
        assert skipped_checks[0].details["max_scan_bytes"] == 1

    def test_unextractable_config_referenced_member_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fail_extract(
            _tar: tarfile.TarFile,
            _member: tarfile.TarInfo,
            *,
            suffix_source: str | None = None,
        ) -> str | None:
            return None

        monkeypatch.setattr(NemoScanner, "_extract_member_to_tempfile", staticmethod(fail_extract))

        nemo_path = tmp_path / "referenced-unextractable-artifact.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/tokenizer.model"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/tokenizer.model", b"payload")

        result = NemoScanner().scan(str(nemo_path))

        failed_checks = [
            check
            for check in result.checks
            if check.details.get("scan_outcome_reason") == "nemo_checkpoint_extract_failed"
        ]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert len(failed_checks) == 1
        assert failed_checks[0].details["entry"] == "artifacts/tokenizer.model"
        assert failed_checks[0].details["source_entry"] == "artifacts/tokenizer.model"
        assert failed_checks[0].details["config_file"] == "model_config.yaml"
        assert failed_checks[0].details["config_path"] == "tokenizer.model"

    def test_config_referenced_nested_scan_failure_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from modelaudit.scanners import archive_dispatch

        def raise_nested_scan(_path: str, config: dict[str, Any] | None = None) -> Any:
            _ = config
            raise RuntimeError("referenced nested boom")

        monkeypatch.setattr(archive_dispatch, "scan_nested_file", raise_nested_scan)

        nemo_path = tmp_path / "referenced-nested-fails.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/tokenizer.model"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/tokenizer.model", b"payload")

        result = NemoScanner().scan(str(nemo_path))

        failed_checks = [
            check
            for check in result.checks
            if check.details.get("scan_outcome_reason") == "nemo_referenced_nested_scan_failed"
        ]
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert len(failed_checks) == 1
        assert failed_checks[0].details["entry"] == "artifacts/tokenizer.model"
        assert failed_checks[0].details["source_entry"] == "artifacts/tokenizer.model"
        assert failed_checks[0].details["config_file"] == "model_config.yaml"
        assert failed_checks[0].details["config_path"] == "tokenizer.model"
        assert failed_checks[0].details["exception_type"] == "RuntimeError"
        assert failed_checks[0].details["exception_message"] == "referenced nested boom"

    def test_metadata_referenced_benign_non_checkpoint_suffix_stays_clean(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-benign-artifact.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/tokenizer.model"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/tokenizer.model", b"plain tokenizer bytes")

        result = NemoScanner().scan(str(nemo_path))

        assert result.success is True
        assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert "scan_outcome" not in result.metadata

    def test_nested_checkpoint_archive_traversal_not_labeled_deserialization_cve(self, tmp_path: Path) -> None:
        nested_checkpoint = io.BytesIO()
        with zipfile.ZipFile(nested_checkpoint, "w") as zipf:
            zipf.writestr("../../evil.pkl", b"not a pickle")

        nemo_path = tmp_path / "checkpoint-archive-traversal.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.pt", nested_checkpoint.getvalue())

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]


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

    @pytest.mark.parametrize(
        "target",
        [
            "cloudpickle.load",
            "cloudpickle.loads",
            "dill.load",
            "dill.loads",
            "torch.load",
            "torch.jit.load",
            "torch.hub.load",
            "torch.hub.load_state_dict_from_url",
            "torch.package.PackageImporter",
            "torch.package.PackageImporter.load_pickle",
            "torch.serialization.load",
            "torch.utils.model_zoo.load_url",
            "joblib.load",
            "sklearn.externals.joblib.load",
            "keras.models.load_model",
            "tensorflow.keras.models.load_model",
            "tensorflow.saved_model.load",
            "tf.keras.models.load_model",
            "mlflow.pyfunc.load_model",
            "pandas.read_pickle",
        ],
    )
    def test_ml_deserialization_targets_detected_as_dangerous(self, tmp_path: Path, target: str) -> None:
        """Hydra targets that deserialize model artifacts should not fall through to INFO review."""
        config = {"model": {"_target_": target, "f": "weights.bin"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if c.name == "CVE-2025-23304: Dangerous Hydra _target_"]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["target"] == target

    def test_numpy_load_without_pickle_is_safe_target(self, tmp_path: Path) -> None:
        """Default numpy.load calls should not be treated as pickle deserialization."""
        config = {"model": {"_target_": "numpy.load", "file": "weights.npy"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert not [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_" and check.details.get("target") == "numpy.load"
        ]
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == "numpy.load"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "model_config",
        [
            {"_target_": "numpy.load", "file": "weights.npy", "allow_pickle": True},
            {"_target_": "numpy.load", "_args_": ["weights.npy", None, True]},
        ],
        ids=["kwarg_allow_pickle", "positional_allow_pickle"],
    )
    def test_numpy_load_with_pickle_enabled_is_dangerous(
        self,
        tmp_path: Path,
        model_config: dict[str, Any],
    ) -> None:
        """numpy.load becomes a pickle sink only when allow_pickle is enabled."""
        path = _create_nemo_file(tmp_path, {"model": model_config})

        result = NemoScanner().scan(str(path))

        cve_checks = [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_" and check.details.get("target") == "numpy.load"
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_skops_load_target_is_review_only(self, tmp_path: Path) -> None:
        """skops.io.load should not be CVE-critical without vulnerable content context."""
        config = {"model": {"_target_": "skops.io.load", "file": "model.skops"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert not [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.details.get("target") == "skops.io.load"
        ]
        review_checks = [
            check
            for check in result.checks
            if check.name == "Hydra _target_ Review" and check.details.get("target") == "skops.io.load"
        ]
        assert len(review_checks) == 1
        assert review_checks[0].severity == IssueSeverity.INFO

    def test_torch_load_target_fails_aggregate_scan(self, tmp_path: Path) -> None:
        """A NeMo config using torch.load should produce a security failure, not exit 0."""
        config = {"model": {"_target_": "torch.load", "f": "payload.pt"}}
        path = _create_nemo_file(tmp_path, config)

        result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        assert determine_exit_code(result) == 1
        assert any(
            issue.severity == IssueSeverity.CRITICAL and "torch.load" in issue.message for issue in result.issues
        )

    def test_top_level_list_target_detected(self, tmp_path: Path) -> None:
        """Top-level YAML lists must be traversed, not mistaken for absent config."""
        path = _create_nemo_file_from_bytes(
            tmp_path,
            b"- _target_: os.system\n  command: id\n",
        )

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        cve_checks = [c for c in result.checks if c.name == "CVE-2025-23304: Dangerous Hydra _target_"]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["target"] == "os.system"
        assert cve_checks[0].details["config_path"] == "[0]._target_"

    def test_nested_list_target_detected(self, tmp_path: Path) -> None:
        """Nested list-of-list structures should remain part of Hydra target traversal."""
        path = _create_nemo_file_from_bytes(
            tmp_path,
            b"trainer:\n  callbacks:\n    - - _target_: subprocess.Popen\n        args:\n          - whoami\n",
        )

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if c.name == "CVE-2025-23304: Dangerous Hydra _target_"]
        assert len(cve_checks) == 1
        assert cve_checks[0].details["target"] == "subprocess.Popen"
        assert cve_checks[0].details["config_path"] == "trainer.callbacks[0][0]._target_"

    @pytest.mark.parametrize(
        ("payload", "expected_reason", "expected_check"),
        [
            (b"model: [unterminated\n", "nemo_config_yaml_parse_failed", "NeMo Config YAML Parsing"),
            (b"null\n", "nemo_config_invalid_structure", "NeMo Config Structure"),
            (b"just text\n", "nemo_config_invalid_structure", "NeMo Config Structure"),
        ],
    )
    def test_unanalyzable_yaml_config_returns_inconclusive_exit2(
        self,
        tmp_path: Path,
        payload: bytes,
        expected_reason: str,
        expected_check: str,
    ) -> None:
        """Present but unanalyzable configs should fail closed as inconclusive coverage."""
        path = _create_nemo_file_from_bytes(tmp_path, payload)

        direct_result = NemoScanner().scan(str(path))
        aggregate_result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        assert direct_result.success is False
        assert direct_result.has_errors is False
        assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert expected_reason in direct_result.metadata["scan_outcome_reasons"]
        checks = [c for c in direct_result.checks if c.name == expected_check]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].severity == IssueSeverity.INFO

        metadata = aggregate_result.file_metadata[str(path)]
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert expected_reason in metadata.get("scan_outcome_reasons")
        assert aggregate_result.success is False
        assert aggregate_result.has_errors is False
        assert determine_exit_code(aggregate_result) == 2

    def test_inconclusive_config_preserves_security_exit1(self, tmp_path: Path) -> None:
        """Security findings should keep priority over inconclusive config coverage."""
        nemo_path = tmp_path / "model.nemo"
        malformed_config = b"model: [unterminated\n"
        script = b"#!/bin/sh\nid\n"
        with tarfile.open(nemo_path, "w") as tar:
            info = tarfile.TarInfo(name="model_config.yaml")
            info.size = len(malformed_config)
            tar.addfile(info, io.BytesIO(malformed_config))
            info = tarfile.TarInfo(name="payload.sh")
            info.size = len(script)
            tar.addfile(info, io.BytesIO(script))

        result = scan_model_directory_or_file(
            str(nemo_path),
            config={"cache_scan_results": False},
        )

        metadata = result.file_metadata[str(nemo_path)]
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_yaml_parse_failed" in metadata.get("scan_outcome_reasons")
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)
        assert determine_exit_code(result) == 1

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
        assert size_checks[0].message == (f"Config file too large: model_config.yaml ({len(oversized_config)} bytes)")
        assert size_checks[0].details["scan_outcome_reason"] == "nemo_config_size_limit"
        assert size_checks[0].details["max_config_size"] == NemoScanner.MAX_CONFIG_SIZE
        assert result.success is True
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_size_limit" in result.metadata["scan_outcome_reasons"]

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            aggregate = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            metadata = aggregate.file_metadata[str(path)]

            assert aggregate.success is True
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert metadata["scan_outcome_reasons"] == ["nemo_config_size_limit"]
            assert determine_exit_code(aggregate) == 1
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

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

    def test_no_yaml_configs_fail_closed_as_inconclusive(self, tmp_path: Path) -> None:
        """Archives with no YAML should not report a clean complete scan."""
        nemo_path = tmp_path / "model.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            data = b"binary weights data"
            info = tarfile.TarInfo(name="weights.bin")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        direct_result = NemoScanner().scan(str(nemo_path))
        aggregate_result = scan_model_directory_or_file(
            str(nemo_path),
            config={"cache_scan_results": False},
        )

        assert direct_result.success is False
        assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_missing" in direct_result.metadata["scan_outcome_reasons"]
        no_config = [
            check
            for check in direct_result.checks
            if check.name == "NeMo Config Presence" and check.status == CheckStatus.FAILED
        ]
        assert len(no_config) == 1
        assert no_config[0].details["scan_outcome_reason"] == "nemo_config_missing"

        metadata = aggregate_result.file_metadata[str(nemo_path)]
        assert aggregate_result.success is False
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_missing" in metadata.get("scan_outcome_reasons", [])
        assert determine_exit_code(aggregate_result) == 2
