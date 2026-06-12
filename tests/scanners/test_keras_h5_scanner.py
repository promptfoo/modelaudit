import base64
import json
import marshal
import os
import subprocess
import sys
import textwrap
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

# Skip if h5py is not available before importing it
pytest.importorskip("h5py")

import h5py

import modelaudit.core as core_module
from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.optimized_config import build_cache_version_context
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners import keras_h5_scanner as keras_h5_scanner_module
from modelaudit.scanners import keras_utils
from modelaudit.scanners.base import DEFAULT_MAX_FILE_READ_SIZE, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner
from modelaudit.utils.file.hdf5 import HDF5_MAGIC, find_hdf5_signature_offset, hdf5_metadata_checksum
from modelaudit.utils.helpers.cache_decorator import (
    should_bypass_cache_for_file_backed_hdf5,
    should_bypass_cache_for_missing_h5py,
)

ASSETS_DIR = Path(__file__).parent.parent / "assets" / "samples" / "keras"


def test_keras_h5_scanner_can_handle(tmp_path):
    """Test the can_handle method of KerasH5Scanner."""
    # Test with actual H5 file
    model_path = create_mock_h5_file(tmp_path)
    assert KerasH5Scanner.can_handle(str(model_path)) is True

    # Test with non-existent file
    assert KerasH5Scanner.can_handle("nonexistent.h5") is False

    # Test with wrong extension
    test_file = tmp_path / "model.pt"
    test_file.write_bytes(b"not an h5 file")
    assert KerasH5Scanner.can_handle(str(test_file)) is False


def create_mock_h5_file(tmp_path, *, malicious=False):
    """Create a mock HDF5 file for testing."""
    h5_path = tmp_path / "model.h5"

    with h5py.File(h5_path, "w") as f:
        # Create a minimal Keras model structure
        model_config: dict[str, Any] = {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [
                    {
                        "class_name": "Dense",
                        "config": {"units": 10, "activation": "relu"},
                    },
                ],
            },
        }

        if malicious:
            # Add a malicious layer - split the long line
            malicious_function = 'lambda x: eval(\'__import__("os").system("rm -rf /")\')'
            model_config["config"]["layers"].append(
                {
                    "class_name": "Lambda",
                    "config": {
                        "function": malicious_function,
                    },
                },
            )

        # Add model_config attribute (required for Keras models)
        f.attrs["model_config"] = json.dumps(model_config)

        # Add some dummy data
        f.create_dataset("layer_names", data=[b"dense_1"])

        # Add weights group
        weights_group = f.create_group("model_weights")
        weights_group.create_dataset("dense_1/kernel:0", data=[[1.0, 2.0]])

    return h5_path


def create_custom_h5_file(
    tmp_path: Path,
    model_config: Any,
    *,
    training_config: Any | None = None,
    keras_version: str = "3.13.2",
    file_name: str = "model.h5",
) -> Path:
    """Create a configurable Keras H5 file for regression tests."""
    h5_path = tmp_path / file_name

    with h5py.File(h5_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        f.attrs["keras_version"] = keras_version
        if training_config is not None:
            f.attrs["training_config"] = json.dumps(training_config)

    return h5_path


def create_raw_config_h5_file(
    tmp_path: Path,
    *,
    model_config_attr: Any,
    training_config_attr: Any | None = None,
    keras_version: str = "3.13.2",
    file_name: str = "model.h5",
) -> Path:
    """Create a Keras H5 file with raw JSON config attributes."""
    h5_path = tmp_path / file_name

    with h5py.File(h5_path, "w") as f:
        f.attrs["model_config"] = model_config_attr
        f.attrs["keras_version"] = keras_version
        if training_config_attr is not None:
            f.attrs["training_config"] = training_config_attr

    return h5_path


def inflate_h5_file_to_size(path: Path, minimum_size: int = DEFAULT_MAX_FILE_READ_SIZE + 4096) -> None:
    """Make an HDF5 fixture appear large using sparse trailing padding."""
    with path.open("ab") as handle:
        handle.truncate(minimum_size)


def assert_not_rejected_by_read_cap(result: Any) -> None:
    reasons = result.metadata.get("scan_outcome_reasons", [])
    assert "max_file_read_size_exceeded" not in reasons
    assert not any(check.name == "File Size Limit" and check.status == CheckStatus.FAILED for check in result.checks)


def create_h5_with_external_link(
    tmp_path: Path,
    *,
    keras_version: str = "3.13.1",
) -> Path:
    """Create a Keras H5 file with an HDF5 ExternalLink to a local test fixture."""
    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])

    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [{"class_name": "Dense", "config": {"units": 1}}],
            },
        },
        keras_version=keras_version,
        file_name="external_link_model.h5",
    )

    with h5py.File(model_path, "a") as f:
        weights_group = f.require_group("model_weights")
        weights_group.attrs["layer_names"] = [b"dense"]
        dense = weights_group.create_group("dense")
        dense.attrs["weight_names"] = [b"linked_kernel"]
        dense["linked_kernel"] = h5py.ExternalLink(external_source.name, "/payload")

    return model_path


def create_h5_with_external_storage(
    tmp_path: Path,
    *,
    keras_version: str = "3.12.0",
) -> Path:
    """Create a Keras H5 file with a dataset backed by HDF5 external storage."""
    raw_storage = tmp_path / "weights.raw"
    raw_storage.write_bytes(b"\x00" * 8)

    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [{"class_name": "Dense", "config": {"units": 1}}],
            },
        },
        keras_version=keras_version,
        file_name="external_storage_model.h5",
    )

    with h5py.File(model_path, "a") as f:
        weights_group = f.require_group("model_weights")
        weights_group.attrs["layer_names"] = [b"dense"]
        dense = weights_group.create_group("dense")
        dense.attrs["weight_names"] = [b"external_kernel"]
        dense.create_dataset(
            "external_kernel",
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )

    return model_path


def create_h5_with_sensitive_external_references(tmp_path: Path, raw_secret: str) -> Path:
    """Create a Keras H5 file whose external-reference metadata contains sensitive evidence."""
    raw_storage = tmp_path / f"{raw_secret}.raw"
    raw_storage.write_bytes(b"\x00" * 8)

    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [{"class_name": "Dense", "config": {"units": 1}}],
            },
        },
        keras_version=f"3.13.1+{raw_secret}",
        file_name="sensitive_external_refs.h5",
    )

    with h5py.File(model_path, "a") as f:
        weights_group = f.require_group("model_weights")
        layer_name = f"layer_{raw_secret}"
        linked_weight_name = f"linked_{raw_secret}"
        external_weight_name = f"external_{raw_secret}_kernel"
        weights_group.attrs["layer_names"] = [layer_name.encode()]
        layer_group = weights_group.create_group(layer_name)
        layer_group.attrs["weight_names"] = [linked_weight_name.encode(), external_weight_name.encode()]
        layer_group[linked_weight_name] = h5py.ExternalLink(
            f"https://user:very-secret-password@example.com/private/model.h5?token={raw_secret}",
            f"/payload/{raw_secret}",
        )
        layer_group.create_dataset(
            external_weight_name,
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )

    return model_path


def test_keras_h5_scanner_safe_model(tmp_path):
    """Test scanning a safe Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    assert len(error_issues) == 0


def test_keras_h5_scanner_detects_cve_2026_1669_external_link(tmp_path: Path) -> None:
    """Vulnerable Keras versions should warn on HDF5 ExternalLink weights."""
    model_path = create_h5_with_external_link(tmp_path, keras_version="3.13.1")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["keras_version"] == "3.13.1"
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/model_weights/dense/linked_kernel",
            "filename": "external_source.h5",
            "path": "/payload",
        },
    ]


def test_keras_h5_scanner_detects_cve_2026_1669_external_storage(tmp_path: Path) -> None:
    """External storage segments should also be attributed to CVE-2026-1669."""
    model_path = create_h5_with_external_storage(tmp_path, keras_version="3.12.0")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "external_storage",
            "hdf5_path": "/model_weights/dense/external_kernel",
            "segments": [{"filename": "weights.raw", "offset": 0, "size": 8}],
        },
    ]


def test_keras_h5_external_reference_details_redact_model_controlled_values(tmp_path: Path) -> None:
    """HDF5 external-reference details should not serialize secrets, URL creds, or private path tokens."""
    raw_secret = "sk-proj-CAND061H5DETAILSECRET000000000000"
    model_path = create_h5_with_sensitive_external_references(tmp_path, raw_secret)

    result = KerasH5Scanner().scan(str(model_path))
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]

    assert len(cve_issues) == 1
    serialized_result = result.to_json()
    assert raw_secret not in serialized_result
    assert "very-secret-password" not in serialized_result
    details_json = json.dumps(cve_issues[0].details, sort_keys=True)
    assert "model_weights" in details_json
    assert "https://" in details_json
    assert "<redacted>" in details_json


def test_keras_h5_custom_layer_config_details_redact_model_controlled_values(tmp_path: Path) -> None:
    """Custom layer details should keep benign config keys while redacting sensitive model-controlled values."""
    raw_secret = "sk-proj-CAND061H5CONFIGSECRET000000000000"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "CustomAuditLayer",
                        "config": {
                            "api_key": raw_secret,
                            "callback": f"https://callback.example/hook?token={raw_secret}",
                            "safe_label": "public_label",
                        },
                    }
                ]
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))
    custom_issues = [check for check in result.checks if check.name == "Custom Layer Class Detection"]

    assert custom_issues
    layer_config = custom_issues[0].details["layer_config"]
    assert layer_config["api_key"] == "<redacted>"
    assert layer_config["safe_label"] == "public_label"
    assert raw_secret not in result.to_json()


def test_keras_h5_layer_counts_preserve_colliding_redacted_classes(tmp_path: Path) -> None:
    """Distinct model-controlled class names must not collapse into one count."""
    first_secret = "sk-proj-" + "A" * 24
    second_secret = "sk-proj-" + "B" * 24
    model_path = create_custom_h5_file(
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

    result = KerasH5Scanner().scan(str(model_path))

    assert result.metadata["layer_counts"] == {"token=<redacted>": 2, "token=<redacted>[2]": 1}
    assert first_secret not in result.to_json()
    assert second_secret not in result.to_json()


def test_keras_h5_non_string_layer_class_fails_closed_without_abort(tmp_path: Path) -> None:
    """Malformed structured class names should remain explicit and serializable."""
    raw_secret = "sk-proj-CAND061H5CLASSSECRET000000000000"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {"class_name": {"api_key": raw_secret}, "config": {}},
                    {"class_name": "Dense", "config": {"units": 2}},
                ]
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    type_checks = [check for check in result.checks if check.name == "Layer Class Type Validation"]
    assert len(type_checks) == 1
    assert type_checks[0].severity == IssueSeverity.WARNING
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_layer_class_invalid_type" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["layer_counts"]["<invalid:dict>"] == 1
    assert raw_secret not in result.to_json()


def test_keras_h5_non_string_model_class_preserves_nested_cve_detection(tmp_path: Path) -> None:
    """Malformed root metadata must not suppress scanning of nested layers."""
    raw_secret = "sk-proj-CAND061H5MODELCLASSSECRET000000000000"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": {"api_key": raw_secret},
            "config": {
                "layers": [
                    {"class_name": "Lambda", "config": {"function": "lambda x: x"}},
                ]
            },
        },
        keras_version="3.10.0",
    )

    result = KerasH5Scanner().scan(str(model_path))

    type_checks = [check for check in result.checks if check.name == "Model Class Type Validation"]
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9905"]
    assert len(type_checks) == 1
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.CRITICAL
    assert result.metadata["model_class"] == "<invalid:dict>"
    assert "keras_h5_model_class_invalid_type" in result.metadata["scan_outcome_reasons"]
    assert raw_secret not in result.to_json()


@pytest.mark.parametrize(
    "fixture_factory",
    [create_h5_with_external_link, create_h5_with_external_storage],
)
def test_keras_h5_scanner_flags_external_references_despite_fixed_file_version(
    tmp_path: Path,
    fixture_factory: Any,
) -> None:
    """Standalone H5 files cannot use artifact-controlled keras_version to suppress external refs."""
    model_path = fixture_factory(tmp_path, keras_version="3.13.2")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["keras_version"] == "3.13.2"
    assert cve_issues[0].details["parse_status"] == "untrusted_artifact_version"
    assert cve_issues[0].details["version_source"] == "hdf5_file_attribute"
    assert not any(
        check.name == "HDF5 External Weight Reference Version Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_keras_h5_scanner_fixed_metadata_without_external_refs_stays_quiet(tmp_path: Path) -> None:
    """Fixed-looking metadata alone should not produce external-reference noise."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [{"class_name": "Dense", "config": {"units": 1}}],
            },
        },
        keras_version="3.13.2",
        file_name="fixed_no_external_refs.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(check.name.startswith("HDF5 External Weight Reference") for check in result.checks)


def test_keras_h5_metadata_redacts_model_controlled_identifiers(tmp_path: Path) -> None:
    raw_secret = "sk-proj-KERASH5METADATASECRET1234567890"
    model_path = tmp_path / "metadata_redaction.h5"
    model_config = {
        "class_name": f"Model_{raw_secret}",
        "config": {"layers": [{"class_name": f"Layer_{raw_secret}", "config": {}}]},
    }

    with h5py.File(model_path, "w") as h5_file:
        h5_file.attrs["model_config"] = json.dumps(model_config)
        h5_file.attrs["keras_version"] = f"3.10.0+{raw_secret}"
        h5_file.create_group(f"group_{raw_secret}")
        weights = h5_file.create_group("model_weights")
        weights.create_dataset(f"kernel_{raw_secret}", data=[1.0])

    metadata = KerasH5Scanner().extract_metadata(str(model_path))
    serialized_metadata = json.dumps(metadata, default=str)

    assert raw_secret not in serialized_metadata
    assert metadata["has_model_config"] is True
    assert metadata["has_model_weights"] is True
    assert metadata["total_parameters"] == 1
    assert metadata["model_class"] == "Model_<redacted>"
    assert metadata["keras_version"] == "3.10.0+<redacted>"
    assert metadata["layer_types"] == ["Layer_<redacted>"]
    assert metadata["parameter_details"] == [{"name": "kernel_<redacted>", "shape": [1], "dtype": "float64", "size": 1}]
    assert "group_<redacted>" in metadata["h5_keys"]


def test_keras_h5_metadata_redacts_extraction_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_secret = "ATTACKER_CONTROLLED_KERAS_H5_METADATA_FAILURE"
    model_path = create_mock_h5_file(tmp_path)

    def fail_h5py_open(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(raw_secret)

    monkeypatch.setattr(keras_h5_scanner_module.h5py, "File", fail_h5py_open)

    metadata = KerasH5Scanner().extract_metadata(str(model_path))

    assert metadata["extraction_error"] == "<redacted>"
    assert raw_secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("keras_version", ["3.13.x", "2.12.0-gpu", "3.13.2rc1junk", "3.13.2+"])
def test_keras_h5_scanner_unparseable_external_reference_versions_mark_unknown_risk(
    tmp_path: Path,
    keras_version: str,
) -> None:
    model_path = create_h5_with_external_link(tmp_path, keras_version=keras_version)

    result = KerasH5Scanner().scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["keras_version"] == keras_version
    assert cve_issues[0].details["parse_status"] == "unknown"
    assert any("is non-canonical" in issue.message for issue in cve_issues)

    assert not any(
        check.name == "HDF5 External Weight Reference Version Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_keras_h5_scanner_benign_model_has_no_warning_noise(tmp_path: Path) -> None:
    """Benign H5 models should not produce warning or critical noise."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [{"class_name": "Dense", "config": {"units": 1}}],
            },
        },
    )

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_large_benign_keras_h5_scans_file_backed_without_default_read_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid large HDF5 Keras files should reach h5py-backed inspection."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        file_name="large_benign.h5",
    )
    inflate_h5_file_to_size(model_path)

    def fail_hash(_self: KerasH5Scanner, _path: str) -> dict[str, str | None]:
        pytest.fail("Keras H5 scanning must not hash/read the whole file")

    monkeypatch.setattr(KerasH5Scanner, "calculate_file_hashes", fail_hash)
    monkeypatch.setattr(
        core_module,
        "_calculate_file_hash",
        lambda _path: pytest.fail("Core must not hash large HDF5 before Keras H5 dispatch"),
    )

    result = KerasH5Scanner().scan(str(model_path))
    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)

    assert model_path.stat().st_size > DEFAULT_MAX_FILE_READ_SIZE
    assert result.success is True
    assert audit_result.success is True
    assert audit_result.content_hash is None
    assert result.metadata["file_backed_scan"] is True
    assert_not_rejected_by_read_cap(result)
    assert any(check.name == "Keras H5 File-Backed Inspection" for check in result.checks)
    assert not any(check.name == "File Integrity Hash" for check in result.checks)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_large_keras_h5_directory_scan_defers_core_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    model_path = create_custom_h5_file(
        model_dir,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        file_name="large_directory_model.h5",
    )
    inflate_h5_file_to_size(model_path)

    monkeypatch.setattr(
        core_module,
        "_calculate_file_hash",
        lambda _path: pytest.fail("Directory scan must not hash large HDF5 before Keras H5 dispatch"),
    )
    monkeypatch.setattr(
        KerasH5Scanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("Keras H5 scanner must not hash large HDF5"),
    )

    audit_result = core_module.scan_model_directory_or_file(str(model_dir), cache_enabled=False)
    metadata = audit_result.file_metadata[str(model_path)]

    assert audit_result.success is True
    assert audit_result.files_scanned == 1
    assert audit_result.content_hash is None
    assert "keras_h5" in audit_result.scanner_names
    assert "max_file_read_size_exceeded" not in (getattr(metadata, "model_extra", {}) or {}).get(
        "scan_outcome_reasons",
        [],
    )


def test_large_keras_h5_streaming_scan_defers_core_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        file_name="large_streamed_model.h5",
    )
    inflate_h5_file_to_size(model_path)

    monkeypatch.setattr(
        "modelaudit.utils.helpers.file_hash.compute_sha256_hash",
        lambda _path: pytest.fail("Streaming scan must not hash large HDF5 before Keras H5 dispatch"),
    )
    monkeypatch.setattr(
        KerasH5Scanner,
        "calculate_file_hashes",
        lambda _self, _path: pytest.fail("Keras H5 scanner must not hash large HDF5"),
    )

    audit_result = core_module.scan_model_streaming(
        file_generator=iter([(model_path, True)]),
        timeout=30,
        delete_after_scan=False,
        cache_enabled=False,
    )
    metadata = audit_result.file_metadata[str(model_path)]

    assert audit_result.success is True
    assert audit_result.files_scanned == 1
    assert audit_result.content_hash is None
    assert "keras_h5" in audit_result.scanner_names
    assert "max_file_read_size_exceeded" not in metadata.get("scan_outcome_reasons", [])


def test_large_malicious_keras_h5_still_detects_lambda_payload(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": "lambda x: __import__('os').system('id')"},
                    }
                ]
            },
        },
        keras_version="3.11.2",
        file_name="large_lambda.h5",
    )
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))
    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)

    assert_not_rejected_by_read_cap(result)
    assert any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        issue.details.get("cve_id") == "CVE-2025-9905" and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )
    assert core_module.determine_exit_code(audit_result) == 1


def test_large_malformed_keras_h5_fails_closed_without_size_limit(tmp_path: Path) -> None:
    model_path = create_raw_config_h5_file(
        tmp_path,
        model_config_attr="{",
        file_name="large_malformed_config.h5",
    )
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))
    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_model_config_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert_not_rejected_by_read_cap(result)
    assert any(check.name == "Keras H5 Config Parse" and check.status == CheckStatus.FAILED for check in result.checks)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    assert core_module.determine_exit_code(audit_result) == 2


def test_large_hdf5_external_link_still_detected_without_target_resolution(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="large_external_link.h5",
    )
    with h5py.File(model_path, "a") as f:
        weights_group = f.require_group("model_weights")
        weights_group.attrs["layer_names"] = [b"dense"]
        dense = weights_group.create_group("dense")
        dense.attrs["weight_names"] = [b"linked_kernel"]
        dense["linked_kernel"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))

    assert_not_rejected_by_read_cap(result)
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/model_weights/dense/linked_kernel",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


def test_large_hdf5_soft_link_to_external_link_still_detected(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="large_soft_external_link.h5",
    )
    with h5py.File(model_path, "a") as f:
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"soft_alias"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        dense["external_payload"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
        dense["soft_alias"] = h5py.SoftLink("/model_weights/dense/external_payload")
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))

    assert_not_rejected_by_read_cap(result)
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/model_weights/dense/soft_alias",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


def test_large_hdf5_soft_link_to_external_storage_still_detected(tmp_path: Path) -> None:
    raw_storage = tmp_path / "weights.raw"
    raw_storage.write_bytes(b"\x00" * 8)
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="large_soft_external_storage.h5",
    )
    with h5py.File(model_path, "a") as f:
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"soft_alias"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        dense.create_dataset(
            "external_kernel",
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )
        dense["soft_alias"] = h5py.SoftLink("/model_weights/dense/external_kernel")
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))

    assert_not_rejected_by_read_cap(result)
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "external_storage",
            "hdf5_path": "/model_weights/dense/soft_alias",
            "segments": [{"filename": "weights.raw", "offset": 0, "size": 8}],
        },
    ]


def test_large_hdf5_virtual_dataset_source_still_detected(tmp_path: Path) -> None:
    virtual_source = tmp_path / "virtual_source.h5"
    with h5py.File(virtual_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="large_virtual_dataset.h5",
    )
    with h5py.File(model_path, "a") as f:
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"virtual_kernel"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
        layout[:] = h5py.VirtualSource(virtual_source.name, "/payload", shape=(2,))
        dense.create_virtual_dataset("virtual_kernel", layout)
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))

    assert_not_rejected_by_read_cap(result)
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "virtual_dataset",
            "hdf5_path": "/model_weights/dense/virtual_kernel",
            "sources": [{"filename": "virtual_source.h5", "path": "/payload"}],
        },
    ]


def test_large_file_backed_hdf5_bypasses_cache_content_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from modelaudit.utils.file.large_file_handler import SMALL_FILE_THRESHOLD
    from modelaudit.utils.helpers.secure_hasher import SecureFileHasher

    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.2",
        file_name="huge_cache_bypass.h5",
    )
    inflate_h5_file_to_size(model_path, SMALL_FILE_THRESHOLD + 4096)
    assert should_bypass_cache_for_file_backed_hdf5(str(model_path)) is True

    def fail_if_cache_hashes_hdf5(self: SecureFileHasher, path: str) -> str:
        if path == str(model_path):
            pytest.fail("large file-backed HDF5 was content-hashed for cache lookup")
        return "a" * 64

    monkeypatch.setattr(SecureFileHasher, "hash_file", fail_if_cache_hashes_hdf5)
    monkeypatch.setattr(
        SecureFileHasher,
        "hash_file_with_stat",
        lambda self, path, _stat: fail_if_cache_hashes_hdf5(self, path),
    )

    reset_cache_manager()
    try:
        audit_result = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
            min_cache_file_size=0,
            max_cache_file_size=SMALL_FILE_THRESHOLD * 2,
            content_hash_threshold=1,
        )
    finally:
        reset_cache_manager()

    assert audit_result.files_scanned == 1
    assert "keras_h5" in audit_result.scanner_names
    assert core_module.determine_exit_code(audit_result) == 0
    metadata = audit_result.file_metadata[str(model_path)]
    assert "max_file_read_size_exceeded" not in metadata.get("scan_outcome_reasons", [])


def test_keras_h5_virtual_dataset_external_source_after_report_cap_still_detected(tmp_path: Path) -> None:
    late_source = tmp_path / "late_virtual_source.h5"
    with h5py.File(late_source, "w") as f:
        f.create_dataset("payload", data=[1.0])
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="late_virtual_dataset.h5",
    )
    with h5py.File(model_path, "a") as f:
        same_file_count = KerasH5Scanner._MAX_HDF5_VIRTUAL_SOURCE_REPORTS
        f.create_dataset("internal_payload", data=[float(index) for index in range(same_file_count)])
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"virtual_kernel"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        layout = h5py.VirtualLayout(shape=(same_file_count + 1,), dtype="float64")
        same_file_source = h5py.VirtualSource(".", "/internal_payload", shape=(same_file_count,))
        for index in range(same_file_count):
            layout[index] = same_file_source[index]
        external_source = h5py.VirtualSource(late_source.name, "/payload", shape=(1,))
        layout[same_file_count] = external_source[0]
        dense.create_virtual_dataset("virtual_kernel", layout)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "virtual_dataset",
            "hdf5_path": "/model_weights/dense/virtual_kernel",
            "sources": [{"filename": "late_virtual_source.h5", "path": "/payload"}],
        },
    ]


def test_keras_h5_virtual_dataset_source_inspection_limit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="virtual_dataset_inspection_limit.h5",
    )
    with h5py.File(model_path, "a") as f:
        f.create_dataset("internal_payload", data=[1.0, 2.0, 3.0])
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"virtual_kernel"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        layout = h5py.VirtualLayout(shape=(3,), dtype="float64")
        same_file_source = h5py.VirtualSource(".", "/internal_payload", shape=(3,))
        for index in range(3):
            layout[index] = same_file_source[index]
        dense.create_virtual_dataset("virtual_kernel", layout)

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_VIRTUAL_SOURCE_INSPECTIONS", 2)

    result = KerasH5Scanner().scan(str(model_path))

    reason = "keras_h5_external_reference_analysis_limit_exceeded"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    limit_checks = [check for check in result.checks if check.name == "HDF5 External Reference Analysis Limit"]
    assert len(limit_checks) == 1
    assert limit_checks[0].status == CheckStatus.FAILED
    assert limit_checks[0].details["virtual_dataset_sources_truncated"] is True


def test_keras_h5_virtual_dataset_external_source_before_scan_wide_budget_still_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_source = tmp_path / "early_virtual_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="virtual_dataset_external_before_budget.h5",
    )
    with h5py.File(model_path, "a") as f:
        f.create_dataset("internal_payload", data=[1.0, 2.0])
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"virtual_kernel"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
        layout[0] = h5py.VirtualSource(external_source.name, "/payload", shape=(2,))[0]
        layout[1] = h5py.VirtualSource(".", "/internal_payload", shape=(2,))[1]
        dense.create_virtual_dataset("virtual_kernel", layout)

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_VIRTUAL_SOURCE_INSPECTIONS", 1)

    result = KerasH5Scanner().scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "virtual_dataset",
            "hdf5_path": "/model_weights/dense/virtual_kernel",
            "sources": [{"filename": "early_virtual_source.h5", "path": "/payload"}],
            "source_count": 2,
            "sources_truncated": True,
        },
    ]
    assert cve_issues[0].details["virtual_dataset_sources_truncated"] is True
    limit_checks = [check for check in result.checks if check.name == "HDF5 External Reference Analysis Limit"]
    assert len(limit_checks) == 1
    assert limit_checks[0].details["visited_virtual_source_count"] == 1
    assert limit_checks[0].details["max_virtual_source_inspections"] == 1


def test_keras_h5_virtual_dataset_source_inspection_budget_is_scan_wide(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="virtual_dataset_scan_wide_budget.h5",
    )
    with h5py.File(model_path, "a") as f:
        f.create_dataset("internal_payload", data=[1.0, 2.0])
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"virtual_a", b"virtual_b"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        same_file_source = h5py.VirtualSource(".", "/internal_payload", shape=(2,))
        for dataset_name in ("virtual_a", "virtual_b"):
            layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
            for index in range(2):
                layout[index] = same_file_source[index]
            dense.create_virtual_dataset(dataset_name, layout)

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_VIRTUAL_SOURCE_INSPECTIONS", 3)

    result = KerasH5Scanner().scan(str(model_path))

    reason = "keras_h5_external_reference_analysis_limit_exceeded"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    limit_checks = [check for check in result.checks if check.name == "HDF5 External Reference Analysis Limit"]
    assert len(limit_checks) == 1
    assert limit_checks[0].status == CheckStatus.FAILED
    assert limit_checks[0].details["visited_virtual_source_count"] == 3
    assert limit_checks[0].details["max_virtual_source_inspections"] == 3
    assert limit_checks[0].details["virtual_dataset_sources_truncated"] is True


def test_keras_h5_same_file_virtual_dataset_source_stays_clean(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="same_file_virtual_dataset.h5",
    )
    with h5py.File(model_path, "a") as f:
        f.create_dataset("internal_payload", data=[1.0, 2.0])
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"virtual_kernel"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
        layout[:] = h5py.VirtualSource(".", "/internal_payload", shape=(2,))
        dense.create_virtual_dataset("virtual_kernel", layout)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_flags_model_config_keras3_layer_vars_external_link(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="keras3_layer_vars_with_model_config.h5",
    )
    with h5py.File(model_path, "a") as f:
        legacy_dense = f.require_group("model_weights").create_group("dense")
        legacy_dense.attrs["weight_names"] = [b"legacy_kernel"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        legacy_dense["legacy_kernel"] = h5py.ExternalLink("missing_legacy_source.h5", "/payload")
        f.create_group("layers").create_group("dense").create_group("vars")["0"] = h5py.ExternalLink(
            "missing_keras3_source.h5",
            "/payload",
        )

    result = KerasH5Scanner().scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/model_weights/dense/legacy_kernel",
            "filename": "missing_legacy_source.h5",
            "path": "/payload",
        },
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense/vars/0",
            "filename": "missing_keras3_source.h5",
            "path": "/payload",
        },
    ]


def test_keras_h5_scanner_allows_model_config_keras3_same_file_virtual_dataset(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="keras3_same_file_vds_with_model_config.h5",
    )
    with h5py.File(model_path, "a") as f:
        f.create_dataset("internal_payload", data=[1.0, 2.0])
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
        layout[:] = h5py.VirtualSource(".", "/internal_payload", shape=(2,))
        vars_group.create_virtual_dataset("0", layout)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


@pytest.mark.parametrize("root_path", ["vars", "optimizer/vars"])
def test_keras_h5_scanner_flags_model_config_keras3_root_vars_external_link(
    tmp_path: Path,
    root_path: str,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        keras_version="3.13.1",
        file_name="keras3_root_vars_with_model_config.h5",
    )
    with h5py.File(model_path, "a") as f:
        vars_group = f.require_group(root_path)
        vars_group["0"] = h5py.ExternalLink("missing_keras3_root_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": f"/{root_path}/0",
            "filename": "missing_keras3_root_source.h5",
            "path": "/payload",
        },
    ]


@pytest.mark.parametrize("root_path", ["vars", "optimizer/vars"])
def test_keras_h5_scanner_flags_keras3_root_vars_external_link(tmp_path: Path, root_path: str) -> None:
    weights_path = tmp_path / "keras3_root_vars.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_group("layers").create_group("dense")
        vars_group = f.require_group(root_path)
        vars_group["0"] = h5py.ExternalLink("missing_external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": f"/{root_path}/0",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


@pytest.mark.parametrize("root_path", ["vars", "optimizer/vars"])
def test_keras_h5_scanner_flags_keras3_root_vars_external_storage(tmp_path: Path, root_path: str) -> None:
    raw_storage = tmp_path / "root_weights.raw"
    raw_storage.write_bytes(b"\x00" * 8)
    weights_path = tmp_path / "keras3_root_external_storage.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_group("layers").create_group("dense")
        vars_group = f.require_group(root_path)
        vars_group.create_dataset(
            "0",
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "external_storage",
            "hdf5_path": f"/{root_path}/0",
            "segments": [{"filename": "root_weights.raw", "offset": 0, "size": 8}],
        },
    ]


@pytest.mark.parametrize("root_path", ["vars", "optimizer/vars"])
def test_keras_h5_scanner_flags_keras3_root_vars_virtual_dataset_source(tmp_path: Path, root_path: str) -> None:
    virtual_source = tmp_path / "root_virtual_source.h5"
    with h5py.File(virtual_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])
    weights_path = tmp_path / "keras3_root_virtual_vars.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_group("layers").create_group("dense")
        vars_group = f.require_group(root_path)
        layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
        layout[:] = h5py.VirtualSource(virtual_source.name, "/payload", shape=(2,))
        vars_group.create_virtual_dataset("0", layout)

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "virtual_dataset",
            "hdf5_path": f"/{root_path}/0",
            "sources": [{"filename": "root_virtual_source.h5", "path": "/payload"}],
        },
    ]


def test_keras_h5_scanner_flags_arbitrary_keras3_saveable_vars_external_link(tmp_path: Path) -> None:
    external_source = tmp_path / "external.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])
    weights_path = tmp_path / "keras3_custom_child.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_group("layers").create_group("dense").create_group("vars").create_dataset("0", data=[1.0])
        f.require_group("custom_parent").require_group("custom_child").require_group("vars")["0"] = h5py.ExternalLink(
            external_source.name,
            "/payload",
        )
    inflate_h5_file_to_size(weights_path, 536_871_936)

    result = KerasH5Scanner().scan(str(weights_path))
    audit_result = core_module.scan_model_directory_or_file(str(weights_path), cache_enabled=False)

    assert weights_path.stat().st_size == 536_871_936
    assert_not_rejected_by_read_cap(result)
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/custom_parent/custom_child/vars/0",
            "filename": "external.h5",
            "path": "/payload",
        },
    ]
    assert core_module.determine_exit_code(audit_result) == 1


def test_keras_h5_scanner_allows_internal_arbitrary_keras3_saveable_vars(tmp_path: Path) -> None:
    weights_path = tmp_path / "keras3_internal_custom_child.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_group("layers").create_group("dense").create_group("vars").create_dataset("0", data=[1.0])
        f.require_group("custom_parent").require_group("custom_child").require_group("vars").create_dataset(
            "0",
            data=[2.0],
        )
    inflate_h5_file_to_size(weights_path, 536_871_936)

    result = KerasH5Scanner().scan(str(weights_path))

    assert result.success is True
    assert_not_rejected_by_read_cap(result)
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_large_hdf5_soft_link_cycle_fails_closed_without_size_limit(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
        },
        file_name="large_soft_cycle.h5",
    )
    with h5py.File(model_path, "a") as f:
        dense = f.require_group("model_weights").create_group("dense")
        dense.attrs["weight_names"] = [b"cycle_a"]
        f["model_weights"].attrs["layer_names"] = [b"dense"]
        dense["cycle_a"] = h5py.SoftLink("/model_weights/dense/cycle_b")
        dense["cycle_b"] = h5py.SoftLink("/model_weights/dense/cycle_a")
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_external_reference_analysis_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert_not_rejected_by_read_cap(result)
    assert any(
        check.name == "HDF5 External Reference Analysis Limit"
        and check.details["soft_link_resolution_incomplete"] is True
        for check in result.checks
    )


def test_sparse_chunked_compressed_hdf5_dataset_does_not_materialize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": "lambda x: __import__('os').system('id')"},
                    }
                ]
            },
        },
        keras_version="3.11.2",
        file_name="sparse_compressed.h5",
    )
    with h5py.File(model_path, "a") as f:
        weights_group = f.require_group("model_weights")
        weights_group.create_dataset(
            "huge_sparse_compressed",
            shape=(1024 * 1024 * 1024,),
            dtype="float32",
            chunks=(1024,),
            compression="gzip",
            fillvalue=0,
        )
    inflate_h5_file_to_size(model_path)

    def fail_dataset_read(_self: Any, _key: Any) -> Any:
        raise AssertionError("HDF5 dataset payload was materialized")

    def fail_read_direct(_self: Any, *_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("HDF5 dataset payload was materialized")

    monkeypatch.setattr(h5py.Dataset, "__getitem__", fail_dataset_read)
    monkeypatch.setattr(h5py.Dataset, "read_direct", fail_read_direct)

    result = KerasH5Scanner().scan(str(model_path))

    assert_not_rejected_by_read_cap(result)
    assert any(issue.details.get("cve_id") == "CVE-2025-9905" for issue in result.issues)


def test_keras_h5_oversized_config_attribute_fails_closed_before_json_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_raw_config_h5_file(
        tmp_path,
        model_config_attr=json.dumps(
            {
                "class_name": "Sequential",
                "config": {"layers": [{"class_name": "Dense", "config": {"padding": "A" * 64}}]},
            }
        ),
        file_name="oversized_config_attr.h5",
    )
    inflate_h5_file_to_size(model_path)
    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_JSON_ATTRIBUTE_BYTES", 32)
    original_attr_getitem = h5py.AttributeManager.__getitem__

    def fail_model_config_materialization(self: Any, name: str) -> Any:
        if name == "model_config":
            raise AssertionError("oversized Keras H5 config should not be materialized")
        return original_attr_getitem(self, name)

    def fail_json_loads(_payload: Any) -> Any:
        raise AssertionError("oversized Keras H5 config should not be parsed")

    monkeypatch.setattr(h5py.AttributeManager, "__getitem__", fail_model_config_materialization)
    monkeypatch.setattr(keras_h5_scanner_module.json, "loads", fail_json_loads)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_model_config_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert_not_rejected_by_read_cap(result)
    assert any(
        check.name == "Keras H5 Config Size Limit" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_generic_hdf5_dangling_layers_soft_link_stays_clean(tmp_path: Path) -> None:
    model_path = tmp_path / "generic_dangling_layers_soft_link.h5"
    with h5py.File(model_path, "w") as f:
        f["layers"] = h5py.SoftLink("/missing")

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    assert any(
        check.name == "Keras Model Format Check" and check.details.get("format") == "generic_h5"
        for check in result.checks
    )


@pytest.mark.parametrize("attr_name", ["layer_names", "weight_names"])
def test_keras_h5_oversized_weight_name_attribute_fails_closed_before_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attr_name: str,
) -> None:
    model_path = tmp_path / f"oversized_{attr_name}.weights.h5"
    with h5py.File(model_path, "w") as f:
        if attr_name == "layer_names":
            f.attrs["layer_names"] = [b"dense", b"A" * 64]
        else:
            f.attrs["layer_names"] = [b"dense"]
            dense = f.create_group("dense")
            dense.attrs["weight_names"] = [b"kernel:0", b"A" * 64]
            dense.create_dataset("kernel:0", data=[1.0])
    inflate_h5_file_to_size(model_path)
    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_NAME_ATTRIBUTE_BYTES", 32)
    original_attr_getitem = h5py.AttributeManager.__getitem__

    def fail_name_attribute_materialization(self: Any, name: str) -> Any:
        if name == attr_name:
            raise AssertionError(f"oversized Keras H5 {attr_name} should not be materialized")
        return original_attr_getitem(self, name)

    monkeypatch.setattr(h5py.AttributeManager, "__getitem__", fail_name_attribute_materialization)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_external_reference_analysis_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert_not_rejected_by_read_cap(result)
    assert any(
        check.name == "HDF5 External Reference Analysis Limit" and check.details["weight_roots_truncated"] is True
        for check in result.checks
    )


def test_large_dense_hdf5_name_attribute_uses_isolated_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import numpy as np

    model_path = tmp_path / "dense_layer_names.weights.h5"
    encoded_attribute_bytes = 16 * 1024 * 1024
    element_size = 32
    with h5py.File(model_path, "w", track_order=True) as f:
        f.attrs.create(
            "layer_names",
            np.full(encoded_attribute_bytes // element_size, b"dense", dtype=f"S{element_size}"),
        )
    inflate_h5_file_to_size(model_path, 536_871_936)

    def fail_parent_attribute_access(_self: Any, name: str) -> Any:
        raise AssertionError(f"large HDF5 attribute {name!r} was inspected in the parent process")

    monkeypatch.setattr(h5py.AttributeManager, "__contains__", fail_parent_attribute_access)
    monkeypatch.setattr(h5py.AttributeManager, "get_id", fail_parent_attribute_access)
    monkeypatch.setattr(h5py.AttributeManager, "__getitem__", fail_parent_attribute_access)

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_external_reference_analysis_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert_not_rejected_by_read_cap(result)
    assert any(
        check.name == "HDF5 External Reference Analysis Limit" and check.details["weight_roots_truncated"] is True
        for check in result.checks
    )


def test_large_variable_string_model_config_uses_json_budget(tmp_path: Path) -> None:
    model_path = tmp_path / "large_variable_model_config.h5"
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "A" * 5000,
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {"function": "lambda x: __import__('os').system('id')"},
                }
            ],
        },
    }
    with h5py.File(model_path, "w") as f:
        f.attrs.create(
            "model_config",
            json.dumps(model_config),
            dtype=h5py.string_dtype(encoding="utf-8"),
        )
        f.require_group("model_weights")
    inflate_h5_file_to_size(model_path)

    result = KerasH5Scanner().scan(str(model_path))

    assert_not_rejected_by_read_cap(result)
    assert "keras_h5_model_config_parse_failed" not in result.metadata.get("scan_outcome_reasons", [])
    assert "keras_h5_model_config_size_limit_exceeded" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        issue.message == "Lambda layer contains dangerous Python code" and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


def test_variable_string_vector_custom_objects_does_not_skip_training_config(tmp_path: Path) -> None:
    model_path = tmp_path / "vector_custom_objects.h5"
    model_config = {
        "class_name": "Sequential",
        "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
    }
    training_config = {
        "loss": {"output_1": "malicious_loss"},
        "metrics": [["accuracy"]],
    }
    with h5py.File(model_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        f.attrs.create(
            "custom_objects",
            ["custom_loss", "custom_metric"],
            dtype=h5py.string_dtype(encoding="utf-8"),
        )
        f.attrs["training_config"] = json.dumps(training_config)

    result = KerasH5Scanner().scan(str(model_path))

    assert "keras_h5_scan_failed" not in result.metadata.get("scan_outcome_reasons", [])
    assert any(
        check.name == "Custom Objects Security Check"
        and check.details["custom_objects"] == ["custom_loss", "custom_metric"]
        for check in result.checks
    )
    assert any(
        check.name == "Custom Loss Detection" and check.details.get("identifier") == "malicious_loss"
        for check in result.checks
    )


def test_empty_variable_string_name_attribute_is_not_truncated(tmp_path: Path) -> None:
    import numpy as np

    model_path = tmp_path / "empty_variable_names.h5"
    with h5py.File(model_path, "w") as f:
        f.attrs.create(
            "layer_names",
            np.array([], dtype=object),
            dtype=h5py.string_dtype(encoding="utf-8"),
        )

    with h5py.File(model_path, "r") as f:
        names, truncated = KerasH5Scanner._read_bounded_hdf5_name_attribute(f.attrs, "layer_names")
        attr_id = f.attrs.get_id("layer_names")
        direct_names, direct_truncated = KerasH5Scanner._read_hdf5_variable_string_name_attribute(
            attr_id,
            max_bytes=KerasH5Scanner._MAX_HDF5_NAME_ATTRIBUTE_BYTES,
            point_count=0,
        )

    assert names == []
    assert truncated is False
    assert direct_names == []
    assert direct_truncated is False


def test_large_empty_variable_string_name_attributes_scan_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import numpy as np

    model_path = tmp_path / "large_empty_variable_names.h5"
    model_config = {"class_name": "Sequential", "config": {"layers": []}}
    empty_names = np.array([], dtype=object)
    with h5py.File(model_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        weights = f.require_group("model_weights")
        weights.attrs.create(
            "weight_names",
            empty_names,
            dtype=h5py.string_dtype(encoding="utf-8"),
        )
        weights.attrs.create(
            "layer_names",
            empty_names,
            dtype=h5py.string_dtype(encoding="utf-8"),
        )
    inflate_h5_file_to_size(model_path)

    worker_name_attrs: list[str] = []
    original_batch_reader: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] = (
        KerasH5Scanner._read_hdf5_attributes_in_worker
    )

    def counting_batch_reader(cls: type[KerasH5Scanner], requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        worker_name_attrs.extend(str(request["attr_name"]) for request in requests if request.get("mode") == "names")
        return original_batch_reader(requests)

    monkeypatch.setattr(KerasH5Scanner, "_read_hdf5_attributes_in_worker", classmethod(counting_batch_reader))

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert_not_rejected_by_read_cap(result)
    assert worker_name_attrs.count("weight_names") >= 1
    assert worker_name_attrs.count("layer_names") >= 1
    assert "keras_h5_external_reference_analysis_limit_exceeded" not in result.metadata.get(
        "scan_outcome_reasons",
        [],
    )
    assert not any(
        check.name == "HDF5 External Reference Analysis Limit" and check.details.get("weight_roots_truncated") is True
        for check in result.checks
    )


def test_large_legacy_weight_name_attributes_are_batched_in_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layer_count = 64
    model_path = tmp_path / "many_legacy_layers.weights.h5"
    with h5py.File(model_path, "w") as f:
        layer_names = [f"layer_{index}".encode() for index in range(layer_count)]
        f.attrs["layer_names"] = layer_names
        for index in range(layer_count):
            layer = f.create_group(f"layer_{index}")
            layer.attrs["weight_names"] = [b"kernel:0"]
            layer.create_dataset("kernel:0", data=[float(index)])
    inflate_h5_file_to_size(model_path)

    worker_batch_sizes: list[int] = []
    original_batch_reader: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] = (
        KerasH5Scanner._read_hdf5_attributes_in_worker
    )

    def counting_batch_reader(cls: type[KerasH5Scanner], requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        worker_batch_sizes.append(len(requests))
        return original_batch_reader(requests)

    monkeypatch.setattr(KerasH5Scanner, "_read_hdf5_attributes_in_worker", classmethod(counting_batch_reader))

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert_not_rejected_by_read_cap(result)
    assert max(worker_batch_sizes) >= layer_count
    assert len(worker_batch_sizes) <= 12


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_pinned_hf_h5_metadata(
    huggingface_hub: Any,
    *,
    repo_id: str,
    revision: str,
    expected_size: int,
    expected_blob_id: str,
    expected_sha256: str,
) -> None:
    info = huggingface_hub.HfApi().model_info(repo_id=repo_id, revision=revision, files_metadata=True)
    assert info.sha == revision
    tf_model = next(sibling for sibling in info.siblings if sibling.rfilename == "tf_model.h5")
    assert tf_model.size == expected_size
    assert tf_model.blob_id == expected_blob_id
    assert tf_model.lfs is not None
    assert tf_model.lfs.sha256 == expected_sha256


def _assert_real_hf_h5_reaches_keras_scan(
    tmp_path: Path,
    *,
    repo_id: str,
    revision: str,
    expected_size: int,
    expected_blob_id: str,
    expected_sha256: str,
    expected_root_keys: list[str] | None = None,
    expected_attrs: set[str] | None = None,
    expected_layer_names: list[str] | None = None,
) -> None:
    if os.environ.get("MODELAUDIT_RUN_REAL_HF_H5") != "1":
        pytest.skip("Set MODELAUDIT_RUN_REAL_HF_H5=1 to download and scan pinned HF H5 models")

    huggingface_hub = pytest.importorskip("huggingface_hub")
    _assert_pinned_hf_h5_metadata(
        huggingface_hub,
        repo_id=repo_id,
        revision=revision,
        expected_size=expected_size,
        expected_blob_id=expected_blob_id,
        expected_sha256=expected_sha256,
    )
    cache_dir = os.environ.get("MODELAUDIT_HF_CACHE_DIR", str(tmp_path / "hf-cache"))
    model_path = Path(
        huggingface_hub.hf_hub_download(
            repo_id=repo_id,
            filename="tf_model.h5",
            revision=revision,
            cache_dir=cache_dir,
        )
    )

    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    metadata = audit_result.file_metadata[str(model_path)]
    metadata_extra = getattr(metadata, "model_extra", {}) or {}

    assert model_path.stat().st_size == expected_size
    assert metadata.file_size == expected_size
    assert _sha256_file(model_path) == expected_sha256
    with h5py.File(model_path, "r") as h5_file:
        if expected_root_keys is not None:
            assert sorted(h5_file.keys()) == expected_root_keys
        if expected_attrs is not None:
            assert set(h5_file.attrs.keys()) == expected_attrs
        layer_names, layer_names_truncated = KerasH5Scanner._read_bounded_hdf5_name_attribute(
            h5_file.attrs,
            "layer_names",
        )
        assert layer_names_truncated is False
        assert layer_names
        if expected_layer_names is not None:
            assert layer_names == expected_layer_names
        for layer_name in layer_names:
            assert layer_name in h5_file
    assert audit_result.files_scanned == 1
    assert "keras_h5" in audit_result.scanner_names
    assert "max_file_read_size_exceeded" not in (metadata_extra.get("scan_outcome_reasons") or [])
    assert any(
        check.name == "Keras Model Format Check" and check.status == CheckStatus.PASSED for check in audit_result.checks
    )
    assert core_module.determine_exit_code(audit_result) == 0


@pytest.mark.integration
def test_real_hf_xlm_roberta_large_h5_reaches_keras_scan_without_read_cap(tmp_path: Path) -> None:
    _assert_real_hf_h5_reaches_keras_scan(
        tmp_path,
        repo_id="FacebookAI/xlm-roberta-large",
        revision="c23d21b0620b635a76227c604d44e43a9f0ee389",
        expected_size=2_240_076_248,
        expected_blob_id="c902fe1cef9561c2e78bd7fccc5f83887e844f8b",
        expected_sha256="a465c8d459fe83e10db5655221e2e7e7b6df3de2216c524399358d17ac7315ea",
        expected_root_keys=["roberta", "top_level_model_weights"],
        expected_attrs={"backend", "keras_version", "layer_names"},
        expected_layer_names=["roberta"],
    )


@pytest.mark.integration
def test_real_hf_esm2_large_h5_reaches_keras_scan_without_read_cap(tmp_path: Path) -> None:
    _assert_real_hf_h5_reaches_keras_scan(
        tmp_path,
        repo_id="facebook/esm2_t33_650M_UR50D",
        revision="08e4846e537177426273712802403f7ba8261b6c",
        expected_size=2_605_109_760,
        expected_blob_id="c3271b7e4fc4dbd0f1bd3980c02cc21101c57cbb",
        expected_sha256="3110b0ee07a47362ff90dc4d780b12287e06f2a09f56c8e117c4aed089fc96b8",
    )


@pytest.mark.integration
def test_real_hf_whisper_large_v2_h5_reaches_keras_scan_without_read_cap(tmp_path: Path) -> None:
    _assert_real_hf_h5_reaches_keras_scan(
        tmp_path,
        repo_id="openai/whisper-large-v2",
        revision="ae4642769ce2ad8fc292556ccea8e901f1530655",
        expected_size=6_174_574_896,
        expected_blob_id="38414d47073f613961f19565ed6b481e1b9b0f80",
        expected_sha256="489f5f36ba6e1959913bb77b30baf85e8b791e1e585dec7d65a2e217bfb8be47",
    )


def test_missing_h5py_returns_inconclusive_exit2_without_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recognized H5 file cannot be considered fully scanned without h5py."""
    model_path = create_h5_with_external_link(tmp_path)
    reason = "keras_h5_h5py_unavailable"
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

    _assert_inconclusive_keras_h5_scan(
        model_path,
        reason,
        "H5PY Library Check",
        "h5py is required for Keras H5 scanning",
    )
    _assert_inconclusive_keras_h5_scan_not_cached(
        model_path,
        reason,
        tmp_path / "missing-h5py-cache",
    )


def test_missing_h5py_invalidates_stale_cache_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing h5py must not return stale clean H5 cache entries."""
    model_path = create_h5_with_external_link(tmp_path)
    extensionless_model_path = tmp_path / "extensionless_hdf5"
    extensionless_model_path.write_bytes(model_path.read_bytes())
    cache_dir = tmp_path / "stale-missing-h5py-cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}

    reset_cache_manager()
    try:
        cache_manager = get_cache_manager(str(cache_dir), enabled=True)
        for cached_path in (model_path, extensionless_model_path):
            version_context = build_cache_version_context(config)
            _, file_identity = cache_manager.get_cached_result_with_identity(
                str(cached_path),
                version_context=version_context,
            )
            assert file_identity is not None
            assert cache_manager.cache is not None
            file_stat, file_hash, change_token, ancestor_identity = file_identity
            try:
                assert cache_manager.store_result(
                    str(cached_path),
                    {
                        "scanner": "keras_h5",
                        "success": True,
                        "issues": [],
                        "checks": [],
                        "metadata": {},
                    },
                    version_context=version_context,
                    expected_file_stat=file_stat,
                    expected_file_hash=file_hash,
                    expected_change_token=change_token,
                    expected_ancestor_identity=ancestor_identity,
                )
            finally:
                cache_manager.cache.release_ancestor_identity(ancestor_identity)

        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)
        scanner = KerasH5Scanner(config=config)

        for cached_path in (model_path, extensionless_model_path):
            result = scanner.scan_with_cache(str(cached_path))
            assert result.success is False
            assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "keras_h5_h5py_unavailable" in result.metadata["scan_outcome_reasons"]

        assert cache_manager.get_stats()["total_entries"] == 2

        monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", True)
        for cached_path in (model_path, extensionless_model_path):
            result = scanner.scan_with_cache(str(cached_path))
            assert any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)

        assert cache_manager.get_stats()["total_entries"] == 4
    finally:
        reset_cache_manager()


def test_missing_h5py_routes_hdf5_userblock_and_bypasses_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Keras H5 file with a legal user block must retain fail-closed routing."""
    external_source = tmp_path / "userblock_external_source.h5"
    with h5py.File(external_source, "w") as h5_file:
        h5_file.create_dataset("payload", data=[1.0, 2.0])

    model_path = tmp_path / "userblock_model.h5"
    with h5py.File(model_path, "w", userblock_size=512) as h5_file:
        h5_file.attrs["model_config"] = json.dumps(
            {
                "class_name": "Sequential",
                "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
            }
        )
        weights_group = h5_file.require_group("model_weights")
        weights_group["linked_kernel"] = h5py.ExternalLink(external_source.name, "/payload")

    assert model_path.read_bytes()[:8] != b"\x89HDF\r\n\x1a\n"
    assert model_path.read_bytes()[512:520] == b"\x89HDF\r\n\x1a\n"
    extensionless_model_path = tmp_path / "userblock_model"
    extensionless_model_path.write_bytes(model_path.read_bytes())
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

    for candidate_path in (model_path, extensionless_model_path):
        assert KerasH5Scanner.can_handle(str(candidate_path)) is True
        assert should_bypass_cache_for_missing_h5py(str(candidate_path)) is True
        _assert_inconclusive_keras_h5_scan(
            candidate_path,
            "keras_h5_h5py_unavailable",
            "H5PY Library Check",
            "h5py is required for Keras H5 scanning",
        )


def test_broken_h5py_import_still_fails_closed_for_extensionless_userblock(tmp_path: Path) -> None:
    model_path = tmp_path / "broken_h5py_userblock"
    with h5py.File(model_path, "w", userblock_size=512) as h5_file:
        h5_file.attrs["model_config"] = json.dumps(
            {
                "class_name": "Sequential",
                "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
            }
        )

    script = textwrap.dedent(
        """
        import importlib.abc
        import json
        import sys

        class BrokenH5pyFinder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "h5py" or fullname.startswith("h5py."):
                    raise RuntimeError("simulated h5py binary failure")
                return None

        sys.meta_path.insert(0, BrokenH5pyFinder())

        import modelaudit.core as core_module

        model_path = sys.argv[1]
        result = core_module.scan_model_directory_or_file(model_path, cache_enabled=False)
        metadata = result.file_metadata[model_path]
        print(
            json.dumps(
                {
                    "success": result.success,
                    "exit_code": core_module.determine_exit_code(result),
                    "check_names": [check.name for check in result.checks],
                    "scan_outcome_reasons": metadata.get("scan_outcome_reasons", []),
                }
            )
        )
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(model_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    assert payload["success"] is False
    assert payload["exit_code"] == 2
    assert "H5PY Library Check" in payload["check_names"]
    assert "keras_h5_h5py_unavailable" in payload["scan_outcome_reasons"]


def test_missing_h5py_cache_bypass_requires_hdf5_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ZIP-backed .keras files should retain normal caching when h5py is unavailable."""
    h5_model_path = create_h5_with_external_link(tmp_path)
    extensionless_model_path = tmp_path / "extensionless_hdf5"
    extensionless_model_path.write_bytes(h5_model_path.read_bytes())
    zip_model_path = tmp_path / "model.keras"
    with zipfile.ZipFile(zip_model_path, "w") as zip_file:
        zip_file.writestr("config.json", "{}")
    magic_only_path = tmp_path / "magic_only.h5"
    magic_only_payload = bytearray(1024)
    magic_only_payload[512:520] = b"\x89HDF\r\n\x1a\n"
    magic_only_path.write_bytes(magic_only_payload)

    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

    assert should_bypass_cache_for_missing_h5py(str(h5_model_path)) is True
    assert should_bypass_cache_for_missing_h5py(str(extensionless_model_path)) is True
    assert should_bypass_cache_for_missing_h5py(str(zip_model_path)) is False
    assert should_bypass_cache_for_missing_h5py(str(magic_only_path)) is False


def _write_synthetic_hdf5_v2_superblock(
    path: Path,
    *,
    offset_size: int,
    length_size: int,
    status_flags: int = 0,
) -> None:
    max_address = (1 << (offset_size * 8)) - 1
    file_size = min(512, max_address - 1)

    def encode_address(value: int) -> bytes:
        return value.to_bytes(offset_size, "little")

    root_group_address = min(128, file_size - 1)
    superblock_without_checksum = b"".join(
        (
            HDF5_MAGIC,
            bytes((2, offset_size, length_size, status_flags)),
            encode_address(0),
            encode_address(max_address),
            encode_address(file_size),
            encode_address(root_group_address),
        )
    )
    superblock = superblock_without_checksum + hdf5_metadata_checksum(superblock_without_checksum).to_bytes(4, "little")
    path.write_bytes(superblock + bytes(file_size - len(superblock)))


def _write_synthetic_hdf5_v1_superblock(path: Path, *, field_width: int) -> None:
    file_size = 512
    undefined_address = (1 << (field_width * 8)) - 1

    def encode_address(value: int) -> bytes:
        return value.to_bytes(field_width, "little")

    superblock = b"".join(
        (
            HDF5_MAGIC,
            bytes((1, 0, 0, 0, 0, field_width, field_width, 0)),
            (4).to_bytes(2, "little"),
            (16).to_bytes(2, "little"),
            bytes(4),
            (32).to_bytes(2, "little"),
            bytes(2),
            encode_address(0),
            encode_address(undefined_address),
            encode_address(file_size),
            encode_address(undefined_address),
        )
    )
    path.write_bytes(superblock + bytes(file_size - len(superblock)))


@pytest.mark.parametrize("field_width", [2, 4, 8, 16, 32])
def test_hdf5_signature_probe_accepts_supported_field_widths(tmp_path: Path, field_width: int) -> None:
    model_path = tmp_path / f"field_width_{field_width}.h5"
    _write_synthetic_hdf5_v2_superblock(
        model_path,
        offset_size=field_width,
        length_size=field_width,
    )

    assert find_hdf5_signature_offset(str(model_path)) == 0


def test_hdf5_metadata_checksum_matches_official_lookup3_vector() -> None:
    assert hdf5_metadata_checksum(b"\x17") == 0xA209C931


def test_hdf5_signature_probe_accepts_legacy_v1_32_byte_addresses(tmp_path: Path) -> None:
    model_path = tmp_path / "legacy_v1_32_byte_addresses.h5"
    _write_synthetic_hdf5_v1_superblock(model_path, field_width=32)

    assert find_hdf5_signature_offset(str(model_path)) == 0


def test_hdf5_signature_probe_rejects_corrupt_v2_checksum(tmp_path: Path) -> None:
    model_path = tmp_path / "corrupt_v2_checksum.h5"
    _write_synthetic_hdf5_v2_superblock(model_path, offset_size=8, length_size=8)
    payload = bytearray(model_path.read_bytes())
    payload[44] ^= 0x01
    model_path.write_bytes(payload)

    assert find_hdf5_signature_offset(str(model_path)) is None


def test_h5py_runtime_failure_bypasses_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_mock_h5_file(tmp_path)
    cache_dir = tmp_path / "runtime-h5py-failure-cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "min_cache_file_size": 0}

    reset_cache_manager()
    try:
        clean_result = KerasH5Scanner(config=config).scan_with_cache(str(model_path))
        assert clean_result.success is True
        cache_manager = get_cache_manager(str(cache_dir), enabled=True)
        assert cache_manager.get_stats()["total_entries"] == 1

        raw_secret = "ATTACKER_CONTROLLED_KERAS_H5_RUNTIME_FAILURE"

        def fail_h5py_open(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError(raw_secret)

        monkeypatch.setattr(keras_h5_scanner_module.h5py, "File", fail_h5py_open)

        failed_result = KerasH5Scanner(config=config).scan_with_cache(str(model_path))
        assert failed_result.success is False
        assert "keras_h5_scan_failed" in failed_result.metadata["scan_outcome_reasons"]
        failure_checks = [check for check in failed_result.checks if check.name == "Keras H5 File Scan"]
        assert failure_checks
        assert failure_checks[0].details["exception"] == "<redacted>"
        assert "<redacted>" in failure_checks[0].message
        assert raw_secret not in failed_result.to_json()
        assert cache_manager.get_stats()["total_entries"] == 1

        audit_result = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        assert core_module.determine_exit_code(audit_result) == 2
        assert "keras_h5_scan_failed" in audit_result.file_metadata[str(model_path)]["scan_outcome_reasons"]
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    ("offset_size", "length_size", "status_flags"),
    [
        (1, 1, 0),
        (3, 8, 0),
        (8, 5, 0),
        (8, 8, 0x08),
    ],
)
def test_hdf5_signature_probe_rejects_malformed_superblock_fields(
    tmp_path: Path,
    offset_size: int,
    length_size: int,
    status_flags: int,
) -> None:
    model_path = tmp_path / f"malformed_{offset_size}_{length_size}_{status_flags}.h5"
    _write_synthetic_hdf5_v2_superblock(
        model_path,
        offset_size=offset_size,
        length_size=length_size,
        status_flags=status_flags,
    )

    assert find_hdf5_signature_offset(str(model_path)) is None


def test_missing_h5py_rejects_malformed_hdf5_near_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "malformed_near_match.h5"
    _write_synthetic_hdf5_v2_superblock(model_path, offset_size=1, length_size=1)
    monkeypatch.setattr(keras_h5_scanner_module, "HAS_H5PY", False)

    assert KerasH5Scanner.can_handle(str(model_path)) is False
    assert should_bypass_cache_for_missing_h5py(str(model_path)) is False


def _assert_inconclusive_keras_h5_scan(
    model_path: Path,
    reason: str,
    expected_check_name: str,
    expected_message_substring: str,
) -> None:
    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == expected_check_name
        and check.status == CheckStatus.FAILED
        and expected_message_substring in check.message
        for check in result.checks
    )

    audit_result = core_module.scan_model_directory_or_file(str(model_path))
    metadata = audit_result.file_metadata[str(model_path)]

    assert audit_result.has_errors is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in metadata.get("scan_outcome_reasons")
    assert core_module.determine_exit_code(audit_result) == 2


def _assert_inconclusive_keras_h5_scan_not_cached(model_path: Path, reason: str, cache_dir: Path) -> None:
    reset_cache_manager()
    try:
        first_result = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )
        second_result = core_module.scan_model_directory_or_file(
            str(model_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        for audit_result in (first_result, second_result):
            metadata = audit_result.file_metadata[str(model_path)]
            assert core_module.determine_exit_code(audit_result) == 2
            assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata.get("scan_outcome_reasons")
            assert not any(
                issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in audit_result.issues
            )

        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


@pytest.mark.parametrize(
    ("model_config", "reason", "expected_check_name", "expected_message_substring"),
    [
        (None, "keras_h5_model_config_invalid_type", "Model Config Type Validation", "Invalid model config type"),
        ([], "keras_h5_model_config_invalid_type", "Model Config Type Validation", "Invalid model config type"),
        (
            {"class_name": "Sequential"},
            "keras_h5_model_layers_missing",
            "Layers Presence Validation",
            "missing required layers list",
        ),
        (
            {"class_name": "Sequential", "config": {}},
            "keras_h5_model_layers_missing",
            "Layers Presence Validation",
            "missing required layers list",
        ),
        (
            {"class_name": "Sequential", "config": "layers hidden in wrong type"},
            "keras_h5_model_config_structure_invalid",
            "Model Config Structure Validation",
            "Invalid model config.config type",
        ),
        (
            {"class_name": "Sequential", "config": {"layers": "layers hidden in wrong type"}},
            "keras_h5_model_layers_invalid_type",
            "Layers Type Validation",
            "Invalid layers type",
        ),
        (
            {"class_name": "Sequential", "config": {"layers": ["not a layer dict"]}},
            "keras_h5_model_layer_invalid_type",
            "Layer Type Validation",
            "Invalid layer type",
        ),
        (
            {"class_name": "Sequential", "config": {"layers": [{"class_name": "TimeDistributed", "config": "..."}]}},
            "keras_h5_layer_config_invalid_type",
            "Layer Config Type Validation",
            "Invalid layer config type",
        ),
        (
            {"class_name": "Sequential", "config": {"layers": [{"class_name": "Functional", "config": {}}]}},
            "keras_h5_nested_model_layers_missing",
            "Nested Model Layers Presence Validation",
            "missing required layers list",
        ),
    ],
)
def test_keras_h5_invalid_model_config_structure_returns_inconclusive_exit2(
    tmp_path: Path,
    model_config: Any,
    reason: str,
    expected_check_name: str,
    expected_message_substring: str,
) -> None:
    """Keras H5 model_config that cannot be fully traversed should fail closed."""
    model_path = create_custom_h5_file(
        tmp_path,
        model_config,
        file_name=f"{reason}.h5",
    )

    _assert_inconclusive_keras_h5_scan(model_path, reason, expected_check_name, expected_message_substring)


def test_keras_h5_malformed_model_config_json_returns_inconclusive_exit2(tmp_path: Path) -> None:
    """Malformed Keras model_config JSON should not be reported as a clean scan or security finding."""
    model_path = create_raw_config_h5_file(
        tmp_path,
        model_config_attr="{",
        file_name="malformed_model_config.h5",
    )

    _assert_inconclusive_keras_h5_scan(
        model_path,
        "keras_h5_model_config_parse_failed",
        "Keras H5 Config Parse",
        "Malformed Keras H5 model_config",
    )
    result = KerasH5Scanner().scan(str(model_path))
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_keras_h5_read_failure_returns_inconclusive_exit2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unavailable Keras H5 content is incomplete analysis, not evidence of malicious content."""
    model_path = create_custom_h5_file(
        tmp_path,
        {"class_name": "Sequential", "config": {"layers": []}},
        file_name="unavailable_content.h5",
    )

    raw_secret = "ATTACKER_CONTROLLED_KERAS_H5_READ_FAILURE"

    def raise_os_error(_self: KerasH5Scanner, _h5_file: Any, _result: Any, _path: str) -> None:
        raise OSError(raw_secret)

    monkeypatch.setattr(KerasH5Scanner, "_check_hdf5_external_references", raise_os_error)

    _assert_inconclusive_keras_h5_scan(
        model_path,
        "keras_h5_read_failed",
        "Keras H5 File Read",
        "Unable to read Keras H5 content",
    )
    result = KerasH5Scanner().scan(str(model_path))
    read_checks = [check for check in result.checks if check.name == "Keras H5 File Read"]
    assert read_checks
    assert read_checks[0].details["exception"] == "<redacted>"
    assert "<redacted>" in read_checks[0].message
    assert raw_secret not in result.to_json()
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    _assert_inconclusive_keras_h5_scan_not_cached(
        model_path,
        "keras_h5_read_failed",
        tmp_path / "read-failure-cache",
    )


def test_keras_h5_unexpected_scan_failure_returns_inconclusive_exit2_without_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected unavailable H5 analysis is incomplete, not a critical model finding."""
    model_path = create_custom_h5_file(
        tmp_path,
        {"class_name": "Sequential", "config": {"layers": []}},
        file_name="unexpected_scan_failure.h5",
    )

    def fail_config_scan(_self: KerasH5Scanner, _model_config: dict[str, Any], _result: Any) -> None:
        raise RuntimeError("simulated unexpected Keras H5 scan failure")

    monkeypatch.setattr(KerasH5Scanner, "_scan_model_config", fail_config_scan)

    _assert_inconclusive_keras_h5_scan(
        model_path,
        "keras_h5_scan_failed",
        "Keras H5 File Scan",
        "Error scanning Keras H5 file",
    )
    _assert_inconclusive_keras_h5_scan_not_cached(
        model_path,
        "keras_h5_scan_failed",
        tmp_path / "scan-failure-cache",
    )


@pytest.mark.parametrize(
    ("training_config", "reason", "expected_check_name", "expected_message_substring"),
    [
        ("{", "keras_h5_training_config_parse_failed", "Keras H5 Config Parse", "Malformed Keras H5 training_config"),
        (
            "null",
            "keras_h5_training_config_invalid_type",
            "Training Config Type Validation",
            "Invalid training config type",
        ),
        (
            ["not", "a", "dict"],
            "keras_h5_training_config_invalid_type",
            "Training Config Type Validation",
            "Invalid training config type",
        ),
    ],
)
def test_keras_h5_invalid_training_config_returns_inconclusive_exit2(
    tmp_path: Path,
    training_config: Any,
    reason: str,
    expected_check_name: str,
    expected_message_substring: str,
) -> None:
    """Unreadable training_config can hide custom metrics/losses, so it must fail closed."""
    model_path = (
        create_raw_config_h5_file(
            tmp_path,
            model_config_attr=json.dumps(
                {
                    "class_name": "Sequential",
                    "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
                }
            ),
            training_config_attr=training_config,
            file_name="invalid_training_config_json.h5",
        )
        if isinstance(training_config, str)
        else create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {"layers": [{"class_name": "Dense", "config": {"units": 1}}]},
            },
            training_config=training_config,
            file_name="invalid_training_config_type.h5",
        )
    )

    _assert_inconclusive_keras_h5_scan(model_path, reason, expected_check_name, expected_message_substring)


def test_keras_h5_inconclusive_training_config_preserves_security_exit1(tmp_path: Path) -> None:
    """Security findings should still take precedence over an incomplete training_config scan."""
    model_path = create_raw_config_h5_file(
        tmp_path,
        model_config_attr=json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {"function": "lambda x: eval('1')"},
                        }
                    ]
                },
            }
        ),
        training_config_attr="{",
        keras_version="3.11.2",
        file_name="lambda_with_malformed_training_config.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))
    audit_result = core_module.scan_model_directory_or_file(str(model_path))

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_training_config_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert core_module.determine_exit_code(audit_result) == 1


def test_keras_h5_inconclusive_scan_outcome_uncached_rerun_preserves_exit2(tmp_path: Path) -> None:
    """Uncached Keras H5 inconclusive results must still produce exit 2 on subsequent scans."""
    model_path = create_custom_h5_file(
        tmp_path,
        [],
        file_name="cached_bad_model_config.h5",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    first_result = core_module.scan_model_directory_or_file(
        str(model_path),
        cache_enabled=True,
        cache_dir=str(cache_dir),
        min_cache_file_size=0,
    )
    second_result = core_module.scan_model_directory_or_file(
        str(model_path),
        cache_enabled=True,
        cache_dir=str(cache_dir),
        min_cache_file_size=0,
    )
    metadata = second_result.file_metadata[str(model_path)]

    assert core_module.determine_exit_code(first_result) == 2
    assert core_module.determine_exit_code(second_result) == 2
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_model_config_invalid_type" in metadata.get("scan_outcome_reasons")
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_keras_h5_scanner_skips_generic_hdf5_external_links_without_keras_metadata(tmp_path: Path) -> None:
    """Generic non-Keras HDF5 files with external links should not be labeled as Keras CVE risk."""
    generic_path = tmp_path / "generic.h5"
    with h5py.File(generic_path, "w") as f:
        f["linked"] = h5py.ExternalLink("external_source.h5", "/payload")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(generic_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_skips_generic_hdf5_external_link_with_only_keras_version(tmp_path: Path) -> None:
    """A keras_version attribute alone must not classify a generic HDF5 file as Keras weights."""
    generic_path = tmp_path / "generic_with_version.h5"
    with h5py.File(generic_path, "w") as f:
        f.attrs["keras_version"] = "3.13.2"
        f["linked"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert result.metadata["keras_version"] == "3.13.2"
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_skips_generic_hdf5_external_storage_with_only_keras_version(tmp_path: Path) -> None:
    """Artifact-controlled version metadata should not turn generic external storage into a Keras CVE."""
    raw_storage = tmp_path / "generic.raw"
    raw_storage.write_bytes(b"\x00" * 8)

    generic_path = tmp_path / "generic_with_external_storage.h5"
    with h5py.File(generic_path, "w") as f:
        f.attrs["keras_version"] = "3.13.2"
        f.create_dataset(
            "external_values",
            shape=(2,),
            dtype="float32",
            external=[(raw_storage.name, 0, 8)],
        )

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert result.metadata["keras_version"] == "3.13.2"
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_skips_generic_nested_weight_like_groups(tmp_path: Path) -> None:
    """Nested generic groups named vars/weights must not imply a Keras weights file."""
    generic_path = tmp_path / "generic_nested.h5"
    with h5py.File(generic_path, "w") as f:
        experiment_vars = f.create_group("experiment").create_group("vars")
        experiment_vars["linked"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


@pytest.mark.parametrize("root_path", ["vars", "optimizer/vars"])
def test_keras_h5_scanner_skips_generic_root_weight_like_groups(tmp_path: Path, root_path: str) -> None:
    """Generic root vars/weights groups are common outside Keras and should stay quiet."""
    generic_path = tmp_path / "generic_root_vars.h5"
    with h5py.File(generic_path, "w") as f:
        f.require_group(root_path)["0"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_skips_bare_generic_model_weights_group(tmp_path: Path) -> None:
    """A group name alone must not turn a generic HDF5 file into Keras weights."""
    generic_path = tmp_path / "generic_model_weights.h5"
    with h5py.File(generic_path, "w") as f:
        weights = f.create_group("model_weights")
        weights["linked"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_skips_external_links_in_ignored_model_metadata(tmp_path: Path) -> None:
    """Only HDF5 trees consumed by the Keras loader should receive weight CVE attribution."""
    model_path = create_custom_h5_file(
        tmp_path,
        {"class_name": "Sequential", "config": {"name": "metadata_only", "layers": []}},
    )
    with h5py.File(model_path, "a") as f:
        f.create_group("model_weights")
        metadata = f.create_group("metadata")
        metadata["docs"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)


def test_keras_h5_scanner_skips_unreferenced_links_inside_model_weights(tmp_path: Path) -> None:
    """Legacy weight containers may include children that Keras never loads."""
    model_path = create_custom_h5_file(
        tmp_path,
        {"class_name": "Sequential", "config": {"name": "ignored_weight_metadata", "layers": []}},
    )
    with h5py.File(model_path, "a") as f:
        weights = f.create_group("model_weights")
        weights.attrs["layer_names"] = [b"dense"]
        dense = weights.create_group("dense")
        dense.attrs["weight_names"] = [b"kernel:0"]
        dense.create_dataset("kernel:0", data=[1.0])
        dense["docs"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)


def test_keras_h5_scanner_skips_generic_layer_names_attr_without_weight_groups(tmp_path: Path) -> None:
    """Generic HDF5 metadata named layer_names is not enough for Keras attribution."""
    generic_path = tmp_path / "generic_layer_names.h5"
    with h5py.File(generic_path, "w") as f:
        f.attrs["layer_names"] = [b"experiment"]
        f.create_group("experiment")
        f["linked"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_metadata_extract_skips_external_weight_links(tmp_path: Path) -> None:
    """Metadata extraction must not resolve HDF5 ExternalLink entries while counting weights."""
    model_path = tmp_path / "metadata_external_link.h5"
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "metadata_external_link",
            "layers": [{"class_name": "Dense", "name": "dense", "config": {"units": 1}}],
        },
    }
    with h5py.File(model_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        weights = f.create_group("model_weights")
        weights.create_dataset("dense/kernel:0", data=[[1.0, 2.0]])
        weights["external_kernel"] = h5py.ExternalLink("missing_external_source.h5", "/payload")

    metadata = KerasH5Scanner().extract_metadata(str(model_path))

    assert "extraction_error" not in metadata
    assert metadata["total_parameters"] == 2
    assert metadata["weight_layers"] == 1
    assert metadata["parameter_details"] == [{"name": "dense/kernel:0", "shape": [1, 2], "dtype": "float64", "size": 2}]
    assert metadata["external_weight_entries_skipped"] is True


def test_keras_h5_metadata_extract_counts_internal_weights(tmp_path: Path) -> None:
    """Benign internal H5 weights should still be summarized for metadata output."""
    model_path = tmp_path / "metadata_internal_weights.h5"
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "metadata_internal_weights",
            "layers": [{"class_name": "Dense", "name": "dense", "config": {"units": 1}}],
        },
    }
    with h5py.File(model_path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        weights = f.create_group("model_weights")
        weights.create_dataset("dense/kernel:0", data=[[1.0], [2.0]])
        weights.create_dataset("dense/bias:0", data=[0.0])

    metadata = KerasH5Scanner().extract_metadata(str(model_path))

    assert "extraction_error" not in metadata
    assert metadata["total_parameters"] == 3
    assert metadata["weight_layers"] == 2
    assert "external_weight_entries_skipped" not in metadata


def test_keras_h5_metadata_extract_counts_internal_soft_link_weights(tmp_path: Path) -> None:
    """An internal model_weights alias is not an external reference and remains countable."""
    model_path = tmp_path / "metadata_internal_soft_link.h5"
    with h5py.File(model_path, "w") as f:
        f.attrs["model_config"] = json.dumps(
            {
                "class_name": "Sequential",
                "config": {"name": "soft_link_weights", "layers": []},
            }
        )
        weights = f.create_group("real_weights")
        weights.create_dataset("dense/kernel:0", data=[[1.0], [2.0]])
        f["model_weights"] = h5py.SoftLink("/real_weights")

    metadata = KerasH5Scanner().extract_metadata(str(model_path))

    assert metadata["total_parameters"] == 2
    assert metadata["weight_layers"] == 1
    assert metadata["model_weights_internal_link"] is True
    assert "model_weights_external_reference" not in metadata


def test_keras_h5_metadata_extract_does_not_follow_soft_link_to_external_link(tmp_path: Path) -> None:
    """A SoftLink alias must not hide an external model_weights target."""
    external_path = tmp_path / "external_weights.h5"
    with h5py.File(external_path, "w") as external_file:
        external_file.create_dataset("weights", data=[1.0, 2.0, 3.0])

    model_path = tmp_path / "metadata_soft_link_to_external.h5"
    with h5py.File(model_path, "w") as f:
        f.attrs["model_config"] = json.dumps(
            {
                "class_name": "Sequential",
                "config": {"name": "soft_link_external_weights", "layers": []},
            }
        )
        f["outside"] = h5py.ExternalLink(external_path.name, "/weights")
        f["model_weights"] = h5py.SoftLink("/outside")

    metadata = KerasH5Scanner().extract_metadata(str(model_path))

    assert metadata["model_weights_external_reference"] is True
    assert "model_weights_internal_link" not in metadata
    assert "total_parameters" not in metadata


def test_keras_h5_scanner_bounds_legacy_layout_probe_before_external_reference_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Oversized legacy layout probes must route into bounded external-reference analysis."""
    weights_path = tmp_path / "legacy_probe.h5"
    with h5py.File(weights_path, "w") as f:
        f.attrs["layer_names"] = [b"layer_0", b"layer_1", b"layer_2"]
        for index in range(3):
            layer = f.create_group(f"layer_{index}")
            if index == 2:
                layer.attrs["weight_names"] = [b"external_payload"]
                layer["external_payload"] = h5py.ExternalLink("missing_external_source.h5", "/payload")

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_LAYOUT_PROBE_ITEMS", 2)

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layer_2/external_payload",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


@pytest.mark.parametrize("layout", ["legacy", "keras3"])
def test_keras_h5_scanner_layout_probe_limit_without_external_references_stays_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    layout: str,
) -> None:
    """Layout probe exhaustion alone must not become a security finding or incomplete scan."""
    weights_path = tmp_path / ("model.weights.h5" if layout == "keras3" else "legacy_probe.h5")
    with h5py.File(weights_path, "w") as f:
        if layout == "legacy":
            f.attrs["layer_names"] = [b"layer_0", b"layer_1", b"layer_2"]
            group = f
        else:
            group = f.create_group("layers")
        for index in range(3):
            group.create_group(f"layer_{index}")

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_LAYOUT_PROBE_ITEMS", 2)

    result = KerasH5Scanner().scan(str(weights_path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_flags_weights_only_external_link_without_keras_metadata(tmp_path: Path) -> None:
    """Weights-only HDF5 files can still be Keras load inputs and must not skip external references."""
    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0])

    weights_path = tmp_path / "weights_only.h5"
    with h5py.File(weights_path, "w") as f:
        f.attrs["keras_version"] = "3.13.2"
        f.attrs["layer_names"] = [b"dense"]
        dense = f.create_group("dense")
        dense.attrs["weight_names"] = [b"kernel:0"]
        dense["kernel:0"] = h5py.ExternalLink(external_source.name, "/payload")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["keras_version"] == "3.13.2"
    assert cve_issues[0].details["parse_status"] == "untrusted_artifact_version"
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/dense/kernel:0",
            "filename": "external_source.h5",
            "path": "/payload",
        },
    ]


def test_keras_h5_scanner_flags_keras3_weights_external_link_without_legacy_attrs(tmp_path: Path) -> None:
    """Keras 3 .weights.h5 files use layers/*/vars rather than legacy attrs."""
    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0])

    weights_path = tmp_path / "renamed_model.h5"
    with h5py.File(weights_path, "w") as f:
        f.attrs["keras_version"] = "3.13.2"
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        vars_group["0"] = h5py.ExternalLink(external_source.name, "/payload")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["keras_version"] == "3.13.2"
    assert cve_issues[0].details["parse_status"] == "untrusted_artifact_version"
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense/vars/0",
            "filename": "external_source.h5",
            "path": "/payload",
        },
    ]


def test_keras_h5_scanner_bounds_keras3_layout_probe_before_external_reference_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Oversized Keras 3 layout probes must route into bounded external-reference analysis."""
    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        layers = f.create_group("layers")
        for index in range(3):
            layer = layers.create_group(f"layer_{index}")
            if index == 2:
                layer.create_group("vars")["external_payload"] = h5py.ExternalLink(
                    "missing_external_source.h5",
                    "/payload",
                )

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_LAYOUT_PROBE_ITEMS", 2)

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/layer_2/vars/external_payload",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


def test_keras_h5_scanner_flags_keras3_weights_external_link_without_resolving_it(tmp_path: Path) -> None:
    """Keras 3 layout probing should not follow attacker-controlled external links."""
    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        layers = f.create_group("layers")
        layers["dense"] = h5py.ExternalLink("missing_external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


@pytest.mark.parametrize("layout", ["legacy", "keras3"])
def test_keras_h5_scanner_flags_weights_only_soft_linked_external_reference(
    tmp_path: Path,
    layout: str,
) -> None:
    """Weights-only SoftLink aliases must still route into external-reference analysis."""
    weights_path = tmp_path / f"soft_linked_{layout}.weights.h5"
    with h5py.File(weights_path, "w") as f:
        if layout == "legacy":
            f.attrs["layer_names"] = [b"dense_alias"]
            dense = f.create_group("real_dense")
            dense.attrs["weight_names"] = [b"kernel:0"]
            dense["kernel:0"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
            f["dense_alias"] = h5py.SoftLink("/real_dense")
            expected_path = "/dense_alias/kernel:0"
        else:
            real_layers = f.create_group("real_layers")
            vars_group = real_layers.create_group("dense").create_group("vars")
            vars_group["0"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
            f["layers"] = h5py.SoftLink("/real_layers")
            expected_path = "/layers/dense/vars/0"

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": expected_path,
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


@pytest.mark.parametrize("reference_kind", ["ExternalLink", "external_storage", "virtual_dataset"])
def test_keras_h5_scanner_flags_soft_link_group_nested_external_reference(
    tmp_path: Path,
    reference_kind: str,
) -> None:
    """A loader-consumed SoftLink group alias must not hide nested external HDF5 references."""
    weights_path = tmp_path / "soft_link_group.weights.h5"
    with h5py.File(weights_path, "w") as f:
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        resolved_group = f.create_group("resolved_group")
        vars_group["0"] = h5py.SoftLink("/resolved_group")
        expected_reference: dict[str, Any]

        if reference_kind == "ExternalLink":
            resolved_group["payload"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
            expected_reference = {
                "kind": "ExternalLink",
                "hdf5_path": "/layers/dense/vars/0/payload",
                "filename": "missing_external_source.h5",
                "path": "/payload",
            }
        elif reference_kind == "external_storage":
            raw_storage = tmp_path / "weights.raw"
            raw_storage.write_bytes(b"\x00" * 8)
            resolved_group.create_dataset(
                "payload",
                shape=(2,),
                dtype="float32",
                external=[(raw_storage.name, 0, 8)],
            )
            expected_reference = {
                "kind": "external_storage",
                "hdf5_path": "/layers/dense/vars/0/payload",
                "segments": [{"filename": "weights.raw", "offset": 0, "size": 8}],
            }
        else:
            virtual_source = tmp_path / "virtual_source.h5"
            with h5py.File(virtual_source, "w") as source_file:
                source_file.create_dataset("payload", data=[1.0, 2.0])
            layout = h5py.VirtualLayout(shape=(2,), dtype="float64")
            layout[:] = h5py.VirtualSource(virtual_source.name, "/payload", shape=(2,))
            resolved_group.create_virtual_dataset("payload", layout)
            expected_reference = {
                "kind": "virtual_dataset",
                "hdf5_path": "/layers/dense/vars/0/payload",
                "sources": [{"filename": "virtual_source.h5", "path": "/payload"}],
            }

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [expected_reference]


def test_keras_h5_scanner_allows_soft_link_group_with_internal_dataset(tmp_path: Path) -> None:
    """Clean internal SoftLink group aliases should stay non-findings."""
    weights_path = tmp_path / "clean_soft_link_group.weights.h5"
    with h5py.File(weights_path, "w") as f:
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        resolved_group = f.create_group("resolved_group")
        resolved_group.create_dataset("payload", data=[1.0, 2.0])
        vars_group["0"] = h5py.SoftLink("/resolved_group")

    result = KerasH5Scanner().scan(str(weights_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_soft_link_group_traversal_respects_link_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    weights_path = tmp_path / "budgeted_soft_link_group.weights.h5"
    with h5py.File(weights_path, "w") as f:
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        resolved_group = f.create_group("resolved_group")
        resolved_group["payload"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
        vars_group["0"] = h5py.SoftLink("/resolved_group")

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_LINK_VISITS", 1)

    result = KerasH5Scanner().scan(str(weights_path))

    reason = "keras_h5_external_reference_analysis_limit_exceeded"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    limit_checks = [check for check in result.checks if check.details.get("scan_outcome_reason") == reason]
    assert len(limit_checks) == 1
    assert limit_checks[0].details["link_visits_truncated"] is True


def test_keras_h5_scanner_legacy_h5py_traversal_flags_dangling_external_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """h5py before 3.11 must still inspect external links without resolving them."""
    weights_path = tmp_path / "legacy.weights.h5"
    with h5py.File(weights_path, "w") as f:
        layers = f.create_group("layers")
        layers["dense"] = h5py.ExternalLink("missing_external_source.h5", "/payload")

    monkeypatch.delattr(h5py.Group, "visititems_links")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


def test_keras_h5_scanner_external_reference_collection_does_not_resolve_soft_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SoftLink aliases are resolved as links without dereferencing external targets."""
    weights_path = tmp_path / "soft_alias.weights.h5"
    with h5py.File(weights_path, "w") as f:
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        vars_group["external_kernel"] = h5py.ExternalLink("missing_external_source.h5", "/payload")
        vars_group["soft_alias"] = h5py.SoftLink("/layers/dense/vars/external_kernel")

    original_get = h5py.Group.get

    def guarded_get(
        self: Any,
        name: Any,
        default: Any = None,
        getclass: bool = False,
        getlink: bool = False,
    ) -> Any:
        if str(name).endswith("soft_alias") and not getlink:
            raise AssertionError("SoftLink target was followed")
        return original_get(self, name, default=default, getclass=getclass, getlink=getlink)

    monkeypatch.setattr(h5py.Group, "get", guarded_get)

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense/vars/external_kernel",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense/vars/soft_alias",
            "filename": "missing_external_source.h5",
            "path": "/payload",
        },
    ]


@pytest.mark.parametrize("legacy_h5py", [False, True])
def test_keras_h5_scanner_external_reference_traversal_limit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_h5py: bool,
) -> None:
    """External-reference traversal limits must fail closed without caching partial scans."""
    weights_path = tmp_path / "traversal_limit.weights.h5"
    with h5py.File(weights_path, "w") as f:
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        for index in range(3):
            vars_group.create_dataset(str(index), data=[float(index)])

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_LINK_VISITS", 2)
    if legacy_h5py:
        monkeypatch.delattr(h5py.Group, "visititems_links")

    result = KerasH5Scanner().scan(str(weights_path))

    reason = "keras_h5_external_reference_analysis_limit_exceeded"
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in result.metadata["scan_outcome_reasons"]
    limit_checks = [check for check in result.checks if check.name == "HDF5 External Reference Analysis Limit"]
    assert len(limit_checks) == 1
    assert limit_checks[0].status == CheckStatus.FAILED
    assert limit_checks[0].message == "Keras H5 external-reference analysis reached a configured safety limit"
    assert limit_checks[0].details["visited_link_count"] == 2
    assert limit_checks[0].details["link_visits_truncated"] is True

    audit_result = core_module.scan_model_directory_or_file(str(weights_path), cache_enabled=False)
    assert core_module.determine_exit_code(audit_result) == 2
    _assert_inconclusive_keras_h5_scan_not_cached(weights_path, reason, tmp_path / f"cache-{legacy_h5py}")


def test_keras_h5_scanner_external_reference_reports_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reference reporting must stay bounded while preserving the security finding."""
    model_path = create_custom_h5_file(
        tmp_path,
        {"class_name": "Sequential", "config": {"layers": []}},
    )
    with h5py.File(model_path, "a") as f:
        weights = f.require_group("model_weights")
        weights.attrs["weight_names"] = [f"linked_{index}".encode() for index in range(3)]
        for index in range(3):
            weights[f"linked_{index}"] = h5py.ExternalLink("missing_external_source.h5", f"/payload/{index}")

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_EXTERNAL_REFERENCE_REPORTS", 2)

    result = KerasH5Scanner().scan(str(model_path))

    reason = "keras_h5_external_reference_analysis_limit_exceeded"
    assert reason in result.metadata["scan_outcome_reasons"]
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert len(cve_issues[0].details["external_references"]) == 2
    assert cve_issues[0].details["external_reference_count"] == 3
    assert cve_issues[0].details["external_references_truncated"] is True

    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    assert core_module.determine_exit_code(audit_result) == 1


def test_keras_h5_scanner_external_storage_segment_reports_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External-storage diagnostics must not retain every attacker-controlled segment."""
    model_path = create_custom_h5_file(
        tmp_path,
        {"class_name": "Sequential", "config": {"layers": []}},
    )
    with h5py.File(model_path, "a") as f:
        weights = f.require_group("model_weights")
        weights.attrs["weight_names"] = [b"external_kernel"]
        weights.create_dataset(
            "external_kernel",
            shape=(3,),
            dtype="float32",
            external=[(f"weights-{index}.raw", 0, 4) for index in range(3)],
        )

    monkeypatch.setattr(KerasH5Scanner, "_MAX_HDF5_EXTERNAL_STORAGE_SEGMENT_REPORTS", 2)

    def fail_if_materialized(_dataset: Any) -> None:
        raise AssertionError("Dataset.external materialized every external-storage segment")

    monkeypatch.setattr(h5py.Dataset, "external", property(fail_if_materialized))

    result = KerasH5Scanner().scan(str(model_path))

    reason = "keras_h5_external_reference_analysis_limit_exceeded"
    assert reason in result.metadata["scan_outcome_reasons"]
    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    external_reference = cve_issues[0].details["external_references"][0]
    assert len(external_reference["segments"]) == 2
    assert external_reference["segment_count"] == 3
    assert external_reference["segments_truncated"] is True


def test_keras_h5_scanner_malicious_model(tmp_path):
    """Test scanning a malicious Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path, malicious=True)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    # The scanner should detect suspicious patterns
    assert any(issue.severity in (IssueSeverity.INFO, IssueSeverity.WARNING) for issue in result.issues)
    assert any(
        "eval" in issue.message.lower() or "system" in issue.message.lower() or "suspicious" in issue.message.lower()
        for issue in result.issues
    )


def test_keras_h5_scanner_invalid_h5(tmp_path: Path) -> None:
    """Corrupt H5 input should fail closed without becoming a security finding."""
    # Create an invalid H5 file (without magic bytes)
    invalid_path = tmp_path / "invalid.h5"
    invalid_path.write_bytes(b"This is not a valid HDF5 file")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(invalid_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_read_failed" in result.metadata["scan_outcome_reasons"]
    assert any("Unable to read Keras H5 content" in issue.message for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def test_keras_h5_scanner_with_blacklist(tmp_path):
    """Test Keras H5 scanner with custom blacklist patterns."""
    # Create a proper H5 file with malicious content
    h5_path = tmp_path / "model.h5"

    with h5py.File(h5_path, "w") as f:
        # Create model config with suspicious content
        model_config = {
            "class_name": "Sequential",
            "config": {
                "name": "sequential",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            # This matches our blacklist
                            "function": "suspicious_function(x)",
                        },
                    },
                ],
            },
        }

        # Add model_config attribute
        f.attrs["model_config"] = json.dumps(model_config)

        # Add some dummy data
        f.create_dataset("layer_names", data=[b"lambda_1"])

    # Create scanner with custom blacklist
    scanner = KerasH5Scanner(config={"blacklist_patterns": ["suspicious_function"]})
    result = scanner.scan(str(h5_path))

    # Should detect Lambda layer
    lambda_issues = [issue for issue in result.issues if "lambda" in issue.message.lower()]
    assert len(lambda_issues) > 0, f"Expected Lambda issues but got: {[i.message for i in result.issues]}"

    # Check that our Lambda validation code ran
    # The new code should detect either dangerous code or suspicious configuration
    relevant_issues = [
        issue
        for issue in result.issues
        if any(phrase in issue.message.lower() for phrase in ["lambda", "executable", "suspicious"])
    ]
    assert len(relevant_issues) > 0


def test_lambda_safe_normalization_pattern_still_passes(tmp_path: Path) -> None:
    """Safe normalization lambdas should continue matching the safe-pattern allowlist."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "safe_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": "lambda x: x / 255"},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )
    assert not any("dangerous Python code" in issue.message for issue in result.issues)


@pytest.mark.parametrize(
    "function_str",
    [
        "lambda x: x * 2",
        "lambda x: x * +2",
        "lambda x: x / 255.0",
        "lambda x: x / -255.0",
        "lambda x: tf.nn.softmax(x)",
        "lambda x: K.softmax(x)",
        "lambda x: (x - 128) / 128",
        "lambda inputs: inputs / 255.0",
        "lambda tensor: tf.nn.relu(tensor)",
        "lambda value: K.softmax(value)",
    ],
)
def test_lambda_additional_safe_normalization_patterns_still_pass(tmp_path: Path, function_str: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "safe_lambda_model_extra",
                "layers": [{"class_name": "Lambda", "config": {"function": function_str}}],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )
    assert not any("dangerous Python code" in issue.message for issue in result.issues)


def test_lambda_whitespace_padded_safe_source_still_passes(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "whitespace_padded_safe_lambda",
                "layers": [{"class_name": "Lambda", "config": {"function": "  lambda x: x / 255  "}}],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_lambda_safe_prefix_with_injected_code_is_flagged(tmp_path: Path) -> None:
    """Semicolon-appended payloads must not bypass Lambda code safety checks."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unsafe_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": 'lambda x: x / 255; __import__("os").system("evil")'},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    # The injected payload must be flagged as dangerous, not allowlisted
    assert any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Expected failed Lambda check but got: {[(c.name, c.status) for c in result.checks]}"
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "function_str",
    [
        'lambda x: x * 2; exec("bad")',
        'lambda x: K.softmax(x); __import__("os").system("evil")',
        'lambda x: (x - 128) / 128; exec("bad")',
    ],
)
def test_lambda_additional_safe_prefixes_with_injected_code_are_flagged(
    tmp_path: Path,
    function_str: str,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unsafe_lambda_model_extra",
                "layers": [{"class_name": "Lambda", "config": {"function": function_str}}],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Expected failed Lambda check but got: {[(c.name, c.status) for c in result.checks]}"
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


def test_lambda_tf_safe_prefix_with_exec_is_not_allowlisted(tmp_path: Path) -> None:
    """Safe tf.nn prefix should not match when arbitrary executable code is appended."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unsafe_tf_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": 'lambda x: tf.nn.softmax(x); exec("bad")'},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    # The injected payload must be flagged as dangerous, not allowlisted
    assert any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    ), f"Expected failed Lambda check but got: {[(c.name, c.status) for c in result.checks]}"
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "function_str",
    [
        "lambda x: K.get_value(x)",
        "lambda x: tf.nn.embedding_lookup(x)",
    ],
)
def test_lambda_framework_helpers_outside_source_allowlist_fail_closed(
    tmp_path: Path,
    function_str: str,
) -> None:
    """Trusted framework roots are not enough for a Lambda source pass."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unsafe_framework_helper_model",
                "layers": [{"class_name": "Lambda", "config": {"function": function_str}}],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis" and check.details.get("allowlist_status") == "not_allowlisted"
    ]
    assert len(matching_checks) == 1
    assert matching_checks[0].status == CheckStatus.FAILED
    assert matching_checks[0].severity == IssueSeverity.WARNING
    assert matching_checks[0].details["validation_status"] == "valid_python"
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


def test_lambda_safe_prefix_with_comment_token_in_malicious_payload_is_flagged(tmp_path: Path) -> None:
    """A single comment token in malicious payload must not suppress detection."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unsafe_comment_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": 'lambda x: x / 255; __import__("os").system("evil") # noop'},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


def test_lambda_dynamic_builtins_dispatch_is_not_marked_safe(tmp_path: Path) -> None:
    """Computed execution names should not receive a passed Lambda code-analysis check."""
    dynamic_exec_lambda = (
        "lambda x: (lambda b: (b if isinstance(b, dict) else vars(b))"
        "[bytes((101,120,101,99)).decode()]"
        "(bytes((112,114,105,110,116,40,49,41)).decode()))"
        "(globals()[bytes((95,95,98,117,105,108,116,105,110,115,95,95)).decode()])"
    )
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dynamic_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": dynamic_exec_lambda},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis" and check.details.get("allowlist_status") == "not_allowlisted"
    ]
    assert matching_checks
    assert matching_checks[0].status == CheckStatus.FAILED
    assert matching_checks[0].severity == IssueSeverity.WARNING
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and "safe Python code" in check.message
        for check in result.checks
    )


def test_lambda_malformed_source_fails_closed_without_echoing_source(tmp_path: Path) -> None:
    malformed_source = "lambda x: x +"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "malformed_source_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"name": "malformed_source", "function": malformed_source},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("validation_status") == "invalid_python"
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].severity == IssueSeverity.WARNING
    assert malformed_source not in str(malformed_checks[0].details)


def test_lambda_empty_source_fails_closed(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "empty_source_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"name": "empty_source", "function": ""},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("validation_status") == "invalid_python"
        for check in result.checks
    )


@pytest.mark.parametrize("malformed_source", ["lambda x: x / \u0661", "lambda\nx: x / 255"])
def test_lambda_malformed_safe_pattern_lookalike_fails_closed(tmp_path: Path, malformed_source: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "malformed_safe_pattern_model",
                "layers": [{"class_name": "Lambda", "config": {"function": malformed_source}}],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("validation_status") == "invalid_python"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "unsafe_source",
    ["lambda x: x / 0", "lambda x: x / -0.0", "lambda x: (x - 128) / 0", "lambda x: (x - 128) / +0"],
)
def test_lambda_zero_divisor_is_not_allowlisted(tmp_path: Path, unsafe_source: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "zero_divisor_model",
                "layers": [{"class_name": "Lambda", "config": {"function": unsafe_source}}],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("allowlist_status") == "not_allowlisted"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )


def test_lambda_deep_unary_number_fails_closed_without_aborting_scan(tmp_path: Path) -> None:
    deeply_nested_source = f"lambda x: x / {'+' * 1_000}255"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "deep_unary_lambda",
                "layers": [
                    {"class_name": "Lambda", "config": {"function": deeply_nested_source}},
                    {
                        "class_name": "Lambda",
                        "config": {"function": 'lambda x: __import__("os").system("id")'},
                    },
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and (
            check.details.get("allowlist_status") == "not_allowlisted"
            or check.details.get("validation_status") == "invalid_python"
        )
        for check in result.checks
    )
    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert not any(check.name == "Scan Completion" and check.status == CheckStatus.FAILED for check in result.checks)


@pytest.mark.parametrize("function_value", [7, True])
def test_lambda_non_code_function_metadata_fails_closed_without_echoing_value(
    tmp_path: Path,
    function_value: Any,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "malformed_function_metadata_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"name": "malformed_function_metadata", "function": function_value},
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("function_type") == type(function_value).__name__
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].severity == IssueSeverity.WARNING
    assert function_value not in malformed_checks[0].details.values()


def test_lambda_dict_bytecode_without_dangerous_patterns_stays_warning(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "safe_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "safe_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    bytecode_issues = [
        issue for issue in result.issues if "embedded bytecode" in issue.message and "lambda_1" in issue.message
    ]
    assert len(bytecode_issues) == 1
    assert bytecode_issues[0].severity == IssueSeverity.WARNING
    assert not [
        issue for issue in result.issues if "lambda_1" in issue.message and issue.severity == IssueSeverity.CRITICAL
    ]
    assert not any(
        check.name == "Lambda Layer Code Analysis" and check.message == "Lambda layer uses malformed function metadata"
        for check in result.checks
    )


def test_lambda_dict_bytecode_with_dangerous_pattern_still_critical(tmp_path: Path) -> None:
    code = compile("import os\nos.system('id')\neval('__import__(\"os\")')", "<lambda>", "exec")
    encoded_code = base64.b64encode(marshal.dumps(code)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dangerous_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dangerous_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    dangerous_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1"
    ]
    assert len(dangerous_checks) == 1
    assert {"eval", "__import__", "os.system"}.issubset(set(dangerous_checks[0].details["dangerous_patterns"]))


def test_lambda_code_details_omit_sensitive_previews_in_json_and_sarif(tmp_path: Path) -> None:
    direct_secret = "H5_DIRECT_SECRET"
    dict_secret = "H5_DICT_SECRET"
    list_secret = "H5_LIST_SECRET"
    invalid_secret = "H5_INVALID_SECRET"
    pycompile_secret = "H5_PYCOMPILE_SECRET"
    lambda_config_key_secret = "UNLABELED_LAMBDA_CONFIG_KEY_VALUE_7F3A9"
    top_level_layer_name_secret = "UNLABELED_TOP_LEVEL_LAYER_VALUE_7F3A9"
    layer_name_secret = "UNLABELED_CONFIG_LAYER_VALUE_7F3A9"
    dangerous_module_secret = "UNLABELED_DANGEROUS_MODULE_VALUE_7F3A9"
    dangerous_function_secret = "UNLABELED_DANGEROUS_FUNCTION_VALUE_7F3A9"
    safe_module_secret = "UNLABELED_SAFE_MODULE_VALUE_7F3A9"
    safe_function_secret = "UNLABELED_SAFE_FUNCTION_VALUE_7F3A9"
    variadic_identifier_secret = "H5_VARIADIC_IDENTIFIER_SECRET"
    variadic_identifier = f"aws_secret_access_key_{variadic_identifier_secret}"

    dict_code = compile(
        f"client_secret = '{dict_secret}'\nimport os\nos.system('id')",
        "<lambda>",
        "exec",
    )
    list_code = compile(
        f"client_secret = '{list_secret}'\nimport os\nos.system('id')",
        "<lambda>",
        "exec",
    )
    encoded_dict_code = base64.b64encode(marshal.dumps(dict_code)).decode()
    encoded_list_code = base64.b64encode(marshal.dumps(list_code)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "redacted_lambda_model",
                "layers": [
                    {
                        "class_name": "keras.layers.Lambda",
                        "name": top_level_layer_name_secret,
                        "config": {
                            "name": layer_name_secret,
                            lambda_config_key_secret: {"payload": "eval"},
                            "function": (
                                f"lambda *{variadic_identifier}: "
                                f"(eval('1'), '{direct_secret}', {variadic_identifier})[-1]"
                            ),
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_dict_code}},
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "list_lambda",
                            "function": [encoded_list_code, None, None],
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "invalid_lambda",
                            "function": f"lambda x: (exec(, aws_secret_access_key='{invalid_secret}')",
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "pycompile_invalid_lambda",
                            "function": f"return '{pycompile_secret}'  # exec",
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dangerous_module_lambda",
                            "module": f"os.{dangerous_module_secret}",
                            "function_name": dangerous_function_secret,
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "safe_module_lambda",
                            "module": f"math.{safe_module_secret}",
                            "function_name": safe_function_secret,
                        },
                    },
                ],
            },
        },
    )

    scanner_result = KerasH5Scanner().scan(str(model_path))
    scanner_json = json.dumps(scanner_result.to_dict(), default=str)
    assert scanner_result.metadata["layer_counts"]["Lambda"] == 7
    assert all("code_preview" not in check.details for check in scanner_result.checks)
    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.details.get("code_analysis_omitted") == "lambda_code_analysis_may_contain_sensitive_identifiers"
        and "code_analysis" not in check.details
        and check.details.get("code_preview_omitted") == "lambda_code_may_contain_sensitive_literals"
        for check in scanner_result.checks
    )
    omitted_bytecode_formats = {
        check.details.get("function_format")
        for check in scanner_result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.details.get("code_preview_omitted") == "opaque_bytecode_may_contain_sensitive_constants"
    }
    assert omitted_bytecode_formats == {"dict_bytecode", "list_bytecode"}
    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.details.get("validation_status") == "invalid_python"
        and check.details.get("validation_error_omitted") == "lambda_code_may_contain_sensitive_literals"
        and "validation_error" not in check.details
        for check in scanner_result.checks
    )
    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        and "module" not in check.details
        and "function" not in check.details
        for check in scanner_result.checks
    )
    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("allowlist_status") == "not_allowlisted"
        and "module" not in check.details
        and "function" not in check.details
        for check in scanner_result.checks
    )

    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    json_output = audit_result.model_dump_json(indent=2, exclude_none=True)
    sarif_output = format_sarif_output(audit_result, [str(model_path)])

    for secret in (
        direct_secret,
        dict_secret,
        list_secret,
        invalid_secret,
        pycompile_secret,
        lambda_config_key_secret,
        top_level_layer_name_secret,
        layer_name_secret,
        dangerous_module_secret,
        dangerous_function_secret,
        safe_module_secret,
        safe_function_secret,
        variadic_identifier_secret,
    ):
        assert secret not in scanner_json
        assert secret not in json_output
        assert secret not in sarif_output


def test_lambda_invalid_source_ignores_keyword_substrings_in_other_metadata(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "invalid_lambda_near_match_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "evaluation_layer",
                            "description": "retrieval quality",
                            "function": "not valid python!",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(check.name == "Lambda Layer Suspicious Keywords Check" for check in result.checks)
    assert not any(check.name == "Suspicious Configuration String Check" for check in result.checks)


def test_lambda_invalid_source_does_not_casefold_builtin_names(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "invalid_lambda_uppercase_builtin_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "uppercase_builtin_lambda",
                            "function": "lambda x: EVAL(x",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(check.name == "Lambda Layer Suspicious Keywords Check" for check in result.checks)
    assert not any(check.name == "Suspicious Configuration String Check" for check in result.checks)


def test_lambda_nested_metadata_omits_artifact_controlled_keys_and_fake_wrapped_layers(tmp_path: Path) -> None:
    nested_key_secret = "NESTED_LAMBDA_KEY_SECRET_7F3A9"
    nested_class_secret = "NESTED_LAMBDA_CLASS_SECRET_7F3A9"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "nested_lambda_metadata_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": "lambda x: x",
                            "metadata": {nested_key_secret: {"payload": "eval"}},
                            "layer": {
                                "class_name": nested_class_secret,
                                "config": {"units": 1},
                            },
                        },
                    }
                ],
            },
        },
    )

    scanner_result = KerasH5Scanner().scan(str(model_path))
    suspicious_checks = [
        check
        for check in scanner_result.checks
        if check.name == "Suspicious Configuration String Check" and check.details.get("suspicious_term") == "eval"
    ]
    assert len(suspicious_checks) == 1
    assert suspicious_checks[0].details.get("context") == "Lambda"
    assert not any(check.name == "Custom Layer Class Detection" for check in scanner_result.checks)

    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    json_output = audit_result.model_dump_json(indent=2, exclude_none=True)
    sarif_output = format_sarif_output(audit_result, [str(model_path)])

    for secret in (nested_key_secret, nested_class_secret):
        assert secret not in json_output
        assert secret not in sarif_output


def test_lambda_nested_metadata_ignores_suspicious_term_near_matches(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "nested_lambda_near_match_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": "lambda x: x",
                            "metadata": {"arbitrary": {"payload": "evaluation"}},
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(
        check.name == "Suspicious Configuration String Check" and check.details.get("suspicious_term") == "eval"
        for check in result.checks
    )


def test_lambda_scalar_function_metadata_fails_closed_without_echoing_value(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "scalar_lambda_function_model",
                "layers": [{"class_name": "Lambda", "config": {"function": 7}}],
            },
        },
        keras_version="3.11.3",
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("function_type") == "int"
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].severity == IssueSeverity.WARNING
    assert (
        malformed_checks[0].details.get("function_payload_omitted")
        == "malformed_lambda_function_may_contain_sensitive_payload"
    )
    assert "function" not in malformed_checks[0].details
    assert result.success is True

    audit_result = core_module.scan_model_directory_or_file(str(model_path), cache_enabled=False)
    assert core_module.determine_exit_code(audit_result) == 1


def test_lambda_null_function_placeholder_is_not_treated_as_malformed(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "null_lambda_function_model",
                "layers": [{"class_name": "Lambda", "config": {"function": None}}],
            },
        },
        keras_version="3.11.3",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.details.get("function_payload_omitted") == "malformed_lambda_function_may_contain_sensitive_payload"
        for check in result.checks
    )


def test_lambda_dict_bytecode_with_benign_module_fields_still_critical(tmp_path: Path) -> None:
    """Dict-format Lambda bytecode must not be skipped by benign module/function metadata."""
    code = compile("import os\nos.system('id')\neval('__import__(\"os\")')", "<lambda>", "exec")
    encoded_code = base64.b64encode(marshal.dumps(code)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "mixed_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                            "module": "keras.ops",
                            "function_name": "identity",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    dangerous_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1"
    ]
    assert len(dangerous_checks) == 1
    assert {"eval", "__import__", "os.system"}.issubset(set(dangerous_checks[0].details["dangerous_patterns"]))
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_lambda_dict_bytecode_with_benign_module_fields_stays_warning(tmp_path: Path) -> None:
    """Opaque dict-format Lambda bytecode should not become a passed module reference check."""
    encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_safe_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "mixed_safe_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                            "module": "keras.ops",
                            "function_name": "identity",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    bytecode_issues = [
        issue for issue in result.issues if "embedded bytecode" in issue.message and "lambda_1" in issue.message
    ]
    assert len(bytecode_issues) == 1
    assert bytecode_issues[0].severity == IssueSeverity.WARNING
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_lambda_dict_malformed_config_does_not_echo_payload(tmp_path: Path) -> None:
    """Malformed dict-format metadata should report its type without retaining attacker content."""
    payload = "attacker-controlled-secret-payload"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "malformed_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "malformed_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": payload},
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("parse_status") == "invalid_config"
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].details["config_type"] == "str"
    assert payload not in str(malformed_checks[0].details)


def test_lambda_list_bytecode_with_dangerous_pattern_is_critical(tmp_path: Path) -> None:
    """Legacy list-format Lambda bytecode in H5 must be decoded and inspected."""
    code = compile("import os\nos.system('id')\neval('__import__(\"os\")')", "<lambda>", "exec")
    encoded_code = base64.b64encode(marshal.dumps(code)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "list_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dangerous_list_lambda",
                            "function": [encoded_code, None, None],
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    dangerous_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1"
    ]
    assert len(dangerous_checks) == 1
    assert dangerous_checks[0].details["function_format"] == "list_bytecode"
    assert {"eval", "__import__", "os.system"}.issubset(set(dangerous_checks[0].details["dangerous_patterns"]))


def test_lambda_list_bytecode_with_benign_module_fields_stays_warning(tmp_path: Path) -> None:
    """Opaque list-format Lambda bytecode should not become a passed module reference check."""
    encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_safe_list_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "mixed_safe_list_lambda",
                            "function": [encoded_code, None, None],
                            "module": "keras.ops",
                            "function_name": "identity",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    bytecode_issues = [
        issue for issue in result.issues if "embedded bytecode" in issue.message and "lambda_1" in issue.message
    ]
    assert len(bytecode_issues) == 1
    assert bytecode_issues[0].severity == IssueSeverity.WARNING
    assert bytecode_issues[0].details["function_format"] == "list_bytecode"
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Code Analysis" and check.message == "Lambda layer uses malformed function metadata"
        for check in result.checks
    )


@pytest.mark.parametrize("function_data", [[], [None, None, None]])
def test_lambda_list_missing_encoded_code_stays_warning(tmp_path: Path, function_data: list[Any]) -> None:
    """Malformed list-format Lambda metadata must remain a security finding."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "malformed_list_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "malformed_list_lambda",
                            "function": function_data,
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("function_format") == "list"
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].severity == IssueSeverity.WARNING


def test_unrecognized_lambda_function_dict_still_uses_module_reference_check(tmp_path: Path) -> None:
    """Only recognized __lambda__ dictionaries should preempt module/function reference analysis."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unrecognized_dict_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "unrecognized_dict_module",
                            "function": {"class_name": "SomeCallable", "config": {}},
                            "module": "os",
                            "function_name": "system",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


def test_lambda_function_dict_function_key_uses_module_reference_check(tmp_path: Path) -> None:
    """Callable dict metadata using a function key must not bypass H5 Lambda module checks."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "function_key_dict_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "function_key_dict_module",
                            "function": {
                                "class_name": "function",
                                "module": "posix",
                                "function": "relu",
                            },
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("reference_source") == "function_dict"
        for check in result.checks
    )


def test_lambda_function_dict_safe_function_key_is_allowlisted(tmp_path: Path) -> None:
    """Benign callable dict metadata should still pass the narrow Lambda allowlist."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "safe_function_key_dict_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "safe_function_key_dict_module",
                            "function": {
                                "class_name": "function",
                                "module": "keras.activations",
                                "function": "relu",
                            },
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("reference_source") == "function_dict"
        and check.details.get("allowlist_status") == "allowlisted"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_lambda_encoded_dict_with_embedded_function_metadata_checks_both_paths(tmp_path: Path) -> None:
    """Dict bytecode analysis must not hide dangerous callable metadata embedded beside code."""
    encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "encoded_dict_embedded_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "encoded_dict_embedded_module",
                            "function": {
                                "class_name": "__lambda__",
                                "config": {"code": encoded_code},
                                "module": "posix",
                                "function": "system",
                            },
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("function_format") == "dict_bytecode"
        for check in result.checks
    )
    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("reference_source") == "function_dict"
        for check in result.checks
    )


def test_lambda_encoded_dict_with_safe_embedded_function_metadata_is_not_critical(tmp_path: Path) -> None:
    """Safe embedded callable metadata should not turn opaque Lambda bytecode into a critical finding."""
    encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "encoded_dict_safe_embedded_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "encoded_dict_safe_embedded_module",
                            "function": {
                                "class_name": "__lambda__",
                                "config": {"code": encoded_code},
                                "module": "keras.activations",
                                "function": "relu",
                            },
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details.get("function_format") == "dict_bytecode"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_unrecognized_lambda_function_dict_without_module_fails_closed(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "unrecognized_dict_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "unrecognized_dict",
                            "function": {"class_name": "SomeCallable", "config": {"secret": "do-not-retain"}},
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("function_format") == "dict"
        and check.details.get("parse_status") == "unrecognized"
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].severity == IssueSeverity.WARNING
    assert "do-not-retain" not in str(malformed_checks[0].details)


@pytest.mark.parametrize(
    ("module_name", "function_name"),
    [(["os"], None), (None, {"name": "system"})],
)
def test_lambda_malformed_module_reference_is_not_marked_safe(
    tmp_path: Path,
    module_name: Any,
    function_name: Any,
) -> None:
    """Malformed mixed module/function metadata must not become a passed safety check."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "malformed_module_reference_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "malformed_module_reference",
                            "function": {"class_name": "SomeCallable", "config": {}},
                            "module": module_name,
                            "function_name": function_name,
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    malformed_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("module_type") == type(module_name).__name__
        and check.details.get("function_type") == type(function_name).__name__
    ]
    assert len(malformed_checks) == 1
    assert malformed_checks[0].severity == IssueSeverity.WARNING
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_lambda_dict_bytecode_with_dangerous_module_fields_still_checks_module_reference(tmp_path: Path) -> None:
    """Opaque dict bytecode must not suppress a dangerous sibling module/function reference."""
    encoded_code = base64.b64encode(marshal.dumps((lambda x: x + 1).__code__)).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_dangerous_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "mixed_dangerous_module",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                            "module": "os",
                            "function_name": "system",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        issue.severity == IssueSeverity.WARNING and "embedded bytecode" in issue.message and "lambda_1" in issue.message
        for issue in result.issues
    )
    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


def test_lambda_safe_string_with_dangerous_module_fields_still_checks_module_reference(tmp_path: Path) -> None:
    """Safe-looking inline Lambda code must not suppress a dangerous sibling module reference."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_safe_string_module_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "mixed_safe_string_module",
                            "function": "lambda x: x / 255",
                            "module": "os",
                            "function_name": "system",
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )
    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


def test_lambda_dict_bytecode_does_not_match_dangerous_substrings_inside_identifiers(tmp_path: Path) -> None:
    """Benign identifiers such as `opened` must not become critical `open` bytecode findings."""
    encoded_code = base64.b64encode(b"def benign():\n    opened = 1\n    return opened\n").decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "benign_identifier_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "benign_identifier_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                        },
                    }
                ],
            },
        },
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details.get("analysis_status") == "opaque_bytecode"
        for check in result.checks
    )


def test_lambda_dict_oversized_code_is_not_decoded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Oversized encoded Lambda bytecode must fail closed before allocating a decoded copy."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "oversized_dict_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "oversized_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": "A" * 9}},
                        },
                    }
                ],
            },
        },
    )

    def fail_decode(_encoded: str) -> bytes:
        raise AssertionError("oversized Lambda bytecode must not be decoded")

    monkeypatch.setattr(keras_utils, "_MAX_LAMBDA_CODE_B64_CHARS", 8)
    monkeypatch.setattr(keras_utils.base64, "b64decode", fail_decode)

    result = KerasH5Scanner().scan(str(model_path))

    oversized_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("analysis_status") == "code_size_limit_exceeded"
    ]
    assert len(oversized_checks) == 1
    assert oversized_checks[0].severity == IssueSeverity.WARNING
    assert oversized_checks[0].details["encoded_code_chars"] == 9
    assert oversized_checks[0].details["max_encoded_code_chars"] == 8


def test_lambda_list_oversized_code_is_not_decoded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Oversized list-format Lambda bytecode must fail closed before allocating a decoded copy."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "oversized_list_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "oversized_list_lambda",
                            "function": ["A" * 9, None, None],
                        },
                    }
                ],
            },
        },
    )

    def fail_decode(_encoded: str) -> bytes:
        raise AssertionError("oversized Lambda bytecode must not be decoded")

    monkeypatch.setattr(keras_utils, "_MAX_LAMBDA_CODE_B64_CHARS", 8)
    monkeypatch.setattr(keras_utils.base64, "b64decode", fail_decode)

    result = KerasH5Scanner().scan(str(model_path))

    oversized_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("analysis_status") == "code_size_limit_exceeded"
    ]
    assert len(oversized_checks) == 1
    assert oversized_checks[0].severity == IssueSeverity.WARNING
    assert oversized_checks[0].details["function_format"] == "list"
    assert oversized_checks[0].details["encoded_code_chars"] == 9
    assert oversized_checks[0].details["max_encoded_code_chars"] == 8


def test_keras_h5_scanner_empty_file(tmp_path):
    """Test scanning an empty file."""
    empty_path = tmp_path / "empty.h5"
    empty_path.write_bytes(b"")  # Create empty file

    scanner = KerasH5Scanner()
    result = scanner.scan(str(empty_path))

    # Should have an error - empty files can't be valid H5
    # May be WARNING, INFO, or other severity depending on error type
    assert len(result.issues) > 0 or not result.success, "Empty file should produce issues or fail"

    # Check for any error-like messages
    issue_messages = " ".join(issue.message.lower() for issue in result.issues)
    has_error_indication = (
        "signature" in issue_messages
        or "invalid" in issue_messages
        or "error" in issue_messages
        or "hdf5" in issue_messages
        or "corrupt" in issue_messages
        or "unable" in issue_messages
        or not result.success
    )
    assert has_error_indication, f"Expected error indication but got: {[i.message for i in result.issues]}"


def test_tensorflow_h5_file_detection(tmp_path):
    """Test that TensorFlow H5 files are properly detected and not flagged as warnings."""
    # Create a TensorFlow-style H5 file (without Keras model_config)
    tf_h5_path = tmp_path / "tf_model.h5"

    with h5py.File(tf_h5_path, "w") as f:
        # Create TensorFlow-style structure without model_config
        # Add typical TensorFlow H5 groups
        model_weights = f.create_group("model_weights")

        # Add some weight data typical of TensorFlow SavedModel converted to H5
        layer_group = model_weights.create_group("dense_layer")
        layer_group.create_dataset("kernel:0", data=[[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])
        layer_group.create_dataset("bias:0", data=[0.1, 0.2, 0.3])

        # Add optimizer weights (typical of TensorFlow)
        optimizer_weights = f.create_group("optimizer_weights")
        optimizer_weights.create_dataset("iteration:0", data=[100])

        # Add variables group
        variables = f.create_group("variables")
        variables.create_dataset("global_step:0", data=[1000])

    scanner = KerasH5Scanner()
    result = scanner.scan(str(tf_h5_path))

    assert result.success is True

    # Should have a DEBUG message about TensorFlow H5, not WARNING
    tensorflow_issues = [issue for issue in result.issues if "tensorflow h5 model" in issue.message.lower()]

    if tensorflow_issues:
        # Should be DEBUG level, not WARNING
        assert all(issue.severity == IssueSeverity.DEBUG for issue in tensorflow_issues)
        assert any("tensorflow h5 model" in issue.message.lower() for issue in tensorflow_issues)

    # Should NOT have any WARNING or CRITICAL issues
    high_severity_issues = [
        issue for issue in result.issues if issue.severity in (IssueSeverity.INFO, IssueSeverity.CRITICAL)
    ]
    assert len(high_severity_issues) == 0, "TensorFlow H5 files should not generate warnings"


def test_non_keras_h5_file_debug_only(tmp_path):
    """Test that non-Keras H5 files generate DEBUG messages only."""
    # Create an H5 file that's neither Keras nor TensorFlow
    generic_h5_path = tmp_path / "generic_data.h5"

    with h5py.File(generic_h5_path, "w") as f:
        # Create generic data structure (not ML-related)
        f.create_dataset("experimental_data", data=[1, 2, 3, 4, 5])
        f.create_dataset("metadata", data=b"some metadata")

        # Create a group with generic data
        data_group = f.create_group("results")
        data_group.create_dataset("measurements", data=[[1.1, 2.2], [3.3, 4.4]])

    scanner = KerasH5Scanner()
    result = scanner.scan(str(generic_h5_path))

    assert result.success is True

    # Should have a DEBUG message about not being a Keras model
    keras_issues = [issue for issue in result.issues if "does not appear to be a keras model" in issue.message.lower()]

    if keras_issues:
        # Should be DEBUG level, not WARNING
        assert all(issue.severity == IssueSeverity.DEBUG for issue in keras_issues)

    # Should NOT have any WARNING or CRITICAL issues
    high_severity_issues = [
        issue for issue in result.issues if issue.severity in (IssueSeverity.INFO, IssueSeverity.CRITICAL)
    ]
    assert len(high_severity_issues) == 0, "Generic H5 files should not generate warnings"


def test_actual_keras_model_still_scans_properly(tmp_path):
    """Test that actual Keras models are still scanned properly."""
    # Create a proper Keras model file
    keras_path = create_mock_h5_file(tmp_path, malicious=False)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(keras_path))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Should not have issues about missing model_config since this is a proper Keras file
    missing_config_issues = [
        issue for issue in result.issues if "does not appear to be a keras model" in issue.message.lower()
    ]
    assert len(missing_config_issues) == 0, "Proper Keras models should not have missing config issues"

    # Should have proper metadata
    assert result.metadata.get("model_class") is not None
    assert "layer_counts" in result.metadata


def test_malicious_keras_model_still_detected(tmp_path: Path) -> None:
    """Test that malicious Keras models are still properly detected."""
    # Create a malicious Keras model file
    malicious_path = create_mock_h5_file(tmp_path, malicious=True)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(malicious_path))

    assert result.success is False

    # Should detect the malicious patterns
    malicious_issues = [
        issue
        for issue in result.issues
        if issue.severity in (IssueSeverity.CRITICAL, IssueSeverity.INFO)
        and any(keyword in issue.message.lower() for keyword in ["suspicious", "lambda", "eval", "malicious"])
    ]
    assert len(malicious_issues) > 0, "Malicious Keras models should still be detected"


def test_lambda_module_reference_uses_token_boundaries_for_benign_modules(tmp_path: Path) -> None:
    """Benign module names containing suspicious substrings should stay warning-level."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "benign_module_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "custom_package.systematic_math",
                            "function_name": "normalize",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="benign_systematic_module.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.FAILED
    ]
    assert len(matching_checks) == 1
    assert matching_checks[0].severity == IssueSeverity.WARNING
    assert matching_checks[0].details["allowlist_status"] == "not_allowlisted"
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert not any(
        check.name == "Suspicious Configuration String Check" and check.details.get("suspicious_term") == "system"
        for check in result.checks
    )


def test_lambda_nested_config_suspicious_terms_remain_case_insensitive(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "uppercase_nested_lambda_config",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": "lambda x: x",
                            "metadata": {"callback": "OS.SYSTEM", "runner": "SubProcess"},
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="uppercase_nested_lambda_config.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    suspicious_terms = {
        check.details.get("suspicious_term")
        for check in result.checks
        if check.name == "Suspicious Configuration String Check" and check.status == CheckStatus.FAILED
    }
    assert {"system", "subprocess"}.issubset(suspicious_terms)
    assert all(
        check.details.get("context") == "Lambda"
        for check in result.checks
        if check.name == "Suspicious Configuration String Check" and check.status == CheckStatus.FAILED
    )


def test_lambda_allowlisted_framework_module_reference_still_passes(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "allowlisted_module_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "keras.ops",
                            "function_name": "normalize",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="allowlisted_module_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("allowlist_status") == "allowlisted"
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("module_name", "function_name"),
    [
        ("keras.activations", "relu"),
        ("keras.backend", "softmax"),
        ("tensorflow.keras.activations", "relu"),
        ("tensorflow.keras.backend", "softmax"),
        ("tensorflow.python.keras.activations", "relu"),
        ("tensorflow.python.keras.backend", "softmax"),
        ("tf.keras.activations", "relu"),
        ("tf.keras.backend", "softmax"),
        ("tf_keras.activations", "relu"),
    ],
)
def test_lambda_legacy_named_framework_function_still_passes(
    tmp_path: Path,
    module_name: str,
    function_name: str,
) -> None:
    """Canonical legacy H5 named-callable metadata should use the reference allowlist."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "legacy_named_function_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": function_name,
                            "function_type": "function",
                            "module": module_name,
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name=f"legacy_named_function_reference_{module_name.replace('.', '_')}.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("allowlist_status") == "allowlisted"
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("allowlist_status") == "not_allowlisted"
        for check in result.checks
    )


def test_lambda_legacy_function_type_with_source_uses_source_allowlist(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "legacy_source_function",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": "lambda x: x / 255",
                            "function_type": "function",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="legacy_source_function.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.PASSED
        and check.details.get("pattern_type") == "safe_normalization"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.details.get("function") == "lambda x: x / 255"
        for check in result.checks
    )


@pytest.mark.parametrize("callback_field", ["output_shape", "mask"])
def test_lambda_serialized_auxiliary_callback_is_scanned(tmp_path: Path, callback_field: str) -> None:
    code = compile("import os\nos.system('id')", "<lambda>", "exec")
    encoded_code = base64.b64encode(marshal.dumps(code)).decode()
    layer_config: dict[str, Any] = {
        "name": "auxiliary_callback",
        "function": "relu",
        "function_type": "function",
        "module": "keras.activations",
        callback_field: [encoded_code, None, None],
        f"{callback_field}_type": "lambda",
        f"{callback_field}_module": "__main__",
    }
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "auxiliary_callback_model",
                "layers": [{"class_name": "Lambda", "config": layer_config}],
            },
        },
        keras_version="3.11.3",
        file_name=f"malicious_{callback_field}.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == f"lambda_1.{callback_field}"
        for check in result.checks
    )


def test_lambda_dict_output_shape_is_scanned_without_legacy_type_marker(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b"import os\nos.system('id')").decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dict_output_shape_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dict_output_shape",
                            "function": "relu",
                            "function_type": "function",
                            "module": "keras.activations",
                            "output_shape": {
                                "class_name": "__lambda__",
                                "config": {"code": encoded_code},
                            },
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="dict_output_shape.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1.output_shape"
        for check in result.checks
    )


def test_lambda_dict_mask_without_legacy_type_marker_is_scanned(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b"import os\nos.system('id')").decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dict_mask_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dict_mask",
                            "function": "relu",
                            "function_type": "function",
                            "module": "keras.activations",
                            "mask": {
                                "class_name": "__lambda__",
                                "config": {"code": encoded_code},
                            },
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="dict_mask.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1.mask"
        for check in result.checks
    )


def test_trusted_keras_submodule_lambda_path_scans_dict_bytecode(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b"import os\nos.system('id')").decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "qualified_lambda_model",
                "layers": [
                    {
                        "class_name": "tensorflow.keras.layers.core.Lambda",
                        "config": {
                            "name": "qualified_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="qualified_lambda.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1"
        for check in result.checks
    )


def test_lambda_raw_output_shape_is_not_treated_as_executable_callback(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "raw_output_shape_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "raw_output_shape",
                            "function": "relu",
                            "function_type": "function",
                            "module": "keras.activations",
                            "output_shape": [None, 32],
                            "output_shape_type": "raw",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="raw_output_shape.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )
    assert not any(
        check.details.get("callback_field") == "output_shape"
        or check.details.get("layer_name") == "lambda_1.output_shape"
        for check in result.checks
    )


@pytest.mark.parametrize("function_value", ["", "   "])
def test_lambda_empty_legacy_named_function_fails_closed(tmp_path: Path, function_value: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "empty_legacy_named_function",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": function_value,
                            "function_type": "function",
                            "module": "keras.activations",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="empty_legacy_named_function.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.details.get("validation_status") == "invalid_python"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_lambda_named_reference_metadata_does_not_suppress_source_analysis(tmp_path: Path) -> None:
    """A separate function name must not reinterpret attacker-controlled source as a named reference."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "conflicting_named_function_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": 'lambda x: __import__("os").system("id")',
                            "function_type": "function",
                            "module": "keras.activations",
                            "function_name": "relu",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="conflicting_named_function_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("module_name", "function_name", "expected_severity"),
    [
        ("os", "system", IssueSeverity.CRITICAL),
        ("io", "open", IssueSeverity.CRITICAL),
        ("io", "open_safe", IssueSeverity.WARNING),
        ("platform", "system", IssueSeverity.WARNING),
        ("custom_package.transforms", "normalize", IssueSeverity.WARNING),
    ],
)
def test_lambda_legacy_named_function_reference_fails_closed(
    tmp_path: Path,
    module_name: str,
    function_name: str,
    expected_severity: IssueSeverity,
) -> None:
    """Legacy named callables outside the narrow allowlist must remain findings."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "legacy_named_function_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": function_name,
                            "function_type": "function",
                            "module": module_name,
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="legacy_named_function_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.FAILED
    ]
    assert len(matching_checks) == 1
    assert matching_checks[0].severity == expected_severity
    assert matching_checks[0].details["module_omitted"] == "artifact_controlled_lambda_reference"
    assert matching_checks[0].details["function_omitted"] == "artifact_controlled_lambda_reference"
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("function_name", "expected_severity"),
    [("subprocess.Popen", IssueSeverity.CRITICAL), ("subprocess.PopenSafe", IssueSeverity.WARNING)],
)
def test_lambda_moduleless_legacy_function_reference_is_case_insensitive(
    tmp_path: Path,
    function_name: str,
    expected_severity: IssueSeverity,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "moduleless_legacy_function_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"function": function_name, "function_type": "function"},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="moduleless_legacy_function_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.FAILED
    ]
    assert len(matching_checks) == 1
    assert matching_checks[0].severity == expected_severity


@pytest.mark.parametrize(
    ("module_name", "function_name"),
    [
        ("keras.attacker", "identity"),
        ("math", "softmax"),
        ("Keras.ops", "normalize"),
        ("keras.activations", "ReLU"),
        ("keras.activations", " relu "),
        (" keras.activations", "relu"),
        ("keras.activations ", "relu"),
        ("tensorflow.python.keras.activations.attacker", "relu"),
    ],
)
def test_lambda_trusted_looking_module_reference_is_not_allowlisted(
    tmp_path: Path,
    module_name: str,
    function_name: str,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "trusted_looking_module_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"module": module_name, "function_name": function_name},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="trusted_looking_module_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.WARNING
        and check.details.get("allowlist_status") == "not_allowlisted"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


@pytest.mark.parametrize(
    "module_name",
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
def test_lambda_exact_native_module_reference_is_critical(tmp_path: Path, module_name: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "native_module_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"module": module_name, "function_name": "native_callable"},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name=f"native_module_reference_{module_name}.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


@pytest.mark.parametrize("module_name", ["posix.path", "_imp.child", "_io_helper", "POSIX", "_IO", "operator"])
def test_lambda_native_module_near_match_is_not_critical(tmp_path: Path, module_name: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "native_module_near_match",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"module": module_name, "function_name": "add"},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name=f"native_module_near_match_{module_name.replace('.', '_')}.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [check for check in result.checks if check.name == "Lambda Layer Module Reference Check"]
    assert len(matching_checks) == 1
    assert matching_checks[0].status == CheckStatus.FAILED
    assert matching_checks[0].severity == IssueSeverity.WARNING


def test_lambda_allowlisted_framework_root_does_not_hide_code_loader(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "allowlisted_code_loader",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "tensorflow",
                            "function_name": "load_op_library",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="allowlisted_code_loader.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_lambda_trusted_framework_unknown_callback_stays_warning(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "trusted_unknown_callback",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "tensorflow.io",
                            "function_name": "write_file",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="trusted_unknown_callback.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.FAILED
    ]
    assert len(matching_checks) == 1
    assert matching_checks[0].severity == IssueSeverity.WARNING
    assert matching_checks[0].details["allowlist_status"] == "not_allowlisted"
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("function_name", "expected_severity"),
    [("compat.v1.py_func", IssueSeverity.CRITICAL), ("io.system", IssueSeverity.WARNING)],
)
def test_lambda_dotted_function_reference_uses_callback_semantics(
    tmp_path: Path,
    function_name: str,
    expected_severity: IssueSeverity,
) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dotted_dangerous_function_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "tensorflow",
                            "function_name": function_name,
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name=f"dotted_dangerous_{function_name.replace('.', '_')}.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == expected_severity
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


def test_lambda_dotted_function_reference_uses_token_boundaries(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dotted_benign_function_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "tensorflow",
                            "function_name": "io.systematic_helper",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="dotted_benign_function_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.FAILED
    ]
    assert len(matching_checks) == 1
    assert matching_checks[0].severity == IssueSeverity.WARNING
    assert matching_checks[0].details["allowlist_status"] == "not_allowlisted"


def test_lambda_allowlisted_framework_root_does_not_hide_python_callback_helper(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "allowlisted_dangerous_callback",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "module": "tensorflow",
                            "function_name": "py_function",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="allowlisted_dangerous_callback.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )
    assert not any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("function") == "py_function"
        for check in result.checks
    )


@pytest.mark.parametrize("function_name", ["raw_ops.PyFunc", "raw_ops.PyFuncStateless", "raw_ops.EagerPyFunc"])
def test_lambda_tensorflow_raw_python_callback_alias_is_critical(tmp_path: Path, function_name: str) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "raw_python_callback",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"module": "tensorflow", "function_name": function_name},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name=f"raw_python_callback_{function_name.lower()}.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("module_omitted") == "artifact_controlled_lambda_reference"
        and check.details.get("function_omitted") == "artifact_controlled_lambda_reference"
        for check in result.checks
    )


def test_lambda_tensorflow_raw_python_callback_near_match_is_not_critical(tmp_path: Path) -> None:
    function_name = "raw_ops.PyFunctional"
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "raw_python_callback_near_match",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"module": "tensorflow", "function_name": function_name},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="raw_python_callback_near_match.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    matching_checks = [check for check in result.checks if check.name == "Lambda Layer Module Reference Check"]
    assert len(matching_checks) == 1
    assert matching_checks[0].status == CheckStatus.FAILED
    assert matching_checks[0].severity == IssueSeverity.WARNING


def test_lambda_safe_source_does_not_suppress_dangerous_module_reference(tmp_path: Path) -> None:
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_source_module_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "function": "lambda x: x / 255",
                            "module": "os",
                            "function_name": "system",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="mixed_source_module_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_lambda_allowlisted_module_does_not_suppress_dict_bytecode_analysis(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b"import os\nos.system('id')").decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "mixed_dict_module_reference",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "mixed_dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                            "module": "keras.layers",
                            "function_name": "normalize",
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="mixed_dict_module_reference.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "lambda_1"
        for check in result.checks
    )


def test_suspicious_config_string_check_detects_dunder_import_call(tmp_path: Path) -> None:
    """Dunder-wrapped `__import__` calls must still match the `import` token check."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "dunder_import_model",
                "layers": [
                    {
                        "class_name": "Dense",
                        "config": {"name": "dense", "initializer": "__import__('os')"},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="dunder_import_model.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert any(
        check.name == "Suspicious Configuration String Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("suspicious_term") == "import"
        for check in result.checks
    ), f"Expected '__import__' to match the import token check. Checks: {result.checks}"


def test_suspicious_config_string_check_ignores_import_substring_in_identifiers(tmp_path: Path) -> None:
    """Benign identifiers containing `import` as a substring should not be flagged."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "imported_model_name",
                "layers": [
                    {
                        "class_name": "Dense",
                        "config": {"name": "imported_initializer", "units": 1},
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="imported_identifier_model.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert not any(
        check.name == "Suspicious Configuration String Check" and check.details.get("suspicious_term") == "import"
        for check in result.checks
    ), f"Expected benign import-containing identifiers to stay quiet. Checks: {result.checks}"


def test_wrapped_layer_config_layer_is_scanned_for_custom_inner_layers(tmp_path: Path) -> None:
    """Wrapper layers with `config.layer` must not hide nested custom classes."""
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "wrapped_custom_layer",
                "layers": [
                    {
                        "class_name": "TimeDistributed",
                        "config": {
                            "name": "wrapper",
                            "layer": {
                                "class_name": "MaliciousLayer",
                                "config": {"name": "inner_bad"},
                            },
                        },
                    }
                ],
            },
        },
        keras_version="3.11.3",
        file_name="wrapped_custom_layer.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert result.success is True
    assert any(
        check.name == "Custom Layer Class Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("layer_class") == "MaliciousLayer"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "keras_version",
    [
        "3.12.1rc1",
        "3.12.1-rc.1",
        "3.12.1_rc_1",
        "3.12.1-preview.1",
        "3.12.1.dev.1",
        "3.13.2rc1",
        "3.13.2rc.",
        "3.13.2_c1",
    ],
)
def test_keras_h5_scanner_treats_cve_2026_1669_fix_prereleases_as_vulnerable(
    tmp_path: Path,
    keras_version: str,
) -> None:
    """Prerelease builds at the CVE-2026-1669 fix boundary should still be flagged."""
    model_path = create_h5_with_external_link(tmp_path, keras_version=keras_version)

    result = KerasH5Scanner().scan(str(model_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["keras_version"] == keras_version


def test_regression_no_false_positives_for_legitimate_files(tmp_path):
    """Regression test to ensure legitimate ML H5 files don't generate false positives."""
    # Test multiple legitimate file types
    test_files = []

    # 1. TensorFlow SavedModel converted to H5
    tf_path = tmp_path / "tf_model.h5"
    with h5py.File(tf_path, "w") as f:
        weights = f.create_group("model_weights")
        layer = weights.create_group("dense_1")
        layer.create_dataset("kernel:0", data=[[0.1, 0.2], [0.3, 0.4]])
        optimizer = f.create_group("optimizer_weights")
        optimizer.create_dataset("iteration:0", data=[42])
    test_files.append(("TensorFlow H5", tf_path))

    # 2. Generic scientific data H5
    science_path = tmp_path / "experiment.h5"
    with h5py.File(science_path, "w") as f:
        f.create_dataset("temperature_data", data=[20.1, 21.5, 22.0])
        f.create_dataset("pressure_data", data=[1013.25, 1012.8, 1014.1])
    test_files.append(("Scientific data H5", science_path))

    # 3. PyTorch model weights saved in H5 format
    pytorch_path = tmp_path / "pytorch_weights.h5"
    with h5py.File(pytorch_path, "w") as f:
        f.create_dataset("layer1.weight", data=[[0.5, -0.3], [0.7, 0.1]])
        f.create_dataset("layer1.bias", data=[0.01, -0.02])
    test_files.append(("PyTorch weights H5", pytorch_path))

    scanner = KerasH5Scanner()

    for file_type, file_path in test_files:
        result = scanner.scan(str(file_path))

        assert result.success is True, f"{file_type} should scan successfully"

        # Should have NO WARNING or CRITICAL issues
        high_severity_issues = [
            issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        ]
        assert len(high_severity_issues) == 0, f"{file_type} should not generate warnings/errors"

        # DEBUG messages are OK for non-Keras files


def test_keras_h5_scanner_detects_subclassed_model(tmp_path):
    """Test that scanner detects subclassed models with custom class names."""
    from modelaudit.scanners.base import CheckStatus

    h5_path = tmp_path / "model.h5"

    with h5py.File(h5_path, "w") as f:
        # Create a model with a custom (subclassed) class name
        model_config = {
            "class_name": "MyCustomModel",  # Subclassed model
            "config": {
                "name": "my_custom_model",
                "layers": [
                    {
                        "class_name": "Dense",
                        "config": {"units": 10, "activation": "relu"},
                    },
                ],
            },
        }
        f.attrs["model_config"] = json.dumps(model_config)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(h5_path))

    # Should detect subclassed model at INFO severity
    subclass_checks = [c for c in result.checks if "subclassed" in c.name.lower()]
    assert len(subclass_checks) > 0
    assert subclass_checks[0].status != CheckStatus.PASSED
    assert subclass_checks[0].severity == IssueSeverity.INFO


def test_keras_h5_scanner_allows_known_safe_classes(tmp_path):
    """Test that scanner passes for known safe model classes."""
    from modelaudit.scanners.base import CheckStatus

    for model_class in ["Sequential", "Functional", "Model"]:
        h5_path = tmp_path / f"model_{model_class}.h5"

        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": model_class,
                "config": {
                    "name": "test_model",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "config": {"units": 10, "activation": "relu"},
                        },
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)
            f.attrs["keras_version"] = "3.11.2"

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        # Should not flag known safe classes
        subclass_issues = [i for i in result.issues if "subclassed" in i.message.lower()]
        assert len(subclass_issues) == 0, f"{model_class} should not be flagged as subclassed"

        # Check should pass
        subclass_checks = [c for c in result.checks if "subclassed" in c.name.lower()]
        assert len(subclass_checks) > 0
        assert all(c.status == CheckStatus.PASSED for c in subclass_checks)


def test_keras_h5_sample_attack_assets_trigger_expected_checks() -> None:
    """Repo Keras attack samples should be covered by scanner assertions."""
    scanner = KerasH5Scanner()
    expected_checks = {
        "custom_layer_attack.h5": "Custom Layer Class Detection",
        "loss_injection.h5": "Custom Loss Detection",
        "metric_injection.h5": "Custom Metric Detection",
    }

    for file_name, check_name in expected_checks.items():
        result = scanner.scan(str(ASSETS_DIR / file_name))
        matching_checks = [check for check in result.checks if check.name == check_name]

        assert len(matching_checks) >= 1, f"Expected {check_name} in sample {file_name}"
        assert any(check.status == CheckStatus.FAILED for check in matching_checks)


def test_training_config_detects_nested_custom_metrics_and_loss_mappings(tmp_path: Path) -> None:
    """Nested training_config metric/loss trees should not bypass custom-object detection."""
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "nested_training_config",
            "layers": [
                {"class_name": "InputLayer", "config": {"batch_shape": [None, 4], "name": "input"}},
                {"class_name": "Dense", "config": {"units": 4}},
            ],
        },
    }
    training_config = {
        "loss": {"output_1": "malicious_loss"},
        "metrics": [["accuracy", {"class_name": "MaliciousMetric", "config": {"name": "malicious_metric"}}]],
        "weighted_metrics": {"output_1": ["Precision", "WeightedBackdoorMetric"]},
    }
    model_path = create_custom_h5_file(tmp_path, model_config, training_config=training_config)

    result = KerasH5Scanner().scan(str(model_path))

    custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
    custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

    assert any(check.details.get("identifier") == "MaliciousMetric" for check in custom_metric_checks)
    assert any(check.details.get("identifier") == "WeightedBackdoorMetric" for check in custom_metric_checks)
    assert any(check.details.get("identifier") == "malicious_loss" for check in custom_loss_checks)


def test_training_config_safe_aliases_do_not_trigger_custom_object_checks(tmp_path: Path) -> None:
    """Standard Keras aliases should not be treated as custom metrics or losses."""
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "safe_aliases",
            "layers": [
                {"class_name": "InputLayer", "config": {"batch_shape": [None, 4], "name": "input"}},
                {"class_name": "Dense", "config": {"units": 4}},
            ],
        },
    }
    training_config = {
        "loss": {"output_1": "mae", "output_2": "mse"},
        "metrics": [["accuracy", "AUC"], [{"class_name": "MeanSquaredError", "config": {}}]],
        "weighted_metrics": {"output_1": ["Precision", "Recall"]},
    }
    model_path = create_custom_h5_file(
        tmp_path,
        model_config,
        training_config=training_config,
        file_name="safe_aliases.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    assert all(check.name != "Custom Metric Detection" for check in result.checks)
    assert all(check.name != "Custom Loss Detection" for check in result.checks)


def test_training_config_deduplicates_custom_object_identifiers_by_normalized_name(tmp_path: Path) -> None:
    """Repeated custom metric/loss aliases with case or spacing drift should only emit once."""
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "dedupe_training_config",
            "layers": [{"class_name": "Dense", "config": {"units": 4}}],
        },
    }
    training_config = {
        "loss": {"output_1": ["malicious_loss", " MALICIOUS_LOSS "]},
        "metrics": [
            "MaliciousMetric",
            " maliciousmetric ",
            {"class_name": "MALICIOUSMETRIC", "config": {}},
        ],
    }
    model_path = create_custom_h5_file(
        tmp_path,
        model_config,
        training_config=training_config,
        file_name="dedupe_custom_objects.h5",
    )

    result = KerasH5Scanner().scan(str(model_path))

    custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
    custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

    assert [check.details.get("identifier") for check in custom_metric_checks] == ["MaliciousMetric"]
    assert [check.details.get("identifier") for check in custom_loss_checks] == ["malicious_loss"]


def test_builtin_random_preprocessing_layers_do_not_trigger_custom_layer_warning(tmp_path: Path) -> None:
    """Built-in preprocessing layers should not be mislabeled as custom layers."""
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "preprocessing_model",
            "layers": [
                {"class_name": "InputLayer", "config": {"batch_shape": [None, 32, 32, 3], "name": "input"}},
                {"class_name": "RandomShear", "config": {"factor": 0.1}},
                {"class_name": "RandomColorJitter", "config": {"value_range": [0, 255], "brightness_factor": 0.1}},
            ],
        },
    }
    model_path = create_custom_h5_file(tmp_path, model_config, file_name="preprocessing.h5")

    result = KerasH5Scanner().scan(str(model_path))

    assert all(check.name != "Custom Layer Class Detection" for check in result.checks)


def test_nested_functional_submodels_are_scanned_for_custom_layers(tmp_path: Path) -> None:
    """Nested Functional/Sequential models should not hide custom layer classes."""
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "outer",
            "layers": [
                {"class_name": "InputLayer", "config": {"batch_shape": [None, 4], "name": "input"}},
                {
                    "class_name": "Functional",
                    "name": "nested_functional",
                    "config": {
                        "layers": [
                            {"class_name": "InputLayer", "config": {"batch_shape": [None, 4], "name": "nested_input"}},
                            {"class_name": "MaliciousLayer", "config": {"name": "nested_malicious"}},
                        ]
                    },
                },
            ],
        },
    }
    model_path = create_custom_h5_file(tmp_path, model_config, file_name="nested_custom_layer.h5")

    result = KerasH5Scanner().scan(str(model_path))
    custom_layer_checks = [check for check in result.checks if check.name == "Custom Layer Class Detection"]

    assert any(check.details.get("layer_class") == "MaliciousLayer" for check in custom_layer_checks)


def test_generic_base_layer_class_still_triggers_custom_layer_warning(tmp_path: Path) -> None:
    """The abstract Keras base Layer export should still require custom-layer review in H5 models."""
    model_config = {
        "class_name": "Sequential",
        "config": {
            "name": "generic_layer_model",
            "layers": [
                {"class_name": "InputLayer", "config": {"batch_shape": [None, 4], "name": "input"}},
                {"class_name": "Layer", "config": {"name": "generic_layer"}},
            ],
        },
    }
    model_path = create_custom_h5_file(tmp_path, model_config, file_name="generic_layer.h5")

    result = KerasH5Scanner().scan(str(model_path))

    assert any(check.name == "Custom Layer Class Detection" for check in result.checks)


class TestCVE20251550H5ModuleReferences:
    """H5 coverage for Keras safe_mode bypass module references outside Lambda-only checks."""

    def test_dangerous_dense_layer_module_is_cve_attributed(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_dense_dangerous_module",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "module": "os",
                            "config": {"name": "dense_evil", "units": 1},
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["cvss"] == 7.3
        assert cve_issues[0].details["cwe"] == "CWE-94"

    @pytest.mark.parametrize(
        ("module_name", "function_name"),
        [
            ("tensorflow", "load_op_library"),
            ("tensorflow", "load_file_system_library"),
            ("numpy.ctypeslib", "load_library"),
        ],
    )
    def test_dangerous_callable_under_trusted_root_is_critical(
        self,
        tmp_path: Path,
        module_name: str,
        function_name: str,
    ) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_trusted_root_dangerous_callable",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "module": "keras.layers",
                            "config": {
                                "name": "dense_dangerous_activation",
                                "units": 1,
                                "activation": {
                                    "class_name": "function",
                                    "module": module_name,
                                    "config": function_name,
                                    "registered_name": function_name,
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["layer_name"] == "dense_dangerous_activation"

    def test_dangerous_lambda_layer_module_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_dangerous_module",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "os",
                            "config": {"name": "lambda_evil", "function": "relu"},
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["layer_name"] == "lambda_1"
        assert cve_issues[0].details["module"] == "os"

    def test_safe_keras_lambda_layer_module_is_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_safe_module",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {"name": "lambda_safe", "function": "relu"},
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        assert not any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)

    def test_dangerous_lambda_config_fn_module_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_dangerous_fn_module",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_evil_fn_module",
                                "function": "relu",
                                "fn_module": "subprocess",
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["key"] == "fn_module"
        assert cve_issues[0].details["module"] == "subprocess"

    def test_dangerous_lambda_config_fn_module_symbol_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_dangerous_fn_symbol",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_dangerous_fn_symbol",
                                "function": "Popen",
                                "function_type": "function",
                                "fn_module": "subprocess",
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["key"] == "fn_module"

    def test_dangerous_functional_layer_module_root_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Functional",
                "config": {
                    "name": "h5_subprocess_call",
                    "layers": [
                        {
                            "class_name": "call",
                            "module": "subprocess",
                            "config": {"args": ["echo", "unsafe"]},
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "subprocess"

    def test_conflicting_trusted_callable_metadata_requires_review(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_conflicting_trusted_callable",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "module": "keras.layers",
                            "config": {
                                "name": "dense_conflicting_activation",
                                "units": 1,
                                "activation": {
                                    "class_name": "function",
                                    "module": "keras.activations",
                                    "config": "unknown_callable",
                                    "registered_name": "relu",
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING

    def test_safe_keras_lambda_config_fn_module_is_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_safe_fn_module",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_safe_fn_module",
                                "function": "relu",
                                "fn_module": "keras.activations",
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        assert not any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)

    def test_dangerous_lambda_inbound_callable_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Functional",
                "config": {
                    "name": "h5_lambda_inbound_callable",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {"name": "lambda_inbound", "function": "relu"},
                            "inbound_nodes": [
                                {
                                    "args": [
                                        {
                                            "class_name": "function",
                                            "module": "posix",
                                            "config": "system",
                                            "registered_name": "system",
                                        }
                                    ],
                                    "kwargs": {},
                                }
                            ],
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["layer_name"] == "lambda_1"
        assert cve_issues[0].details["module"] == "posix"

    def test_dangerous_lambda_nested_callable_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_nested_callable",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_nested",
                                "function": "relu",
                                "activation": {
                                    "class_name": "function",
                                    "module": "posix",
                                    "config": "system",
                                    "registered_name": "system",
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["layer_name"] == "lambda_1"
        assert cve_issues[0].details["module"] == "posix"

    def test_lambda_function_dict_is_owned_by_lambda_analyzer(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_function_dict",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_function_dict",
                                "function": {
                                    "class_name": "function",
                                    "module": "posix",
                                    "function": "system",
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        module_checks = [check for check in result.checks if check.name == "Lambda Layer Module Reference Check"]
        assert len(module_checks) == 1
        assert module_checks[0].severity == IssueSeverity.CRITICAL
        assert module_checks[0].details["reference_source"] == "function_dict"
        assert not any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)

    def test_lambda_function_dict_checks_authoritative_config_and_registered_name(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_conflicting_lambda_callable",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {
                                "name": "lambda_conflict",
                                "function": {
                                    "class_name": "function",
                                    "module": "tensorflow",
                                    "config": "load_op_library",
                                    "registered_name": "identity",
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        module_checks = [check for check in result.checks if check.name == "Lambda Layer Module Reference Check"]
        assert any(check.severity == IssueSeverity.CRITICAL for check in module_checks)
        assert not any(check.status == CheckStatus.PASSED for check in module_checks)

    def test_lambda_function_wrapper_still_scans_nested_callable(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_function_wrapper",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_function_wrapper",
                                "function": {
                                    "class_name": "Wrapper",
                                    "config": {
                                        "activation": {
                                            "class_name": "function",
                                            "module": "posix",
                                            "config": "system",
                                            "registered_name": "system",
                                        }
                                    },
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"

    def test_untyped_lambda_auxiliary_callable_still_uses_generic_module_analysis(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_lambda_untyped_output_shape",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "module": "keras.layers",
                            "config": {
                                "name": "lambda_untyped_output_shape",
                                "function": "relu",
                                "function_type": "function",
                                "module": "keras.activations",
                                "output_shape": {
                                    "class_name": "function",
                                    "module": "posix",
                                    "config": "system",
                                    "registered_name": "system",
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["module"] == "posix"

    def test_nested_module_walk_fails_closed_at_node_limit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(KerasH5Scanner, "_MAX_SERIALIZED_CONFIG_NODES", 5)
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_bounded_nested_config",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "module": "keras.layers",
                            "config": {
                                "activation": {
                                    "class_name": "function",
                                    "module": "posix",
                                    "config": "system",
                                    "registered_name": "system",
                                },
                                "padding": list(range(20)),
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        assert any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)
        assert result.metadata["analysis_incomplete"] is True
        assert "keras_h5_serialized_config_node_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert sum(check.name == "Serialized Config Traversal Limit" for check in result.checks) == 1

    def test_nested_module_after_node_limit_is_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(KerasH5Scanner, "_MAX_SERIALIZED_CONFIG_NODES", 5)
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_late_nested_callable",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "module": "keras.layers",
                            "config": {
                                "noise_0": 0,
                                "noise_1": 1,
                                "noise_2": 2,
                                "noise_3": 3,
                                "noise_4": 4,
                                "noise_5": 5,
                                "activation": {
                                    "class_name": "function",
                                    "module": "posix",
                                    "config": "system",
                                    "registered_name": "system",
                                },
                            },
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        assert not any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        audit_result = core_module.scan_model_directory_or_file(str(model_path), scanner_config={})
        assert core_module.determine_exit_code(audit_result) == 2

    def test_nested_non_lambda_serialized_function_is_critical(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_nested_activation_module",
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
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-1550"]
        assert cve_issues
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["layer_name"] == "dense_with_native_activation"
        assert cve_issues[0].details["module"] == "posix"

    def test_safe_keras_layer_module_is_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_safe_module",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "dense_safe",
                            "module": "keras.layers",
                            "config": {"units": 1},
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        assert not any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)

    def test_non_callable_unknown_dense_module_is_not_flagged(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "h5_unknown_dense_module",
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "dense_custom_module",
                            "module": "custom_project.layers",
                            "config": {"units": 1},
                        }
                    ],
                },
            },
        )

        result = KerasH5Scanner().scan(str(model_path))

        assert not any(issue.details.get("cve_id") == "CVE-2025-1550" for issue in result.issues)


class TestCVE20259905H5SafeMode:
    """Test CVE-2025-9905: Keras H5 safe_mode ignored for Lambda layers."""

    def test_lambda_layer_triggers_cve_2025_9905(self, tmp_path: Path) -> None:
        """Lambda layer in H5 file should flag CVE-2025-9905."""
        h5_path = tmp_path / "model.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {"function": "lambda x: x * 2"},
                        }
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)
            f.attrs["keras_version"] = "3.11.2"

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        cve_issues = [i for i in result.issues if "CVE-2025-9905" in i.message]
        assert len(cve_issues) >= 1, "Lambda in H5 should trigger CVE-2025-9905"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_redacted_local_version_still_triggers_cve_2025_9905(self, tmp_path: Path) -> None:
        """Display redaction must not downgrade a valid vulnerable local version."""
        raw_secret = "sk-proj-CAND061H5VERSIONSECRET000000000000"
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {"function": "lambda x: x"},
                        }
                    ]
                },
            },
            keras_version=f"3.10.0+{raw_secret}",
            file_name="redacted_local_version.h5",
        )

        result = KerasH5Scanner().scan(str(model_path))
        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9905"]

        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["keras_version"] == "3.10.0+<redacted>"
        assert raw_secret not in result.to_json()

    @pytest.mark.parametrize(
        "layer_class",
        [
            "keras.layers.Lambda",
            "keras.src.layers.core.lambda_layer.Lambda",
            "tensorflow.keras.layers.Lambda",
            "tensorflow.python.keras.layers.core.Lambda",
            "tf.keras.layers.Lambda",
            "tf_keras.src.layers.core.lambda_layer.Lambda",
        ],
    )
    def test_fully_qualified_lambda_layer_triggers_cve_2025_9905(self, tmp_path: Path, layer_class: str) -> None:
        """Serialized fully-qualified Lambda class names should not bypass H5 Lambda checks."""
        h5_path = tmp_path / "qualified_lambda.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {
                            "class_name": layer_class,
                            "config": {"function": "lambda x: x * 2"},
                        }
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)
            f.attrs["keras_version"] = "3.11.2"

        result = KerasH5Scanner().scan(str(h5_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9905"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["layer_class"] == "Lambda"
        assert cve_issues[0].details["keras_version"] == "3.11.2"

    @pytest.mark.parametrize(
        "layer_class",
        [
            "myproject.layers.Lambda",
            "keras.attacker.Lambda",
            "keras.layers.attacker.Lambda",
            "tensorflow.keras.layers_evil.Lambda",
        ],
    )
    def test_custom_namespace_lambda_layer_not_attributed_to_keras_cve(
        self,
        tmp_path: Path,
        layer_class: str,
    ) -> None:
        """Custom classes ending in Lambda should stay in the custom-layer review path."""
        h5_path = tmp_path / f"custom_{layer_class.replace('.', '_')}.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {
                            "class_name": layer_class,
                            "config": {"function": "lambda x: x * 2"},
                        }
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)
            f.attrs["keras_version"] = "3.11.2"

        result = KerasH5Scanner().scan(str(h5_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9905"]
        custom_layer_checks = [
            check
            for check in result.checks
            if check.name == "Custom Layer Class Detection" and check.details.get("layer_class") == layer_class
        ]
        assert cve_issues == []
        assert len(custom_layer_checks) == 1

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE details should be present in issue details."""
        h5_path = tmp_path / "model.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {"function": "lambda x: x"},
                        }
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        cve_issues = [i for i in result.issues if "CVE-2025-9905" in i.message]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-9905"
        assert details["cvss"] == 7.3
        assert details["cwe"] == "CWE-693"
        assert details["description"]
        assert details["layer_name"] == "lambda_1"
        assert "3.11.3" in details["remediation"]

    def test_no_cve_without_lambda(self, tmp_path: Path) -> None:
        """H5 model without Lambda should NOT trigger CVE-2025-9905."""
        h5_path = tmp_path / "model.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {"class_name": "Dense", "config": {"units": 10}},
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        cve_issues = [i for i in result.issues if "CVE-2025-9905" in i.message]
        assert len(cve_issues) == 0, "No Lambda = no CVE-2025-9905"

    @pytest.mark.parametrize(
        "keras_version",
        ["3.11.3", "3.11.3.post1", "3.11.3.post_", "3.11.3-1", "3.11.3+vendor.1"],
    )
    def test_no_cve_for_fixed_keras_version(self, tmp_path: Path, keras_version: str) -> None:
        """Lambda layer with fixed Keras version should not be CVE-attributed."""
        h5_path = tmp_path / f"model_{keras_version.replace('.', '_').replace('+', '_')}.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {"function": "lambda x: x"},
                        }
                    ],
                },
            }
            f.attrs["model_config"] = json.dumps(model_config)
            f.attrs["keras_version"] = keras_version

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        cve_issues = [i for i in result.issues if "CVE-2025-9905" in i.message]
        assert len(cve_issues) == 0, "Fixed Keras versions should not trigger CVE-2025-9905 attribution"

    @pytest.mark.parametrize(
        "keras_version",
        ["3.11.3rc1", "3.11.3rc.", "3.11.3-rc.1", "3.11.3_rc_1", "3.11.3.dev.1"],
    )
    def test_cve_fix_prerelease_still_triggers_cve_2025_9905(
        self,
        tmp_path: Path,
        keras_version: str,
    ) -> None:
        """3.11.3 prereleases are still pre-fix builds and should remain CVE-attributed."""
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [{"class_name": "Lambda", "config": {"function": "lambda x: x"}}],
                },
            },
            keras_version=keras_version,
            file_name=f"model_{keras_version.replace('.', '_').replace('-', '_')}.h5",
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9905"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["keras_version"] == keras_version

    def test_unparseable_keras_versions_mark_unknown_risk(self, tmp_path: Path) -> None:
        """Unparseable versions must not be treated as safely non-vulnerable."""
        scanner = KerasH5Scanner()
        versions = ["3.11.x", "2.12.0-gpu", "3.11.3+", "3.11.3rc1junk", "not-a-version"]

        for version in versions:
            h5_path = tmp_path / f"model_{version.replace('.', '_')}.h5"
            with h5py.File(h5_path, "w") as f:
                model_config = {
                    "class_name": "Sequential",
                    "config": {
                        "name": "test",
                        "layers": [
                            {
                                "class_name": "Lambda",
                                "config": {"function": "lambda x: x"},
                            }
                        ],
                    },
                }
                f.attrs["model_config"] = json.dumps(model_config)
                f.attrs["keras_version"] = version

            result = scanner.scan(str(h5_path))
            cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9905"]
            assert len(cve_issues) >= 1, f"Expected CVE uncertainty issue for non-canonical version {version}"
            assert all(i.severity == IssueSeverity.WARNING for i in cve_issues)
            assert all(i.details.get("parse_status") == "unknown" for i in cve_issues)

            passed_checks = [c for c in result.checks if c.name == "H5 Lambda Version Risk Check"]
            assert len(passed_checks) == 0, f"Version {version} should not be marked as safely outside vulnerable range"

    def test_cve_2024_3660_unparseable_version_marks_unknown_risk(self, tmp_path: Path) -> None:
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [{"class_name": "Lambda", "config": {"function": "lambda x: x"}}],
                },
            },
            keras_version="2.12.0-gpu",
            file_name="model_noncanonical_2_12_gpu.h5",
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2024-3660"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == "2.12.0-gpu"
        assert cve_issues[0].details["parse_status"] == "unknown"
        assert "is non-canonical" in cve_issues[0].message

    def test_two_part_keras_versions_are_parsed_with_zero_patch(self, tmp_path: Path) -> None:
        """Two-part versions such as 3.11 should be evaluated as 3.11.0, not unknown risk."""
        model_path = create_custom_h5_file(
            tmp_path,
            {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [{"class_name": "Lambda", "config": {"function": "lambda x: x"}}],
                },
            },
            keras_version="3.11",
            file_name="model_3_11.h5",
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9905"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details.get("parse_status") != "unknown"

    def test_pep440_keras_versions_within_vulnerable_range_are_critical(self, tmp_path: Path) -> None:
        """PEP 440 prerelease/postrelease variants in vulnerable range should be attributed."""
        scanner = KerasH5Scanner()
        versions = ["3.11.2rc1", "3.11.2.post1", "3.11.3rc1"]

        for version in versions:
            h5_path = tmp_path / f"model_{version.replace('.', '_')}.h5"
            with h5py.File(h5_path, "w") as f:
                model_config = {
                    "class_name": "Sequential",
                    "config": {
                        "name": "test",
                        "layers": [
                            {
                                "class_name": "Lambda",
                                "config": {"function": "lambda x: x"},
                            }
                        ],
                    },
                }
                f.attrs["model_config"] = json.dumps(model_config)
                f.attrs["keras_version"] = version

            result = scanner.scan(str(h5_path))
            cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9905"]
            assert len(cve_issues) >= 1, f"Expected CVE attribution for version {version}"
            assert all(i.severity == IssueSeverity.CRITICAL for i in cve_issues)
            assert all(i.details.get("parse_status") != "unknown" for i in cve_issues)
