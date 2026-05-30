import base64
import json
import marshal
from pathlib import Path
from typing import Any

import pytest

# Skip if h5py is not available before importing it
pytest.importorskip("h5py")

import h5py

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner

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
        weights_group["linked_kernel"] = h5py.ExternalLink(external_source.name, "/payload")

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
        weights_group.create_dataset(
            "external_kernel",
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
            "hdf5_path": "/model_weights/linked_kernel",
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
            "hdf5_path": "/model_weights/external_kernel",
            "segments": [{"filename": "weights.raw", "offset": 0, "size": 8}],
        },
    ]


def test_keras_h5_scanner_skips_cve_2026_1669_on_fixed_version(tmp_path: Path) -> None:
    """Fixed Keras versions should not emit warning-level CVE-2026-1669 findings."""
    model_path = create_h5_with_external_link(tmp_path, keras_version="3.13.2")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
    assert any(
        check.name == "HDF5 External Weight Reference Version Check" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


@pytest.mark.parametrize("keras_version", ["3.13.x", "2.12.0-gpu"])
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

    audit_result = scan_model_directory_or_file(str(model_path))
    metadata = audit_result.file_metadata[str(model_path)]

    assert audit_result.has_errors is False
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in metadata.get("scan_outcome_reasons")
    assert determine_exit_code(audit_result) == 2


def _assert_inconclusive_keras_h5_scan_not_cached(model_path: Path, reason: str, cache_dir: Path) -> None:
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

    def raise_os_error(_self: KerasH5Scanner, _h5_file: Any, _result: Any, _path: str) -> None:
        raise OSError("simulated Keras H5 content read failure")

    monkeypatch.setattr(KerasH5Scanner, "_check_hdf5_external_references", raise_os_error)

    _assert_inconclusive_keras_h5_scan(
        model_path,
        "keras_h5_read_failed",
        "Keras H5 File Read",
        "Unable to read Keras H5 content",
    )
    result = KerasH5Scanner().scan(str(model_path))
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
    audit_result = scan_model_directory_or_file(str(model_path))

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "keras_h5_training_config_parse_failed" in result.metadata["scan_outcome_reasons"]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert determine_exit_code(audit_result) == 1


def test_keras_h5_inconclusive_scan_outcome_uncached_rerun_preserves_exit2(tmp_path: Path) -> None:
    """Uncached Keras H5 inconclusive results must still produce exit 2 on subsequent scans."""
    model_path = create_custom_h5_file(
        tmp_path,
        [],
        file_name="cached_bad_model_config.h5",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
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
    metadata = second_result.file_metadata[str(model_path)]

    assert determine_exit_code(first_result) == 2
    assert determine_exit_code(second_result) == 2
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


def test_keras_h5_scanner_skips_generic_root_weight_like_groups(tmp_path: Path) -> None:
    """Generic root vars/weights groups are common outside Keras and should stay quiet."""
    generic_path = tmp_path / "generic_root_vars.h5"
    with h5py.File(generic_path, "w") as f:
        f["vars"] = h5py.ExternalLink("external_source.h5", "/payload")

    result = KerasH5Scanner().scan(str(generic_path))

    assert result.success is True
    assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
    assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


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


def test_keras_h5_scanner_flags_weights_only_external_link_without_keras_metadata(tmp_path: Path) -> None:
    """Weights-only HDF5 files can still be Keras load inputs and must not skip external references."""
    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0])

    weights_path = tmp_path / "weights_only.h5"
    with h5py.File(weights_path, "w") as f:
        f.attrs["layer_names"] = [b"dense"]
        dense = f.create_group("dense")
        dense.attrs["weight_names"] = [b"kernel:0"]
        dense["kernel:0"] = h5py.ExternalLink(external_source.name, "/payload")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].severity == IssueSeverity.WARNING
    assert cve_issues[0].details["parse_status"] == "unknown"
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

    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        vars_group = f.create_group("layers").create_group("dense").create_group("vars")
        vars_group["0"] = h5py.ExternalLink(external_source.name, "/payload")

    result = KerasH5Scanner().scan(str(weights_path))

    cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
    assert len(cve_issues) == 1
    assert cve_issues[0].details["parse_status"] == "unknown"
    assert cve_issues[0].details["external_references"] == [
        {
            "kind": "ExternalLink",
            "hdf5_path": "/layers/dense/vars/0",
            "filename": "external_source.h5",
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
        "lambda x: K.softmax(x)",
        "lambda x: (x - 128) / 128",
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
        issue for issue in result.issues if "embedded bytecode" in issue.message and "safe_dict_lambda" in issue.message
    ]
    assert len(bytecode_issues) == 1
    assert bytecode_issues[0].severity == IssueSeverity.WARNING
    assert not [
        issue
        for issue in result.issues
        if "safe_dict_lambda" in issue.message and issue.severity == IssueSeverity.CRITICAL
    ]


def test_lambda_dict_bytecode_with_dangerous_pattern_still_critical(tmp_path: Path) -> None:
    encoded_code = base64.b64encode(b"import os\nos.system('id')\neval('__import__(\"os\")')").decode()
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
        and check.details.get("layer_name") == "dangerous_dict_lambda"
    ]
    assert len(dangerous_checks) == 1
    assert {"eval", "__import__", "os.system"}.issubset(set(dangerous_checks[0].details["dangerous_patterns"]))


def test_lambda_code_previews_redact_credentials_in_json_and_sarif(tmp_path: Path) -> None:
    direct_secret = "H5_DIRECT_SECRET"
    dict_secret = "H5_DICT_SECRET"
    encoded_code = base64.b64encode(
        f"import os\nclient_secret='{dict_secret}'\nos.system('id')\n".encode(),
    ).decode()
    model_path = create_custom_h5_file(
        tmp_path,
        {
            "class_name": "Sequential",
            "config": {
                "name": "redacted_lambda_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "direct_lambda",
                            "function": f"lambda x: (eval('1'), \"client_secret='{direct_secret}'\", x)[-1]",
                        },
                    },
                    {
                        "class_name": "Lambda",
                        "config": {
                            "name": "dict_lambda",
                            "function": {"class_name": "__lambda__", "config": {"code": encoded_code}},
                        },
                    },
                ],
            },
        },
    )

    scanner_result = KerasH5Scanner().scan(str(model_path))
    previews = [
        check.details.get("code_preview")
        for check in scanner_result.checks
        if check.name == "Lambda Layer Code Analysis" and check.details.get("code_preview")
    ]
    assert previews
    string_previews = [preview for preview in previews if isinstance(preview, str)]
    assert len(string_previews) == len(previews)
    assert all(direct_secret not in preview and dict_secret not in preview for preview in string_previews)
    assert any("<redacted>" in preview for preview in string_previews)

    audit_result = scan_model_directory_or_file(str(model_path))
    json_output = audit_result.model_dump_json(indent=2, exclude_none=True)
    sarif_output = format_sarif_output(audit_result, [str(model_path)])

    assert direct_secret not in json_output
    assert dict_secret not in json_output
    assert direct_secret not in sarif_output
    assert dict_secret not in sarif_output
    assert "<redacted>" in json_output
    assert "<redacted>" in sarif_output


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
    """Benign module names containing suspicious substrings should not trigger CRITICAL findings."""
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
    assert not any(
        check.name == "Lambda Layer Module Reference Check" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(
        check.name == "Suspicious Configuration String Check" and check.details.get("suspicious_term") == "system"
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


@pytest.mark.parametrize("keras_version", ["3.12.1rc1", "3.13.2rc1"])
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

    @pytest.mark.parametrize(
        "layer_class",
        [
            "keras.layers.Lambda",
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

    def test_custom_namespace_lambda_layer_not_attributed_to_keras_cve(self, tmp_path: Path) -> None:
        """Custom classes ending in Lambda should stay in the custom-layer review path."""
        h5_path = tmp_path / "custom_lambda.h5"
        with h5py.File(h5_path, "w") as f:
            model_config = {
                "class_name": "Sequential",
                "config": {
                    "name": "test",
                    "layers": [
                        {
                            "class_name": "myproject.layers.Lambda",
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
            if check.name == "Custom Layer Class Detection"
            and check.details.get("layer_class") == "myproject.layers.Lambda"
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

    def test_no_cve_for_fixed_keras_version(self, tmp_path: Path) -> None:
        """Lambda layer with fixed Keras version should not be CVE-attributed."""
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
            f.attrs["keras_version"] = "3.11.3"

        scanner = KerasH5Scanner()
        result = scanner.scan(str(h5_path))

        cve_issues = [i for i in result.issues if "CVE-2025-9905" in i.message]
        assert len(cve_issues) == 0, "Fixed Keras versions should not trigger CVE-2025-9905 attribution"

    def test_cve_fix_prerelease_still_triggers_cve_2025_9905(self, tmp_path: Path) -> None:
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
            keras_version="3.11.3rc1",
            file_name="model_prerelease.h5",
        )

        result = KerasH5Scanner().scan(str(model_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2025-9905"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["keras_version"] == "3.11.3rc1"

    def test_unparseable_keras_versions_mark_unknown_risk(self, tmp_path: Path) -> None:
        """Unparseable versions must not be treated as safely non-vulnerable."""
        scanner = KerasH5Scanner()
        versions = ["3.11.x", "2.12.0-gpu", "not-a-version"]

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
