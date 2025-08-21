import json

import pytest

# Skip if h5py is not available before importing it
pytest.importorskip("h5py")

import h5py

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner


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
        model_config = {
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


def test_keras_h5_scanner_safe_model(tmp_path):
    """Test scanning a safe Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(error_issues) == 0


def test_keras_h5_scanner_malicious_model(tmp_path):
    """Test scanning a malicious Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path, malicious=True)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    # The scanner should detect suspicious patterns
    assert any(issue.severity in (IssueSeverity.CRITICAL, IssueSeverity.WARNING) for issue in result.issues)
    assert any(
        "eval" in issue.message.lower() or "system" in issue.message.lower() or "suspicious" in issue.message.lower()
        for issue in result.issues
    )


def test_keras_h5_scanner_invalid_h5(tmp_path):
    """Test scanning an invalid H5 file."""
    # Create an invalid H5 file (without magic bytes)
    invalid_path = tmp_path / "invalid.h5"
    invalid_path.write_bytes(b"This is not a valid HDF5 file")

    scanner = KerasH5Scanner()
    result = scanner.scan(str(invalid_path))

    # Should have an error about invalid H5
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "invalid" in issue.message.lower() or "not an hdf5" in issue.message.lower() or "error" in issue.message.lower()
        for issue in result.issues
    )


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


def test_keras_h5_scanner_empty_file(tmp_path):
    """Test scanning an empty file."""
    empty_path = tmp_path / "empty.h5"
    empty_path.write_bytes(b"")  # Create empty file

    scanner = KerasH5Scanner()
    result = scanner.scan(str(empty_path))

    # Should have an error about invalid H5
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "file signature not found" in issue.message.lower()
        or "invalid" in issue.message.lower()
        or "error scanning" in issue.message.lower()
        for issue in result.issues
    )


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
        issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
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
        issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
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


def test_malicious_keras_model_still_detected(tmp_path):
    """Test that malicious Keras models are still properly detected."""
    # Create a malicious Keras model file
    malicious_path = create_mock_h5_file(tmp_path, malicious=True)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(malicious_path))

    assert result.success is True

    # Should detect the malicious patterns
    malicious_issues = [
        issue
        for issue in result.issues
        if issue.severity in (IssueSeverity.CRITICAL, IssueSeverity.WARNING)
        and any(keyword in issue.message.lower() for keyword in ["suspicious", "lambda", "eval", "malicious"])
    ]
    assert len(malicious_issues) > 0, "Malicious Keras models should still be detected"


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
