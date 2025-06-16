import json

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner

# Skip all tests if h5py is not available
pytest.importorskip("h5py")
import h5py  # noqa: E402


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
            malicious_function = (
                'lambda x: eval(\'__import__("os").system("rm -rf /")\')'
            )
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
    error_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
    ]
    assert len(error_issues) == 0


def test_keras_h5_scanner_malicious_model(tmp_path):
    """Test scanning a malicious Keras H5 model."""
    model_path = create_mock_h5_file(tmp_path, malicious=True)

    scanner = KerasH5Scanner()
    result = scanner.scan(str(model_path))

    # The scanner should detect suspicious patterns
    assert any(
        issue.severity in (IssueSeverity.CRITICAL, IssueSeverity.WARNING)
        for issue in result.issues
    )
    assert any(
        "eval" in issue.message.lower()
        or "system" in issue.message.lower()
        or "suspicious" in issue.message.lower()
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
        "invalid" in issue.message.lower()
        or "not an hdf5" in issue.message.lower()
        or "error" in issue.message.lower()
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

    # Should detect our blacklisted pattern
    blacklist_issues = [
        issue
        for issue in result.issues
        if "suspicious_function" in issue.message.lower()
        or "lambda" in issue.message.lower()
    ]
    assert len(blacklist_issues) > 0


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
