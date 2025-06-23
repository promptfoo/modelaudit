import pickle

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.tf_savedmodel_scanner import TensorFlowSavedModelScanner

# Try to import tensorflow and its core module
try:
    import tensorflow  # noqa: F401
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel  # noqa: F401

    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False


def test_tf_savedmodel_scanner_can_handle(tmp_path):
    """Test the can_handle method of TensorFlowSavedModelScanner."""
    # Create a directory with saved_model.pb
    tf_dir = tmp_path / "tf_model"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"dummy content")

    # Create a regular directory
    regular_dir = tmp_path / "regular_dir"
    regular_dir.mkdir()

    # Create a file
    test_file = tmp_path / "test.pb"
    test_file.write_bytes(b"dummy content")

    if HAS_TENSORFLOW:
        assert TensorFlowSavedModelScanner.can_handle(str(tf_dir)) is True
        assert TensorFlowSavedModelScanner.can_handle(str(regular_dir)) is False
        assert (
            TensorFlowSavedModelScanner.can_handle(str(test_file)) is True
        )  # Now accepts any .pb file
    else:
        # When TensorFlow is not installed, can_handle returns False
        assert TensorFlowSavedModelScanner.can_handle(str(tf_dir)) is False
        assert TensorFlowSavedModelScanner.can_handle(str(regular_dir)) is False
        assert TensorFlowSavedModelScanner.can_handle(str(test_file)) is False


def create_tf_savedmodel(tmp_path, *, malicious=False):
    """Create a mock TensorFlow SavedModel directory for testing."""
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel  # noqa: F811

    # Create a directory that mimics a TensorFlow SavedModel
    model_dir = tmp_path / "tf_model"
    model_dir.mkdir()

    # Create a minimal valid SavedModel protobuf
    saved_model = SavedModel()

    # Add a meta graph
    meta_graph = saved_model.meta_graphs.add()

    # Add a simple graph
    graph_def = meta_graph.graph_def

    # Add a simple constant node
    node = graph_def.node.add()
    node.name = "Const"
    node.op = "Const"

    if malicious:
        # Add a suspicious operation
        suspicious_node = graph_def.node.add()
        suspicious_node.name = "suspicious_op"
        suspicious_node.op = "PyFunc"  # This is in our suspicious ops list

    # Write the protobuf to file
    with (model_dir / "saved_model.pb").open("wb") as f:
        f.write(saved_model.SerializeToString())

    # Create variables directory
    variables_dir = model_dir / "variables"
    variables_dir.mkdir()

    # Create variables.index
    (variables_dir / "variables.index").write_bytes(b"dummy index content")

    # Create variables.data
    (variables_dir / "variables.data-00000-of-00001").write_bytes(b"dummy data content")

    # Create assets directory
    assets_dir = model_dir / "assets"
    assets_dir.mkdir()

    # If malicious, add a malicious pickle file
    if malicious:

        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('malicious code')",))

        malicious_data = {"malicious": MaliciousClass()}
        malicious_pickle = pickle.dumps(malicious_data)
        (model_dir / "malicious.pkl").write_bytes(malicious_pickle)

    return model_dir


@pytest.mark.skipif(not HAS_TENSORFLOW, reason="TensorFlow not installed")
def test_tf_savedmodel_scanner_safe_model(tmp_path):
    """Test scanning a safe TensorFlow SavedModel."""
    model_dir = create_tf_savedmodel(tmp_path)

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(model_dir))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
    ]
    assert len(error_issues) == 0


@pytest.mark.skipif(not HAS_TENSORFLOW, reason="TensorFlow not installed")
def test_tf_savedmodel_scanner_malicious_model(tmp_path):
    """Test scanning a malicious TensorFlow SavedModel."""
    model_dir = create_tf_savedmodel(tmp_path, malicious=True)

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(model_dir))

    # The scanner should detect errors from:
    # 1. Malicious pickle files in the directory, OR
    # 2. Suspicious TensorFlow operations (e.g. PyFunc), OR
    # 3. Both malicious files and suspicious operations
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "malicious.pkl" in issue.message.lower()
        or "eval" in issue.message.lower()
        or "pyfunc" in issue.message.lower()
        or "suspicious" in issue.message.lower()
        for issue in result.issues
    )


def test_tf_savedmodel_scanner_invalid_model(tmp_path):
    """Test scanning an invalid TensorFlow SavedModel."""
    # Create an invalid model directory (missing required files)
    invalid_dir = tmp_path / "invalid_model"
    invalid_dir.mkdir()
    (invalid_dir / "saved_model.pb").write_bytes(b"dummy content")
    # Missing variables directory

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(invalid_dir))

    # Should have errors about invalid protobuf format or TensorFlow not installed
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "error" in issue.message.lower()
        or "parsing" in issue.message.lower()
        or "invalid" in issue.message.lower()
        or "tensorflow not installed" in issue.message.lower()
        for issue in result.issues
    )


@pytest.mark.skipif(not HAS_TENSORFLOW, reason="TensorFlow not installed")
def test_tf_savedmodel_scanner_with_blacklist(tmp_path):
    """Test TensorFlow SavedModel scanner with custom blacklist patterns."""
    model_dir = create_tf_savedmodel(tmp_path)

    # Create a file with content that matches our blacklist
    (model_dir / "custom_file.txt").write_bytes(
        b"This file contains suspicious_function",
    )

    # Create scanner with custom blacklist
    scanner = TensorFlowSavedModelScanner(
        config={"blacklist_patterns": ["suspicious_function"]},
    )
    result = scanner.scan(str(model_dir))

    # Should detect our blacklisted pattern
    blacklist_issues = [
        issue
        for issue in result.issues
        if "suspicious_function" in issue.message.lower()
    ]
    assert len(blacklist_issues) > 0


def test_tf_savedmodel_scanner_not_a_directory(tmp_path):
    """Test scanning a file instead of a directory."""
    # Create a file
    test_file = tmp_path / "model.pb"
    test_file.write_bytes(b"dummy content")

    scanner = TensorFlowSavedModelScanner()
    result = scanner.scan(str(test_file))

    # Should have an error about invalid protobuf format or TensorFlow not installed
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "error" in issue.message.lower()
        or "parsing" in issue.message.lower()
        or "tensorflow not installed" in issue.message.lower()
        for issue in result.issues
    )


@pytest.mark.skipif(not HAS_TENSORFLOW, reason="TensorFlow not installed")
def test_tf_savedmodel_scanner_unreadable_file(tmp_path):
    """Scanner should report unreadable files instead of silently skipping."""
    model_dir = create_tf_savedmodel(tmp_path)

    missing = model_dir / "missing.txt"
    missing.write_text("secret")
    # Replace file with dangling symlink to trigger read error
    missing.unlink()
    missing.symlink_to("/nonexistent/path")

    scanner = TensorFlowSavedModelScanner(config={"blacklist_patterns": ["secret"]})
    result = scanner.scan(str(model_dir))

    assert any("error reading file" in issue.message.lower() for issue in result.issues)
