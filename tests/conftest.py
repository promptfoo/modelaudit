import logging
import pickle
import shutil
import tempfile
import zipfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def setup_logging():
    """Set up logging for tests."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    # Suppress excessive logging during tests
    logging.getLogger("modelaudit").setLevel(logging.CRITICAL)

    yield

    # Reset logging after test
    logging.getLogger("modelaudit").setLevel(logging.NOTSET)


@pytest.fixture
def sample_results():
    """Return a sample results dictionary for testing."""
    return {
        "path": "/path/to/model",
        "files_scanned": 5,
        "bytes_scanned": 1024,
        "duration": 0.5,
        "start_time": 1000.0,
        "finish_time": 1000.5,
        "issues": [
            {
                "message": "Test issue 1",
                "severity": "warning",
                "location": "test1.pkl",
                "details": {"test": "value1"},
                "timestamp": 1000.1,
            },
            {
                "message": "Test issue 2",
                "severity": "error",
                "location": "test2.pkl",
                "details": {"test": "value2"},
                "timestamp": 1000.2,
            },
            {
                "message": "Test issue 3",
                "severity": "info",
                "location": "test3.pkl",
                "details": {"test": "value3"},
                "timestamp": 1000.3,
            },
        ],
        "success": True,
        "has_errors": True,
    }


@pytest.fixture
def temp_model_dir(tmp_path):
    """Create a temporary directory with various model files for testing."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()

    # Create a real pickle file
    pickle_data = {"weights": [1, 2, 3], "bias": [0.1]}
    with (model_dir / "model1.pkl").open("wb") as f:
        pickle.dump(pickle_data, f)

    # Create a real PyTorch ZIP file
    zip_path = model_dir / "model2.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Add a real pickle inside
        pickled_data = pickle.dumps({"model": "data"})
        zipf.writestr("data.pkl", pickled_data)

    # Create a TensorFlow SavedModel directory
    tf_dir = model_dir / "tf_model"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"tensorflow model content")

    # Create a subdirectory with more models
    sub_dir = model_dir / "subdir"
    sub_dir.mkdir()
    (sub_dir / "model3.h5").write_bytes(b"\x89HDF\r\n\x1a\nkeras model content")

    return model_dir


@pytest.fixture
def mock_progress_callback():
    """Return a mock progress callback function that records calls."""
    progress_messages = []
    progress_percentages = []

    def progress_callback(message, percentage):
        progress_messages.append(message)
        progress_percentages.append(percentage)

    # Add the recorded messages and percentages as attributes
    progress_callback.messages = progress_messages
    progress_callback.percentages = progress_percentages

    return progress_callback


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_malicious_pickle_data():
    """Provide mock malicious pickle data for testing."""
    return {
        "os_system": b"cos\nsystem\nq\x00.",
        "eval_call": b"cbuiltins\neval\nq\x00.",
        "subprocess_call": b"csubprocess\ncall\nq\x00.",
    }


@pytest.fixture
def performance_markers():
    """Markers for performance-related tests."""
    return {
        "max_scan_time": 1.0,  # Maximum scan time in seconds
        "max_validation_time": 0.001,  # Maximum validation time in seconds
    }


# Configure pytest to handle missing optional dependencies gracefully
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow (deselect with '-m \"not slow\"')",
    )
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line(
        "markers",
        "performance: mark test as performance benchmark",
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests based on their names."""
    for item in items:
        # Mark performance tests
        if "performance" in item.name.lower() or "benchmark" in item.name.lower():
            item.add_marker(pytest.mark.performance)

        # Mark integration tests
        if "integration" in item.name.lower() or "real_world" in item.name.lower():
            item.add_marker(pytest.mark.integration)

        # Mark slow tests
        if "large" in item.name.lower() or "multiple" in item.name.lower():
            item.add_marker(pytest.mark.slow)


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Ensure test files are cleaned up after each test."""
    yield
    # Cleanup any test files that might have been left behind
    for pattern in ["*.test_*", "test_*", "*.tmp"]:
        for file in Path.cwd().glob(pattern):
            try:
                if file.is_file():
                    file.unlink()
                elif file.is_dir():
                    shutil.rmtree(file)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors
