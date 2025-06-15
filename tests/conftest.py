import logging

import pytest


@pytest.fixture(autouse=True)
def setup_logging():
    """Set up logging for tests."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    # Suppress excessive logging during tests
    logging.getLogger("modelaudit").setLevel(logging.ERROR)

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

    # Create various model files
    (model_dir / "model1.pkl").write_bytes(b"pickle model content")
    (model_dir / "model2.pt").write_bytes(b"pytorch model content")

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
