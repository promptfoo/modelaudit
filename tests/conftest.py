import logging
import pickle
import shutil
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.additional_mock_utils import (
    FastCacheMocks,
    FastCompressionMocks,
    FastCryptoMocks,
    FastLoggingMocks,
    setup_ultra_fast_environment,
)

# Import our optimized mock utilities
from tests.mock_utils import FastFileSystem, FastMLMocks, FastNetworkMock, FastScannerMocks, setup_fast_test_environment

# Mock utilities for heavy dependencies


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
    progress_callback.messages = progress_messages  # type: ignore[attr-defined]
    progress_callback.percentages = progress_percentages  # type: ignore[attr-defined]

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


@pytest.fixture
def mock_scanner_registry():
    """Mock scanner registry to avoid loading heavy ML dependencies."""
    with patch("modelaudit.scanners.SCANNER_REGISTRY") as mock_registry:
        # Create lightweight mock scanners
        mock_pickle_scanner = Mock()
        mock_pickle_scanner.can_handle.return_value = True
        mock_pickle_scanner.scan.return_value = Mock(issues=[], files_scanned=1)

        mock_registry.__iter__.return_value = [mock_pickle_scanner]
        yield mock_registry


@pytest.fixture
def mock_ml_dependencies():
    """Mock heavy ML dependencies to prevent imports during unit tests."""
    mocks = {}

    # Mock TensorFlow
    mock_tf = MagicMock()
    mock_tf.__version__ = "2.13.0"
    mocks["tensorflow"] = mock_tf

    # Mock Keras
    mock_keras = MagicMock()
    mock_keras.__version__ = "2.13.0"
    mocks["keras"] = mock_keras

    # Mock PyTorch
    mock_torch = MagicMock()
    mock_torch.__version__ = "2.6.0"
    mocks["torch"] = mock_torch

    # Mock pandas/pyarrow that causes the crash
    mock_pandas = MagicMock()
    mocks["pandas"] = mock_pandas

    with patch.dict("sys.modules", mocks):
        yield mocks


@pytest.fixture
def mock_cli_scan_command():
    """Mock the CLI scan command to avoid heavy dependency loading."""
    # Mock the core scan function that the CLI actually uses
    # Create complete mock data matching ModelAuditResultModel structure
    import time

    current_time = time.time()

    mock_result_dict = {
        "files_scanned": 1,
        "bytes_scanned": 1024,
        "duration": 0.1,
        "issues": [],  # Use empty list to avoid Issue object complications
        "checks": [],  # Required field
        "assets": [],  # Required field
        "has_errors": False,
        "scanner_names": ["test_scanner"],  # Required field
        "file_metadata": {},  # Required field
        "start_time": current_time,  # Required field
        "total_checks": 1,  # Required field
        "passed_checks": 1,  # Required field
        "failed_checks": 0,  # Required field
        "success": True,
    }

    with patch("modelaudit.cli.scan_model_directory_or_file") as mock_scan:
        # Create a mock ModelAuditResultModel that properly exposes attributes
        mock_model = Mock()
        mock_model.model_dump.return_value = mock_result_dict

        # Ensure the mock exposes the attributes the CLI expects
        mock_model.issues = mock_result_dict["issues"]
        mock_model.files_scanned = mock_result_dict["files_scanned"]
        mock_model.bytes_scanned = mock_result_dict["bytes_scanned"]
        mock_model.has_errors = mock_result_dict["has_errors"]

        mock_scan.return_value = mock_model
        yield mock_scan


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


# Enhanced fixtures using fast mocking utilities


@pytest.fixture
def fast_filesystem():
    """Provide a fast in-memory filesystem for tests."""
    return FastFileSystem()


@pytest.fixture
def fast_test_env():
    """Complete fast test environment with all mocks enabled."""
    return setup_fast_test_environment()


@pytest.fixture
def fast_scanner_result():
    """Fast mock scanner result for testing."""
    return FastScannerMocks.create_scan_result()


@pytest.fixture
def fast_network():
    """Fast network mocks for testing."""
    return FastNetworkMock()


@pytest.fixture
def mock_heavy_ml_libs():
    """Mock heavy ML libraries to prevent slow imports."""
    ml_mocks = FastMLMocks()

    # Create sklearn mock with proper structure
    sklearn_mock = MagicMock()
    sklearn_mock.__version__ = "1.3.0"
    sklearn_mock.linear_model = MagicMock()

    # Create dill mock with required methods
    dill_mock = MagicMock()
    dill_mock.dump = MagicMock()
    dill_mock.load = MagicMock()
    dill_mock.__version__ = "0.3.7"

    # Create joblib mock
    joblib_mock = MagicMock()
    joblib_mock.load = MagicMock()
    joblib_mock.dump = MagicMock()
    joblib_mock.__version__ = "1.3.0"

    mocks = {
        "torch": ml_mocks.create_torch_mock(),
        "tensorflow": ml_mocks.create_tensorflow_mock(),
        "tf": ml_mocks.create_tensorflow_mock(),
        "numpy": ml_mocks.create_numpy_mock(),
        "pandas": MagicMock(),
        "joblib": joblib_mock,
        "dill": dill_mock,
        "scipy": MagicMock(),
        "sklearn": sklearn_mock,
        "transformers": MagicMock(),
        "onnx": MagicMock(),
        "onnxruntime": MagicMock(),
    }

    with patch.dict("sys.modules", mocks):
        yield mocks


@pytest.fixture
def fast_file_operations():
    """Mock file operations for faster I/O."""
    filesystem = FastFileSystem()

    # Add common test files
    filesystem.add_file("/tmp/test.pkl", b"mock pickle content")
    filesystem.add_file("/tmp/test.pt", b"mock pytorch content")
    filesystem.add_file("/tmp/test.h5", b"mock keras content")

    def mock_open(file, mode="r", **kwargs):
        path_str = str(Path(file))
        if "w" in mode or "a" in mode:
            mock_file = Mock()
            mock_file.write = Mock()
            mock_file.__enter__ = Mock(return_value=mock_file)
            mock_file.__exit__ = Mock(return_value=None)
            return mock_file
        else:
            content = filesystem.get_file(path_str)
            if "b" in mode:
                import io

                return io.BytesIO(content)
            else:
                import io

                return io.StringIO(content.decode("utf-8"))

    # Mock path checking functions
    def mock_path_exists(path):
        return filesystem.exists(str(path))

    def mock_path_isfile(path):
        return filesystem.is_file(str(path))

    def mock_access(path, mode):
        # Always return True for readable files in our mock filesystem
        return filesystem.exists(str(path))

    with (
        patch("builtins.open", side_effect=mock_open),
        patch("os.path.exists", side_effect=mock_path_exists),
        patch("os.path.isfile", side_effect=mock_path_isfile),
        patch("os.access", side_effect=mock_access),
        patch.object(Path, "exists", lambda self: filesystem.exists(str(self))),
        patch.object(Path, "is_file", lambda self: filesystem.is_file(str(self))),
    ):
        yield filesystem


@pytest.fixture
def no_sleep():
    """Mock time.sleep to prevent delays in tests."""
    with patch("time.sleep"):
        yield


@pytest.fixture
def fast_tempfiles():
    """Mock temporary file creation for faster tests."""

    def mock_mkdtemp(*args, **kwargs):
        return f"/tmp/mock_temp_{id(args)}"

    def mock_mkstemp(*args, **kwargs):
        fd = 123
        path = f"/tmp/mock_temp_file_{id(args)}"
        return fd, path

    with patch("tempfile.mkdtemp", side_effect=mock_mkdtemp), patch("tempfile.mkstemp", side_effect=mock_mkstemp):
        yield


@pytest.fixture
def mock_subprocess():
    """Mock subprocess calls to avoid external process execution."""
    mock_result = Mock()
    mock_result.returncode = 0
    mock_result.stdout = b"mock output"
    mock_result.stderr = b""

    with (
        patch("subprocess.run", return_value=mock_result),
        patch("subprocess.call", return_value=0),
        patch("subprocess.check_output", return_value=b"mock output"),
    ):
        yield mock_result


@pytest.fixture
def fast_network_calls():
    """Mock all network calls for faster tests."""
    network = FastNetworkMock()

    with (
        patch("requests.get", side_effect=network.mock_requests_get),
        patch("requests.post", side_effect=network.mock_requests_get),
        patch("urllib.request.urlopen") as mock_urlopen,
    ):
        mock_response = Mock()
        mock_response.read.return_value = b'{"status": "ok"}'
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        yield network


# Additional specialized mocking fixtures


@pytest.fixture
def fast_crypto():
    """Mock cryptographic operations for speed."""
    crypto_mocks = FastCryptoMocks()

    with patch.dict("sys.modules", {"hashlib": Mock(**crypto_mocks.mock_hashlib())}):
        yield crypto_mocks


@pytest.fixture
def fast_compression():
    """Mock compression operations for speed."""
    compression_mocks = FastCompressionMocks()

    with (
        patch("zipfile.ZipFile", side_effect=lambda *a, **k: compression_mocks.create_mock_zipfile()),
        patch("tarfile.open", side_effect=lambda *a, **k: compression_mocks.create_mock_tarfile()),
    ):
        yield compression_mocks


@pytest.fixture
def fast_cache():
    """Provide fast in-memory cache mock."""
    return FastCacheMocks()


@pytest.fixture
def no_logging():
    """Disable logging for performance."""
    logging_mocks = FastLoggingMocks()

    with patch.dict("sys.modules", {"logging": Mock(**logging_mocks.mock_logging_module())}):
        yield


@pytest.fixture
def ultra_fast_env():
    """Complete ultra-fast environment with ALL performance mocks enabled."""
    return setup_ultra_fast_environment()


@pytest.fixture
def fast_secure_hasher():
    """Mock the SecureFileHasher for instant hashing."""
    from tests.additional_mock_utils import FastSecureHasherMock

    with patch("modelaudit.utils.secure_hasher.SecureFileHasher", FastSecureHasherMock):
        yield FastSecureHasherMock()
