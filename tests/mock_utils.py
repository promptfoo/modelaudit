"""
Optimized mocking utilities for faster test execution.

This module provides enhanced mocking strategies to replace slow file I/O,
network calls, and heavy dependency operations with fast in-memory mocks.
"""

import io
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch


class FastFileSystem:
    """In-memory file system mock for faster file I/O operations."""

    def __init__(self):
        self._files: dict[str, bytes] = {}
        self._dirs: set[str] = set()

    def add_file(self, path: str, content: bytes | str) -> None:
        """Add a file to the mock filesystem."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        self._files[str(Path(path))] = content
        # Ensure parent directories exist
        parent = str(Path(path).parent)
        while parent != "." and parent != "/":
            self._dirs.add(parent)
            parent = str(Path(parent).parent)

    def get_file(self, path: str) -> bytes:
        """Get file content."""
        return self._files.get(str(Path(path)), b"")

    def exists(self, path: str) -> bool:
        """Check if file or directory exists."""
        path_str = str(Path(path))
        return path_str in self._files or path_str in self._dirs

    def is_file(self, path: str) -> bool:
        """Check if path is a file."""
        return str(Path(path)) in self._files

    def is_dir(self, path: str) -> bool:
        """Check if path is a directory."""
        return str(Path(path)) in self._dirs

    def stat(self, path: str):
        """Mock stat result."""
        content = self._files.get(str(Path(path)), b"")
        mock_stat = Mock()
        mock_stat.st_size = len(content)
        mock_stat.st_mtime = time.time()
        mock_stat.st_mode = 0o100644  # Regular file
        return mock_stat


class FastNetworkMock:
    """Fast network operation mocks."""

    @staticmethod
    def mock_requests_get(url: str, **kwargs) -> Mock:
        """Mock requests.get with instant response."""
        response = Mock()
        response.status_code = 200
        response.content = b'{"status": "ok"}'
        response.text = '{"status": "ok"}'
        response.json.return_value = {"status": "ok"}
        response.headers = {"content-type": "application/json"}
        response.raise_for_status.return_value = None
        return response

    @staticmethod
    def mock_download(url: str, path: str, **kwargs) -> Path:
        """Mock file download operation."""
        # Just return the target path without actually downloading
        return Path(path)


class FastMLMocks:
    """Fast mocks for heavy ML dependencies."""

    @staticmethod
    def create_torch_mock():
        """Create lightweight PyTorch mock."""
        torch_mock = MagicMock()
        torch_mock.__version__ = "2.0.0"
        torch_mock.load.return_value = {"model": "data"}
        torch_mock.jit.load.return_value = Mock()
        return torch_mock

    @staticmethod
    def create_tensorflow_mock():
        """Create lightweight TensorFlow mock."""
        tf_mock = MagicMock()
        tf_mock.__version__ = "2.13.0"
        tf_mock.keras.models.load_model.return_value = Mock()
        tf_mock.saved_model.load.return_value = Mock()
        return tf_mock

    @staticmethod
    def create_numpy_mock():
        """Create lightweight NumPy mock."""
        np_mock = MagicMock()
        np_mock.__version__ = "1.24.0"
        np_mock.load.return_value = {"data": [1, 2, 3]}
        return np_mock


class FastScannerMocks:
    """Fast mocks for scanner operations."""

    @staticmethod
    def create_scan_result(
        issues: list | None = None, files_scanned: int = 1, bytes_scanned: int = 1024, success: bool = True
    ):
        """Create a mock scan result."""
        result = Mock()
        result.issues = issues or []
        result.files_scanned = files_scanned
        result.bytes_scanned = bytes_scanned
        result.success = success
        result.has_errors = len(result.issues) > 0 if issues else False
        result.duration = 0.001  # Very fast mock scan
        result.scanner_names = ["mock_scanner"]
        result.assets = []
        result.checks = []
        result.file_metadata = {}
        result.start_time = time.time()
        result.total_checks = 1
        result.passed_checks = 1 if success else 0
        result.failed_checks = 0 if success else 1
        return result


def fast_tempfile_mock():
    """Mock tempfile operations with in-memory paths."""

    def mock_mkdtemp(*args, **kwargs):
        return f"/tmp/mock_temp_{id(args)}"

    def mock_mkstemp(*args, **kwargs):
        fd = 123
        path = f"/tmp/mock_temp_file_{id(args)}"
        return fd, path

    return patch("tempfile.mkdtemp", side_effect=mock_mkdtemp), patch("tempfile.mkstemp", side_effect=mock_mkstemp)


def fast_time_mock():
    """Mock time operations to avoid actual delays."""
    mock_time = 1000.0

    def mock_time_func():
        return mock_time

    def mock_sleep(duration):
        nonlocal mock_time
        mock_time += duration

    return patch("time.time", side_effect=mock_time_func), patch("time.sleep", side_effect=mock_sleep)


def mock_heavy_file_operations():
    """Context manager for mocking heavy file operations."""

    class FileOpMocks:
        def __init__(self):
            self.filesystem = FastFileSystem()
            self.patches = []

        def __enter__(self):
            # Mock file operations
            def mock_open(file, mode="r", **kwargs):
                path_str = str(Path(file))
                if "w" in mode or "a" in mode:
                    # Writing - return a mock file handle
                    mock_file = Mock()
                    mock_file.write = Mock()
                    mock_file.__enter__ = Mock(return_value=mock_file)
                    mock_file.__exit__ = Mock(return_value=None)
                    return mock_file
                else:
                    # Reading - return content from filesystem
                    content = self.filesystem.get_file(path_str)
                    if "b" in mode:
                        return io.BytesIO(content)
                    else:
                        return io.StringIO(content.decode("utf-8"))

            # Mock Path operations
            def mock_path_exists(path_self):
                return self.filesystem.exists(str(path_self))

            def mock_path_is_file(path_self):
                return self.filesystem.is_file(str(path_self))

            def mock_path_is_dir(path_self):
                return self.filesystem.is_dir(str(path_self))

            def mock_path_stat(path_self):
                return self.filesystem.stat(str(path_self))

            # Mock os.path functions too
            def mock_os_path_exists(path):
                return self.filesystem.exists(str(path))

            def mock_os_path_isfile(path):
                return self.filesystem.is_file(str(path))

            def mock_os_path_isdir(path):
                return self.filesystem.is_dir(str(path))

            # Apply patches
            self.patches = [
                patch("builtins.open", side_effect=mock_open),
                patch.object(Path, "exists", mock_path_exists),
                patch.object(Path, "is_file", mock_path_is_file),
                patch.object(Path, "is_dir", mock_path_is_dir),
                patch.object(Path, "stat", mock_path_stat),
                patch("os.path.exists", side_effect=mock_os_path_exists),
                patch("os.path.isfile", side_effect=mock_os_path_isfile),
                patch("os.path.isdir", side_effect=mock_os_path_isdir),
            ]

            for p in self.patches:
                p.start()

            return self.filesystem

        def __exit__(self, exc_type, exc_val, exc_tb):
            for p in reversed(self.patches):
                p.stop()

    return FileOpMocks()


def mock_all_network_calls():
    """Mock all common network operations."""
    network_mock = FastNetworkMock()

    return patch.multiple(
        "requests",
        get=Mock(side_effect=network_mock.mock_requests_get),
        post=Mock(side_effect=network_mock.mock_requests_get),
        put=Mock(side_effect=network_mock.mock_requests_get),
        delete=Mock(side_effect=network_mock.mock_requests_get),
    )


def setup_fast_test_environment():
    """Set up a complete fast test environment with all common mocks."""

    class FastTestEnv:
        def __init__(self):
            self.patches = []
            self.filesystem = FastFileSystem()

        def __enter__(self):
            # Setup ML library mocks
            ml_mocks = FastMLMocks()
            ml_modules = {
                "torch": ml_mocks.create_torch_mock(),
                "tensorflow": ml_mocks.create_tensorflow_mock(),
                "numpy": ml_mocks.create_numpy_mock(),
                "pandas": MagicMock(),
                "joblib": MagicMock(),
                "dill": MagicMock(),
            }

            # Setup time mocks
            mock_time = 1000.0

            def fast_time():
                return mock_time

            def fast_sleep(duration):
                pass  # No-op sleep

            # Setup file system mocks
            def mock_open(file, mode="r", **kwargs):
                if "w" in mode or "a" in mode:
                    mock_file = Mock()
                    mock_file.__enter__ = Mock(return_value=mock_file)
                    mock_file.__exit__ = Mock(return_value=None)
                    return mock_file
                else:
                    content = self.filesystem.get_file(str(file))
                    if "b" in mode:
                        return io.BytesIO(content)
                    else:
                        return io.StringIO(content.decode("utf-8"))

            # Setup network mocks
            network = FastNetworkMock()

            # Apply all patches
            self.patches = [
                patch.dict("sys.modules", ml_modules),
                patch("time.time", side_effect=fast_time),
                patch("time.sleep", side_effect=fast_sleep),
                patch("builtins.open", side_effect=mock_open),
                patch("requests.get", side_effect=network.mock_requests_get),
                patch("tempfile.mkdtemp", return_value="/tmp/mock_temp"),
            ]

            for p in self.patches:
                p.start()

            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            for p in reversed(self.patches):
                p.stop()

        def add_file(self, path: str, content: str | bytes):
            """Add a file to the mock filesystem."""
            self.filesystem.add_file(path, content)

    return FastTestEnv()
