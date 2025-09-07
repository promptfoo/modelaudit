"""
Additional specialized mocking utilities for ModelAudit test performance.

These mocks target specific performance bottlenecks found in the codebase
beyond the basic file/network/ML library mocking.
"""

import io
from typing import Any
from unittest.mock import Mock, patch


class FastCryptoMocks:
    """Fast mocks for cryptographic operations that are CPU intensive."""

    @staticmethod
    def fast_hash(data: bytes, algorithm: str = "sha256") -> str:
        """Return a fast fake hash without actual computation."""
        # Use first 8 bytes of data + algorithm name to create a deterministic fake hash
        sample = data[:8] + data[-8:] if len(data) > 8 else data

        fake_hash = f"{algorithm}:{sample.hex()}"
        # Pad to look like real hash length
        if algorithm == "sha256":
            return (fake_hash + "0" * 64)[:64]
        elif algorithm == "blake2b":
            return (fake_hash + "0" * 128)[:128]
        else:
            return (fake_hash + "0" * 40)[:40]  # sha1 length

    @staticmethod
    def mock_hashlib():
        """Mock hashlib operations for speed."""

        def mock_hash_new(algorithm, digest_size=None):
            mock_hasher = Mock()
            mock_hasher.update = Mock()
            mock_hasher.digest = Mock(return_value=b"fake_digest")

            # Generate hex digest of appropriate length
            if algorithm == "blake2b" and digest_size:
                hex_length = digest_size * 2  # Each byte becomes 2 hex chars
                hex_digest = "a" * hex_length  # Simple deterministic hex string
            elif algorithm == "sha256":
                hex_digest = "a" * 64  # 32 bytes = 64 hex chars
            elif algorithm == "md5":
                hex_digest = "a" * 32  # 16 bytes = 32 hex chars
            else:
                hex_digest = "fake_hex_digest"

            mock_hasher.hexdigest = Mock(return_value=hex_digest)
            return mock_hasher

        def blake2b_factory(data=b"", digest_size=32):
            return mock_hash_new("blake2b", digest_size)

        return {
            "sha256": Mock(side_effect=lambda: mock_hash_new("sha256")),
            "blake2b": Mock(side_effect=blake2b_factory),
            "md5": Mock(side_effect=lambda: mock_hash_new("md5")),
            "new": Mock(side_effect=mock_hash_new),
        }


class FastCompressionMocks:
    """Fast mocks for compression/decompression operations."""

    @staticmethod
    def create_mock_zipfile():
        """Create a fast mock ZipFile that doesn't do actual compression."""
        mock_zip = Mock()
        mock_namelist = ["file1.txt", "file2.bin", "subdir/file3.py"]
        mock_zip.namelist.return_value = mock_namelist

        def mock_open(name, mode="r"):
            # Return mock file content based on name
            if name.endswith(".txt"):
                return io.BytesIO(b"mock text content")
            elif name.endswith(".py"):
                return io.BytesIO(b'# mock python code\nprint("hello")')
            else:
                return io.BytesIO(b"mock binary content")

        mock_zip.open = Mock(side_effect=mock_open)
        mock_zip.read = Mock(return_value=b"mock file content")
        mock_zip.__enter__ = Mock(return_value=mock_zip)
        mock_zip.__exit__ = Mock(return_value=None)

        return mock_zip

    @staticmethod
    def create_mock_tarfile():
        """Create a fast mock TarFile."""
        mock_tar = Mock()
        mock_members = [Mock(name=f"file{i}.txt", size=1024) for i in range(3)]
        mock_tar.getmembers.return_value = mock_members
        mock_tar.extractfile.return_value = io.BytesIO(b"mock tar content")
        return mock_tar


class FastCacheMocks:
    """Fast mocks for caching operations."""

    def __init__(self):
        self._cache: dict[str, Any] = {}

    def get(self, key: str) -> Any:
        """Get from mock cache."""
        return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        """Set in mock cache."""
        self._cache[key] = value

    def clear(self) -> None:
        """Clear mock cache."""
        self._cache.clear()

    def exists(self, key: str) -> bool:
        """Check if key exists in mock cache."""
        return key in self._cache


class FastLoggingMocks:
    """Fast mocks for logging operations that can be expensive."""

    @staticmethod
    def create_null_logger():
        """Create a logger that does nothing for performance."""
        logger = Mock()
        logger.debug = Mock()
        logger.info = Mock()
        logger.warning = Mock()
        logger.error = Mock()
        logger.critical = Mock()
        logger.exception = Mock()
        logger.log = Mock()
        return logger

    @staticmethod
    def mock_logging_module():
        """Mock the entire logging module for tests that don't need logs."""
        return {
            "getLogger": Mock(side_effect=lambda name: FastLoggingMocks.create_null_logger()),
            "basicConfig": Mock(),
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40,
            "CRITICAL": 50,
        }


class FastSerializationMocks:
    """Fast mocks for JSON/YAML serialization that can be slow for large objects."""

    @staticmethod
    def fast_json_loads(data: str) -> dict:
        """Fast mock JSON parsing."""
        # Return a simple mock object instead of actual parsing
        return {"mock": "data", "parsed": True, "size": len(data)}

    @staticmethod
    def fast_json_dumps(obj: Any) -> str:
        """Fast mock JSON serialization."""
        # Return mock JSON string
        return '{"mock": "serialized", "type": "' + type(obj).__name__ + '"}'

    @staticmethod
    def mock_json_module():
        """Mock json module operations."""
        return {
            "loads": Mock(side_effect=FastSerializationMocks.fast_json_loads),
            "dumps": Mock(side_effect=FastSerializationMocks.fast_json_dumps),
            "load": Mock(return_value={"mock": "loaded"}),
            "dump": Mock(),
        }


class FastSecureHasherMock:
    """Mock the SecureFileHasher class for speed."""

    def __init__(self, full_hash_threshold: int = 2 * 1024**3):
        self.full_hash_threshold = full_hash_threshold

    def hash_file(self, file_path: str) -> str:
        """Return instant fake hash."""
        # Create deterministic fake hash from file path
        return f"mock_hash_{hash(file_path) % 10000:04d}"

    def enhanced_hash_large_file(self, file_path: str) -> str:
        """Return instant fake hash for large files."""
        return f"mock_enhanced_hash_{hash(file_path) % 10000:04d}"


def mock_compression_libraries():
    """Context manager to mock compression libraries."""
    compression_mocks = FastCompressionMocks()

    return patch.multiple(
        "zipfile", ZipFile=Mock(side_effect=lambda *args, **kwargs: compression_mocks.create_mock_zipfile())
    ), patch.multiple("tarfile", open=Mock(side_effect=lambda *args, **kwargs: compression_mocks.create_mock_tarfile()))


def mock_crypto_operations():
    """Context manager to mock cryptographic operations."""
    crypto_mocks = FastCryptoMocks()

    return patch.dict("sys.modules", {"hashlib": Mock(**crypto_mocks.mock_hashlib())})


def mock_serialization():
    """Context manager to mock serialization operations."""
    serial_mocks = FastSerializationMocks()

    return patch.dict("sys.modules", {"json": Mock(**serial_mocks.mock_json_module())})


def mock_logging_operations():
    """Context manager to disable logging for performance."""
    logging_mocks = FastLoggingMocks()

    return patch.dict("sys.modules", {"logging": Mock(**logging_mocks.mock_logging_module())})


class UltraFastTestEnvironment:
    """
    Ultra-fast test environment that mocks ALL expensive operations.

    Use this for unit tests that need maximum speed and don't require
    real I/O, networking, compression, hashing, or logging.
    """

    def __init__(self):
        self.patches = []

    def __enter__(self):
        from tests.mock_utils import setup_fast_test_environment

        # Start with basic fast environment
        self.base_env = setup_fast_test_environment()
        self.base_env_result = self.base_env.__enter__()

        # Add specialized mocks
        crypto_mocks = FastCryptoMocks()
        compression_mocks = FastCompressionMocks()
        cache_mock = FastCacheMocks()
        logging_mocks = FastLoggingMocks()
        serial_mocks = FastSerializationMocks()

        additional_mocks = {
            # Crypto
            "hashlib": Mock(**crypto_mocks.mock_hashlib()),
            # Compression
            "zipfile": Mock(ZipFile=Mock(side_effect=lambda *a, **k: compression_mocks.create_mock_zipfile())),
            "tarfile": Mock(open=Mock(side_effect=lambda *a, **k: compression_mocks.create_mock_tarfile())),
            "gzip": Mock(open=Mock(return_value=io.BytesIO(b"mock gzip content"))),
            "bz2": Mock(open=Mock(return_value=io.BytesIO(b"mock bz2 content"))),
            # Serialization
            "json": Mock(**serial_mocks.mock_json_module()),
            "yaml": Mock(safe_load=Mock(return_value={"mock": "yaml"})),
            "pickle": Mock(dumps=Mock(return_value=b"mock_pickle"), loads=Mock(return_value={"mock": "unpickled"})),
            # Logging (ultra-quiet)
            "logging": Mock(**logging_mocks.mock_logging_module()),
        }

        self.patches = [
            patch.dict("sys.modules", additional_mocks),
            patch("modelaudit.utils.secure_hasher.SecureFileHasher", FastSecureHasherMock),
        ]

        for p in self.patches:
            p.start()

        return self.base_env_result  # Return the base environment so add_file works

    def __exit__(self, exc_type, exc_val, exc_tb):
        for p in reversed(self.patches):
            p.stop()
        self.base_env.__exit__(exc_type, exc_val, exc_tb)


# Convenience fixtures for specific mock categories
def setup_crypto_mocks():
    """Set up just cryptographic operation mocks."""
    return mock_crypto_operations()


def setup_compression_mocks():
    """Set up just compression operation mocks."""
    return mock_compression_libraries()


def setup_serialization_mocks():
    """Set up just serialization operation mocks."""
    return mock_serialization()


def setup_ultra_fast_environment():
    """Set up the ultra-fast test environment with all mocks."""
    return UltraFastTestEnvironment()
