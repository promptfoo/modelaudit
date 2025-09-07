"""Optimized configuration handling for cache operations."""

import functools
from typing import Any


class CacheConfiguration:
    """Pre-computed cache configuration to avoid repeated extraction overhead."""

    def __init__(self, config: dict[str, Any] | None = None):
        if config is None:
            config = {}

        self.enabled = config.get("cache_enabled", True)
        self.cache_dir = config.get("cache_dir")
        self.max_file_size = config.get("max_cache_file_size", 100 * 1024 * 1024)  # 100MB default
        self.min_file_size = config.get("min_cache_file_size", 1024)  # 1KB minimum
        self.use_content_hash_threshold = config.get("content_hash_threshold", 10 * 1024 * 1024)  # 10MB

        # Pre-compute common decisions
        self._small_file_extensions = {".txt", ".md", ".json", ".yaml", ".yml"}
        self._large_file_extensions = {".bin", ".pkl", ".h5", ".onnx", ".pb", ".pth", ".pt"}

    @functools.lru_cache(maxsize=128)  # noqa: B019
    def should_cache_file(self, file_size: int, file_ext: str = "") -> bool:
        """
        Cached decision about whether to cache a specific file.

        Uses LRU cache to avoid repeated computation for similar files.
        """
        if not self.enabled:
            return False

        # Don't cache very small files (overhead not worth it)
        if file_size < self.min_file_size:
            return False

        # Don't cache extremely large files
        if file_size > self.max_file_size:
            return False

        # Small text files - usually not worth caching
        return not (file_ext.lower() in self._small_file_extensions and file_size < 10 * 1024)  # 10KB

    @functools.lru_cache(maxsize=64)  # noqa: B019
    def get_cache_strategy(self, file_size: int, file_ext: str = "") -> str:
        """
        Get optimal caching strategy for a file.

        Returns:
            'quick' for fast metadata-based keys
            'content' for content-hash based keys
            'none' for no caching
        """
        if not self.should_cache_file(file_size, file_ext):
            return "none"

        # Large files benefit from content hashing (deduplication)
        if file_size > self.use_content_hash_threshold:
            return "content"

        # Medium files use quick keys (balance of speed vs accuracy)
        return "quick"

    def get_performance_hint(self, file_size: int) -> dict[str, Any]:
        """Get performance hints for cache operations."""
        return {
            "use_batch_operations": file_size > 1024 * 1024,  # 1MB
            "parallel_io_recommended": file_size > 10 * 1024 * 1024,  # 10MB
            "memory_streaming_recommended": file_size > 50 * 1024 * 1024,  # 50MB
        }


class ConfigurationExtractor:
    """Optimized configuration extraction with minimal overhead."""

    def __init__(self):
        self._config_cache = {}  # Cache parsed configurations briefly
        self._cache_expiry = 30.0  # 30 seconds

    def extract_fast(self, args: tuple, kwargs: dict) -> tuple[CacheConfiguration | None, str | None]:
        """
        Fast configuration extraction with caching.

        Returns:
            Tuple of (cache_config, file_path)
        """
        config_dict = None
        file_path = None

        # Fast path: extract file path first
        if args:
            if hasattr(args[0], "__dict__") and hasattr(args[0], "config"):
                # Method call: self.scan(path)
                config_dict = getattr(args[0], "config", {})
                file_path = args[1] if len(args) > 1 else kwargs.get("path")
            else:
                # Function call: scan_file(path, config=None)
                file_path = args[0]
                config_dict = args[1] if len(args) > 1 else kwargs.get("config")
        else:
            # Keyword arguments only
            file_path = kwargs.get("path")
            config_dict = kwargs.get("config")

        # If no file path, return minimal config
        if not file_path:
            return CacheConfiguration({}), None

        # Check cache for parsed configuration
        config_key = id(config_dict) if config_dict else "default"

        if config_key in self._config_cache:
            cached_config, timestamp = self._config_cache[config_key]
            import time

            if time.time() - timestamp < self._cache_expiry:
                return cached_config, file_path

        # Parse new configuration
        cache_config = CacheConfiguration(config_dict if isinstance(config_dict, dict) else {})

        # Cache the parsed configuration
        import time

        self._config_cache[config_key] = (cache_config, time.time())

        # Cleanup old cache entries periodically
        if len(self._config_cache) > 20:
            self._cleanup_config_cache()

        return cache_config, file_path

    def _cleanup_config_cache(self) -> None:
        """Remove expired configuration cache entries."""
        import time

        current_time = time.time()

        expired_keys = [
            key for key, (_, timestamp) in self._config_cache.items() if current_time - timestamp > self._cache_expiry
        ]

        for key in expired_keys:
            del self._config_cache[key]


# Global extractor instance to reuse across decorators
_global_extractor = ConfigurationExtractor()


def get_config_extractor() -> ConfigurationExtractor:
    """Get global configuration extractor instance."""
    return _global_extractor
