"""Tests for optimized cache configuration."""

from modelaudit.cache.optimized_config import (
    CacheConfiguration,
    ConfigurationExtractor,
    get_config_extractor,
)


class TestCacheConfiguration:
    """Tests for CacheConfiguration class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CacheConfiguration()
        assert config.enabled is True
        assert config.cache_dir is None
        assert config.max_file_size == 100 * 1024 * 1024
        assert config.min_file_size == 1024

    def test_custom_values(self):
        """Test custom configuration values."""
        config = CacheConfiguration(
            {
                "cache_enabled": False,
                "cache_dir": "/tmp/cache",
                "max_cache_file_size": 50 * 1024 * 1024,
                "min_cache_file_size": 2048,
            }
        )
        assert config.enabled is False
        assert config.cache_dir == "/tmp/cache"
        assert config.max_file_size == 50 * 1024 * 1024
        assert config.min_file_size == 2048

    def test_should_cache_disabled(self):
        """Test caching disabled globally."""
        config = CacheConfiguration({"cache_enabled": False})
        assert config.should_cache_file(10000) is False

    def test_should_cache_too_small(self):
        """Test file too small to cache."""
        config = CacheConfiguration()
        assert config.should_cache_file(100) is False

    def test_should_cache_too_large(self):
        """Test file too large to cache."""
        config = CacheConfiguration()
        assert config.should_cache_file(200 * 1024 * 1024) is False

    def test_should_cache_normal_file(self):
        """Test normal file should be cached."""
        config = CacheConfiguration()
        assert config.should_cache_file(50 * 1024) is True

    def test_should_cache_small_text_file(self):
        """Test small text files are not cached."""
        config = CacheConfiguration()
        assert config.should_cache_file(5 * 1024, ".txt") is False
        assert config.should_cache_file(5 * 1024, ".json") is False

    def test_should_cache_large_text_file(self):
        """Test larger text files are cached."""
        config = CacheConfiguration()
        assert config.should_cache_file(50 * 1024, ".txt") is True

    def test_get_cache_strategy_none(self):
        """Test no caching strategy."""
        config = CacheConfiguration({"cache_enabled": False})
        assert config.get_cache_strategy(10000) == "none"

    def test_get_cache_strategy_quick(self):
        """Test quick caching strategy for medium files."""
        config = CacheConfiguration()
        assert config.get_cache_strategy(5 * 1024 * 1024) == "quick"

    def test_get_cache_strategy_content(self):
        """Test content caching strategy for large files."""
        config = CacheConfiguration()
        assert config.get_cache_strategy(50 * 1024 * 1024) == "content"

    def test_get_performance_hint_small_file(self):
        """Test performance hints for small files."""
        config = CacheConfiguration()
        hints = config.get_performance_hint(100 * 1024)
        assert hints["use_batch_operations"] is False
        assert hints["parallel_io_recommended"] is False
        assert hints["memory_streaming_recommended"] is False

    def test_get_performance_hint_large_file(self):
        """Test performance hints for large files."""
        config = CacheConfiguration()
        hints = config.get_performance_hint(100 * 1024 * 1024)
        assert hints["use_batch_operations"] is True
        assert hints["parallel_io_recommended"] is True
        assert hints["memory_streaming_recommended"] is True


class TestConfigurationExtractor:
    """Tests for ConfigurationExtractor class."""

    def test_extract_from_args(self):
        """Test extracting config from positional args."""
        extractor = ConfigurationExtractor()
        config, path = extractor.extract_fast(("/test/file.pkl",), {})
        assert path == "/test/file.pkl"
        assert config is not None

    def test_extract_from_kwargs(self):
        """Test extracting config from keyword args."""
        extractor = ConfigurationExtractor()
        _config, path = extractor.extract_fast((), {"path": "/test/file.pkl"})
        assert path == "/test/file.pkl"

    def test_extract_with_config_dict(self):
        """Test extracting with config dict."""
        extractor = ConfigurationExtractor()
        config_dict = {"cache_enabled": False}
        config, _path = extractor.extract_fast(("/test/file.pkl", config_dict), {})
        assert config is not None
        assert config.enabled is False

    def test_extract_no_path(self):
        """Test extraction with no path."""
        extractor = ConfigurationExtractor()
        config, path = extractor.extract_fast((), {})
        assert path is None
        assert config is not None

    def test_config_caching(self):
        """Test configuration caching."""
        extractor = ConfigurationExtractor()
        config_dict = {"cache_enabled": True}

        # First call
        config1, _ = extractor.extract_fast(("/file1.pkl", config_dict), {})

        # Second call with same config
        config2, _ = extractor.extract_fast(("/file2.pkl", config_dict), {})

        # Should return cached config
        assert config1 is config2

    def test_cleanup_config_cache(self):
        """Test cache cleanup."""
        extractor = ConfigurationExtractor()
        extractor._cache_expiry = 0  # Immediate expiry

        # Add some entries
        for i in range(25):
            config_dict = {"id": i}
            extractor.extract_fast((f"/file{i}.pkl", config_dict), {})

        # Trigger cleanup
        extractor._cleanup_config_cache()

        # Cache should be cleaned
        assert len(extractor._config_cache) <= 20


class TestGetConfigExtractor:
    """Tests for get_config_extractor function."""

    def test_returns_global_instance(self):
        """Test that same instance is returned."""
        ext1 = get_config_extractor()
        ext2 = get_config_extractor()
        assert ext1 is ext2

    def test_instance_is_extractor(self):
        """Test that returned instance is ConfigurationExtractor."""
        ext = get_config_extractor()
        assert isinstance(ext, ConfigurationExtractor)
