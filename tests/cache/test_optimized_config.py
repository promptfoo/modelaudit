"""Tests for optimized cache configuration."""

from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache.optimized_config import (
    CACHE_SCHEMA_VERSION,
    CacheConfiguration,
    ConfigurationExtractor,
    build_cache_version_context,
    get_config_extractor,
)


def test_cache_schema_invalidates_pre_whitelist_policy_entries() -> None:
    """Security-policy changes must not reuse cached pre-fix severities."""
    assert CACHE_SCHEMA_VERSION == "2.2"
    assert build_cache_version_context()["cache_schema_version"] == "2.2"


class TestCacheConfiguration:
    """Tests for CacheConfiguration class."""

    def test_default_values(self) -> None:
        config = CacheConfiguration()
        assert config.enabled is True
        assert config.cache_dir is None
        assert config.max_file_size == 100 * 1024 * 1024
        assert config.min_file_size == 1024

    def test_custom_values(self, tmp_path: Path) -> None:
        cache_dir = str(tmp_path / "cache")
        config = CacheConfiguration(
            {
                "cache_enabled": False,
                "cache_dir": cache_dir,
                "max_cache_file_size": 50 * 1024 * 1024,
                "min_cache_file_size": 2048,
            }
        )
        assert config.enabled is False
        assert config.cache_dir == cache_dir
        assert config.max_file_size == 50 * 1024 * 1024
        assert config.min_file_size == 2048

    @pytest.mark.parametrize(
        ("enabled", "size", "extension", "expected"),
        [
            pytest.param(False, 10000, "", False, id="disabled"),
            pytest.param(None, 100, "", False, id="too-small"),
            pytest.param(None, 200 * 1024 * 1024, "", False, id="too-large"),
            pytest.param(None, 50 * 1024, "", True, id="normal"),
            pytest.param(None, 5 * 1024, ".txt", False, id="small-text"),
            pytest.param(None, 5 * 1024, ".json", False, id="small-json"),
            pytest.param(None, 50 * 1024, ".txt", True, id="large-text"),
        ],
    )
    def test_should_cache_file(self, enabled: bool | None, size: int, extension: str, expected: bool) -> None:
        config = CacheConfiguration({"cache_enabled": enabled} if enabled is not None else None)
        assert config.should_cache_file(size, extension) is expected

    @pytest.mark.parametrize(
        ("enabled", "size", "expected"),
        [
            pytest.param(False, 10000, "none", id="disabled"),
            pytest.param(None, 5 * 1024 * 1024, "quick", id="medium"),
            pytest.param(None, 50 * 1024 * 1024, "content", id="large"),
        ],
    )
    def test_get_cache_strategy(self, enabled: bool | None, size: int, expected: str) -> None:
        config = CacheConfiguration({"cache_enabled": enabled} if enabled is not None else None)
        assert config.get_cache_strategy(size) == expected

    @pytest.mark.parametrize(
        ("size", "expected"),
        [pytest.param(100 * 1024, False, id="small"), pytest.param(100 * 1024 * 1024, True, id="large")],
    )
    def test_get_performance_hint(self, size: int, expected: bool) -> None:
        hints = CacheConfiguration().get_performance_hint(size)
        assert hints["use_batch_operations"] is expected
        assert hints["parallel_io_recommended"] is expected
        assert hints["memory_streaming_recommended"] is expected


class TestConfigurationExtractor:
    """Tests for ConfigurationExtractor class."""

    @pytest.mark.parametrize("call_shape", ["positional", "keyword", "disabled", "no-path"])
    def test_extract(self, call_shape: str, tmp_path: Path) -> None:
        file_path = str(tmp_path / "file.pkl")
        cases: dict[str, tuple[tuple[Any, ...], dict[str, Any], str | None, bool]] = {
            "positional": ((file_path,), {}, file_path, True),
            "keyword": ((), {"path": file_path}, file_path, True),
            "disabled": ((file_path, {"cache_enabled": False}), {}, file_path, False),
            "no-path": ((), {}, None, True),
        }
        args, kwargs, expected_path, expected_enabled = cases[call_shape]
        config, path = ConfigurationExtractor().extract_fast(args, kwargs)
        assert path == expected_path
        assert config is not None
        assert config.enabled is expected_enabled

    def test_config_caching(self, tmp_path: Path) -> None:
        extractor = ConfigurationExtractor()
        config_dict = {"cache_enabled": True}
        config1, _ = extractor.extract_fast((str(tmp_path / "file1.pkl"), config_dict), {})
        config2, _ = extractor.extract_fast((str(tmp_path / "file2.pkl"), config_dict), {})
        assert config1 is config2

    def test_cleanup_config_cache(self, tmp_path: Path) -> None:
        extractor = ConfigurationExtractor()
        extractor._cache_expiry = 0  # Immediate expiry
        for i in range(25):
            extractor.extract_fast((str(tmp_path / f"file{i}.pkl"), {"id": i}), {})

        newest_timestamp = max(timestamp for _, timestamp in extractor._config_cache.values())
        extractor._cleanup_config_cache(current_time=newest_timestamp + 1.0)
        assert len(extractor._config_cache) <= 20


def test_get_config_extractor_returns_global_instance() -> None:
    extractor = get_config_extractor()
    assert extractor is get_config_extractor()
    assert isinstance(extractor, ConfigurationExtractor)
