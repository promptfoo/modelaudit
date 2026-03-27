from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.batch_operations import BatchCacheOperations
from modelaudit.cache.optimized_config import (
    ConfigurationExtractor,
    build_cache_version_context,
    get_config_extractor,
)
from modelaudit.config.rule_config import ModelAuditConfig, get_config, reset_config, set_config
from modelaudit.utils.helpers.cache_decorator import cached_scan


@pytest.fixture(autouse=True)
def reset_cache_state() -> Iterator[None]:
    reset_cache_manager()
    reset_config()
    extractor = get_config_extractor()
    extractor._config_cache.clear()
    extractor._result_cache.clear()
    extractor._last_cleanup = time.monotonic()
    yield
    reset_cache_manager()
    reset_config()
    extractor._config_cache.clear()
    extractor._result_cache.clear()
    extractor._last_cleanup = time.monotonic()


def _make_cacheable_file(tmp_path: Path, name: str = "model.bin") -> Path:
    file_path = tmp_path / name
    file_path.write_bytes(b"x" * 2048)
    return file_path


def test_cached_scan_persists_miss_and_hits_on_second_call(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"call_count": calls["count"], "timeout": config["timeout"]}

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == {"call_count": 1, "timeout": 30}
    assert second == first
    assert calls["count"] == 1

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 1


def test_cached_scan_invalidates_on_material_scan_config_change(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"call_count": calls["count"], "timeout": config["timeout"]}

    base_config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    changed_config = {**base_config, "timeout": 5}

    first = scan(str(file_path), base_config)
    second = scan(str(file_path), changed_config)
    third = scan(str(file_path), changed_config)

    assert first == {"call_count": 1, "timeout": 30}
    assert second == {"call_count": 2, "timeout": 5}
    assert third == second
    assert calls["count"] == 2


def test_cached_scan_invalidates_on_rule_config_change(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {"call_count": calls["count"], "suppress_count": len(get_config().suppress)}

    first = scan(str(file_path), config)
    set_config(ModelAuditConfig(suppress={"S710"}))
    second = scan(str(file_path), config)
    third = scan(str(file_path), config)

    assert first == {"call_count": 1, "suppress_count": 0}
    assert second == {"call_count": 2, "suppress_count": 1}
    assert third == second
    assert calls["count"] == 2


def test_cached_scan_skips_persisting_operational_failures(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scan timeout after 1 seconds", "severity": "warning"}],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_operational_failures_from_checks(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [{"message": "Scan timeout after 1 seconds", "status": "failed"}],
            "issues": [],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_scanning_error_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scanning error: failed to read shard 0", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_memory_mapped_scan_errors(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [{"message": "Memory-mapped scan error: invalid mapping", "status": "failed"}],
            "issues": [],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_configuration_extractor_rebuilds_cached_config_after_mutation() -> None:
    extractor = ConfigurationExtractor()
    config = {"cache_enabled": True, "timeout": 30}

    first, _ = extractor.extract_fast(("file.bin", config), {})
    config["timeout"] = 5
    second, _ = extractor.extract_fast(("file.bin", config), {})

    assert first is not None
    assert second is not None
    assert first is not second
    assert first.get_version_context() != second.get_version_context()


def test_get_cache_manager_reinitializes_for_new_cache_dir(tmp_path: Path) -> None:
    first = get_cache_manager(str(tmp_path / "cache-a"), enabled=True)
    second = get_cache_manager(str(tmp_path / "cache-b"), enabled=True)

    assert first is not second
    assert second.cache is not None
    assert second.cache.cache_dir == tmp_path / "cache-b"


def test_batch_lookup_returns_cached_entries(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    cache_manager.store_result(
        str(file_path),
        expected,
        10,
        version_context=version_context,
    )

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] == expected


def test_cache_entry_omits_raw_version_context(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    version_context = build_cache_version_context({"timeout": 30, "api_token": "super-secret-token"})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    cache_manager.store_result(
        str(file_path),
        expected,
        10,
        version_context=version_context,
    )

    assert cache_manager.cache is not None
    cache_key = cache_manager.cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache_manager.cache._get_cache_file_path(cache_key)

    raw_cache_text = cache_file_path.read_text(encoding="utf-8")
    cache_entry = json.loads(raw_cache_text)

    assert "super-secret-token" not in raw_cache_text
    assert "version_context" not in cache_entry["version_info"]
