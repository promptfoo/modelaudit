from __future__ import annotations

import json
import os
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
from modelaudit.cache.scan_results_cache import ScanResultsCache
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


def test_cached_scan_skips_persisting_scan_timed_out_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scan timed out: metadata helper exceeded limit", "severity": "warning"}],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_package_not_installed_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [
                {
                    "message": "paddlepaddle package not installed. Install with 'pip install paddlepaddle'",
                    "status": "failed",
                }
            ],
            "issues": [],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_os_level_errors(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "No such file or directory while opening sidecar", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


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


@pytest.mark.parametrize(
    "message",
    [
        "Associated .bin weights file not found",
        "Not a valid zip file: /tmp/example.zip",
    ],
)
def test_cached_scan_persists_deterministic_validation_findings(tmp_path: Path, message: str) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": message, "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == second
    assert calls["count"] == 1
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 1


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


def test_get_cache_manager_reenables_cache_subsystems(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    disabled_manager = get_cache_manager(str(cache_dir), enabled=False)
    assert disabled_manager.enabled is False

    enabled_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(enabled_manager)

    assert enabled_manager.enabled is True
    assert enabled_manager.cache is not None
    assert enabled_manager.key_generator is not None
    assert batch_ops.get_batch_stats()["enabled"] is True


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


def test_batch_lookup_rejects_stale_cache_entries(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache_manager.store_result(str(file_path), expected, 10, version_context=version_context) is True
    assert cache_manager.cache is not None

    cache_key = cache_manager.cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache_manager.cache._get_cache_file_path(cache_key)
    cache_entry = json.loads(cache_file_path.read_text(encoding="utf-8"))
    cache_entry["cache_metadata"]["scanned_at"] = time.time() - (31 * 24 * 60 * 60)
    cache_file_path.write_text(json.dumps(cache_entry, indent=2), encoding="utf-8")

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] is None
    assert not cache_file_path.exists()


def test_batch_store_skips_operational_failures(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)

    stored_count = batch_ops.batch_store(
        [
            (
                str(file_path),
                {
                    "scanner": "test",
                    "success": False,
                    "issues": [{"message": "Scan timed out: metadata helper exceeded limit", "severity": "warning"}],
                    "checks": [],
                    "metadata": {},
                },
                10,
            )
        ]
    )

    assert stored_count == 0
    assert cache_manager.get_stats()["total_entries"] == 0


def test_batch_store_counts_only_persisted_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)

    assert cache_manager.cache is not None
    monkeypatch.setattr(cache_manager.cache, "_generate_cache_key", lambda *args, **kwargs: None)

    stored_count = batch_ops.batch_store(
        [
            (
                str(file_path),
                {
                    "scanner": "test",
                    "success": True,
                    "issues": [],
                    "checks": [],
                    "metadata": {},
                },
                10,
            )
        ]
    )

    assert stored_count == 0
    assert cache_manager.get_stats()["total_entries"] == 0


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


def test_cache_key_is_none_when_scanner_versions_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When scanner versions cannot be resolved, caching must be disabled
    entirely to avoid key collisions between different scanner versions."""
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})

    def raise_scanner_versions() -> dict[str, str]:
        raise RuntimeError("scanner registry unavailable")

    monkeypatch.setattr(cache, "_get_scanner_versions", raise_scanner_versions)

    key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert key is None


def test_cache_key_generation_avoids_full_hash_for_medium_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="medium.bin")
    file_path.write_bytes(b"x" * (2 * 1024 * 1024))
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))

    def fail_hash(_: str) -> str:
        raise AssertionError("content hash should not be used for medium-file cache lookups")

    monkeypatch.setattr(cache.key_generator.hasher, "hash_file", fail_hash)

    cache_key = cache.generate_cache_key(str(file_path), version_context=build_cache_version_context({"timeout": 30}))

    assert cache_key is not None


def test_same_size_rewrite_with_high_resolution_mtime_invalidates_cache(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="medium.bin")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache.store_result(str(file_path), expected, 10, version_context=version_context) is True

    original_stat = file_path.stat()
    file_path.write_bytes(b"y" * 2048)
    base_second_ns = (original_stat.st_mtime_ns // 1_000_000_000) * 1_000_000_000
    original_offset_ns = original_stat.st_mtime_ns % 1_000_000_000
    new_offset_ns = 123_456_789 if original_offset_ns != 123_456_789 else 123_456_790
    os.utime(file_path, ns=(original_stat.st_atime_ns, base_second_ns + new_offset_ns))

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)

    assert cached_result is None


def test_same_size_rewrite_with_restored_mtime_invalidates_cache(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="small.bin")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache.store_result(str(file_path), expected, 10, version_context=version_context) is True

    original_stat = file_path.stat()
    file_path.write_bytes(b"y" * 2048)
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)

    assert cached_result is None
