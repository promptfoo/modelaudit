"""Performance benchmarks and tests for cache optimizations."""

import os
import tempfile
import time
from collections.abc import Callable, Iterable
from copy import deepcopy
from pathlib import Path
from typing import Any, TypeVar

import pytest

from modelaudit.cache.adaptive_cache_keys import AdaptiveCacheKeyGenerator, FileFingerprint
from modelaudit.cache.batch_operations import BatchCacheOperations
from modelaudit.cache.cache_manager import CacheManager
from modelaudit.cache.optimized_config import CacheConfiguration, ConfigurationExtractor
from modelaudit.cache.scan_results_cache import ScannedFileIdentity

T = TypeVar("T")


def _time_repeated(operation: Callable[[], T], iterations: int) -> tuple[T, float]:
    """Time exactly the requested number of complete operation batches."""
    assert iterations > 0
    start_time = time.perf_counter()
    for _ in range(iterations):
        result = operation()
    return result, time.perf_counter() - start_time


def _write_files(tmp_path: Path, contents: Iterable[tuple[str, bytes]]) -> list[str]:
    paths = []
    for name, content in contents:
        path = tmp_path / name
        path.write_bytes(content)
        paths.append(str(path))
    return paths


class MockScanner:
    """Mock scanner for testing configuration extraction."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config


@pytest.mark.performance
class TestCacheOptimizationPerformance:
    """Test performance improvements in cache optimizations."""

    def test_adaptive_cache_key_performance(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test adaptive cache key generation vs traditional approach."""
        key_generator = AdaptiveCacheKeyGenerator()
        test_files = _write_files(
            tmp_path,
            [
                ("small.txt", b"small content"),
                ("medium.bin", b"medium content" * 1000),
                ("large.bin", b"large content" * 100000),
            ],
        )
        stat_calls = {"adaptive": 0, "traditional": 0}
        current_label: str | None = None
        original_stat = os.stat

        def counting_stat(path: str) -> os.stat_result:
            if current_label is not None:
                stat_calls[current_label] += 1
            return original_stat(path)

        monkeypatch.setattr(os, "stat", counting_stat)

        def generate_adaptive_keys() -> list[str]:
            keys = []
            for file_path in test_files:
                stat_result = os.stat(file_path)
                key = key_generator.generate_key_with_stat_reuse(file_path, stat_result)
                keys.append(key)
            return keys

        def generate_traditional_keys() -> list[str]:
            keys = []
            for file_path in test_files:
                os.stat(file_path)  # Cache key generation
                os.stat(file_path)  # Cache validation
                key = key_generator.generate_key(file_path)
                keys.append(key)
            return keys

        current_label = "adaptive"
        adaptive_result, adaptive_time = _time_repeated(generate_adaptive_keys, 100)
        current_label = "traditional"
        traditional_result, traditional_time = _time_repeated(generate_traditional_keys, 100)
        current_label = None
        assert adaptive_result == traditional_result

        print(f"\nAdaptive key generation: {adaptive_time:.4f}s ({len(adaptive_result)} keys)")
        print(f"Traditional approach: {traditional_time:.4f}s")
        if adaptive_time > 0:
            print(f"Performance improvement: {traditional_time / adaptive_time:.1f}x")

        # Stat reuse should reduce syscalls even when timings are noisy.
        assert stat_calls["traditional"] >= stat_calls["adaptive"] * 2

    def test_batch_cache_operations_performance(self, tmp_path: Path) -> None:
        """Test batch cache operations functionality and basic performance."""
        cache_manager = CacheManager(str(tmp_path / "cache"), enabled=True)
        batch_ops = BatchCacheOperations(cache_manager)
        test_files = _write_files(
            tmp_path, ((f"test_file_{i}.bin", (f"test content {i}" * 100).encode()) for i in range(10))
        )
        test_results: list[tuple[str, dict[str, Any], int | None]] = []
        expected_file_identities: dict[str, ScannedFileIdentity] = {}
        assert cache_manager.cache is not None
        for i, file_path in enumerate(test_files):
            expected_file_identities[file_path] = cache_manager.cache.capture_file_identity(file_path)
            scan_result = {
                "scanner": "test",
                "success": True,
                "issues": [],
                "checks": [],
                "metadata": {"test": True, "file_index": i},
            }
            test_results.append((file_path, scan_result, 100))  # 100ms scan time

        expected_results = {file_path: deepcopy(scan_result) for file_path, scan_result, _ in test_results}
        stored_count = batch_ops.batch_store(test_results, expected_file_identities=expected_file_identities)
        print(f"Stored {stored_count} results out of {len(test_results)}")
        assert stored_count == 10
        assert batch_ops.batch_lookup(test_files) == expected_results

        def batch_lookup() -> dict[str, dict[str, Any] | None]:
            return batch_ops.batch_lookup(test_files)

        def individual_lookup() -> dict[str, dict[str, Any] | None]:
            results = {}
            for file_path in test_files:
                result = cache_manager.get_cached_result(file_path)
                results[file_path] = result
            return results

        batch_result, batch_time = _time_repeated(batch_lookup, 10)
        individual_result, individual_time = _time_repeated(individual_lookup, 10)
        print(f"\nBatch lookup: {batch_time:.4f}s")
        print(f"Individual lookup: {individual_time:.4f}s")
        assert len(batch_result) == len(individual_result) == 10
        assert batch_result == individual_result == expected_results
        print("Batch cache operations test completed successfully")

    def test_configuration_extraction_performance(self, tmp_path: Path) -> None:
        """Test optimized configuration extraction and identity reuse."""
        config_extractor = ConfigurationExtractor()
        # Keep this test focused on cache reuse rather than expiry behavior.
        config_extractor._cache_expiry = 3600.0
        test_configs: list[dict[str, Any]] = [
            {"cache_enabled": True, "cache_dir": str(tmp_path / "cache")},
            {"cache_enabled": False},
            {"max_cache_file_size": 50 * 1024 * 1024},
            {},
        ]
        test_cases: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        for config in test_configs:
            test_cases.extend(
                [
                    (("test_file.bin", config), {}),
                    (("another_file.pkl",), {"config": config}),
                    ((MockScanner(config), "scanner_file.h5"), {}),
                ]
            )
        expected_results = [
            (enabled, path)
            for enabled in (True, False, True, True)
            for path in ("test_file.bin", "another_file.pkl", "scanner_file.h5")
        ]

        def optimized_extraction() -> list[tuple[bool, str | None]]:
            results = []
            for args, kwargs in test_cases:
                cache_config, file_path = config_extractor.extract_fast(args, kwargs)
                if cache_config is not None:
                    results.append((cache_config.enabled, file_path))
                else:
                    results.append((False, file_path))
            return results

        # Prime both caches before measuring warm extraction.
        assert optimized_extraction() == expected_results
        expected_config_ids = {
            config_key: id(cache_config)
            for config_key, (cache_config, _created_at) in config_extractor._config_cache.items()
        }
        expected_result_keys = set(config_extractor._result_cache)
        assert len(expected_config_ids) == 4
        assert len(set(expected_config_ids.values())) == 4
        assert len(expected_result_keys) == 12

        opt_result, opt_time = _time_repeated(optimized_extraction, 200)
        assert opt_result == expected_results
        assert {
            config_key: id(cache_config)
            for config_key, (cache_config, _created_at) in config_extractor._config_cache.items()
        } == expected_config_ids
        assert set(config_extractor._result_cache) == expected_result_keys
        print(f"\nOptimized extraction: {opt_time:.4f}s ({len(opt_result)} configurations)")

    def test_file_fingerprint_performance(self, tmp_path: Path) -> None:
        """Test file fingerprint generation performance."""
        test_files = _write_files(
            tmp_path,
            ((f"test_{size_mb}mb.bin", b"X" * int(size_mb * 1024 * 1024)) for size_mb in [0.001, 0.1, 1, 5]),
        )

        def optimized_fingerprints() -> list[str]:
            fingerprints = []
            for file_path in test_files:
                stat_result = os.stat(file_path)
                fp = FileFingerprint.from_stat(file_path, stat_result)
                fingerprints.append(fp.quick_key())
            return fingerprints

        def traditional_fingerprints() -> list[str]:
            fingerprints = []
            for file_path in test_files:
                os.stat(file_path)
                fp = FileFingerprint.from_path(file_path)  # Another stat call
                fingerprints.append(fp.quick_key())
            return fingerprints

        opt_result, opt_time = _time_repeated(optimized_fingerprints, 300)
        traditional_result, traditional_time = _time_repeated(traditional_fingerprints, 300)
        assert opt_result == traditional_result
        print(f"\nOptimized fingerprints: {opt_time:.4f}s ({len(opt_result)} fingerprints)")
        print(f"Traditional fingerprints: {traditional_time:.4f}s")
        if opt_time > 0:
            print(f"Performance improvement: {traditional_time / opt_time:.1f}x")
            # Micro-benchmarks are noisy in shared CI/dev environments.
            # Guard against major regressions without requiring a strict speedup.
            assert opt_time <= traditional_time * 1.5

    def test_cache_configuration_decisions(self) -> None:
        """Test cache configuration decision making performance."""
        cache_config = CacheConfiguration(
            {"cache_enabled": True, "max_cache_file_size": 100 * 1024 * 1024, "min_cache_file_size": 1024}
        )
        test_cases = [
            (500, ".txt"),
            (50000, ".json"),
            (1024 * 1024, ".pkl"),
            (10 * 1024 * 1024, ".bin"),
            (500 * 1024 * 1024, ".h5"),
        ]

        def make_cache_decisions() -> list[tuple[bool, str]]:
            decisions = []
            for file_size, file_ext in test_cases:
                should_cache = cache_config.should_cache_file(file_size, file_ext)
                strategy = cache_config.get_cache_strategy(file_size, file_ext)
                decisions.append((should_cache, strategy))
            return decisions

        iterations = 500
        result, decision_time = _time_repeated(make_cache_decisions, iterations)
        print(f"Actual decisions: {result}")
        assert [should_cache for should_cache, _ in result] == [False, True, True, True, False]
        total_decisions = len(result) * iterations
        print(f"\nMade {total_decisions} cache decisions in {decision_time:.4f}s")
        print(f"Decisions per second: {total_decisions / decision_time:.0f}")
        assert decision_time < 1.0


class TestCacheOptimizationCorrectness:
    """Test correctness of cache optimizations outside performance selection."""

    def test_adaptive_key_generator_consistency(self, tmp_path: Path) -> None:
        key_generator = AdaptiveCacheKeyGenerator()
        (test_file,) = _write_files(tmp_path, [("test.bin", b"test content")])
        key1 = key_generator.generate_key(test_file)
        key2 = key_generator.generate_key_with_stat_reuse(test_file, os.stat(test_file))
        assert key1 == key2

    def test_batch_operations_equivalence(self, tmp_path: Path) -> None:
        """Tiny text files must miss in both batch and individual lookups."""
        with tempfile.TemporaryDirectory(dir=tmp_path) as temp_dir:
            cache_root = Path(temp_dir)
            cache_manager = CacheManager(str(cache_root / "cache"), enabled=True)
            batch_ops = BatchCacheOperations(cache_manager)
            test_files = _write_files(cache_root, ((f"test_{i}.txt", f"content {i}".encode()) for i in range(5)))
            batch_results = batch_ops.batch_lookup(test_files)
            individual_results = {file_path: cache_manager.get_cached_result(file_path) for file_path in test_files}
            assert batch_results == individual_results
            assert set(batch_results) == set(test_files)
            for result in batch_results.values():
                assert result is None

    def test_optimized_config_extraction_correctness(self, tmp_path: Path) -> None:
        extractor = ConfigurationExtractor()
        expected_cache_dir = str(tmp_path / "cache")
        test_config = {"cache_enabled": True, "cache_dir": expected_cache_dir, "max_cache_file_size": 1000000}
        test_cases: list[tuple[tuple[Any, ...], dict[str, Any]]] = [
            (("file.bin", test_config), {}),
            (("file.bin",), {"config": test_config}),
            ((MockScanner(test_config), "file.bin"), {}),
        ]
        for args, kwargs in test_cases:
            cache_config, file_path = extractor.extract_fast(args, kwargs)
            assert cache_config is not None
            assert cache_config.enabled is True
            assert cache_config.cache_dir == expected_cache_dir
            assert cache_config.max_file_size == 1000000
            assert file_path == "file.bin"
