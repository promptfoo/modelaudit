"""Performance benchmarks and tests for cache optimizations."""

import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache.batch_operations import BatchCacheOperations
from modelaudit.cache.cache_manager import CacheManager
from modelaudit.cache.optimized_config import CacheConfiguration, ConfigurationExtractor
from modelaudit.cache.smart_cache_keys import FileFingerprint, SmartCacheKeyGenerator


@pytest.mark.performance
class TestCacheOptimizationPerformance:
    """Test performance improvements in cache optimizations."""

    def test_smart_cache_key_performance(self):
        """Test smart cache key generation vs traditional approach."""
        key_generator = SmartCacheKeyGenerator()

        # Create test files of various sizes
        test_files = []
        with tempfile.TemporaryDirectory() as temp_dir:
            # Small file
            small_file = Path(temp_dir) / "small.txt"
            small_file.write_text("small content")
            test_files.append(str(small_file))

            # Medium file
            medium_file = Path(temp_dir) / "medium.bin"
            medium_file.write_bytes(b"medium content" * 1000)  # ~14KB
            test_files.append(str(medium_file))

            # Large file
            large_file = Path(temp_dir) / "large.bin"
            large_file.write_bytes(b"large content" * 100000)  # ~1.3MB
            test_files.append(str(large_file))

            def generate_smart_keys():
                """Generate keys using optimized smart generation."""
                keys = []
                for file_path in test_files:
                    stat_result = os.stat(file_path)
                    key = key_generator.generate_key_with_stat_reuse(file_path, stat_result)
                    keys.append(key)
                return keys

            def generate_traditional_keys():
                """Generate keys using traditional approach (multiple stat calls)."""
                keys = []
                for file_path in test_files:
                    # Simulate multiple stat calls like traditional approach
                    os.stat(file_path)  # Cache key generation
                    os.stat(file_path)  # Cache validation
                    key = key_generator.generate_key(file_path)
                    keys.append(key)
                return keys

            # Time smart key generation
            iterations = 100
            start_time = time.time()
            for _ in range(iterations):
                smart_result = generate_smart_keys()
            smart_time = time.time() - start_time

            # Time traditional approach
            start_time = time.time()
            for _ in range(iterations):
                traditional_result = generate_traditional_keys()
            traditional_time = time.time() - start_time

            # Verify results are equivalent
            assert len(smart_result) == len(traditional_result)
            assert smart_result == traditional_result

            print(f"\nSmart key generation: {smart_time:.4f}s ({len(smart_result)} keys)")
            print(f"Traditional approach: {traditional_time:.4f}s")

            if smart_time > 0:
                improvement = traditional_time / smart_time
                print(f"Performance improvement: {improvement:.1f}x")
                assert improvement > 1.1  # Should be at least 10% faster

    def test_batch_cache_operations_performance(self):
        """Test batch cache operations functionality and basic performance."""

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir) / "cache"
            cache_manager = CacheManager(str(cache_dir), enabled=True)
            batch_ops = BatchCacheOperations(cache_manager)

            # Create test files
            test_files = []
            test_results: list[tuple[str, dict[str, Any], int | None]] = []

            for i in range(10):  # Reduced number for faster test
                file_path = Path(temp_dir) / f"test_file_{i}.bin"
                content = f"test content {i}" * 100  # ~1.3KB each
                file_path.write_text(content)
                test_files.append(str(file_path))

                # Create mock scan result
                scan_result = {
                    "scanner": "test",
                    "success": True,
                    "issues": [],
                    "checks": [],
                    "metadata": {"test": True},
                }
                test_results.append((str(file_path), scan_result, 100))  # 100ms scan time

            # Test batch store operations
            stored_count = batch_ops.batch_store(test_results)
            print(f"Stored {stored_count} results out of {len(test_results)}")
            assert stored_count > 0  # Should store some results

            # Test batch lookup operations
            batch_result = batch_ops.batch_lookup(test_files)
            assert len(batch_result) == len(test_files)

            # Test that batch operations complete without errors
            def batch_lookup():
                return batch_ops.batch_lookup(test_files)

            def individual_lookup():
                results = {}
                for file_path in test_files:
                    result = cache_manager.get_cached_result(file_path)
                    results[file_path] = result
                return results

            # Basic timing test (reduced iterations)
            iterations = 10
            start_time = time.time()
            for _ in range(iterations):
                batch_result = batch_lookup()
            batch_time = time.time() - start_time

            start_time = time.time()
            for _ in range(iterations):
                individual_result = individual_lookup()
            individual_time = time.time() - start_time

            print(f"\nBatch lookup: {batch_time:.4f}s")
            print(f"Individual lookup: {individual_time:.4f}s")

            # Basic functionality test
            assert len(batch_result) == len(test_files)
            assert len(individual_result) == len(test_files)

            print("Batch cache operations test completed successfully")

    def test_configuration_extraction_performance(self):
        """Test optimized configuration extraction."""
        config_extractor = ConfigurationExtractor()

        # Test configurations
        test_configs = [
            {"cache_enabled": True, "cache_dir": "/tmp/cache"},
            {"cache_enabled": False},
            {"max_cache_file_size": 50 * 1024 * 1024},  # 50MB
            {},  # Default config
        ]

        # Flatten test cases
        test_cases = []
        for config in test_configs:
            test_args_kwargs = [
                (("test_file.bin", config), {}),
                (("another_file.pkl",), {"config": config}),
                ((MockScanner(config), "scanner_file.h5"), {}),
            ]
            for args, kwargs in test_args_kwargs:
                test_cases.append((args, kwargs))

        def optimized_extraction():
            """Optimized configuration extraction."""
            results = []
            for args, kwargs in test_cases:
                cache_config, file_path = config_extractor.extract_fast(args, kwargs)
                if cache_config is not None:
                    results.append((cache_config.enabled, file_path))
                else:
                    results.append((False, file_path))
            return results

        def traditional_extraction():
            """Traditional configuration extraction (simulated)."""
            results = []
            for args, kwargs in test_cases:
                # Simulate repeated parsing overhead
                config_dict, file_path = _extract_config_and_path_slow(args, kwargs)
                cache_config = CacheConfiguration(config_dict)
                results.append((cache_config.enabled, file_path))
            return results

        # Time optimized extraction
        iterations = 200
        start_time = time.time()
        for _ in range(iterations):
            opt_result = optimized_extraction()
        opt_time = time.time() - start_time

        # Time traditional approach for comparison
        start_time = time.time()
        for _ in range(iterations):
            traditional_result = traditional_extraction()
        traditional_time = time.time() - start_time

        # Verify results are equivalent
        assert len(opt_result) == len(traditional_result)
        assert opt_result == traditional_result

        print(f"\nOptimized extraction: {opt_time:.4f}s ({len(opt_result)} configurations)")
        print(f"Traditional extraction: {traditional_time:.4f}s")

        if opt_time > 0:
            improvement = traditional_time / opt_time
            print(f"Performance improvement: {improvement:.1f}x")
            assert improvement > 1.1  # Should be at least 10% faster

    def test_file_fingerprint_performance(self):
        """Test file fingerprint generation performance."""

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_files = []
            for size_mb in [0.001, 0.1, 1, 5]:  # Various sizes (reduced for speed)
                file_path = Path(temp_dir) / f"test_{size_mb}mb.bin"
                content_size = int(size_mb * 1024 * 1024)
                content = b"X" * content_size
                file_path.write_bytes(content)
                test_files.append(str(file_path))

            def optimized_fingerprints():
                """Generate fingerprints with stat reuse."""
                fingerprints = []
                for file_path in test_files:
                    stat_result = os.stat(file_path)
                    fp = FileFingerprint.from_stat(file_path, stat_result)
                    fingerprints.append(fp.quick_key())
                return fingerprints

            def traditional_fingerprints():
                """Generate fingerprints with multiple stat calls."""
                fingerprints = []
                for file_path in test_files:
                    # Simulate multiple stat calls
                    os.stat(file_path)
                    fp = FileFingerprint.from_path(file_path)  # Another stat call
                    fingerprints.append(fp.quick_key())
                return fingerprints

            # Time optimized approach
            iterations = 100
            start_time = time.time()
            for _ in range(iterations):
                opt_result = optimized_fingerprints()
            opt_time = time.time() - start_time

            # Time traditional approach
            start_time = time.time()
            for _ in range(iterations):
                traditional_result = traditional_fingerprints()
            traditional_time = time.time() - start_time

            # Verify results are equivalent
            assert len(opt_result) == len(traditional_result)
            assert opt_result == traditional_result

            print(f"\nOptimized fingerprints: {opt_time:.4f}s ({len(opt_result)} fingerprints)")
            print(f"Traditional fingerprints: {traditional_time:.4f}s")

            if opt_time > 0:
                improvement = traditional_time / opt_time
                print(f"Performance improvement: {improvement:.1f}x")
                assert improvement > 1.0  # Should be at least as fast

    def test_cache_configuration_decisions(self):
        """Test cache configuration decision making performance."""
        cache_config = CacheConfiguration(
            {
                "cache_enabled": True,
                "max_cache_file_size": 100 * 1024 * 1024,  # 100MB
                "min_cache_file_size": 1024,  # 1KB
            }
        )

        # Test file characteristics
        test_cases = [
            (500, ".txt"),  # Small text file
            (50000, ".json"),  # Medium JSON file
            (1024 * 1024, ".pkl"),  # 1MB pickle file
            (10 * 1024 * 1024, ".bin"),  # 10MB binary file
            (500 * 1024 * 1024, ".h5"),  # 500MB HDF5 file (too large)
        ]

        def make_cache_decisions():
            """Make cache decisions with LRU caching."""
            decisions = []
            for file_size, file_ext in test_cases:
                should_cache = cache_config.should_cache_file(file_size, file_ext)
                strategy = cache_config.get_cache_strategy(file_size, file_ext)
                decisions.append((should_cache, strategy))
            return decisions

        # Time decision making (benefits from LRU cache)
        iterations = 500
        start_time = time.time()
        for _ in range(iterations):
            result = make_cache_decisions()
        decision_time = time.time() - start_time

        # Verify basic functionality - check the actual thresholds
        print(f"Actual decisions: {result}")

        # Basic checks that should be true
        assert not result[0][0]  # 500 bytes - too small
        assert result[1][0]  # 50KB - should cache
        assert result[2][0]  # 1MB - should cache
        assert result[3][0]  # 10MB - should cache
        assert not result[4][0]  # 500MB - too large

        total_decisions = len(result) * iterations
        print(f"\nMade {total_decisions} cache decisions in {decision_time:.4f}s")
        print(f"Decisions per second: {total_decisions / decision_time:.0f}")

        # Should be very fast due to LRU caching
        assert decision_time < 1.0  # Should complete in under 1 second


class MockScanner:
    """Mock scanner for testing configuration extraction."""

    def __init__(self, config):
        self.config = config


def _extract_config_and_path_slow(args, kwargs):
    """Slow version of config extraction for comparison."""
    config = None
    file_path = None

    if args:
        if hasattr(args[0], "__dict__") and hasattr(args[0], "config"):
            # Method call
            raw_config = getattr(args[0], "config", {})
            # Simulate slow parsing
            config = dict(raw_config) if raw_config else {}
            file_path = args[1] if len(args) > 1 else kwargs.get("path")
        else:
            # Function call
            file_path = args[0]
            raw_config = args[1] if len(args) > 1 else kwargs.get("config")
            config = dict(raw_config) if raw_config else {}
    else:
        file_path = kwargs.get("path")
        raw_config = kwargs.get("config")
        config = dict(raw_config) if raw_config else {}

    return config, file_path


class TestCacheOptimizationCorrectness:
    """Test correctness of cache optimizations."""

    def test_smart_key_generator_consistency(self):
        """Test that smart key generator produces consistent results."""
        key_generator = SmartCacheKeyGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.bin"
            test_file.write_bytes(b"test content")

            # Generate key multiple ways
            key1 = key_generator.generate_key(str(test_file))

            stat_result = os.stat(str(test_file))
            key2 = key_generator.generate_key_with_stat_reuse(str(test_file), stat_result)

            # Should produce the same key
            assert key1 == key2

    def test_batch_operations_equivalence(self):
        """Test that batch operations produce same results as individual operations."""

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir) / "cache"
            cache_manager = CacheManager(str(cache_dir), enabled=True)
            batch_ops = BatchCacheOperations(cache_manager)

            # Create test files
            test_files = []
            for i in range(5):
                file_path = Path(temp_dir) / f"test_{i}.txt"
                file_path.write_text(f"content {i}")
                test_files.append(str(file_path))

            # Batch lookup (should all be misses initially)
            batch_results = batch_ops.batch_lookup(test_files)

            # Individual lookups
            individual_results: dict[str, dict[str, Any] | None] = {}
            for file_path_str in test_files:
                result = cache_manager.get_cached_result(file_path_str)
                individual_results[file_path_str] = result

            # Should match
            assert batch_results == individual_results

            # All should be None (cache misses)
            for result in batch_results.values():
                assert result is None

    def test_optimized_config_extraction_correctness(self):
        """Test that optimized config extraction maintains correctness."""
        extractor = ConfigurationExtractor()

        test_config = {"cache_enabled": True, "cache_dir": "/tmp/test", "max_cache_file_size": 1000000}

        # Test various argument patterns
        test_cases = [
            (("file.bin", test_config), {}),
            (("file.bin",), {"config": test_config}),
            ((MockScanner(test_config), "file.bin"), {}),
        ]

        for args, kwargs in test_cases:
            cache_config, file_path = extractor.extract_fast(args, kwargs)

            assert cache_config is not None, "cache_config should not be None"
            assert cache_config.enabled == test_config["cache_enabled"]
            assert cache_config.cache_dir == test_config["cache_dir"]
            assert cache_config.max_file_size == test_config["max_cache_file_size"]
            assert file_path == "file.bin"
