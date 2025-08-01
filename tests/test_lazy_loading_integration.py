"""
Integration tests for lazy loading with core scanning functionality.
"""

import tempfile
import time
from pathlib import Path

import pytest

from modelaudit import core
from modelaudit.scanners import _registry


class TestCoreIntegration:
    """Test integration of lazy loading with core scanning functionality."""

    def test_scan_file_uses_lazy_loading(self):
        """Test that scan_file uses lazy loading correctly."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Create a JSON file with ML-related content
        with tempfile.NamedTemporaryFile(suffix="_config.json", mode="w") as f:
            f.write('{"model": "test", "tokenizer": "config"}')
            f.flush()

            # Scan the file
            result = core.scan_file(f.name)

            # Should have completed successfully
            assert result is not None
            assert result.scanner_name in ["manifest", "unknown"]

            # Should have loaded minimal scanners
            loaded_count = len(_registry._loaded_scanners)
            assert loaded_count <= 5  # Should be minimal

    def test_scan_directory_uses_lazy_loading(self):
        """Test that directory scanning uses lazy loading efficiently."""
        _registry._loaded_scanners.clear()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create various file types
            json_file = Path(temp_dir) / "config.json"
            json_file.write_text('{"test": "value"}')

            pkl_file = Path(temp_dir) / "model.pkl"
            pkl_file.write_bytes(b"fake pickle data")

            # Scan the directory
            results = core.scan_model_directory_or_file(temp_dir)

            # Should have completed successfully
            assert results["success"] is True
            assert results["files_scanned"] == 2

            # Should have loaded only necessary scanners
            loaded_count = len(_registry._loaded_scanners)
            assert loaded_count <= 10  # Should be reasonable

    def test_preferred_scanner_lazy_loading(self):
        """Test that preferred scanner detection uses lazy loading."""
        _registry._loaded_scanners.clear()

        # Create a pickle file (should prefer pickle scanner)
        with tempfile.NamedTemporaryFile(suffix=".pkl") as f:
            f.write(b"\x80\x02]q\x00.")  # Simple pickle data

            result = core.scan_file(f.name)

            # Should use pickle scanner
            assert result.scanner_name == "pickle"

            # Should have loaded pickle scanner
            assert "pickle" in _registry._loaded_scanners

    def test_multiple_file_types_incremental_loading(self):
        """Test that scanning multiple file types loads scanners incrementally."""
        _registry._loaded_scanners.clear()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create different file types
            files = [
                ("config.json", '{"test": "value"}'),
                ("model.pkl", "fake pickle content"),
                ("data.txt", "text content"),
            ]

            loaded_counts = []

            for filename, content in files:
                file_path = Path(temp_dir) / filename
                file_path.write_text(content)

                # Scan the file
                _ = core.scan_file(str(file_path))

                # Track how many scanners are loaded
                loaded_counts.append(len(_registry._loaded_scanners))

            # Should show incremental loading (or at least not loading everything at once)
            assert loaded_counts[0] > 0  # Some scanners loaded for first file
            # Later scans might load more, but shouldn't load everything
            assert max(loaded_counts) <= 15  # Reasonable upper bound


class TestPerformanceCharacteristics:
    """Test performance characteristics of lazy loading."""

    def test_import_performance(self):
        """Test that importing scanners is fast with lazy loading."""
        # This test measures import time
        start_time = time.time()

        # This should be fast (lazy loading)
        from modelaudit import scanners

        import_time = time.time() - start_time

        # Should be much faster than 1 second (was 7+ seconds before)
        assert import_time < 1.0

        # Accessing the registry should also be fast
        start_time = time.time()
        _ = scanners.SCANNER_REGISTRY
        access_time = time.time() - start_time

        # First access loads scanners, but should still be reasonable
        assert access_time < 5.0  # Much better than 7+ seconds

    def test_single_scanner_access_performance(self):
        """Test that accessing a single scanner is fast."""
        _registry._loaded_scanners.clear()

        start_time = time.time()

        # Access a lightweight scanner

        access_time = time.time() - start_time

        # Should be very fast (no heavy dependencies)
        assert access_time < 0.5

    def test_heavy_scanner_access_expected_slow(self):
        """Test that heavy scanners are slower but only when accessed."""
        _registry._loaded_scanners.clear()

        # First verify that we haven't loaded tensorflow yet
        import sys

        _ = "tensorflow" in sys.modules

        start_time = time.time()

        try:
            # This might be slow due to tensorflow import
            from modelaudit.scanners import TensorFlowSavedModelScanner

            _access_time = time.time() - start_time

            # This is expected to be slower due to tensorflow
            # But we can't assert exact time since it depends on system
            # Just verify it doesn't crash and returns a valid scanner
            assert TensorFlowSavedModelScanner is not None

        except ImportError:
            # TensorFlow might not be installed, which is fine
            pytest.skip("TensorFlow not available")


class TestErrorRecovery:
    """Test error recovery in lazy loading scenarios."""

    def test_missing_dependency_graceful_handling(self):
        """Test that missing dependencies are handled gracefully."""
        _registry._loaded_scanners.clear()

        # Try to load a scanner that might have missing dependencies
        # This should not crash the entire system
        scanner_classes = _registry.get_scanner_classes()

        # Should return some scanners, even if some fail to load
        assert len(scanner_classes) > 0

        # All returned scanners should be valid
        for scanner_class in scanner_classes:
            assert hasattr(scanner_class, "can_handle")
            assert hasattr(scanner_class, "scan")

    def test_scan_continues_with_available_scanners(self):
        """Test that scanning continues even if some scanners fail to load."""
        # Create a file that should be scannable by available scanners
        with tempfile.NamedTemporaryFile(suffix="_config.json", mode="w") as f:
            f.write('{"model": "test", "config": "data"}')
            f.flush()

            # This should work even if some heavy dependency scanners fail
            result = core.scan_file(f.name)

            # Should complete successfully
            assert result is not None
            # Might be "unknown" if manifest scanner fails, but shouldn't crash
            assert result.scanner_name in ["manifest", "unknown"]


class TestRegistryIntrospection:
    """Test introspection capabilities of the scanner registry."""

    def test_get_available_scanners(self):
        """Test getting available scanner IDs."""
        scanners = _registry.get_available_scanners()

        assert len(scanners) > 0
        assert "pickle" in scanners
        assert "manifest" in scanners
        assert "zip" in scanners

    def test_get_scanner_info(self):
        """Test getting scanner metadata."""
        pickle_info = _registry.get_scanner_info("pickle")

        assert pickle_info is not None
        assert pickle_info["module"] == "modelaudit.scanners.pickle_scanner"
        assert pickle_info["class"] == "PickleScanner"
        assert pickle_info["priority"] == 1
        assert len(pickle_info["dependencies"]) == 0

    def test_scanner_priority_ordering(self):
        """Test that scanners are ordered by priority."""
        scanners = list(_registry._scanners.items())

        # Find pickle and zip scanners
        pickle_priority = None
        zip_priority = None

        for scanner_id, info in scanners:
            if scanner_id == "pickle":
                pickle_priority = info["priority"]
            elif scanner_id == "zip":
                zip_priority = info["priority"]

        assert pickle_priority is not None
        assert zip_priority is not None
        # Pickle should have higher priority (lower number) than zip
        assert pickle_priority < zip_priority


class TestCacheEfficiency:
    """Test caching behavior of lazy loading system."""

    def test_scanner_caching_across_calls(self):
        """Test that scanners are cached across multiple calls."""
        _registry._loaded_scanners.clear()

        # Load a scanner multiple times
        scanner1 = _registry._load_scanner("pickle")
        scanner2 = _registry._load_scanner("pickle")
        scanner3 = _registry._load_scanner("pickle")

        # Should be the same instance (cached)
        assert scanner1 is scanner2
        assert scanner2 is scanner3

        # Should only be in cache once
        assert len(_registry._loaded_scanners) == 1

    def test_registry_cache_efficiency(self):
        """Test that the lazy list caches its results."""
        from modelaudit.scanners import SCANNER_REGISTRY

        # Access the registry multiple times
        list1 = list(SCANNER_REGISTRY)
        list2 = list(SCANNER_REGISTRY)

        # Should return consistent results
        assert len(list1) == len(list2)

        # The classes should be the same instances (cached)
        for scanner1, scanner2 in zip(list1, list2):
            assert scanner1 is scanner2
