"""
Integration tests for lazy loading with core scanning functionality.
"""

import tempfile
import time
from pathlib import Path

import pytest

from modelaudit import core
from modelaudit.scanners import _registry

MAX_SCANNERS_FOR_SINGLE_FILE_SCAN = 5
MAX_SCANNERS_FOR_DIRECTORY_SCAN = 10
MAX_SCANNERS_FOR_INCREMENTAL_SCAN = 15


class TestCoreIntegration:
    """Test integration of lazy loading with core scanning functionality."""

    def test_scan_file_uses_lazy_loading(self) -> None:
        """Test that scan_file uses lazy loading correctly."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Create a JSON file with ML-related content
        with tempfile.NamedTemporaryFile(suffix="_config.json", mode="w", delete=False) as f:
            f.write('{"model": "test", "tokenizer": "config"}')
            f.flush()
            f.close()  # Close file before scanning (required on Windows to allow deletion)

            try:
                # Scan the file
                result = core.scan_file(f.name)

                # Should have completed successfully
                assert result is not None
                assert result.scanner_name in ["manifest", "unknown"]

                # Should have loaded minimal scanners
                loaded_count = len(_registry._loaded_scanners)
                assert loaded_count <= MAX_SCANNERS_FOR_SINGLE_FILE_SCAN
            finally:
                Path(f.name).unlink(missing_ok=True)

    def test_scan_directory_uses_lazy_loading(self) -> None:
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

            # This test verifies lazy loading, not the security verdict. The
            # non-pickle model.pkl now (correctly) produces fail-closed spoofing
            # warnings, so assert the scan ran over both files instead of demanding
            # success, which is no longer a valid proxy for "scan completed".
            assert results["files_scanned"] == 2
            assert results["has_errors"] is False

            # Should have loaded only necessary scanners
            loaded_count = len(_registry._loaded_scanners)
            assert loaded_count <= MAX_SCANNERS_FOR_DIRECTORY_SCAN

    def test_preferred_scanner_lazy_loading(self, tmp_path: Path) -> None:
        """Test that preferred scanner detection uses lazy loading."""
        _registry._loaded_scanners.clear()

        # Create a pickle file (should prefer pickle scanner)
        file_path = tmp_path / "model.pkl"
        file_path.write_bytes(b"\x80\x02]q\x00.")  # Simple pickle data

        result = core.scan_file(str(file_path))

        # Should use pickle scanner
        assert result.scanner_name == "pickle"

        # Should have loaded pickle scanner
        assert "pickle" in _registry._loaded_scanners

    def test_multiple_file_types_incremental_loading(self) -> None:
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
            assert max(loaded_counts) <= MAX_SCANNERS_FOR_INCREMENTAL_SCAN


class TestPerformanceCharacteristics:
    """Test performance characteristics of lazy loading."""

    def test_import_performance(self) -> None:
        """Test that importing scanners is fast with lazy loading."""
        # This test measures import time
        start_time = time.time()

        # This should be fast (lazy loading)
        from modelaudit import scanners

        import_time = time.time() - start_time

        # The historical eager-loading baseline was 7+ seconds; 1 second leaves
        # room for local and CI variance while still catching a real regression.
        assert import_time < 1.0

        # Accessing the registry should also be fast
        start_time = time.time()
        _ = scanners.SCANNER_REGISTRY
        access_time = time.time() - start_time

        # First access performs one-time lazy-loading work, so keep this looser
        # than the import guard while still catching a return to the old 7+ second path.
        assert access_time < 5.0

    def test_single_scanner_access_performance(self) -> None:
        """Test that accessing a single scanner is fast."""
        _registry._loaded_scanners.clear()

        start_time = time.time()
        from modelaudit.scanners import PickleScanner

        access_time = time.time() - start_time

        # Should be very fast (no heavy dependencies)
        assert access_time < 0.5
        assert _registry._loaded_scanners["pickle"] is PickleScanner

    def test_heavy_scanner_loads_only_when_accessed(self) -> None:
        """Heavy scanners should remain unloaded until their class is requested."""
        _registry._loaded_scanners.clear()
        assert "tf_savedmodel" not in _registry._loaded_scanners

        try:
            from modelaudit.scanners import TensorFlowSavedModelScanner

        except ImportError:
            # TensorFlow might not be installed, which is fine
            pytest.skip("TensorFlow not available")

        assert _registry._loaded_scanners["tf_savedmodel"] is TensorFlowSavedModelScanner


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
        with tempfile.NamedTemporaryFile(suffix="_config.json", mode="w", delete=False) as f:
            f.write('{"model": "test", "config": "data"}')
            f.flush()
            f.close()  # Close file before scanning (required on Windows to allow deletion)

            try:
                # This should work even if some heavy dependency scanners fail
                result = core.scan_file(f.name)

                # Should complete successfully
                assert result is not None
                # Might be "unknown" if manifest scanner fails, but shouldn't crash
                assert result.scanner_name in ["manifest", "unknown"]
            finally:
                Path(f.name).unlink(missing_ok=True)


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
        for scanner1, scanner2 in zip(list1, list2, strict=False):
            assert scanner1 is scanner2
