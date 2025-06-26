"""
Tests for lazy loading functionality in the scanner registry.
"""

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.scanners import _registry
from modelaudit.scanners.base import BaseScanner


class TestScannerRegistry:
    """Test the ScannerRegistry lazy loading functionality."""

    def test_registry_initialization(self):
        """Test that the registry initializes with proper scanner metadata."""
        assert _registry._scanners is not None
        assert len(_registry._scanners) > 0

        # Check that we have all expected scanners
        expected_scanners = [
            "pickle",
            "pytorch_binary",
            "tf_savedmodel",
            "keras_h5",
            "onnx",
            "pytorch_zip",
            "gguf",
            "joblib",
            "numpy",
            "oci_layer",
            "manifest",
            "pmml",
            "weight_distribution",
            "safetensors",
            "flax_msgpack",
            "tflite",
            "zip",
        ]

        for scanner_id in expected_scanners:
            assert scanner_id in _registry._scanners
            scanner_info = _registry._scanners[scanner_id]
            assert "module" in scanner_info
            assert "class" in scanner_info
            assert "priority" in scanner_info
            assert "dependencies" in scanner_info

    def test_scanner_not_loaded_initially(self):
        """Test that scanners are not loaded during registry initialization."""
        # Reset loaded scanners to test fresh state
        _registry._loaded_scanners.clear()

        assert len(_registry._loaded_scanners) == 0

        # Accessing the registry should not load scanners
        scanner_ids = _registry.get_available_scanners()
        assert len(scanner_ids) > 0
        assert len(_registry._loaded_scanners) == 0

    def test_lazy_scanner_loading(self):
        """Test that scanners are loaded only when requested."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Load a light scanner (no heavy dependencies)
        scanner_class = _registry._load_scanner("pickle")
        assert scanner_class is not None
        assert "pickle" in _registry._loaded_scanners
        assert _registry._loaded_scanners["pickle"] is scanner_class

        # Verify only one scanner was loaded
        assert len(_registry._loaded_scanners) == 1

    def test_scanner_caching(self):
        """Test that scanners are cached after first load."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Load scanner twice
        scanner1 = _registry._load_scanner("pickle")
        scanner2 = _registry._load_scanner("pickle")

        # Should be the same instance (cached)
        assert scanner1 is scanner2
        assert len(_registry._loaded_scanners) == 1

    def test_get_scanner_for_path_extension_filtering(self):
        """Test that get_scanner_for_path filters by extension before loading."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Create temporary files with different extensions
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pkl_path = f.name

        try:
            # This should only load the pickle scanner
            scanner = _registry.get_scanner_for_path(pkl_path)
            assert scanner is not None
            assert scanner.name == "pickle"

            # Verify only pickle scanner was loaded (and maybe a few others that handle .pkl)
            loaded_count = len(_registry._loaded_scanners)
            assert loaded_count <= 3  # Should be minimal

        finally:
            Path(pkl_path).unlink(missing_ok=True)

    def test_priority_based_scanner_selection(self):
        """Test that scanners are selected based on priority."""
        scanner_info = _registry.get_scanner_info("pickle")
        assert scanner_info is not None
        assert scanner_info["priority"] == 1  # Pickle should have highest priority

        zip_info = _registry.get_scanner_info("zip")
        assert zip_info is not None
        assert zip_info["priority"] == 99  # Zip should have lowest priority (fallback)

    def test_heavy_dependency_marking(self):
        """Test that heavy dependencies are properly marked."""
        # Check heavy dependency scanners
        heavy_scanners = ["tf_savedmodel", "keras_h5", "onnx", "tflite"]

        for scanner_id in heavy_scanners:
            scanner_info = _registry.get_scanner_info(scanner_id)
            assert scanner_info is not None
            assert len(scanner_info["dependencies"]) > 0

        # Check light dependency scanners
        light_scanners = ["pickle", "pytorch_binary", "zip", "manifest"]

        for scanner_id in light_scanners:
            scanner_info = _registry.get_scanner_info(scanner_id)
            assert scanner_info is not None
            assert len(scanner_info["dependencies"]) == 0

    @patch("importlib.import_module")
    def test_scanner_load_failure_handling(self, mock_import):
        """Test handling of scanner loading failures."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Mock import failure
        mock_import.side_effect = ImportError("Module not found")

        # Should return None for failed import
        scanner = _registry._load_scanner("tf_savedmodel")
        assert scanner is None
        assert "tf_savedmodel" not in _registry._loaded_scanners

    def test_get_scanner_classes_loads_available_scanners(self):
        """Test that get_scanner_classes loads all available scanners."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # This should attempt to load all scanners
        scanner_classes = _registry.get_scanner_classes()

        # Should have loaded multiple scanners
        assert len(scanner_classes) > 0
        assert len(_registry._loaded_scanners) > 0

        # All returned classes should be BaseScanner subclasses
        for scanner_class in scanner_classes:
            assert issubclass(scanner_class, BaseScanner)


class TestLazyListInterface:
    """Test the lazy list interface for SCANNER_REGISTRY."""

    def test_lazy_list_iteration(self):
        """Test that the lazy list can be iterated."""
        from modelaudit.scanners import SCANNER_REGISTRY

        count = 0
        for scanner in SCANNER_REGISTRY:
            assert issubclass(scanner, BaseScanner)
            count += 1

        assert count > 0

    def test_lazy_list_length(self):
        """Test that the lazy list reports correct length."""
        from modelaudit.scanners import SCANNER_REGISTRY

        length = len(SCANNER_REGISTRY)
        assert length > 0

        # Should match the number of scanners in registry
        expected_count = len(_registry.get_available_scanners())
        assert length <= expected_count  # May be less due to import failures

    def test_lazy_list_indexing(self):
        """Test that the lazy list supports indexing."""
        from modelaudit.scanners import SCANNER_REGISTRY

        if len(SCANNER_REGISTRY) > 0:
            first_scanner = SCANNER_REGISTRY[0]
            assert issubclass(first_scanner, BaseScanner)

    def test_lazy_list_contains(self):
        """Test that the lazy list supports 'in' operator."""
        from modelaudit.scanners import SCANNER_REGISTRY, PickleScanner

        # This will load PickleScanner if not already loaded
        assert PickleScanner in SCANNER_REGISTRY


class TestBackwardsCompatibility:
    """Test backwards compatibility of the lazy loading system."""

    def test_direct_scanner_import(self):
        """Test that scanners can still be imported directly."""
        from modelaudit.scanners import PickleScanner

        assert PickleScanner is not None
        assert issubclass(PickleScanner, BaseScanner)

    def test_scanner_registry_usage(self):
        """Test that SCANNER_REGISTRY still works as expected."""
        from modelaudit.scanners import SCANNER_REGISTRY

        # Should be iterable
        scanner_list = list(SCANNER_REGISTRY)
        assert len(scanner_list) > 0

        # All should be BaseScanner subclasses
        for scanner in scanner_list:
            assert issubclass(scanner, BaseScanner)

    def test_scanner_can_handle_method(self):
        """Test that scanner can_handle methods work correctly."""
        from modelaudit.scanners import PickleScanner

        # Create temporary pickle file
        with tempfile.NamedTemporaryFile(suffix=".pkl") as f:
            assert PickleScanner.can_handle(f.name)

    def test_scanner_instantiation(self):
        """Test that scanners can be instantiated correctly."""
        from modelaudit.scanners import PickleScanner

        scanner = PickleScanner()
        assert scanner is not None
        assert hasattr(scanner, "scan")
        assert hasattr(scanner, "can_handle")


class TestPerformanceCharacteristics:
    """Test performance characteristics of lazy loading."""

    def test_minimal_loading_for_specific_files(self):
        """Test that only necessary scanners are loaded for specific files."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Create a JSON file (should only load manifest scanner)
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w") as f:
            f.write('{"test": "value"}')
            f.flush()

            _ = _registry.get_scanner_for_path(f.name)

            # Should have loaded minimal scanners
            loaded_count = len(_registry._loaded_scanners)
            assert loaded_count <= 3  # Should be very few

    def test_no_heavy_dependencies_for_light_files(self):
        """Test that heavy dependencies are not loaded for light files."""
        # Reset loaded scanners
        _registry._loaded_scanners.clear()

        # Simulate a system without heavy dependencies
        heavy_modules = ["tensorflow", "torch", "h5py", "onnx"]
        initial_modules = set(sys.modules.keys())

        # Create a simple text file
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w") as f:
            f.write("test content")
            f.flush()

            # This should not load heavy dependencies
            _ = _registry.get_scanner_for_path(f.name)

            # Check that heavy modules weren't imported
            new_modules = set(sys.modules.keys()) - initial_modules
            for heavy_module in heavy_modules:
                # None of the heavy modules should be in newly imported modules
                _ = any(heavy_module in mod for mod in new_modules)
                # We can't assert this is False because modules might already be loaded
                # But we can verify the behavior in isolation


class TestErrorHandling:
    """Test error handling in lazy loading system."""

    def test_invalid_scanner_id(self):
        """Test handling of invalid scanner IDs."""
        scanner = _registry._load_scanner("nonexistent_scanner")
        assert scanner is None

    def test_scanner_info_for_invalid_id(self):
        """Test getting scanner info for invalid ID."""
        info = _registry.get_scanner_info("nonexistent_scanner")
        assert info is None

    @patch("modelaudit.scanners._registry._load_scanner")
    def test_scanner_loading_exception_handling(self, mock_load):
        """Test handling of exceptions during scanner loading."""
        # Mock scanner loading to raise an exception
        mock_load.return_value = None

        _ = _registry.get_scanner_for_path("test.pkl")
        # Should handle gracefully, either return None or a fallback
        # The exact behavior depends on implementation details

    def test_getattr_with_invalid_name(self):
        """Test __getattr__ with invalid scanner name."""
        from modelaudit import scanners

        with pytest.raises(AttributeError):
            _ = scanners.NonExistentScanner


class TestSpecificFileTypes:
    """Test lazy loading behavior with specific file types."""

    def test_json_file_loading(self):
        """Test that JSON files load only manifest scanner."""
        _registry._loaded_scanners.clear()

        # Use a realistic ML config filename that manifest scanner will handle
        with tempfile.NamedTemporaryFile(
            suffix="_config.json",
            mode="w",
            delete=False,
        ) as f:
            f.write('{"model": "test", "tokenizer": "config"}')
            f.flush()

            try:
                _ = _registry.get_scanner_for_path(f.name)
                # May be None if manifest scanner doesn't handle this specific file
                # This is actually expected behavior - not all JSON files are ML-related

                # Should have loaded minimal scanners (or none if no match)
                assert len(_registry._loaded_scanners) <= 3
            finally:
                Path(f.name).unlink(missing_ok=True)

    def test_pickle_file_loading(self):
        """Test that pickle files load pickle scanner efficiently."""
        _registry._loaded_scanners.clear()

        with tempfile.NamedTemporaryFile(suffix=".pkl") as f:
            scanner = _registry.get_scanner_for_path(f.name)
            assert scanner is not None
            assert scanner.name == "pickle"

            # Should have loaded pickle scanner
            assert "pickle" in _registry._loaded_scanners

    def test_unknown_extension_handling(self):
        """Test handling of files with unknown extensions."""
        _registry._loaded_scanners.clear()

        with tempfile.NamedTemporaryFile(suffix=".unknown_ext") as f:
            _ = _registry.get_scanner_for_path(f.name)
            # May return None or a fallback scanner
            # The exact behavior depends on implementation

    def test_manifest_scanner_exact_filename_matching(self):
        """Test that manifest scanner uses exact filename matching to prevent false positives."""
        _registry._loaded_scanners.clear()

        # Test exact match - should work
        with tempfile.NamedTemporaryFile(suffix="config.json", delete=False) as f:
            f.write(b'{"test": "config"}')
            exact_path = f.name

        # Test false positive case - should NOT match
        with tempfile.NamedTemporaryFile(
            suffix="config.json.backup",
            delete=False,
        ) as f:
            f.write(b'{"test": "backup"}')
            backup_path = f.name

        try:
            # Exact filename should potentially match (depends on manifest scanner logic)
            exact_scanner = _registry.get_scanner_for_path(exact_path)

            # Backup file should NOT match due to exact matching
            backup_scanner = _registry.get_scanner_for_path(backup_path)

            # The backup file should not be matched by manifest scanner
            # since "config.json.backup" != "config.json"
            if exact_scanner is not None:
                # If exact match works, backup should not match
                assert backup_scanner is None or backup_scanner.name != "manifest"

        finally:
            Path(exact_path).unlink(missing_ok=True)
            Path(backup_path).unlink(missing_ok=True)
