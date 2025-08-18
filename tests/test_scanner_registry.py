from modelaudit.scanners import SCANNER_REGISTRY, _registry
from modelaudit.scanners.base import BaseScanner


def test_scanner_registry_contains_all_scanners():
    """Test that the scanner registry contains all expected scanners or tracks failed loads."""
    # Check that all expected scanners are either loaded or in failed scanners
    scanner_classes = [cls.__name__ for cls in SCANNER_REGISTRY]
    failed_scanners = _registry.get_failed_scanners()

    # Core scanners that should always load (no heavy dependencies)
    core_scanners = [
        "PickleScanner",
        "PyTorchZipScanner",
        "SafeTensorsScanner",
        "PmmlScanner",
    ]

    for scanner in core_scanners:
        assert scanner in scanner_classes, f"Core scanner {scanner} should always be available"

    # ML framework scanners that may fail due to compatibility issues
    # Map scanner class names to their registry IDs for proper matching
    ml_scanners_map = {
        "TensorFlowSavedModelScanner": "tf_savedmodel",
        "KerasH5Scanner": "keras_h5",
        "OnnxScanner": "onnx",
        "TFLiteScanner": "tflite",
        "CoreMLScanner": "coreml",
        "OpenVinoScanner": "openvino",
        "TensorRTScanner": "tensorrt",
        "PaddleScanner": "paddle",
    }

    for scanner_class, scanner_id in ml_scanners_map.items():
        scanner_available = scanner_class in scanner_classes
        scanner_failed = scanner_id in failed_scanners

        assert scanner_available or scanner_failed, (
            f"Scanner {scanner_class} (ID: {scanner_id}) should either be loaded or in failed scanners. "
            f"Loaded: {scanner_classes}, Failed: {list(failed_scanners.keys())}"
        )


def test_scanner_registry_instances():
    """Test that all scanners in the registry are subclasses of BaseScanner."""
    for scanner_class in SCANNER_REGISTRY:
        assert issubclass(scanner_class, BaseScanner)

        # Check that each scanner has the required class attributes
        assert hasattr(scanner_class, "name")
        assert hasattr(scanner_class, "description")
        assert hasattr(scanner_class, "supported_extensions")

        # Check that each scanner has the required methods
        assert hasattr(scanner_class, "can_handle")
        assert hasattr(scanner_class, "scan")


def test_scanner_registry_unique_names():
    """Test that all scanners in the registry have unique names."""
    scanner_names = [cls.name for cls in SCANNER_REGISTRY]

    # Check for duplicates
    assert len(scanner_names) == len(set(scanner_names)), "Duplicate scanner names found"


def test_scanner_registry_file_extension_coverage():
    """Test that the scanner registry covers all expected file extensions."""
    # Collect all supported extensions from all scanners
    all_extensions = []
    for scanner_class in SCANNER_REGISTRY:
        all_extensions.extend(scanner_class.supported_extensions)

    # Check that common model file extensions are covered
    # Only include extensions that we know are supported by the scanners
    common_extensions = [
        ".pkl",
        ".pickle",
        ".pt",
        ".pth",
        ".h5",
        ".hdf5",
        ".keras",
        ".pb",
        ".onnx",
        ".safetensors",
        ".msgpack",
        ".tflite",
        ".pdmodel",
        ".pdiparams",
        ".engine",
        ".plan",
    ]

    for ext in common_extensions:
        assert ext in all_extensions, f"Extension {ext} not covered by any scanner"


def test_scanner_registry_instantiation():
    """Test that all scanners in the registry can be instantiated."""
    for scanner_class in SCANNER_REGISTRY:
        # Should be able to instantiate with default config
        scanner = scanner_class()
        assert scanner.config == {}

        # Should be able to instantiate with custom config
        custom_config = {"test_option": "test_value"}
        scanner = scanner_class(config=custom_config)
        assert scanner.config == custom_config


def test_scanner_registry_graceful_fallback():
    """Test that scanner registry handles failed loads gracefully."""
    failed_scanners = _registry.get_failed_scanners()

    # If there are failed scanners, they should have error messages
    for scanner_id, error_msg in failed_scanners.items():
        assert isinstance(error_msg, str)
        assert len(error_msg) > 0
        assert scanner_id in error_msg or "numpy" in error_msg.lower() or "tensorflow" in error_msg.lower()

    # Registry should still function even with failed scanners
    assert len(SCANNER_REGISTRY) > 0, "Some scanners should still be available"


def test_numpy_compatibility_detection():
    """Test that NumPy compatibility status is properly detected."""
    numpy_compatible, numpy_status = _registry.get_numpy_status()

    assert isinstance(numpy_compatible, bool)
    assert isinstance(numpy_status, str)
    assert "numpy" in numpy_status.lower()

    # Should provide helpful information
    assert len(numpy_status) > 10
