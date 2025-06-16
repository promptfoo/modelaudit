from modelaudit.scanners import SCANNER_REGISTRY
from modelaudit.scanners.base import BaseScanner


def test_scanner_registry_contains_all_scanners():
    """Test that the scanner registry contains all expected scanners."""
    # Check that all expected scanners are in the registry
    scanner_classes = [cls.__name__ for cls in SCANNER_REGISTRY]

    assert "PickleScanner" in scanner_classes
    assert "TensorFlowSavedModelScanner" in scanner_classes
    assert "KerasH5Scanner" in scanner_classes
    assert "PyTorchZipScanner" in scanner_classes
    assert "OnnxScanner" in scanner_classes


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
    assert len(scanner_names) == len(set(scanner_names)), (
        "Duplicate scanner names found"
    )


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
