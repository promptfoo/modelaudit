from . import (
    base,
    gguf_scanner,
    keras_h5_scanner,
    manifest_scanner,
    pickle_scanner,
    pytorch_zip_scanner,
    tf_savedmodel_scanner,
    zip_scanner,
)

# Import scanner classes for direct use
from .base import BaseScanner, Issue, IssueSeverity, ScanResult
from .gguf_scanner import GGUFScanner
from .keras_h5_scanner import KerasH5Scanner
from .manifest_scanner import ManifestScanner
from .pickle_scanner import PickleScanner
from .pytorch_zip_scanner import PyTorchZipScanner
from .tf_savedmodel_scanner import TensorFlowSavedModelScanner
from .zip_scanner import ZipScanner

# Create a registry of all available scanners
# Order matters - more specific scanners should come before generic ones
SCANNER_REGISTRY = [
    PickleScanner,
    TensorFlowSavedModelScanner,
    KerasH5Scanner,
    PyTorchZipScanner,  # Must come before ZipScanner since .pt/.pth files are zip files
    GGUFScanner,
    ManifestScanner,
    ZipScanner,  # Generic zip scanner should be last
    # Add new scanners here as they are implemented
]

__all__ = [
    "base",
    "keras_h5_scanner",
    "pickle_scanner",
    "pytorch_zip_scanner",
    "tf_savedmodel_scanner",
    "manifest_scanner",
    "gguf_scanner",
    "zip_scanner",
    "BaseScanner",
    "ScanResult",
    "IssueSeverity",
    "Issue",
    "PickleScanner",
    "TensorFlowSavedModelScanner",
    "KerasH5Scanner",
    "PyTorchZipScanner",
    "GGUFScanner",
    "ManifestScanner",
    "ZipScanner",
    "SCANNER_REGISTRY",
]
