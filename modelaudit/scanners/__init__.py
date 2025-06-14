from . import (
    base,
    keras_h5_scanner,
    manifest_scanner,
    pickle_scanner,
    pytorch_zip_scanner,
    tf_savedmodel_scanner,
)

# Import scanner classes for direct use
from .base import BaseScanner, Issue, IssueSeverity, ScanResult
from .keras_h5_scanner import KerasH5Scanner
from .manifest_scanner import ManifestScanner
from .pickle_scanner import PickleScanner
from .pytorch_zip_scanner import PyTorchZipScanner
from .tf_savedmodel_scanner import TensorFlowSavedModelScanner

# Create a registry of all available scanners
SCANNER_REGISTRY = [
    PickleScanner,
    TensorFlowSavedModelScanner,
    KerasH5Scanner,
    PyTorchZipScanner,
    ManifestScanner,
    # Add new scanners here as they are implemented
]

__all__ = [
    "base",
    "keras_h5_scanner",
    "pickle_scanner",
    "pytorch_zip_scanner",
    "tf_savedmodel_scanner",
    "manifest_scanner",
    "BaseScanner",
    "ScanResult",
    "IssueSeverity",
    "Issue",
    "PickleScanner",
    "TensorFlowSavedModelScanner",
    "KerasH5Scanner",
    "PyTorchZipScanner",
    "ManifestScanner",
    "SCANNER_REGISTRY",
]
