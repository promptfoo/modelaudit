from . import (
    base,
    keras_h5_scanner,
    manifest_scanner,
    pickle_scanner,
    pytorch_binary_scanner,
    pytorch_zip_scanner,
    safetensors_scanner,
    tf_savedmodel_scanner,
    weight_distribution_scanner,
    zip_scanner,
)

# Import scanner classes for direct use
from .base import BaseScanner, Issue, IssueSeverity, ScanResult
from .keras_h5_scanner import KerasH5Scanner
from .manifest_scanner import ManifestScanner
from .pickle_scanner import PickleScanner
from .pytorch_binary_scanner import PyTorchBinaryScanner
from .pytorch_zip_scanner import PyTorchZipScanner
from .safetensors_scanner import SafeTensorsScanner
from .tf_savedmodel_scanner import TensorFlowSavedModelScanner
from .weight_distribution_scanner import WeightDistributionScanner
from .zip_scanner import ZipScanner

# Create a registry of all available scanners
# Order matters - more specific scanners should come before generic ones
SCANNER_REGISTRY = [
    PickleScanner,
    PyTorchBinaryScanner,  # Must come before generic scanners for .bin files
    TensorFlowSavedModelScanner,
    KerasH5Scanner,
    PyTorchZipScanner,  # Must come before ZipScanner since .pt/.pth files are zip files
    ManifestScanner,
    WeightDistributionScanner,
    SafeTensorsScanner,
    ZipScanner,  # Generic zip scanner should be last
    # Add new scanners here as they are implemented
]

__all__ = [
    "base",
    "keras_h5_scanner",
    "pickle_scanner",
    "pytorch_binary_scanner",
    "pytorch_zip_scanner",
    "tf_savedmodel_scanner",
    "manifest_scanner",
    "weight_distribution_scanner",
    "zip_scanner",
    "BaseScanner",
    "ScanResult",
    "IssueSeverity",
    "Issue",
    "PickleScanner",
    "PyTorchBinaryScanner",
    "TensorFlowSavedModelScanner",
    "KerasH5Scanner",
    "PyTorchZipScanner",
    "ManifestScanner",
    "WeightDistributionScanner",
    "SafeTensorsScanner",
    "ZipScanner",
    "SCANNER_REGISTRY",
]
