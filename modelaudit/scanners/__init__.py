from . import base
from . import keras_h5_scanner
from . import pickle_scanner
from . import pytorch_zip_scanner
from . import tf_savedmodel_scanner
from . import manifest_scanner
from . import zip_scanner

# Import scanner classes for direct use
from .base import BaseScanner, ScanResult, IssueSeverity, Issue
from .pickle_scanner import PickleScanner
from .tf_savedmodel_scanner import TensorFlowSavedModelScanner
from .keras_h5_scanner import KerasH5Scanner
from .pytorch_zip_scanner import PyTorchZipScanner
from .manifest_scanner import ManifestScanner
from .zip_scanner import ZipScanner

# Create a registry of all available scanners
# Order matters - more specific scanners should come before generic ones
SCANNER_REGISTRY = [
    PickleScanner,
    TensorFlowSavedModelScanner,
    KerasH5Scanner,
    PyTorchZipScanner,  # Must come before ZipScanner since .pt/.pth files are zip files
    ManifestScanner,
    ZipScanner,  # Generic zip scanner should be last
    # Add new scanners here as they are implemented
]

__all__ = [
    'base',
    'keras_h5_scanner',
    'pickle_scanner',
    'pytorch_zip_scanner',
    'tf_savedmodel_scanner',
    'manifest_scanner',
    'zip_scanner',
    'BaseScanner',
    'ScanResult',
    'IssueSeverity',
    'Issue',
    'PickleScanner',
    'TensorFlowSavedModelScanner',
    'KerasH5Scanner',
    'PyTorchZipScanner',
    'ManifestScanner',
    'ZipScanner',
    'SCANNER_REGISTRY',
]
