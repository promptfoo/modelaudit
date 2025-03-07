from . import base
from . import keras_h5_scanner
from . import pickle_scanner
from . import pytorch_zip_scanner
from . import tf_savedmodel_scanner
from . import manifest_scanner

# Import scanner classes for direct use
from .base import BaseScanner, ScanResult, IssueSeverity, Issue
from .pickle_scanner import PickleScanner
from .tf_savedmodel_scanner import TensorFlowSavedModelScanner
from .keras_h5_scanner import KerasH5Scanner
from .pytorch_zip_scanner import PyTorchZipScanner
from .manifest_scanner import ManifestScanner

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
    'base',
    'keras_h5_scanner',
    'pickle_scanner',
    'pytorch_zip_scanner',
    'tf_savedmodel_scanner',
    'manifest_scanner',
    'BaseScanner',
    'ScanResult',
    'IssueSeverity',
    'Issue',
    'PickleScanner',
    'TensorFlowSavedModelScanner',
    'KerasH5Scanner',
    'PyTorchZipScanner',
    'ManifestScanner',
    'SCANNER_REGISTRY',
]
