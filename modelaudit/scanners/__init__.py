import importlib
import logging
from typing import Any, ClassVar, Dict, List, Optional, Type

from .base import BaseScanner, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """
    Lazy-loading registry for model scanners
    
    This registry manages scanner loading and selection. For security patterns
    used by scanners, see modelaudit.suspicious_symbols module.
    """

    def __init__(self):
        self._scanners: Dict[str, Dict[str, Any]] = {}
        self._loaded_scanners: Dict[str, Type[BaseScanner]] = {}
        self._init_registry()

    def _init_registry(self):
        """Initialize the scanner registry with metadata"""
        # Order matters - more specific scanners should come before generic ones
        self._scanners = {
            "pickle": {
                "module": "modelaudit.scanners.pickle_scanner",
                "class": "PickleScanner",
                "description": "Scans pickle files for malicious code",
                "extensions": [".pkl", ".pickle", ".dill", ".pt", ".pth", ".ckpt"],
                "priority": 1,
                "dependencies": [],  # No heavy dependencies
            },
            "pytorch_binary": {
                "module": "modelaudit.scanners.pytorch_binary_scanner",
                "class": "PyTorchBinaryScanner",
                "description": "Scans PyTorch binary files",
                "extensions": [".bin"],
                "priority": 2,  # Must come before generic scanners for .bin files
                "dependencies": [],  # No heavy dependencies
            },
            "tf_savedmodel": {
                "module": "modelaudit.scanners.tf_savedmodel_scanner",
                "class": "TensorFlowSavedModelScanner",
                "description": "Scans TensorFlow SavedModel files",
                "extensions": [".pb", ""],  # Empty string for directories
                "priority": 3,
                "dependencies": ["tensorflow"],  # Heavy dependency
            },
            "keras_h5": {
                "module": "modelaudit.scanners.keras_h5_scanner",
                "class": "KerasH5Scanner",
                "description": "Scans Keras H5 model files",
                "extensions": [".h5", ".hdf5", ".keras"],
                "priority": 4,
                "dependencies": ["h5py"],  # Heavy dependency
            },
            "onnx": {
                "module": "modelaudit.scanners.onnx_scanner",
                "class": "OnnxScanner",
                "description": "Scans ONNX model files",
                "extensions": [".onnx"],
                "priority": 5,
                "dependencies": ["onnx"],  # Heavy dependency
            },
            "pytorch_zip": {
                "module": "modelaudit.scanners.pytorch_zip_scanner",
                "class": "PyTorchZipScanner",
                "description": "Scans PyTorch ZIP-based model files",
                "extensions": [".pt", ".pth"],
                "priority": 6,  # Must come before ZipScanner since .pt/.pth files are zip files
                "dependencies": [],  # No heavy dependencies
            },
            "gguf": {
                "module": "modelaudit.scanners.gguf_scanner",
                "class": "GgufScanner",
                "description": "Scans GGUF/GGML model files",
                "extensions": [".gguf", ".ggml"],
                "priority": 7,
                "dependencies": [],  # No heavy dependencies
            },
            "joblib": {
                "module": "modelaudit.scanners.joblib_scanner",
                "class": "JoblibScanner",
                "description": "Scans joblib serialized files",
                "extensions": [".joblib"],
                "priority": 8,
                "dependencies": [],  # No heavy dependencies
            },
            "numpy": {
                "module": "modelaudit.scanners.numpy_scanner",
                "class": "NumPyScanner",
                "description": "Scans NumPy array files",
                "extensions": [".npy", ".npz"],
                "priority": 9,
                "dependencies": [],  # numpy is core dependency
            },
            "oci_layer": {
                "module": "modelaudit.scanners.oci_layer_scanner",
                "class": "OciLayerScanner",
                "description": "Scans OCI container layers",
                "extensions": [".manifest"],
                "priority": 10,
                "dependencies": [],  # pyyaml optional, handled gracefully
            },
            "manifest": {
                "module": "modelaudit.scanners.manifest_scanner",
                "class": "ManifestScanner",
                "description": "Scans manifest and configuration files",
                "extensions": [
                    ".json",
                    ".yaml",
                    ".yml",
                    ".xml",
                    ".toml",
                    ".ini",
                    ".cfg",
                    ".config",
                    ".manifest",
                    ".model",
                    ".metadata",
                ],
                "priority": 11,
                "dependencies": [],  # pyyaml optional, handled gracefully
            },
            "pmml": {
                "module": "modelaudit.scanners.pmml_scanner",
                "class": "PmmlScanner",
                "description": "Scans PMML model files",
                "extensions": [".pmml"],
                "priority": 12,
                "dependencies": [],  # No heavy dependencies
            },
            "weight_distribution": {
                "module": "modelaudit.scanners.weight_distribution_scanner",
                "class": "WeightDistributionScanner",
                "description": "Analyzes weight distributions for anomalies",
                "extensions": [
                    ".pt",
                    ".pth",
                    ".h5",
                    ".keras",
                    ".hdf5",
                    ".pb",
                    ".onnx",
                    ".safetensors",
                ],
                "priority": 13,
                "dependencies": [
                    "torch",
                    "h5py",
                    "tensorflow",
                    "onnx",
                    "safetensors",
                ],  # Multiple heavy deps
            },
            "safetensors": {
                "module": "modelaudit.scanners.safetensors_scanner",
                "class": "SafeTensorsScanner",
                "description": "Scans SafeTensors model files",
                "extensions": [".safetensors"],
                "priority": 14,
                "dependencies": [],  # No heavy dependencies for basic scanning
            },
            "flax_msgpack": {
                "module": "modelaudit.scanners.flax_msgpack_scanner",
                "class": "FlaxMsgpackScanner",
                "description": "Scans Flax msgpack checkpoint files",
                "extensions": [".msgpack"],
                "priority": 15,
                "dependencies": ["msgpack"],  # Light dependency
            },
            "tflite": {
                "module": "modelaudit.scanners.tflite_scanner",
                "class": "TFLiteScanner",
                "description": "Scans TensorFlow Lite model files",
                "extensions": [".tflite"],
                "priority": 16,
                "dependencies": ["tflite"],  # Heavy dependency
            },
            "zip": {
                "module": "modelaudit.scanners.zip_scanner",
                "class": "ZipScanner",
                "description": "Scans ZIP archive files",
                "extensions": [".zip", ".npz"],
                "priority": 99,  # Generic zip scanner should be last
                "dependencies": [],  # No heavy dependencies
            },
        }

    def _load_scanner(self, scanner_id: str) -> Optional[Type[BaseScanner]]:
        """Lazy load a scanner class"""
        if scanner_id in self._loaded_scanners:
            return self._loaded_scanners[scanner_id]

        if scanner_id not in self._scanners:
            return None

        scanner_info = self._scanners[scanner_id]

        try:
            module = importlib.import_module(scanner_info["module"])
            scanner_class = getattr(module, scanner_info["class"])
            self._loaded_scanners[scanner_id] = scanner_class
            logger.debug(f"Loaded scanner: {scanner_id}")
            return scanner_class
        except ImportError as e:
            logger.debug(f"Failed to load scanner {scanner_id}: {e}")
            return None
        except AttributeError as e:
            logger.error(
                f"Scanner class {scanner_info['class']} not found in {scanner_info['module']}: {e}"
            )
            return None

    def get_scanner_classes(self) -> List[Type[BaseScanner]]:
        """Get all available scanner classes in priority order"""
        scanner_classes = []
        # Sort by priority
        sorted_scanners = sorted(self._scanners.items(), key=lambda x: x[1]["priority"])

        for scanner_id, _ in sorted_scanners:
            scanner_class = self._load_scanner(scanner_id)
            if scanner_class:
                scanner_classes.append(scanner_class)

        return scanner_classes

    def get_scanner_for_path(self, path: str) -> Optional[Type[BaseScanner]]:
        """Get the best scanner for a given path (lazy loaded)"""
        import os

        # Sort by priority
        sorted_scanners = sorted(self._scanners.items(), key=lambda x: x[1]["priority"])

        # First, try to find scanners based on extension without loading them
        file_ext = os.path.splitext(path)[1].lower()
        filename = os.path.basename(path).lower()

        for scanner_id, scanner_info in sorted_scanners:
            extensions = scanner_info.get("extensions", [])

            # Quick extension check before loading scanner
            extension_match = False
            if file_ext in extensions:
                extension_match = True
            elif "" in extensions and os.path.isdir(path):  # Directory scanner
                extension_match = True
            elif scanner_id == "manifest":
                # Special handling for manifest scanner - check filename patterns
                aiml_patterns = [
                    "config.json",
                    "model.json",
                    "tokenizer.json",
                    "params.json",
                    "hyperparams.yaml",
                    "training_args.json",
                    "dataset_info.json",
                    "model.yaml",
                    "environment.yml",
                    "conda.yaml",
                    "requirements.txt",
                    "metadata.json",
                    "index.json",
                    "tokenizer_config.json",
                    "model_config.json",
                ]
                # Use exact filename matching to avoid false positives like "config.json.backup"
                if any(filename == pattern or filename.endswith(f"/{pattern}") for pattern in aiml_patterns):
                    extension_match = True

            if extension_match:
                # Only load and check can_handle for scanners that match extension
                scanner_class = self._load_scanner(scanner_id)
                if scanner_class and scanner_class.can_handle(path):
                    return scanner_class

        return None

    def get_available_scanners(self) -> List[str]:
        """Get list of available scanner IDs"""
        return list(self._scanners.keys())

    def get_scanner_info(self, scanner_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata about a scanner without loading it"""
        return self._scanners.get(scanner_id)


# Global registry instance
_registry = ScannerRegistry()


class _LazyList:
    """Lazy list that loads scanners only when accessed"""

    def __init__(self, registry):
        self._registry = registry
        self._cached_list = None

    def _get_list(self):
        if self._cached_list is None:
            self._cached_list = self._registry.get_scanner_classes()
        return self._cached_list

    def __iter__(self):
        return iter(self._get_list())

    def __len__(self):
        return len(self._get_list())

    def __getitem__(self, index):
        return self._get_list()[index]

    def __contains__(self, item):
        return item in self._get_list()


# Legacy interface - SCANNER_REGISTRY as a lazy list
SCANNER_REGISTRY = _LazyList(_registry)


# Export scanner classes with lazy loading
def __getattr__(name: str):
    """Lazy loading for scanner classes"""
    # Map class names to scanner IDs
    class_to_id = {
        "PickleScanner": "pickle",
        "PyTorchBinaryScanner": "pytorch_binary",
        "TensorFlowSavedModelScanner": "tf_savedmodel",
        "KerasH5Scanner": "keras_h5",
        "OnnxScanner": "onnx",
        "PyTorchZipScanner": "pytorch_zip",
        "GgufScanner": "gguf",
        "JoblibScanner": "joblib",
        "NumPyScanner": "numpy",
        "OciLayerScanner": "oci_layer",
        "ManifestScanner": "manifest",
        "PmmlScanner": "pmml",
        "WeightDistributionScanner": "weight_distribution",
        "SafeTensorsScanner": "safetensors",
        "FlaxMsgpackScanner": "flax_msgpack",
        "TFLiteScanner": "tflite",
        "ZipScanner": "zip",
    }

    if name in class_to_id:
        scanner_id = class_to_id[name]
        scanner_class = _registry._load_scanner(scanner_id)
        if scanner_class:
            return scanner_class
        else:
            raise ImportError(
                f"Failed to load scanner '{name}' - dependencies may not be installed"
            )

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Export the registry for direct use
__all__ = [
    # Base classes (already imported)
    "BaseScanner",
    "Issue",
    "IssueSeverity",
    "ScanResult",
    # Registry
    "SCANNER_REGISTRY",
    "_registry",
    # Scanner classes will be lazy loaded via __getattr__
]
