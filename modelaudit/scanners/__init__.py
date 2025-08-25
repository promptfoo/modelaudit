import importlib
import logging
import threading
import warnings
from collections.abc import Iterator
from typing import Any, Optional

from .base import BaseScanner, Check, CheckStatus, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)


def _check_numpy_compatibility() -> tuple[bool, str]:
    """Check NumPy version compatibility and return status with message"""
    try:
        import numpy as np

        numpy_version = np.__version__
        major_version = int(numpy_version.split(".")[0])

        if major_version >= 2:
            return (
                False,
                f"NumPy {numpy_version} detected. Some ML frameworks may require NumPy < 2.0 for compatibility.",
            )

        return True, f"NumPy {numpy_version} detected (compatible)."
    except ImportError:
        return False, "NumPy not available."


def _is_numpy_compatibility_error(exception: Exception) -> bool:
    """Check if an exception is related to NumPy compatibility issues"""
    error_str = str(exception).lower()
    numpy_indicators = [
        "_array_api not found",
        "numpy.dtype size changed",
        "compiled using numpy 1.x cannot be run in numpy 2",
        "compiled against numpy",
        "binary incompatibility",
    ]
    return any(indicator in error_str for indicator in numpy_indicators)


class ScannerRegistry:
    """
    Lazy-loading registry for model scanners

    This registry manages scanner loading and selection. For security patterns
    used by scanners, see modelaudit.suspicious_symbols module.
    """

    def __init__(self) -> None:
        self._scanners: dict[str, dict[str, Any]] = {}
        self._loaded_scanners: dict[str, type[BaseScanner]] = {}
        self._failed_scanners: dict[str, str] = {}  # Track failed scanner loads
        self._lock = threading.Lock()
        self._numpy_compatible: Optional[bool] = None  # Lazy initialization
        self._numpy_status: Optional[str] = None
        self._init_registry()

    def _ensure_numpy_status(self) -> None:
        """Lazy initialization of NumPy compatibility status."""
        if self._numpy_compatible is None:
            try:
                self._numpy_compatible, self._numpy_status = _check_numpy_compatibility()
            except RecursionError:
                # Handle environments with very low recursion limits
                self._numpy_compatible = False
                self._numpy_status = "NumPy compatibility check failed due to low recursion limit"

    # Class-level constant for AI/ML manifest patterns
    _AIML_MANIFEST_PATTERNS = frozenset(
        [
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
        ],
    )

    def _init_registry(self) -> None:
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
                "numpy_sensitive": False,
            },
            "pytorch_binary": {
                "module": "modelaudit.scanners.pytorch_binary_scanner",
                "class": "PyTorchBinaryScanner",
                "description": "Scans PyTorch binary files",
                "extensions": [".bin"],
                "priority": 3,  # After pytorch_zip to allow ZIP detection first
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "tf_savedmodel": {
                "module": "modelaudit.scanners.tf_savedmodel_scanner",
                "class": "TensorFlowSavedModelScanner",
                "description": "Scans TensorFlow SavedModel files",
                "extensions": [".pb", ""],  # Empty string for directories
                "priority": 4,
                "dependencies": ["tensorflow"],  # Heavy dependency
                "numpy_sensitive": True,  # TensorFlow is sensitive to NumPy version
            },
            "keras_zip": {
                "module": "modelaudit.scanners.keras_zip_scanner",
                "class": "KerasZipScanner",
                "description": "Scans ZIP-based Keras model files",
                "extensions": [".keras"],
                "priority": 4,  # Higher priority than keras_h5 to check ZIP format first
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "keras_h5": {
                "module": "modelaudit.scanners.keras_h5_scanner",
                "class": "KerasH5Scanner",
                "description": "Scans Keras H5 model files",
                "extensions": [".h5", ".hdf5", ".keras"],
                "priority": 5,
                "dependencies": ["h5py"],  # Heavy dependency
                "numpy_sensitive": True,  # H5py can be sensitive to NumPy version
            },
            "onnx": {
                "module": "modelaudit.scanners.onnx_scanner",
                "class": "OnnxScanner",
                "description": "Scans ONNX model files",
                "extensions": [".onnx"],
                "priority": 6,
                "dependencies": ["onnx"],  # Heavy dependency
                "numpy_sensitive": True,  # ONNX can be sensitive to NumPy version
            },
            "coreml": {
                "module": "modelaudit.scanners.coreml_scanner",
                "class": "CoreMLScanner",
                "description": "Scans Apple Core ML model files",
                "extensions": [".mlmodel"],
                "priority": 6,
                "dependencies": ["coreml"],  # Heavy dependency
                "numpy_sensitive": True,
            },
            "openvino": {
                "module": "modelaudit.scanners.openvino_scanner",
                "class": "OpenVinoScanner",
                "description": "Scans OpenVINO IR model files",
                "extensions": [".xml"],
                "priority": 6,
                "dependencies": [],
                "numpy_sensitive": False,
            },
            "pytorch_zip": {
                "module": "modelaudit.scanners.pytorch_zip_scanner",
                "class": "PyTorchZipScanner",
                "description": "Scans PyTorch ZIP-based model files",
                "extensions": [".pt", ".pth", ".bin"],  # Include .bin for torch.save() outputs
                "priority": 2,  # Higher priority than pytorch_binary to check ZIP format first
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "executorch": {
                "module": "modelaudit.scanners.executorch_scanner",
                "class": "ExecuTorchScanner",
                "description": "Scans ExecuTorch mobile archives",
                "extensions": [".ptl", ".pte"],
                "priority": 6,  # Similar priority to PyTorch Zip
                "dependencies": [],
                "numpy_sensitive": False,
            },
            "gguf": {
                "module": "modelaudit.scanners.gguf_scanner",
                "class": "GgufScanner",
                "description": "Scans GGUF/GGML model files",
                "extensions": [".gguf", ".ggml"],
                "priority": 7,
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "joblib": {
                "module": "modelaudit.scanners.joblib_scanner",
                "class": "JoblibScanner",
                "description": "Scans joblib serialized files",
                "extensions": [".joblib"],
                "priority": 8,
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "numpy": {
                "module": "modelaudit.scanners.numpy_scanner",
                "class": "NumPyScanner",
                "description": "Scans NumPy array files",
                "extensions": [".npy", ".npz"],
                "priority": 9,
                "dependencies": [],  # numpy is core dependency
                "numpy_sensitive": False,  # This scanner handles NumPy compatibility internally
            },
            "oci_layer": {
                "module": "modelaudit.scanners.oci_layer_scanner",
                "class": "OciLayerScanner",
                "description": "Scans OCI container layers",
                "extensions": [".manifest"],
                "priority": 10,
                "dependencies": [],  # pyyaml optional, handled gracefully
                "numpy_sensitive": False,
            },
            "text": {
                "module": "modelaudit.scanners.text_scanner",
                "class": "TextScanner",
                "description": "Scans ML-related text files",
                "extensions": [".txt", ".md", ".markdown", ".rst"],
                "priority": 11,
                "dependencies": [],
                "numpy_sensitive": False,
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
                "priority": 12,
                "dependencies": [],  # pyyaml optional, handled gracefully
                "numpy_sensitive": False,
            },
            "pmml": {
                "module": "modelaudit.scanners.pmml_scanner",
                "class": "PmmlScanner",
                "description": "Scans PMML model files",
                "extensions": [".pmml"],
                "priority": 12,
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
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
                    # Note: .safetensors removed - handled exclusively by SafeTensorsScanner
                ],
                "priority": 13,
                "dependencies": [
                    "torch",
                    "h5py",
                    "tensorflow",
                    "onnx",
                    "safetensors",
                ],  # Multiple heavy deps
                "numpy_sensitive": True,  # Multiple ML frameworks
            },
            "safetensors": {
                "module": "modelaudit.scanners.safetensors_scanner",
                "class": "SafeTensorsScanner",
                "description": "Scans SafeTensors model files",
                "extensions": [".safetensors"],
                "priority": 14,
                "dependencies": [],  # No heavy dependencies for basic scanning
                "numpy_sensitive": False,
            },
            "flax_msgpack": {
                "module": "modelaudit.scanners.flax_msgpack_scanner",
                "class": "FlaxMsgpackScanner",
                "description": "Scans Flax/JAX msgpack checkpoint files with enhanced security analysis",
                "extensions": [".msgpack", ".flax", ".orbax", ".jax"],
                "priority": 15,
                "dependencies": ["msgpack"],  # Light dependency
                "numpy_sensitive": False,
            },
            "jax_checkpoint": {
                "module": "modelaudit.scanners.jax_checkpoint_scanner",
                "class": "JaxCheckpointScanner",
                "description": "Scans JAX checkpoint files in various serialization formats",
                "extensions": [".ckpt", ".checkpoint", ".orbax-checkpoint", ".pickle"],
                "priority": 15,  # Same priority as flax_msgpack, will be tried in order
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "tflite": {
                "module": "modelaudit.scanners.tflite_scanner",
                "class": "TFLiteScanner",
                "description": "Scans TensorFlow Lite model files",
                "extensions": [".tflite"],
                "priority": 16,
                "dependencies": ["tflite"],  # Heavy dependency
                "numpy_sensitive": True,  # TensorFlow Lite can be sensitive
            },
            "tensorrt": {
                "module": "modelaudit.scanners.tensorrt_scanner",
                "class": "TensorRTScanner",
                "description": "Scans TensorRT engine files",
                "extensions": [".engine", ".plan"],
                "priority": 17,
                "dependencies": [],
                "numpy_sensitive": False,
            },
            "paddle": {
                "module": "modelaudit.scanners.paddle_scanner",
                "class": "PaddleScanner",
                "description": "Scans PaddlePaddle model files",
                "extensions": [".pdmodel", ".pdiparams"],
                "priority": 18,
                "dependencies": ["paddlepaddle"],
                "numpy_sensitive": True,
            },
            "tar": {
                "module": "modelaudit.scanners.tar_scanner",
                "class": "TarScanner",
                "description": "Scans TAR archive files",
                "extensions": [
                    ".tar",
                    ".tar.gz",
                    ".tgz",
                    ".tar.bz2",
                    ".tbz2",
                    ".tar.xz",
                    ".txz",
                ],
                "priority": 98,
                "dependencies": [],
                "numpy_sensitive": False,
            },
            "jinja2_template": {
                "module": "modelaudit.scanners.jinja2_template_scanner",
                "class": "Jinja2TemplateScanner",
                "description": "Scans for Jinja2 template injection vulnerabilities in ML models",
                "extensions": [".gguf", ".json", ".yaml", ".yml", ".jinja", ".j2", ".template"],
                "priority": 14,  # High priority for security scanner, before safetensors
                "dependencies": ["jinja2", "gguf"],  # gguf optional for GGUF support
                "numpy_sensitive": False,
            },
            "metadata": {
                "module": "modelaudit.scanners.metadata_scanner",
                "class": "MetadataScanner",
                "description": "Scans model metadata files for security issues",
                "extensions": [".json", ".md", ".markdown", ".rst", ".yml", ".yaml"],
                "priority": 1,  # High priority for security-focused metadata scanning
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
            "zip": {
                "module": "modelaudit.scanners.zip_scanner",
                "class": "ZipScanner",
                "description": "Scans ZIP archive files",
                "extensions": [".zip", ".npz"],
                "priority": 99,  # Generic zip scanner should be last
                "dependencies": [],  # No heavy dependencies
                "numpy_sensitive": False,
            },
        }

    def _load_scanner(self, scanner_id: str) -> Optional[type[BaseScanner]]:
        """Lazy load a scanner class (thread-safe) with enhanced error handling"""
        # Check if already loaded (fast path without lock)
        if scanner_id in self._loaded_scanners:
            return self._loaded_scanners[scanner_id]

        # Check if already failed to load
        if scanner_id in self._failed_scanners:
            return None

        # Use lock for loading to prevent race conditions
        with self._lock:
            # Double-check after acquiring lock
            if scanner_id in self._loaded_scanners:
                return self._loaded_scanners[scanner_id]

            if scanner_id in self._failed_scanners:
                return None

            if scanner_id not in self._scanners:
                return None

            scanner_info = self._scanners[scanner_id]

            try:
                # Suppress warnings during import to avoid cluttering output
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    module = importlib.import_module(scanner_info["module"])
                    scanner_class = getattr(module, scanner_info["class"])

                self._loaded_scanners[scanner_id] = scanner_class
                logger.debug(f"Loaded scanner: {scanner_id}")
                return scanner_class

            except ImportError as e:
                # Missing dependency - provide helpful message
                scanner_deps = scanner_info.get("dependencies", [])
                is_numpy_sensitive = scanner_info.get("numpy_sensitive", False)

                if scanner_deps:
                    error_msg = (
                        f"Scanner {scanner_id} requires dependencies: {scanner_deps}. "
                        f"Install with 'pip install modelaudit[{','.join(scanner_deps)}]'"
                    )
                else:
                    error_msg = f"Scanner {scanner_id} import failed: {e}"

                self._failed_scanners[scanner_id] = error_msg

                # For expected dependency issues, use info level
                if scanner_deps or (is_numpy_sensitive and _is_numpy_compatibility_error(e)):
                    logger.info(error_msg)
                else:
                    logger.debug(error_msg)

                return None

            except Exception as e:
                # Unexpected error - provide detailed information
                scanner_deps = scanner_info.get("dependencies", [])
                is_numpy_sensitive = scanner_info.get("numpy_sensitive", False)

                if _is_numpy_compatibility_error(e):
                    if is_numpy_sensitive:
                        self._ensure_numpy_status()  # Lazy initialization
                        error_msg = (
                            f"Scanner {scanner_id} failed due to NumPy compatibility issue. "
                            f"{self._numpy_status} Consider using 'pip install numpy<2.0' if needed."
                        )
                        logger.info(error_msg)  # Info level - expected for NumPy issues
                    else:
                        error_msg = f"Scanner {scanner_id} failed with NumPy compatibility error: {e}"
                        logger.warning(error_msg)  # Warning - unexpected NumPy issue
                elif isinstance(e, AttributeError):
                    error_msg = f"Scanner class {scanner_info['class']} not found in {scanner_info['module']}: {e}"
                    logger.warning(error_msg)  # Warning - code structure issue
                else:
                    error_msg = f"Scanner {scanner_id} failed to load: {e}"
                    logger.warning(error_msg)  # Warning - unexpected error

                self._failed_scanners[scanner_id] = error_msg
                return None

    def has_scanner_class(self, class_name: str) -> bool:
        """Check if a scanner class is available without loading it.

        Args:
            class_name: Name of the scanner class to check for

        Returns:
            True if the scanner is registered and can potentially be loaded
        """
        return any(scanner_info.get("class") == class_name for scanner_info in self._scanners.values())

    def get_scanner_classes(self) -> list[type[BaseScanner]]:
        """Get all available scanner classes in priority order"""
        scanner_classes = []
        # Sort by priority
        sorted_scanners = sorted(self._scanners.items(), key=lambda x: x[1]["priority"])

        for scanner_id, _ in sorted_scanners:
            scanner_class = self._load_scanner(scanner_id)
            if scanner_class:
                scanner_classes.append(scanner_class)

        return scanner_classes

    def get_scanner_for_path(self, path: str) -> Optional[type[BaseScanner]]:
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
            if file_ext in extensions or ("" in extensions and os.path.isdir(path)):
                extension_match = True
            elif scanner_id == "manifest":
                # Special handling for manifest scanner - check filename patterns
                extension_match = self._is_aiml_manifest_file(filename)

            if extension_match:
                # Only load and check can_handle for scanners that match extension
                scanner_class = self._load_scanner(scanner_id)
                if scanner_class and scanner_class.can_handle(path):
                    return scanner_class

        return None

    def get_available_scanners(self) -> list[str]:
        """Get list of available scanner IDs"""
        return list(self._scanners.keys())

    def get_scanner_info(self, scanner_id: str) -> Optional[dict[str, Any]]:
        """Get metadata about a scanner without loading it"""
        return self._scanners.get(scanner_id)

    def load_scanner_by_id(self, scanner_id: str) -> Optional[type[BaseScanner]]:
        """Load a specific scanner by ID (public API)"""
        return self._load_scanner(scanner_id)

    def get_failed_scanners(self) -> dict[str, str]:
        """Get information about scanners that failed to load"""
        return self._failed_scanners.copy()

    def get_available_scanners_summary(self) -> dict[str, Any]:
        """Get comprehensive summary of scanner availability for diagnostics"""
        # Force loading of all scanners to populate failed_scanners
        loaded_scanners = []
        dependency_errors = {}
        numpy_errors = {}

        for scanner_id in self._scanners:
            scanner_class = self._load_scanner(scanner_id)
            if scanner_class:
                loaded_scanners.append(scanner_id)
            elif scanner_id in self._failed_scanners:
                error_msg = self._failed_scanners[scanner_id]
                scanner_info = self._scanners[scanner_id]
                dependencies = scanner_info.get("dependencies", [])

                # Categorize errors for better reporting
                if "NumPy compatibility" in error_msg or "numpy" in error_msg.lower():
                    numpy_errors[scanner_id] = error_msg
                elif dependencies and (
                    "requires dependencies" in error_msg
                    or (isinstance(error_msg, str) and "pip install modelaudit[" in error_msg)
                ):
                    dependency_errors[scanner_id] = {
                        "error": error_msg,
                        "dependencies": dependencies,
                        "install_command": f"pip install modelaudit[{','.join(dependencies)}]",
                    }

        return {
            "total_scanners": len(self._scanners),
            "loaded_scanners": len(loaded_scanners),
            "failed_scanners": len(self._failed_scanners),
            "loaded_scanner_list": sorted(loaded_scanners),
            "failed_scanner_details": self._failed_scanners.copy(),
            "dependency_errors": dependency_errors,
            "numpy_errors": numpy_errors,
            "success_rate": round((len(loaded_scanners) / len(self._scanners)) * 100, 1)
            if len(self._scanners) > 0
            else 0.0,
        }

    def get_numpy_status(self) -> tuple[bool, str]:
        """Get NumPy compatibility status"""
        self._ensure_numpy_status()  # Lazy initialization
        # After lazy initialization, these are guaranteed to be non-None
        assert self._numpy_compatible is not None
        assert self._numpy_status is not None
        return self._numpy_compatible, self._numpy_status

    def _is_aiml_manifest_file(self, filename: str) -> bool:
        """Check if filename matches AI/ML manifest patterns."""
        # Use exact filename matching to avoid false positives like "config.json.backup"
        return any(filename == pattern or filename.endswith(f"/{pattern}") for pattern in self._AIML_MANIFEST_PATTERNS)


# Global registry instance
_registry = ScannerRegistry()


class _LazyList:
    """Lazy list that loads scanners only when accessed (thread-safe)"""

    def __init__(self, registry: ScannerRegistry) -> None:
        self._registry = registry
        self._cached_list: Optional[list[type[BaseScanner]]] = None
        self._lock = threading.Lock()

    def _get_list(self) -> list[type[BaseScanner]]:
        # Fast path without lock
        if self._cached_list is not None:
            return self._cached_list

        # Use lock for initialization
        with self._lock:
            # Double-check after acquiring lock
            if self._cached_list is None:
                self._cached_list = self._registry.get_scanner_classes()
            return self._cached_list

    def __iter__(self) -> Iterator[type[BaseScanner]]:
        return iter(self._get_list())

    def __len__(self) -> int:
        return len(self._get_list())

    def __getitem__(self, index: int) -> type[BaseScanner]:
        return self._get_list()[index]

    def __contains__(self, item: Any) -> bool:
        return item in self._get_list()


# Legacy interface - SCANNER_REGISTRY as a lazy list
SCANNER_REGISTRY = _LazyList(_registry)


# Export scanner classes with lazy loading
def __getattr__(name: str) -> Any:
    """Lazy loading for scanner classes"""
    # Map class names to scanner IDs
    class_to_id = {
        "PickleScanner": "pickle",
        "PyTorchBinaryScanner": "pytorch_binary",
        "TensorFlowSavedModelScanner": "tf_savedmodel",
        "KerasH5Scanner": "keras_h5",
        "OnnxScanner": "onnx",
        "CoreMLScanner": "coreml",
        "OpenVinoScanner": "openvino",
        "PyTorchZipScanner": "pytorch_zip",
        "ExecuTorchScanner": "executorch",
        "GgufScanner": "gguf",
        "JoblibScanner": "joblib",
        "NumPyScanner": "numpy",
        "OciLayerScanner": "oci_layer",
        "ManifestScanner": "manifest",
        "PmmlScanner": "pmml",
        "WeightDistributionScanner": "weight_distribution",
        "SafeTensorsScanner": "safetensors",
        "FlaxMsgpackScanner": "flax_msgpack",
        "JaxCheckpointScanner": "jax_checkpoint",
        "TFLiteScanner": "tflite",
        "TensorRTScanner": "tensorrt",
        "PaddleScanner": "paddle",
        "TarScanner": "tar",
        "Jinja2TemplateScanner": "jinja2_template",
        "MetadataScanner": "metadata",
        "ZipScanner": "zip",
    }

    if name in class_to_id:
        scanner_id = class_to_id[name]
        scanner_class = _registry.load_scanner_by_id(scanner_id)
        if scanner_class:
            return scanner_class
        raise ImportError(
            f"Failed to load scanner '{name}' - dependencies may not be installed",
        )

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Helper function for getting scanner for a file
def get_scanner_for_file(path: str, config: Optional[dict[str, Any]] = None) -> Optional[BaseScanner]:
    """Get an instantiated scanner for a given file path"""
    scanner_class = _registry.get_scanner_for_path(path)
    if scanner_class:
        return scanner_class(config=config)
    return None


# Export the registry for direct use
__all__ = [
    # Registry
    "SCANNER_REGISTRY",
    # Base classes (already imported)
    "BaseScanner",
    "Check",
    "CheckStatus",
    "Issue",
    "IssueSeverity",
    "ScanResult",
    "_registry",
    "get_scanner_for_file",
    # Scanner classes will be lazy loaded via __getattr__
]
