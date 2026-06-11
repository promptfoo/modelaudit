import importlib
import logging
import threading
import warnings
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..scanner_registry_metadata import get_scanner_registry_metadata
from ..scanner_selection import ScannerSelectionPolicy, allows_zip_structure_analysis, policy_from_config
from .base import BaseScanner, Check, CheckStatus, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)

_READ_FAILURE_AWARE_EXTENSION_SCANNERS = frozenset(
    {
        "cntk",
        "coreml",
        "lightgbm",
        "manifest",
        "metadata",
        "numpy",
        "paddle",
        "pytorch_binary",
        "r_serialized",
        "safetensors",
        "tensorrt",
        "text",
        "tf_metagraph",
        "tf_savedmodel",
        "zip",
    }
)
_READ_FAILURE_AWARE_UNREADABLE_EXTENSION_OWNERS = {
    "cntk": frozenset({".cmf", ".dnn"}),
    "coreml": frozenset({".mlmodel"}),
    "lightgbm": frozenset({".lgb", ".lightgbm"}),
    "numpy": frozenset({".npy"}),
    "paddle": frozenset({".pdiparams", ".pdmodel"}),
    "pytorch_binary": frozenset({".bin"}),
    "r_serialized": frozenset({".rda", ".rdata", ".rds"}),
    "safetensors": frozenset({".safetensors"}),
    "tensorrt": frozenset({".engine", ".plan", ".trt"}),
    "tf_metagraph": frozenset({".meta"}),
    "tf_savedmodel": frozenset({".pb"}),
    "zip": frozenset({".npz", ".zip"}),
}


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
        self._numpy_compatible: bool | None = None  # Lazy initialization
        self._numpy_status: str | None = None
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

    def _init_registry(self) -> None:
        """Initialize the scanner registry from descriptor metadata."""
        self._scanners = get_scanner_registry_metadata()
        if not self._scanners:
            raise RuntimeError("Scanner registry metadata is empty")

    def _load_scanner(self, scanner_id: str) -> type[BaseScanner] | None:
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
                logger.debug("Scanner loaded successfully")
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

                # For expected dependency issues, use debug level
                if scanner_deps or (is_numpy_sensitive and _is_numpy_compatibility_error(e)):
                    logger.debug("Scanner unavailable due to an optional dependency or compatibility issue")
                else:
                    logger.debug("Scanner unavailable during lazy loading")

                return None

            except Exception as e:
                # Unexpected error - provide detailed information
                is_numpy_sensitive = scanner_info.get("numpy_sensitive", False)

                if _is_numpy_compatibility_error(e):
                    if is_numpy_sensitive:
                        self._ensure_numpy_status()  # Lazy initialization
                        error_msg = (
                            f"Scanner {scanner_id} failed due to NumPy compatibility issue. "
                            f"{self._numpy_status} Consider using 'pip install numpy<2.0' if needed."
                        )
                        logger.debug("Scanner unavailable due to a NumPy compatibility issue")
                    else:
                        error_msg = f"Scanner {scanner_id} failed with NumPy compatibility error: {e}"
                        logger.warning("Scanner failed with an unexpected NumPy compatibility issue")
                elif isinstance(e, AttributeError):
                    error_msg = f"Scanner class {scanner_info['class']} not found in {scanner_info['module']}: {e}"
                    logger.warning("Scanner class could not be loaded")
                else:
                    error_msg = f"Scanner {scanner_id} failed to load: {e}"
                    logger.warning("Scanner failed to load unexpectedly")

                self._failed_scanners[scanner_id] = error_msg
                return None

    def has_scanner_class(self, class_name: str) -> bool:
        """Check if a scanner class is available without loading it.

        Args:
            class_name: Name of the scanner class to check for

        Returns:
            True if the scanner is registered and can potentially be loaded
        """
        return self.get_scanner_id_for_class(class_name) is not None

    def get_scanner_id_for_class(self, class_name: str) -> str | None:
        """Resolve a scanner class name from the registry's descriptor catalog."""
        for scanner_id, scanner_info in self._scanners.items():
            if scanner_info.get("class") == class_name:
                return scanner_id
        return None

    def get_scanner_id_for_header_format(self, header_format: str) -> str | None:
        """Resolve a detected header format to a scanner ID from descriptor metadata."""
        if header_format in self._scanners:
            return header_format

        for scanner_id, scanner_info in self._scanners.items():
            if header_format in scanner_info.get("header_formats", ()):
                return scanner_id

        return None

    def get_scanner_id_for_content_routed_filename(self, path: str) -> str | None:
        """Resolve a scanner from an exact descriptor-owned filename route."""
        filename = Path(path).name.lower()
        for scanner_id, scanner_info in sorted(self._scanners.items(), key=lambda item: item[1]["priority"]):
            if not self._is_content_routed_filename(filename, scanner_info):
                continue
            scanner_class = self._load_scanner(scanner_id)
            if scanner_class and scanner_class.can_handle(path):
                return scanner_id
        return None

    def get_header_format_to_scanner_ids(self) -> dict[str, str]:
        """Return all descriptor-owned header-format routes without loading scanners."""
        header_format_to_scanner_id = {scanner_id: scanner_id for scanner_id in self._scanners}
        for scanner_id, scanner_info in self._scanners.items():
            for header_format in scanner_info.get("header_formats", ()):
                header_format_to_scanner_id[header_format] = scanner_id
        return header_format_to_scanner_id

    def get_scanner_classes(
        self,
        scanner_selection: ScannerSelectionPolicy | None = None,
    ) -> list[type[BaseScanner]]:
        """Get all available scanner classes in priority order"""
        scanner_classes = []
        # Sort by priority
        sorted_scanners = sorted(self._scanners.items(), key=lambda x: x[1]["priority"])

        for scanner_id, _ in sorted_scanners:
            if scanner_selection is not None and not scanner_selection.allows(scanner_id):
                continue
            scanner_class = self._load_scanner(scanner_id)
            if scanner_class:
                scanner_classes.append(scanner_class)

        return scanner_classes

    def get_scanner_for_path(
        self,
        path: str,
        scanner_selection: ScannerSelectionPolicy | None = None,
    ) -> type[BaseScanner] | None:
        """Get the best scanner for a given path (lazy loaded)"""
        import os

        # Sort by priority
        sorted_scanners = sorted(self._scanners.items(), key=lambda x: x[1]["priority"])

        filename = os.path.basename(path).lower()
        if os.path.isdir(path):
            for scanner_id, scanner_info in sorted_scanners:
                if scanner_selection is not None and not scanner_selection.allows(scanner_id):
                    continue
                if "" not in scanner_info.get("extensions", []):
                    continue
                scanner_class = self._load_scanner(scanner_id)
                if scanner_class and scanner_class.can_handle(path):
                    return scanner_class
            return None

        # Try the most specific suffixes first so .tar.gz routes to TarScanner
        # before the generic compressed wrapper scanner can claim the .gz suffix.
        file_ext = os.path.splitext(path)[1].lower()
        suffixes = [suffix.lower() for suffix in Path(path).suffixes]
        candidate_extensions: list[str] = []
        for i in range(len(suffixes), 0, -1):
            candidate = "".join(suffixes[-i:])
            if candidate and candidate not in candidate_extensions:
                candidate_extensions.append(candidate)
        if file_ext and file_ext not in candidate_extensions:
            candidate_extensions.append(file_ext)
        if not candidate_extensions:
            candidate_extensions.append("")

        try:
            read_probe_failed = os.path.isfile(path) and not os.access(path, os.R_OK)
        except OSError:
            read_probe_failed = True
        is_zip_file = False
        zip_probe_failed = False
        try:
            is_zip_file = os.path.isfile(path) and zipfile.is_zipfile(path)
        except OSError:
            # Continue only into scanners that explicitly translate unreadable
            # owned inputs into an operationally incomplete outcome.
            zip_probe_failed = True

        for candidate_extension in candidate_extensions:
            for scanner_id, scanner_info in sorted_scanners:
                if scanner_selection is not None and not scanner_selection.allows(scanner_id):
                    continue
                if (read_probe_failed or zip_probe_failed) and scanner_id not in _READ_FAILURE_AWARE_EXTENSION_SCANNERS:
                    continue
                extensions = scanner_info.get("extensions", [])
                content_routed_extensions = scanner_info.get("content_routed_extensions", [])
                if candidate_extension not in extensions and candidate_extension not in content_routed_extensions:
                    continue

                scanner_class = self._load_scanner(scanner_id)
                unreadable_extension_owner = (
                    read_probe_failed
                    and candidate_extension in _READ_FAILURE_AWARE_UNREADABLE_EXTENSION_OWNERS.get(scanner_id, ())
                )
                if scanner_class and (scanner_class.can_handle(path) or unreadable_extension_owner):
                    if scanner_id != "llamafile" and (
                        scanner_selection is None or scanner_selection.allows("llamafile")
                    ):
                        from modelaudit.utils.file.detection import is_llamafile_executable

                        if is_llamafile_executable(path):
                            llamafile_class = self._load_scanner("llamafile")
                            if llamafile_class:
                                return llamafile_class
                    if scanner_id != "torch7" and (scanner_selection is None or scanner_selection.allows("torch7")):
                        from modelaudit.utils.file.detection import is_torch7_suffix_override_candidate

                        if is_torch7_suffix_override_candidate(path):
                            torch7_class = self._load_scanner("torch7")
                            if torch7_class and torch7_class.can_handle(path):
                                return torch7_class
                    return scanner_class

        # Filename-owned scanners still need to retain ownership when an
        # unreadable file prevents later content-routing fallback.
        if read_probe_failed or zip_probe_failed:
            for scanner_id, scanner_info in sorted_scanners:
                if scanner_selection is not None and not scanner_selection.allows(scanner_id):
                    continue
                if scanner_id not in _READ_FAILURE_AWARE_EXTENSION_SCANNERS:
                    continue
                if not self._is_content_routed_filename(filename, scanner_info):
                    continue

                scanner_class = self._load_scanner(scanner_id)
                if scanner_class and scanner_class.can_handle(path):
                    return scanner_class
            return None

        # Some ZIP-backed artifacts intentionally use pickle/checkpoint suffixes.
        # If stricter extension-specific scanners all decline, fall back to the
        # generic ZIP scanner so helper-level routing does not drop coverage.
        if is_zip_file and (scanner_selection is None or scanner_selection.allows("zip")):
            if file_ext == ".model":
                from modelaudit.utils.file.detection import _is_malformed_sentencepiece_model_proto_candidate_file

                if _is_malformed_sentencepiece_model_proto_candidate_file(path):
                    return None
            scanner_class = self._load_scanner("zip")
            if scanner_class and scanner_class.can_handle(path):
                return scanner_class

        try:
            from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension

            header_format = detect_file_format(path)
            extension_format = detect_format_from_extension(path)
        except Exception:
            header_format = "unknown"
            extension_format = "unknown"

        header_scanner_id = self.get_scanner_id_for_header_format(header_format)
        header_scanner_info = self._scanners.get(header_scanner_id or "")
        extension_scanner_id = self.get_scanner_id_for_header_format(extension_format)
        compatible_header_route = (
            header_format == header_scanner_id
            or extension_format == "unknown"
            or extension_scanner_id == header_scanner_id
        )
        if (
            header_scanner_id
            and header_scanner_info
            and compatible_header_route
            and (scanner_selection is None or scanner_selection.allows(header_scanner_id))
        ):
            scanner_class = self._load_scanner(header_scanner_id)
            if scanner_class and (
                scanner_class.can_handle(path) or (header_scanner_id != "zip" and os.path.exists(path))
            ):
                return scanner_class

        # Manifest-like config files sometimes intentionally use generic or
        # missing extensions, so keep the descriptor-owned filename fallback.
        for scanner_id, scanner_info in sorted_scanners:
            if scanner_selection is not None and not scanner_selection.allows(scanner_id):
                continue
            if not self._is_content_routed_filename(filename, scanner_info):
                continue

            scanner_class = self._load_scanner(scanner_id)
            if scanner_class and scanner_class.can_handle(path):
                return scanner_class

        return None

    def get_available_scanners(self) -> list[str]:
        """Get list of available scanner IDs"""
        return list(self._scanners.keys())

    def get_scanner_info(self, scanner_id: str) -> dict[str, Any] | None:
        """Get metadata about a scanner without loading it"""
        return self._scanners.get(scanner_id)

    def load_scanner_by_id(self, scanner_id: str) -> type[BaseScanner] | None:
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

    @staticmethod
    def _is_content_routed_filename(filename: str, scanner_info: dict[str, Any]) -> bool:
        """Check descriptor-declared filename routes without arbitrary suffix fallback."""
        if not filename:
            return False

        content_routed_filenames = {
            str(routed_name).lower() for routed_name in scanner_info.get("content_routed_filenames", [])
        }
        if filename in content_routed_filenames:
            return True

        if any(
            filename.startswith(str(prefix).lower())
            for prefix in scanner_info.get("content_routed_filename_prefixes", [])
        ):
            return True

        allowed_extensions = {str(extension).lower() for extension in scanner_info.get("extensions", [])}
        allowed_extensions.discard("")
        if not allowed_extensions:
            return False

        for routed_name in content_routed_filenames:
            if "".join(Path(routed_name).suffixes):
                continue
            if any(filename == f"{routed_name}{extension}" for extension in allowed_extensions):
                return True

        return False


# Global registry instance
_registry = ScannerRegistry()


class _LazyList:
    """Lazy list that loads scanners only when accessed (thread-safe)"""

    def __init__(self, registry: ScannerRegistry) -> None:
        self._registry = registry
        self._cached_list: list[type[BaseScanner]] | None = None
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
    """Lazy-load scanner classes from the registry's descriptor catalog."""
    scanner_id = _registry.get_scanner_id_for_class(name)
    if scanner_id is not None:
        scanner_class = _registry.load_scanner_by_id(scanner_id)
        if scanner_class:
            return scanner_class
        raise ImportError(
            f"Failed to load scanner '{name}' - dependencies may not be installed",
        )

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Helper function for getting scanner for a file
def get_scanner_for_file(path: str, config: dict[str, Any] | None = None) -> BaseScanner | None:
    """Get an instantiated scanner for a given file path"""
    scanner_selection = policy_from_config(config)
    from .zip_scanner import ZipScanner

    raw_config = config or {}
    try:
        max_entries = int(raw_config.get("max_zip_entries", ZipScanner.DEFAULT_MAX_ENTRIES))
    except (TypeError, ValueError):
        max_entries = ZipScanner.DEFAULT_MAX_ENTRIES
    max_directory_size = ZipScanner.central_directory_size_limit(raw_config)
    if allows_zip_structure_analysis(scanner_selection, path) and ZipScanner.requires_preflight_result(
        path,
        max_entries,
        max_directory_size,
    ):
        return ZipScanner(config=config)
    scanner_class = _registry.get_scanner_for_path(
        path,
        scanner_selection=scanner_selection if scanner_selection.active else None,
    )
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
    "get_scanner_for_file",
    # Scanner classes will be lazy loaded via __getattr__
]
