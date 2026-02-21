"""ModelAudit package initialization.

This package uses the modern single-source version approach recommended by the
Python Packaging Authority (PyPA) as of 2025. The version is defined once in
pyproject.toml and accessed at runtime via importlib.metadata.
"""

import sys

if sys.version_info < (3, 10):  # noqa: UP036 — intentional safety net for bypassed requires-python
    import warnings

    warnings.warn(
        f"modelaudit requires Python 3.10+, but you are running Python "
        f"{sys.version_info[0]}.{sys.version_info[1]}. "
        f"Please upgrade: https://www.promptfoo.dev/docs/model-audit/",
        stacklevel=2,
    )

# Set high recursion limit for security analysis
# ModelAudit needs to handle complex file structures and deep analysis
# This is safe since we're analyzing files, not executing arbitrary code
_original_recursion_limit = sys.getrecursionlimit()
_MODELAUDIT_RECURSION_LIMIT = max(_original_recursion_limit, 10000)

# Only increase the limit, never decrease it
if _original_recursion_limit < _MODELAUDIT_RECURSION_LIMIT:
    sys.setrecursionlimit(_MODELAUDIT_RECURSION_LIMIT)

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("modelaudit")
except RecursionError:
    # Should be very rare now with higher recursion limit
    __version__ = "unknown"
except PackageNotFoundError:  # type: ignore[possibly-unresolved-reference]
    # Package is not installed or in development mode
    __version__ = "unknown"


def ensure_high_recursion_limit(minimum_limit: int = 10000) -> int:
    """
    Ensure the recursion limit is at least the specified minimum.

    This is safe for ModelAudit since we're analyzing files, not executing arbitrary code.
    Returns the previous recursion limit.
    """
    current_limit = sys.getrecursionlimit()
    if current_limit < minimum_limit:
        sys.setrecursionlimit(minimum_limit)
    return current_limit


# Public API — lazy-loaded to avoid circular imports at package init time.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "scan_file": ("modelaudit.core", "scan_file"),
    "scan_model_directory_or_file": ("modelaudit.core", "scan_model_directory_or_file"),
    "ScanResult": ("modelaudit.scanners.base", "ScanResult"),
    "IssueSeverity": ("modelaudit.scanners.base", "IssueSeverity"),
    "Issue": ("modelaudit.scanners.base", "Issue"),
    "BaseScanner": ("modelaudit.scanners.base", "BaseScanner"),
}


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        import importlib

        mod = importlib.import_module(module_path)
        val = getattr(mod, attr)
        # Cache on the module so __getattr__ is not called again
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseScanner",
    "Issue",
    "IssueSeverity",
    "ScanResult",
    "__version__",
    "scan_file",
    "scan_model_directory_or_file",
]
