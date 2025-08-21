"""ModelAudit package initialization.

This package uses the modern single-source version approach recommended by the
Python Packaging Authority (PyPA) as of 2025. The version is defined once in
pyproject.toml and accessed at runtime via importlib.metadata.
"""

import sys

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
except PackageNotFoundError:
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
