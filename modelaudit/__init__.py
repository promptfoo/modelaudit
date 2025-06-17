"""ModelAudit package initialization.

This package uses the modern single-source version approach recommended by the
Python Packaging Authority (PyPA) as of 2025. The version is defined once in
pyproject.toml and accessed at runtime via importlib.metadata.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("modelaudit")
except PackageNotFoundError:
    # Package is not installed or in development mode
    __version__ = "unknown"
