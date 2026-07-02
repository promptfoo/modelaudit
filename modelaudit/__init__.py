"""ModelAudit package initialization.

This package uses the modern single-source version approach recommended by the
Python Packaging Authority (PyPA) as of 2025. The version is defined once in
pyproject.toml and accessed at runtime via importlib.metadata.
"""

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modelaudit.core import scan_file as scan_file
    from modelaudit.core import scan_model_directory_or_file as scan_model_directory_or_file
    from modelaudit.scanner_results import Issue as Issue
    from modelaudit.scanner_results import IssueSeverity as IssueSeverity
    from modelaudit.scanner_results import ScanResult as ScanResult
    from modelaudit.scanners.base import BaseScanner as BaseScanner
    from modelaudit.version import __version__ as __version__

if sys.version_info < (3, 10):  # noqa: UP036 — intentional safety net for bypassed requires-python
    import warnings

    warnings.warn(
        f"modelaudit requires Python 3.10+, but you are running Python "
        f"{sys.version_info[0]}.{sys.version_info[1]}. "
        f"Please upgrade: https://www.promptfoo.dev/docs/model-audit/",
        stacklevel=2,
    )

# Public API — lazy-loaded to avoid circular imports at package init time.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "Issue": ("modelaudit.scanner_results", "Issue"),
    "IssueSeverity": ("modelaudit.scanner_results", "IssueSeverity"),
    "ScanResult": ("modelaudit.scanner_results", "ScanResult"),
    "__version__": ("modelaudit.version", "__version__"),
    "scan_file": ("modelaudit.core", "scan_file"),
    "scan_model_directory_or_file": ("modelaudit.core", "scan_model_directory_or_file"),
    "BaseScanner": ("modelaudit.scanners.base", "BaseScanner"),
}


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        import importlib

        mod = importlib.import_module(module_path)
        val = getattr(mod, attr)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__: list[str] = [
    "BaseScanner",
    "Issue",
    "IssueSeverity",
    "ScanResult",
    "__version__",
    "scan_file",
    "scan_model_directory_or_file",
]
