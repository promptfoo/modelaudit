"""
Central registry of model file extensions supported by ModelAudit.

Dynamically extracts all scannable file extensions from the scanner registry
to ensure we always know what ModelAudit can scan.
"""

from ..scanner_registry_metadata import get_registered_scanner_extensions


def get_all_scannable_extensions() -> set[str]:
    """
    Get ALL file extensions that have registered scanners.

    This includes model files, configs, documentation, archives, templates, etc.
    Anything that ModelAudit has a scanner for will be included.

    Returns:
        Set of all file extensions with scanners (e.g., {'.pkl', '.json', '.md', '.zip'})

    Example:
        >>> extensions = get_all_scannable_extensions()
        >>> '.pkl' in extensions  # Pickle scanner
        True
        >>> '.json' in extensions  # Manifest scanner
        True
        >>> '.md' in extensions  # Text scanner
        True
        >>> '.zip' in extensions  # Zip scanner
        True
    """
    return get_registered_scanner_extensions()


# Cache for all scannable extensions
_SCANNABLE_EXTENSIONS_CACHE: set[str] | None = None


def get_model_extensions() -> set[str]:
    """
    Get cached scannable extensions (alias for backwards compatibility).

    Returns:
        Cached set of all scannable file extensions
    """
    global _SCANNABLE_EXTENSIONS_CACHE
    if _SCANNABLE_EXTENSIONS_CACHE is None:
        _SCANNABLE_EXTENSIONS_CACHE = get_all_scannable_extensions()
    return _SCANNABLE_EXTENSIONS_CACHE
