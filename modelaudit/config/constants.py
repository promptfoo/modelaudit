"""Shared constants for ModelAudit."""

from ..scanner_registry_metadata import get_registered_scanner_extensions

# Extensions that ModelAudit can route to a scanner.
SCANNABLE_MODEL_EXTENSIONS: frozenset[str] = frozenset(get_registered_scanner_extensions())

# Subset of core model extensions used for license checking (lower risk, common formats)
COMMON_MODEL_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pkl",
        ".joblib",
        ".pt",
        ".pth",
        ".onnx",
        ".pb",
        ".h5",
        ".keras",
        ".safetensors",
    }
)
