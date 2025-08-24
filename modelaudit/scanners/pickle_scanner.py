# Legacy compatibility module
# This module provides backward compatibility for code importing PickleScanner
# from the old pickle_scanner module name

import pickletools  # Standard library module

from ..suspicious_symbols import SUSPICIOUS_GLOBALS
from .fickling_pickle_scanner import FicklingPickleScanner

# Legacy alias - maintains backward compatibility
PickleScanner = FicklingPickleScanner

# Legacy function compatibility
def is_suspicious_global(module_name: str, func_name: str) -> bool:
    """
    Check if a global module/function combination is suspicious.

    This function provides backward compatibility for tests that expect
    the old PickleScanner interface.
    """
    if module_name not in SUSPICIOUS_GLOBALS:
        return False

    suspicious_funcs = SUSPICIOUS_GLOBALS[module_name]
    if suspicious_funcs == "*":
        return True

    if isinstance(suspicious_funcs, list):
        return func_name in suspicious_funcs

    return False

# Legacy constants for backward compatibility
ML_SAFE_GLOBALS = {
    "joblib": ["dump", "load", "Memory"],
    "dill": ["dump", "load", "dumps", "loads"],
    "pickle": ["dump", "load", "dumps", "loads"],
    "numpy": ["array", "load", "save", "ndarray", "dtype", "_reconstruct"],
    "torch": ["save", "load", "tensor"],
    "sklearn": ["Pipeline", "BaseEstimator"]
}

# ML context detection function (from fickling_pickle_scanner)
def _detect_ml_context(data):
    """
    Legacy function that delegates to the FicklingPickleScanner's _detect_ml_context method.
    """
    scanner = FicklingPickleScanner()
    return scanner._detect_ml_context(data)

def _is_legitimate_serialization_file(file_path: str) -> bool:
    """
    Check if a file appears to be a legitimate serialization file.

    This is a simplified compatibility function that checks for basic
    file existence and common serialization patterns.
    """
    import os

    if not os.path.exists(file_path):
        return False

    if os.path.getsize(file_path) == 0:
        return False

    # Check file extension
    legitimate_extensions = [".pkl", ".pickle", ".joblib", ".dill", ".p"]
    if not any(file_path.lower().endswith(ext) for ext in legitimate_extensions):
        return False

    # Basic magic byte check for pickle files
    try:
        with open(file_path, "rb") as f:
            first_bytes = f.read(8)
            if not first_bytes:
                return False

            # Check for pickle protocol markers
            pickle_markers = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05", b"("]
            if any(first_bytes.startswith(marker) for marker in pickle_markers):
                return True

    except OSError:
        return False

    return False

def _is_actually_dangerous_global(module_name: str, func_name: str) -> bool:
    """
    Determine if a global is actually dangerous in the current context.

    This is a more nuanced version of is_suspicious_global that considers
    ML context and legitimate use cases.
    """
    # For backward compatibility, delegate to is_suspicious_global
    # but exclude some ML-safe cases
    if not is_suspicious_global(module_name, func_name):
        return False

    # Allow some ML-related patterns that might be flagged but are generally safe
    ml_safe_patterns = [
        ("numpy", "_reconstruct"),  # NumPy array reconstruction
        ("numpy", "dtype"),         # Data type definitions
        ("torch", "load"),          # PyTorch model loading
        ("sklearn", "Pipeline"),    # Sklearn pipelines
    ]

    return (module_name, func_name) not in ml_safe_patterns

def _should_ignore_opcode_sequence(opcodes: list) -> bool:
    """
    Determine if an opcode sequence should be ignored as benign.

    This function provides backward compatibility for tests that expect
    opcode sequence analysis.
    """
    if not opcodes:
        return True

    # Simple heuristic: if the sequence only contains "safe" operations
    # like GLOBAL references to known ML modules, we can ignore it
    safe_patterns = [
        "numpy",
        "torch",
        "sklearn",
        "pandas",
        "collections",
        "OrderedDict"
    ]

    # Convert opcodes to string representation for pattern matching
    opcodes_str = str(opcodes).lower()

    # If the sequence only contains safe ML-related patterns, ignore it
    if any(pattern in opcodes_str for pattern in safe_patterns):
        # But check for dangerous operations mixed in
        dangerous_patterns = ["system", "exec", "eval", "import", "open"]
        if not any(pattern in opcodes_str for pattern in dangerous_patterns):
            return True

    return False

# Export for backwards compatibility
__all__ = [
    "ML_SAFE_GLOBALS",
    "PickleScanner",
    "_detect_ml_context",
    "_is_actually_dangerous_global",
    "_is_legitimate_serialization_file",
    "_should_ignore_opcode_sequence",
    "is_suspicious_global",
    "pickletools"  # Re-export standard library module
]
