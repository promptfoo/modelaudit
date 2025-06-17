"""
Consolidated suspicious symbols used by ModelAudit security scanners.

This module centralizes all security pattern definitions used across ModelAudit scanners
to ensure consistency, maintainability, and comprehensive threat detection.

Architecture Overview:
    The suspicious symbols system provides a centralized repository of security patterns
    that are imported by individual scanners (PickleScanner, TensorFlowScanner, etc.).
    This approach ensures:

    1. **Consistency**: All scanners use the same threat definitions
    2. **Maintainability**: Security patterns are updated in one location
    3. **Extensibility**: New patterns can be added without modifying multiple files
    4. **Performance**: Compiled regex patterns are shared across scanners

Usage Examples:
    >>> from modelaudit.suspicious_symbols import SUSPICIOUS_GLOBALS, SUSPICIOUS_OPS
    >>>
    >>> # Check if a global reference is suspicious
    >>> if "os" in SUSPICIOUS_GLOBALS:
    >>>     print("os module flagged as suspicious")
    >>>
    >>> # Check TensorFlow operations
    >>> if "PyFunc" in SUSPICIOUS_OPS:
    >>>     print("PyFunc operation flagged as suspicious")

Security Pattern Categories:
    - SUSPICIOUS_GLOBALS: Dangerous Python modules/functions (pickle files)
    - SUSPICIOUS_STRING_PATTERNS: Regex patterns for malicious code strings
    - SUSPICIOUS_OPS: Dangerous TensorFlow operations
    - SUSPICIOUS_LAYER_TYPES: Risky Keras layer types
    - SUSPICIOUS_CONFIG_PROPERTIES: Dangerous configuration keys
    - SUSPICIOUS_CONFIG_PATTERNS: Manifest file security patterns

Maintenance Guidelines:
    When adding new patterns:
    1. Document the security rationale in comments
    2. Add corresponding test cases
    3. Consider false positive impact on legitimate ML models
    4. Test against real-world model samples
    5. Update this module's docstring with new pattern categories

Performance Considerations:
    - String patterns use compiled regex for efficiency
    - Dictionary lookups are O(1) for module checks
    - Patterns are loaded once at import time
    - Consider pattern complexity for large model files

Version History:
    - v1.0: Initial consolidation from individual scanner files
    - v1.1: Added documentation and architecture overview
"""

from typing import Any

# =============================================================================
# PICKLE SECURITY PATTERNS
# =============================================================================

# Suspicious globals used by PickleScanner
# These represent Python modules/functions that can execute arbitrary code
# when encountered in pickle files during deserialization
SUSPICIOUS_GLOBALS = {
    # System interaction modules - HIGH RISK
    "os": "*",  # File system operations, command execution
    "posix": "*",  # Unix system calls (os.system equivalent)
    "sys": "*",  # Python runtime manipulation
    "subprocess": "*",  # Process spawning and control
    "runpy": "*",  # Dynamic module execution
    # Code execution functions - CRITICAL RISK
    "builtins": ["eval", "exec", "__import__"],  # Dynamic code evaluation
    "operator": ["attrgetter"],  # Attribute access bypass
    "importlib": ["import_module"],  # Dynamic module loading
    # Serialization/deserialization - MEDIUM RISK
    "pickle": ["loads", "load"],  # Recursive pickle loading
    "base64": ["b64decode", "b64encode", "decode"],  # Encoding/obfuscation
    "codecs": ["decode", "encode"],  # Text encoding manipulation
    # File system operations - HIGH RISK
    "shutil": ["rmtree", "copy", "move"],  # File system modifications
    "tempfile": ["mktemp"],  # Temporary file creation
    # Process control - CRITICAL RISK
    "pty": ["spawn"],  # Pseudo-terminal spawning
    "platform": ["system", "popen"],  # System information/execution
    # Low-level system access - CRITICAL RISK
    "ctypes": ["*"],  # C library access
    "socket": ["*"],  # Network communication
    # Serialization libraries that can execute arbitrary code - HIGH RISK
    "dill": [
        "load",
        "loads",
        "load_module",
        "load_module_asdict",
        "load_session",
    ],  # dill's load helpers can execute arbitrary code when unpickling
    # References to the private dill._dill module are also suspicious
    "dill._dill": "*",
}

# Suspicious string patterns used by PickleScanner
# Regex patterns that match potentially malicious code in string literals
SUSPICIOUS_STRING_PATTERNS = [
    # Python magic methods - can hide malicious code
    r"__[\w]+__",  # Magic methods like __reduce__, __setstate__
    # Encoding/decoding operations - often used for obfuscation
    r"base64\.b64decode",  # Base64 decoding
    # Dynamic code execution - CRITICAL
    r"eval\(",  # Dynamic expression evaluation
    r"exec\(",  # Dynamic code execution
    # System command execution - CRITICAL
    r"os\.system",  # Direct system command execution
    r"subprocess\.(?:Popen|call|check_output)",  # Process spawning
    # Dynamic imports - HIGH RISK
    r"import ",  # Import statements in strings
    r"importlib",  # Dynamic import library
    r"__import__",  # Built-in import function
    # Code construction - MEDIUM RISK
    r"lambda",  # Anonymous function creation
    # Hex encoding - possible obfuscation
    r"\\x[0-9a-fA-F]{2}",  # Hex-encoded characters
]

# =============================================================================
# TENSORFLOW/KERAS SECURITY PATTERNS
# =============================================================================

# Suspicious TensorFlow operations
# These operations can perform file I/O, code execution, or system interaction
SUSPICIOUS_OPS = {
    # File system operations - HIGH RISK
    "ReadFile",  # Read arbitrary files
    "WriteFile",  # Write arbitrary files
    "MergeV2Checkpoints",  # Checkpoint manipulation
    "Save",  # Save operations (potential overwrite)
    "SaveV2",  # SaveV2 operations
    # Code execution - CRITICAL RISK
    "PyFunc",  # Execute Python functions
    "PyCall",  # Call Python code
    # System operations - CRITICAL RISK
    "ShellExecute",  # Execute shell commands
    "ExecuteOp",  # Execute arbitrary operations
    "SystemConfig",  # System configuration access
    # Data decoding - MEDIUM RISK (can process untrusted data)
    "DecodeRaw",  # Raw data decoding
    "DecodeJpeg",  # JPEG decoding (image processing)
    "DecodePng",  # PNG decoding (image processing)
}

# Suspicious Keras layer types
# Layer types that can contain arbitrary code or complex functionality
SUSPICIOUS_LAYER_TYPES = {
    "Lambda": "Can contain arbitrary Python code",
    "TFOpLambda": "Can call TensorFlow operations",
    "Functional": "Complex layer that might hide malicious components",
    "PyFunc": "Can execute Python code",
    "CallbackLambda": "Can execute callbacks at runtime",
}

# Suspicious configuration properties for Keras models
# Configuration keys that might contain executable code
SUSPICIOUS_CONFIG_PROPERTIES = [
    "function",  # Function references
    "module",  # Module specifications
    "code",  # Code strings
    "eval",  # Evaluation expressions
    "exec",  # Execution commands
    "import",  # Import statements
    "subprocess",  # Process control
    "os.",  # Operating system calls
    "system",  # System function calls
    "popen",  # Process opening
    "shell",  # Shell access
]

# =============================================================================
# MANIFEST/CONFIGURATION SECURITY PATTERNS
# =============================================================================

# Suspicious configuration patterns for manifest files
# Grouped by threat category for easier maintenance and understanding
SUSPICIOUS_CONFIG_PATTERNS = {
    # Network access patterns - MEDIUM RISK
    # These patterns indicate potential for unauthorized network communication
    "network_access": [
        "url",  # URLs for data exfiltration
        "endpoint",  # API endpoints
        "server",  # Server specifications
        "host",  # Host configurations
        "callback",  # Callback URLs
        "webhook",  # Webhook endpoints
        "http",  # HTTP protocol usage
        "https",  # HTTPS protocol usage
        "ftp",  # FTP protocol usage
        "socket",  # Socket connections
    ],
    # File access patterns - HIGH RISK
    # These patterns indicate potential for unauthorized file system access
    "file_access": [
        "file",  # File references
        "path",  # Path specifications
        "directory",  # Directory access
        "folder",  # Folder references
        "output",  # Output file specifications
        "save",  # Save operations
        "load",  # Load operations
        "write",  # Write operations
        "read",  # Read operations
    ],
    # Code execution patterns - CRITICAL RISK
    # These patterns indicate potential for arbitrary code execution
    "execution": [
        "exec",  # Execution commands
        "eval",  # Evaluation expressions
        "execute",  # Execute operations
        "run",  # Run commands
        "command",  # Command specifications
        "script",  # Script references
        "shell",  # Shell access
        "subprocess",  # Process spawning
        "system",  # System calls
        "code",  # Code strings
    ],
    # Credential patterns - HIGH RISK (data exposure)
    # These patterns indicate potential credential exposure
    "credentials": [
        "password",  # Password fields
        "secret",  # Secret values
        "credential",  # Credential specifications
        "auth",  # Authentication data
        "authentication",  # Authentication configuration
        "api_key",  # API key storage
    ],
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_all_suspicious_patterns() -> dict[str, Any]:
    """
    Get all suspicious patterns for testing or analysis.

    Returns:
        Dictionary containing all pattern categories with metadata
    """
    return {
        "pickle_globals": {
            "patterns": SUSPICIOUS_GLOBALS,
            "description": "Dangerous Python modules/functions in pickle files",
            "risk_level": "HIGH",
        },
        "pickle_strings": {
            "patterns": SUSPICIOUS_STRING_PATTERNS,
            "description": "Regex patterns for malicious code strings",
            "risk_level": "MEDIUM-HIGH",
        },
        "tensorflow_ops": {
            "patterns": SUSPICIOUS_OPS,
            "description": "Dangerous TensorFlow operations",
            "risk_level": "HIGH",
        },
        "keras_layers": {
            "patterns": SUSPICIOUS_LAYER_TYPES,
            "description": "Risky Keras layer types",
            "risk_level": "MEDIUM",
        },
        "config_properties": {
            "patterns": SUSPICIOUS_CONFIG_PROPERTIES,
            "description": "Dangerous configuration keys",
            "risk_level": "MEDIUM",
        },
        "manifest_patterns": {
            "patterns": SUSPICIOUS_CONFIG_PATTERNS,
            "description": "Manifest file security patterns",
            "risk_level": "MEDIUM",
        },
    }


def validate_patterns() -> list[str]:
    """
    Validate all suspicious patterns for correctness.

    Returns:
        List of validation warnings/errors (empty list if all valid)
    """
    import re

    warnings = []

    # Validate regex patterns
    for pattern in SUSPICIOUS_STRING_PATTERNS:
        try:
            re.compile(pattern)
        except re.error as e:
            warnings.append(f"Invalid regex pattern '{pattern}': {e}")

    # Validate global patterns structure
    for module, funcs in SUSPICIOUS_GLOBALS.items():
        if not isinstance(module, str):
            warnings.append(f"Module name must be string: {module}")
        if not (funcs == "*" or isinstance(funcs, list)):
            warnings.append(f"Functions must be '*' or list for module {module}")

    return warnings
