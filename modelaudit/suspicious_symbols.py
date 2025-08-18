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

from .explanations import DANGEROUS_OPCODES as _EXPLAIN_OPCODES

# =============================================================================
# PICKLE SECURITY PATTERNS
# =============================================================================

# Suspicious globals used by PickleScanner
# These represent Python modules/functions that can execute arbitrary code
# when encountered in pickle files during deserialization
SUSPICIOUS_GLOBALS = {
    # System interaction modules - HIGH RISK
    "os": "*",  # File system operations, command execution (system, popen, spawn*)
    "posix": "*",  # Unix system calls (os.system equivalent)
    "sys": "*",  # Python runtime manipulation
    "subprocess": "*",  # Process spawning and control (call, run, Popen, check_output)
    "runpy": "*",  # Dynamic module execution (run_module, run_path)
    "commands": "*",  # Python 2 legacy command execution (getoutput, getstatusoutput)
    "webbrowser": "*",  # Can open malicious URLs (open, open_new, open_new_tab)
    "importlib": "*",  # Dynamic module imports (import_module, reload)
    # Code execution functions - CRITICAL RISK
    "builtins": [
        "eval",
        "exec",
        "compile",
        "open",
        "input",
        "__import__",
    ],  # Dynamic code evaluation and file access
    # Python 2 style builtins - CRITICAL RISK
    "__builtin__": [
        "eval",
        "exec",
        "execfile",
        "compile",
        "open",
        "input",
        "raw_input",
        "__import__",
        "reload",
    ],  # Python 2 style builtin functions (still exploitable in many contexts)
    # Alternative builtin references - CRITICAL RISK
    "__builtins__": [
        "eval",
        "exec",
        "compile",
        "open",
        "input",
        "__import__",
    ],  # Sometimes used as dict or module reference
    "operator": ["attrgetter"],  # Attribute access bypass
    "importlib.machinery": "*",  # Module machinery manipulation
    "importlib.util": "*",  # Module utilities for dynamic imports
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

# Builtin functions that enable dynamic code execution or module loading
DANGEROUS_BUILTINS = [
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "__import__",
    "globals",  # Access to global namespace
    "locals",  # Access to local namespace
    "setattr",  # Can set arbitrary attributes
    "getattr",  # Can access arbitrary attributes
    "delattr",  # Can delete attributes
    "vars",  # Access to object's namespace
    "dir",  # Can enumerate available attributes
]

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
    r"os\.popen",  # Process spawning with pipe
    r"os\.spawn[a-z]*",  # os.spawn* variants (spawnv, spawnve, spawnl, etc.)
    r"subprocess\.(?:Popen|call|check_output|run|check_call)",  # Process spawning
    r"commands\.(?:getoutput|getstatusoutput)",  # Python 2 legacy command execution
    # Dynamic imports - HIGH RISK
    # Match explicit module imports to reduce noise from unrelated "import" substrings
    r"\bimport\s+[\w\.]+",  # Import statements referencing modules
    r"importlib",  # Dynamic import library
    r"__import__",  # Built-in import function
    # Code construction - MEDIUM RISK
    r"lambda",  # Anonymous function creation
    # Hex encoding - possible obfuscation
    r"\\x[0-9a-fA-F]{2}",  # Hex-encoded characters
]

# Suspicious metadata patterns used by SafeTensorsScanner and others
# Regex patterns that match unusual or potentially malicious metadata values
SUSPICIOUS_METADATA_PATTERNS = [
    r"https?://",  # Embedded URLs can be used for exfiltration
    r"(?i)\bimport\s+(?:os|subprocess|sys)\b",  # Inline Python imports
    r"(?i)(?:rm\s+-rf|wget\s|curl\s|chmod\s)",  # Shell command indicators
    r"(?i)<script",  # Embedded HTML/JS content
]

# Dangerous pickle opcodes that can lead to code execution
DANGEROUS_OPCODES = set(_EXPLAIN_OPCODES.keys())

# ======================================================================
# BINARY SECURITY PATTERNS
# ======================================================================

# Byte patterns that commonly indicate embedded Python code in binary blobs
# Used by scanners that analyze raw binary sections for malicious content
BINARY_CODE_PATTERNS: list[bytes] = [
    b"import os",
    b"import sys",
    b"import subprocess",
    b"eval(",
    b"exec(",
    b"__import__",
    b"compile(",
    b"globals()",
    b"locals()",
    b"open(",
    b"file(",
    b"input(",
    b"raw_input(",
    b"execfile(",
    b"os.system",
    b"subprocess.call",
    b"subprocess.Popen",
    b"socket.socket",
]

# Common executable file signatures found in malicious model data
EXECUTABLE_SIGNATURES: dict[bytes, str] = {
    b"MZ": "Windows executable (PE)",
    b"\x7fELF": "Linux executable (ELF)",
    b"\xfe\xed\xfa\xce": "macOS executable (Mach-O 32-bit)",
    b"\xfe\xed\xfa\xcf": "macOS executable (Mach-O 64-bit)",
    b"\xcf\xfa\xed\xfe": "macOS executable (Mach-O)",
    b"#!/": "Shell script shebang",
    b"#!/bin/": "Shell script shebang",
    b"#!/usr/bin/": "Shell script shebang",
}

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
        "dangerous_builtins": {
            "patterns": DANGEROUS_BUILTINS,
            "description": "Builtin functions enabling dynamic code execution",
            "risk_level": "HIGH",
        },
        "dangerous_opcodes": {
            "patterns": sorted(DANGEROUS_OPCODES),
            "description": "Pickle opcodes that can trigger code execution",
            "risk_level": "HIGH",
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
        "metadata_strings": {
            "patterns": SUSPICIOUS_METADATA_PATTERNS,
            "description": "Regex patterns for suspicious metadata values in model files",
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
    for pattern in SUSPICIOUS_STRING_PATTERNS + SUSPICIOUS_METADATA_PATTERNS:
        try:
            re.compile(pattern)
        except re.error as e:
            warnings.append(f"Invalid regex pattern '{pattern}': {e}")

    # Validate global patterns structure
    for module, funcs in SUSPICIOUS_GLOBALS.items():
        if not isinstance(module, str):
            warnings.append(f"Module name must be string: {module}")  # pragma: no cover
        if not (funcs == "*" or isinstance(funcs, list)):
            warnings.append(f"Functions must be '*' or list for module {module}")

    # Validate dangerous builtins
    for builtin in DANGEROUS_BUILTINS:
        if not isinstance(builtin, str):
            warnings.append(f"Builtin name must be string: {builtin}")  # pragma: no cover

    # Validate dangerous opcodes
    for opcode in DANGEROUS_OPCODES:
        if not isinstance(opcode, str):
            warnings.append(f"Opcode name must be string: {opcode}")  # pragma: no cover

    # Validate binary code patterns
    for binary_pattern in BINARY_CODE_PATTERNS:
        if not isinstance(binary_pattern, bytes):
            warnings.append(f"Binary code pattern must be bytes: {binary_pattern!r}")  # pragma: no cover

    # Validate executable signatures
    for signature, description in EXECUTABLE_SIGNATURES.items():
        if not isinstance(signature, bytes):
            warnings.append(f"Signature must be bytes: {signature!r}")  # pragma: no cover
        if not isinstance(description, str):
            warnings.append(f"Description must be string for signature {signature!r}")  # pragma: no cover
        if not description:
            warnings.append(
                f"Description must be non-empty for signature {signature!r}",
            )

    return warnings
