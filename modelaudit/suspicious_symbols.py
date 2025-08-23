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
    - JINJA2_SSTI_PATTERNS: Jinja2 Server-Side Template Injection patterns

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

# OS module aliases that provide system access similar to the 'os' module
OS_MODULE_ALIASES: dict[str, dict[str, Any]] = {
    "nt": {
        "severity": "CRITICAL",
        "description": "Windows OS module alias - provides system access including os.system()",
        "functions": "*",
    },
    "posix": {
        "severity": "CRITICAL",
        "description": "Unix/Linux OS module alias - provides system access including os.system()",
        "functions": "*",
    },
    "ntpath": {
        "severity": "HIGH",
        "description": "Windows path manipulation - can access restricted paths",
        "functions": "*",
    },
    "posixpath": {
        "severity": "HIGH",
        "description": "Unix path manipulation - can access restricted paths",
        "functions": "*",
    },
}

# =============================================================================
# PICKLE SECURITY PATTERNS
# =============================================================================

# Suspicious globals used by PickleScanner
# These represent Python modules/functions that can execute arbitrary code
# when encountered in pickle files during deserialization
SUSPICIOUS_GLOBALS = {
    # System interaction modules - HIGH RISK
    "os": "*",  # File system operations, command execution (system, popen, spawn*)
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
        # Add all dangerous builtins
        "globals",  # Access to global namespace
        "locals",  # Access to local namespace
        "setattr",  # Can set arbitrary attributes
        "getattr",  # Can access arbitrary attributes
        "delattr",  # Can delete attributes
        "vars",  # Access to object's namespace
        "dir",  # Can enumerate available attributes
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

# Advanced pickle patterns targeting sophisticated exploitation techniques
# These patterns represent high-risk modules/functions used in advanced attacks
ADVANCED_PICKLE_PATTERNS = {
    "operator": ["attrgetter"],  # CRITICAL: Can bypass attribute access restrictions to reach dangerous methods
    "pty": "*",  # CRITICAL: Pseudo-terminal spawning enables shell access
    "bdb": "*",  # HIGH: Python debugger can inspect/modify runtime state
    "asyncio": "*",  # MEDIUM: Async execution can obfuscate malicious operations
    "_pickle": "*",  # HIGH: Low-level pickle operations bypass safety checks
    "types": ["CodeType", "FunctionType"],  # CRITICAL: Direct code object construction enables arbitrary code execution
}

# Merge advanced patterns into main suspicious globals set
SUSPICIOUS_GLOBALS.update(ADVANCED_PICKLE_PATTERNS)

# Include OS module aliases in suspicious globals
SUSPICIOUS_GLOBALS.update({alias: data["functions"] for alias, data in OS_MODULE_ALIASES.items()})

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

# =============================================================================
# CVE-SPECIFIC SECURITY PATTERNS
# =============================================================================

# CVE-2020-13092: scikit-learn joblib.load deserialization vulnerability
# Patterns that indicate potential exploitation of insecure joblib.load() usage
CVE_2020_13092_PATTERNS = [
    # Direct exploitation patterns - require both components for higher specificity
    r"joblib\.load.*os\.system",  # joblib.load with system calls
    r"joblib\.load.*subprocess",  # joblib.load with subprocess
    r"sklearn.*joblib\.load.*system",  # sklearn + joblib.load + system calls
    # Attack vector patterns - __reduce__ method exploitation
    r"__reduce__.*os\.system.*sklearn",  # sklearn context with __reduce__ + system
    r"__reduce__.*subprocess.*sklearn",  # sklearn context with __reduce__ + subprocess
    r"__reduce__.*eval.*sklearn",  # sklearn context with __reduce__ + eval
    # Sklearn model with dangerous operations - require both sklearn AND dangerous operation
    r"sklearn.*joblib.*os\.system",  # sklearn + joblib + system calls
    r"sklearn.*joblib.*subprocess",  # sklearn + joblib + subprocess
    r"Pipeline.*__reduce__.*system",  # Pipeline with __reduce__ + system calls
    # File extension indicators - more specific patterns
    r"\.joblib.*sklearn.*os\.system",  # .joblib files with sklearn and system calls
    r"\.pkl.*sklearn.*joblib.*system",  # .pkl files with sklearn + joblib + system
]

# CVE-2024-34997: joblib NumpyArrayWrapper deserialization vulnerability
# Patterns that indicate potential exploitation of NumpyArrayWrapper.read_array()
CVE_2024_34997_PATTERNS = [
    # Direct exploitation patterns - require dangerous combinations
    r"NumpyArrayWrapper.*pickle\.load",  # NumpyArrayWrapper with pickle.load
    r"numpy_pickle.*read_array.*pickle\.load",  # numpy_pickle + read_array + pickle.load
    r"joblib.*NumpyArrayWrapper.*system",  # joblib + NumpyArrayWrapper + system calls
    # Attack vector patterns - pickle.load exploitation via NumpyArrayWrapper
    r"NumpyArrayWrapper.*pickle\.load.*system",  # NumpyArrayWrapper + pickle.load + system
    r"read_array.*pickle\.load.*subprocess",  # read_array + pickle.load + subprocess
    r"numpy_pickle.*pickle\.load.*eval",  # numpy_pickle + pickle.load + eval
    # Cache-related exploitation patterns - require dangerous operations
    r"joblib.*cache.*NumpyArrayWrapper.*system",  # joblib cache + NumpyArrayWrapper + system
    r"NumpyArrayWrapper.*cache.*pickle\.load",  # NumpyArrayWrapper + cache + pickle.load
    r"read_array.*cache.*__reduce__",  # read_array + cache + __reduce__
    # Combined patterns indicating sophisticated attacks
    r"NumpyArrayWrapper.*__reduce__.*system",  # NumpyArrayWrapper + __reduce__ + system
    r"numpy_pickle.*__reduce__.*subprocess",  # numpy_pickle + __reduce__ + subprocess
]

# Combined CVE patterns for efficient scanning
# Used by scanners to detect CVE-specific exploitation attempts
CVE_COMBINED_PATTERNS = {
    "CVE-2020-13092": {
        "patterns": CVE_2020_13092_PATTERNS,
        "description": "scikit-learn joblib.load deserialization vulnerability",
        "severity": "CRITICAL",
        "cwe": "CWE-502",  # Deserialization of Untrusted Data
        "cvss": 9.8,  # Critical severity
        "affected_versions": "scikit-learn <= 0.23.0",
        "remediation": "Update scikit-learn, validate input sources, avoid joblib.load() with untrusted data",
    },
    "CVE-2024-34997": {
        "patterns": CVE_2024_34997_PATTERNS,
        "description": "joblib NumpyArrayWrapper deserialization vulnerability",
        "severity": "HIGH",
        "cwe": "CWE-502",  # Deserialization of Untrusted Data
        "cvss": 8.1,  # High severity
        "affected_versions": "joblib v1.4.2",
        "remediation": "Update joblib, validate cache integrity, avoid untrusted NumpyArrayWrapper data",
    },
}

# Binary patterns for CVE detection in raw file content
CVE_BINARY_PATTERNS = [
    # CVE-2020-13092 binary signatures
    b"joblib.load",
    b"sklearn",
    b"__reduce__",
    b"os.system",
    b"Pipeline",
    # CVE-2024-34997 binary signatures
    b"NumpyArrayWrapper",
    b"read_array",
    b"numpy_pickle",
    b"pickle.load",
    b"joblib.cache",
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
    "PyFuncStateless",  # Execute Python functions (stateless variant)
    "EagerPyFunc",  # Execute Python functions (eager execution)
    "PyCall",  # Call Python code
    # System operations - CRITICAL RISK
    "ShellExecute",  # Execute shell commands
    "ExecuteOp",  # Execute arbitrary operations
    "SystemConfig",  # System configuration access
    # Data decoding - CRITICAL (scanner emits CRITICAL for these ops in suspicious-ops path)
    "DecodeRaw",  # Raw data decoding
    "DecodeJpeg",  # JPEG decoding (image processing)
    "DecodePng",  # PNG decoding (image processing)
}

TENSORFLOW_DANGEROUS_OPS: dict[str, str] = {
    # File system operations - HIGH RISK
    "ReadFile": "Can read arbitrary files from the system",
    "WriteFile": "Can write arbitrary files to the system",
    "MergeV2Checkpoints": "Can manipulate checkpoint files",
    "Save": "Can save data to arbitrary locations",
    "SaveV2": "Can save data to arbitrary locations",
    # Code execution - CRITICAL RISK
    "PyFunc": "Can execute arbitrary Python functions",
    "PyFuncStateless": "Can execute arbitrary Python functions (stateless variant)",
    "EagerPyFunc": "Can execute arbitrary Python functions (eager execution)",
    "PyCall": "Can call arbitrary Python code",
    # System operations - CRITICAL RISK
    "ShellExecute": "Can execute shell commands",
    "ExecuteOp": "Can execute arbitrary operations",
    "SystemConfig": "Can access system configuration",
    # Data decoding - CRITICAL (scanner emits CRITICAL for these ops in suspicious-ops path)
    "DecodeRaw": "Can decode raw image data, potential injection of malicious content",
    "DecodeJpeg": "Can decode JPEG data, potential injection of malicious content",
    "DecodePng": "Can decode PNG data, potential injection of malicious content",
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
# JINJA2 TEMPLATE INJECTION PATTERNS
# =============================================================================

# Jinja2 Server-Side Template Injection (SSTI) patterns
# These patterns detect potential template injection vulnerabilities in ML model templates
# Primarily targeting CVE-2024-34359 and similar SSTI attack vectors in ML contexts
JINJA2_SSTI_PATTERNS = {
    # Critical risk patterns - immediate code execution
    # These patterns indicate direct attempts to execute arbitrary code
    "critical_injection": [
        # Direct function calls for code execution
        r"__import__\s*\(",  # __import__('os').system('cmd')
        r"eval\s*\(",  # eval('malicious_code')
        r"exec\s*\(",  # exec('malicious_code')
        r"compile\s*\(",  # compile('code', '<string>', 'exec')
        # System command execution
        r"os\.system\s*\(",  # os.system('cmd')
        r"os\.popen\s*\(",  # os.popen('cmd')
        r"subprocess\.",  # subprocess.call, subprocess.Popen, etc.
        r"commands\.",  # commands.getoutput (Python 2)
        # Process spawning
        r"os\.spawn[a-z]*\s*\(",  # os.spawnv, os.spawnl, etc.
        r"pty\.spawn\s*\(",  # pty.spawn('/bin/sh')
        # File system manipulation
        r"shutil\.rmtree\s*\(",  # shutil.rmtree('/path')
        r"os\.remove\s*\(",  # os.remove('file')
        r"os\.unlink\s*\(",  # os.unlink('file')
        # Network operations
        r"socket\.socket\s*\(",  # socket.socket()
        r"urllib\.request\.",  # urllib.request.urlopen
        r"requests\.",  # requests.get, requests.post
        # Dynamic module loading
        r"importlib\.",  # importlib.import_module
        r"runpy\.",  # runpy.run_module, runpy.run_path
    ],
    # Object traversal patterns - Python object hierarchy exploitation
    # These patterns navigate Python's object model to reach dangerous functions
    "object_traversal": [
        # Basic object traversal
        r"__class__\.__mro__",  # Access method resolution order
        r"__class__\.__base__",  # Access base class
        r"__class__\.__bases__",  # Access base classes tuple
        r"__subclasses__\(\)",  # Get all subclasses
        # Advanced traversal patterns
        r"__class__\.__mro__\[\d+\]",  # Index into MRO (e.g., __mro__[1])
        r"__class__\.__base__\.__subclasses__\(\)",  # Chain: base -> subclasses
        r"__mro__\[1\]\.__subclasses__\(\)",  # Common pattern: object class
        # Subclass iteration and filtering
        r"__subclasses__\(\)\[\d+\]",  # Direct subclass access by index
        r"for .+ in .*__subclasses__",  # Iterate through subclasses
        r"if .+ in .*__name__",  # Filter classes by name
    ],
    # Global scope access patterns - accessing dangerous global functions
    # These patterns access global namespaces to reach restricted functions
    "global_access": [
        # Direct global access
        r"__globals__\[",  # Access globals dictionary
        r"__builtins__\[",  # Access builtins dictionary
        r"__init__\.__globals__",  # Access through __init__ method
        # Framework-specific global access
        r"self\.__init__\.__globals__",  # Self reference to globals
        r"\.environment\.globals",  # Jinja2 environment globals
        r"cycler\.__init__\.__globals__",  # Via cycler object
        r"joiner\.__init__\.__globals__",  # Via joiner object
        r"namespace\.__init__\.__globals__",  # Via namespace object
        # Request/application context access (web frameworks)
        r"request\.application\.__globals__",  # Flask request object
        r"config\.__class__\.__init__\.__globals__",  # Config object globals
        # Module globals access
        r"\._module\.__builtins__",  # Module builtins
        r"sys\.modules\[",  # Access loaded modules
    ],
    # WAF bypass and obfuscation patterns
    # These patterns detect attempts to evade basic security filters
    "obfuscation": [
        # Character encoding bypasses
        r"\\x[0-9a-fA-F]{2}",  # Hex encoding: \x5f for _
        r"chr\(\d+\)",  # Character construction: chr(95) for _
        r"['\"]\.join\(",  # String joining: ''.join([chr(x) for x in ...])
        # Attribute access bypasses
        r"\|attr\(",  # Jinja2 filter: |attr('__class__')
        r"\[['\"]\w+['\"]\]",  # Bracket notation: ['__class__']
        r"getattr\s*\(",  # getattr(obj, '__class__')
        # String construction bypasses
        r"format\s*\(",  # String formatting
        r"{}".format(r"|format\("),  # Template string formatting
        r"f['\"].*\{",  # f-string formatting
        # Base64 and other encoding
        r"base64\.",  # Base64 encoding/decoding
        r"codecs\.",  # Codec operations
        r"binascii\.",  # Binary/ASCII conversions
    ],
    # Template control flow exploitation
    # These patterns detect malicious use of Jinja2 control structures
    "control_flow": [
        # Loops for class discovery
        r"{% for .+ in .*__subclasses__",  # Loop through subclasses
        r"{% for .+ in .*__mro__",  # Loop through MRO
        r"{% for .+ in .*__dict__",  # Loop through object dict
        # Conditionals for class filtering
        r"{% if .+ in .*__name__",  # Filter by class name
        r"{% if .*warning.* in",  # Common: look for 'warnings' class
        r"{% if .*popen.* in",  # Look for popen functionality
        # Variable assignment for payload staging
        r"{% set .+ = .*__",  # Set variable to dangerous object
        r"{% set .+ = .*\.__class__",  # Set variable to class
        # Macro definition for code reuse
        r"{% macro .+ %}",  # Define reusable code block
    ],
    # Environment and configuration access
    # These patterns detect attempts to access system information
    "environment_access": [
        # Environment variables
        r"os\.environ",  # Access environment variables
        r"sys\.argv",  # Command line arguments
        r"sys\.path",  # Python path
        # System information
        r"platform\.",  # Platform information
        r"sys\.version",  # Python version
        r"os\.getcwd",  # Current working directory
        r"os\.listdir",  # Directory listing
        # Configuration access
        r"config\.items\(\)",  # Framework configuration
        r"app\.config",  # Application config
        r"settings\.",  # Settings access
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
        "tensorflow_dangerous_ops": {
            "patterns": TENSORFLOW_DANGEROUS_OPS,
            "description": "TensorFlow operations with security risk explanations",
            "risk_level": "CRITICAL",
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
        "jinja2_ssti": {
            "patterns": JINJA2_SSTI_PATTERNS,
            "description": "Jinja2 Server-Side Template Injection patterns",
            "risk_level": "CRITICAL",
        },
        "cve_patterns": {
            "patterns": CVE_COMBINED_PATTERNS,
            "description": "CVE-specific vulnerability patterns",
            "risk_level": "CRITICAL",
        },
        "cve_binary_signatures": {
            "patterns": CVE_BINARY_PATTERNS,
            "description": "Binary signatures for CVE detection",
            "risk_level": "HIGH",
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
    all_string_patterns = (
        SUSPICIOUS_STRING_PATTERNS + SUSPICIOUS_METADATA_PATTERNS + CVE_2020_13092_PATTERNS + CVE_2024_34997_PATTERNS
    )
    for pattern in all_string_patterns:
        try:
            re.compile(pattern)
        except re.error as e:
            warnings.append(f"Invalid regex pattern '{pattern}': {e}")

    # Validate CVE pattern structure
    for cve_id, cve_info in CVE_COMBINED_PATTERNS.items():
        if not isinstance(cve_id, str):
            warnings.append(f"CVE ID must be string: {cve_id}")
        if not isinstance(cve_info, dict):
            warnings.append(f"CVE info must be dict for {cve_id}")
        required_fields = ["patterns", "description", "severity", "cwe", "cvss"]
        for field in required_fields:
            if field not in cve_info:
                warnings.append(f"Missing required field '{field}' in {cve_id}")

    # Validate CVE binary patterns
    for binary_pattern in CVE_BINARY_PATTERNS:
        if not isinstance(binary_pattern, bytes):
            warnings.append(f"CVE binary pattern must be bytes: {binary_pattern!r}")

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

    # Validate TensorFlow dangerous ops mapping
    for op, desc in TENSORFLOW_DANGEROUS_OPS.items():
        if not isinstance(op, str) or not op:
            warnings.append(f"TF dangerous op key must be non-empty string: {op!r}")
        if not isinstance(desc, str) or not desc:
            warnings.append(f"TF dangerous op description must be non-empty string for {op!r}")
        if op not in SUSPICIOUS_OPS:
            warnings.append(f"TF dangerous op '{op}' not present in SUSPICIOUS_OPS (possible drift)")

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
