"""Consolidated suspicious symbols used by scanners."""

# Suspicious globals used by PickleScanner
SUSPICIOUS_GLOBALS = {
    "os": "*",
    "posix": "*",
    "sys": "*",
    "subprocess": "*",
    "runpy": "*",
    "builtins": ["eval", "exec", "__import__"],
    "operator": ["attrgetter"],
    "importlib": ["import_module"],
    "pickle": ["loads", "load"],
    "base64": ["b64decode", "b64encode", "decode"],
    "codecs": ["decode", "encode"],
    "shutil": ["rmtree", "copy", "move"],
    "tempfile": ["mktemp"],
    "pty": ["spawn"],
    "platform": ["system", "popen"],
    "ctypes": ["*"],
    "socket": ["*"],
}

# Suspicious string patterns used by PickleScanner
SUSPICIOUS_STRING_PATTERNS = [
    r"__[\w]+__",  # Magic methods
    r"base64\.b64decode",
    r"eval\(",
    r"exec\(",
    r"os\.system",
    r"subprocess\.(?:Popen|call|check_output)",
    r"import ",
    r"importlib",
    r"__import__",
    r"lambda",
    r"\\x[0-9a-fA-F]{2}",  # Hex encoded characters
]

# Suspicious TensorFlow operations
SUSPICIOUS_OPS = {
    "ReadFile",
    "WriteFile",
    "MergeV2Checkpoints",
    "Save",
    "SaveV2",
    "PyFunc",
    "PyCall",
    "ShellExecute",
    "ExecuteOp",
    "SystemConfig",
    "DecodeRaw",
    "DecodeJpeg",
    "DecodePng",
}

# Suspicious Keras layer types
SUSPICIOUS_LAYER_TYPES = {
    "Lambda": "Can contain arbitrary Python code",
    "TFOpLambda": "Can call TensorFlow operations",
    "Functional": "Complex layer that might hide malicious components",
    "PyFunc": "Can execute Python code",
    "CallbackLambda": "Can execute callbacks at runtime",
}

# Suspicious configuration properties for Keras models
SUSPICIOUS_CONFIG_PROPERTIES = [
    "function",
    "module",
    "code",
    "eval",
    "exec",
    "import",
    "subprocess",
    "os.",
    "system",
    "popen",
    "shell",
]

# Suspicious configuration patterns for manifest files
SUSPICIOUS_CONFIG_PATTERNS = {
    "network_access": [
        "url",
        "endpoint",
        "server",
        "host",
        "callback",
        "webhook",
        "http",
        "https",
        "ftp",
        "socket",
    ],
    "file_access": [
        "file",
        "path",
        "directory",
        "folder",
        "output",
        "save",
        "load",
        "write",
        "read",
    ],
    "execution": [
        "exec",
        "eval",
        "execute",
        "run",
        "command",
        "script",
        "shell",
        "subprocess",
        "system",
        "code",
    ],
    "credentials": [
        "password",
        "secret",
        "credential",
        "auth",
        "authentication",
        "api_key",
    ],
}
