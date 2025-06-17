"""
Security issue explanations for ModelAudit.

This module provides centralized, security-team-friendly explanations
for common security issues found in ML model files.
"""

from typing import Optional

# Common explanations for dangerous imports and modules
DANGEROUS_IMPORTS = {
    "os": "The 'os' module provides direct access to operating system functions, allowing execution of arbitrary system commands, file system manipulation, and environment variable access. Malicious models can use this to compromise the host system, steal data, or install malware.",
    "posix": "The 'posix' module provides direct access to POSIX system calls on Unix-like systems. Like the 'os' module, it can execute arbitrary system commands and manipulate the file system. The 'posix.system' function is equivalent to 'os.system' and poses the same security risks.",
    "sys": "The 'sys' module provides access to interpreter internals and system-specific parameters. It can be used to modify the Python runtime, access command-line arguments, or manipulate the module import system to load malicious code.",
    "subprocess": "The 'subprocess' module allows spawning new processes and executing system commands. This is a critical security risk as it enables arbitrary command execution on the host system.",
    "eval": "The 'eval' function executes arbitrary Python code from strings. This is extremely dangerous as it allows dynamic code execution, potentially running any malicious code embedded in the model.",
    "exec": "The 'exec' function executes arbitrary Python statements from strings. Like eval, this enables unrestricted code execution and is a severe security risk.",
    "__import__": "The '__import__' function dynamically imports modules at runtime. Attackers can use this to load malicious modules or bypass import restrictions.",
    "importlib": "The 'importlib' module provides programmatic module importing capabilities. It can be used to dynamically load malicious code or bypass security controls.",
    "pickle": "Nested pickle operations (pickle.load/loads within a pickle) can indicate attempts to obfuscate malicious payloads or create multi-stage attacks.",
    "base64": "Base64 encoding/decoding functions are often used to obfuscate malicious payloads, making them harder to detect through static analysis.",
    "socket": "The 'socket' module enables network communication. Malicious models can use this to exfiltrate data, download additional payloads, or establish command & control channels.",
    "ctypes": "The 'ctypes' module provides low-level system access through foreign function interfaces. It can bypass Python's safety features and directly manipulate memory or call system libraries.",
    "pty": "The 'pty' module provides pseudo-terminal utilities. The 'spawn' function can be used to create interactive shells, potentially giving attackers remote access.",
    "platform": "Functions like 'platform.system' or 'platform.popen' can be used for system reconnaissance or command execution.",
    "shutil": "The 'shutil' module provides high-level file operations. Functions like 'rmtree' can recursively delete directories, potentially causing data loss.",
    "tempfile": "Unsafe temp file creation (like 'mktemp') can lead to race conditions and security vulnerabilities.",
    "runpy": "The 'runpy' module executes Python modules as scripts, potentially running malicious code embedded in the model.",
    "operator.attrgetter": "The 'attrgetter' function can be used to access object attributes dynamically, potentially bypassing access controls or reaching sensitive data.",
    "builtins": "Direct access to builtin functions can be used to bypass restrictions or access dangerous functionality like eval/exec.",
    "dill": "The 'dill' module extends pickle's capabilities to serialize almost any Python object, including lambda functions and code objects. This significantly increases the attack surface for code execution.",
}

# Explanations for dangerous pickle opcodes
DANGEROUS_OPCODES = {
    "REDUCE": "The REDUCE opcode calls a callable with arguments, effectively executing arbitrary Python functions. This is the primary mechanism for pickle-based code execution attacks through __reduce__ methods.",
    "INST": "The INST opcode instantiates objects by calling their class constructor. Malicious classes can execute code in __init__ methods during unpickling.",
    "OBJ": "The OBJ opcode creates class instances. Like INST, this can trigger code execution through object initialization.",
    "NEWOBJ": "The NEWOBJ opcode creates new-style class instances. It can execute initialization code and is commonly used in pickle exploits.",
    "NEWOBJ_EX": "The NEWOBJ_EX opcode is an extended version of NEWOBJ with additional capabilities for creating objects, potentially executing initialization code.",
    "BUILD": "The BUILD opcode updates object state and can trigger code execution through __setstate__ or __setattr__ methods.",
    "STACK_GLOBAL": "The STACK_GLOBAL opcode imports modules and retrieves attributes dynamically. Outside ML contexts, this often indicates attempts to access dangerous functionality.",
    "GLOBAL": "The GLOBAL opcode imports and accesses module attributes. When referencing dangerous modules, this indicates potential security risks.",
}

# Explanations for specific patterns and behaviors
PATTERN_EXPLANATIONS = {
    "base64_payload": "Base64-encoded data in models often conceals malicious payloads. Legitimate ML models rarely need encoded strings unless handling specific data formats.",
    "hex_encoded": "Hexadecimal-encoded strings (\\x00 format) can hide malicious code or data. This obfuscation technique is commonly used to evade detection.",
    "lambda_layer": "Lambda layers in Keras/TensorFlow can contain arbitrary Python code that executes during model inference. Unlike standard layers, these can perform system operations beyond tensor computations.",
    "executable_in_zip": "Executable files (.exe, .sh, .bat, etc.) within model archives are highly suspicious. ML models should only contain weights and configuration, not executables.",
    "dissimilar_weights": "Weight vectors that are completely dissimilar to others in the same layer may indicate injected malicious data masquerading as model parameters.",
    "outlier_neurons": "Neurons with weight distributions far outside the normal range might encode hidden functionality or backdoors rather than learned features.",
    "blacklisted_name": "This model name appears on security blacklists, indicating known malicious models or naming patterns associated with attacks.",
    "manifest_name_mismatch": "Model names in manifests that don't match expected patterns may indicate tampered or malicious models trying to impersonate legitimate ones.",
    "encoded_strings": "Encoded or obfuscated strings in model files often hide malicious payloads or commands from security scanners.",
    "pickle_size_limit": "Extremely large pickle files may indicate embedded malicious data or attempts to cause resource exhaustion.",
    "nested_pickle": "Pickle operations within pickled data (nested pickling) is often used to create multi-stage exploits or hide malicious payloads.",
    "torch_legacy": "Legacy PyTorch formats may have unpatched vulnerabilities. The _use_new_zipfile_serialization=False flag indicates use of the older, less secure format.",
}


# Function to get explanation for a security issue
def get_explanation(category: str, specific_item: str = None) -> Optional[str]:
    """
    Get a security explanation for a given category and item.

    Args:
        category: The category of security issue ('import', 'opcode', 'pattern')
        specific_item: The specific item (e.g., 'os', 'REDUCE', 'base64_payload')

    Returns:
        A security-team-friendly explanation, or None if not found
    """
    if category == "import" and specific_item in DANGEROUS_IMPORTS:
        return DANGEROUS_IMPORTS[specific_item]
    elif category == "opcode" and specific_item in DANGEROUS_OPCODES:
        return DANGEROUS_OPCODES[specific_item]
    elif category == "pattern" and specific_item in PATTERN_EXPLANATIONS:
        return PATTERN_EXPLANATIONS[specific_item]

    return None


# Convenience functions for common use cases
def get_import_explanation(module_name: str) -> Optional[str]:
    """Get explanation for a dangerous import/module."""
    # Handle module.function format (e.g., "os.system")
    base_module = module_name.split(".")[0]
    return get_explanation("import", base_module)


def get_opcode_explanation(opcode_name: str) -> Optional[str]:
    """Get explanation for a dangerous pickle opcode."""
    return get_explanation("opcode", opcode_name)


def get_pattern_explanation(pattern_name: str) -> Optional[str]:
    """Get explanation for a suspicious pattern."""
    return get_explanation("pattern", pattern_name)
