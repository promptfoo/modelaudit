"""
Security issue explanations for ModelAudit.

This module provides centralized, security-team-friendly explanations
for common security issues found in ML model files.
"""

from typing import Optional

# Common explanations for dangerous imports and modules
DANGEROUS_IMPORTS: dict[str, str] = {
    "os": (
        "The 'os' module provides direct access to operating system functions, allowing execution of arbitrary system "
        "commands, file system manipulation, and environment variable access. Malicious models can use this to "
        "compromise the host system, steal data, or install malware."
    ),
    "posix": (
        "The 'posix' module provides direct access to POSIX system calls on Unix-like systems. Like the 'os' module, "
        "it can execute arbitrary system commands and manipulate the file system. The 'posix.system' function is "
        "equivalent to 'os.system' and poses the same security risks."
    ),
    "nt": (
        "The 'nt' module is a Windows-specific alias for 'os', exposing the same system command and file operations. "
        "Attackers can invoke functions like 'nt.system' to execute arbitrary commands."
    ),
    "ntpath": (
        "The 'ntpath' module provides Windows path manipulation utilities. These can be abused to access or modify "
        "restricted system paths, facilitating privilege escalation or data exfiltration."
    ),
    "posixpath": (
        "The 'posixpath' module provides POSIX path manipulation utilities. Attackers can leverage it to traverse or "
        "access restricted paths on Unix-like systems."
    ),
    "sys": (
        "The 'sys' module provides access to interpreter internals and system-specific parameters. It can be used to "
        "modify the Python runtime, access command-line arguments, or manipulate the module import system to load "
        "malicious code."
    ),
    "subprocess": (
        "The 'subprocess' module allows spawning new processes and executing system commands. This is a critical "
        "security risk as it enables arbitrary command execution on the host system."
    ),
    "eval": (
        "The 'eval' function executes arbitrary Python code from strings. This is extremely dangerous as it allows "
        "dynamic code execution, potentially running any malicious code embedded in the model."
    ),
    "exec": (
        "The 'exec' function executes arbitrary Python statements from strings. Like eval, this enables unrestricted "
        "code execution and is a severe security risk."
    ),
    "__import__": (
        "The '__import__' function dynamically imports modules at runtime. Attackers can use this to load malicious "
        "modules or bypass import restrictions."
    ),
    "importlib": (
        "The 'importlib' module provides programmatic module importing capabilities. It can be used to dynamically "
        "load malicious code or bypass security controls."
    ),
    "pickle": (
        "Nested pickle operations (pickle.load/loads within a pickle) can indicate attempts to obfuscate malicious "
        "payloads or create multi-stage attacks."
    ),
    "base64": (
        "Base64 encoding/decoding functions are often used to obfuscate malicious payloads, making them harder to "
        "detect through static analysis."
    ),
    "socket": (
        "The 'socket' module enables network communication. Malicious models can use this to exfiltrate data, download "
        "additional payloads, or establish command & control channels."
    ),
    "ctypes": (
        "The 'ctypes' module provides low-level system access through foreign function interfaces. It can bypass "
        "Python's safety features and directly manipulate memory or call system libraries."
    ),
    "pty": (
        "The 'pty' module provides pseudo-terminal utilities. The 'spawn' function can be used to create interactive "
        "shells, potentially giving attackers remote access."
    ),
    "platform": (
        "Functions like 'platform.system' or 'platform.popen' can be used for system reconnaissance or command "
        "execution."
    ),
    "shutil": (
        "The 'shutil' module provides high-level file operations. Functions like 'rmtree' can recursively delete "
        "directories, potentially causing data loss."
    ),
    "tempfile": ("Unsafe temp file creation (like 'mktemp') can lead to race conditions and security vulnerabilities."),
    "runpy": (
        "The 'runpy' module executes Python modules as scripts, potentially running malicious code embedded in the "
        "model."
    ),
    "operator.attrgetter": (
        "The 'attrgetter' function can be used to access object attributes dynamically, potentially bypassing "
        "access controls or reaching sensitive data."
    ),
    "builtins": (
        "Direct access to builtin functions can be used to bypass restrictions or access dangerous functionality "
        "like eval/exec."
    ),
    "dill": (
        "The 'dill' module extends pickle's capabilities to serialize almost any Python object, including lambda "
        "functions and code objects. This significantly increases the attack surface for code execution."
    ),
}

# Explanations for dangerous pickle opcodes
DANGEROUS_OPCODES = {
    "REDUCE": (
        "The REDUCE opcode calls a callable with arguments, effectively executing arbitrary Python functions. This is "
        "the primary mechanism for pickle-based code execution attacks through __reduce__ methods."
    ),
    "INST": (
        "The INST opcode instantiates objects by calling their class constructor. Malicious classes can execute code "
        "in __init__ methods during unpickling."
    ),
    "OBJ": (
        "The OBJ opcode creates class instances. Like INST, this can trigger code execution through object "
        "initialization."
    ),
    "NEWOBJ": (
        "The NEWOBJ opcode creates new-style class instances. It can execute initialization code and is commonly "
        "used in pickle exploits."
    ),
    "NEWOBJ_EX": (
        "The NEWOBJ_EX opcode is an extended version of NEWOBJ with additional capabilities for creating objects, "
        "potentially executing initialization code."
    ),
    "BUILD": (
        "The BUILD opcode updates object state and can trigger code execution through __setstate__ or __setattr__ "
        "methods."
    ),
    "STACK_GLOBAL": (
        "The STACK_GLOBAL opcode imports modules and retrieves attributes dynamically. Outside ML contexts, this "
        "often indicates attempts to access dangerous functionality."
    ),
    "GLOBAL": (
        "The GLOBAL opcode imports and accesses module attributes. When referencing dangerous modules, this "
        "indicates potential security risks."
    ),
}

# Explanations for specific patterns and behaviors
PATTERN_EXPLANATIONS = {
    "base64_payload": (
        "Base64-encoded data in models often conceals malicious payloads. Legitimate ML models rarely need encoded "
        "strings unless handling specific data formats."
    ),
    "hex_encoded": (
        "Hexadecimal-encoded strings (\\x00 format) can hide malicious code or data. This obfuscation technique is "
        "commonly used to evade detection."
    ),
    "lambda_layer": (
        "Lambda layers in Keras/TensorFlow can contain arbitrary Python code that executes during model inference. "
        "Unlike standard layers, these can perform system operations beyond tensor computations."
    ),
    "executable_in_zip": (
        "Executable files (.exe, .sh, .bat, etc.) within model archives are highly suspicious. ML models should "
        "only contain weights and configuration, not executables."
    ),
    "dissimilar_weights": (
        "Weight vectors that are completely dissimilar to others in the same layer may indicate injected malicious "
        "data masquerading as model parameters."
    ),
    "outlier_neurons": (
        "Neurons with weight distributions far outside the normal range might encode hidden functionality or "
        "backdoors rather than learned features."
    ),
    "blacklisted_name": (
        "This model name appears on security blacklists, indicating known malicious models or naming patterns "
        "associated with attacks."
    ),
    "manifest_name_mismatch": (
        "Model names in manifests that don't match expected patterns may indicate tampered or malicious models "
        "trying to impersonate legitimate ones."
    ),
    "encoded_strings": (
        "Encoded or obfuscated strings in model files often hide malicious payloads or commands from security scanners."
    ),
    "pickle_size_limit": (
        "Extremely large pickle files may indicate embedded malicious data or attempts to cause resource exhaustion."
    ),
    "nested_pickle": (
        "Pickle operations within pickled data (nested pickling) is often used to create multi-stage exploits or "
        "hide malicious payloads."
    ),
    "torch_legacy": (
        "Legacy PyTorch formats may have unpatched vulnerabilities. The _use_new_zipfile_serialization=False flag "
        "indicates use of the older, less secure format."
    ),
}

# Explanations for suspicious TensorFlow operations
#
# Risk Categories:
# - CRITICAL: Code execution (PyFunc, PyCall, ExecuteOp, ShellExecute) & System access (SystemConfig)
# - HIGH: File system operations (ReadFile, WriteFile, Save, SaveV2, MergeV2Checkpoints)
# - MEDIUM: Data processing with potential exploits (DecodeRaw, DecodeJpeg, DecodePng)
#
# Threat Context: Malicious ML models embed these operations to execute during model loading/inference,
# bypassing security tools that typically trust ML models. Used for RCE, data exfiltration, backdoors,
# and supply chain attacks.
TF_OP_EXPLANATIONS = {
    # Code execution operations - CRITICAL RISK
    "PyFunc": (
        "The PyFunc operation executes arbitrary Python code in the TensorFlow graph, which attackers can "
        "abuse to run system commands or other malicious code."
    ),
    "PyFuncStateless": (
        "The PyFuncStateless operation executes arbitrary Python code without maintaining state between calls, "
        "which attackers can abuse to run system commands or other malicious code."
    ),
    "EagerPyFunc": (
        "The EagerPyFunc operation executes arbitrary Python code in eager execution mode, which attackers can "
        "abuse to run system commands or other malicious code during model loading or inference."
    ),
    "PyCall": (
        "The PyCall operation invokes Python callbacks during graph execution, creating dangerous security risks "
        "by allowing arbitrary code execution that could compromise the system."
    ),
    "ExecuteOp": (
        "ExecuteOp allows running arbitrary operations and poses severe security risks by enabling "
        "malicious code execution that could compromise the host system."
    ),
    # System operations - CRITICAL RISK
    "ShellExecute": (
        "ShellExecute runs shell commands from the TensorFlow graph, posing severe security risks by enabling "
        "arbitrary command execution, potentially compromising the host system."
    ),
    "SystemConfig": (
        "SystemConfig operations access or modify system configuration, creating dangerous security risks "
        "by enabling reconnaissance or privilege escalation attacks."
    ),
    # File system operations - HIGH RISK
    "ReadFile": (
        "ReadFile retrieves data from arbitrary files; malicious models could exfiltrate secrets or read "
        "sensitive files."
    ),
    "WriteFile": (
        "WriteFile writes data to arbitrary locations, which could overwrite files or drop malicious payloads."
    ),
    "Save": (
        "Save operations write checkpoint data. Attackers might use them to persist malicious data or "
        "overwrite existing files."
    ),
    "SaveV2": ("SaveV2 is a variant of Save with similar risks of writing arbitrary files during graph execution."),
    "MergeV2Checkpoints": (
        "MergeV2Checkpoints manipulates TensorFlow checkpoints by reading and writing checkpoint files, "
        "which could be used to overwrite existing files or inject malicious parameters."
    ),
    # Data processing operations - MEDIUM RISK
    "DecodeRaw": ("DecodeRaw processes raw binary data that may be malicious or cause resource exhaustion."),
    "DecodeJpeg": (
        "DecodeJpeg decodes JPEG images; crafted images may exploit vulnerabilities or consume excessive resources."
    ),
    "DecodePng": ("DecodePng decodes PNG data, which could be abused with malformed inputs."),
}


# Function to get explanation for a security issue
def get_explanation(category: str, specific_item: Optional[str] = None) -> Optional[str]:
    """
    Get a security explanation for a given category and item.

    Args:
        category: The category of security issue ('import', 'opcode', 'pattern', 'tf_op')
        specific_item: The specific item (e.g., 'os', 'REDUCE', 'base64_payload', 'PyFunc')

    Returns:
        A security-team-friendly explanation, or None if not found
    """
    if category == "import" and specific_item in DANGEROUS_IMPORTS:
        return DANGEROUS_IMPORTS[specific_item]
    if category == "opcode" and specific_item in DANGEROUS_OPCODES:
        return DANGEROUS_OPCODES[specific_item]
    if category == "pattern" and specific_item in PATTERN_EXPLANATIONS:
        return PATTERN_EXPLANATIONS[specific_item]
    if category == "tf_op" and specific_item in TF_OP_EXPLANATIONS:
        return TF_OP_EXPLANATIONS[specific_item]

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


def get_tf_op_explanation(op_name: str) -> Optional[str]:
    """Get explanation for a suspicious TensorFlow operation."""
    return get_explanation("tf_op", op_name)


# Default explanations for common issue messages when no explicit "why"
# is provided at the call site.
COMMON_MESSAGE_EXPLANATIONS = {
    # Archive and compression security issues
    "Maximum ZIP nesting depth": (
        "Deeply nested archives can be used to hide malicious content or create"
        " zip bombs that exhaust system resources during extraction."
    ),
    "ZIP file contains too many entries": (
        "Large numbers of archive entries may indicate a malicious zip bomb designed to"
        " overwhelm the scanner or extraction process."
    ),
    "Archive entry": (
        "Archive paths should never resolve outside the extraction directory as"
        " this enables path traversal attacks where attackers can overwrite arbitrary files."
    ),
    "Symlink": (
        "Symlinks inside archives can point to sensitive locations and enable path traversal attacks when extracted."
    ),
    "Decompressed size too large": (
        "Maliciously crafted compressed data can expand to enormous sizes"
        " (compression bombs) to exhaust system memory and crash the application."
    ),
    "Not a valid zip file": (
        "Corrupted or malformed archives could be used to crash tools or hide malicious payloads."
    ),
    # File integrity and validation issues
    "File too small": (
        "Files smaller than expected may be truncated or corrupted, which is"
        " often a sign of tampering or incomplete downloads."
    ),
    "File too large": (
        "Extremely large files may be used for denial-of-service attacks by"
        " exhausting system resources during processing."
    ),
    "File type validation failed": (
        "Mismatched file headers and extensions may indicate file spoofing attacks"
        " where malicious content is disguised as a legitimate model format."
    ),
    # ML-specific security patterns
    "Custom objects found": (
        "Custom objects in ML models can contain arbitrary Python code that executes"
        " during model loading, potentially compromising the system."
    ),
    "External reference": (
        "External file references in models can be used to access sensitive data"
        " or load malicious content from outside the model file."
    ),
    "Lambda layer": (
        "Lambda layers in neural networks can execute arbitrary Python code during"
        " model inference, bypassing normal security controls."
    ),
    "Custom layer": (
        "Custom layers may contain untrusted code that executes during model"
        " operations, potentially performing malicious actions."
    ),
    "Unusual layer configuration": (
        "Non-standard layer configurations may indicate model tampering or"
        " hidden functionality designed to bypass security measures."
    ),
    "Custom metric": (
        "Custom metrics can execute arbitrary code during training or evaluation,"
        " potentially compromising the ML pipeline."
    ),
    "Custom loss function": (
        "Custom loss functions may contain malicious code that executes during model training or inference."
    ),
    # Dependency and module issues
    "Module not installed": (
        "Missing required modules may indicate supply chain attacks where"
        " attackers rely on users installing malicious packages."
    ),
    "Import error": (
        "Import failures may indicate tampered dependencies or attempts to"
        " load malicious modules not present in the environment."
    ),
    "Deprecated module": ("Deprecated modules may have unpatched security vulnerabilities that attackers can exploit."),
    # General security and scanning issues
    "Too many": (
        "Excessive quantities of data structures may indicate a malicious attempt"
        " to overwhelm the system or hide malicious content."
    ),
    "Error scanning": (
        "Scanning errors may indicate corrupted files, unsupported formats, or"
        " malicious content designed to crash security tools."
    ),
    "Timeout": (
        "Processing timeouts may indicate maliciously crafted content designed"
        " to cause denial-of-service by consuming excessive computational resources."
    ),
    "Memory limit exceeded": (
        "Excessive memory usage may indicate malicious content designed to"
        " crash the system or hide attacks within resource exhaustion."
    ),
    # Metadata and configuration issues
    "Missing metadata": (
        "Missing or incomplete metadata may indicate tampered models or attempts to hide malicious modifications."
    ),
    "Invalid metadata": (
        "Corrupted metadata may indicate file tampering or malicious modifications to model configurations."
    ),
    "Unexpected metadata": (
        "Unusual metadata fields may contain hidden payloads or indicate model tampering by malicious actors."
    ),
}


def get_message_explanation(message: str, context: Optional[str] = None) -> Optional[str]:
    """Return a default explanation for an issue message if available.

    Args:
        message: The issue message to find an explanation for
        context: Optional context to provide more specific explanations
                (e.g., scanner name, file type, etc.)

    Returns:
        An explanation string if a matching pattern is found, None otherwise
    """
    # First try to find a basic explanation
    base_explanation = None
    for prefix, explanation in COMMON_MESSAGE_EXPLANATIONS.items():
        if message.startswith(prefix):
            base_explanation = explanation
            break

    # If no base explanation found, return None
    if base_explanation is None:
        return None

    # If context is provided, try to enhance the explanation
    if context:
        enhanced_explanation = _enhance_explanation_with_context(message, base_explanation, context)
        if enhanced_explanation:
            return enhanced_explanation

    return base_explanation


def _enhance_explanation_with_context(message: str, base_explanation: str, context: str) -> Optional[str]:
    """Enhance explanations based on context information."""
    context_lower = context.lower()

    # ML model-specific context enhancements
    if any(scanner in context_lower for scanner in ["pickle", "pytorch", "keras", "tensorflow"]):
        if message.startswith("Custom objects found"):
            return (
                "Custom objects in ML models can execute arbitrary Python code during model loading. "
                "This is particularly dangerous in pickle-based formats where object deserialization "
                "can trigger immediate code execution without user consent."
            )
        if message.startswith("File too large"):
            return (
                "Extremely large model files may indicate embedded malicious data or denial-of-service "
                "attacks. ML models with unexpectedly large sizes should be verified for legitimate "
                "architectural reasons before deployment."
            )

    # Archive-specific context enhancements
    elif any(scanner in context_lower for scanner in ["zip", "tar", "archive"]):
        if message.startswith("Archive entry"):
            return (
                "Archive path traversal is especially dangerous in ML model deployments where "
                "automated systems may extract models to predictable locations, enabling "
                "attackers to overwrite critical system files or model configurations."
            )

    # ONNX/compiled model context
    elif any(scanner in context_lower for scanner in ["onnx", "tflite", "compiled"]) and message.startswith("Custom"):
        return (
            base_explanation + " In compiled models, custom components may bypass "
            "the sandboxing that interpreted models provide, making them particularly risky."
        )

    # Return None if no context-specific enhancement applies
    return None


# CVE-2025-32434 Specific Explanations
def get_cve_2025_32434_explanation(vulnerability_type: str) -> str:
    """Get specific explanation for CVE-2025-32434 vulnerability types"""

    explanations = {
        "pytorch_version": (
            "CVE-2025-32434 affects PyTorch versions ≤2.5.1 and allows remote code execution "
            "when loading models with torch.load(weights_only=True). The 'weights_only=True' "
            "parameter was commonly believed to provide security protection, but this "
            "vulnerability demonstrates that malicious pickle files can still execute "
            "arbitrary code regardless of this setting. Upgrade to PyTorch 2.6.0+ immediately."
        ),
        "weights_only_false_security": (
            "This model contains dangerous pickle opcodes that can execute arbitrary code "
            "even when loaded with torch.load(weights_only=True). This is the core of "
            "CVE-2025-32434 - the 'weights_only=True' parameter does NOT provide security "
            "protection against sophisticated attacks. The parameter is a feature flag, not "
            "a security boundary. Never rely on it for security with untrusted models."
        ),
        "dangerous_opcodes": (
            "The detected opcodes (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL, BUILD) are "
            "fundamental pickle operations that enable arbitrary code execution. These "
            "opcodes can invoke __reduce__ methods, instantiate arbitrary classes, and "
            "import dangerous modules. CVE-2025-32434 exploits the fact that torch.load() "
            "processes these opcodes even with weights_only=True, allowing malicious models "
            "to execute code during the loading process."
        ),
        "opcode_sequences": (
            "Specific opcode sequences have been identified that indicate CVE-2025-32434 "
            "exploitation attempts. These include PyTorch imports followed by execution "
            "opcodes, chained REDUCE operations for complex payloads, and eval/exec "
            "patterns with embedded string data. These sequences represent sophisticated "
            "attacks designed to bypass the weights_only=True assumption."
        ),
        "torchscript_vulnerabilities": (
            "TorchScript models can contain embedded code that executes during compilation "
            "or loading. CVE-2025-32434 can be combined with TorchScript injection to "
            "create multi-stage attacks. Dangerous patterns include serialization injection, "
            "module manipulation, hook injection, and bytecode-level code execution. "
            "These attacks can persist even after model loading completes."
        ),
    }

    return explanations.get(
        vulnerability_type,
        "This issue is related to CVE-2025-32434, a critical PyTorch vulnerability. "
        "Review the CVE documentation and update to PyTorch 2.6.0+ immediately.",
    )


def get_pytorch_security_explanation(issue_type: str) -> str:
    """Get PyTorch-specific security explanations"""

    explanations = {
        "pickle_serialization": (
            "PyTorch models use Python's pickle format for serialization, which is inherently "
            "unsafe. Pickle can execute arbitrary code during deserialization through __reduce__ "
            "methods, class instantiation, and module imports. This is not a bug but a "
            "fundamental design characteristic. Use SafeTensors format for better security."
        ),
        "model_source_validation": (
            "Model files should only be loaded from trusted, verified sources. Implement "
            "cryptographic signature verification, hash validation, and supply chain security "
            "practices. Never load models from untrusted URLs, user uploads, or unverified "
            "repositories without thorough security scanning."
        ),
        "safe_loading_practices": (
            "Safe model loading requires: (1) PyTorch 2.6.0+, (2) weights_only=True as basic "
            "precaution, (3) model source validation, (4) hash verification, (5) security "
            "scanning with tools like ModelAudit, and (6) sandboxed loading for untrusted "
            "models. Consider migrating to SafeTensors format for inherent safety."
        ),
        "torchscript_security": (
            "TorchScript models contain compiled code that can include dangerous operations. "
            "Validate all script modules for unsafe operations, avoid dynamic code generation, "
            "and review hook functions for malicious behavior. TorchScript can bypass some "
            "Python-level security controls, making validation critical."
        ),
    }

    return explanations.get(
        issue_type,
        "This is a PyTorch-specific security concern. Review PyTorch security best practices "
        "and ensure you're following safe model loading procedures.",
    )
