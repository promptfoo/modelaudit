"""
Helper module to map security detections to rule codes.
Centralizes the logic for assigning rule codes to specific security issues.
"""

from typing import Optional


def get_import_rule_code(module: str, function: Optional[str] = None) -> Optional[str]:
    """Get rule code for dangerous imports/modules."""
    module_lower = module.lower()

    # Direct module imports
    if module_lower in ["os", "__os__"]:
        return "S101"
    elif module_lower in ["sys", "__sys__"]:
        return "S102"
    elif module_lower in ["subprocess", "__subprocess__"]:
        return "S103"
    elif module_lower in ["socket", "__socket__"]:
        return "S301"
    elif module_lower in ["importlib", "__importlib__"]:
        return "S107"
    elif module_lower in ["runpy", "__runpy__"]:
        return "S108"
    elif module_lower in ["webbrowser", "__webbrowser__"]:
        return "S109"
    elif module_lower in ["ctypes", "__ctypes__"]:
        return "S110"
    elif module_lower in ["pty", "tty", "__pty__", "__tty__"]:
        return "S111"
    elif module_lower in ["code", "__code__"]:
        return "S112"
    elif module_lower in ["types"]:
        return "S113"
    elif module_lower in ["ast", "__ast__"]:
        return "S114"

    # Builtin dangerous functions
    if module_lower in ["__builtin__", "__builtins__", "builtins"]:
        if function:
            func_lower = function.lower()
            if func_lower in ["eval", "exec", "execfile"]:
                return "S104"
            elif func_lower == "compile":
                return "S105"
            elif func_lower == "__import__":
                return "S106"
        return "S115"  # General builtins manipulation

    # Network modules
    elif module_lower in ["requests", "urllib", "urllib2", "urllib3"]:
        return "S302"
    elif module_lower in ["http.client", "httplib", "httplib2"]:
        return "S303"
    elif module_lower in ["ftplib"]:
        return "S304"
    elif module_lower in ["telnetlib"]:
        return "S305"
    elif module_lower in ["smtplib"]:
        return "S306"

    # File operations
    elif module_lower in ["shutil"]:
        return "S403"
    elif module_lower in ["tempfile"]:
        return "S404"

    # Pickle/serialization
    elif module_lower in ["pickle", "cPickle", "_pickle"] or module_lower in ["dill", "cloudpickle"]:
        return "S213"

    return None


def get_pickle_opcode_rule_code(opcode_name: str) -> Optional[str]:
    """Get rule code for pickle opcodes."""
    opcode_upper = opcode_name.upper()

    if opcode_upper == "REDUCE":
        return "S201"
    elif opcode_upper == "INST":
        return "S202"
    elif opcode_upper == "OBJ":
        return "S203"
    elif opcode_upper == "NEWOBJ":
        return "S204"
    elif opcode_upper == "STACK_GLOBAL":
        return "S205"
    elif opcode_upper in ["GLOBAL", "GLOBALS"]:
        return "S206"
    elif opcode_upper == "BUILD":
        return "S207"
    elif opcode_upper == "SETATTR":
        return "S208"
    elif opcode_upper == "SETITEM":
        return "S209"
    elif opcode_upper == "SETITEMS":
        return "S210"
    elif opcode_upper in ["EXT1", "EXT2", "EXT4"]:
        return "S211"

    return None


def get_embedded_code_rule_code(code_type: str) -> Optional[str]:
    """Get rule code for embedded code/executables."""
    code_lower = code_type.lower()

    if "pe" in code_lower or "windows" in code_lower or "exe" in code_lower:
        return "S501"
    elif "elf" in code_lower or "linux" in code_lower:
        return "S502"
    elif "mach-o" in code_lower or "macos" in code_lower:
        return "S503"
    elif "shell" in code_lower or "bash" in code_lower or "sh" in code_lower:
        return "S504"
    elif "batch" in code_lower or "bat" in code_lower or "cmd" in code_lower:
        return "S505"
    elif "powershell" in code_lower or "ps1" in code_lower:
        return "S506"
    elif "python" in code_lower and "script" in code_lower:
        return "S507"
    elif "javascript" in code_lower or "js" in code_lower:
        return "S508"
    elif "wasm" in code_lower or "webassembly" in code_lower:
        return "S509"
    elif "torchscript" in code_lower or "jit" in code_lower:
        return "S510"

    return None


def get_encoding_rule_code(encoding_type: str) -> Optional[str]:
    """Get rule code for encoding/obfuscation."""
    enc_lower = encoding_type.lower()

    if "base64" in enc_lower or "b64" in enc_lower:
        return "S601"
    elif "hex" in enc_lower:
        return "S602"
    elif "zlib" in enc_lower or "compress" in enc_lower:
        return "S603"
    elif "encrypt" in enc_lower or "obfuscat" in enc_lower:
        return "S604"
    elif "unicode" in enc_lower:
        return "S605"
    elif "rot13" in enc_lower or "caesar" in enc_lower:
        return "S606"
    elif "xor" in enc_lower:
        return "S607"

    return None


def get_secret_rule_code(secret_type: str) -> Optional[str]:
    """Get rule code for secrets/credentials."""
    secret_lower = secret_type.lower()

    if "api" in secret_lower and "key" in secret_lower:
        return "S701"
    elif "password" in secret_lower or "passwd" in secret_lower:
        return "S702"
    elif "private" in secret_lower and "key" in secret_lower:
        return "S703"
    elif "aws" in secret_lower or "akia" in secret_lower:
        return "S704"
    elif "azure" in secret_lower or "gcp" in secret_lower:
        return "S705"
    elif any(db in secret_lower for db in ["mongodb", "postgresql", "mysql", "sqlite"]):
        return "S706"
    elif "jwt" in secret_lower or "bearer" in secret_lower:
        return "S707"
    elif "oauth" in secret_lower or "access_token" in secret_lower:
        return "S708"
    elif "webhook" in secret_lower:
        return "S709"
    elif "entropy" in secret_lower:
        return "S710"

    return None


def get_file_issue_rule_code(issue_type: str) -> Optional[str]:
    """Get rule code for file-related issues."""
    issue_lower = issue_type.lower()

    if "traversal" in issue_lower or "../" in issue_lower:
        return "S405"
    elif "symlink" in issue_lower:
        return "S406"
    elif "archive" in issue_lower and "bomb" in issue_lower:
        return "S410"
    elif "mismatch" in issue_lower and ("type" in issue_lower or "extension" in issue_lower):
        return "S901"
    elif "corrupt" in issue_lower:
        return "S902"
    elif "magic" in issue_lower and "bytes" in issue_lower:
        return "S903"
    elif "size" in issue_lower and ("large" in issue_lower or "excessive" in issue_lower):
        return "S904"
    elif "polyglot" in issue_lower:
        return "S908"

    return None


def get_model_rule_code(issue_type: str) -> Optional[str]:
    """Get rule code for model-specific issues."""
    issue_lower = issue_type.lower()

    if "weight" in issue_lower and "distribution" in issue_lower:
        return "S801"
    elif "outlier" in issue_lower and "neuron" in issue_lower:
        return "S802"
    elif "dissimilar" in issue_lower and "vector" in issue_lower:
        return "S803"
    elif "dimension" in issue_lower and "excessive" in issue_lower:
        return "S804"
    elif "backdoor" in issue_lower or "trojan" in issue_lower:
        return "S807"
    elif "blacklist" in issue_lower:
        return "S1001"
    elif "malicious" in issue_lower and "hash" in issue_lower:
        return "S1002"
    elif "typosquat" in issue_lower:
        return "S1003"
    elif "torch.load" in issue_lower or ("unsafe" in issue_lower and "pytorch" in issue_lower):
        return "S1101"
    elif "lambda" in issue_lower and "layer" in issue_lower:
        return "S1103"

    return None


def get_generic_rule_code(message: str) -> Optional[str]:
    """
    Try to determine rule code from a generic message.
    This is a fallback for messages that don't fit specific categories.
    """
    msg_lower = message.lower()

    # Try each specialized mapper
    for mapper in [
        lambda: get_file_issue_rule_code(msg_lower),
        lambda: get_encoding_rule_code(msg_lower),
        lambda: get_secret_rule_code(msg_lower),
        lambda: get_embedded_code_rule_code(msg_lower),
        lambda: get_model_rule_code(msg_lower),
    ]:
        code = mapper()
        if code:
            return code

    # Check for specific patterns
    if "protocol" in msg_lower and "version" in msg_lower:
        return "S212"
    elif (
        ("stack" in msg_lower and "depth" in msg_lower)
        or "timeout" in msg_lower
        or "timed out" in msg_lower
        or ("opcode" in msg_lower and "count" in msg_lower)
    ):
        return None  # Internal check, no rule

    return None
