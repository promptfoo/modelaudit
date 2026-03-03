"""
Helper module to map security detections to rule codes.
Centralizes the logic for assigning rule codes to specific security issues.
"""

import logging

from modelaudit.rules import RuleRegistry

logger = logging.getLogger("modelaudit.scanners.rule_mapper")
_warned_unknown_codes: set[str] = set()


def _rule(code: str) -> str:
    """Return a rule code and warn once if it is missing from RuleRegistry."""
    if RuleRegistry.get_rule(code) is None and code not in _warned_unknown_codes:
        logger.warning("rule_mapper returned unknown rule code: %s", code)
        _warned_unknown_codes.add(code)
    return code


def get_import_rule_code(module: str, function: str | None = None) -> str | None:
    """Get rule code for dangerous imports/modules."""
    module_lower = module.lower()

    # Direct module imports
    if module_lower in ["os", "__os__"]:
        return _rule("S101")
    elif module_lower in ["sys", "__sys__"]:
        return _rule("S102")
    elif module_lower in ["subprocess", "__subprocess__"]:
        return _rule("S103")
    elif module_lower in ["socket", "__socket__"]:
        return _rule("S301")
    elif module_lower in ["importlib", "__importlib__"]:
        return _rule("S107")
    elif module_lower in ["runpy", "__runpy__"]:
        return _rule("S108")
    elif module_lower in ["webbrowser", "__webbrowser__"]:
        return _rule("S109")
    elif module_lower in ["ctypes", "__ctypes__"]:
        return _rule("S110")
    elif module_lower in ["pty", "tty", "__pty__", "__tty__"]:
        return _rule("S111")
    elif module_lower in ["code", "__code__"]:
        return _rule("S112")
    elif module_lower in ["types"]:
        return _rule("S113")
    elif module_lower in ["ast", "__ast__"]:
        return _rule("S114")

    # Builtin dangerous functions
    if module_lower in ["__builtin__", "__builtins__", "builtins"]:
        if function:
            func_lower = function.lower()
            if func_lower in ["eval", "exec", "execfile"]:
                return _rule("S104")
            elif func_lower == "compile":
                return _rule("S105")
            elif func_lower == "__import__":
                return _rule("S106")
        return _rule("S115")  # General builtins manipulation

    # Network modules
    elif module_lower in ["requests", "urllib", "urllib2", "urllib3"]:
        return _rule("S302")
    elif module_lower in ["http.client", "httplib", "httplib2"]:
        return _rule("S303")
    elif module_lower in ["ftplib"]:
        return _rule("S304")
    elif module_lower in ["telnetlib"]:
        return _rule("S305")
    elif module_lower in ["smtplib"]:
        return _rule("S306")

    # File operations
    elif module_lower in ["shutil"]:
        return _rule("S403")
    elif module_lower in ["tempfile"]:
        return _rule("S404")

    # Pickle/serialization
    elif module_lower in ["pickle", "cPickle", "_pickle"] or module_lower in ["dill", "cloudpickle"]:
        return _rule("S213")

    return None


def get_pickle_opcode_rule_code(opcode_name: str) -> str | None:
    """Get rule code for pickle opcodes."""
    opcode_upper = opcode_name.upper()

    if opcode_upper == "REDUCE":
        return _rule("S201")
    elif opcode_upper == "INST":
        return _rule("S202")
    elif opcode_upper == "OBJ":
        return _rule("S203")
    elif opcode_upper == "NEWOBJ":
        return _rule("S204")
    elif opcode_upper == "STACK_GLOBAL":
        return _rule("S205")
    elif opcode_upper in ["GLOBAL", "GLOBALS"]:
        return _rule("S206")
    elif opcode_upper == "BUILD":
        return _rule("S207")
    elif opcode_upper == "SETATTR":
        return _rule("S208")
    elif opcode_upper == "SETITEM":
        return _rule("S209")
    elif opcode_upper == "SETITEMS":
        return _rule("S210")
    elif opcode_upper in ["EXT1", "EXT2", "EXT4"]:
        return _rule("S211")

    return None


def get_embedded_code_rule_code(code_type: str) -> str | None:
    """Get rule code for embedded code/executables."""
    code_lower = code_type.lower()

    if "torchscript" in code_lower or "jit" in code_lower:
        return _rule("S510")
    elif (
        "windows" in code_lower
        or "pe executable" in code_lower
        or "portable executable" in code_lower
        or "mz header" in code_lower
        or ".exe" in code_lower
        or " exe" in code_lower
    ):
        return _rule("S501")
    elif "elf" in code_lower or "linux" in code_lower:
        return _rule("S502")
    elif "mach-o" in code_lower or "macos" in code_lower:
        return _rule("S503")
    elif "shell" in code_lower or "bash" in code_lower or "#!/bin/sh" in code_lower or ".sh" in code_lower:
        return _rule("S504")
    elif "batch" in code_lower or ".bat" in code_lower or ".cmd" in code_lower:
        return _rule("S505")
    elif "powershell" in code_lower or "ps1" in code_lower:
        return _rule("S506")
    elif "python" in code_lower and "script" in code_lower:
        return _rule("S507")
    elif "javascript" in code_lower or ".js" in code_lower:
        return _rule("S508")
    elif "wasm" in code_lower or "webassembly" in code_lower:
        return _rule("S509")

    return None


def get_encoding_rule_code(encoding_type: str) -> str | None:
    """Get rule code for encoding/obfuscation."""
    enc_lower = encoding_type.lower()

    if "base64" in enc_lower or "b64" in enc_lower:
        return _rule("S601")
    elif "hex" in enc_lower:
        return _rule("S602")
    elif "zlib" in enc_lower or "compress" in enc_lower:
        return _rule("S603")
    elif "encrypt" in enc_lower or "obfuscat" in enc_lower:
        return _rule("S604")
    elif "unicode" in enc_lower:
        return _rule("S605")
    elif "rot13" in enc_lower or "caesar" in enc_lower:
        return _rule("S606")
    elif "xor" in enc_lower:
        return _rule("S607")
    elif "url" in enc_lower or "percent" in enc_lower:
        return _rule("S609")
    elif "custom" in enc_lower or "unknown" in enc_lower:
        return _rule("S610")

    return None


def get_secret_rule_code(secret_type: str) -> str | None:
    """Get rule code for secrets/credentials."""
    secret_lower = secret_type.lower()

    if "api" in secret_lower and "key" in secret_lower:
        return _rule("S701")
    elif "password" in secret_lower or "passwd" in secret_lower:
        return _rule("S702")
    elif "private" in secret_lower and "key" in secret_lower:
        return _rule("S703")
    elif "aws" in secret_lower or "akia" in secret_lower:
        return _rule("S704")
    elif "azure" in secret_lower or "gcp" in secret_lower:
        return _rule("S705")
    elif any(db in secret_lower for db in ["mongodb", "postgresql", "mysql", "sqlite"]):
        return _rule("S706")
    elif "jwt" in secret_lower or "bearer" in secret_lower:
        return _rule("S707")
    elif "oauth" in secret_lower or "access_token" in secret_lower:
        return _rule("S708")
    elif "webhook" in secret_lower:
        return _rule("S709")
    elif "entropy" in secret_lower:
        return _rule("S710")

    return None


def get_network_rule_code(network_type: str) -> str | None:
    """Get rule code for network communication indicators."""
    net_lower = network_type.lower()

    if "socket" in net_lower:
        return _rule("S301")
    elif any(token in net_lower for token in ["requests", "urllib", "urlopen", "urlretrieve"]):
        return _rule("S302")
    elif any(token in net_lower for token in ["http.client", "httplib", "httpconnection"]):
        return _rule("S303")
    elif "ftp" in net_lower:
        return _rule("S304")
    elif "telnet" in net_lower:
        return _rule("S305")
    elif "smtp" in net_lower:
        return _rule("S306")
    elif any(token in net_lower for token in ["dns", "gethostby", "resolve"]):
        return _rule("S307")
    elif any(token in net_lower for token in ["ipv4", "ipv6", "ip address"]):
        return _rule("S308")
    elif any(
        token in net_lower
        for token in [
            "network_function",
            "explicit_network_pattern",
            "blacklisted_domain",
            "suspicious_port",
            "c&c",
            "exfil",
            "backdoor",
            "beacon",
        ]
    ):
        return _rule("S310")
    elif any(token in net_lower for token in ["url", "domain", "cloud_storage_url", "http://", "https://"]):
        return _rule("S309")

    return None


def get_file_issue_rule_code(issue_type: str) -> str | None:
    """Get rule code for file-related issues."""
    issue_lower = issue_type.lower()

    if "traversal" in issue_lower or "../" in issue_lower:
        return _rule("S405")
    elif "symlink" in issue_lower:
        return _rule("S406")
    elif "system" in issue_lower and "file" in issue_lower:
        return _rule("S408")
    elif "archive" in issue_lower and "bomb" in issue_lower:
        return _rule("S410")
    elif "mismatch" in issue_lower and ("type" in issue_lower or "extension" in issue_lower):
        return _rule("S901")
    elif "corrupt" in issue_lower:
        return _rule("S902")
    elif "magic" in issue_lower and "bytes" in issue_lower:
        return _rule("S903")
    elif "size" in issue_lower and ("large" in issue_lower or "excessive" in issue_lower):
        return _rule("S904")
    elif "suspicious" in issue_lower and ("pattern" in issue_lower or "config" in issue_lower):
        return _rule("S905")
    elif "polyglot" in issue_lower:
        return _rule("S908")

    return None


def get_model_rule_code(issue_type: str) -> str | None:
    """Get rule code for model-specific issues."""
    issue_lower = issue_type.lower()

    if "weight" in issue_lower and "distribution" in issue_lower:
        return _rule("S801")
    elif "outlier" in issue_lower and "neuron" in issue_lower:
        return _rule("S802")
    elif "dissimilar" in issue_lower and "vector" in issue_lower:
        return _rule("S803")
    elif "dimension" in issue_lower and "excessive" in issue_lower:
        return _rule("S804")
    elif "backdoor" in issue_lower or "trojan" in issue_lower:
        return _rule("S807")
    elif "blacklist" in issue_lower:
        return _rule("S1001")
    elif "malicious" in issue_lower and "hash" in issue_lower:
        return _rule("S1002")
    elif "typosquat" in issue_lower:
        return _rule("S1003")
    elif "torch.load" in issue_lower or ("unsafe" in issue_lower and "pytorch" in issue_lower):
        return _rule("S1101")
    elif "lambda" in issue_lower and "layer" in issue_lower:
        return _rule("S1103")

    return None


def get_generic_rule_code(message: str) -> str | None:
    """
    Try to determine rule code from a generic message.
    This is a fallback for messages that don't fit specific categories.
    """
    msg_lower = message.lower()

    # Try each specialized mapper
    for mapper in [
        lambda: get_file_issue_rule_code(msg_lower),
        lambda: get_network_rule_code(msg_lower),
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
        return _rule("S212")
    elif (
        ("stack" in msg_lower and "depth" in msg_lower)
        or "timeout" in msg_lower
        or "timed out" in msg_lower
        or ("opcode" in msg_lower and "count" in msg_lower)
    ):
        return None  # Internal check, no rule
    elif "unknown" in msg_lower and ("opcode" in msg_lower or "operation" in msg_lower):
        return _rule("S999")  # Unknown opcode/operation

    return None
